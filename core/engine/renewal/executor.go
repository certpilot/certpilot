// Package renewal manages automated and manual certificate renewal pipelines.
package renewal

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/deploy"
	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// Executor coordinates renewing a single certificate through its gateway plugin.
type Executor struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	keyring   *secrets.Keyring
	broker    *events.Broker
	// policyEng is what makes a rule change reach certificates that already
	// exist. This is the only component that touches every managed certificate
	// on a timer; without it, tightening a policy governs only certificates
	// that have not been issued yet. May be nil, in which case renewal behaves
	// as it did before and says so.
	policyEng *policy.Engine
}

// NewExecutor creates a new renewal executor. The broker may be nil, in which
// case no events are published.
func NewExecutor(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring, broker *events.Broker,
	policyEng *policy.Engine) *Executor {
	return &Executor{
		store:     s,
		pluginMgr: pm,
		keyring:   kr,
		broker:    broker,
		policyEng: policyEng,
	}
}

// RenewCertificate executes a certificate renewal through the assigned CA
// account gateway.
//
// A renewal is only complete when the new certificate and the key that matches
// it are both persisted. Storing one without the other produces a record that
// looks healthy on a dashboard and cannot terminate TLS.
func (e *Executor) RenewCertificate(ctx context.Context, certID string) (*store.Certificate, error) {
	cert, err := e.store.GetCertificate(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate %s: %w", certID, err)
	}

	if cert.CAAccountID == nil || *cert.CAAccountID == "" {
		return nil, fmt.Errorf("certificate %s has no assigned CA account", certID)
	}

	/*
	 * A key CertPilot does not hold cannot be rotated by CertPilot.
	 *
	 * RenewCertificateRequest carries no CSR, so the gateway generates a fresh
	 * keypair and the response is sealed into this record. For a certificate
	 * issued from a caller-supplied CSR — whose key is in an HSM, a load
	 * balancer, or a host that will never send it here — that is two failures
	 * at once. The certificate stops matching the key that is actually serving
	 * it, and key_custody goes on reading EXTERNAL while CertPilot quietly
	 * holds a key, which is the one question that field exists to answer.
	 *
	 * An agent-held key is the same case, and this guard used to test for
	 * EXTERNAL alone. A manual renewal of an agent's certificate therefore went
	 * through: the core sealed a key for a record still naming the host as its
	 * holder, and the host went on serving the certificate the record no longer
	 * described (#107). The API refuses both now, and the queue cancels both;
	 * this stays as the last line for any path that reaches here regardless.
	 */
	if err := KeyHeldElsewhere(ctx, e.store, cert); err != nil {
		return nil, err
	}

	caAccount, err := e.store.GetCAAccount(ctx, *cert.CAAccountID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA account: %w", err)
	}

	gw, err := e.pluginMgr.GetGateway(caAccount.Name)
	if err != nil {
		// Fall back to matching by provider type, for deployments that run one
		// shared gateway per protocol rather than one per account.
		gw, err = e.pluginMgr.GetGateway(caAccount.ProviderType)
		if err != nil {
			return nil, fmt.Errorf("gateway for CA account %s is not connected: %w", caAccount.Name, err)
		}
	}

	providerConfig, err := e.decryptCAConfig(caAccount)
	if err != nil {
		return nil, err
	}

	slog.Info("executing certificate renewal",
		"cert_id", certID,
		"common_name", cert.CommonName,
		"gateway", gw.Name,
	)

	now := time.Now()
	cert.LastRenewalAttempt = &now
	// Captured before anything overwrites it: this is what the endpoints are
	// expected to stop serving.
	previousFingerprint := cert.FingerprintSHA256

	// What the rules in force *today* say this should be, rather than what the
	// row happens to hold. Before this, renewal re-signed whatever a
	// certificate already was: an RSA-1024 certificate imported in 2023 renewed
	// as RSA-1024 in 2031, on schedule, quietly, showing green.
	//
	// Renewal generates the key — RenewCertificateRequest carries no CSR — so
	// raising a key floor is something it can actually act on rather than only
	// report.
	shape := e.conformance(ctx, cert)
	// A renewal is an issuance, so the record moves to the version that
	// governed it. Only when there was a template to judge against: nil here
	// must not erase what is stored, which is what the UPDATE's COALESCE is for.
	if shape.TemplateVersion != nil {
		cert.TemplateVersion = shape.TemplateVersion
	}

	renewReq := &providerv1.RenewCertificateRequest{
		ProviderCertificateId: cert.SerialNumber,
		// Deduplicated: an issued certificate carries its common name as a SAN
		// too, and sending both produced a certificate listing the same name twice.
		Domains:          shape.Domains,
		KeyType:          shape.KeyType,
		KeySize:          int32(shape.KeySize),
		ProviderConfig:   providerConfig,
		CaProfile:        shape.CAProfile,
		KeyUsage:         shape.KeyUsage,
		ExtendedKeyUsage: shape.ExtendedKeyUsage,
		// Restated on every renewal (#102). Without it the gateway applied its
		// own default, and a 90-day certificate came back lasting a year.
		ValidityDays: int32(shape.ValidityDays),
	}
	if cert.CertificatePEM != nil {
		renewReq.CurrentCertificatePem = []byte(*cert.CertificatePEM)
	}

	resp, err := gw.Client.RenewCertificate(ctx, renewReq)
	if err != nil {
		return nil, e.recordFailure(ctx, cert, err)
	}

	if resp.Certificate == nil || len(resp.Certificate.CertificatePem) == 0 {
		return nil, e.recordFailure(ctx, cert, fmt.Errorf("gateway reported success but returned no certificate"))
	}

	// Parse before persisting. A gateway that returns something that is not a
	// certificate must not be able to overwrite a working record with it.
	info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem)
	if err != nil {
		return nil, e.recordFailure(ctx, cert,
			fmt.Errorf("gateway returned data that is not a valid X.509 certificate: %w", err))
	}

	// Issue, then check — #30. A renewal is an issuance, and the same
	// question applies: did the CA actually honour what today's rules ask
	// for, or only agree to sign something.
	findings, err := issuance.VerifyConformance(&issuance.Decision{
		Template: shape.Template, KeyType: shape.KeyType, KeySize: shape.KeySize,
		Domains: shape.Domains, ValidityDays: shape.ValidityDays,
	}, resp.Certificate.CertificatePem)
	if err != nil {
		return nil, e.recordFailure(ctx, cert,
			fmt.Errorf("renewed certificate could not be checked for conformance: %w", err))
	}
	if !shape.ValidityDeclared {
		findings = inferredLifetimeIsReported(findings)
	}
	// Enforcement is a template property; a certificate with no template has
	// nothing to enforce against, the same reasoning applyTemplateFloor
	// already applies to the key-and-validity floor above.
	if shape.Template != nil {
		if blocking := issuance.Enforced(shape.Template, findings); len(blocking) > 0 {
			messages := make([]string, 0, len(blocking))
			for _, f := range blocking {
				messages = append(messages, f.Message)
			}
			if _, revokeErr := gw.Client.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
				CertificatePem:        resp.Certificate.CertificatePem,
				ProviderCertificateId: resp.ProviderCertificateId,
				ProviderConfig:        providerConfig,
			}); revokeErr != nil {
				slog.Warn("could not revoke a renewal that failed conformance under an ENFORCE template",
					"template", shape.Template.Slug, "cert_id", cert.ID, "error", revokeErr)
			}
			return nil, e.recordFailure(ctx, cert, fmt.Errorf(
				"template %q requires ENFORCE conformance and the CA did not honour the renewal: %s",
				shape.Template.Slug, strings.Join(messages, "; ")))
		}
	}

	// Seal the rotated key before anything else is written. Renewal normally
	// rotates the key, and dropping the new key here is what previously left
	// the stored certificate and key mismatched after every renewal.
	if len(resp.Certificate.PrivateKeyPem) > 0 {
		sealed, err := e.keyring.Encrypt(resp.Certificate.PrivateKeyPem, secrets.ContextCertificatePrivKey)
		if err != nil {
			return nil, e.recordFailure(ctx, cert,
				fmt.Errorf("failed to encrypt the renewed private key, refusing to store it in the clear: %w", err))
		}
		cert.PrivateKeyEncrypted = &sealed
	}

	certPEM := string(resp.Certificate.CertificatePem)
	cert.CertificatePEM = &certPEM
	if len(resp.Certificate.ChainPem) > 0 {
		chainPEM := string(resp.Certificate.ChainPem)
		cert.ChainPEM = &chainPEM
	}

	notBefore, notAfter := info.NotBefore, info.NotAfter
	cert.NotBefore = &notBefore
	cert.NotAfter = &notAfter
	cert.DaysRemaining = info.DaysRemaining
	cert.SerialNumber = info.SerialNumber
	cert.IssuerDN = info.IssuerDN
	cert.FingerprintSHA256 = info.FingerprintSHA256
	cert.KeyType = info.KeyType
	cert.KeySize = info.KeySize

	cert.Status = "ISSUED"
	cert.RenewalError = nil
	cert.RenewalCount++
	// Non-blocking findings reach here even under ENFORCE, the same as the
	// issuance paths: neither shorter validity nor an added subject field was
	// ever the class that setting refuses.
	cert.ConformanceFindings = findings

	if err := e.store.UpdateCertificate(ctx, cert); err != nil {
		return nil, fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	// A renewal is not done when the certificate is stored. It is done when the
	// thing serving it is serving it.
	//
	// This is where that stops being somebody else's job. Deployments are
	// enqueued directly rather than driven off the cert.renewed event published
	// below: the broker drops the oldest event on a slow consumer, which is the
	// right policy for a wall display and precisely the wrong one here — a
	// dropped event would be a certificate that renewed and silently never
	// deployed, which is the failure this phase exists to prevent, produced by
	// the machinery meant to prevent it.
	//
	// A failure here is not fatal to the renewal, which has already happened.
	// It is loud, because the certificate is now newer than the thing serving
	// it and nothing is scheduled to fix that.
	rollout, deployErr := deploy.EnqueueFor(ctx, e.store, cert, store.DeployReasonRenewal, nil, nil)
	if deployErr != nil {
		slog.Error("a certificate was renewed and its deployments could not be queued",
			"cert_id", cert.ID, "common_name", cert.CommonName, "error", deployErr)
	} else if rollout.Total() > 0 {
		slog.Info("queued deployments for a renewed certificate",
			"common_name", cert.CommonName, "queued", rollout.Queued,
			"already_queued", rollout.Already, "switched_off", rollout.Skipped,
			"not_automatic", rollout.OptedOut)
	}

	// Written through the narrow verification writer rather than as fields on
	// the row above. UpdateCertificate has an explicit column list, and adding
	// to the model without adding to that list drops the value in silence —
	// which is exactly what happened the first time this was written, and the
	// in-memory store could not show it because it stores whole structs.
	verifyAt := time.Now().Add(VerifyGrace)
	if err := e.store.UpdateCertificateVerification(ctx, cert.ID, store.VerificationUpdate{
		State:               store.VerificationPending,
		CheckedAt:           time.Now(),
		VerifyAfter:         &verifyAt,
		Attempts:            0,
		PreviousFingerprint: previousFingerprint,
	}); err != nil {
		// Not fatal to the renewal, which has already happened and been stored.
		// But it does mean nothing will check that this reached the server, so
		// it is said loudly rather than logged at debug.
		slog.Error("a certificate was renewed but its deployment check could not be scheduled",
			"cert_id", cert.ID, "error", err)
	}

	_ = e.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     "cert.renewed",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details: fmt.Sprintf(`{"cn": %q, "serial": %q, "not_after": %q, "renewal_count": %d}`,
			cert.CommonName, cert.SerialNumber, notAfter.Format(time.RFC3339), cert.RenewalCount),
	})

	e.broker.Publish(events.Event{
		Topic:    events.TopicCertRenewed,
		Severity: events.SeverityInfo,
		EntityID: cert.ID,
		Payload: map[string]any{
			"common_name":    cert.CommonName,
			"serial_number":  cert.SerialNumber,
			"days_remaining": cert.DaysRemaining,
			"not_after":      notAfter.Format(time.RFC3339),
			"renewal_count":  cert.RenewalCount,
		},
	})

	slog.Info("certificate renewed successfully",
		"cert_id", cert.ID,
		"common_name", cert.CommonName,
		"serial", cert.SerialNumber,
		"days_remaining", cert.DaysRemaining,
	)

	return cert, nil
}

// recordFailure marks a renewal as failed, audits it, and returns the error to
// propagate.
func (e *Executor) recordFailure(ctx context.Context, cert *store.Certificate, cause error) error {
	errMsg := cause.Error()
	cert.RenewalError = &errMsg
	cert.Status = "RENEWAL_FAILED"

	if err := e.store.UpdateCertificate(ctx, cert); err != nil {
		slog.Error("failed to record renewal failure", "cert_id", cert.ID, "error", err)
	}

	_ = e.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     "cert.renewal_failed",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details:    fmt.Sprintf(`{"error": %q, "cn": %q}`, errMsg, cert.CommonName),
	})

	// Deliberately does not publish.
	//
	// A failed renewal is still a certificate on its way to expiry with nobody
	// watching, but this function is now one attempt among many rather than the
	// whole story. The queue owns the alert and raises it once, when a failure
	// stops being a blip — announcing here would put a CRITICAL message in the
	// channel every few minutes for a fortnight, and a channel people mute
	// takes the CA expiry alerts sharing it along too.
	return fmt.Errorf("renewal failed for %s: %w", cert.CommonName, cause)
}

func (e *Executor) decryptCAConfig(acc *store.CAAccount) (string, error) {
	return decryptCAConfig(e.keyring, acc)
}

// decryptCAConfig opens a CA account's sealed configuration.
//
// Shared by the executor and the renewal information poller: both have to hand
// the same provider config to the same gateway, and two copies of this would be
// two places for the pre-encryption fallback below to drift.
func decryptCAConfig(keyring *secrets.Keyring, acc *store.CAAccount) (string, error) {
	if acc.ConfigEncrypted == "" {
		return "", nil
	}
	// Accounts written before encryption existed are stored as plaintext JSON.
	if !secrets.IsEnvelope(acc.ConfigEncrypted) {
		return acc.ConfigEncrypted, nil
	}
	plaintext, err := keyring.DecryptString(acc.ConfigEncrypted, secrets.ContextCAAccountConfig)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt the configuration for CA account %q: %w", acc.Name, err)
	}
	return plaintext, nil
}
