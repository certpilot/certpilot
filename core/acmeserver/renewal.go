package acmeserver

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/deploy"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// liveStatuses are the states a certificate is still in service in. A revoked
// or expired record is history, and ordering its names again is a new record
// rather than an overwrite of the one that says what happened.
var liveStatuses = map[string]bool{"ISSUED": true, "EXPIRING": true, "RENEWAL_FAILED": true}

// renews finds the certificate an order renews, if it renews one.
//
// An ACME client renews by ordering the same names again. Recorded as a new
// certificate every time, the one it replaced stayed ISSUED: counted in the
// inventory, on the horizon, and alerting as it neared expiry about a
// certificate nothing served any more. A renewal is written over the record
// instead, as the core's own renewals and the agent's are.
//
// It is a renewal when the same account ordered, under this template, exactly
// these names with the same key type, and that certificate is still live. A
// different key type is a second certificate, not a renewal: two certificates
// for one name, one RSA and one ECDSA, is how a server offers both.
func (s *Server) renews(c *gin.Context, account *store.ACMEAccount, tpl *store.CertificateTemplate,
	names []store.ACMEIdentifier, keyType string) (*store.Certificate, error) {

	ctx := c.Request.Context()
	orders, err := s.cfg.Store.ListACMEOrdersByAccount(ctx, account.ID)
	if err != nil {
		return nil, fmt.Errorf("could not look for the certificate this renews: %w", err)
	}
	want := map[string]bool{}
	for _, id := range names {
		want[id.Value] = true
	}

	seen := map[string]bool{}
	var match *store.Certificate
	for _, o := range orders {
		if o.CertificateID == nil || seen[*o.CertificateID] {
			continue
		}
		// Several orders point at one record once it has been renewed.
		seen[*o.CertificateID] = true
		cert, err := s.cfg.Store.GetCertificate(ctx, *o.CertificateID)
		if err != nil || cert == nil {
			continue
		}
		if cert.TemplateID == nil || *cert.TemplateID != tpl.ID ||
			!liveStatuses[cert.Status] || !strings.EqualFold(cert.KeyType, keyType) || !sameNames(cert, want) {
			continue
		}
		if match == nil || (cert.NotAfter != nil && match.NotAfter != nil && cert.NotAfter.After(*match.NotAfter)) {
			match = cert
		}
	}
	return match, nil
}

// sameNames reports whether a certificate names exactly the set want.
func sameNames(cert *store.Certificate, want map[string]bool) bool {
	have := map[string]bool{}
	for _, name := range append([]string{cert.CommonName}, cert.SANs...) {
		if name = strings.ToLower(strings.TrimSuffix(name, ".")); name != "" {
			have[name] = true
		}
	}
	if len(have) != len(want) {
		return false
	}
	for name := range have {
		if !want[name] {
			return false
		}
	}
	return true
}

// recordRenewal writes next over the record of the certificate it replaces:
// new material, one more renewal, and the old fingerprint kept so the verifier
// can tell whether the servers have picked the new one up.
func (s *Server) recordRenewal(c *gin.Context, req *signed, tpl *store.CertificateTemplate,
	prev, next *store.Certificate) (*store.Certificate, error) {

	ctx := c.Request.Context()
	previousFingerprint := prev.FingerprintSHA256

	prev.FingerprintSHA256 = next.FingerprintSHA256
	prev.CommonName = next.CommonName
	prev.SANs = next.SANs
	prev.SerialNumber = next.SerialNumber
	prev.IssuerDN = next.IssuerDN
	prev.NotBefore = next.NotBefore
	prev.NotAfter = next.NotAfter
	prev.DaysRemaining = next.DaysRemaining
	prev.KeyType = next.KeyType
	prev.KeySize = next.KeySize
	prev.CertificatePEM = next.CertificatePEM
	prev.ChainPEM = next.ChainPEM
	prev.CAAccountID = next.CAAccountID
	prev.TemplateID = next.TemplateID
	prev.TemplateVersion = next.TemplateVersion
	prev.RenewalLeadDays = next.RenewalLeadDays
	prev.ConformanceFindings = next.ConformanceFindings
	prev.Status = "ISSUED"
	prev.RenewalError = nil
	prev.RenewalCount++

	if err := s.cfg.Store.UpdateCertificate(ctx, prev); err != nil {
		return nil, err
	}

	// The client installs what it renews straight away, so the check is
	// scheduled as for a finished rollout. Through the narrow writer, because
	// UpdateCertificate's column list does not carry these.
	verifyAt := s.cfg.Now().Add(deploy.DeployedVerifyGrace)
	if err := s.cfg.Store.UpdateCertificateVerification(ctx, prev.ID, store.VerificationUpdate{
		State:               store.VerificationPending,
		CheckedAt:           s.cfg.Now(),
		VerifyAfter:         &verifyAt,
		PreviousFingerprint: previousFingerprint,
	}); err != nil {
		slog.Error("an ACME client renewed a certificate but its deployment check could not be scheduled",
			"cert_id", prev.ID, "error", err)
	}
	prev.PreviousFingerprint = previousFingerprint

	s.audit(c, "cert.renewed_via_acme", req.account.ID, req.account.ID, gin.H{
		"certificate": prev.ID, "cn": prev.CommonName, "names": prev.SANs, "template": tpl.Slug,
		"serial": prev.SerialNumber, "renewal_count": prev.RenewalCount, "previous_fingerprint": previousFingerprint,
	})
	if s.cfg.Broker != nil {
		s.cfg.Broker.Publish(events.Event{
			Topic:    events.TopicCertRenewed,
			Severity: events.SeverityInfo,
			EntityID: prev.ID,
			Payload: map[string]any{
				"common_name":    prev.CommonName,
				"serial_number":  prev.SerialNumber,
				"days_remaining": prev.DaysRemaining,
				"not_after":      prev.NotAfter.Format(time.RFC3339),
				"renewal_count":  prev.RenewalCount,
				"renewed_by":     "ACME (key held by the client)",
			},
		})
	}
	return prev, nil
}
