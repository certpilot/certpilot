package pki

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// Importer records what a CA account's gateway says about its own issuers.
//
// `GetCAInfo` has been in the gateway contract since the first proto file and
// nothing ever called it, which left the inventory the wrong way round.
// CertPilot tracked the certificates — monitored them, alerted on them, renewed
// them — while the CA that signed every one of them was not in the system at
// all. An expiring leaf takes down one service. An expiring issuing CA takes
// down everything it ever signed, and no amount of certificate automation helps
// once it has happened.
//
// One rule governs everything below: **the certificate is the truth.** A
// gateway reports names, types and expiry dates, and all of that is hearsay
// about a document CertPilot has been handed. Everything derivable is derived
// from the certificate itself; the gateway is believed only about the two
// things the certificate does not contain — what the CA is called where it
// lives, and where the mount publishes its CRL.
type Importer struct {
	store   store.Store
	plugins *pluginmgr.Manager
	keyring *secrets.Keyring
	broker  *events.Broker

	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewImporter creates an issuer importer. The broker may be nil, in which case
// no events are published.
func NewImporter(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring, broker *events.Broker) *Importer {
	return &Importer{
		store:   s,
		plugins: pm,
		keyring: kr,
		broker:  broker,
		stopCh:  make(chan struct{}),
	}
}

// Outcome is what happened to one CA a gateway offered.
type Outcome struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Action is added, refreshed, or skipped.
	Action string `json:"action"`
	// Reason is set when the CA was skipped, and says what was missing rather
	// than that something was.
	Reason string `json:"reason,omitempty"`
	// DaysRemaining is carried so a caller can report the discovery that
	// matters without a second query.
	DaysRemaining int `json:"days_remaining,omitempty"`
}

// Actions an Outcome can record.
const (
	ActionAdded     = "added"
	ActionRefreshed = "refreshed"
	ActionSkipped   = "skipped"
)

// Result is what one account's gateway yielded.
type Result struct {
	Account  string    `json:"account"`
	Outcomes []Outcome `json:"outcomes"`
	// Error is set when the account could not be asked at all, which is
	// different from an account that was asked and reported nothing.
	Error string `json:"error,omitempty"`
}

// Added counts the CAs this run put into the inventory.
func (r Result) Added() int { return r.count(ActionAdded) }

// Refreshed counts the CAs this run confirmed are still offered.
func (r Result) Refreshed() int { return r.count(ActionRefreshed) }

func (r Result) count(action string) int {
	n := 0
	for _, outcome := range r.Outcomes {
		if outcome.Action == action {
			n++
		}
	}
	return n
}

// Start sweeps every account on the given interval.
//
// Slower than the health monitor on purpose. A mount's issuers change when
// somebody rotates a CA, which is a thing that happens a few times a decade;
// what changes daily is how long those CAs have left, and that is the health
// monitor's job on rows this has already created.
func (i *Importer) Start(interval time.Duration) {
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	slog.Info("starting CA issuer import", "interval", interval)

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		i.sweepAndLog(context.Background())
		for {
			select {
			case <-ticker.C:
				i.sweepAndLog(context.Background())
			case <-i.stopCh:
				return
			}
		}
	}()
}

// Stop halts the importer. It is safe to call more than once.
func (i *Importer) Stop() {
	i.stopOnce.Do(func() { close(i.stopCh) })
}

func (i *Importer) sweepAndLog(ctx context.Context) {
	results, err := i.SweepAll(ctx)
	if err != nil {
		slog.Error("CA issuer import failed", "error", err)
		return
	}
	for _, result := range results {
		if result.Error != "" {
			slog.Warn("could not import issuers from a CA account",
				"account", result.Account, "error", result.Error)
			continue
		}
		if added := result.Added(); added > 0 {
			slog.Info("imported CA issuers", "account", result.Account,
				"added", added, "refreshed", result.Refreshed())
		}
	}
}

// SweepAll asks every CA account's gateway for its issuers.
func (i *Importer) SweepAll(ctx context.Context) ([]Result, error) {
	accounts, err := i.store.ListCAAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not list CA accounts: %w", err)
	}

	results := make([]Result, 0, len(accounts))
	for _, account := range accounts {
		// One account that cannot be reached does not stop the others. A Vault
		// that is sealed is a reason to skip an account, not a reason to leave
		// the rest of the estate's CAs unrecorded.
		results = append(results, i.ImportAccount(ctx, account))
	}
	return results, nil
}

// ImportAccount asks one account's gateway for its issuers and records them.
func (i *Importer) ImportAccount(ctx context.Context, account *store.CAAccount) Result {
	result := Result{Account: account.Name}

	gateway, err := i.plugins.GetGateway(account.Name)
	if err != nil {
		gateway, err = i.plugins.GetGateway(account.ProviderType)
		if err != nil {
			result.Error = fmt.Sprintf("no gateway is connected for %s", account.ProviderType)
			return result
		}
	}
	// Asking a gateway that does not implement this produces an Unimplemented
	// error per call, on a timer, for ever. The capability exists so the answer
	// is known without asking.
	if gateway.Capabilities == nil || !gateway.Capabilities.SupportsCaInfo {
		return result
	}

	config, err := decryptCAConfig(i.keyring, account)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	resp, err := gateway.Client.GetCAInfo(ctx, &providerv1.GetCAInfoRequest{ProviderConfig: config})
	if err != nil {
		result.Error = fmt.Sprintf("the gateway could not report its issuers: %v", err)
		return result
	}

	for _, reported := range resp.CaChain {
		result.Outcomes = append(result.Outcomes, i.record(ctx, account, reported))
	}
	i.linkParents(ctx, result)
	return result
}

// record puts one reported CA into the inventory, or says why it could not.
func (i *Importer) record(
	ctx context.Context, account *store.CAAccount, reported *commonv1.CAAuthorityInfo,
) Outcome {
	name := strings.TrimSpace(reported.GetName())
	if name == "" {
		name = "unnamed CA"
	}

	// Everything here depends on there being a certificate. A CA named without
	// one cannot be tracked at all: there is no expiry to monitor, no
	// fingerprint to identify it by, and no key to describe. The ACME gateway
	// reports exactly this — ACME publishes no endpoint listing issuers, so it
	// returns the directory as a placeholder — and recording it would create a
	// row that looks like a monitored CA and is not.
	pem := strings.TrimSpace(string(reported.GetCertificatePem()))
	if pem == "" {
		return Outcome{Name: name, Action: ActionSkipped,
			Reason: "the gateway named this CA and did not send its certificate, so there is no expiry to monitor and nothing to identify it by"}
	}
	info, err := x509util.ParseCertificatePEM([]byte(pem))
	if err != nil {
		return Outcome{Name: name, Action: ActionSkipped,
			Reason: fmt.Sprintf("what the gateway sent is not a certificate: %v", err)}
	}

	existing, err := i.store.GetCAAuthorityByFingerprint(ctx, info.FingerprintSHA256)
	if err != nil {
		return Outcome{Name: name, Fingerprint: info.FingerprintSHA256, Action: ActionSkipped,
			Reason: fmt.Sprintf("could not check whether this CA is already known: %v", err)}
	}
	if existing != nil {
		return i.refresh(ctx, account, existing, reported, info)
	}
	return i.add(ctx, account, name, pem, reported, info)
}

// add creates a CA nobody had recorded.
func (i *Importer) add(
	ctx context.Context, account *store.CAAccount, name, pem string,
	reported *commonv1.CAAuthorityInfo, info *x509util.CertInfo,
) Outcome {
	now := time.Now()
	ca := &store.CAAuthority{
		Name:              name,
		CAType:            authorityType(info, reported.GetCaType()),
		SubjectDN:         info.SubjectDN,
		IssuerDN:          info.IssuerDN,
		SerialNumber:      info.SerialNumber,
		NotBefore:         info.NotBefore,
		NotAfter:          info.NotAfter,
		DaysRemaining:     info.DaysRemaining,
		KeyType:           info.KeyType,
		KeySize:           info.KeySize,
		FingerprintSHA256: info.FingerprintSHA256,
		CertificatePEM:    pem,
		// The two facts the certificate does not carry, taken from the gateway.
		CRLDistributionURL: firstNonEmpty(crlOf(info), reported.GetCrlUrl()),
		OCSPResponderURL:   firstNonEmpty(ocspOf(info), reported.GetOcspUrl()),
		CAAccountID:        &account.ID,
		Status:             statusFor(info.DaysRemaining),
		Source:             store.CASourceGateway,
		LastSeenAt:         &now,
	}

	if err := i.store.CreateCAAuthority(ctx, ca); err != nil {
		// `name` is unique, and a gateway has no way to know what an operator
		// has already called something else. Losing the CA over a label would
		// be the wrong trade: its expiry is the thing worth having.
		if !isNameConflict(err) {
			return Outcome{Name: name, Fingerprint: info.FingerprintSHA256, Action: ActionSkipped,
				Reason: fmt.Sprintf("could not record this CA: %v", err)}
		}
		ca.Name = fmt.Sprintf("%s (%s)", name, shortFingerprint(info.FingerprintSHA256))
		if err := i.store.CreateCAAuthority(ctx, ca); err != nil {
			return Outcome{Name: name, Fingerprint: info.FingerprintSHA256, Action: ActionSkipped,
				Reason: fmt.Sprintf("could not record this CA: %v", err)}
		}
	}

	i.announce(ca, account)
	return Outcome{
		Name: ca.Name, Fingerprint: ca.FingerprintSHA256,
		Action: ActionAdded, DaysRemaining: info.DaysRemaining,
	}
}

// refresh updates a CA that is already recorded.
//
// Deliberately narrow. The fingerprint matched, which means the certificate is
// byte-for-byte the one already stored, so everything derived from it is
// already right — there is nothing to correct. What can have changed is the
// relationship: whether this CA is linked to the account that offers it,
// whether the mount has since published a CRL, and when it was last seen.
//
// The name, the alert thresholds, the owning team, the tags and the notes are
// never touched. Those are what an operator decided, and a sweep that
// overwrote them every twelve hours would be worse than not running.
func (i *Importer) refresh(
	ctx context.Context, account *store.CAAccount, existing *store.CAAuthority,
	reported *commonv1.CAAuthorityInfo, info *x509util.CertInfo,
) Outcome {
	now := time.Now()
	existing.LastSeenAt = &now
	if existing.CAAccountID == nil || *existing.CAAccountID == "" {
		existing.CAAccountID = &account.ID
	}
	if existing.CRLDistributionURL == "" {
		existing.CRLDistributionURL = firstNonEmpty(crlOf(info), reported.GetCrlUrl())
	}
	if existing.OCSPResponderURL == "" {
		existing.OCSPResponderURL = firstNonEmpty(ocspOf(info), reported.GetOcspUrl())
	}

	if err := i.store.UpdateCAAuthority(ctx, existing); err != nil {
		return Outcome{Name: existing.Name, Fingerprint: existing.FingerprintSHA256,
			Action: ActionSkipped, Reason: fmt.Sprintf("could not update this CA: %v", err)}
	}
	return Outcome{
		Name: existing.Name, Fingerprint: existing.FingerprintSHA256,
		Action: ActionRefreshed, DaysRemaining: info.DaysRemaining,
	}
}

// linkParents joins each imported CA to its issuer where both are recorded.
//
// Run after the whole account, because a chain arrives in whatever order the
// gateway listed it and an intermediate's root may not have existed yet when
// the intermediate was written.
func (i *Importer) linkParents(ctx context.Context, result Result) {
	for _, outcome := range result.Outcomes {
		if outcome.Action != ActionAdded || outcome.Fingerprint == "" {
			continue
		}
		child, err := i.store.GetCAAuthorityByFingerprint(ctx, outcome.Fingerprint)
		if err != nil || child == nil || child.ParentCAID != nil {
			continue
		}
		// A self-signed root issues itself. Pointing it at itself would make
		// the chain walk a cycle.
		if child.IssuerDN == "" || child.IssuerDN == child.SubjectDN {
			continue
		}

		parent := i.findBySubject(ctx, child.IssuerDN, child.FingerprintSHA256)
		if parent == nil {
			continue
		}
		child.ParentCAID = &parent.ID
		if err := i.store.UpdateCAAuthority(ctx, child); err != nil {
			slog.Warn("could not link a CA to its issuer",
				"ca", child.Name, "issuer", parent.Name, "error", err)
		}
	}
}

// findBySubject looks for the CA that issued a subject DN.
func (i *Importer) findBySubject(ctx context.Context, subjectDN, excludeFingerprint string) *store.CAAuthority {
	all, err := i.store.ListCAAuthorities(ctx, store.CAFilter{})
	if err != nil {
		return nil
	}
	for _, candidate := range all {
		if candidate.SubjectDN == subjectDN && candidate.FingerprintSHA256 != excludeFingerprint {
			return candidate
		}
	}
	return nil
}

// announce publishes a CA entering the inventory.
//
// The severity comes from how long it has left, because the case worth waking
// somebody for is the one where a CA that nobody was watching turns out to be
// weeks from expiry. That is not a discovery, it is an incident that has been
// running silently.
func (i *Importer) announce(ca *store.CAAuthority, account *store.CAAccount) {
	if i.broker == nil {
		return
	}
	severity := events.SeverityInfo
	switch {
	case ca.DaysRemaining <= 30:
		severity = events.SeverityCritical
	case ca.DaysRemaining <= 180:
		severity = events.SeverityWarning
	}

	i.broker.Publish(events.Event{
		Topic:    events.TopicCADiscovered,
		Severity: severity,
		EntityID: ca.ID,
		Payload: map[string]any{
			"ca_name":        ca.Name,
			"ca_type":        ca.CAType,
			"ca_account":     account.Name,
			"provider_type":  account.ProviderType,
			"days_remaining": ca.DaysRemaining,
			"not_after":      ca.NotAfter.Format(time.RFC3339),
			"subject_dn":     ca.SubjectDN,
		},
	})
}

// ── Deriving from the certificate ───────────────────────────

// authorityType classifies a CA from its own certificate, falling back to what
// the gateway called it.
//
// The certificate first because it is the document that will be verified: a
// gateway calling something an issuing CA does not make a verifier treat it as
// one. The fallback covers a certificate whose basic constraints are missing,
// which is a broken CA and still one whose expiry matters.
func authorityType(info *x509util.CertInfo, reported string) string {
	if info.IsCA {
		if info.IssuerDN == info.SubjectDN {
			return "ROOT"
		}
		return "INTERMEDIATE"
	}
	switch strings.ToUpper(strings.TrimSpace(reported)) {
	case "ROOT", "INTERMEDIATE", "ISSUING":
		return strings.ToUpper(strings.TrimSpace(reported))
	}
	return "ISSUING"
}

// statusFor is the same rule the registration endpoint applies, so a CA that
// arrives through a gateway and one somebody typed in do not start life in
// different states. The health monitor takes over from here.
func statusFor(daysRemaining int) string {
	switch {
	case daysRemaining <= 30:
		return "CRITICAL"
	case daysRemaining <= 180:
		return "WARNING"
	default:
		return "HEALTHY"
	}
}

func crlOf(info *x509util.CertInfo) string {
	if len(info.CRLURLs) > 0 {
		return info.CRLURLs[0]
	}
	return ""
}

func ocspOf(info *x509util.CertInfo) string {
	if len(info.OCSPURLs) > 0 {
		return info.OCSPURLs[0]
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func shortFingerprint(fingerprint string) string {
	if len(fingerprint) <= 8 {
		return fingerprint
	}
	return fingerprint[:8]
}

// isNameConflict reports whether a write failed because the name is taken.
//
// Matched on the message because the two stores report it differently and
// neither exposes a typed error. Being wrong here costs a CA a nicer name, not
// its record.
func isNameConflict(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "duplicate key") && strings.Contains(message, "name")
}

// decryptCAConfig opens a CA account's sealed configuration.
//
// Held here rather than shared with the renewal executor, which has its own
// copy: the two packages would otherwise have to agree on a home for a
// four-line function, and a CA account's sealed configuration is a thing each
// caller opens for one call and does not keep.
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
		return "", fmt.Errorf("could not decrypt the configuration for CA account %q: %w", acc.Name, err)
	}
	return plaintext, nil
}
