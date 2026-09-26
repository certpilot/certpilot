package renewal

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/store"
)

func conformFixture(t *testing.T) (store.Store, *policy.Engine, string) {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemoryStore()

	existing, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range existing {
		if err := s.DeletePolicy(ctx, p.ID); err != nil {
			t.Fatal(err)
		}
	}

	acc := &store.CAAccount{
		Name: "Test CA", ProviderType: "selfsigned",
		GatewayAddr: "127.0.0.1:9443", ConfigEncrypted: "sealed", Status: "CONNECTED",
	}
	if err := s.CreateCAAccount(ctx, acc); err != nil {
		t.Fatal(err)
	}
	return s, policy.NewEngine(s), acc.ID
}

func templateFor(t *testing.T, s store.Store, accountID string, shape func(*store.CertificateTemplate)) *store.CertificateTemplate {
	t.Helper()
	tpl := &store.CertificateTemplate{
		Slug: "t", Name: "T", Version: 1, IsEnabled: true,
		CAAccountID:        accountID,
		SubjectMode:        store.SubjectModeSupplied,
		AllowedKeyTypes:    []string{"RSA", "ECDSA", "Ed25519"},
		ECDSACurves:        []string{"P-256", "P-384", "P-521"},
		KeyCustodyRequired: store.KeyCustodyAny,
		RenewBeforeDays:    30,
	}
	if shape != nil {
		shape(tpl)
	}
	if err := s.CreateCertificateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	return tpl
}

func certUnder(tpl *store.CertificateTemplate, keyType string, keySize int, names ...string) *store.Certificate {
	cert := &store.Certificate{
		ID: "cert-1", CommonName: names[0], SANs: names[1:],
		KeyType: keyType, KeySize: keySize, Status: "ISSUED",
	}
	if tpl != nil {
		id, version := tpl.ID, tpl.Version
		cert.TemplateID, cert.TemplateVersion = &id, &version
	}
	return cert
}

func addPolicy(t *testing.T, s store.Store, name, ruleType, config, severity string) {
	t.Helper()
	err := s.CreatePolicy(context.Background(), &store.Policy{
		Name: name, IsEnabled: true, RuleType: ruleType,
		RuleConfig: config, Severity: severity,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ── Renewing into conformance ───────────────────────────────

// TestRenewalRaisesAKeyToWhatTheTemplateNowRequires is the point of this whole
// change.
//
// Renewal generates the key — RenewCertificateRequest carries no CSR — so a
// raised floor is something it can act on rather than only report. Before this
// it built the request from the row, so an RSA-1024 certificate renewed as
// RSA-1024 for ever and tightening a rule reached nothing already issued.
func TestRenewalRaisesAKeyToWhatTheTemplateNowRequires(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	tpl := templateFor(t, s, accountID, func(x *store.CertificateTemplate) {
		x.RSAMinBits = 3072
	})

	got, err := conform(context.Background(), s, eng, certUnder(tpl, "RSA", 1024, "a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got.KeySize != 3072 {
		t.Errorf("renewal asked for RSA %d; the template requires at least 3072", got.KeySize)
	}
	if len(got.Upgrades) != 1 || !strings.Contains(got.Upgrades[0], "1024") {
		t.Errorf("the upgrade was not recorded: %v", got.Upgrades)
	}
}

// TestRenewalNeverDowngrades.
//
// Asking a template for a key with the fields left empty yields its *minimum*.
// An RSA-4096 certificate under a template whose floor is 2048 must not be
// rekeyed weaker on its next renewal — which is what a naive "ask the template
// what it wants" implementation does, and it looks like progress.
func TestRenewalNeverDowngrades(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	tpl := templateFor(t, s, accountID, func(x *store.CertificateTemplate) {
		x.RSAMinBits = 2048
	})

	got, err := conform(context.Background(), s, eng, certUnder(tpl, "RSA", 4096, "a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got.KeySize != 4096 {
		t.Errorf("a 4096-bit key was rekeyed to %d under a 2048 floor", got.KeySize)
	}
	if len(got.Upgrades) != 0 {
		t.Errorf("nothing changed, so nothing should have been reported: %v", got.Upgrades)
	}
}

// TestAConformingCertificateKeepsExactlyTheKeyItHas.
//
// Rotating RSA to ECDSA on a renewal that did not need it is a change nobody
// asked for, and some endpoint will not survive it.
func TestAConformingCertificateKeepsExactlyTheKeyItHas(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	// ECDSA is listed, and would be chosen first by a "pick the best" rule.
	tpl := templateFor(t, s, accountID, func(x *store.CertificateTemplate) {
		x.AllowedKeyTypes = []string{"ECDSA", "RSA"}
	})

	got, err := conform(context.Background(), s, eng, certUnder(tpl, "RSA", 2048, "a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyType != "RSA" || got.KeySize != 2048 {
		t.Errorf("a conforming certificate was changed to %s/%d", got.KeyType, got.KeySize)
	}
	if len(got.Upgrades)+len(got.Unfixable) != 0 {
		t.Errorf("a conforming certificate produced findings: %v %v", got.Upgrades, got.Unfixable)
	}
}

// TestAForbiddenKeyTypeMovesToOneTheTemplateIssues. The one case where changing
// the algorithm is what the operator asked for, by writing the template.
func TestAForbiddenKeyTypeMovesToOneTheTemplateIssues(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	tpl := templateFor(t, s, accountID, func(x *store.CertificateTemplate) {
		x.AllowedKeyTypes = []string{"ECDSA"}
		x.ECDSACurves = []string{"P-384", "P-521"}
	})

	got, err := conform(context.Background(), s, eng, certUnder(tpl, "RSA", 2048, "a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyType != "ECDSA" {
		t.Errorf("key type stayed %s under an ECDSA-only template", got.KeyType)
	}
	// The least the template permits, not the most: moving the key is already a
	// change, and moving it further than the rules require is a second one.
	if got.KeySize != 384 {
		t.Errorf("curve chosen was P-%d; the least this template permits is P-384", got.KeySize)
	}
}

// ── What renewal cannot fix ─────────────────────────────────

// TestANameOutsideATightenedRuleIsReportedAndStillRenewed.
//
// Renewal reissues for the names the certificate already carries and cannot
// drop one — the endpoints serving it expect every name it has. Refusing would
// convert a policy tightening into an outage, which is how people learn to
// switch automation off.
func TestANameOutsideATightenedRuleIsReportedAndStillRenewed(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	tpl := templateFor(t, s, accountID, func(x *store.CertificateTemplate) {
		x.CommonNameRule.Suffixes = []string{"internal.example.com"}
	})

	got, err := conform(context.Background(), s, eng,
		certUnder(tpl, "RSA", 2048, "legacy.partner.net"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Unfixable) == 0 {
		t.Fatal("a name outside the template's suffixes was not reported")
	}
	if !strings.Contains(got.Unfixable[0], "legacy.partner.net") {
		t.Errorf("the finding does not name the offending name: %v", got.Unfixable)
	}
	// And it is still renewable — the key came back, not an error.
	if got.KeyType != "RSA" || got.KeySize != 2048 {
		t.Errorf("the certificate was not renewable: %s/%d", got.KeyType, got.KeySize)
	}
}

// ── The floor, on certificates that predate templates ───────

// TestTheFloorReachesACertificateWithNoTemplate.
//
// Most of an inventory predates templates — discovered, imported, issued before
// migration 036. Exempting all of it would mean a policy change governs only
// certificates that do not exist yet, which is the defect this issue was
// written about.
func TestTheFloorReachesACertificateWithNoTemplate(t *testing.T) {
	s, eng, _ := conformFixture(t)
	addPolicy(t, s, "RSA 3072 or better", policy.RuleKeySize,
		`{"rsa_min_bits": 3072}`, policy.SeverityBlock)

	got, err := conform(context.Background(), s, eng,
		certUnder(nil, "RSA", 1024, "ancient.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Unfixable) == 0 {
		t.Fatal("a certificate with no template was not judged against the floor")
	}
	if !strings.Contains(got.Unfixable[0], "RSA 3072 or better") {
		t.Errorf("the finding does not name the policy: %v", got.Unfixable)
	}
}

// TestAdvisoryPoliciesAreNotFindings. A WARNING is advice about a request.
// Reporting every one on every renewal would bury the BLOCK that matters.
func TestAdvisoryPoliciesAreNotFindings(t *testing.T) {
	s, eng, _ := conformFixture(t)
	addPolicy(t, s, "Prefer 3072", policy.RuleKeySize,
		`{"rsa_min_bits": 3072}`, policy.SeverityWarning)

	got, err := conform(context.Background(), s, eng,
		certUnder(nil, "RSA", 2048, "a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Unfixable) != 0 {
		t.Errorf("a WARNING was reported as a conformance failure: %v", got.Unfixable)
	}
}

// TestTheTemplateUpgradeIsJudgedNotTheOldKey.
//
// The floor is evaluated on the key renewal is about to ask for. Judging the
// key the certificate currently has would report a violation the template had
// already fixed one line earlier.
func TestTheTemplateUpgradeIsJudgedNotTheOldKey(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	tpl := templateFor(t, s, accountID, func(x *store.CertificateTemplate) {
		x.RSAMinBits = 4096
	})
	addPolicy(t, s, "RSA 3072 or better", policy.RuleKeySize,
		`{"rsa_min_bits": 3072}`, policy.SeverityBlock)

	got, err := conform(context.Background(), s, eng, certUnder(tpl, "RSA", 1024, "a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got.KeySize != 4096 {
		t.Errorf("the template floor was not applied: %d", got.KeySize)
	}
	if len(got.Unfixable) != 0 {
		t.Errorf("the floor was judged against the old key, not the new one: %v", got.Unfixable)
	}
}

// TestADeletedTemplateDoesNotStopRenewal. A template removed out from under a
// certificate is not a reason to let it expire.
func TestADeletedTemplateDoesNotStopRenewal(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	tpl := templateFor(t, s, accountID, nil)
	cert := certUnder(tpl, "RSA", 2048, "a.example.com")
	if err := s.DeleteCertificateTemplate(context.Background(), tpl.ID); err != nil {
		t.Fatal(err)
	}

	got, err := conform(context.Background(), s, eng, cert)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyType != "RSA" || got.KeySize != 2048 {
		t.Errorf("a certificate whose template is gone was not renewable: %s/%d", got.KeyType, got.KeySize)
	}
}

// TestARenewalRecordsTheVersionItConformedTo.
//
// Found by running it. A renewal is an issuance: the certificate now on disk
// was produced under the template as it stands, not as it stood when the
// original was signed. Leaving the old version behind makes an auditor read a
// conforming certificate as a stale one — the opposite of what the field is
// for.
func TestARenewalRecordsTheVersionItConformedTo(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	tpl := templateFor(t, s, accountID, func(x *store.CertificateTemplate) {
		x.RSAMinBits = 2048
	})
	cert := certUnder(tpl, "RSA", 2048, "a.example.com")

	// The operator tightens the template. Version moves with the rules.
	tpl.RSAMinBits = 4096
	tpl.Version = 2
	if err := s.UpdateCertificateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}

	got, err := conform(context.Background(), s, eng, cert)
	if err != nil {
		t.Fatal(err)
	}
	if got.TemplateVersion == nil {
		t.Fatal("the version judged against was not recorded")
	}
	if *got.TemplateVersion != 2 {
		t.Errorf("recorded version %d; the renewal was judged against 2", *got.TemplateVersion)
	}
	if got.KeySize != 4096 {
		t.Errorf("the tightened floor was not applied: %d", got.KeySize)
	}
}

// TestACertificateWithNoTemplateRecordsNoVersion. Nil must not reach the store
// as a value — the UPDATE COALESCEs it, and a zero would be a version that
// never existed.
func TestACertificateWithNoTemplateRecordsNoVersion(t *testing.T) {
	s, eng, _ := conformFixture(t)

	got, err := conform(context.Background(), s, eng, certUnder(nil, "RSA", 2048, "a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got.TemplateVersion != nil {
		t.Errorf("a certificate with no template reported version %v", *got.TemplateVersion)
	}
}

// TestRenewalDoesNotCountTheCommonNameTwice.
//
// Found by running it: the finding came back duplicated, and the same cause
// meant the gateway was sent the same name twice. CAB Forum rules require the
// common name to appear as a SAN, so an issued certificate carries it in both
// fields — issuance has deduplicated since the inventory started reporting "one
// extra name" on every certificate, and renewal never did.
func TestRenewalDoesNotCountTheCommonNameTwice(t *testing.T) {
	s, eng, accountID := conformFixture(t)
	tpl := templateFor(t, s, accountID, func(x *store.CertificateTemplate) {
		x.CommonNameRule.Suffixes = []string{"internal.example.com"}
	})

	cert := certUnder(tpl, "RSA", 2048, "a.example.com")
	// What an issued certificate actually looks like: the CN repeated in the
	// SANs, in a different case, with a trailing dot for good measure.
	cert.SANs = []string{"a.example.com", "A.Example.com."}

	got, err := conform(context.Background(), s, eng, cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Domains) != 1 {
		t.Errorf("one name came through as %v", got.Domains)
	}
	if len(got.Unfixable) != 1 {
		t.Errorf("one naming problem was reported %d times: %v", len(got.Unfixable), got.Unfixable)
	}
}

// A lifetime read off a certificate is rounded, not truncated. Let's Encrypt
// ends a 90-day certificate one second short of 90 days; truncating asked for
// 89 on its renewal, and a day shorter again on the one after (#102).
func TestTheLifetimeReadOffACertificateIsRounded(t *testing.T) {
	notBefore := time.Date(2026, 9, 22, 21, 30, 7, 0, time.UTC)
	for _, tc := range []struct {
		lifetime time.Duration
		want     int
	}{
		{90*24*time.Hour - time.Second, 90},
		{90*24*time.Hour + 30*time.Second, 90},
		{6*24*time.Hour - time.Second, 6},
		{47 * 24 * time.Hour, 47},
	} {
		notAfter := notBefore.Add(tc.lifetime)
		cert := &store.Certificate{NotBefore: &notBefore, NotAfter: &notAfter}
		if got := validityOrDefault(0, cert); got != tc.want {
			t.Errorf("lifetime %v: asked for %d days, want %d", tc.lifetime, got, tc.want)
		}
	}
}
