package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
)

// ── Fixtures ────────────────────────────────────────────────

func fixture(t *testing.T) (*Resolver, store.Store, string) {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemoryStore()

	// The sample store ships a BLOCK policy for RSA >= 2048. Left in place it
	// would be an unstated premise under every assertion here.
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

	return NewResolver(s, policy.NewEngine(s)), s, acc.ID
}

// unconstrained is what migration 037 generates: a template that permits what
// was permitted before templates existed.
func unconstrained(slug, accountID string) *store.CertificateTemplate {
	return &store.CertificateTemplate{
		Slug: slug, Name: slug, Version: 1, IsEnabled: true,
		CAAccountID:        accountID,
		SubjectMode:        store.SubjectModeSupplied,
		AllowedKeyTypes:    []string{"RSA", "ECDSA", "Ed25519"},
		ECDSACurves:        []string{"P-256", "P-384", "P-521"},
		KeyCustodyRequired: store.KeyCustodyAny,
		RenewBeforeDays:    30,
		AutoRenew:          true,
	}
}

func save(t *testing.T, s store.Store, tpl *store.CertificateTemplate) *store.CertificateTemplate {
	t.Helper()
	if err := s.CreateCertificateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	return tpl
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

// csrFor builds a real, signed signing request. A fabricated CSRInfo would not
// exercise the parser, and the parser is where proof of possession is checked.
func csrFor(t *testing.T, subject pkix.Name, dnsNames []string, ecdsaCurve elliptic.Curve) *x509util.CSRInfo {
	t.Helper()

	var key any
	var err error
	if ecdsaCurve != nil {
		key, err = ecdsa.GenerateKey(ecdsaCurve, rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: subject, DNSNames: dnsNames}, key)
	if err != nil {
		t.Fatal(err)
	}

	info, err := x509util.ParseCSRPEM(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: der,
	}))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// refusedBy asserts a resolve failed at a particular rung, with a message that
// explains why.
func refusedBy(t *testing.T, err error, rung, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal at the %s rung, got none", rung)
	}
	r, ok := AsRefusal(err)
	if !ok {
		t.Fatalf("expected a Refusal, got %T: %v", err, err)
	}
	if r.Rung != rung {
		t.Errorf("refused at the %q rung, expected %q: %v", r.Rung, rung, r.Message)
	}
	if !strings.Contains(r.Message, contains) {
		t.Errorf("the message does not explain the refusal, wanted %q in: %s", contains, r.Message)
	}
}

// ── Which template governs ──────────────────────────────────

func TestAnUnknownTemplateIsTheCallersMistake(t *testing.T) {
	r, _, accountID := fixture(t)
	_, err := r.Resolve(context.Background(), Request{
		TemplateRef: "no-such-thing", CAAccountID: accountID,
		CommonName: "a.example.com",
	})
	refusedBy(t, err, RungRequest, "no-such-thing")
}

func TestNamingNeitherATemplateNorAnAccountIsRefused(t *testing.T) {
	r, _, _ := fixture(t)
	_, err := r.Resolve(context.Background(), Request{CommonName: "a.example.com"})
	refusedBy(t, err, RungRequest, "nothing to issue under")
}

// TestARequestNamingNoTemplateBehavesAsItDidBefore is the compatibility path,
// and the reason migration 037 exists. A caller written before templates did
// must not notice them.
func TestARequestNamingNoTemplateBehavesAsItDidBefore(t *testing.T) {
	r, s, accountID := fixture(t)
	save(t, s, unconstrained(DefaultSlug(accountID), accountID))

	d, err := r.Resolve(context.Background(), Request{
		CAAccountID: accountID,
		CommonName:  "anything.at.all.example.com",
	})
	if err != nil {
		t.Fatalf("the compatibility path refused a request: %v", err)
	}
	if d.KeyType != "RSA" || d.KeySize != 2048 || d.ValidityDays != 90 {
		t.Errorf("the defaults changed: %s/%d for %d days, expected RSA/2048 for 90",
			d.KeyType, d.KeySize, d.ValidityDays)
	}
}

func TestADisabledTemplateIssuesNothing(t *testing.T) {
	r, s, accountID := fixture(t)
	tpl := unconstrained("retired", accountID)
	tpl.IsEnabled = false
	save(t, s, tpl)

	_, err := r.Resolve(context.Background(), Request{
		TemplateRef: "retired", CommonName: "a.example.com",
	})
	refusedBy(t, err, RungTemplate, "disabled")
}

func TestATemplateResolvesByEitherSlugOrID(t *testing.T) {
	r, s, accountID := fixture(t)
	tpl := save(t, s, unconstrained("by-name", accountID))

	for _, ref := range []string{"by-name", tpl.ID} {
		d, err := r.Resolve(context.Background(), Request{
			TemplateRef: ref, CommonName: "a.example.com",
		})
		if err != nil {
			t.Fatalf("ref %q: %v", ref, err)
		}
		if d.Template.ID != tpl.ID {
			t.Errorf("ref %q resolved to the wrong template", ref)
		}
	}
}

// TestTheTemplatePinsTheIssuerEvenWhenTheRequestNamesAnother.
//
// A requester who could choose an issuer could choose the cheapest, the least
// logged, or the one with the widest trust.
func TestTheTemplatePinsTheIssuerEvenWhenTheRequestNamesAnother(t *testing.T) {
	r, s, accountID := fixture(t)
	other := &store.CAAccount{
		Name: "Somewhere else", ProviderType: "acme",
		GatewayAddr: "127.0.0.1:9444", ConfigEncrypted: "sealed", Status: "CONNECTED",
	}
	if err := s.CreateCAAccount(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	save(t, s, unconstrained("pinned", accountID))

	d, err := r.Resolve(context.Background(), Request{
		TemplateRef: "pinned", CAAccountID: other.ID, CommonName: "a.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Account.ID != accountID {
		t.Errorf("the request chose its own issuer: got %s, template pins %s",
			d.Account.Name, accountID)
	}
}
