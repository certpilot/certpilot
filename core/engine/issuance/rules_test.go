package issuance

import (
	"context"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"testing"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/store"
)

// ── Rungs 6 and 5: the CSR, then the request ────────────────

// TestTheCSRDecidesTheNamesAndTheKey.
//
// Not a precedence preference — a fact. The request is signed, and the only key
// that can serve the resulting certificate is the one the requester already
// holds. Honouring a conflicting key_type from the JSON body would issue a
// certificate nobody can use.
func TestTheCSRDecidesTheNamesAndTheKey(t *testing.T) {
	r, s, accountID := fixture(t)
	save(t, s, unconstrained("any", accountID))

	csr := csrFor(t, pkix.Name{CommonName: "real.example.com"},
		[]string{"real.example.com", "also.example.com"}, elliptic.P384())

	d, err := r.Resolve(context.Background(), Request{
		TemplateRef: "any",
		CSR:         csr,
		// All of this contradicts the CSR and none of it may win.
		CommonName: "claimed.example.com",
		SANs:       []string{"invented.example.com"},
		KeyType:    "RSA",
		KeySize:    512,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.CommonName != "real.example.com" {
		t.Errorf("common name came from the body: %s", d.CommonName)
	}
	if len(d.Domains) != 2 {
		t.Errorf("names came from the body: %v", d.Domains)
	}
	if d.KeyType != "ECDSA" || d.KeySize != 384 {
		t.Errorf("the key came from the body: %s/%d", d.KeyType, d.KeySize)
	}
}

func TestWithoutACSRACommonNameIsRequired(t *testing.T) {
	r, s, accountID := fixture(t)
	save(t, s, unconstrained("any", accountID))

	_, err := r.Resolve(context.Background(), Request{TemplateRef: "any"})
	refusedBy(t, err, RungRequest, "common_name is required")
}

// TestANameRepeatedInTheSANsIsCountedOnce. CAB Forum rules require the common
// name to appear as a SAN, so nearly every client sends it twice — and the
// inventory reported "one extra name" for every certificate.
func TestANameRepeatedInTheSANsIsCountedOnce(t *testing.T) {
	r, s, accountID := fixture(t)
	save(t, s, unconstrained("any", accountID))

	d, err := r.Resolve(context.Background(), Request{
		TemplateRef: "any",
		CommonName:  "a.example.com",
		SANs:        []string{"A.EXAMPLE.COM", "b.example.com", "b.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Domains) != 2 {
		t.Errorf("names were not deduplicated case-insensitively: %v", d.Domains)
	}
}

// TestAnUnspecifiedKeyComesFromTheTemplateNotAConstant.
//
// A template permitting only ECDSA should not have RSA chosen for it by a
// hardcoded default and then refused one line later for being RSA.
func TestAnUnspecifiedKeyComesFromTheTemplateNotAConstant(t *testing.T) {
	r, s, accountID := fixture(t)
	tpl := unconstrained("ecdsa-only", accountID)
	tpl.AllowedKeyTypes = []string{"ECDSA"}
	tpl.ECDSACurves = []string{"P-384", "P-521"}
	save(t, s, tpl)

	d, err := r.Resolve(context.Background(), Request{
		TemplateRef: "ecdsa-only", CommonName: "a.example.com",
	})
	if err != nil {
		t.Fatalf("a request that named no key was refused: %v", err)
	}
	if d.KeyType != "ECDSA" {
		t.Errorf("key type defaulted to %s under an ECDSA-only template", d.KeyType)
	}
	if d.KeySize != 384 {
		t.Errorf("curve defaulted to P-%d; the least this template permits is P-384", d.KeySize)
	}
}

// ── Rung 2: what the template supplies ──────────────────────

func TestASuppliedLifetimeWinsAndSaysSo(t *testing.T) {
	r, s, accountID := fixture(t)
	tpl := unconstrained("ninety-days", accountID)
	tpl.ValidityDays = 90
	save(t, s, tpl)

	d, err := r.Resolve(context.Background(), Request{
		TemplateRef: "ninety-days", CommonName: "a.example.com", ValidityDays: 365,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.ValidityDays != 90 {
		t.Errorf("the request chose its own lifetime: %d", d.ValidityDays)
	}
	// AWS resolves this by ignoring the request silently. Somebody who asked
	// for 365 days and received 90 should be told which rule shortened it.
	if len(d.Overrides) != 1 {
		t.Fatalf("the override was not reported: %v", d.Overrides)
	}
}

func TestATemplatesDefaultsFillOnlyWhatTheRequestLeftEmpty(t *testing.T) {
	r, s, accountID := fixture(t)
	tpl := unconstrained("tagged", accountID)
	tpl.DefaultEnvironment = "production"
	tpl.DefaultTeam = "platform"
	tpl.DefaultTags = []string{"from-template"}
	save(t, s, tpl)

	d, err := r.Resolve(context.Background(), Request{
		TemplateRef: "tagged", CommonName: "a.example.com", Team: "payments",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Team != "payments" {
		t.Errorf("the template overwrote a team the request set: %s", d.Team)
	}
	if d.Environment != "production" {
		t.Errorf("the template default did not fill an empty environment: %q", d.Environment)
	}
}

// ── Rung 3: what the template constrains ────────────────────

func TestTheTemplateRefusesWhatItDoesNotPermit(t *testing.T) {
	ctx := context.Background()
	yes := true

	for _, tc := range []struct {
		name     string
		template func(*store.CertificateTemplate)
		request  func(*Request, *testing.T)
		contains string
	}{
		{
			name:     "a key type it does not issue",
			template: func(x *store.CertificateTemplate) { x.AllowedKeyTypes = []string{"ECDSA"} },
			request:  func(q *Request, _ *testing.T) { q.KeyType = "RSA"; q.KeySize = 4096 },
			contains: "key type RSA is not one template",
		},
		{
			name:     "an RSA key under its floor",
			template: func(x *store.CertificateTemplate) { x.RSAMinBits = 3072 },
			request:  func(q *Request, _ *testing.T) { q.KeyType = "RSA"; q.KeySize = 2048 },
			contains: "requires at least 3072",
		},
		{
			name:     "an RSA key over its ceiling",
			template: func(x *store.CertificateTemplate) { x.RSAMaxBits = 4096 },
			request:  func(q *Request, _ *testing.T) { q.KeyType = "RSA"; q.KeySize = 8192 },
			contains: "allows at most 4096",
		},
		{
			name:     "a curve it does not issue",
			template: func(x *store.CertificateTemplate) { x.ECDSACurves = []string{"P-384"} },
			request:  func(q *Request, _ *testing.T) { q.KeyType = "ECDSA"; q.KeySize = 256 },
			contains: "curve P-256 is not one template",
		},
		{
			name:     "a wildcard it never permitted",
			template: func(x *store.CertificateTemplate) {},
			request:  func(q *Request, _ *testing.T) { q.CommonName = "*.example.com" },
			contains: "wildcard name",
		},
		{
			name: "a name outside its zone",
			template: func(x *store.CertificateTemplate) {
				x.CommonNameRule.Suffixes = []string{"example.com"}
			},
			request:  func(q *Request, _ *testing.T) { q.CommonName = "a.elsewhere.net" },
			contains: "outside the suffixes",
		},
		{
			name: "a name that only looks like its zone",
			template: func(x *store.CertificateTemplate) {
				x.CommonNameRule.Suffixes = []string{"example.com"}
			},
			request:  func(q *Request, _ *testing.T) { q.CommonName = "evil-example.com" },
			contains: "outside the suffixes",
		},
		{
			name: "a forbidden word",
			template: func(x *store.CertificateTemplate) {
				x.CommonNameRule.ForbiddenPatterns = []string{"admin"}
			},
			request:  func(q *Request, _ *testing.T) { q.CommonName = "admin.example.com" },
			contains: "which template",
		},
		{
			name:     "more names than it allows",
			template: func(x *store.CertificateTemplate) { x.SANRules.MaxNames = 2 },
			request: func(q *Request, _ *testing.T) {
				q.SANs = []string{"b.example.com", "c.example.com"}
			},
			contains: "allows at most 2",
		},
		{
			name:     "a lifetime over its ceiling",
			template: func(x *store.CertificateTemplate) { x.MaxValidityDays = 90 },
			request:  func(q *Request, _ *testing.T) { q.ValidityDays = 365 },
			contains: "allows at most 90",
		},
		{
			name:     "no signing request where it requires one",
			template: func(x *store.CertificateTemplate) { x.CSRRequired = true },
			request:  func(q *Request, _ *testing.T) {},
			contains: "only against a signing request",
		},
		{
			name: "a key CertPilot would hold where it requires an agent",
			template: func(x *store.CertificateTemplate) {
				x.KeyCustodyRequired = store.KeyCustodyAgent
			},
			request:  func(q *Request, _ *testing.T) { q.KeyCustody = store.KeyCustodyCertPilot },
			contains: "held by AGENT",
		},
		{
			name: "a metadata field it requires and the request skipped",
			template: func(x *store.CertificateTemplate) {
				x.RequireMetadata = []string{"change_ticket"}
			},
			request:  func(q *Request, _ *testing.T) { q.MetadataKeys = []string{"cost_centre"} },
			contains: "change_ticket",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s, accountID := fixture(t)
			tpl := unconstrained("t", accountID)
			tc.template(tpl)
			save(t, s, tpl)

			req := Request{TemplateRef: "t", CommonName: "a.example.com"}
			tc.request(&req, t)

			_, err := r.Resolve(ctx, req)
			refusedBy(t, err, RungTemplate, tc.contains)
		})
	}

	// And the wildcard a template did permit goes through, or the pointer on
	// AllowWildcards buys nothing.
	t.Run("a wildcard it did permit", func(t *testing.T) {
		r, s, accountID := fixture(t)
		tpl := unconstrained("wild", accountID)
		tpl.SANRules.AllowWildcards = &yes
		save(t, s, tpl)

		if _, err := r.Resolve(ctx, Request{
			TemplateRef: "wild", CommonName: "*.example.com",
		}); err != nil {
			t.Fatalf("a template that permits wildcards refused one: %v", err)
		}
	})
}

// TestASuppliedSubjectCannotBeOverriddenByACSR is the ESC1 rung.
//
// CertPilot cannot strip a subject from a signed request — the CSR is passed to
// the CA as it stands, and rewriting it is not available without the private
// key. An override that silently did nothing would be a control that reports
// success while the CA issues whatever the requester asked for. Refusing is the
// only honest enforcement.
func TestASuppliedSubjectCannotBeOverriddenByACSR(t *testing.T) {
	r, s, accountID := fixture(t)
	tpl := unconstrained("supplied-subject", accountID)
	tpl.SubjectMode = store.SubjectModeSupplied
	tpl.SubjectDefaults = map[string]string{"O": "Example Ltd"}
	save(t, s, tpl)

	csr := csrFor(t, pkix.Name{
		CommonName:   "a.example.com",
		Organization: []string{"Somebody Else Entirely"},
	}, []string{"a.example.com"}, nil)

	_, err := r.Resolve(context.Background(), Request{TemplateRef: "supplied-subject", CSR: csr})
	refusedBy(t, err, RungTemplate, "Somebody Else Entirely")

	// The same request under a template that lets the requester set the
	// subject is fine. That is what CONSTRAINED means, and it is the setting an
	// operator has to choose deliberately.
	open := unconstrained("requester-subject", accountID)
	open.SubjectMode = store.SubjectModeConstrained
	open.SubjectDefaults = map[string]string{"O": "Example Ltd"}
	save(t, s, open)

	if _, err := r.Resolve(context.Background(), Request{
		TemplateRef: "requester-subject", CSR: csr,
	}); err != nil {
		t.Fatalf("a CONSTRAINED template refused a subject the requester may set: %v", err)
	}
}

// TestAMatchingSubjectIsNotARefusal. A CSR that asks for exactly what the
// template supplies is not in conflict with it.
func TestAMatchingSubjectIsNotARefusal(t *testing.T) {
	r, s, accountID := fixture(t)
	tpl := unconstrained("matching", accountID)
	tpl.SubjectDefaults = map[string]string{"O": "Example Ltd"}
	save(t, s, tpl)

	csr := csrFor(t, pkix.Name{
		CommonName: "a.example.com", Organization: []string{"Example Ltd"},
	}, []string{"a.example.com"}, nil)

	if _, err := r.Resolve(context.Background(), Request{TemplateRef: "matching", CSR: csr}); err != nil {
		t.Fatalf("a CSR agreeing with its template was refused: %v", err)
	}
}

// ── Rung 1: the floor ───────────────────────────────────────

// TestTheFloorStillRefusesWhatATemplatePermits. A template tightens; it never
// widens. Otherwise every template is a way around the estate's minimums.
func TestTheFloorStillRefusesWhatATemplatePermits(t *testing.T) {
	r, s, accountID := fixture(t)
	save(t, s, unconstrained("permissive", accountID))
	addPolicy(t, s, "RSA 3072 or better", policy.RuleKeySize,
		`{"rsa_min_bits": 3072}`, policy.SeverityBlock)

	_, err := r.Resolve(context.Background(), Request{
		TemplateRef: "permissive", CommonName: "a.example.com",
		KeyType: "RSA", KeySize: 2048,
	})
	refusedBy(t, err, RungPolicy, "RSA 3072 or better")
}

// TestAnAdvisoryFindingIsReportedAndNotRefused. A WARNING is advice. Refusing
// on it would make every advisory rule a hard constraint.
func TestAnAdvisoryFindingIsReportedAndNotRefused(t *testing.T) {
	r, s, accountID := fixture(t)
	save(t, s, unconstrained("permissive", accountID))
	addPolicy(t, s, "Prefer 3072", policy.RuleKeySize,
		`{"rsa_min_bits": 3072}`, policy.SeverityWarning)

	d, err := r.Resolve(context.Background(), Request{
		TemplateRef: "permissive", CommonName: "a.example.com",
		KeyType: "RSA", KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("a WARNING refused a request: %v", err)
	}
	if len(d.Violations) != 1 {
		t.Errorf("the advisory finding was dropped rather than reported: %v", d.Violations)
	}
}

// TestAPolicyThatCannotBeEvaluatedBlocks. Treating an evaluation failure as
// "no violations" means a database blip silently disables every policy at once.
func TestAPolicyThatCannotBeEvaluatedBlocks(t *testing.T) {
	r, s, accountID := fixture(t)
	save(t, s, unconstrained("permissive", accountID))
	// A rule type this build cannot evaluate. The engine reports it as a
	// violation rather than passing it, and at BLOCK it must stop the request.
	addPolicy(t, s, "Needs approval", "approval_required", `{}`, policy.SeverityBlock)

	_, err := r.Resolve(context.Background(), Request{
		TemplateRef: "permissive", CommonName: "a.example.com",
	})
	if err == nil {
		t.Fatal("a policy this build cannot evaluate was treated as satisfied")
	}
}
