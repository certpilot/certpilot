package api

import (
	"context"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/store"
)

// templateFixture returns a handler over a store with one CA account and no
// policies, so each test states its own floor.
func templateFixture(t *testing.T) (*TemplateHandler, store.Store, string) {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemoryStore()

	// The sample store ships a BLOCK policy for RSA >= 2048. Useful demo data,
	// and a hidden premise in every assertion below if it stays.
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

	return NewTemplateHandler(s, policy.NewEngine(s)), s, acc.ID
}

func addPolicy(t *testing.T, s store.Store, name, ruleType, config, severity string) {
	t.Helper()
	p := &store.Policy{
		Name: name, IsEnabled: true, RuleType: ruleType,
		RuleConfig: config, Severity: severity,
	}
	if err := s.CreatePolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

func minimalTemplate(accountID string) store.CertificateTemplate {
	return store.CertificateTemplate{
		Slug: "t", Name: "T", Version: 1, IsEnabled: true,
		CAAccountID:        accountID,
		SubjectMode:        store.SubjectModeSupplied,
		AllowedKeyTypes:    []string{"RSA", "ECDSA", "Ed25519"},
		KeyCustodyRequired: store.KeyCustodyAny,
		RenewBeforeDays:    30,
	}
}

// ── The template against itself ─────────────────────────────

func TestATemplateThatContradictsItselfIsRefused(t *testing.T) {
	_, _, accountID := templateFixture(t)

	for _, tc := range []struct {
		name   string
		mutate func(*store.CertificateTemplate)
		expect string
	}{
		{
			name:   "a supplied validity above its own ceiling",
			mutate: func(x *store.CertificateTemplate) { x.ValidityDays = 400; x.MaxValidityDays = 90 },
			expect: "exceeds the ceiling",
		},
		{
			name:   "an RSA range with no room in it",
			mutate: func(x *store.CertificateTemplate) { x.RSAMinBits = 4096; x.RSAMaxBits = 2048 },
			expect: "no RSA key could satisfy both",
		},
		{
			name:   "no key type at all",
			mutate: func(x *store.CertificateTemplate) { x.AllowedKeyTypes = nil },
			expect: "permits no key at all",
		},
		{
			name:   "a key type this build cannot issue",
			mutate: func(x *store.CertificateTemplate) { x.AllowedKeyTypes = []string{"DSA"} },
			expect: "not a key type this build can issue",
		},
		{
			name: "a CSR whose key CertPilot is also required to hold",
			mutate: func(x *store.CertificateTemplate) {
				x.CSRRequired = true
				x.KeyCustodyRequired = store.KeyCustodyCertPilot
			},
			expect: "cannot both be true",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := minimalTemplate(accountID)
			tc.mutate(&tpl)
			err := validateTemplateShape(&tpl)
			if err == nil {
				t.Fatal("a contradictory template was accepted")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("the message does not explain the contradiction: %v", err)
			}
		})
	}
}

// ── The template against the floor ──────────────────────────

// TestATemplateThatCouldNeverIssueAnythingIsRefused is the save-time check.
//
// Google's docs acknowledge that a template and a CA-pool policy can conflict
// and send the reader elsewhere to resolve it, which means the conflict
// surfaces on the day somebody needed a certificate. This is the same conflict,
// reported while the operator is still looking at the form.
func TestATemplateThatCouldNeverIssueAnythingIsRefused(t *testing.T) {
	h, s, accountID := templateFixture(t)
	addPolicy(t, s, "P-384 or better", policy.RuleKeySize,
		`{"ecdsa_min_bits": 384}`, policy.SeverityBlock)

	tpl := minimalTemplate(accountID)
	tpl.AllowedKeyTypes = []string{"ECDSA"}
	tpl.ECDSACurves = []string{"P-256"}

	err := h.validate(context.Background(), &tpl)
	if err == nil {
		t.Fatal("a template whose only permitted key the floor refuses was accepted")
	}
	if !strings.Contains(err.Error(), "could never issue a certificate") {
		t.Errorf("the message does not say what is wrong: %v", err)
	}
	// The operator has to be told which rule, not just that there was one.
	if !strings.Contains(err.Error(), "P-384 or better") {
		t.Errorf("the message does not name the policy that refused it: %v", err)
	}
}

// TestOnePermittedKeyGettingThroughIsEnough. A template offering P-256 and
// P-384 under a P-384 floor can issue: the floor judges each request, and P-384
// requests pass. Refusing the template would be refusing a working
// configuration.
func TestOnePermittedKeyGettingThroughIsEnough(t *testing.T) {
	h, s, accountID := templateFixture(t)
	addPolicy(t, s, "P-384 or better", policy.RuleKeySize,
		`{"ecdsa_min_bits": 384}`, policy.SeverityBlock)

	tpl := minimalTemplate(accountID)
	tpl.AllowedKeyTypes = []string{"ECDSA"}
	tpl.ECDSACurves = []string{"P-256", "P-384"}

	if err := h.validate(context.Background(), &tpl); err != nil {
		t.Fatalf("a template that can issue P-384 was refused: %v", err)
	}
}

// TestOnlyABlockPolicyRefusesATemplate. A WARNING is advice about a request.
// Treating it as a reason to refuse a template would make every advisory rule
// a hard constraint, which is the opposite of what the severity means.
func TestOnlyABlockPolicyRefusesATemplate(t *testing.T) {
	h, s, accountID := templateFixture(t)
	addPolicy(t, s, "Prefer P-384", policy.RuleKeySize,
		`{"ecdsa_min_bits": 384}`, policy.SeverityWarning)

	tpl := minimalTemplate(accountID)
	tpl.AllowedKeyTypes = []string{"ECDSA"}
	tpl.ECDSACurves = []string{"P-256"}

	if err := h.validate(context.Background(), &tpl); err != nil {
		t.Fatalf("a WARNING policy refused a template: %v", err)
	}
}

// TestATemplateWithNoNameRulesIsNotJudgedOnAPlaceholder.
//
// A template that says nothing about names permits every name, so some name
// always satisfies a naming policy and the template is usable. Judging the
// probe's placeholder would refuse a perfectly good template because of a
// hostname this code made up.
func TestATemplateWithNoNameRulesIsNotJudgedOnAPlaceholder(t *testing.T) {
	h, s, accountID := templateFixture(t)
	addPolicy(t, s, "Our zone only", policy.RuleNaming,
		`{"allowed_suffixes": ["corp.internal"]}`, policy.SeverityBlock)

	tpl := minimalTemplate(accountID)

	if err := h.validate(context.Background(), &tpl); err != nil {
		t.Fatalf("a template with no name rules was refused over a placeholder name: %v", err)
	}
}

// TestATemplateBoundToNamesTheFloorForbidsIsRefused is the other half. Here the
// template has named a zone, and every name it permits is outside the one the
// policy allows — so it genuinely cannot issue anything.
func TestATemplateBoundToNamesTheFloorForbidsIsRefused(t *testing.T) {
	h, s, accountID := templateFixture(t)
	addPolicy(t, s, "Our zone only", policy.RuleNaming,
		`{"allowed_suffixes": ["corp.internal"]}`, policy.SeverityBlock)

	tpl := minimalTemplate(accountID)
	tpl.CommonNameRule.Suffixes = []string{"partner.example.com"}

	err := h.validate(context.Background(), &tpl)
	if err == nil {
		t.Fatal("a template restricted to names the floor forbids was accepted")
	}
	if !strings.Contains(err.Error(), "Our zone only") {
		t.Errorf("the message does not name the policy that refused it: %v", err)
	}
}

// TestARequiredMetadataKeyMustExist. A required field under a misspelled key is
// a requirement no form will show and no request can satisfy — the same defect
// validateMetadata refuses on a certificate, refused here on the template that
// would have demanded it.
func TestARequiredMetadataKeyMustExist(t *testing.T) {
	h, _, accountID := templateFixture(t)

	tpl := minimalTemplate(accountID)
	tpl.RequireMetadata = []string{"cost_center"} // the field, if any, is cost_centre

	err := h.validate(context.Background(), &tpl)
	if err == nil {
		t.Fatal("a template requiring an undefined metadata field was accepted")
	}
	if !strings.Contains(err.Error(), "cost_center") {
		t.Errorf("the message does not name the offending key: %v", err)
	}
}

// TestAnUnknownCAAccountIsRefusedByName. The foreign key would catch this and
// would report a constraint name.
func TestAnUnknownCAAccountIsRefusedByName(t *testing.T) {
	h, _, _ := templateFixture(t)

	tpl := minimalTemplate("00000000-0000-0000-0000-000000000000")
	err := h.validate(context.Background(), &tpl)
	if err == nil {
		t.Fatal("a template pointing at no CA account was accepted")
	}
	if !strings.Contains(err.Error(), "ca_account_id") {
		t.Errorf("the message does not say which field is wrong: %v", err)
	}
}

// ── Versioning ──────────────────────────────────────────────

// TestRenamingATemplateDoesNotBumpItsVersion.
//
// Certificates record the version they were issued under. A version that moved
// when somebody fixed a typo in the description makes "issued under version 3"
// mean nothing, and the audit question it exists to answer — what were the
// rules at the time — becomes unanswerable.
func TestRenamingATemplateDoesNotBumpItsVersion(t *testing.T) {
	_, _, accountID := templateFixture(t)

	before := minimalTemplate(accountID)
	after := before
	after.Name = "A clearer name"
	after.Description = "A better explanation"

	if rulesDiffer(&before, &after) {
		t.Error("a rename counted as a rule change")
	}
}

func TestChangingWhatATemplatePermitsBumpsItsVersion(t *testing.T) {
	_, _, accountID := templateFixture(t)
	yes := true

	for _, tc := range []struct {
		name   string
		mutate func(*store.CertificateTemplate)
	}{
		{"a key type removed", func(x *store.CertificateTemplate) { x.AllowedKeyTypes = []string{"ECDSA"} }},
		{"an RSA floor raised", func(x *store.CertificateTemplate) { x.RSAMinBits = 3072 }},
		{"a lifetime shortened", func(x *store.CertificateTemplate) { x.ValidityDays = 47 }},
		{"a name suffix added", func(x *store.CertificateTemplate) { x.CommonNameRule.Suffixes = []string{"example.com"} }},
		{"wildcards decided", func(x *store.CertificateTemplate) { x.SANRules.AllowWildcards = &yes }},
		{"the subject opened to the requester", func(x *store.CertificateTemplate) { x.SubjectMode = store.SubjectModeConstrained }},
		{"the issuer moved", func(x *store.CertificateTemplate) { x.CAAccountID = "somewhere-else" }},
		{"the CA profile changed", func(x *store.CertificateTemplate) { x.CAProfile = "shortlived" }},
		{"custody asserted", func(x *store.CertificateTemplate) { x.KeyCustodyRequired = store.KeyCustodyAgent }},
		{"a metadata field required", func(x *store.CertificateTemplate) { x.RequireMetadata = []string{"cost_centre"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := minimalTemplate(accountID)
			after := minimalTemplate(accountID)
			tc.mutate(&after)
			if !rulesDiffer(&before, &after) {
				t.Error("a change to what this template permits did not count as a rule change")
			}
		})
	}
}

// TestAnEmptySliceAndAnAbsentOneAreTheSameRule. A round trip through the store
// turns nil into []. If that counted as a rule change, every save would bump
// the version and the counter would stop meaning anything.
func TestAnEmptySliceAndAnAbsentOneAreTheSameRule(t *testing.T) {
	_, _, accountID := templateFixture(t)

	before := minimalTemplate(accountID)
	before.DefaultTags = nil
	before.SubjectDefaults = nil

	after := minimalTemplate(accountID)
	after.DefaultTags = []string{}
	after.SubjectDefaults = map[string]string{}

	if rulesDiffer(&before, &after) {
		t.Error("an empty slice was treated as different from an absent one")
	}
}

// ── Defaults ────────────────────────────────────────────────

// TestOmittingTheKeyTypesPermitsAllThree.
//
// This was wrong in the first cut and only live testing found it. The refusal
// message for an empty allowed_key_types says "omit the field to permit all
// three", and omitting it produced exactly that refusal: the input struct
// passed the caller's nil through, so the INSERT wrote an empty list instead of
// letting the column default apply. Advice that produces the error it was meant
// to avoid.
func TestOmittingTheKeyTypesPermitsAllThree(t *testing.T) {
	h, _, accountID := templateFixture(t)

	in := TemplateInput{Slug: "defaults", Name: "Defaults", CAAccountID: accountID}
	tpl := in.template()

	if len(tpl.AllowedKeyTypes) != 3 {
		t.Errorf("omitting allowed_key_types gave %v, wanted all three", tpl.AllowedKeyTypes)
	}
	if len(tpl.ECDSACurves) != 3 {
		t.Errorf("omitting ecdsa_curves gave %v, wanted all three", tpl.ECDSACurves)
	}
	if err := h.validate(context.Background(), &tpl); err != nil {
		t.Fatalf("a template that omitted the optional key fields was refused: %v", err)
	}
}

// TestASlugMustBeUsableAsAMachineName. The pattern lives on the column too, and
// reaching it produces a raw SQLSTATE 23514 naming a constraint — which tells
// an operator nothing about what a slug may contain.
func TestASlugMustBeUsableAsAMachineName(t *testing.T) {
	_, _, accountID := templateFixture(t)

	for _, slug := range []string{"BAD Slug", "has spaces", "Uppercase", "9-leading-digit", "", "-leading-hyphen", "trailing_underscore"} {
		tpl := minimalTemplate(accountID)
		tpl.Slug = slug
		err := validateTemplateShape(&tpl)
		if err == nil {
			t.Errorf("slug %q was accepted", slug)
			continue
		}
		if !strings.Contains(err.Error(), "machine name") {
			t.Errorf("slug %q: the message does not explain the rule: %v", slug, err)
		}
	}

	for _, slug := range []string{"a", "internal-mtls", "public-tls-90d"} {
		tpl := minimalTemplate(accountID)
		tpl.Slug = slug
		if err := validateTemplateShape(&tpl); err != nil {
			t.Errorf("slug %q should be usable: %v", slug, err)
		}
	}
}

// TestATemplateAGrantStillNamesCannotBeDeleted.
//
// Found by running it: the delete reached the foreign key and came back as
// `SQLSTATE 23503 … template_grants_template_id_fkey`, which names a constraint
// and not a thing an operator can act on. The restrict is deliberate — a rule
// that vanished when somebody removed a template would take an estate's
// permissions with it — so the fix is the message, not the constraint.
//
// A *revoked* grant still references its template, and that is the case that
// produced the raw error: the grant looked gone and was not.
func TestATemplateAGrantStillNamesCannotBeDeleted(t *testing.T) {
	h, s, accountID := templateFixture(t)
	ctx := context.Background()

	tpl := minimalTemplate(accountID)
	tpl.Slug = "spoken-for"
	if err := s.CreateCertificateTemplate(ctx, &tpl); err != nil {
		t.Fatal(err)
	}

	agentID := "some-agent"
	grant := &store.TemplateGrant{
		Name: "web tier", TemplateID: tpl.ID, SubjectKind: store.GrantSubjectAgent,
		AgentID: &agentID, Names: []string{"a.example.com"}, IsEnabled: true,
	}
	if err := s.CreateTemplateGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}

	blocking, err := h.grantsUsing(ctx, tpl.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocking) != 1 || blocking[0] != "web tier" {
		t.Fatalf("the grant holding this template was not found: %v", blocking)
	}

	// Revoked, and it still counts — which is the whole point.
	if err := s.RevokeTemplateGrant(ctx, grant.ID, nil); err != nil {
		t.Fatal(err)
	}
	blocking, err = h.grantsUsing(ctx, tpl.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocking) != 1 {
		t.Errorf("a revoked grant stopped counting, and it still references the template: %v", blocking)
	}
}
