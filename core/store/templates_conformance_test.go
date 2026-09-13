package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// caAccountFor creates the account a template has to point at.
//
// The foreign key is `on delete restrict`, so a template cannot exist without
// one, and a test that invented an id would pass in memory and fail against
// PostgreSQL — which is the whole class of defect this file exists to catch.
func caAccountFor(t *testing.T, s Store, name string) string {
	t.Helper()
	acc := &CAAccount{
		Name:            name,
		ProviderType:    "selfsigned",
		GatewayAddr:     "127.0.0.1:9443",
		ConfigEncrypted: "sealed",
		Status:          "CONNECTED",
	}
	if err := s.CreateCAAccount(context.Background(), acc); err != nil {
		t.Fatalf("creating the CA account this template needs: %v", err)
	}
	return acc.ID
}

// fullTemplate sets every field a caller owns to something distinguishable, so
// a writer that drops one is visible rather than plausible.
func fullTemplate(slug, accountID string) *CertificateTemplate {
	required := true
	allowWildcards := false
	return &CertificateTemplate{
		Slug:        slug,
		Name:        "Internal mTLS",
		Description: "Service mesh identities, issued to the host that will hold the key",
		Version:     1,
		IsEnabled:   true,

		CAAccountID: accountID,
		CAProfile:   "internal-mtls",

		SubjectMode:     SubjectModeConstrained,
		SubjectDefaults: map[string]string{"O": "Example Ltd", "OU": "Platform", "C": "GB"},
		CommonNameRule: CommonNameRule{
			Required:          &required,
			Suffixes:          []string{"internal.example.com"},
			ForbiddenPatterns: []string{"admin", "root"},
		},
		SANRules: SANRules{
			Types:          []string{"DNS", "IP"},
			Suffixes:       []string{"internal.example.com"},
			AllowWildcards: &allowWildcards,
			MaxNames:       8,
		},

		AllowedKeyTypes:    []string{"ECDSA", "Ed25519"},
		RSAMinBits:         3072,
		RSAMaxBits:         8192,
		ECDSACurves:        []string{"P-256", "P-384"},
		CSRRequired:        true,
		KeyCustodyRequired: KeyCustodyAgent,

		ValidityDays:    90,
		MaxValidityDays: 180,
		RenewBeforeDays: 21,
		AutoRenew:       false,

		RequireMetadata:    []string{"cost_centre", "change_ticket"},
		DefaultEnvironment: "production",
		DefaultTeam:        "platform",
		DefaultTags:        []string{"mesh", "internal"},
	}
}

// compareTemplates reports every field that did not survive a round trip.
func compareTemplates(t *testing.T, stage string, want, got *CertificateTemplate) {
	t.Helper()
	for _, field := range []struct {
		name       string
		want, have any
	}{
		{"slug", want.Slug, got.Slug},
		{"name", want.Name, got.Name},
		{"description", want.Description, got.Description},
		{"version", want.Version, got.Version},
		{"is_enabled", want.IsEnabled, got.IsEnabled},
		{"ca_account_id", want.CAAccountID, got.CAAccountID},
		{"ca_profile", want.CAProfile, got.CAProfile},
		{"subject_mode", want.SubjectMode, got.SubjectMode},
		{"subject_defaults", fmt.Sprint(want.SubjectDefaults), fmt.Sprint(got.SubjectDefaults)},
		{"common_name_rule.suffixes", fmt.Sprint(want.CommonNameRule.Suffixes), fmt.Sprint(got.CommonNameRule.Suffixes)},
		{"common_name_rule.forbidden_patterns", fmt.Sprint(want.CommonNameRule.ForbiddenPatterns), fmt.Sprint(got.CommonNameRule.ForbiddenPatterns)},
		{"san_rules.types", fmt.Sprint(want.SANRules.Types), fmt.Sprint(got.SANRules.Types)},
		{"san_rules.suffixes", fmt.Sprint(want.SANRules.Suffixes), fmt.Sprint(got.SANRules.Suffixes)},
		{"san_rules.max_names", want.SANRules.MaxNames, got.SANRules.MaxNames},
		{"allowed_key_types", fmt.Sprint(want.AllowedKeyTypes), fmt.Sprint(got.AllowedKeyTypes)},
		{"rsa_min_bits", want.RSAMinBits, got.RSAMinBits},
		{"rsa_max_bits", want.RSAMaxBits, got.RSAMaxBits},
		{"ecdsa_curves", fmt.Sprint(want.ECDSACurves), fmt.Sprint(got.ECDSACurves)},
		{"csr_required", want.CSRRequired, got.CSRRequired},
		{"key_custody_required", want.KeyCustodyRequired, got.KeyCustodyRequired},
		{"validity_days", want.ValidityDays, got.ValidityDays},
		{"max_validity_days", want.MaxValidityDays, got.MaxValidityDays},
		{"renew_before_days", want.RenewBeforeDays, got.RenewBeforeDays},
		{"auto_renew", want.AutoRenew, got.AutoRenew},
		{"require_metadata", fmt.Sprint(want.RequireMetadata), fmt.Sprint(got.RequireMetadata)},
		{"default_environment", want.DefaultEnvironment, got.DefaultEnvironment},
		{"default_team", want.DefaultTeam, got.DefaultTeam},
		{"default_tags", fmt.Sprint(want.DefaultTags), fmt.Sprint(got.DefaultTags)},
	} {
		if fmt.Sprint(field.want) != fmt.Sprint(field.have) {
			t.Errorf("%s: %s was dropped: wrote %v, read back %v",
				stage, field.name, field.want, field.have)
		}
	}
}

// TestACertificateTemplateKeepsEveryFieldItWasGiven is the Class B assertion
// for the newest model: a field a writer silently drops round-trips in memory
// and vanishes against PostgreSQL.
//
// A template has twenty-eight columns and seven of them are jsonb. The four
// places a column must be touched — the SELECT list, the scanner, the INSERT
// and the UPDATE — all look correct in isolation while any one of them is
// missing, and the value is gone.
func TestACertificateTemplateKeepsEveryFieldItWasGiven(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		accountID := caAccountFor(t, s, "round-trip CA")

		tpl := fullTemplate("internal-mtls", accountID)
		if err := s.CreateCertificateTemplate(ctx, tpl); err != nil {
			t.Fatalf("create: %v", err)
		}
		if tpl.ID == "" {
			t.Fatal("create did not assign an id")
		}

		got, err := s.GetCertificateTemplate(ctx, tpl.ID)
		if err != nil {
			t.Fatal(err)
		}
		compareTemplates(t, "after create", tpl, got)

		// Now change every field a caller owns, and assert the UPDATE carries
		// all of them. An UPDATE that names twenty-six of twenty-eight columns
		// passes every test that only checks creation.
		second := caAccountFor(t, s, "second CA")
		tpl.Name = "Public TLS"
		tpl.Description = "Marketing estate"
		tpl.Version = 2
		tpl.IsEnabled = false
		tpl.CAAccountID = second
		tpl.CAProfile = "tlsserver"
		tpl.SubjectMode = SubjectModeSupplied
		tpl.SubjectDefaults = map[string]string{"O": "Example Ltd", "C": "US"}
		tpl.CommonNameRule.Suffixes = []string{"example.com"}
		tpl.CommonNameRule.ForbiddenPatterns = []string{"internal"}
		tpl.SANRules.Types = []string{"DNS"}
		tpl.SANRules.Suffixes = []string{"example.com"}
		tpl.SANRules.MaxNames = 100
		tpl.AllowedKeyTypes = []string{"RSA"}
		tpl.RSAMinBits = 2048
		tpl.RSAMaxBits = 4096
		tpl.ECDSACurves = []string{"P-521"}
		tpl.CSRRequired = false
		tpl.KeyCustodyRequired = KeyCustodyCertPilot
		tpl.ValidityDays = 47
		tpl.MaxValidityDays = 47
		tpl.RenewBeforeDays = 10
		tpl.AutoRenew = true
		tpl.RequireMetadata = []string{"data_classification"}
		tpl.DefaultEnvironment = "staging"
		tpl.DefaultTeam = "web"
		tpl.DefaultTags = []string{"public"}

		if err := s.UpdateCertificateTemplate(ctx, tpl); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err = s.GetCertificateTemplate(ctx, tpl.ID)
		if err != nil {
			t.Fatal(err)
		}
		compareTemplates(t, "after update", tpl, got)
	})
}

// TestAnAbsentWildcardDecisionIsNotAFalseOne is the invariant the pointer
// fields exist for.
//
// A template that has never mentioned wildcards has not forbidden them. If the
// round trip turns a missing key into `false`, the first read of that template
// starts refusing wildcard requests nobody decided to refuse — and the rule
// would appear in no audit, because nobody wrote it.
func TestAnAbsentWildcardDecisionIsNotAFalseOne(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		accountID := caAccountFor(t, s, "silent CA")

		tpl := &CertificateTemplate{
			Slug:               "unopinionated",
			Name:               "Unopinionated",
			Version:            1,
			IsEnabled:          true,
			CAAccountID:        accountID,
			SubjectMode:        SubjectModeSupplied,
			KeyCustodyRequired: KeyCustodyAny,
			RenewBeforeDays:    30,
		}
		if err := s.CreateCertificateTemplate(ctx, tpl); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := s.GetCertificateTemplate(ctx, tpl.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.SANRules.AllowWildcards != nil {
			t.Errorf("a template that never mentioned wildcards read back with a decision: %v",
				*got.SANRules.AllowWildcards)
		}
		if got.CommonNameRule.Required != nil {
			t.Errorf("a template that never mentioned the common name read back with a decision: %v",
				*got.CommonNameRule.Required)
		}

		// And an explicit false must survive as an explicit false, or the
		// pointer buys nothing.
		no := false
		tpl.SANRules.AllowWildcards = &no
		if err := s.UpdateCertificateTemplate(ctx, tpl); err != nil {
			t.Fatal(err)
		}
		got, err = s.GetCertificateTemplate(ctx, tpl.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.SANRules.AllowWildcards == nil || *got.SANRules.AllowWildcards {
			t.Errorf("an explicit refusal of wildcards did not survive the round trip: %v",
				got.SANRules.AllowWildcards)
		}
	})
}

// TestATemplateSlugIsUniqueInBothStores. The in-memory store enforces no
// constraints unless somebody writes them, so a uniqueness rule that lives only
// in the schema is a rule half the tests do not have.
func TestATemplateSlugIsUniqueInBothStores(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		accountID := caAccountFor(t, s, "unique CA")

		first := fullTemplate("taken", accountID)
		if err := s.CreateCertificateTemplate(ctx, first); err != nil {
			t.Fatalf("create: %v", err)
		}

		second := fullTemplate("taken", accountID)
		second.Name = "A different name, the same slug"
		if err := s.CreateCertificateTemplate(ctx, second); err == nil {
			t.Fatal("a second template took a slug that was already in use")
		}
	})
}

// TestATemplateIsFoundByItsSlug. The slug is what an agent or a CI job names;
// a pipeline should not have to carry a uuid.
func TestATemplateIsFoundByItsSlug(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		accountID := caAccountFor(t, s, "slug CA")

		tpl := fullTemplate("find-me", accountID)
		if err := s.CreateCertificateTemplate(ctx, tpl); err != nil {
			t.Fatal(err)
		}

		got, err := s.GetCertificateTemplateBySlug(ctx, "find-me")
		if err != nil {
			t.Fatalf("by slug: %v", err)
		}
		if got.ID != tpl.ID {
			t.Errorf("by slug returned %s, wanted %s", got.ID, tpl.ID)
		}

		if _, err := s.GetCertificateTemplateBySlug(ctx, "no-such-template"); err == nil {
			t.Error("an unknown slug resolved to a template")
		} else if !strings.Contains(err.Error(), "no-such-template") {
			t.Errorf("the error does not name what was looked for: %v", err)
		}
	})
}

// TestNoTemplatesIsAnEmptyListNotNull. A null here serialises as `null` rather
// than `[]`, and the console renders a template list it cannot iterate.
func TestNoTemplatesIsAnEmptyListNotNull(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		got, err := s.ListCertificateTemplates(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("an empty result came back as nil rather than an empty slice")
		}
		if len(got) != 0 {
			t.Fatalf("a fresh store already has %d templates", len(got))
		}
	})
}

// TestDeletingATemplateSaysSoWhenItIsNotThere. Both stores have to agree that
// deleting something absent is an error, or a handler returns 204 for a
// template it never removed.
func TestDeletingATemplateSaysSoWhenItIsNotThere(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		if err := s.DeleteCertificateTemplate(ctx, "00000000-0000-0000-0000-000000000000"); err == nil {
			t.Error("deleting a template that does not exist reported success")
		}
	})
}
