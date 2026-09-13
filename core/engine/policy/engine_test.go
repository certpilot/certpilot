package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
)

// evaluate runs one policy against one request through the real engine and the
// in-memory store, so the test exercises the same path issuance does.
func evaluate(t *testing.T, p store.Policy, req Request) []Violation {
	t.Helper()

	st := store.NewMemoryStore()
	if p.Severity == "" {
		p.Severity = SeverityBlock
	}
	p.IsEnabled = true
	if err := st.CreatePolicy(context.Background(), &p); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	violations, err := NewEngine(st).EvaluateRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return violations
}

func mustViolate(t *testing.T, violations []Violation, wants ...string) {
	t.Helper()
	if len(violations) == 0 {
		t.Fatalf("expected a violation, got none")
	}
	joined := strings.ToLower(strings.Join(messages(violations), " | "))
	for _, want := range wants {
		if !strings.Contains(joined, strings.ToLower(want)) {
			t.Errorf("violation should mention %q, got: %s", want, joined)
		}
	}
}

func mustPass(t *testing.T, violations []Violation) {
	t.Helper()
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got: %s", strings.Join(messages(violations), " | "))
	}
}

func messages(violations []Violation) []string {
	out := make([]string, 0, len(violations))
	for _, v := range violations {
		out = append(out, v.Message)
	}
	return out
}

func rsa2048() Request {
	return Request{
		CommonName:     "shop.example.com",
		Domains:        []string{"shop.example.com"},
		KeyType:        "RSA",
		KeySize:        2048,
		ValidityDays:   90,
		CAProviderType: "selfsigned",
	}
}

// ── The defect this file exists for ──────────────────────────────────────────

// A rule type the engine cannot evaluate must not be mistaken for one that
// passed. Before the default case, key_type, naming and approval_required all
// saved successfully, listed as enabled, and enforced nothing — so an operator
// who wrote "ECDSA only, BLOCK" got a row in a table and an estate full of RSA.
func TestARuleTypeTheEngineCannotEvaluateDoesNotPass(t *testing.T) {
	v := evaluate(t, store.Policy{
		Name:       "invented",
		RuleType:   "quantum_resistance_required",
		RuleConfig: `{"whatever": true}`,
	}, rsa2048())

	mustViolate(t, v, "cannot evaluate", "quantum_resistance_required")
	if v[0].Severity != SeverityBlock {
		t.Errorf("an unevaluable BLOCK policy must stay BLOCK, got %q", v[0].Severity)
	}
}

// A rule_config that does not parse used to disable its own policy silently:
// the code read `if err := json.Unmarshal(...); err == nil`, so a typo was
// indistinguishable from a request that complied.
func TestAnUnparseableRuleConfigDoesNotPass(t *testing.T) {
	v := evaluate(t, store.Policy{
		Name:       "typo",
		RuleType:   RuleKeySize,
		RuleConfig: `{"min_key_size": "four thousand"}`,
	}, rsa2048())

	mustViolate(t, v, "does not parse")
}

// A policy that parses but constrains nothing is a policy somebody believes is
// protecting them.
func TestAPolicyThatConstrainsNothingDoesNotPass(t *testing.T) {
	for _, tc := range []struct{ name, ruleType, config string }{
		{"key size", RuleKeySize, `{}`},
		{"key type", RuleKeyType, `{"allowed_key_types": []}`},
		{"lifetime", RuleMaxLifetime, `{}`},
		{"ca restriction", RuleCARestriction, `{"allowed_providers": []}`},
		{"naming", RuleNaming, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := evaluate(t, store.Policy{
				Name: "empty", RuleType: tc.ruleType, RuleConfig: tc.config,
			}, rsa2048())
			mustViolate(t, v, "enabled but")
		})
	}
}

// The approval workflow does not exist. A policy asking for one must say so
// rather than pass, which is what it did before.
func TestApprovalRequiredSaysThereIsNoApprovalWorkflow(t *testing.T) {
	v := evaluate(t, store.Policy{
		Name:       "four eyes",
		RuleType:   RuleApprovalRequired,
		RuleConfig: `{}`,
	}, rsa2048())

	mustViolate(t, v, "no approval workflow")
}

// ── key_type ─────────────────────────────────────────────────────────────────

func TestKeyTypeAllowsAndForbidsEverySupportedAlgorithm(t *testing.T) {
	for _, keyType := range supportedKeyTypes() {
		t.Run("allowed/"+keyType, func(t *testing.T) {
			req := rsa2048()
			req.KeyType = keyType
			mustPass(t, evaluate(t, store.Policy{
				Name:       "allow this one",
				RuleType:   RuleKeyType,
				RuleConfig: `{"allowed_key_types": ["` + keyType + `"]}`,
			}, req))
		})

		t.Run("forbidden/"+keyType, func(t *testing.T) {
			req := rsa2048()
			req.KeyType = keyType
			mustViolate(t, evaluate(t, store.Policy{
				Name:       "forbid this one",
				RuleType:   RuleKeyType,
				RuleConfig: `{"forbidden_key_types": ["` + keyType + `"]}`,
			}, req), "forbidden")
		})
	}
}

// The rule must not be defeated by spelling. "EC" and "ecdsa" are the same
// algorithm as "ECDSA", and a policy naming one has to catch the others.
func TestKeyTypeIsNotDefeatedBySpelling(t *testing.T) {
	for _, spelling := range []string{"ECDSA", "ecdsa", "EC", "ec"} {
		t.Run(spelling, func(t *testing.T) {
			req := rsa2048()
			req.KeyType = spelling
			req.KeySize = 256
			mustViolate(t, evaluate(t, store.Policy{
				Name:       "RSA only",
				RuleType:   RuleKeyType,
				RuleConfig: `{"allowed_key_types": ["RSA"]}`,
			}, req), "not permitted")
		})
	}
}

func TestAnUnknownKeyTypeIsRefusedRatherThanAllowed(t *testing.T) {
	req := rsa2048()
	req.KeyType = "Kyber1024"
	mustViolate(t, evaluate(t, store.Policy{
		Name:       "known algorithms only",
		RuleType:   RuleKeyType,
		RuleConfig: `{"allowed_key_types": ["RSA", "ECDSA", "Ed25519"]}`,
	}, req), "not a key type this build supports")
}

// ── key_size ─────────────────────────────────────────────────────────────────

// The original rule checked `keyType == "RSA"` and nothing else, so an ECDSA
// request passed a key size policy without being looked at.
func TestKeySizeAppliesToECDSAAndNotOnlyToRSA(t *testing.T) {
	req := rsa2048()
	req.KeyType = "ECDSA"
	req.KeySize = 256

	mustViolate(t, evaluate(t, store.Policy{
		Name:       "P-384 or better",
		RuleType:   RuleKeySize,
		RuleConfig: `{"ecdsa_min_bits": 384}`,
	}, req), "P-256", "P-384")
}

// RSA bits and ECDSA curve bits are not comparable numbers, and a floor written
// for one must not be applied to the other: 256 is a strong ECDSA key.
func TestAnRSAFloorDoesNotCondemnAnECDSAKey(t *testing.T) {
	req := rsa2048()
	req.KeyType = "ECDSA"
	req.KeySize = 256

	mustPass(t, evaluate(t, store.Policy{
		Name:       "RSA 3072",
		RuleType:   RuleKeySize,
		RuleConfig: `{"rsa_min_bits": 3072}`,
	}, req))
}

// Policies written against the original shape have to keep working; min_key_size
// always meant RSA bits, because RSA was all the rule ever looked at.
func TestTheOriginalMinKeySizeStillMeansRSABits(t *testing.T) {
	req := rsa2048()
	req.KeySize = 1024

	mustViolate(t, evaluate(t, store.Policy{
		Name:       "legacy shape",
		RuleType:   RuleKeySize,
		RuleConfig: `{"min_key_size": 2048}`,
	}, req), "below the minimum of 2048")
}

// Ed25519 has one size. A floor cannot be violated, and reporting one would be
// nonsense — forbidding the algorithm is what key_type is for.
func TestEd25519IsNotJudgedAgainstASizeFloor(t *testing.T) {
	req := rsa2048()
	req.KeyType = "Ed25519"
	req.KeySize = 256

	mustPass(t, evaluate(t, store.Policy{
		Name:       "RSA 4096",
		RuleType:   RuleKeySize,
		RuleConfig: `{"rsa_min_bits": 4096, "ecdsa_min_bits": 384}`,
	}, req))
}

// ── naming ───────────────────────────────────────────────────────────────────

// The oldest way to get a certificate for a name somebody thought they owned:
// a suffix check that is not anchored to a label boundary.
func TestAnAllowedSuffixDoesNotAdmitALookalikeDomain(t *testing.T) {
	req := rsa2048()
	req.CommonName = "evil-example.com"
	req.Domains = []string{"evil-example.com"}

	mustViolate(t, evaluate(t, store.Policy{
		Name:       "our zone only",
		RuleType:   RuleNaming,
		RuleConfig: `{"allowed_suffixes": ["example.com"]}`,
	}, req), "outside the suffixes")
}

func TestAnAllowedSuffixAdmitsTheZoneAndItsChildren(t *testing.T) {
	for _, name := range []string{"example.com", "shop.example.com", "a.b.example.com", "*.example.com"} {
		t.Run(name, func(t *testing.T) {
			req := rsa2048()
			req.CommonName = name
			req.Domains = []string{name}
			mustPass(t, evaluate(t, store.Policy{
				Name:       "our zone only",
				RuleType:   RuleNaming,
				RuleConfig: `{"allowed_suffixes": ["example.com"]}`,
			}, req))
		})
	}
}

func TestWildcardsCanBeForbidden(t *testing.T) {
	req := rsa2048()
	req.CommonName = "*.example.com"
	req.Domains = []string{"*.example.com"}

	mustViolate(t, evaluate(t, store.Policy{
		Name:       "no wildcards",
		RuleType:   RuleNaming,
		RuleConfig: `{"allow_wildcards": false}`,
	}, req), "wildcard")
}

// allow_wildcards is a pointer for this reason: a naming policy written to cap
// SAN count must not ban wildcards as a side effect of Go's zero value.
func TestANamingPolicyThatDoesNotMentionWildcardsPermitsThem(t *testing.T) {
	req := rsa2048()
	req.CommonName = "*.example.com"
	req.Domains = []string{"*.example.com"}

	mustPass(t, evaluate(t, store.Policy{
		Name:       "cap the names",
		RuleType:   RuleNaming,
		RuleConfig: `{"max_sans": 10}`,
	}, req))
}

func TestSANCountIsCapped(t *testing.T) {
	req := rsa2048()
	req.Domains = []string{"a.example.com", "b.example.com", "c.example.com"}

	mustViolate(t, evaluate(t, store.Policy{
		Name:       "at most two",
		RuleType:   RuleNaming,
		RuleConfig: `{"max_sans": 2}`,
	}, req), "more than the 2 allowed")
}

// Every offending name is reported, not just the first. An operator fixing them
// one round trip at a time is an operator who gives up.
func TestEveryOffendingNameIsReported(t *testing.T) {
	req := rsa2048()
	req.Domains = []string{"ok.example.com", "bad.test", "worse.invalid"}

	v := evaluate(t, store.Policy{
		Name:       "our zone only",
		RuleType:   RuleNaming,
		RuleConfig: `{"allowed_suffixes": ["example.com"]}`,
	}, req)

	if len(v) != 2 {
		t.Fatalf("expected both offending names reported, got %d: %s",
			len(v), strings.Join(messages(v), " | "))
	}
}

func TestForbiddenPatternsRefuseAName(t *testing.T) {
	req := rsa2048()
	req.Domains = []string{"db.internal"}

	mustViolate(t, evaluate(t, store.Policy{
		Name:       "nothing internal",
		RuleType:   RuleNaming,
		RuleConfig: `{"forbidden_patterns": ["*.internal"]}`,
	}, req), "forbids")
}

// ── lifetime and CA ──────────────────────────────────────────────────────────

func TestLifetimeBoundsApplyInBothDirections(t *testing.T) {
	short := rsa2048()
	short.ValidityDays = 1
	mustViolate(t, evaluate(t, store.Policy{
		Name: "between", RuleType: RuleMaxLifetime, RuleConfig: `{"min_days": 30, "max_days": 90}`,
	}, short), "below the minimum")

	long := rsa2048()
	long.ValidityDays = 400
	mustViolate(t, evaluate(t, store.Policy{
		Name: "between", RuleType: RuleMaxLifetime, RuleConfig: `{"min_days": 30, "max_days": 90}`,
	}, long), "exceeds the maximum")
}

func TestCARestrictionNamesWhatIsAllowed(t *testing.T) {
	req := rsa2048()
	req.CAProviderType = "selfsigned"

	mustViolate(t, evaluate(t, store.Policy{
		Name: "public CAs only", RuleType: RuleCARestriction,
		RuleConfig: `{"allowed_providers": ["acme"]}`,
	}, req), "not permitted", "acme")
}

// ── scoping ──────────────────────────────────────────────────────────────────

// A policy scoped to another zone must not judge this request at all, including
// the failure paths above — otherwise a misconfigured policy for one team
// blocks every other team's issuance.
func TestAPolicyScopedToAnotherZoneIsNotApplied(t *testing.T) {
	req := rsa2048() // shop.example.com

	mustPass(t, evaluate(t, store.Policy{
		Name:          "someone else's rule",
		RuleType:      "invented_rule_type",
		RuleConfig:    `{}`,
		DomainPattern: "*.other.test",
	}, req))
}

func TestADisabledPolicyIsNotApplied(t *testing.T) {
	st := store.NewMemoryStore()
	p := store.Policy{
		Name: "switched off", RuleType: RuleKeyType, Severity: SeverityBlock,
		RuleConfig: `{"allowed_key_types": ["Ed25519"]}`, IsEnabled: false,
	}
	if err := st.CreatePolicy(context.Background(), &p); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	v, err := NewEngine(st).EvaluateRequest(context.Background(), rsa2048())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	mustPass(t, v)
}

// The severity on the policy is the severity on the violation: only BLOCK stops
// issuance, so a rule the engine cannot evaluate must not be promoted to BLOCK
// by the engine's own opinion of how serious that is.
func TestTheViolationCarriesThePolicysOwnSeverity(t *testing.T) {
	for _, severity := range []string{SeverityInfo, SeverityWarning, SeverityBlock} {
		t.Run(severity, func(t *testing.T) {
			v := evaluate(t, store.Policy{
				Name: "graded", RuleType: RuleKeyType, Severity: severity,
				RuleConfig: `{"allowed_key_types": ["Ed25519"]}`,
			}, rsa2048())

			if len(v) != 1 || v[0].Severity != severity {
				t.Fatalf("expected one %s violation, got %+v", severity, v)
			}
		})
	}
}
