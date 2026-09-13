// Package policy implements policy validation and compliance rule enforcement for CertPilot.
//
// The governing rule here is that a policy never silently does nothing. A rule
// type this build cannot evaluate, a rule_config that will not parse, and a
// configuration that constrains nothing all produce a violation at the policy's
// own severity rather than being skipped.
//
// That is not defensiveness for its own sake. Before it, three of the six rule
// types the API accepted — key_type, naming and approval_required — saved
// successfully, listed as enabled, and enforced nothing at all. An operator who
// wrote "ECDSA only, BLOCK" got a row in a table and an estate full of RSA.
// Failing open is the one behaviour a security control must not have, and it is
// the behaviour you get for free from a switch with no default.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/certpilot/certpilot-gateway-sdk/crypto"
	"github.com/certpilot/certpilot/core/store"
)

// Rule types this engine evaluates. The schema's CHECK constraint and the API's
// binding tag must not admit anything absent from here without a case below.
const (
	RuleKeySize          = "key_size"
	RuleKeyType          = "key_type"
	RuleCARestriction    = "ca_restriction"
	RuleMaxLifetime      = "max_lifetime"
	RuleNaming           = "naming"
	RuleApprovalRequired = "approval_required"
)

// Severity levels, in the order a caller should care about them.
const (
	SeverityInfo    = "INFO"
	SeverityWarning = "WARNING"
	SeverityBlock   = "BLOCK"
)

// Violation represents a policy rule violation.
type Violation struct {
	PolicyName string `json:"policy_name"`
	RuleType   string `json:"rule_type"`
	Message    string `json:"message"`
	Severity   string `json:"severity"` // INFO, WARNING, BLOCK
}

// Request is everything about a certificate request that a policy may judge.
//
// A struct rather than six positional arguments: the previous signature took
// (domains, keyType, keySize, validityDays, caProviderType) and every future
// rule would have added another int or string to a call site that already had
// two of each.
type Request struct {
	// CommonName is the subject CN. Empty when the request carried a CSR whose
	// subject has none, which is legal and increasingly common.
	CommonName string
	// Domains is the CN and every SAN, deduplicated. This is what a naming rule
	// judges, because a certificate is as permissive as its most permissive name.
	Domains []string
	// KeyType and KeySize are the *actual* values. When the requester supplied a
	// CSR the caller has already replaced the requested values with the ones
	// read out of it, so a weak key cannot be smuggled past a floor by claiming
	// a strong one in the JSON body.
	KeyType string
	KeySize int

	ValidityDays   int
	CAProviderType string
}

// Engine evaluates policy rules against certificates or requests.
type Engine struct {
	store store.Store
}

// NewEngine creates a new policy engine.
func NewEngine(s store.Store) *Engine {
	return &Engine{store: s}
}

// EvaluateRequest checks if a certificate request conforms to all active policies.
func (e *Engine) EvaluateRequest(ctx context.Context, req Request) ([]Violation, error) {
	policies, err := e.store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}

	var violations []Violation

	for _, p := range policies {
		if !p.IsEnabled {
			continue
		}

		// A domain pattern narrows which requests a policy judges. An empty one
		// judges every request.
		if p.DomainPattern != "" && !matchesDomainPattern(req.Domains, p.DomainPattern) {
			continue
		}

		violations = append(violations, evaluatePolicy(p, req)...)
	}

	return violations, nil
}

// evaluatePolicy applies one policy to one request.
func evaluatePolicy(p *store.Policy, req Request) []Violation {
	fail := func(format string, args ...any) []Violation {
		return []Violation{{
			PolicyName: p.Name,
			RuleType:   p.RuleType,
			Severity:   p.Severity,
			Message:    fmt.Sprintf(format, args...),
		}}
	}

	switch p.RuleType {
	case RuleKeySize:
		return evaluateKeySize(p, req, fail)
	case RuleKeyType:
		return evaluateKeyType(p, req, fail)
	case RuleMaxLifetime:
		return evaluateMaxLifetime(p, req, fail)
	case RuleCARestriction:
		return evaluateCARestriction(p, req, fail)
	case RuleNaming:
		return evaluateNaming(p, req, fail)

	case RuleApprovalRequired:
		// There is no approval workflow: no approvals table, no endpoint to
		// approve or reject, no pending state on a certificate. Until there is,
		// the only honest thing a policy naming it can do is say so. It used to
		// pass silently, which told an operator who asked for a gate that they
		// had one.
		return fail(
			"policy %q requires approval, but this build has no approval workflow: "+
				"nothing can approve or reject a request. Remove the policy, or "+
				"express the constraint as a rule that can be evaluated",
			p.Name,
		)

	default:
		// The reason this default exists. Without it an unrecognised rule type
		// is skipped, and a policy that cannot be evaluated is indistinguishable
		// from a policy that passed.
		return fail(
			"policy %q uses rule type %q, which this build cannot evaluate; "+
				"refusing to treat it as satisfied",
			p.Name, p.RuleType,
		)
	}
}

type failFunc func(format string, args ...any) []Violation

// decode unmarshals a rule_config, turning a parse failure into a violation.
//
// This used to be `if err := json.Unmarshal(...); err == nil` — a rule_config
// with a typo in it disabled the policy and reported nothing.
func decode(p *store.Policy, target any, fail failFunc) []Violation {
	if err := json.Unmarshal([]byte(p.RuleConfig), target); err != nil {
		return fail(
			"policy %q has a rule_config that does not parse (%v), so it cannot "+
				"be evaluated", p.Name, err,
		)
	}
	return nil
}

// ── key_size ─────────────────────────────────────────────────────────────────

type keySizeConfig struct {
	// MinKeySize is the original field and meant RSA bits, because RSA was the
	// only algorithm the rule ever checked. Still honoured so that policies
	// written against the old shape keep working.
	MinKeySize int `json:"min_key_size"`

	// RSAMinBits and ECDSAMinBits are separate because their units are not
	// comparable: 256 is a strong ECDSA key and a broken RSA one. A single
	// number cannot express a floor for both, and the old rule's answer —
	// check RSA and ignore everything else — left ECDSA with no floor at all.
	RSAMinBits   int `json:"rsa_min_bits"`
	ECDSAMinBits int `json:"ecdsa_min_bits"`
}

func evaluateKeySize(p *store.Policy, req Request, fail failFunc) []Violation {
	var cfg keySizeConfig
	if v := decode(p, &cfg, fail); v != nil {
		return v
	}

	rsaMin := cfg.RSAMinBits
	if rsaMin == 0 {
		rsaMin = cfg.MinKeySize
	}

	if rsaMin <= 0 && cfg.ECDSAMinBits <= 0 {
		return fail(
			"policy %q is enabled but sets no key size floor: give it rsa_min_bits, "+
				"ecdsa_min_bits, or both", p.Name,
		)
	}

	switch normaliseKeyType(req.KeyType) {
	case string(crypto.KeyTypeRSA):
		if rsaMin > 0 && req.KeySize < rsaMin {
			return fail(
				"RSA key size %d is below the minimum of %d bits required by policy %q",
				req.KeySize, rsaMin, p.Name,
			)
		}
	case string(crypto.KeyTypeECDSA):
		if cfg.ECDSAMinBits > 0 && req.KeySize < cfg.ECDSAMinBits {
			return fail(
				"ECDSA curve P-%d is below the minimum of P-%d required by policy %q",
				req.KeySize, cfg.ECDSAMinBits, p.Name,
			)
		}
	case string(crypto.KeyTypeEd25519):
		// Ed25519 has one size. There is no weaker variant to forbid, so a size
		// floor cannot be violated — and reporting one would be nonsense. Use a
		// key_type rule to forbid the algorithm itself.
	}

	return nil
}

// ── key_type ─────────────────────────────────────────────────────────────────

type keyTypeConfig struct {
	AllowedKeyTypes []string `json:"allowed_key_types"`
	// ForbiddenKeyTypes is the other way round, for the common case of banning
	// one algorithm without having to enumerate the rest — and without a new
	// algorithm being silently permitted the day it is added.
	ForbiddenKeyTypes []string `json:"forbidden_key_types"`
}

func evaluateKeyType(p *store.Policy, req Request, fail failFunc) []Violation {
	var cfg keyTypeConfig
	if v := decode(p, &cfg, fail); v != nil {
		return v
	}

	if len(cfg.AllowedKeyTypes) == 0 && len(cfg.ForbiddenKeyTypes) == 0 {
		return fail(
			"policy %q is enabled but names no key types: give it allowed_key_types "+
				"or forbidden_key_types", p.Name,
		)
	}

	requested := normaliseKeyType(req.KeyType)
	if requested == "" {
		return fail(
			"policy %q restricts key types but the request names %q, which is not a "+
				"key type this build supports (%s)",
			p.Name, req.KeyType, strings.Join(supportedKeyTypes(), ", "),
		)
	}

	for _, forbidden := range cfg.ForbiddenKeyTypes {
		if normaliseKeyType(forbidden) == requested {
			return fail(
				"key type %s is forbidden by policy %q", requested, p.Name,
			)
		}
	}

	if len(cfg.AllowedKeyTypes) > 0 {
		for _, allowed := range cfg.AllowedKeyTypes {
			if normaliseKeyType(allowed) == requested {
				return nil
			}
		}
		return fail(
			"key type %s is not permitted by policy %q, which allows only %s",
			requested, p.Name, strings.Join(cfg.AllowedKeyTypes, ", "),
		)
	}

	return nil
}

// normaliseKeyType maps what a request or a policy wrote to what the crypto
// package calls it, so that "ec", "ECDSA" and "EC" are one thing and a policy
// cannot be defeated by spelling.
func normaliseKeyType(s string) string {
	kt, err := crypto.ParseKeyType(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return string(kt)
}

func supportedKeyTypes() []string {
	return []string{
		string(crypto.KeyTypeRSA),
		string(crypto.KeyTypeECDSA),
		string(crypto.KeyTypeEd25519),
	}
}

// ── max_lifetime ─────────────────────────────────────────────────────────────

type maxLifetimeConfig struct {
	MaxDays int `json:"max_days"`
	// MinDays exists because a validity floor is a real requirement: a CA that
	// issues for a day makes renewal the only thing the estate ever does.
	MinDays int `json:"min_days"`
}

func evaluateMaxLifetime(p *store.Policy, req Request, fail failFunc) []Violation {
	var cfg maxLifetimeConfig
	if v := decode(p, &cfg, fail); v != nil {
		return v
	}

	if cfg.MaxDays <= 0 && cfg.MinDays <= 0 {
		return fail(
			"policy %q is enabled but sets no lifetime bound: give it max_days, "+
				"min_days, or both", p.Name,
		)
	}

	if cfg.MaxDays > 0 && req.ValidityDays > cfg.MaxDays {
		return fail(
			"requested validity of %d days exceeds the maximum of %d allowed by policy %q",
			req.ValidityDays, cfg.MaxDays, p.Name,
		)
	}
	if cfg.MinDays > 0 && req.ValidityDays > 0 && req.ValidityDays < cfg.MinDays {
		return fail(
			"requested validity of %d days is below the minimum of %d required by policy %q",
			req.ValidityDays, cfg.MinDays, p.Name,
		)
	}

	return nil
}

// ── ca_restriction ───────────────────────────────────────────────────────────

type caRestrictionConfig struct {
	AllowedProviders []string `json:"allowed_providers"`
}

func evaluateCARestriction(p *store.Policy, req Request, fail failFunc) []Violation {
	var cfg caRestrictionConfig
	if v := decode(p, &cfg, fail); v != nil {
		return v
	}

	if len(cfg.AllowedProviders) == 0 {
		return fail(
			"policy %q is enabled but names no providers in allowed_providers", p.Name,
		)
	}

	for _, provider := range cfg.AllowedProviders {
		if strings.EqualFold(strings.TrimSpace(provider), req.CAProviderType) {
			return nil
		}
	}

	return fail(
		"CA provider %s is not permitted by policy %q, which allows only %s",
		req.CAProviderType, p.Name, strings.Join(cfg.AllowedProviders, ", "),
	)
}

// ── naming ───────────────────────────────────────────────────────────────────

type namingConfig struct {
	// AllowedSuffixes permits names ending in one of these, matched on label
	// boundaries so that "example.com" does not admit "notexample.com".
	AllowedSuffixes []string `json:"allowed_suffixes"`
	// ForbiddenPatterns refuses names matching any of these. Same syntax as
	// domain_pattern: an exact name, or a leading "*." wildcard.
	ForbiddenPatterns []string `json:"forbidden_patterns"`
	// AllowWildcards is a pointer so that "false" can be told from "absent". A
	// bool defaulting to false would make every naming policy ban wildcards by
	// accident, including ones written to constrain something else entirely.
	AllowWildcards *bool `json:"allow_wildcards"`
	// MaxSANs caps how much one certificate is allowed to speak for. A hundred
	// names on one key means one compromise is a hundred outages.
	MaxSANs int `json:"max_sans"`
}

func evaluateNaming(p *store.Policy, req Request, fail failFunc) []Violation {
	var cfg namingConfig
	if v := decode(p, &cfg, fail); v != nil {
		return v
	}

	if len(cfg.AllowedSuffixes) == 0 && len(cfg.ForbiddenPatterns) == 0 &&
		cfg.AllowWildcards == nil && cfg.MaxSANs <= 0 {
		return fail(
			"policy %q is enabled but constrains no names: give it allowed_suffixes, "+
				"forbidden_patterns, allow_wildcards or max_sans", p.Name,
		)
	}

	var violations []Violation
	add := func(format string, args ...any) {
		violations = append(violations, fail(format, args...)...)
	}

	if cfg.MaxSANs > 0 && len(req.Domains) > cfg.MaxSANs {
		add(
			"the request carries %d names, more than the %d allowed by policy %q",
			len(req.Domains), cfg.MaxSANs, p.Name,
		)
	}

	for _, name := range req.Domains {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" {
			continue
		}

		if cfg.AllowWildcards != nil && !*cfg.AllowWildcards && strings.HasPrefix(lower, "*.") {
			add("wildcard name %q is not permitted by policy %q", name, p.Name)
		}

		for _, pattern := range cfg.ForbiddenPatterns {
			if matchesDomainPattern([]string{lower}, pattern) {
				add(
					"name %q matches %q, which policy %q forbids",
					name, pattern, p.Name,
				)
			}
		}

		if len(cfg.AllowedSuffixes) > 0 && !hasAllowedSuffix(lower, cfg.AllowedSuffixes) {
			add(
				"name %q is outside the suffixes policy %q allows (%s)",
				name, p.Name, strings.Join(cfg.AllowedSuffixes, ", "),
			)
		}
	}

	return violations
}

// hasAllowedSuffix reports whether name is the suffix itself or sits beneath it.
//
// Matched on a label boundary on purpose: a plain strings.HasSuffix would let
// "evil-example.com" through a policy that allows "example.com", which is the
// oldest way to get a certificate for a name somebody thought they controlled.
func hasAllowedSuffix(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(suffix, ".")))
		if suffix == "" {
			continue
		}
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
		// A wildcard for the zone itself: "*.example.com" is beneath
		// "example.com" and must not need a separate entry.
		if strings.HasPrefix(name, "*.") && strings.TrimPrefix(name, "*.") == suffix {
			return true
		}
	}
	return false
}

// ── shared ───────────────────────────────────────────────────────────────────

func matchesDomainPattern(domains []string, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if pattern == "*" || pattern == d {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(d, suffix) {
				return true
			}
		}
	}
	return false
}
