package renewal

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// conformance is what the rules in force today say about a certificate that is
// about to be renewed.
type conformance struct {
	// KeyType and KeySize are what to ask the CA for. Equal to what the
	// certificate already has when it still conforms.
	KeyType string
	KeySize int
	// ValidityDays is what to ask for, when a template supplies one.
	ValidityDays int

	// Domains is what to renew for, deduplicated.
	Domains []string

	// TemplateVersion is the version this renewal was judged against, when
	// there was a template. The certificate records it, because a renewal is an
	// issuance: the certificate now on disk was produced under these rules, and
	// leaving the version the *original* was issued under would make an auditor
	// read a conforming certificate as a stale one.
	TemplateVersion *int
	// Template is the object TemplateVersion names, kept alongside it because
	// #30's post-renewal conformance check needs the rules themselves — the
	// SANs mode, the conformance switch — not only which version they were.
	// Nil under the same conditions TemplateVersion is nil.
	Template *store.CertificateTemplate

	// CAProfile, KeyUsage and ExtendedKeyUsage are read fresh from the
	// (possibly changed) template on every renewal, the same as KeyType and
	// KeySize above — a renewal is an issuance, so it asks under today's
	// rules, not the ones that were in force when this certificate was first
	// issued.
	CAProfile        string
	KeyUsage         []string
	ExtendedKeyUsage []string

	// Upgrades are changes renewal is making because the rules moved. Recorded
	// so an operator can see that a certificate was quietly strengthened rather
	// than discovering it from a fingerprint change.
	Upgrades []string
	// Unfixable are the ways this certificate no longer satisfies its rules
	// that renewal cannot do anything about — a name now outside the template's
	// suffixes, most often. Reported, never a refusal.
	Unfixable []string
}

// conform decides what to renew a certificate into.
//
// The renewal sweep is the only component that touches every managed
// certificate on a timer, which makes it the only place a policy change can
// reach an estate that already exists. Before this it built its request from
// the row — `KeyType: cert.KeyType, KeySize: cert.KeySize` — so an RSA-1024
// certificate renewed as RSA-1024 for ever, and tightening a rule changed what
// could be requested tomorrow and nothing about what was already issued.
//
// Two rules govern the answer, and both are easy to get wrong in the direction
// that looks like progress:
//
//   - **Never downgrade.** Asking a template for a key with the fields left
//     empty yields its *minimum*, so an RSA-4096 certificate under a template
//     whose floor is 2048 would be rekeyed weaker on its next renewal.
//   - **No gratuitous change.** A certificate that already satisfies its rules
//     keeps exactly the key it has. Rotating RSA to ECDSA on a renewal that did
//     not need it is a change nobody asked for, and some endpoint will not
//     survive it.
//
// A certificate with no template is still judged, against the estate-wide
// floor. Most of an inventory predates templates — discovered, imported, issued
// before migration 036 — and exempting all of it would mean a policy change
// governed only certificates that did not exist yet.
func conform(ctx context.Context, s store.Store, eng *policy.Engine, cert *store.Certificate) (*conformance, error) {
	out := &conformance{KeyType: cert.KeyType, KeySize: cert.KeySize, Domains: renewalNames(cert)}

	var tpl *store.CertificateTemplate
	if cert.TemplateID != nil && *cert.TemplateID != "" {
		t, err := s.GetCertificateTemplate(ctx, *cert.TemplateID)
		if err == nil {
			tpl = t
		}
		// A template deleted out from under a certificate is not a reason to
		// stop renewing it. The floor below still applies.
	}

	domains := renewalNames(cert)

	if tpl != nil {
		version := tpl.Version
		out.TemplateVersion = &version
		out.Template = tpl
		applyTemplateFloor(out, tpl, cert)
		out.Unfixable = append(out.Unfixable, templateMismatches(tpl, cert, domains)...)
		if tpl.ValidityDays > 0 {
			out.ValidityDays = tpl.ValidityDays
		}
		out.CAProfile = tpl.CAProfile
		out.KeyUsage = tpl.KeyUsage
		out.ExtendedKeyUsage = tpl.ExtendedKeyUsage
	}

	// The floor, judged on the key renewal is actually going to ask for rather
	// than the one the certificate has — otherwise a template upgrade that
	// already fixed the problem would still be reported as a violation.
	violations, err := eng.EvaluateRequest(ctx, policy.Request{
		CommonName:   cert.CommonName,
		Domains:      domains,
		KeyType:      out.KeyType,
		KeySize:      out.KeySize,
		ValidityDays: validityOrDefault(out.ValidityDays, cert),
	})
	if err != nil {
		// Unlike issuance, this does not refuse. A database blip must not stop
		// an estate renewing — an expired certificate is a worse outcome than
		// an unjudged one, and the sweep will judge it again in an hour.
		return out, fmt.Errorf("could not evaluate policy for %s: %w", cert.ID, err)
	}

	raiseForViolations(out, violations)
	return out, nil
}

// applyTemplateFloor raises the key to what the template now requires, and
// never lowers it.
func applyTemplateFloor(out *conformance, tpl *store.CertificateTemplate, cert *store.Certificate) {
	if !keyTypePermitted(tpl, out.KeyType) {
		// The template no longer issues this algorithm. Renewal generates the
		// key, so it can move — and this is the one case where changing the key
		// type is what the operator asked for by writing the template.
		replacement := firstPermittedKeyType(tpl)
		if replacement == "" {
			out.Unfixable = append(out.Unfixable, fmt.Sprintf(
				"template %q permits no key type this build can issue", tpl.Slug))
			return
		}
		out.Upgrades = append(out.Upgrades, fmt.Sprintf(
			"key type %s → %s, which is what template %q now issues",
			out.KeyType, replacement, tpl.Slug))
		out.KeyType = replacement
		out.KeySize = 0 // chosen below, from the template's own floor
	}

	switch strings.ToUpper(out.KeyType) {
	case "RSA":
		if out.KeySize < tpl.RSAMinBits {
			if out.KeySize > 0 {
				out.Upgrades = append(out.Upgrades, fmt.Sprintf(
					"RSA %d → %d bits, the minimum template %q now requires",
					out.KeySize, tpl.RSAMinBits, tpl.Slug))
			}
			out.KeySize = tpl.RSAMinBits
		}
		if out.KeySize <= 0 {
			out.KeySize = 2048
		}
	case "ECDSA":
		if !curvePermitted(tpl, out.KeySize) {
			replacement := weakestPermittedCurve(tpl)
			if replacement == 0 {
				out.KeySize = 256
				break
			}
			if out.KeySize > 0 {
				out.Upgrades = append(out.Upgrades, fmt.Sprintf(
					"curve P-%d → P-%d, which is what template %q now issues",
					out.KeySize, replacement, tpl.Slug))
			}
			out.KeySize = replacement
		}
	default:
		if out.KeySize <= 0 {
			out.KeySize = 256
		}
	}
}

// templateMismatches lists what renewal cannot fix.
//
// Names, above all. Renewal reissues for the names the certificate already
// carries, and it cannot drop one to satisfy a suffix rule that tightened — the
// endpoints serving it expect every name it has.
func templateMismatches(tpl *store.CertificateTemplate, cert *store.Certificate, domains []string) []string {
	var out []string

	suffixes := append(append([]string{}, tpl.CommonNameRule.Suffixes...), tpl.SANRules.Suffixes...)
	allowWildcards := tpl.SANRules.AllowWildcards != nil && *tpl.SANRules.AllowWildcards

	for _, name := range domains {
		if strings.HasPrefix(name, "*.") && !allowWildcards {
			out = append(out, fmt.Sprintf(
				"carries wildcard %q, which template %q no longer permits", name, tpl.Slug))
			continue
		}
		if len(suffixes) > 0 && !hasSuffix(name, suffixes) {
			out = append(out, fmt.Sprintf(
				"carries %q, which is outside the suffixes template %q now allows (%s)",
				name, tpl.Slug, strings.Join(suffixes, ", ")))
		}
	}

	if tpl.SANRules.MaxNames > 0 && len(domains) > tpl.SANRules.MaxNames {
		out = append(out, fmt.Sprintf(
			"carries %d names and template %q now allows at most %d",
			len(domains), tpl.Slug, tpl.SANRules.MaxNames))
	}
	return out
}

// raiseForViolations turns what the floor found into an upgrade where renewal
// can act, and a report where it cannot.
func raiseForViolations(out *conformance, violations []policy.Violation) {
	for _, v := range violations {
		if v.Severity != policy.SeverityBlock {
			continue
		}
		if v.RuleType == policy.RuleKeySize || v.RuleType == policy.RuleKeyType {
			// The floor refuses the key renewal was about to ask for, and the
			// template did not already raise it above the floor. Report rather
			// than guess: the message names the required minimum, and inferring
			// a number out of prose is how a sweep starts issuing keys nobody
			// specified.
			out.Unfixable = append(out.Unfixable, v.Message)
			continue
		}
		out.Unfixable = append(out.Unfixable, v.Message)
	}
}

func validityOrDefault(days int, cert *store.Certificate) int {
	if days > 0 {
		return days
	}
	if cert.NotBefore != nil && cert.NotAfter != nil {
		if d := int(cert.NotAfter.Sub(*cert.NotBefore).Hours() / 24); d > 0 {
			return d
		}
	}
	return 90
}

func keyTypePermitted(tpl *store.CertificateTemplate, keyType string) bool {
	if len(tpl.AllowedKeyTypes) == 0 {
		return true
	}
	for _, allowed := range tpl.AllowedKeyTypes {
		if strings.EqualFold(allowed, keyType) {
			return true
		}
	}
	return false
}

func firstPermittedKeyType(tpl *store.CertificateTemplate) string {
	for _, want := range []string{"RSA", "ECDSA", "Ed25519"} {
		for _, allowed := range tpl.AllowedKeyTypes {
			if strings.EqualFold(allowed, want) {
				return want
			}
		}
	}
	return ""
}

func curvePermitted(tpl *store.CertificateTemplate, bits int) bool {
	if len(tpl.ECDSACurves) == 0 {
		return true
	}
	for _, c := range tpl.ECDSACurves {
		if curveBits(c) == bits {
			return true
		}
	}
	return false
}

// weakestPermittedCurve is the least the template allows, not the most.
// Renewal moving a key is already a change; moving it further than the rules
// require is a second one nobody asked for.
func weakestPermittedCurve(tpl *store.CertificateTemplate) int {
	best := 0
	for _, c := range tpl.ECDSACurves {
		if bits := curveBits(c); bits > 0 && (best == 0 || bits < best) {
			best = bits
		}
	}
	return best
}

func curveBits(curve string) int {
	switch strings.ToUpper(strings.TrimSpace(curve)) {
	case "P-256", "P256", "PRIME256V1", "SECP256R1":
		return 256
	case "P-384", "P384", "SECP384R1":
		return 384
	case "P-521", "P521", "SECP521R1":
		return 521
	}
	return 0
}

// hasSuffix matches on label boundaries, so `evil-example.com` does not pass a
// rule that allows `example.com`.
func hasSuffix(name string, suffixes []string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(suffix), "."))
		if suffix == "" {
			continue
		}
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

// conformance decides what this renewal should ask for, and records what it
// could not fix.
//
// Never returns an error and never refuses. An expired certificate is a worse
// outcome than a non-conforming one, and a sweep that declined to renew would
// turn a policy tightening into an outage across an estate — which is exactly
// the class of failure that makes people switch automation off.
func (e *Executor) conformance(ctx context.Context, cert *store.Certificate) *conformance {
	if e.policyEng == nil {
		return &conformance{KeyType: cert.KeyType, KeySize: cert.KeySize}
	}

	shape, err := conform(ctx, e.store, e.policyEng, cert)
	if err != nil {
		// Judged nothing, so renew what is there. Said out loud rather than
		// swallowed: "renewed without being judged" and "renewed and conforms"
		// must not look identical in a log.
		slog.Warn("renewing without re-evaluating the rules",
			"cert_id", cert.ID, "common_name", cert.CommonName, "error", err)
		return shape
	}

	for _, up := range shape.Upgrades {
		slog.Info("renewing into conformance",
			"cert_id", cert.ID, "common_name", cert.CommonName, "change", up)
	}
	if len(shape.Unfixable) > 0 {
		// Renewal cannot fix these — a name outside a tightened suffix rule
		// cannot be dropped, because the endpoints serving it expect it. So the
		// certificate is renewed and the divergence is raised for a person.
		slog.Warn("renewing a certificate that no longer satisfies its rules",
			"cert_id", cert.ID, "common_name", cert.CommonName,
			"reasons", strings.Join(shape.Unfixable, "; "))
		e.announceDrift(cert, shape)
	}
	return shape
}

// announceDrift publishes what renewal could not fix.
//
// "Fourteen certificates renew under rules they no longer satisfy" is a
// sentence about a real estate that nothing in this product could produce
// before. It is also what makes tightening a rule worth doing: without it, a
// policy change affects only certificates that do not exist yet.
func (e *Executor) announceDrift(cert *store.Certificate, shape *conformance) {
	_ = e.store.CreateAuditLog(context.Background(), &store.AuditLog{
		Action:     "cert.renewed_nonconforming",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details: fmt.Sprintf(`{"cn":%q,"reasons":%q}`,
			cert.CommonName, strings.Join(shape.Unfixable, "; ")),
	})

	if e.broker == nil {
		return
	}
	e.broker.Publish(events.Event{
		Topic:    events.TopicCertRenewedNonConforming,
		Severity: events.SeverityWarning,
		EntityID: cert.ID,
		Payload: map[string]any{
			"certificate_id": cert.ID,
			"common_name":    cert.CommonName,
			"conforms":       false,
			"reasons":        shape.Unfixable,
		},
	})
}

// renewalNames is what this certificate covers, deduplicated.
//
// CAB Forum rules require the common name to also appear as a SAN, so an issued
// certificate carries it in both fields and `append([]string{cert.CommonName},
// cert.SANs...)` lists it twice. Issuance has deduplicated since the inventory
// started reporting "one extra name" on every certificate; renewal never did,
// so it sent the duplicate to the CA and reported every naming finding twice.
func renewalNames(cert *store.Certificate) []string {
	seen := make(map[string]bool, len(cert.SANs)+1)
	out := make([]string, 0, len(cert.SANs)+1)
	for _, n := range append([]string{cert.CommonName}, cert.SANs...) {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}
