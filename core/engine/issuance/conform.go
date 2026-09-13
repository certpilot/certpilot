package issuance

import (
	"crypto/x509"
	"fmt"
	"sort"
	"strings"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/store"
)

// This file is #30, and the reasoning for it is stated in the issue plainly
// enough to repeat rather than paraphrase: CertPilot cannot enforce key usage
// or extended key usage on ACME or Vault, because those are the CA's decision.
// Sending a request and storing whatever comes back, unchecked, is a control
// that passes while enforcing nothing — reintroduced at the very last step of
// a milestone that exists to remove exactly that shape of defect.
//
// The one honest answer available is issue, then check: parse what the CA
// actually returned and compare it against what the template asked for.

// VerifyConformance compares an issued certificate against the decision that
// authorised it, returning every way they diverge.
//
// Every finding here is real regardless of the template's conformance
// setting — this function does not know about ENFORCE or REPORT, and does not
// need to: it answers "did the CA do what was asked", which has one answer,
// not two. What differs by template is what happens next, which is Enforced's
// job and happens after this returns.
func VerifyConformance(d *Decision, certPEM []byte) ([]store.ConformanceFinding, error) {
	info, err := x509util.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("cannot verify conformance: %w", err)
	}
	cert, err := x509util.ParseX509PEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("cannot verify conformance: %w", err)
	}

	var findings []store.ConformanceFinding
	findings = append(findings, checkKeyConformance(d, info)...)
	findings = append(findings, checkNameConformance(d, info)...)
	findings = append(findings, checkValidityConformance(d, info)...)
	findings = append(findings, checkSubjectConformance(d, cert)...)
	return findings, nil
}

// Enforced returns the findings an ENFORCE template refuses on. Under REPORT,
// always empty: every finding is recorded, none blocks.
//
// This is the one place the template's conformance setting is read. Keeping
// it separate from VerifyConformance means the comparison itself cannot drift
// from what actually happened based on a setting that has nothing to do with
// whether something happened.
func Enforced(tpl *store.CertificateTemplate, findings []store.ConformanceFinding) []store.ConformanceFinding {
	if tpl.Conformance != store.ConformanceEnforce {
		return nil
	}
	var blocking []store.ConformanceFinding
	for _, f := range findings {
		if f.Severity == store.FindingBlock {
			blocking = append(blocking, f)
		}
	}
	return blocking
}

// checkKeyConformance: key type and size are BLOCK-class. A certificate
// carrying a different key than what was asked for is not the certificate
// that was authorised — recording it would launder an unauthorised key into
// something that looks authorised, which is worse than refusing it.
func checkKeyConformance(d *Decision, info *x509util.CertInfo) []store.ConformanceFinding {
	var out []store.ConformanceFinding
	if d.KeyType != "" && !strings.EqualFold(d.KeyType, info.KeyType) {
		out = append(out, store.ConformanceFinding{
			Field:    "key_type",
			Severity: store.FindingBlock,
			Message: fmt.Sprintf("requested %s, the CA issued %s",
				d.KeyType, orUnknown(info.KeyType)),
		})
	}
	// Ed25519 has one size; comparing it would only ever produce a finding
	// that says 256 != 256 under a different label, or refuse a certificate
	// for no reason tied to what was actually asked.
	if d.KeySize > 0 && !strings.EqualFold(info.KeyType, "Ed25519") && d.KeySize != info.KeySize {
		out = append(out, store.ConformanceFinding{
			Field:    "key_size",
			Severity: store.FindingBlock,
			Message:  fmt.Sprintf("requested %d bits, the CA issued %d", d.KeySize, info.KeySize),
		})
	}
	return out
}

// checkNameConformance: the names on the certificate must be exactly the set
// that was authorised — not a superset, not a subset. BLOCK-class: a CA that
// added or dropped a name issued for something other than what the decision
// permitted, and the record must not imply otherwise.
func checkNameConformance(d *Decision, info *x509util.CertInfo) []store.ConformanceFinding {
	if len(d.Domains) == 0 {
		return nil
	}
	want := normalizedSet(d.Domains)
	have := normalizedSet(info.SANs)

	var missing, extra []string
	for name := range want {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	for name := range have {
		if !want[name] {
			extra = append(extra, name)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(extra)

	var detail []string
	if len(missing) > 0 {
		detail = append(detail, fmt.Sprintf("missing %s", strings.Join(missing, ", ")))
	}
	if len(extra) > 0 {
		detail = append(detail, fmt.Sprintf("added %s", strings.Join(extra, ", ")))
	}
	return []store.ConformanceFinding{{
		Field:    "sans",
		Severity: store.FindingBlock,
		Message:  fmt.Sprintf("the certificate's names do not match what was authorised: %s", strings.Join(detail, "; ")),
	}}
}

// checkValidityConformance: shorter is the CA being correct (public CAs cap
// lifetime; SC-081v3 is already shortening every deadline this project
// tracks) and is recorded, never blocked. Longer means the CA issued beyond
// what was asked, which is either a misconfiguration or the wrong CA — BLOCK.
//
// A day of slack absorbs rounding: "30 days" requested becomes a NotBefore/
// NotAfter pair that is almost never exactly 30*24h apart once a CA's own
// clock and not-before backdating are in it.
func checkValidityConformance(d *Decision, info *x509util.CertInfo) []store.ConformanceFinding {
	if d.ValidityDays <= 0 {
		return nil
	}
	actualDays := info.NotAfter.Sub(info.NotBefore).Hours() / 24
	requested := float64(d.ValidityDays)
	const slack = 1.0

	switch {
	case actualDays < requested-slack:
		return []store.ConformanceFinding{{
			Field:    "validity",
			Severity: store.FindingReport,
			Message: fmt.Sprintf("requested %d days, the CA issued %.0f — most public CAs cap lifetime below what is asked",
				d.ValidityDays, actualDays),
		}}
	case actualDays > requested+slack:
		return []store.ConformanceFinding{{
			Field:    "validity",
			Severity: store.FindingBlock,
			Message: fmt.Sprintf("requested %d days, the CA issued %.0f — a CA issuing beyond the requested lifetime is misconfigured or is not the CA that was expected",
				d.ValidityDays, actualDays),
		}}
	default:
		return nil
	}
}

// checkSubjectConformance: fields the CA added beyond what SUPPLIED asked
// for. Always REPORT — refusing would make CertPilot unusable against any CA
// that adds, say, an OU by policy, and hiding the addition would make the
// template a fiction. Only checked in SUPPLIED mode: CONSTRAINED means the
// requester chose the subject, and this function has no opinion about a
// subject nobody here specified.
func checkSubjectConformance(d *Decision, cert *x509.Certificate) []store.ConformanceFinding {
	if d.Template == nil || d.Template.SubjectMode != "SUPPLIED" {
		return nil
	}
	declared := map[string]bool{}
	for k := range d.Template.SubjectDefaults {
		declared[strings.ToUpper(strings.TrimSpace(k))] = true
	}

	var added []string
	check := func(key string, values []string) {
		if len(values) > 0 && !declared[key] {
			added = append(added, key)
		}
	}
	check("O", cert.Subject.Organization)
	check("OU", cert.Subject.OrganizationalUnit)
	check("C", cert.Subject.Country)
	check("L", cert.Subject.Locality)
	check("ST", cert.Subject.Province)
	if len(added) == 0 {
		return nil
	}
	sort.Strings(added)
	return []store.ConformanceFinding{{
		Field:    "subject",
		Severity: store.FindingReport,
		Message: fmt.Sprintf("the CA added subject field%s the template did not declare: %s",
			plural(len(added)), strings.Join(added, ", ")),
	}}
}

func normalizedSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))] = true
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown key type"
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
