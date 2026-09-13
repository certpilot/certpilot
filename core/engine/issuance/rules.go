package issuance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/certpilot/certpilot/core/store"
)

// applyNamesAndKey fills the Decision from the CSR where there is one and from
// the request where there is not — rungs 6 and 5.
//
// A CSR outranks the request for exactly two things and for a reason that is
// not about precedence: the names and the public key are facts about a document
// that has already been signed. Honouring a conflicting key_type from the JSON
// body would issue a certificate whose key nobody holds.
func applyNamesAndKey(d *Decision, tpl *store.CertificateTemplate, req Request) error {
	if req.CSR != nil {
		names := req.CSR.Names()
		if len(names) == 0 {
			return refuse(RungRequest, "the signing request names nothing to certify")
		}
		d.CommonName = names[0]
		d.Domains = dedupe(names)
		d.KeyType = req.CSR.KeyType
		d.KeySize = req.CSR.KeySize
	} else {
		if strings.TrimSpace(req.CommonName) == "" {
			return refuse(RungRequest,
				"common_name is required when no csr_pem is supplied")
		}
		d.CommonName = req.CommonName
		d.Domains = dedupe(append([]string{req.CommonName}, req.SANs...))
		d.KeyType = req.KeyType
		d.KeySize = req.KeySize
	}

	// Where the request said nothing, the template's own floor is a better
	// default than a constant: a template that permits only ECDSA should not
	// have RSA chosen for it and then refused one line later.
	if d.KeyType == "" {
		d.KeyType = defaultKeyType(tpl)
	}
	if d.KeySize <= 0 {
		d.KeySize = defaultKeySize(tpl, d.KeyType)
	}
	return nil
}

func defaultKeyType(tpl *store.CertificateTemplate) string {
	for _, want := range []string{"RSA", "ECDSA", "Ed25519"} {
		for _, allowed := range tpl.AllowedKeyTypes {
			if strings.EqualFold(allowed, want) {
				return want
			}
		}
	}
	if len(tpl.AllowedKeyTypes) > 0 {
		return tpl.AllowedKeyTypes[0]
	}
	return "RSA"
}

func defaultKeySize(tpl *store.CertificateTemplate, keyType string) int {
	switch strings.ToUpper(keyType) {
	case "RSA":
		if tpl.RSAMinBits > 0 {
			return tpl.RSAMinBits
		}
		return 2048
	case "ECDSA":
		if bits := weakestCurve(tpl.ECDSACurves); bits > 0 {
			return bits
		}
		return 256
	default:
		return 256
	}
}

// applySuppliedValues is rung 2: what the template decides regardless of what
// was asked for.
func applySuppliedValues(d *Decision, tpl *store.CertificateTemplate, req Request) {
	if tpl.ValidityDays > 0 {
		if req.ValidityDays > 0 && req.ValidityDays != tpl.ValidityDays {
			d.Overrides = append(d.Overrides, fmt.Sprintf(
				"validity_days: asked for %d, template %q issues %d",
				req.ValidityDays, tpl.Slug, tpl.ValidityDays))
		}
		d.ValidityDays = tpl.ValidityDays
	} else {
		d.ValidityDays = req.ValidityDays
		if d.ValidityDays <= 0 {
			d.ValidityDays = 90
		}
	}

	d.Environment = req.Environment
	if d.Environment == "" {
		d.Environment = tpl.DefaultEnvironment
	}
	d.Team = req.Team
	if d.Team == "" {
		d.Team = tpl.DefaultTeam
	}
	d.Tags = req.Tags
	if len(d.Tags) == 0 {
		d.Tags = tpl.DefaultTags
	}
}

// checkTemplate is rung 3: everything the template constrains.
func checkTemplate(d *Decision, tpl *store.CertificateTemplate, req Request) error {
	if err := checkAuthorityRequest(req); err != nil {
		return err
	}
	if err := checkKey(d, tpl); err != nil {
		return err
	}
	if err := checkSANTypes(tpl, req); err != nil {
		return err
	}
	if err := checkNames(d, tpl); err != nil {
		return err
	}
	if err := checkSubject(tpl, req); err != nil {
		return err
	}
	if err := checkCustody(tpl, req); err != nil {
		return err
	}
	if err := checkMetadata(tpl, req); err != nil {
		return err
	}
	if tpl.MaxValidityDays > 0 && d.ValidityDays > tpl.MaxValidityDays {
		return refuse(RungTemplate,
			"a lifetime of %d days was asked for and template %q allows at most %d",
			d.ValidityDays, tpl.Slug, tpl.MaxValidityDays)
	}
	return nil
}

func checkKey(d *Decision, tpl *store.CertificateTemplate) error {
	permitted := false
	for _, allowed := range tpl.AllowedKeyTypes {
		if strings.EqualFold(allowed, d.KeyType) {
			permitted = true
			break
		}
	}
	if !permitted {
		return refuse(RungTemplate,
			"key type %s is not one template %q issues (%s)",
			d.KeyType, tpl.Slug, strings.Join(tpl.AllowedKeyTypes, ", "))
	}

	switch strings.ToUpper(d.KeyType) {
	case "RSA":
		if tpl.RSAMinBits > 0 && d.KeySize < tpl.RSAMinBits {
			return refuse(RungTemplate,
				"an RSA key of %d bits was asked for and template %q requires at least %d",
				d.KeySize, tpl.Slug, tpl.RSAMinBits)
		}
		if tpl.RSAMaxBits > 0 && d.KeySize > tpl.RSAMaxBits {
			return refuse(RungTemplate,
				"an RSA key of %d bits was asked for and template %q allows at most %d",
				d.KeySize, tpl.Slug, tpl.RSAMaxBits)
		}
	case "ECDSA":
		if len(tpl.ECDSACurves) == 0 {
			return nil
		}
		for _, curve := range tpl.ECDSACurves {
			if curveBits(curve) == d.KeySize {
				return nil
			}
		}
		return refuse(RungTemplate,
			"curve P-%d is not one template %q issues (%s)",
			d.KeySize, tpl.Slug, strings.Join(tpl.ECDSACurves, ", "))
	}
	return nil
}

func checkNames(d *Decision, tpl *store.CertificateTemplate) error {
	rule := tpl.CommonNameRule
	if rule.Required != nil && *rule.Required && strings.TrimSpace(d.CommonName) == "" {
		return refuse(RungTemplate,
			"template %q requires a common name and the request has none", tpl.Slug)
	}

	if tpl.SANRules.MaxNames > 0 && len(d.Domains) > tpl.SANRules.MaxNames {
		return refuse(RungTemplate,
			"%d names were asked for and template %q allows at most %d",
			len(d.Domains), tpl.Slug, tpl.SANRules.MaxNames)
	}

	// The suffix lists are additive. A name has to clear whichever of them the
	// template wrote; a template that wrote neither restricts nothing.
	suffixes := append(append([]string{}, rule.Suffixes...), tpl.SANRules.Suffixes...)

	allowWildcards := tpl.SANRules.AllowWildcards != nil && *tpl.SANRules.AllowWildcards

	for _, name := range d.Domains {
		if strings.HasPrefix(name, "*.") && !allowWildcards {
			return refuse(RungTemplate,
				"wildcard name %q is not permitted by template %q", name, tpl.Slug)
		}
		for _, pattern := range rule.ForbiddenPatterns {
			if pattern != "" && strings.Contains(strings.ToLower(name), strings.ToLower(pattern)) {
				return refuse(RungTemplate,
					"name %q contains %q, which template %q forbids", name, pattern, tpl.Slug)
			}
		}
		if len(suffixes) > 0 && !hasSuffix(name, suffixes) {
			return refuse(RungTemplate,
				"name %q is outside the suffixes template %q allows (%s)",
				name, tpl.Slug, strings.Join(suffixes, ", "))
		}
	}
	return nil
}

// checkSubject is the ESC1 rung.
//
// With subject_mode SUPPLIED the requester does not choose the subject. A CSR
// carries one, and CertPilot cannot strip it: the request is signed and is
// passed to the CA as it stands, so rewriting it is not available. Refusing is
// the only honest enforcement — an override that silently did nothing would be
// a control that reports success while the CA issues whatever the CSR asked
// for.
func checkSubject(tpl *store.CertificateTemplate, req Request) error {
	if tpl.SubjectMode != store.SubjectModeSupplied || req.CSR == nil {
		return nil
	}
	if len(tpl.SubjectDefaults) == 0 {
		return nil
	}

	keys := make([]string, 0, len(tpl.SubjectDefaults))
	for key := range tpl.SubjectDefaults {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		want := tpl.SubjectDefaults[key]
		got, present := req.CSR.Subject[key]
		if !present || got == want {
			continue
		}
		return refuse(RungTemplate,
			"the signing request asks for %s=%q and template %q supplies %s=%q. "+
				"A signed request cannot be rewritten, so this one has to be regenerated "+
				"or issued under a template whose subject the requester may set",
			key, got, tpl.Slug, key, want)
	}
	return nil
}

func checkCustody(tpl *store.CertificateTemplate, req Request) error {
	if tpl.CSRRequired && req.CSR == nil {
		return refuse(RungTemplate,
			"template %q issues only against a signing request, so the private key is "+
				"generated by the requester and never reaches CertPilot", tpl.Slug)
	}
	if tpl.KeyCustodyRequired == store.KeyCustodyAny || tpl.KeyCustodyRequired == "" {
		return nil
	}
	if req.KeyCustody != "" && req.KeyCustody != tpl.KeyCustodyRequired {
		return refuse(RungTemplate,
			"template %q issues only certificates whose key is held by %s, and this one would be held by %s",
			tpl.Slug, tpl.KeyCustodyRequired, req.KeyCustody)
	}
	return nil
}

func checkMetadata(tpl *store.CertificateTemplate, req Request) error {
	if len(tpl.RequireMetadata) == 0 {
		return nil
	}
	answered := make(map[string]bool, len(req.MetadataKeys))
	for _, key := range req.MetadataKeys {
		answered[key] = true
	}
	var missing []string
	for _, key := range tpl.RequireMetadata {
		if !answered[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return refuse(RungTemplate,
			"template %q requires %s, which this request does not answer",
			tpl.Slug, strings.Join(missing, ", "))
	}
	return nil
}

// ── Shared helpers ──────────────────────────────────────────

// hasSuffix matches on label boundaries.
//
// A plain strings.HasSuffix lets `evil-example.com` pass a rule that allows
// `example.com`, which is the whole attack this kind of rule exists to stop.
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

// dedupe removes repeats while preserving order, comparing without regard to
// case because DNS names are case-insensitive and "APP.example.com" and
// "app.example.com" are one name.
//
// CAB Forum rules require the common name to also appear as a SAN, so nearly
// every client sends it in both fields — and the certificate came back listing
// the same name twice, which the inventory then reported as "one extra name".
// Harmless in the certificate, wrong on every screen that counts them.
func dedupe(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		// Lowercased and stripped of a trailing dot, because DNS names are
		// case-insensitive and "app.example.com." is the same name as
		// "app.example.com". Normalising here rather than at each comparison is
		// what lets the issued certificate, the grant's name list and the
		// template's suffixes all be talking about the same string.
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
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

// weakestCurve is the default when a request named no size: the least this
// template permits, rather than the most. A default that silently chose the
// strongest available would be a different certificate from the one an
// unchanged caller used to get.
func weakestCurve(curves []string) int {
	best := 0
	for _, c := range curves {
		if bits := curveBits(c); bits > 0 && (best == 0 || bits < best) {
			best = bits
		}
	}
	return best
}

// checkAuthorityRequest refuses a request asking to become an authority.
//
// Refused rather than stripped: a client asking for basicConstraints CA:TRUE or
// keyCertSign is either broken or hostile, and both deserve an error rather
// than a certificate that silently is not what they asked for.
//
// This lived in the fleet issuer and applied only to agents, so a person
// submitting the same CSR through the API reached the gateway unchecked — the
// mirror image of the bypass this package exists to close. It applies to every
// path now because every path comes through here.
func checkAuthorityRequest(req Request) error {
	if req.CSR == nil {
		return nil
	}
	if req.CSR.RequestsCA {
		return refuse(RungTemplate,
			"this request asks for a CA certificate (basicConstraints CA:TRUE). "+
				"CertPilot issues certificates for the names a requester has been granted, "+
				"never an authority that could issue more")
	}
	if req.CSR.RequestsKeyCertSign {
		return refuse(RungTemplate,
			"this request asks for the keyCertSign usage, which would let the certificate "+
				"sign others. CertPilot issues certificates, never an authority")
	}
	return nil
}

// checkSANTypes enforces san_rules.types.
//
// Without this the field was accepted by the API, stored, shown on the template
// and consulted by nothing — a rule an operator wrote that changed no outcome.
// That is the defect class this whole line of work exists to remove, and it was
// reintroduced one layer up.
//
// Only a CSR can carry an IP, email or URI name; the JSON request body has no
// field for them. So a request without one has only DNS names by construction
// and nothing to check.
func checkSANTypes(tpl *store.CertificateTemplate, req Request) error {
	if len(tpl.SANRules.Types) == 0 || req.CSR == nil {
		return nil
	}

	permitted := map[string]bool{}
	for _, t := range tpl.SANRules.Types {
		permitted[strings.ToUpper(strings.TrimSpace(t))] = true
	}

	for _, present := range []struct {
		kind   string
		values []string
	}{
		{"IP", req.CSR.IPAddresses},
		{"EMAIL", req.CSR.EmailAddresses},
		{"URI", req.CSR.URIs},
	} {
		if len(present.values) == 0 || permitted[present.kind] {
			continue
		}
		return refuse(RungTemplate,
			"the signing request carries %s name %q, and template %q permits only %s",
			strings.ToLower(present.kind), present.values[0], tpl.Slug,
			strings.Join(tpl.SANRules.Types, ", "))
	}

	// DNS is the one that can be forbidden rather than merely absent, and a
	// template permitting only IP or email names is a real configuration —
	// a SPIFFE identity, or a mail server certificate.
	if len(req.CSR.DNSNames) > 0 && !permitted["DNS"] {
		return refuse(RungTemplate,
			"the signing request carries DNS name %q, and template %q permits only %s",
			req.CSR.DNSNames[0], tpl.Slug, strings.Join(tpl.SANRules.Types, ", "))
	}
	return nil
}
