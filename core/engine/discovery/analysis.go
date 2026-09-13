package discovery

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// Finding codes. Stable identifiers: a dashboard filter, an alert rule, and a
// suppression list all key off these, so they outlive any rewording of the
// detail text.
const (
	FindingExpired          = "expired"
	FindingNotYetValid      = "not_yet_valid"
	FindingExpiringSoon     = "expiring_soon"
	FindingHostnameMismatch = "hostname_mismatch"
	FindingSelfSigned       = "self_signed"
	FindingUntrustedIssuer  = "untrusted_issuer"
	FindingIncompleteChain  = "incomplete_chain"
	FindingWeakKey          = "weak_key"
	FindingWeakSignature    = "weak_signature"
	FindingLegacyTLS        = "legacy_tls"
	FindingWeakCipher       = "weak_cipher"
	FindingNoForwardSecrecy = "no_forward_secrecy"
	FindingLongValidity     = "long_validity"

	// Findings that only exist on a repeated scan. The value of the second run
	// is not the list, it is the difference.
	FindingCertificateChanged  = "certificate_changed"
	FindingEndpointDisappeared = "endpoint_disappeared"
	FindingEndpointAppeared    = "endpoint_appeared"
)

// reconcile compares an endpoint against what it was last seen serving.
//
// Returns the findings that describe the change, and whether the change is one
// worth telling somebody about.
//
// The distinction that carries the weight: a certificate that changed on an
// endpoint CertPilot manages is a renewal, and unremarkable. The same change on
// an endpoint it does not manage means something out there renewed a
// certificate without going through any of this — which is the shadow-PKI
// signal the whole feature exists to surface, and it is invisible to a first
// scan.
func reconcile(result *store.DiscoveryResult, previous *store.DiscoveryResult) []store.Finding {
	findings := []store.Finding{}
	if previous == nil {
		// Not a finding on its own. Every endpoint is new the first time, and
		// an estate's first scan should not report itself as a hundred changes.
		return findings
	}

	switch {
	case previous.Reachable && !result.Reachable:
		findings = append(findings, store.Finding{
			Code:     FindingEndpointDisappeared,
			Severity: events.SeverityWarning,
			Detail: fmt.Sprintf("This endpoint was serving %q when it was last scanned on %s, and no longer answers. Either it moved and the scan no longer covers it, or it is down.",
				fallbackName(previous), previous.ScannedAt.UTC().Format("2 January 2006")),
		})

	case !previous.Reachable && result.Reachable:
		findings = append(findings, store.Finding{
			Code:     FindingEndpointAppeared,
			Severity: events.SeverityInfo,
			Detail:   "This endpoint did not answer the last time it was scanned and does now.",
		})

	case result.Reachable && previous.FingerprintSHA256 != "" &&
		previous.FingerprintSHA256 != result.FingerprintSHA256:
		severity := events.SeverityInfo
		detail := fmt.Sprintf("The certificate here changed since %s. CertPilot manages the new one, so this is a renewal it knows about.",
			previous.ScannedAt.UTC().Format("2 January 2006"))
		if result.ManagementState != store.DiscoveryManaged {
			// The finding that only a repeated scan can produce.
			severity = events.SeverityWarning
			detail = fmt.Sprintf("The certificate here changed since %s and CertPilot manages neither the old one nor the new one. Something is renewing certificates on this endpoint outside this system, so somebody knows how to replace it — find out who.",
				previous.ScannedAt.UTC().Format("2 January 2006"))
		}
		findings = append(findings, store.Finding{
			Code: FindingCertificateChanged, Severity: severity, Detail: detail,
		})
	}

	return findings
}

func fallbackName(result *store.DiscoveryResult) string {
	if result.CommonName != "" {
		return result.CommonName
	}
	return "a certificate"
}

const (
	// expiringSoonDays is when a discovered certificate starts being a finding
	// in its own right. Deliberately wider than the renewal lead time: this one
	// is not being renewed by anything, so the clock that matters is how long
	// someone has to find an owner for it.
	expiringSoonDays = 30
	// publicMaxValidityDays tracks CA/Browser Forum ballot SC-081v3, which took
	// maximum TLS validity to 200 days in March 2026. A publicly-trusted
	// certificate issued for longer than the current maximum predates the
	// change, so it is the one that will not renew the way its owner expects.
	publicMaxValidityDays = 200
	// minRSABits and minECDSABits are the floor below which a key is not a
	// weakness to schedule but a finding to act on.
	minRSABits   = 2048
	minECDSABits = 256
)

// analyse decides what the served chain terminates in, and what is wrong with
// the endpoint.
//
// Trust and validity are answered separately and on purpose. An expired
// certificate from a CA the organisation runs is a different problem from a
// current certificate signed by a CA nobody can identify, and a scanner that
// collapsed both into "invalid" would leave the reader unable to tell which
// they were looking at.
func analyse(probe *Probe, anchors *TrustAnchors, now time.Time) (string, []store.Finding) {
	findings := []store.Finding{}
	if len(probe.Chain) == 0 {
		return store.TrustUnknown, findings
	}
	leaf := probe.Chain[0]

	trust := resolveTrust(probe, anchors, now)
	incomplete := chainIncomplete(probe.Chain, anchors)

	// ── Validity ───────────────────────────────────────────
	switch {
	case now.After(leaf.NotAfter):
		findings = append(findings, store.Finding{
			Code:     FindingExpired,
			Severity: events.SeverityCritical,
			Detail: fmt.Sprintf("The certificate expired on %s, %s ago. Anything still validating it is failing now.",
				leaf.NotAfter.UTC().Format("2 January 2006"), humanDuration(now.Sub(leaf.NotAfter))),
		})
	case now.Before(leaf.NotBefore):
		findings = append(findings, store.Finding{
			Code:     FindingNotYetValid,
			Severity: events.SeverityCritical,
			Detail: fmt.Sprintf("The certificate is not valid until %s. Clients are rejecting it now, and a clock skew on either side is the usual cause.",
				leaf.NotBefore.UTC().Format("2 January 2006")),
		})
	default:
		if days := int(leaf.NotAfter.Sub(now).Hours() / 24); days <= expiringSoonDays {
			findings = append(findings, store.Finding{
				Code:     FindingExpiringSoon,
				Severity: events.SeverityWarning,
				Detail: fmt.Sprintf("The certificate expires in %d days, on %s.",
					days, leaf.NotAfter.UTC().Format("2 January 2006")),
			})
		}
	}

	// ── Identity ───────────────────────────────────────────
	if err := leaf.VerifyHostname(probe.Target.Host); err != nil {
		// Scanning by IP address and getting a name-based certificate is
		// expected rather than wrong: the server has no way to know which
		// virtual host was wanted. Recorded, but not as a problem with the
		// endpoint.
		severity := events.SeverityCritical
		detail := fmt.Sprintf("The certificate is not valid for %q. It covers %s.",
			probe.Target.Host, describeNames(leaf))
		if net.ParseIP(probe.Target.Host) != nil {
			severity = events.SeverityInfo
			detail = fmt.Sprintf("Scanned by IP address, so the server returned its default virtual host. The certificate covers %s.",
				describeNames(leaf))
		}
		findings = append(findings, store.Finding{
			Code: FindingHostnameMismatch, Severity: severity, Detail: detail,
		})
	}

	// ── Trust ──────────────────────────────────────────────
	switch trust {
	case store.TrustSelfSigned:
		findings = append(findings, store.Finding{
			Code:     FindingSelfSigned,
			Severity: events.SeverityWarning,
			Detail:   "The certificate signed itself, so no CA vouches for this endpoint and no CA can revoke it. Appliances shipped with a default certificate look like this.",
		})
	case store.TrustUntrusted:
		findings = append(findings, store.Finding{
			Code:     FindingUntrustedIssuer,
			Severity: events.SeverityWarning,
			Detail: fmt.Sprintf("The chain terminates in %q, which is neither publicly trusted nor a CA registered in CertPilot. Either register that CA so its expiry is watched, or find out who is issuing certificates here.",
				leaf.Issuer.String()),
		})
	case store.TrustInternal:
		if name, ok := anchors.name(probe.Chain); ok {
			findings = append(findings, store.Finding{
				Code:     "internal_issuer",
				Severity: events.SeverityInfo,
				Detail:   fmt.Sprintf("Issued by %q, a CA registered in CertPilot.", name),
			})
		}
	}

	if incomplete {
		findings = append(findings, store.Finding{
			Code:     FindingIncompleteChain,
			Severity: events.SeverityWarning,
			Detail: fmt.Sprintf("The server sent %s and no issuing CA certificate. Clients that already hold the intermediate will connect and clients that do not will fail, which is why this breaks intermittently and only for some users.",
				pluralCerts(len(probe.Chain))),
		})
	}

	findings = append(findings, keyFindings(leaf)...)
	findings = append(findings, chainSignatureFindings(probe.Chain)...)
	findings = append(findings, handshakeFindings(probe)...)

	if trust == store.TrustPublic {
		if days := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24); days > publicMaxValidityDays {
			findings = append(findings, store.Finding{
				Code:     FindingLongValidity,
				Severity: events.SeverityWarning,
				Detail: fmt.Sprintf("Issued for %d days, longer than the %d-day maximum public CAs may now issue. Its replacement will be shorter-lived, so whatever renews it has to run more often than it does today.",
					days, publicMaxValidityDays),
			})
		}
	}

	return trust, findings
}

// chainIncomplete reports whether the server failed to send an intermediate it
// needed to.
//
// The rule: a served chain is complete when the certificate at the top of it is
// self-signed, or when its issuer is a root. Anything else means the client has
// to already hold an intermediate to get there — which some clients will and
// some will not, and that is exactly why a missing intermediate breaks
// intermittently, for some users, on some machines.
//
// When the issuing certificate is one CertPilot holds, the answer is
// definitive. When it is not, the only case called is a server that sent
// nothing but its own leaf: no public CA has been permitted to issue directly
// from a root for years, so a lone non-self-signed leaf is a missing
// intermediate with near-certainty. Anything else stays silent rather than
// putting a finding on every correctly-configured endpoint.
//
// The reason this cannot lean on verification: a platform verifier caches
// intermediates it has seen before, so the same endpoint verifies cleanly on a
// machine that has visited it and fails on a fresh one. Which is exactly the
// defect being looked for, and exactly why it cannot be found by asking whether
// verification succeeded here.
func chainIncomplete(chain []*x509.Certificate, anchors *TrustAnchors) bool {
	if len(chain) == 0 {
		return false
	}
	top := chain[len(chain)-1]
	if isSelfSigned(top) {
		return false
	}
	if issuer := anchors.find(top.Issuer.String()); issuer != nil {
		return !isSelfSigned(issuer)
	}
	return len(chain) == 1 && !chain[0].IsCA
}

// find returns the registered CA certificate with this subject, or nil.
func (a *TrustAnchors) find(subjectDN string) *x509.Certificate {
	if a == nil {
		return nil
	}
	for _, cert := range a.Certs {
		if cert.Subject.String() == subjectDN {
			return cert
		}
	}
	return nil
}

// resolveTrust reports what the served chain terminates in.
//
// Verification runs at a time inside the certificate's validity window rather
// than at now. An expired certificate fails every verification for one reason,
// and letting that reason swallow the answer to "who issued this" would report
// every expired internal certificate as issued by an unknown CA — which is the
// opposite of the truth and points the investigation the wrong way. Expiry is
// reported by its own finding.
func resolveTrust(probe *Probe, anchors *TrustAnchors, now time.Time) string {
	leaf := probe.Chain[0]

	served := x509.NewCertPool()
	for _, cert := range probe.Chain[1:] {
		served.AddCert(cert)
	}

	// Verification is attempted at now, and then at a moment inside the
	// certificate's own validity window. An expired certificate fails path
	// building for one reason, and letting that reason decide the trust answer
	// would report every expired public certificate as issued by an unknown CA.
	verify := func(intermediates *x509.CertPool) bool {
		for _, at := range []time.Time{now, leaf.NotAfter.Add(-time.Hour), leaf.NotBefore.Add(time.Hour)} {
			_, err := leaf.Verify(x509.VerifyOptions{
				// Nil roots means the host's public store.
				Intermediates: intermediates,
				CurrentTime:   at,
				// The hostname is checked separately, so that "wrong name" and
				// "unknown issuer" stay two answers rather than one.
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if err == nil {
				return true
			}
		}
		return false
	}

	if verify(served) {
		return store.TrustPublic
	}
	if !anchors.Empty() {
		withAnchors := x509.NewCertPool()
		for _, cert := range probe.Chain[1:] {
			withAnchors.AddCert(cert)
		}
		for _, cert := range anchors.Certs {
			withAnchors.AddCert(cert)
		}
		if verify(withAnchors) {
			return store.TrustPublic
		}
	}

	// Internal trust is decided on signatures rather than by path building.
	//
	// The question is not "is this chain valid today" but "did a CA this
	// organisation watches sign this", and those come apart precisely when it
	// matters most: an expired certificate, an intermediate whose own validity
	// window has moved on, a clock that is wrong. Every one of those would fail
	// x509 verification and be reported as an unknown issuer, sending whoever
	// reads it looking for a rogue CA that does not exist.
	if issuedByAnchor(probe.Chain, anchors) {
		return store.TrustInternal
	}

	if isSelfSigned(leaf) {
		return store.TrustSelfSigned
	}
	return store.TrustUntrusted
}

// issuedByAnchor reports whether any certificate in the served chain was signed
// by a CA registered in CertPilot.
//
// Walks the whole chain, not just the leaf: an endpoint serving
// leaf → intermediate where only the root is registered is still issued under a
// hierarchy the organisation runs.
func issuedByAnchor(chain []*x509.Certificate, anchors *TrustAnchors) bool {
	if anchors.Empty() {
		return false
	}
	for _, cert := range chain {
		issuer := anchors.find(cert.Issuer.String())
		if issuer == nil {
			continue
		}
		// CheckSignatureFrom verifies the signature and that the issuer is
		// permitted to sign certificates. It deliberately says nothing about
		// validity dates, which is the property being relied on here.
		if cert.CheckSignatureFrom(issuer) == nil {
			return true
		}
	}
	return false
}

// isSelfSigned reports whether the certificate signed itself.
//
// Checks the signature directly rather than through CheckSignatureFrom, which
// also requires the issuer to be a valid CA. A self-signed *leaf* — the default
// certificate on an appliance, the thing this most often finds — carries no CA
// basic constraint, so CheckSignatureFrom rejects it and it would be reported
// as having an unknown issuer instead of as self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func keyFindings(leaf *x509.Certificate) []store.Finding {
	findings := []store.Finding{}

	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := pub.N.BitLen(); bits < minRSABits {
			findings = append(findings, store.Finding{
				Code:     FindingWeakKey,
				Severity: events.SeverityCritical,
				Detail: fmt.Sprintf("RSA-%d. Below the %d-bit minimum, and no public CA will renew it at this size.",
					bits, minRSABits),
			})
		}
	case *ecdsa.PublicKey:
		if bits := pub.Curve.Params().BitSize; bits < minECDSABits {
			findings = append(findings, store.Finding{
				Code:     FindingWeakKey,
				Severity: events.SeverityCritical,
				Detail:   fmt.Sprintf("ECDSA on a %d-bit curve, below the %d-bit minimum.", bits, minECDSABits),
			})
		}
	}

	return findings
}

// chainSignatureFindings looks for obsolete signatures anywhere in the served
// chain, not only on the leaf.
//
// A SHA-1 intermediate breaks the chain just as completely as a SHA-1 leaf, and
// it is the more common of the two — a certificate reissued with a modern
// signature under an intermediate nobody rotated. Checking only the leaf reports
// that endpoint as clean while browsers refuse it.
//
// Self-signed certificates are skipped. A root's own signature is never
// verified by anything; flagging a SHA-1 root is the classic false positive that
// teaches people to ignore this check.
func chainSignatureFindings(chain []*x509.Certificate) []store.Finding {
	findings := []store.Finding{}

	for i, cert := range chain {
		if isSelfSigned(cert) {
			continue
		}
		switch cert.SignatureAlgorithm {
		case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			where := "The certificate is"
			if i > 0 {
				where = fmt.Sprintf("%q, an issuing certificate in the served chain, is", cert.Subject.CommonName)
			}
			findings = append(findings, store.Finding{
				Code:     FindingWeakSignature,
				Severity: events.SeverityCritical,
				Detail: fmt.Sprintf("%s signed with %s. Browsers have rejected this family of signatures for years, so anything still accepting this endpoint is not checking.",
					where, cert.SignatureAlgorithm),
			})
		}
	}

	return findings
}

func handshakeFindings(probe *Probe) []store.Finding {
	findings := []store.Finding{}

	if probe.Version < tls.VersionTLS12 {
		findings = append(findings, store.Finding{
			Code:     FindingLegacyTLS,
			Severity: events.SeverityWarning,
			Detail: fmt.Sprintf("Negotiated %s. Every major client refuses this by default, so whatever is still talking to this endpoint has been configured to accept it.",
				tlsVersionName(probe.Version)),
		})
	}

	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == probe.CipherSuite {
			findings = append(findings, store.Finding{
				Code:     FindingWeakCipher,
				Severity: events.SeverityWarning,
				Detail:   fmt.Sprintf("Negotiated %s, which Go classifies as insecure.", tls.CipherSuiteName(probe.CipherSuite)),
			})
			break
		}
	}

	if probe.CurveID == 0 && probe.Version >= tls.VersionTLS12 {
		findings = append(findings, store.Finding{
			Code:     FindingNoForwardSecrecy,
			Severity: events.SeverityWarning,
			Detail:   "The key exchange was RSA key transport. A recording of this traffic becomes readable the day the server's private key leaks, however far in the future that is.",
		})
	}

	// A classical key exchange is deliberately *not* a finding.
	//
	// It is true of nearly every endpoint on the internet today, and a finding
	// that appears on almost every row is not a finding — it is the noise that
	// makes people stop reading the list. The fact itself is not lost: the
	// negotiated group is recorded verbatim on the result instead, which is
	// where a posture report reads it from — "142 of your endpoints do not
	// negotiate X25519MLKEM768" is a query over that column, not a finding on
	// 142 rows.

	return findings
}

// name returns the CertPilot name of the CA that issued this chain, if one of
// the registered CAs appears in it.
func (a *TrustAnchors) name(chain []*x509.Certificate) (string, bool) {
	if a == nil {
		return "", false
	}
	// The leaf's issuer first, which is the CA that actually signed it.
	if name, ok := a.Names[chain[0].Issuer.String()]; ok {
		return name, true
	}
	for _, cert := range chain[1:] {
		if name, ok := a.Names[cert.Subject.String()]; ok {
			return name, true
		}
	}
	return "", false
}

func describeNames(cert *x509.Certificate) string {
	names := allNames(cert)
	switch {
	case len(names) == 0:
		return "no names at all"
	case len(names) <= 4:
		return strings.Join(names, ", ")
	default:
		return fmt.Sprintf("%s and %d more", strings.Join(names[:4], ", "), len(names)-4)
	}
}

func pluralCerts(n int) string {
	if n == 1 {
		return "only its own certificate"
	}
	return fmt.Sprintf("%d certificates", n)
}

func humanDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 365:
		return fmt.Sprintf("%d years", days/365)
	case days >= 1:
		return fmt.Sprintf("%d days", days)
	default:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
}

// FingerprintSHA256 renders a certificate's SHA-256 fingerprint in the form
// CertPilot stores and compares on.
//
// Exported because it is the identity the whole system agrees on: discovery
// decides managed-or-not with it, cloud inventory matches on it, and
// post-renewal verification asks with it whether the certificate a server is
// presenting is the one that was just issued. Two spellings of that would be
// two answers to the same question.
func FingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return x509util.CertInfoFromX509(cert).FingerprintSHA256
}
