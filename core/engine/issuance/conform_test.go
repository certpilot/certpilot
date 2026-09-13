package issuance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// issueTestCert builds a real, parseable certificate with the given shape, so
// these tests exercise VerifyConformance against bytes it actually has to
// parse — not a struct built to match what the check expects.
func issueTestCert(t *testing.T, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svc.example.com"},
		DNSNames:     []string{"svc.example.com"},
		NotBefore:    now,
		NotAfter:     now.Add(30 * 24 * time.Hour),
		IsCA:         true,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestVerifyConformanceOnAnExactMatchFindsNothing(t *testing.T) {
	d := &Decision{KeyType: "ECDSA", KeySize: 256, Domains: []string{"svc.example.com"}, ValidityDays: 30}
	certPEM := issueTestCert(t, nil)

	findings, err := VerifyConformance(d, certPEM)
	if err != nil {
		t.Fatalf("VerifyConformance: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("an exact match should find nothing, got %+v", findings)
	}
}

// TestVerifyConformanceCatchesAWrongKeyType. The gateway that generates its
// own key when it should have signed a CSR is #29's precedent for this whole
// mechanism; this is the same failure one layer later, for a CA that signs
// with a key type nobody asked for.
func TestVerifyConformanceCatchesAWrongKeyType(t *testing.T) {
	d := &Decision{KeyType: "RSA", KeySize: 2048, Domains: []string{"svc.example.com"}}
	certPEM := issueTestCert(t, nil) // actually ECDSA

	findings, err := VerifyConformance(d, certPEM)
	if err != nil {
		t.Fatalf("VerifyConformance: %v", err)
	}
	if !hasFinding(findings, "key_type", store.FindingBlock) {
		t.Fatalf("expected a BLOCK finding on key_type, got %+v", findings)
	}
}

// TestVerifyConformanceCatchesAddedNames. A CA that issued for more than was
// authorised is the one this project can least afford to record silently:
// the extra name is now a certificate in the inventory for something nobody
// approved.
func TestVerifyConformanceCatchesAddedNames(t *testing.T) {
	d := &Decision{Domains: []string{"svc.example.com"}}
	certPEM := issueTestCert(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"svc.example.com", "unexpected.example.com"}
	})

	findings, err := VerifyConformance(d, certPEM)
	if err != nil {
		t.Fatalf("VerifyConformance: %v", err)
	}
	if !hasFinding(findings, "sans", store.FindingBlock) {
		t.Fatalf("expected a BLOCK finding on sans, got %+v", findings)
	}
}

// TestVerifyConformanceReportsShorterValidityWithoutBlocking. The CA capping
// lifetime below what was requested is the CA being correct — every public CA
// does this — and refusing it would make CertPilot unusable against any of
// them.
func TestVerifyConformanceReportsShorterValidityWithoutBlocking(t *testing.T) {
	d := &Decision{ValidityDays: 90}
	certPEM := issueTestCert(t, func(c *x509.Certificate) {
		c.NotAfter = c.NotBefore.Add(47 * 24 * time.Hour)
	})

	findings, err := VerifyConformance(d, certPEM)
	if err != nil {
		t.Fatalf("VerifyConformance: %v", err)
	}
	if !hasFinding(findings, "validity", store.FindingReport) {
		t.Fatalf("expected a REPORT finding on validity, got %+v", findings)
	}
	if hasFinding(findings, "validity", store.FindingBlock) {
		t.Fatalf("a shorter validity must never be BLOCK-class, got %+v", findings)
	}
}

// TestVerifyConformanceBlocksLongerValidity. The other direction is not the
// CA being generous — it is either misconfigured or not the CA that was
// expected, and the issue is explicit that this direction blocks.
func TestVerifyConformanceBlocksLongerValidity(t *testing.T) {
	d := &Decision{ValidityDays: 30}
	certPEM := issueTestCert(t, func(c *x509.Certificate) {
		c.NotAfter = c.NotBefore.Add(365 * 24 * time.Hour)
	})

	findings, err := VerifyConformance(d, certPEM)
	if err != nil {
		t.Fatalf("VerifyConformance: %v", err)
	}
	if !hasFinding(findings, "validity", store.FindingBlock) {
		t.Fatalf("expected a BLOCK finding on validity, got %+v", findings)
	}
}

// TestVerifyConformanceReportsAnAddedSubjectField. Some CAs add an OU by
// policy; refusing would make CertPilot unusable against them, and hiding it
// would make the template's SUPPLIED subject a fiction.
func TestVerifyConformanceReportsAnAddedSubjectField(t *testing.T) {
	d := &Decision{
		Template: &store.CertificateTemplate{
			SubjectMode:     "SUPPLIED",
			SubjectDefaults: map[string]string{"O": "Example Ltd"},
		},
	}
	certPEM := issueTestCert(t, func(c *x509.Certificate) {
		c.Subject.Organization = []string{"Example Ltd"}
		c.Subject.OrganizationalUnit = []string{"Managed PKI"}
	})

	findings, err := VerifyConformance(d, certPEM)
	if err != nil {
		t.Fatalf("VerifyConformance: %v", err)
	}
	if !hasFinding(findings, "subject", store.FindingReport) {
		t.Fatalf("expected a REPORT finding on subject, got %+v", findings)
	}
}

// TestVerifyConformanceIgnoresSubjectUnderConstrainedMode. CONSTRAINED means
// the requester chose the subject; this function has no template default to
// compare against and must not invent one.
func TestVerifyConformanceIgnoresSubjectUnderConstrainedMode(t *testing.T) {
	d := &Decision{Template: &store.CertificateTemplate{SubjectMode: "CONSTRAINED"}}
	certPEM := issueTestCert(t, func(c *x509.Certificate) {
		c.Subject.OrganizationalUnit = []string{"Whatever The Requester Chose"}
	})

	findings, err := VerifyConformance(d, certPEM)
	if err != nil {
		t.Fatalf("VerifyConformance: %v", err)
	}
	if hasFinding(findings, "subject", "") {
		t.Fatalf("CONSTRAINED mode must not check subject fields, got %+v", findings)
	}
}

// TestEnforcedFiltersByTemplateConformance is the axis VerifyConformance
// deliberately does not know about: the same findings, read under both
// settings, must come out different.
func TestEnforcedFiltersByTemplateConformance(t *testing.T) {
	findings := []store.ConformanceFinding{
		{Field: "key_type", Severity: store.FindingBlock},
		{Field: "validity", Severity: store.FindingReport},
	}

	report := &store.CertificateTemplate{Conformance: store.ConformanceReport}
	if got := Enforced(report, findings); len(got) != 0 {
		t.Fatalf("REPORT must never block, got %+v", got)
	}

	enforce := &store.CertificateTemplate{Conformance: store.ConformanceEnforce}
	got := Enforced(enforce, findings)
	if len(got) != 1 || got[0].Field != "key_type" {
		t.Fatalf("ENFORCE must block exactly the BLOCK-class findings, got %+v", got)
	}
}

func hasFinding(findings []store.ConformanceFinding, field, severity string) bool {
	for _, f := range findings {
		if f.Field == field && (severity == "" || f.Severity == severity) {
			return true
		}
	}
	return false
}
