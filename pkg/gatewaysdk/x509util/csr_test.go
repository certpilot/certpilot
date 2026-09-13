package x509util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"strings"
	"testing"
)

func makeCSR(t *testing.T, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestAValidRequestIsParsed(t *testing.T) {
	csrPEM := makeCSR(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com", "www.example.com"},
	})

	info, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	if info.CommonName != "app.example.com" {
		t.Errorf("common name = %q", info.CommonName)
	}
	if info.KeyType != "ECDSA" || info.KeySize != 256 {
		t.Errorf("key = %s-%d, want ECDSA-256", info.KeyType, info.KeySize)
	}
	if info.Curve != "P-256" {
		t.Errorf("curve = %q, want P-256", info.Curve)
	}
}

// TestATamperedRequestIsRefused is the reason ParseCSRPEM exists rather than a
// bare x509.ParseCertificateRequest call.
//
// Go does not verify a CSR's signature when parsing it. The signature is the
// only thing that makes a CSR a request rather than an assertion: without this
// check, anyone can submit a request carrying somebody else's public key and
// have a CA issue a certificate for names they control, bound to a key held by
// someone else.
func TestATamperedRequestIsRefused(t *testing.T) {
	csrPEM := makeCSR(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com"},
	})

	block, _ := pem.Decode(csrPEM)
	// Corrupt the trailing signature bytes, leaving the request body intact and
	// still parseable — exactly what a forgery looks like.
	der := append([]byte(nil), block.Bytes...)
	der[len(der)-1] ^= 0xff
	der[len(der)-2] ^= 0xff
	tampered := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	if _, err := ParseCSRPEM(tampered); err == nil {
		t.Fatal("a request whose signature does not verify was accepted; it does not prove possession of the private key")
	} else if !strings.Contains(err.Error(), "possession") {
		t.Errorf("error should say what the failure means, got: %v", err)
	}
}

func TestACertificatePastedInsteadIsNamed(t *testing.T) {
	// The commonest paste error. A generic "could not parse" sends people
	// looking at their CSR tooling instead of at their clipboard.
	certPEM := generateTestCert(t)
	_, err := ParseCSRPEM(certPEM)
	if err == nil {
		t.Fatal("a certificate was accepted as a signing request")
	}
	if !strings.Contains(err.Error(), "not a signing request") {
		t.Errorf("error should say it is a certificate, got: %v", err)
	}
}

func TestAPrivateKeyPastedInsteadIsRefusedWithoutEchoingIt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	_, err = ParseCSRPEM(keyPEM)
	if err == nil {
		t.Fatal("a private key was accepted as a signing request")
	}
	if !strings.Contains(err.Error(), "do not paste private keys") {
		t.Errorf("error should warn against it, got: %v", err)
	}
	// The message is going into an HTTP response and very likely a log.
	if strings.Contains(err.Error(), "PRIVATE KEY") && strings.Contains(err.Error(), "MII") {
		t.Error("the error echoes key material back")
	}
}

// TestTheCommonNameIsNotRepeatedAsASAN guards a detail that is easy to get
// wrong: CAB Forum rules require the CN to also appear in the SAN list, so
// nearly every real CSR carries it twice.
func TestTheCommonNameIsNotRepeatedAsASAN(t *testing.T) {
	csrPEM := makeCSR(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"APP.example.com", "www.example.com"},
	})

	info, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	names := info.Names()
	if len(names) != 2 {
		t.Fatalf("names = %v, want the common name once plus one SAN", names)
	}
	if names[0] != "app.example.com" {
		t.Errorf("the common name should lead, got %v", names)
	}
}

func TestARequestWithNoNamesIsRefused(t *testing.T) {
	csrPEM := makeCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{Organization: []string{"Example Corp"}},
	})

	if _, err := ParseCSRPEM(csrPEM); err == nil {
		t.Fatal("a request asking for no names was accepted")
	}
}

// TestNamesThatCannotBeCarriedAreReported covers the difference between issuing
// what was asked for and issuing something close to it. A dropped IP SAN is
// discovered in production unless it is reported here.
func TestNamesThatCannotBeCarriedAreReported(t *testing.T) {
	csrPEM := makeCSR(t, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "app.example.com"},
		DNSNames:       []string{"app.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.7")},
		EmailAddresses: []string{"ops@example.com"},
	})

	info, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	dropped := info.DroppedNames()
	if len(dropped) != 2 {
		t.Fatalf("dropped = %v, want the IP and the email", dropped)
	}
}

func TestAnRSARequestReportsItsModulusSize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	info, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	// The policy engine gates on key size, so a wrong number here is a policy
	// bypass rather than a display bug.
	if info.KeyType != "RSA" || info.KeySize != 2048 {
		t.Errorf("key = %s-%d, want RSA-2048", info.KeyType, info.KeySize)
	}
}

func TestGarbageIsRefused(t *testing.T) {
	if _, err := ParseCSRPEM([]byte("hello")); err == nil {
		t.Fatal("non-PEM input was accepted")
	}
}
