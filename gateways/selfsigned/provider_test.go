package selfsigned

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
)

func TestIssueCertificate(t *testing.T) {
	p := NewProvider()

	req := &providerv1.IssueCertificateRequest{
		Domains:      []string{"test.example.com", "api.example.com"},
		KeyType:      "RSA",
		KeySize:      2048,
		ValidityDays: 90,
	}

	resp, err := p.IssueCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if resp.Certificate == nil {
		t.Fatal("expected certificate in response, got nil")
	}

	if resp.Certificate.CommonName != "test.example.com" {
		t.Errorf("expected CN test.example.com, got %s", resp.Certificate.CommonName)
	}

	if len(resp.Certificate.Sans) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(resp.Certificate.Sans))
	}

	// Decode and parse the returned PEM
	block, _ := pem.Decode(resp.Certificate.CertificatePem)
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("parsed cert CN mismatch: %s", cert.Subject.CommonName)
	}

	// Test self-signature verification
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-signature verification failed: %v", err)
	}
}

func TestCapabilities(t *testing.T) {
	p := NewProvider()

	resp, err := p.GetCapabilities(context.Background(), &providerv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities failed: %v", err)
	}

	if resp.Capabilities.ProviderName != "selfsigned" {
		t.Errorf("expected provider name selfsigned, got %s", resp.Capabilities.ProviderName)
	}
	if !resp.Capabilities.SupportsWildcard {
		t.Errorf("expected SupportsWildcard=true")
	}
}

func TestHealthCheck(t *testing.T) {
	p := NewProvider()

	resp, err := p.HealthCheck(context.Background(), &providerv1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	if resp.Status == 0 {
		t.Errorf("expected valid health status, got 0")
	}
}

// TestACSRIsSignedWithoutTheGatewaySeeingTheKey.
//
// The path the agent uses. A CSR means the private key was generated wherever
// it will be used and has never travelled — so a response carrying one would
// mean the gateway had ignored the request and generated its own pair, and the
// certificate on the host would not match the key in the database.
func TestACSRIsSignedWithoutTheGatewaySeeingTheKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "site.example.com"},
		DNSNames: []string{"site.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	resp, err := NewProvider().IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		CsrPem:  csrPEM,
		Domains: []string{"site.example.com"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(resp.Certificate.PrivateKeyPem) != 0 {
		t.Fatal("a CSR-based issuance must return no private key")
	}
	if len(resp.Certificate.ChainPem) == 0 {
		t.Fatal("a signed certificate needs the authority that signed it")
	}

	block, _ := pem.Decode(resp.Certificate.CertificatePem)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The certificate carries the requester's public key, which is the whole
	// point: only the host can use it.
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("the certificate does not carry the key from the request")
	}
	// And it is not an authority, whatever anybody asked for.
	if cert.IsCA {
		t.Fatal("a certificate signed from a CSR must not be a CA")
	}
}

// TestAnUnsignedCSRIsRefused. Without this check anybody who can reach the
// gateway could obtain a certificate for a public key they do not hold.
func TestAnUnsignedCSRIsRefused(t *testing.T) {
	_, err := NewProvider().IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		CsrPem: []byte("-----BEGIN CERTIFICATE REQUEST-----\nbm90aGluZw==\n-----END CERTIFICATE REQUEST-----\n"),
	})
	if err == nil {
		t.Fatal("garbage must not produce a certificate")
	}
}
