package x509util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   "pki.example.com",
			Organization: []string{"CertPilot Tests"},
		},
		DNSNames:              []string{"pki.example.com", "alt.example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(60 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
		OCSPServer:            []string{"http://ocsp.example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseCertificatePEM(t *testing.T) {
	certPEM := generateTestCert(t)

	info, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}

	if info.CommonName != "pki.example.com" {
		t.Errorf("expected CN pki.example.com, got %s", info.CommonName)
	}

	if len(info.SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(info.SANs))
	}

	if info.KeyType != "RSA" {
		t.Errorf("expected key type RSA, got %s", info.KeyType)
	}

	if info.KeySize != 2048 {
		t.Errorf("expected key size 2048, got %d", info.KeySize)
	}

	if len(info.CRLURLs) != 1 || info.CRLURLs[0] != "http://crl.example.com/ca.crl" {
		t.Errorf("CRL URLs mismatch: %v", info.CRLURLs)
	}

	if len(info.OCSPURLs) != 1 || info.OCSPURLs[0] != "http://ocsp.example.com" {
		t.Errorf("OCSP URLs mismatch: %v", info.OCSPURLs)
	}

	if info.DaysRemaining < 59 || info.DaysRemaining > 61 {
		t.Errorf("expected ~60 days remaining, got %d", info.DaysRemaining)
	}
}
