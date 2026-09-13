package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenerateKeyPairRSA(t *testing.T) {
	key, err := GenerateKeyPair(KeyTypeRSA, 2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair RSA failed: %v", err)
	}

	pemBytes, err := EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Errorf("expected RSA PRIVATE KEY PEM block, got %v", block)
	}
}

func TestGenerateKeyPairECDSA(t *testing.T) {
	key, err := GenerateKeyPair(KeyTypeECDSA, 256)
	if err != nil {
		t.Fatalf("GenerateKeyPair ECDSA failed: %v", err)
	}

	pemBytes, err := EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Errorf("expected EC PRIVATE KEY PEM block, got %v", block)
	}
}

func TestGenerateCSR(t *testing.T) {
	key, err := GenerateKeyPair(KeyTypeRSA, 2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	csrPEM, err := GenerateCSR(key, "example.com", []string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected CERTIFICATE REQUEST block, got %v", block)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	if csr.Subject.CommonName != "example.com" {
		t.Errorf("expected CN example.com, got %s", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(csr.DNSNames))
	}
}
