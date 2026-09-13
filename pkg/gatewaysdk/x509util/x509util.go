// Package x509util provides utilities for parsing and inspecting X.509 certificates.
package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"
)

// CertInfo holds parsed information about an X.509 certificate.
type CertInfo struct {
	CommonName        string    `json:"common_name"`
	SANs              []string  `json:"sans"`
	SerialNumber      string    `json:"serial_number"`
	IssuerDN          string    `json:"issuer_dn"`
	SubjectDN         string    `json:"subject_dn"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	DaysRemaining     int       `json:"days_remaining"`
	KeyType           string    `json:"key_type"`
	KeySize           int       `json:"key_size"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	IsCA              bool      `json:"is_ca"`

	// SignatureAlgorithm is how this certificate was signed, which is a
	// different fact from what its key is and is not derivable from it. A
	// certificate can carry a perfectly good ECDSA P-384 key and be signed with
	// SHA-1, and only one of those two is visible in KeyType. Cryptographic
	// posture reporting that looked only at the key would call that certificate
	// healthy.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	// PublicKeyAlgorithm is the algorithm name as X.509 records it, kept beside
	// KeyType because KeyType carries this project's own vocabulary and this
	// carries the certificate's.
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`
	// Curve is the named curve for an elliptic key — P-256, P-384 — which is
	// the parameter set a CBOM has to name and which KeySize only implies.
	Curve    string   `json:"curve,omitempty"`
	Issuer   string   `json:"issuer"`
	CRLURLs  []string `json:"crl_urls"`
	OCSPURLs []string `json:"ocsp_urls"`
}

// ParseCertificatePEM parses a PEM-encoded certificate and returns CertInfo.
func ParseCertificatePEM(certPEM []byte) (*CertInfo, error) {
	cert, err := ParseX509PEM(certPEM)
	if err != nil {
		return nil, err
	}
	return CertInfoFromX509(cert), nil
}

// ParseX509PEM returns the certificate itself rather than a summary of it.
//
// CertInfo is a flattened view for storage and display; anything doing
// cryptography needs the real thing — checking revocation, for one, has to hash
// the issuer's public key and verify a signature, and neither is derivable from
// a struct of strings.
func ParseX509PEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// CertInfoFromX509 extracts CertInfo from a parsed x509.Certificate.
func CertInfoFromX509(cert *x509.Certificate) *CertInfo {
	fingerprint := sha256.Sum256(cert.Raw)

	info := &CertInfo{
		CommonName:        cert.Subject.CommonName,
		SANs:              cert.DNSNames,
		SerialNumber:      cert.SerialNumber.Text(16),
		IssuerDN:          cert.Issuer.String(),
		SubjectDN:         cert.Subject.String(),
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		DaysRemaining:     daysUntil(cert.NotAfter),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		IsCA:              cert.IsCA,
		CRLURLs:           cert.CRLDistributionPoints,
		OCSPURLs:          cert.OCSPServer,
	}

	info.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	info.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()

	// Determine key type and size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType = "RSA"
		info.KeySize = pub.Size() * 8
	case *ecdsa.PublicKey:
		info.KeyType = "ECDSA"
		if pub.Curve != nil {
			info.KeySize = pub.Curve.Params().BitSize
			info.Curve = pub.Curve.Params().Name
		} else {
			info.KeySize = 256
		}
	case ed25519.PublicKey:
		info.KeyType = "Ed25519"
		info.KeySize = 256
		info.Curve = "Curve25519"
	default:
		info.KeyType = "Unknown"
		info.KeySize = 0
	}

	return info
}

// ParseCertificateChainPEM parses a PEM bundle containing multiple certificates.
func ParseCertificateChainPEM(chainPEM []byte) ([]*CertInfo, error) {
	var certs []*CertInfo
	rest := chainPEM

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in chain: %w", err)
		}

		certs = append(certs, CertInfoFromX509(cert))
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM bundle")
	}

	return certs, nil
}

// DetermineCAType returns "ROOT", "INTERMEDIATE", or "ISSUING" based on cert properties.
func DetermineCAType(cert *x509.Certificate) string {
	if !cert.IsCA {
		return ""
	}
	// Self-signed = root
	if cert.Issuer.String() == cert.Subject.String() {
		return "ROOT"
	}
	// CA with basic constraints and path length = 0 → issuing
	if cert.MaxPathLen == 0 && cert.MaxPathLenZero {
		return "ISSUING"
	}
	return "INTERMEDIATE"
}

func daysUntil(t time.Time) int {
	d := time.Until(t).Hours() / 24
	if d < 0 {
		return 0
	}
	return int(d)
}
