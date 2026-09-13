// Package crypto provides utilities for cryptographic key generation and CSR creation.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
)

// KeyType represents the type of cryptographic key.
type KeyType string

const (
	KeyTypeRSA     KeyType = "RSA"
	KeyTypeECDSA   KeyType = "ECDSA"
	KeyTypeEd25519 KeyType = "Ed25519"
)

// GenerateKeyPair generates a new private key of the specified type and size.
func GenerateKeyPair(keyType KeyType, keySize int) (crypto.PrivateKey, error) {
	switch keyType {
	case KeyTypeRSA:
		if keySize < 2048 {
			keySize = 2048
		}
		return rsa.GenerateKey(rand.Reader, keySize)
	case KeyTypeECDSA:
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case KeyTypeEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// GenerateCSR creates a Certificate Signing Request for the given domains.
func GenerateCSR(privateKey crypto.PrivateKey, commonName string, sans []string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: sans,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// EncodePrivateKeyPEM encodes a private key to PEM format.
func EncodePrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}), nil
	case ed25519.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ParseKeyType parses a string into a KeyType.
func ParseKeyType(s string) (KeyType, error) {
	switch strings.ToUpper(s) {
	case "RSA":
		return KeyTypeRSA, nil
	case "ECDSA", "EC":
		return KeyTypeECDSA, nil
	case "ED25519":
		return KeyTypeEd25519, nil
	default:
		return "", fmt.Errorf("unknown key type: %s", s)
	}
}
