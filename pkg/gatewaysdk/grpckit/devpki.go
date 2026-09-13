package grpckit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// DevPKI is the set of files GenerateDevPKI writes.
type DevPKI struct {
	CACert     string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// GenerateDevPKI creates a throwaway CA and an mTLS keypair for each end of the
// core-to-gateway channel.
//
// Mutual TLS is only worth requiring if turning it on is a single command.
// Without this, the realistic outcome is that every developer runs with TLS
// disabled and that setting follows them to production. The material here is
// explicitly not production material: the CA key is written next to the
// certificates it signs, and everything expires in a year.
//
// Existing files are left alone, so re-running is safe.
func GenerateDevPKI(dir string, hosts []string) (*DevPKI, error) {
	if dir == "" {
		return nil, fmt.Errorf("grpckit: output directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("grpckit: failed to create %s: %w", dir, err)
	}

	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}

	paths := &DevPKI{
		CACert:     filepath.Join(dir, "ca.pem"),
		ServerCert: filepath.Join(dir, "gateway.pem"),
		ServerKey:  filepath.Join(dir, "gateway-key.pem"),
		ClientCert: filepath.Join(dir, "core.pem"),
		ClientKey:  filepath.Join(dir, "core-key.pem"),
	}
	caKeyPath := filepath.Join(dir, "ca-key.pem")

	if allExist(paths.CACert, paths.ServerCert, paths.ServerKey, paths.ClientCert, paths.ClientKey) {
		return paths, nil
	}

	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: "CertPilot Development CA", Organization: []string{"CertPilot"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("grpckit: failed to create development CA: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	if err := writePEM(paths.CACert, "CERTIFICATE", caDER, 0o644); err != nil {
		return nil, err
	}
	if err := writeKey(caKeyPath, caKey); err != nil {
		return nil, err
	}

	// The gateway certificate authenticates the server end and must carry the
	// names the core will dial.
	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: "certpilot-gateway", Organization: []string{"CertPilot"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}
	if err := issueInto(paths.ServerCert, paths.ServerKey, serverTemplate, caCert, caKey); err != nil {
		return nil, err
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: "certpilot-core", Organization: []string{"CertPilot"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := issueInto(paths.ClientCert, paths.ClientKey, clientTemplate, caCert, caKey); err != nil {
		return nil, err
	}

	return paths, nil
}

func issueInto(certPath, keyPath string, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return fmt.Errorf("grpckit: failed to issue %s: %w", certPath, err)
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	return writeKey(keyPath, key)
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, encoded, mode); err != nil {
		return fmt.Errorf("grpckit: failed to write %s: %w", path, err)
	}
	return nil
}

func mustSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// crypto/rand failing means the process cannot do anything useful.
		panic("grpckit: crypto/rand unavailable: " + err.Error())
	}
	return serial
}

func allExist(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}
