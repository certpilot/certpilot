package selfsigned

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// signingCA is the authority this gateway signs CSRs with.
//
// A self-signed certificate is one whose subject key signed it, which is
// precisely what a CSR makes impossible: the requester keeps the private key,
// so nothing here can produce that signature. Honouring a CSR therefore means
// being a small CA, and this is it.
//
// Generated once per process and held in memory. That is the right shape for a
// development gateway — nothing here should ever be trusted by anything that
// matters, and a CA key that does not survive a restart is a CA key that cannot
// quietly become load-bearing.
type signingCA struct {
	once sync.Once
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  []byte
	err  error
}

var localCA signingCA

func (c *signingCA) get() (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	c.once.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			c.err = err
			return
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			c.err = err
			return
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:   "CertPilot Self-Signed Gateway CA",
				Organization: []string{"CertPilot Self-Signed"},
			},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLenZero:        true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			c.err = err
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			c.err = err
			return
		}
		c.key, c.cert = key, cert
		c.pem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

		slog.Info("self-signed gateway created its signing CA for this process",
			"subject", tmpl.Subject.CommonName, "serial", serial.Text(16),
			"note", "in memory only; a restart issues from a new authority")
	})
	return c.key, c.cert, c.pem, c.err
}

// issueFromCSR signs a caller-supplied certificate request.
//
// This is the path that matters. A CSR means the private key was generated
// wherever it will be used and has never travelled — which is the whole point
// of the host agent, and the reason this gateway needed to grow a CA at all.
//
// Two rules, and both are the sort of thing a CA gets wrong once:
//
//   - The signature on the CSR is checked. Without it, anybody who can reach
//     this gateway can obtain a certificate for a public key they do not hold
//     the private half of, which is a certificate issued to whoever the key
//     really belongs to.
//   - **Every extension the CSR asks for is ignored.** A CSR is a request, not
//     an instruction. A request carrying basicConstraints CA:TRUE must not
//     produce a CA certificate, and the safe way to guarantee that is to build
//     the template here rather than to copy anything out of the request.
func issueFromCSR(req *providerv1.IssueCertificateRequest) (*providerv1.IssueCertificateResponse, error) {
	block, _ := pem.Decode(req.CsrPem)
	if block == nil {
		return nil, fmt.Errorf("csr_pem is not a PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("csr_pem is not a certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the certificate request is not signed by the key it contains: %w", err)
	}

	caKey, caCert, caPEM, err := localCA.get()
	if err != nil {
		return nil, fmt.Errorf("this gateway could not create a signing authority: %w", err)
	}

	// Names come from the caller, which has already decided what this requester
	// is allowed to ask for. The CSR's own names are used only when the caller
	// supplied none.
	domains := req.Domains
	if len(domains) == 0 {
		domains = csr.DNSNames
		if len(domains) == 0 && csr.Subject.CommonName != "" {
			domains = []string{csr.Subject.CommonName}
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains were supplied and the request contains none")
	}

	validityDays := 365
	if req.ValidityDays > 0 {
		validityDays = int(req.ValidityDays)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	// Built here, from nothing the request asked for beyond its public key.
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domains[0], Organization: []string{"CertPilot Self-Signed"}},
		DNSNames:              domains,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign the certificate request: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyType, keySize := describeKey(csr)
	slog.Info("signed a certificate request",
		"cn", template.Subject.CommonName, "domains", domains,
		"serial", serial.Text(16), "key", fmt.Sprintf("%s/%d", keyType, keySize),
		"private_key", "not seen by this gateway")

	return &providerv1.IssueCertificateResponse{
		Certificate: &commonv1.CertificateInfo{
			CommonName:     template.Subject.CommonName,
			Sans:           domains,
			SerialNumber:   serial.Text(16),
			IssuerDn:       caCert.Subject.String(),
			SubjectDn:      template.Subject.String(),
			NotBefore:      timestamppb.New(template.NotBefore),
			NotAfter:       timestamppb.New(template.NotAfter),
			KeyType:        keyType,
			KeySize:        int32(keySize),
			CertificatePem: certPEM,
			ChainPem:       caPEM,
			// Deliberately absent. The requester has the private key; this
			// gateway never saw it and has nothing to return.
			PrivateKeyPem: nil,
		},
		ProviderCertificateId: serial.Text(16),
	}, nil
}

// describeKey reports what the requester's key is, for the record.
func describeKey(csr *x509.CertificateRequest) (string, int) {
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	default:
		switch csr.PublicKeyAlgorithm {
		case x509.RSA:
			if k, ok := csr.PublicKey.(interface{ Size() int }); ok {
				return "RSA", k.Size() * 8
			}
			return "RSA", 0
		case x509.Ed25519:
			return "Ed25519", 256
		}
	}
	return csr.PublicKeyAlgorithm.String(), 0
}
