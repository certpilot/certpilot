package acmeserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
)

// fakeGateway signs whatever CSR it is given with a CA of its own, or refuses
// when told to. It is the far end of finalize.
type fakeGateway struct {
	providerv1.UnimplementedCertificateProviderServiceServer
	addr    string
	refuse  atomic.Bool
	issued  atomic.Int32
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	lastDNS atomic.Value
}

func startGateway(t *testing.T) *fakeGateway {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := grpckit.NewServer(grpckit.ServerOptions{MaxRecvMsgSize: 10 << 20, TLS: grpckit.TLSConfig{Insecure: true}})
	if err != nil {
		t.Fatal(err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ACME Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(der)
	gw := &fakeGateway{addr: lis.Addr().String(), caKey: caKey, caCert: caCert}
	providerv1.RegisterCertificateProviderServiceServer(srv, gw)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return gw
}

func (g *fakeGateway) GetCapabilities(context.Context, *providerv1.GetCapabilitiesRequest) (*providerv1.GetCapabilitiesResponse, error) {
	return &providerv1.GetCapabilitiesResponse{Capabilities: &commonv1.ProviderCapabilities{
		ProviderName: "fake", ProviderType: "selfsigned", SupportedKeyTypes: []string{"ECDSA", "RSA"},
	}}, nil
}

func (g *fakeGateway) HealthCheck(context.Context, *providerv1.HealthCheckRequest) (*providerv1.HealthCheckResponse, error) {
	return &providerv1.HealthCheckResponse{Status: commonv1.HealthStatus_HEALTH_STATUS_HEALTHY}, nil
}

func (g *fakeGateway) IssueCertificate(_ context.Context, req *providerv1.IssueCertificateRequest) (*providerv1.IssueCertificateResponse, error) {
	if g.refuse.Load() {
		return nil, errors.New("the CA is refusing everything today")
	}
	block, _ := pem.Decode(req.GetCsrPem())
	if block == nil {
		return nil, errors.New("no CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	g.lastDNS.Store(req.GetDomains())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: req.GetDomains()[0]},
		DNSNames:     req.GetDomains(),
		NotBefore:    time.Now(), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, g.caCert, csr.PublicKey, g.caKey)
	if err != nil {
		return nil, err
	}
	g.issued.Add(1)
	return &providerv1.IssueCertificateResponse{Certificate: &commonv1.CertificateInfo{
		CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		ChainPem:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.caCert.Raw}),
	}}, nil
}
