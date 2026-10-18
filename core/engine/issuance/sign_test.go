package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// What a gateway can do wrong, each of which the signer has to catch before a
// certificate reaches the inventory.
type gatewayMode int

const (
	signsTheRequest gatewayMode = iota
	refuses
	returnsNothing
	returnsGarbage
	returnsAPrivateKey
	usesItsOwnKey
)

type fakeGateway struct {
	providerv1.UnimplementedCertificateProviderServiceServer
	addr    string
	mode    gatewayMode
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	revoked atomic.Int32
	// refuseRevocation makes the CA decline a revocation, as opposed to the
	// call failing.
	refuseRevocation atomic.Bool
	lastReason       atomic.Int32
	lastPEM          atomic.Value // string
}

func startGateway(t *testing.T, mode gatewayMode) *fakeGateway {
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
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(der)

	gw := &fakeGateway{addr: lis.Addr().String(), mode: mode, caKey: caKey, caCert: caCert}
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

func (g *fakeGateway) RevokeCertificate(_ context.Context, req *providerv1.RevokeCertificateRequest) (*providerv1.RevokeCertificateResponse, error) {
	g.revoked.Add(1)
	g.lastReason.Store(req.Reason)
	g.lastPEM.Store(string(req.CertificatePem))
	if g.refuseRevocation.Load() {
		return &providerv1.RevokeCertificateResponse{Message: "this account may not revoke that"}, nil
	}
	return &providerv1.RevokeCertificateResponse{Success: true}, nil
}

func (g *fakeGateway) IssueCertificate(_ context.Context, req *providerv1.IssueCertificateRequest) (*providerv1.IssueCertificateResponse, error) {
	switch g.mode {
	case refuses:
		return nil, errors.New("policy at the CA says no")
	case returnsNothing:
		return &providerv1.IssueCertificateResponse{Certificate: &commonv1.CertificateInfo{}}, nil
	case returnsGarbage:
		return &providerv1.IssueCertificateResponse{Certificate: &commonv1.CertificateInfo{
			CertificatePem: []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"),
		}}, nil
	}

	block, _ := pem.Decode(req.GetCsrPem())
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	var pub any = csr.PublicKey
	var ownKey []byte
	if g.mode == usesItsOwnKey || g.mode == returnsAPrivateKey {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		pub = &k.PublicKey
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		ownKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: req.GetDomains()[0]},
		DNSNames:     req.GetDomains(),
		NotBefore:    time.Now(), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, g.caCert, pub, g.caKey)
	if err != nil {
		return nil, err
	}
	info := &commonv1.CertificateInfo{
		CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		ChainPem:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.caCert.Raw}),
	}
	if g.mode == returnsAPrivateKey {
		info.PrivateKeyPem = ownKey
	}
	return &providerv1.IssueCertificateResponse{Certificate: info}, nil
}

// signFixture is a signer wired to a gateway, a decision for an ECDSA
// certificate under an ENFORCE template, and a CSR for it.
func signFixture(t *testing.T, mode gatewayMode) (*Signer, *Decision, string, *fakeGateway) {
	t.Helper()
	gw := startGateway(t, mode)
	pm := pluginmgr.NewManager(grpckit.TLSConfig{Insecure: true})
	t.Cleanup(pm.Close)
	if _, err := pm.RegisterGateway(context.Background(), "fake", gw.addr, "selfsigned", ""); err != nil {
		t.Fatal(err)
	}
	kr, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "web.example.com"}, DNSNames: []string{"web.example.com"},
	}, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	decision := &Decision{
		Template:   &store.CertificateTemplate{Slug: "web", Conformance: store.ConformanceEnforce},
		Account:    &store.CAAccount{Name: "fake", GatewayAddr: gw.addr, ProviderType: "selfsigned"},
		CommonName: "web.example.com", Domains: []string{"web.example.com"},
		KeyType: "ECDSA", KeySize: 256,
	}
	return NewSigner(pm, kr), decision, csrPEM, gw
}

func TestASignedRequestComesBackParsedAndChecked(t *testing.T) {
	s, d, csr, _ := signFixture(t, signsTheRequest)
	got, err := s.SignCSR(context.Background(), d, csr)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got.Info.CommonName != "web.example.com" || len(got.CertificatePEM) == 0 || len(got.ChainPEM) == 0 {
		t.Errorf("incomplete result: %+v", got.Info)
	}
	if got.Gateway != "fake" {
		t.Errorf("gateway %q, want fake", got.Gateway)
	}
}

func TestSigningSaysWhyItFailed(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode gatewayMode
		want string
	}{
		{"the CA refuses", refuses, "the CA refused this request"},
		{"no certificate comes back", returnsNothing, "returned no certificate"},
		{"what comes back is not a certificate", returnsGarbage, "not a valid X.509 certificate"},
		{"the gateway made its own key", returnsAPrivateKey, "ignored the request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, d, csr, _ := signFixture(t, tc.mode)
			_, err := s.SignCSR(context.Background(), d, csr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error saying %q", err, tc.want)
			}
		})
	}
}

// A CA that signs a different key than the one requested has issued a
// certificate nobody can use and nobody authorised. Under ENFORCE it is refused,
// and the CA is asked to revoke it so it does not outlive the refusal.
func TestACertificateForTheWrongKeyIsRefusedAndRevoked(t *testing.T) {
	s, d, csr, gw := signFixture(t, usesItsOwnKey)
	_, err := s.SignCSR(context.Background(), d, csr)
	if err == nil || !strings.Contains(err.Error(), "requires ENFORCE conformance") {
		t.Fatalf("got %v, want an ENFORCE refusal", err)
	}
	if gw.revoked.Load() != 1 {
		t.Errorf("the CA was asked to revoke %d times, want 1", gw.revoked.Load())
	}
}

func TestAGatewayThatIsNotConnectedIsSaidPlainly(t *testing.T) {
	s, d, csr, _ := signFixture(t, signsTheRequest)
	d.Account = &store.CAAccount{Name: "nowhere", GatewayAddr: "127.0.0.1:1", ProviderType: "selfsigned"}
	_, err := s.SignCSR(context.Background(), d, csr)
	if err == nil || !strings.Contains(err.Error(), "is not connected") {
		t.Fatalf("got %v, want a not-connected error naming the account", err)
	}
}
