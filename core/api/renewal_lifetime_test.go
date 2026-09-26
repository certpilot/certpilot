package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// #102. A renewal never told the CA how long the certificate should last. The
// gateway applied its own default, and the check that exists to catch a CA
// issuing longer than asked was silenced by the same missing number: on the
// published quickstart a 90-day certificate renewed into a 365-day one,
// reported success, and raised no finding.

// lifetimeGateway renews for the lifetime it is asked for, the way a gateway
// built against SDK v0.4.0 does, or ignores it and uses its own 365-day
// default, the way every gateway before that did.
type lifetimeGateway struct {
	providerv1.UnimplementedCertificateProviderServiceServer

	addr    string
	ignores bool
	asked   atomic.Int32
}

func startLifetimeGateway(t *testing.T, ignores bool) *lifetimeGateway {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	srv, err := grpckit.NewServer(grpckit.ServerOptions{MaxRecvMsgSize: 10 << 20, TLS: grpckit.TLSConfig{Insecure: true}})
	if err != nil {
		t.Fatalf("could not build a gRPC server: %v", err)
	}
	gw := &lifetimeGateway{addr: lis.Addr().String(), ignores: ignores}
	gw.asked.Store(-1)
	providerv1.RegisterCertificateProviderServiceServer(srv, gw)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return gw
}

func (g *lifetimeGateway) GetCapabilities(context.Context, *providerv1.GetCapabilitiesRequest) (*providerv1.GetCapabilitiesResponse, error) {
	return &providerv1.GetCapabilitiesResponse{Capabilities: &commonv1.ProviderCapabilities{
		ProviderName: "lifetime-test", ProviderType: "selfsigned", SupportedKeyTypes: []string{"ECDSA"},
	}}, nil
}

func (g *lifetimeGateway) HealthCheck(context.Context, *providerv1.HealthCheckRequest) (*providerv1.HealthCheckResponse, error) {
	return &providerv1.HealthCheckResponse{Status: commonv1.HealthStatus_HEALTH_STATUS_HEALTHY}, nil
}

func (g *lifetimeGateway) RenewCertificate(_ context.Context, req *providerv1.RenewCertificateRequest) (*providerv1.RenewCertificateResponse, error) {
	g.asked.Store(req.GetValidityDays())
	days := int32(365)
	if !g.ignores && req.GetValidityDays() > 0 {
		days = req.GetValidityDays()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: req.GetDomains()[0]},
		DNSNames:     req.GetDomains(),
		NotBefore:    now,
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &providerv1.RenewCertificateResponse{Certificate: &commonv1.CertificateInfo{
		CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPem:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}}, nil
}

// renewNinetyDayCertificate seeds a 90-day certificate CertPilot holds the key
// for, optionally under a template, and renews it through gw.
func renewNinetyDayCertificate(t *testing.T, gw *lifetimeGateway, tpl *store.CertificateTemplate) (*store.Certificate, error) {
	t.Helper()
	_, st, pm := realRouterWithPlugins(t)
	if _, err := pm.RegisterGateway(context.Background(), "lifetime-test", gw.addr, "selfsigned", ""); err != nil {
		t.Fatalf("registering the gateway: %v", err)
	}
	notBefore := time.Now().Add(-80 * 24 * time.Hour)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	cert := seedCertificate(t, st, func(c *store.Certificate, acc *store.CAAccount) {
		acc.Name = "lifetime-test"
		c.CommonName = "lifetime.example.com"
		c.SANs = []string{"lifetime.example.com"}
		c.SerialNumber = "0b0c0d"
		c.KeyType, c.KeySize = "ECDSA", 256
		c.KeyCustody = store.KeyCustodyCertPilot
		c.NotBefore, c.NotAfter = &notBefore, &notAfter
	})
	if tpl != nil {
		tpl.CAAccountID = *cert.CAAccountID
		if err := st.CreateCertificateTemplate(context.Background(), tpl); err != nil {
			t.Fatalf("seeding the template: %v", err)
		}
		cert.TemplateID = &tpl.ID
		if err := st.UpdateCertificate(context.Background(), cert); err != nil {
			t.Fatalf("assigning the template: %v", err)
		}
	}
	keyring, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	exec := renewal.NewExecutor(st, pm, keyring, events.NewBroker(), policy.NewEngine(st))
	return exec.RenewCertificate(context.Background(), cert.ID)
}

func lifetimeOf(t *testing.T, c *store.Certificate) time.Duration {
	t.Helper()
	if c == nil || c.NotBefore == nil || c.NotAfter == nil {
		t.Fatal("the renewed certificate has no validity dates")
	}
	return c.NotAfter.Sub(*c.NotBefore)
}

// With no template naming a lifetime, a renewal asks for the one the
// certificate already has. That is the whole of the quickstart case.
func TestARenewalAsksForTheLifetimeTheCertificateHad(t *testing.T) {
	gw := startLifetimeGateway(t, false)
	renewed, err := renewNinetyDayCertificate(t, gw, nil)
	if err != nil {
		t.Fatalf("renewing: %v", err)
	}
	if got := gw.asked.Load(); got != 90 {
		t.Errorf("the gateway was asked for %d days; the certificate being renewed lasts 90", got)
	}
	if got := lifetimeOf(t, renewed); got < 89*24*time.Hour || got > 91*24*time.Hour {
		t.Errorf("the renewal lasts %v, want 90 days", got.Round(time.Hour))
	}
	for _, f := range renewed.ConformanceFindings {
		if f.Field == "validity" {
			t.Errorf("a renewal for exactly what was asked raised a validity finding: %s", f.Message)
		}
	}
}

// A gateway that ignores the lifetime — every one released before the contract
// carried it — is now caught: the lengthening is on the record. Reported, not
// refused, even under ENFORCE, because the 90 was inferred from the certificate
// rather than declared by anybody; refusing would turn a core upgrade ahead of
// its gateways into a failed, revoked renewal for every certificate.
func TestALongerRenewalIsReportedWhenTheLifetimeWasOnlyInferred(t *testing.T) {
	gw := startLifetimeGateway(t, true)
	renewed, err := renewNinetyDayCertificate(t, gw, &store.CertificateTemplate{
		Slug: "no-lifetime", Name: "No lifetime", Conformance: store.ConformanceEnforce,
	})
	if err != nil {
		t.Fatalf("a renewal whose lifetime was only inferred was refused: %v", err)
	}
	var finding *store.ConformanceFinding
	for i := range renewed.ConformanceFindings {
		if renewed.ConformanceFindings[i].Field == "validity" {
			finding = &renewed.ConformanceFindings[i]
		}
	}
	if finding == nil {
		t.Fatalf("a 90-day certificate renewed into %v and nothing was recorded: %+v",
			lifetimeOf(t, renewed).Round(time.Hour), renewed.ConformanceFindings)
	}
	if finding.Severity != store.FindingReport {
		t.Errorf("severity = %s, want REPORT for a lifetime nobody declared", finding.Severity)
	}
	if !strings.Contains(finding.Message, "365") {
		t.Errorf("the finding should say what the CA issued: %s", finding.Message)
	}
}

// A lifetime a template declares keeps the refusal it has always had. This is
// what the downgrade above must not reach.
func TestALongerRenewalIsStillRefusedWhenATemplateDeclaresTheLifetime(t *testing.T) {
	gw := startLifetimeGateway(t, true)
	_, err := renewNinetyDayCertificate(t, gw, &store.CertificateTemplate{
		Slug: "ninety-days", Name: "Ninety days", Conformance: store.ConformanceEnforce, ValidityDays: 90,
	})
	if err == nil {
		t.Fatal("a renewal longer than the template's declared lifetime was accepted under ENFORCE")
	}
	if got := gw.asked.Load(); got != 90 {
		t.Errorf("the gateway was asked for %d days; the template declares 90", got)
	}
}
