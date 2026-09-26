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
	"net/http"
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

// #107. A certificate whose key was generated on a host, or supplied as a
// signing request from anywhere else, cannot be renewed by CertPilot:
// RenewCertificateRequest carries no CSR, so the gateway makes a fresh keypair
// and the core seals it. CertPilot then holds a key it promised never to hold,
// for a record that goes on saying the key is on the host, and the host keeps
// serving the certificate the record no longer describes.
//
// The gateway below does renew, and returns a key with the certificate the way
// every gateway does when it generated the key itself. A test against a gateway
// that could not renew would pass whether or not anything refused.

// renewingGateway is a CA that renews whatever it is asked to, with a key of
// its own making.
type renewingGateway struct {
	providerv1.UnimplementedCertificateProviderServiceServer

	addr       string
	renewCalls atomic.Int32
}

func startRenewingGateway(t *testing.T) *renewingGateway {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	srv, err := grpckit.NewServer(grpckit.ServerOptions{
		MaxRecvMsgSize: 10 << 20,
		TLS:            grpckit.TLSConfig{Insecure: true},
	})
	if err != nil {
		t.Fatalf("could not build a gRPC server: %v", err)
	}

	gw := &renewingGateway{addr: lis.Addr().String()}
	providerv1.RegisterCertificateProviderServiceServer(srv, gw)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return gw
}

func (g *renewingGateway) GetCapabilities(context.Context, *providerv1.GetCapabilitiesRequest) (*providerv1.GetCapabilitiesResponse, error) {
	return &providerv1.GetCapabilitiesResponse{
		Capabilities: &commonv1.ProviderCapabilities{
			ProviderName:      "custody-test",
			ProviderType:      "selfsigned",
			SupportedKeyTypes: []string{"ECDSA"},
		},
	}, nil
}

func (g *renewingGateway) HealthCheck(context.Context, *providerv1.HealthCheckRequest) (*providerv1.HealthCheckResponse, error) {
	return &providerv1.HealthCheckResponse{Status: commonv1.HealthStatus_HEALTH_STATUS_HEALTHY}, nil
}

func (g *renewingGateway) RenewCertificate(_ context.Context, req *providerv1.RenewCertificateRequest) (*providerv1.RenewCertificateResponse, error) {
	g.renewCalls.Add(1)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	names := req.GetDomains()
	if len(names) == 0 {
		names = []string{"www.example.com"}
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(30 * 24 * time.Hour),
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
	return &providerv1.RenewCertificateResponse{
		Certificate: &commonv1.CertificateInfo{
			CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			PrivateKeyPem:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		},
	}, nil
}

// seedHeldCertificate is an issued certificate whose key CertPilot does not
// hold: on an enrolled host when custody is AGENT, wherever the signing
// request came from when it is EXTERNAL.
func seedHeldCertificate(t *testing.T, st store.Store, custody string) (*store.Certificate, *store.Agent) {
	t.Helper()

	var agent *store.Agent
	if custody == store.KeyCustodyAgent {
		agent = &store.Agent{Name: "web-01", Hostname: "web-01.example.com", Status: "ACTIVE"}
		if err := st.CreateAgent(context.Background(), agent); err != nil {
			t.Fatalf("seeding the agent: %v", err)
		}
	}
	cert := seedCertificate(t, st, func(c *store.Certificate, acc *store.CAAccount) {
		acc.Name = "custody-test"
		c.CommonName = "www.example.com"
		c.SANs = []string{"www.example.com"}
		c.SerialNumber = "0a0b0c"
		c.KeyCustody = custody
		if agent != nil {
			c.KeyHolderAgentID = &agent.ID
		}
	})
	return cert, agent
}

func assertStillHeldElsewhere(t *testing.T, st store.Store, before *store.Certificate) {
	t.Helper()
	ctx := context.Background()

	if key, err := st.GetCertificatePrivateKey(ctx, before.ID); err == nil && key != "" {
		t.Error("CertPilot now holds a private key for a certificate whose key is held elsewhere")
	}
	after, err := st.GetCertificate(ctx, before.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if after.KeyCustody != before.KeyCustody {
		t.Errorf("key_custody = %q, want it left at %q", after.KeyCustody, before.KeyCustody)
	}
	if after.FingerprintSHA256 != before.FingerprintSHA256 {
		t.Error("the record now describes a different certificate from the one the key holder is serving")
	}
}

func TestRenewingAnAgentHeldCertificateIsRefusedAndSaysWhatToDoInstead(t *testing.T) {
	r, st, pm := realRouterWithPlugins(t)
	gw := startRenewingGateway(t)
	if _, err := pm.RegisterGateway(context.Background(), "custody-test", gw.addr, "selfsigned", ""); err != nil {
		t.Fatalf("registering the gateway: %v", err)
	}
	cert, agent := seedHeldCertificate(t, st, store.KeyCustodyAgent)

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/renew", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// Naming the host is the useful part: it is where the operator has to go.
	if !strings.Contains(body, agent.Name) {
		t.Errorf("the refusal should name the agent holding the key, %q: %s", agent.Name, body)
	}
	if !strings.Contains(body, "certpilot-agent request") {
		t.Errorf("the refusal should say how to renew it from the host: %s", body)
	}

	jobs, _, err := st.ListRenewalJobs(context.Background(), store.RenewalJobFilter{CertificateID: cert.ID})
	if err != nil {
		t.Fatalf("ListRenewalJobs: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("a refused renewal still queued %d job(s)", len(jobs))
	}
	assertStillHeldElsewhere(t, st, cert)
}

// The same refusal for a key that came in as a signing request. The executor
// already refused these, but only in a worker, after the caller had been told
// the renewal was queued.
func TestRenewingAnExternallyHeldCertificateIsRefusedAtTheAPI(t *testing.T) {
	r, st, _ := realRouterWithPlugins(t)
	cert, _ := seedHeldCertificate(t, st, store.KeyCustodyExternal)

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/renew", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "signing request") {
		t.Errorf("the refusal should say a new signing request is how this is renewed: %s", w.Body.String())
	}
	jobs, _, _ := st.ListRenewalJobs(context.Background(), store.RenewalJobFilter{CertificateID: cert.ID})
	if len(jobs) != 0 {
		t.Errorf("a refused renewal still queued %d job(s)", len(jobs))
	}
}

// The executor is the last line. A job that reaches it by any other path — one
// queued before this fix, or by code written after it — must not commit the
// key either, and must not so much as ask the CA.
func TestTheExecutorWillNotRenewAnAgentHeldCertificate(t *testing.T) {
	_, st, pm := realRouterWithPlugins(t)
	gw := startRenewingGateway(t)
	if _, err := pm.RegisterGateway(context.Background(), "custody-test", gw.addr, "selfsigned", ""); err != nil {
		t.Fatalf("registering the gateway: %v", err)
	}
	keyring, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	cert, agent := seedHeldCertificate(t, st, store.KeyCustodyAgent)

	exec := renewal.NewExecutor(st, pm, keyring, events.NewBroker(), policy.NewEngine(st))
	_, err = exec.RenewCertificate(context.Background(), cert.ID)
	if err == nil {
		t.Fatal("the executor renewed a certificate whose key is on a host")
	}
	if !strings.Contains(err.Error(), agent.Name) {
		t.Errorf("the error should name the agent holding the key: %v", err)
	}
	if got := gw.renewCalls.Load(); got != 0 {
		t.Errorf("the CA was asked to renew %d time(s); it should not have been asked at all", got)
	}
	assertStillHeldElsewhere(t, st, cert)
}
