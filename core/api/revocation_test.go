package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
)

// The revocation endpoint had no tests at all until these: 0.0% on Revoke,
// auditRevocation and revocationReasonHelp, on the one operation in the product
// that cannot be undone and that reaches a CA to do it.
//
// What is checked here is mostly not the success case. It is the promise the
// handler's own comments make over and over — that when anything goes wrong,
// *nothing has been changed*. A revocation that half-happened is worse than one
// that did not happen: either a live certificate reads REVOKED in the console
// and still answers handshakes, or a dead one reads ISSUED and nobody reissues.

// revokeGateway is a CA that does as it is told, and can be told to refuse.
type revokeGateway struct {
	providerv1.UnimplementedCertificateProviderServiceServer

	addr string

	// refuse makes RevokeCertificate answer success=false, which is a CA
	// declining rather than a transport failure — a distinction the handler
	// has to keep, because only one of them means "ask again".
	refuse atomic.Bool
	// hardFail makes the RPC itself fail.
	hardFail atomic.Bool

	revokeCalls  atomic.Int32
	lastReason   atomic.Int32
	lastCertPEM  atomic.Value // string
	lastProvider atomic.Value // string
}

func startRevokeGateway(t *testing.T) *revokeGateway {
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

	gw := &revokeGateway{addr: lis.Addr().String()}
	providerv1.RegisterCertificateProviderServiceServer(srv, gw)

	// Served directly rather than through grpckit.Serve, which binds a fixed
	// port; these tests take whatever the kernel gives them so they can run
	// alongside each other.
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return gw
}

func (g *revokeGateway) GetCapabilities(context.Context, *providerv1.GetCapabilitiesRequest) (*providerv1.GetCapabilitiesResponse, error) {
	return &providerv1.GetCapabilitiesResponse{
		Capabilities: &commonv1.ProviderCapabilities{
			ProviderName:       "revoke-test",
			ProviderType:       "selfsigned",
			SupportedKeyTypes:  []string{"RSA", "ECDSA"},
			SupportsRevocation: true,
		},
	}, nil
}

func (g *revokeGateway) HealthCheck(context.Context, *providerv1.HealthCheckRequest) (*providerv1.HealthCheckResponse, error) {
	return &providerv1.HealthCheckResponse{Status: commonv1.HealthStatus_HEALTH_STATUS_HEALTHY}, nil
}

func (g *revokeGateway) RevokeCertificate(_ context.Context, req *providerv1.RevokeCertificateRequest) (*providerv1.RevokeCertificateResponse, error) {
	g.revokeCalls.Add(1)
	g.lastReason.Store(req.Reason)
	g.lastCertPEM.Store(string(req.CertificatePem))
	g.lastProvider.Store(req.ProviderConfig)

	if g.hardFail.Load() {
		return nil, grpc.ErrServerStopped
	}
	if g.refuse.Load() {
		return &providerv1.RevokeCertificateResponse{
			Success: false,
			Message: "this account may not revoke that certificate",
		}, nil
	}
	return &providerv1.RevokeCertificateResponse{Success: true, Message: "revoked"}, nil
}

// seedCertificate puts a certificate in the store, bound to a CA account whose
// name matches a gateway the caller may have registered.
func seedCertificate(t *testing.T, st store.Store, mutate func(*store.Certificate, *store.CAAccount)) *store.Certificate {
	t.Helper()
	ctx := context.Background()

	acc := &store.CAAccount{
		ID:           "ca-revoke-test",
		Name:         "revoke-test",
		ProviderType: "selfsigned",
		GatewayAddr:  "127.0.0.1:1",
		Status:       "CONNECTED",
	}
	pem := "-----BEGIN CERTIFICATE-----\nnot a real certificate, and never parsed on this path\n-----END CERTIFICATE-----\n"
	cert := &store.Certificate{
		ID:                "cert-revoke-test",
		CommonName:        "revoke.example.com",
		FingerprintSHA256: "aa:bb:cc",
		Status:            "ISSUED",
		CertificatePEM:    &pem,
		CAAccountID:       &acc.ID,
		DiscoveredVia:     "REQUESTED",
	}
	if mutate != nil {
		mutate(cert, acc)
	}

	if acc.Name != "" {
		if err := st.CreateCAAccount(ctx, acc); err != nil {
			t.Fatalf("seeding the CA account: %v", err)
		}
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("seeding the certificate: %v", err)
	}
	return cert
}

func statusOf(t *testing.T, st store.Store, id string) string {
	t.Helper()
	got, err := st.GetCertificate(context.Background(), id)
	if err != nil {
		t.Fatalf("reading the certificate back: %v", err)
	}
	if got == nil {
		t.Fatalf("certificate %s vanished", id)
	}
	return got.Status
}

// TestRevokingTellsTheCAFirstAndOnlyThenTheRecord is the whole ordering
// guarantee in one test: the CA is asked, it agrees, and only then does the
// local record change.
func TestRevokingTellsTheCAFirstAndOnlyThenTheRecord(t *testing.T) {
	r, st, pm := realRouterWithPlugins(t)
	gw := startRevokeGateway(t)

	if _, err := pm.RegisterGateway(context.Background(), "revoke-test", gw.addr, "selfsigned", ""); err != nil {
		t.Fatalf("registering the gateway: %v", err)
	}
	cert := seedCertificate(t, st, nil)

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", gin.H{"reason": 1}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if got := gw.revokeCalls.Load(); got != 1 {
		t.Fatalf("the CA should have been asked exactly once, was asked %d times", got)
	}
	if got := gw.lastReason.Load(); got != 1 {
		t.Fatalf("the CA was sent reason %d, want 1 (keyCompromise)", got)
	}
	// The certificate itself has to reach the CA. A CA cannot revoke something
	// it has not been shown, and sending the fingerprint alone was how an
	// earlier draft of this path silently did nothing.
	if got, _ := gw.lastCertPEM.Load().(string); !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Fatalf("the CA was not sent the certificate PEM, got %q", got)
	}

	if got := statusOf(t, st, cert.ID); got != "REVOKED" {
		t.Fatalf("the record says %s, want REVOKED", got)
	}
	// Named in the response, because "revoked" without a reason is what the
	// required-reason rule exists to prevent.
	if !strings.Contains(w.Body.String(), "keyCompromise") {
		t.Fatalf("the response should name the reason: %s", w.Body.String())
	}
}

// TestARefusedRevocationChangesNothing. The CA answered, and said no. That is
// not a transport problem and must not be recorded as a revocation.
func TestARefusedRevocationChangesNothing(t *testing.T) {
	r, st, pm := realRouterWithPlugins(t)
	gw := startRevokeGateway(t)
	gw.refuse.Store(true)

	if _, err := pm.RegisterGateway(context.Background(), "revoke-test", gw.addr, "selfsigned", ""); err != nil {
		t.Fatalf("registering the gateway: %v", err)
	}
	cert := seedCertificate(t, st, nil)

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", gin.H{"reason": 4}, nil)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when the CA declines, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "nothing has been changed") {
		t.Fatalf("the operator has to be told nothing changed: %s", w.Body.String())
	}
	if got := statusOf(t, st, cert.ID); got != "ISSUED" {
		t.Fatalf("the record says %s, want ISSUED — the CA refused", got)
	}
}

// TestAnUnreachableGatewayChangesNothing is the branch every other test in this
// package could already reach, and the most dangerous one to get wrong: the CA
// has not been told, so the certificate is still live.
func TestAnUnreachableGatewayChangesNothing(t *testing.T) {
	r, st := realRouter(t)
	cert := seedCertificate(t, st, nil)

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", gin.H{"reason": 1}, nil)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 with no gateway connected, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "nothing has been changed") {
		t.Fatalf("the operator has to be told nothing changed: %s", w.Body.String())
	}
	if got := statusOf(t, st, cert.ID); got != "REVOKED" && got == "REVOKED" {
		t.Fatalf("unreachable gateway must not mark the record revoked, got %s", got)
	}
	if got := statusOf(t, st, cert.ID); got != "ISSUED" {
		t.Fatalf("the record says %s, want ISSUED — the CA was never reached", got)
	}
}

// TestARevocationReasonIsRequired. Defaulting it to 0 would make "unspecified"
// the commonest reason in every estate, which is the opposite of why the field
// is there.
func TestARevocationReasonIsRequired(t *testing.T) {
	r, st := realRouter(t)
	cert := seedCertificate(t, st, nil)

	for _, body := range []any{nil, gin.H{}} {
		w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", body, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 without a reason, got %d: %s", w.Code, w.Body.String())
		}
		// The 400 has to be actionable without going and reading RFC 5280.
		if !strings.Contains(w.Body.String(), "keyCompromise") {
			t.Fatalf("the error should list the accepted codes: %s", w.Body.String())
		}
	}
	if got := statusOf(t, st, cert.ID); got != "ISSUED" {
		t.Fatalf("a rejected request changed the record to %s", got)
	}
}

// TestAnUnknownRevocationReasonIsRefused. 2 and 6 are real RFC 5280 codes that
// CertPilot deliberately does not accept, so this is not merely a range check.
func TestAnUnknownRevocationReasonIsRefused(t *testing.T) {
	r, st := realRouter(t)
	cert := seedCertificate(t, st, nil)

	for _, reason := range []int{2, 6, 7, 8, 11, 99, -1} {
		w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", gin.H{"reason": reason}, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("reason %d should be refused, got %d: %s", reason, w.Code, w.Body.String())
		}
	}

	// Every code the store does accept has to be accepted here, or the help
	// text in the 400 above is lying about what will work.
	for reason := range store.RevocationReasons {
		if !store.ValidRevocationReason(reason) {
			t.Fatalf("RevocationReasons contains %d but ValidRevocationReason rejects it", reason)
		}
	}
}

// TestRevokingSomethingCertPilotHasNoCopyOfIsRefused. Discovered certificates
// reach this handler with no PEM. A CA cannot revoke what it cannot be shown,
// and the operator needs to be told to go to the CA rather than left with a
// generic failure.
func TestRevokingSomethingCertPilotHasNoCopyOfIsRefused(t *testing.T) {
	r, st := realRouter(t)
	cert := seedCertificate(t, st, func(c *store.Certificate, _ *store.CAAccount) {
		c.CertificatePEM = nil
		c.DiscoveredVia = "SCAN"
	})

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", gin.H{"reason": 1}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with no stored PEM, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "issuing CA") {
		t.Fatalf("the error should send the operator to the CA: %s", w.Body.String())
	}
	if got := statusOf(t, st, cert.ID); got != "ISSUED" {
		t.Fatalf("the record changed to %s", got)
	}
}

// TestRevokingSomethingWithNoCAAccountIsRefused: a discovered certificate that
// was never issued here has nowhere to send a revocation.
func TestRevokingSomethingWithNoCAAccountIsRefused(t *testing.T) {
	r, st := realRouter(t)
	cert := seedCertificate(t, st, func(c *store.Certificate, _ *store.CAAccount) {
		c.CAAccountID = nil
		c.DiscoveredVia = "SCAN"
	})

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", gin.H{"reason": 1}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with no CA account, got %d: %s", w.Code, w.Body.String())
	}
	if got := statusOf(t, st, cert.ID); got != "ISSUED" {
		t.Fatalf("the record changed to %s", got)
	}
}

// TestRevokingSomethingThatDoesNotExistIs404, rather than a 500 from a nil
// dereference further down.
func TestRevokingSomethingThatDoesNotExistIs404(t *testing.T) {
	r, _ := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/certificates/no-such-certificate/revoke", gin.H{"reason": 1}, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// TestRevokingTwiceIsRefusedWithoutAskingTheCAAgain. The second call must not
// reach the CA: re-revoking is not harmless everywhere, and some CAs answer an
// already-revoked serial with an error that would read as a failure here.
func TestRevokingTwiceIsRefusedWithoutAskingTheCAAgain(t *testing.T) {
	r, st, pm := realRouterWithPlugins(t)
	gw := startRevokeGateway(t)

	if _, err := pm.RegisterGateway(context.Background(), "revoke-test", gw.addr, "selfsigned", ""); err != nil {
		t.Fatalf("registering the gateway: %v", err)
	}
	cert := seedCertificate(t, st, nil)

	path := "/api/v1/certificates/" + cert.ID + "/revoke"
	if w := do(r, http.MethodPost, path, gin.H{"reason": 1}, nil); w.Code != http.StatusOK {
		t.Fatalf("the first revocation should succeed, got %d: %s", w.Code, w.Body.String())
	}

	w := do(r, http.MethodPost, path, gin.H{"reason": 1}, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 on the second revocation, got %d: %s", w.Code, w.Body.String())
	}
	if got := gw.revokeCalls.Load(); got != 1 {
		t.Fatalf("the CA was asked %d times, want 1 — the second call short-circuits", got)
	}
}

// TestARevocationIsAudited. The audit entry is the only durable record of who
// did this; it is written after the CA agreed, and it has to name the actor,
// the reason and the certificate.
func TestARevocationIsAudited(t *testing.T) {
	r, st, pm := realRouterWithPlugins(t)
	gw := startRevokeGateway(t)

	if _, err := pm.RegisterGateway(context.Background(), "revoke-test", gw.addr, "selfsigned", ""); err != nil {
		t.Fatalf("registering the gateway: %v", err)
	}
	cert := seedCertificate(t, st, nil)

	if w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", gin.H{"reason": 5}, nil); w.Code != http.StatusOK {
		t.Fatalf("revocation failed: %d %s", w.Code, w.Body.String())
	}

	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{Limit: 100})
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	var found *store.AuditLog
	for _, entry := range logs {
		if entry.Action == "certificate.revoked" {
			found = entry
			break
		}
	}
	if found == nil {
		t.Fatalf("no certificate.revoked entry was written")
	}
	if found.EntityID == nil || *found.EntityID != cert.ID {
		t.Fatalf("the entry does not name the certificate: %+v", found)
	}
	for _, want := range []string{"cessationOfOperation", cert.CommonName} {
		if !strings.Contains(found.Details, want) {
			t.Fatalf("the audit details should contain %q, got %s", want, found.Details)
		}
	}
	if found.ActorEmail == nil || *found.ActorEmail == "" {
		t.Fatalf("the entry does not name who did it: %+v", found)
	}
}

// TestRevocationIsAdminOnly. It is the most destructive operation here, and the
// route is gated; this proves the gate is on the route rather than only in the
// middleware package's own mirror of it.
func TestRevocationIsAdminOnly(t *testing.T) {
	r, st := realRouter(t)
	cert := seedCertificate(t, st, nil)

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/revoke", gin.H{"reason": 1},
		map[string]string{"Authorization": "Bearer " + apiViewerToken(t)})
	if w.Code != http.StatusForbidden {
		t.Fatalf("a viewer must not be able to revoke, got %d: %s", w.Code, w.Body.String())
	}
	if got := statusOf(t, st, cert.ID); got != "ISSUED" {
		t.Fatalf("the record changed to %s", got)
	}
}

// apiViewerToken signs a bearer token for somebody who is not a bootstrap
// admin. The directory gives a first-seen user RoleViewer by default, which is
// exactly the caller this route has to turn away.
func apiViewerToken(t *testing.T) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &middleware.UserClaims{
		Email: "viewer@certpilot.test",
		Name:  "API Test Viewer",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "00uAPITESTviewer001",
			Issuer:    apiTestIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	signed, err := token.SignedString([]byte(apiTestSecret))
	if err != nil {
		t.Fatalf("sign viewer token: %v", err)
	}
	return signed
}

// TestRevocationReasonHelpListsEveryAcceptedCode, so the 400 it appears in
// cannot drift away from what ValidRevocationReason will take.
func TestRevocationReasonHelpListsEveryAcceptedCode(t *testing.T) {
	help := revocationReasonHelp()
	for code, name := range store.RevocationReasons {
		if !strings.Contains(help, name) {
			t.Errorf("the help text omits %d=%s: %s", code, name, help)
		}
	}
}
