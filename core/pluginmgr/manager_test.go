package pluginmgr

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// fakeGateway is a minimal in-process provider.v1 server. It exists only to
// give RegisterGateway something real to dial and a health service to answer
// — grpckit.Dial forces the handshake, so a real listener is unavoidable.
type fakeGateway struct {
	providerv1.UnimplementedCertificateProviderServiceServer

	server *grpc.Server
	addr   string

	// failCapabilities makes GetCapabilities fail until told to stop, so a
	// test can reproduce "connected, but capabilities never landed" and then
	// prove the sweep recovers from it.
	failCapabilities atomic.Bool
	capCalls         atomic.Int32
	healthCalls      atomic.Int32
}

func startFakeGateway(t *testing.T) *fakeGateway {
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

	fg := &fakeGateway{server: srv, addr: lis.Addr().String()}
	providerv1.RegisterCertificateProviderServiceServer(srv, fg)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return fg
}

func (f *fakeGateway) GetCapabilities(context.Context, *providerv1.GetCapabilitiesRequest) (*providerv1.GetCapabilitiesResponse, error) {
	f.capCalls.Add(1)
	if f.failCapabilities.Load() {
		return nil, context.DeadlineExceeded
	}
	return &providerv1.GetCapabilitiesResponse{
		Capabilities: &commonv1.ProviderCapabilities{
			ProviderName: "fake",
			ProviderType: "fake",
		},
	}, nil
}

func (f *fakeGateway) HealthCheck(context.Context, *providerv1.HealthCheckRequest) (*providerv1.HealthCheckResponse, error) {
	f.healthCalls.Add(1)
	return &providerv1.HealthCheckResponse{Status: commonv1.HealthStatus_HEALTH_STATUS_HEALTHY}, nil
}

func testManager() *Manager {
	return NewManager(grpckit.TLSConfig{Insecure: true})
}

// TestRegisterGatewayClosesThePreviousConnection.
//
// A reconnect under the same name used to leave the old *grpc.ClientConn
// open forever — nothing closed it, and nothing else could reach it to. One
// file descriptor and one keepalive goroutine pair leaked per reconnect, on a
// connection no code held a reference to any more.
func TestRegisterGatewayClosesThePreviousConnection(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	ctx := context.Background()

	first, err := m.RegisterGateway(ctx, "acme", fg.addr, "acme", "")
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	firstConn := first.Conn

	// Force a reconnect under the same name: RegisterGateway short-circuits
	// when the existing entry is already connected, so mark it disconnected
	// first, the way a failed health check would.
	m.mu.Lock()
	m.gateways["acme"].IsConnected = false
	m.mu.Unlock()

	if _, err := m.RegisterGateway(ctx, "acme", fg.addr, "acme", ""); err != nil {
		t.Fatalf("second registration failed: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for firstConn.GetState() != connectivity.Shutdown && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := firstConn.GetState(); got != connectivity.Shutdown {
		t.Fatalf("the previous connection is %s, want Shutdown: RegisterGateway did not close it on reconnect", got)
	}
}

// TestHealthCheckAllRecoversMissingCapabilities.
//
// Capabilities are fetched once, at registration, and were never refreshed.
// A gateway whose GetCapabilities was merely slow — or failing — at startup
// answered correctly forever after and this process never asked again,
// leaving supports_ca_info permanently false and CA import permanently
// silent for a gateway that only needed a few more seconds.
func TestHealthCheckAllRecoversMissingCapabilities(t *testing.T) {
	fg := startFakeGateway(t)
	fg.failCapabilities.Store(true)

	m := testManager()
	ctx := context.Background()

	gw, err := m.RegisterGateway(ctx, "acme", fg.addr, "acme", "")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	if gw.Capabilities != nil {
		t.Fatal("capabilities are present despite the fake being told to fail them")
	}
	if calls := fg.capCalls.Load(); calls != 1 {
		t.Fatalf("GetCapabilities was called %d times at registration, want 1", calls)
	}

	// The gateway recovers, the way one that was merely slow to come up
	// would.
	fg.failCapabilities.Store(false)

	m.HealthCheckAll(ctx)

	m.mu.RLock()
	caps := m.gateways["acme"].Capabilities
	m.mu.RUnlock()

	if caps == nil {
		t.Fatal("HealthCheckAll did not recover capabilities from a gateway that is now healthy and answering")
	}
	if caps.ProviderName != "fake" {
		t.Errorf("recovered capabilities have provider_name %q, want %q", caps.ProviderName, "fake")
	}
	if calls := fg.capCalls.Load(); calls != 2 {
		t.Errorf("GetCapabilities was called %d times total, want exactly 2 (registration + one recovery attempt)", calls)
	}
}

// TestHealthCheckAllLeavesPresentCapabilitiesAlone. A gateway that already
// answered GetCapabilities should not be asked again on every sweep — the
// refresh exists for the gap between registration and the first successful
// answer, not as a standing poll.
func TestHealthCheckAllLeavesPresentCapabilitiesAlone(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	ctx := context.Background()

	if _, err := m.RegisterGateway(ctx, "acme", fg.addr, "acme", ""); err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	if calls := fg.capCalls.Load(); calls != 1 {
		t.Fatalf("GetCapabilities called %d times at registration, want 1", calls)
	}

	m.HealthCheckAll(ctx)
	m.HealthCheckAll(ctx)

	if calls := fg.capCalls.Load(); calls != 1 {
		t.Errorf("GetCapabilities called %d times after two healthy sweeps, want still 1: a gateway with capabilities already present should not be re-asked", calls)
	}
	if calls := fg.healthCalls.Load(); calls != 2 {
		t.Errorf("HealthCheck called %d times, want 2", calls)
	}
}

// TestHealthCheckAllMarksAFailedGatewayDisconnected preserves the existing
// behaviour the sweep is built on: a gateway that stops answering is marked
// disconnected rather than left looking healthy between requests.
func TestHealthCheckAllMarksAFailedGatewayDisconnected(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	ctx := context.Background()

	if _, err := m.RegisterGateway(ctx, "acme", fg.addr, "acme", ""); err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	// Stop answering, the way a wedged or restarting gateway does.
	fg.server.Stop()

	m.HealthCheckAll(ctx)

	m.mu.RLock()
	connected := m.gateways["acme"].IsConnected
	m.mu.RUnlock()

	if connected {
		t.Fatal("a gateway that stopped answering HealthCheck is still marked connected")
	}
}

// TestStopBeforeStartDoesNotPanicOrBlock. Nothing in this codebase calls Stop
// before Start in a real shutdown sequence — Shutdown only runs after Start —
// but a caller managing the lifecycle by hand should not be able to wedge or
// crash the process by getting the order wrong.
//
// This manager is not reused afterward. stopCh is closed by sync.Once and
// never recreated, matching pki.Importer's Start/Stop idiom elsewhere in this
// codebase — so on this specific manager, Stop before Start also means every
// later Start's sweep goroutine sees an already-closed channel and exits
// before its first tick. That is the documented shape of the idiom being
// followed here, not a defect in it: Stop is a shutdown signal a Manager
// receives once, not a pause a caller can resume from.
func TestStopBeforeStartDoesNotPanicOrBlock(t *testing.T) {
	m := testManager()
	m.Stop()
	m.Stop() // idempotent
}

// TestStartRunsTheHealthSweepOnItsTimer.
func TestStartRunsTheHealthSweepOnItsTimer(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()

	if _, err := m.RegisterGateway(context.Background(), "acme", fg.addr, "acme", ""); err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	m.Start(20 * time.Millisecond)
	t.Cleanup(m.Stop)

	deadline := time.Now().Add(2 * time.Second)
	for fg.healthCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fg.healthCalls.Load() == 0 {
		t.Fatal("Start did not run the health sweep on its timer")
	}

	// Stop must be idempotent, including after a real Start.
	m.Stop()
	m.Stop()
}
