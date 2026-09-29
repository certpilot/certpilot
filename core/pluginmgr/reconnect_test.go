package pluginmgr

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
)

// deadAddr is an address nothing listens on: a port that was bound, then
// released, so a dial to it is refused for as long as the test runs.
func deadAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()
	return addr
}

// silentAddr accepts TCP connections and never says a word, so a gRPC dial to
// it hangs in the handshake until its deadline, which is what a wedged gateway
// behind a load balancer looks like.
func silentAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	return lis.Addr().String()
}

// TestGatewayForConnectsAnAccountsGatewayOnFirstUse.
//
// After a core restart the manager starts empty and only the gateways in the
// config file are dialled again. A CA account created through the API names
// its own gateway address, and nothing reconnected it, so every issuance,
// renewal and revocation through it failed with "gateway for CA … is not
// connected" until somebody pressed Check now. That is the quickstart's own
// selfsigned-eval account, and it broke renewal for anyone who restarted.
func TestGatewayForConnectsAnAccountsGatewayOnFirstUse(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	t.Cleanup(m.Close)

	gw, err := m.GatewayFor(context.Background(), Endpoint{
		Name: "selfsigned-eval", Addr: fg.addr, Type: "selfsigned",
	})
	if err != nil {
		t.Fatalf("GatewayFor did not connect the account's gateway: %v", err)
	}
	if gw.Name != "selfsigned-eval" || !gw.IsConnected {
		t.Fatalf("got gateway %q connected=%v, want selfsigned-eval connected", gw.Name, gw.IsConnected)
	}
	if _, err := m.GetGateway("selfsigned-eval"); err != nil {
		t.Fatalf("the gateway was not kept registered for the next lookup: %v", err)
	}
}

// TestGatewayForFallsBackToTheProviderType keeps the lookup every call site
// used before: an account with no address of its own is served by a gateway
// registered under its provider type.
func TestGatewayForFallsBackToTheProviderType(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	t.Cleanup(m.Close)
	ctx := context.Background()

	if _, err := m.RegisterGateway(ctx, "selfsigned", fg.addr, "selfsigned", ""); err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	gw, err := m.GatewayFor(ctx, Endpoint{Name: "legacy-account", Type: "selfsigned"})
	if err != nil {
		t.Fatalf("GatewayFor did not fall back to the provider type: %v", err)
	}
	if gw.Name != "selfsigned" {
		t.Fatalf("got gateway %q, want the one registered as selfsigned", gw.Name)
	}
}

// TestGatewayForDoesNotRedialAnUnreachableGatewayOnEveryCall.
//
// A dial to a gateway that is down waits out its whole deadline. Reconnecting
// on demand must not turn that into a stall on every request that touches the
// account while it is down: one attempt, then a pause before the next.
func TestGatewayForDoesNotRedialAnUnreachableGatewayOnEveryCall(t *testing.T) {
	m := testManager()
	t.Cleanup(m.Close)
	m.dialTimeout = 300 * time.Millisecond
	ep := Endpoint{Name: "down", Addr: deadAddr(t), Type: "acme"}

	if _, err := m.GatewayFor(context.Background(), ep); err == nil {
		t.Fatal("GatewayFor reported a gateway nothing is listening for as connected")
	}

	start := time.Now()
	if _, err := m.GatewayFor(context.Background(), ep); err == nil {
		t.Fatal("the second attempt reported the dead gateway as connected")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("the second attempt took %s: it dialled again instead of waiting out the pause", elapsed)
	}
}

// TestRegisterGatewayDoesNotBlockLookupsWhileDialling.
//
// Registration held the manager's lock for the whole dial, up to fifteen
// seconds against a gateway that does not answer. Every issuance looks its
// gateway up under the same lock, so one slow reconnect stalled all of them.
func TestRegisterGatewayDoesNotBlockLookupsWhileDialling(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	t.Cleanup(m.Close)
	m.dialTimeout = 2 * time.Second
	ctx := context.Background()

	if _, err := m.RegisterGateway(ctx, "live", fg.addr, "acme", ""); err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = m.RegisterGateway(ctx, "wedged", silentAddr(t), "acme", "")
	}()
	time.Sleep(150 * time.Millisecond) // well inside the wedged dial

	start := time.Now()
	if _, err := m.GetGateway("live"); err != nil {
		t.Fatalf("lookup of a connected gateway failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("a lookup waited %s behind another gateway's dial", elapsed)
	}
	<-done
}

// TestHealthCheckAllReconnectsAGatewayThatRecovered.
//
// The sweep only ever checked gateways already marked connected. One failed
// check (a gateway restarting, a network blip) marked it disconnected, and
// nothing looked at it again: it stayed unusable until somebody pressed Check
// now, however long ago it came back.
func TestHealthCheckAllReconnectsAGatewayThatRecovered(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	t.Cleanup(m.Close)
	ctx := context.Background()

	if _, err := m.RegisterGateway(ctx, "acme", fg.addr, "acme", ""); err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	// An earlier sweep found it down; it is answering again now.
	m.mu.Lock()
	m.gateways["acme"].IsConnected = false
	m.mu.Unlock()

	m.HealthCheckAll(ctx)

	if _, err := m.GetGateway("acme"); err != nil {
		t.Fatalf("a gateway that answers its health check again is still unusable: %v", err)
	}
}

// TestConnectAllRegistersEveryEndpoint is what startup uses for the gateways
// CA accounts name, so the gateway list is true straight after a restart
// rather than only after each account's first request.
func TestConnectAllRegistersEveryEndpoint(t *testing.T) {
	a, b := startFakeGateway(t), startFakeGateway(t)
	m := testManager()
	t.Cleanup(m.Close)
	m.dialTimeout = 300 * time.Millisecond

	m.ConnectAll(context.Background(), []Endpoint{
		{Name: "one", Addr: a.addr, Type: "acme"},
		{Name: "two", Addr: b.addr, Type: "vault"},
		{Name: "down", Addr: deadAddr(t), Type: "acme"},
	})

	for _, name := range []string{"one", "two"} {
		if _, err := m.GetGateway(name); err != nil {
			t.Errorf("%s was not connected: %v", name, err)
		}
	}
	if _, err := m.GetGateway("down"); err == nil {
		t.Error("a gateway nothing is listening for was reported connected")
	}
}

// TestHealthCheckAllConnectsAGatewayThatWasDownAtStartup.
//
// A gateway that was not running when the core started never made it into the
// registry, so the sweep, which only walked the registry, never tried it again.
// It stayed unusable after it came up, until somebody pressed Check now.
func TestHealthCheckAllConnectsAGatewayThatWasDownAtStartup(t *testing.T) {
	m := testManager()
	t.Cleanup(m.Close)
	m.dialTimeout = 300 * time.Millisecond
	addr := deadAddr(t)

	m.ConnectAll(context.Background(), []Endpoint{{Name: "late", Addr: addr, Type: "acme"}})
	if _, err := m.GetGateway("late"); err == nil {
		t.Fatal("a gateway nothing is listening for was reported connected")
	}

	// It comes up, on the address it was configured with.
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not take the port back for the gateway: %v", err)
	}
	startFakeGatewayOn(t, lis)

	m.HealthCheckAll(context.Background())

	if _, err := m.GetGateway("late"); err != nil {
		t.Fatalf("the sweep did not connect a gateway that came up after startup: %v", err)
	}
}

// startFakeGatewayOn serves the fake gateway on a listener the test chose.
func startFakeGatewayOn(t *testing.T, lis net.Listener) *fakeGateway {
	t.Helper()
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
