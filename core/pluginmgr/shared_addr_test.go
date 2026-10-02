package pluginmgr

import (
	"context"
	"testing"
)

// TestAnAccountUsesTheGatewayAlreadyConnectedAtItsAddress.
//
// v0.1.x accepted a CA account's server_name and never stored it: the column
// arrived in v0.2.0 (migration 043), empty for every account that already
// existed. The quickstart's own selfsigned-eval account is one of them, and it
// names the address of the gateway the config file already connects as
// selfsigned-dev, with server_name localhost. After the upgrade the core dialled
// that address again without a server name, failed hostname verification after
// a timeout, and issuing, renewing and revoking through the account all failed.
// A gateway already connected at an account's address is that account's
// gateway: the same process, reached the same way.
func TestAnAccountUsesTheGatewayAlreadyConnectedAtItsAddress(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	t.Cleanup(m.Close)
	ctx := context.Background()

	if _, err := m.RegisterGateway(ctx, "selfsigned-dev", fg.addr, "selfsigned", "localhost"); err != nil {
		t.Fatal(err)
	}

	gw, err := m.GatewayFor(ctx, Endpoint{Name: "selfsigned-eval", Addr: fg.addr, Type: "selfsigned"})
	if err != nil {
		t.Fatalf("an account naming a connected gateway's address got no gateway: %v", err)
	}
	if gw.Name != "selfsigned-dev" {
		t.Errorf("got gateway %q, want the one already connected at that address", gw.Name)
	}
	if n := len(m.ListGateways()); n != 1 {
		t.Errorf("%d gateways registered, want 1: the account dialled its address a second time", n)
	}
}

// TestStartupDoesNotRedialAnAddressThatIsAlreadyConnected: ConnectAll is what
// startup and the health sweep use for account gateways. Dialling an address
// that is already connected, under another name and without its server name,
// fails every sweep and logs a warning about a gateway that works.
func TestStartupDoesNotRedialAnAddressThatIsAlreadyConnected(t *testing.T) {
	fg := startFakeGateway(t)
	m := testManager()
	t.Cleanup(m.Close)
	ctx := context.Background()

	if _, err := m.RegisterGateway(ctx, "selfsigned-dev", fg.addr, "selfsigned", "localhost"); err != nil {
		t.Fatal(err)
	}
	m.ConnectAll(ctx, []Endpoint{{Name: "selfsigned-eval", Addr: fg.addr, Type: "selfsigned"}})

	if n := len(m.ListGateways()); n != 1 {
		t.Errorf("%d gateways registered after ConnectAll, want 1", n)
	}
}
