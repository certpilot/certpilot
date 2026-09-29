package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
)

// silentAddr accepts connections and never answers, so a dial to it waits out
// its whole deadline: a gateway that is down behind something still listening.
func silentAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

// TestStartupDoesNotWaitForACAAccountsGateway.
//
// Connecting the gateways CA accounts name at startup fixed renewal after a
// restart, and in its first form held startup until every one of them had
// answered or timed out. In memory mode the seeded sample account names
// localhost:9091, so a core with nothing running there took fifteen seconds to
// open its port, and the compatibility job decided it had not started. The
// config file's gateways are still connected before startup goes on, as they
// always were; an account's gateway connects in the background, and the first
// request that needs it connects it too.
func TestStartupDoesNotWaitForACAAccountsGateway(t *testing.T) {
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	if err := st.CreateCAAccount(context.Background(), &store.CAAccount{
		Name: "wedged", ProviderType: "acme", GatewayAddr: silentAddr(t), Status: "CONNECTED",
	}); err != nil {
		t.Fatal(err)
	}
	pm := pluginmgr.NewManager(grpckit.TLSConfig{Insecure: true})
	t.Cleanup(pm.Close)

	start := time.Now()
	done := connectGateways(context.Background(), nil, st, pm)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("startup waited %s for a CA account's gateway", elapsed)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the background connection never finished")
	}
}
