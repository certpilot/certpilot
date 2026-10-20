package pluginmgr

import (
	"testing"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
)

// The metrics scrape reads connection state from another goroutine than the
// health sweep that writes it; it has to get a copy taken under the lock.
func TestConnectionStatesIsASnapshotByName(t *testing.T) {
	m := NewManager(grpckit.TLSConfig{Insecure: true})
	m.mu.Lock()
	m.gateways["letsencrypt"] = &GatewayClient{Name: "letsencrypt", IsConnected: true}
	m.gateways["vault"] = &GatewayClient{Name: "vault", IsConnected: false}
	m.mu.Unlock()

	got := m.ConnectionStates()
	if len(got) != 2 || !got["letsencrypt"] || got["vault"] {
		t.Fatalf("ConnectionStates = %v, want letsencrypt connected and vault not", got)
	}

	got["vault"] = true
	if m.ConnectionStates()["vault"] {
		t.Fatal("changing the returned map changed the manager's state")
	}
}
