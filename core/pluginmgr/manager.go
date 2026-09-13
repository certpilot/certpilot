// Package pluginmgr manages active gateway plugin gRPC connections and registries.
package pluginmgr

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"google.golang.org/grpc"
)

// GatewayClient wraps a gRPC connection to a gateway plugin.
type GatewayClient struct {
	Name         string
	Addr         string
	Type         string
	Conn         *grpc.ClientConn
	Client       providerv1.CertificateProviderServiceClient
	Capabilities *commonv1.ProviderCapabilities
	LastHealth   *providerv1.HealthCheckResponse
	LastChecked  time.Time
	IsConnected  bool
}

// Manager manages connections to all configured gateway plugins.
type Manager struct {
	// tls is the client identity the core presents to every gateway. The
	// channel carries CSRs, private keys, and CA credentials, so it is
	// mutually authenticated unless explicitly disabled for development.
	tls grpckit.TLSConfig

	mu       sync.RWMutex
	gateways map[string]*GatewayClient
}

// NewManager creates a new plugin manager.
func NewManager(tls grpckit.TLSConfig) *Manager {
	return &Manager{
		tls:      tls,
		gateways: make(map[string]*GatewayClient),
	}
}

// RegisterGateway connects to a gateway plugin and retrieves its capabilities.
//
// serverName overrides the name expected in the gateway's certificate, for
// gateways dialed by IP or through a service alias. Pass "" to derive it from
// the address.
func (m *Manager) RegisterGateway(ctx context.Context, name, addr, gwType, serverName string) (*GatewayClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already registered
	if existing, ok := m.gateways[name]; ok && existing.IsConnected {
		return existing, nil
	}

	slog.Info("connecting to gateway plugin", "name", name, "addr", addr, "type", gwType)

	tlsCfg := m.tls
	if !tlsCfg.Insecure {
		tlsCfg.ServerName = serverName
		if tlsCfg.ServerName == "" {
			// Default to the host portion of the dial address, which is what
			// the certificate should name.
			if host, _, err := net.SplitHostPort(addr); err == nil {
				tlsCfg.ServerName = host
			} else {
				tlsCfg.ServerName = addr
			}
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	conn, err := grpckit.Dial(dialCtx, addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gateway %s at %s: %w", name, addr, err)
	}

	client := providerv1.NewCertificateProviderServiceClient(conn)

	// Fetch capabilities
	capResp, err := client.GetCapabilities(ctx, &providerv1.GetCapabilitiesRequest{})
	if err != nil {
		slog.Warn("failed to fetch gateway capabilities, using defaults", "name", name, "error", err)
	}

	var caps *commonv1.ProviderCapabilities
	if capResp != nil {
		caps = capResp.Capabilities
	}

	gw := &GatewayClient{
		Name:         name,
		Addr:         addr,
		Type:         gwType,
		Conn:         conn,
		Client:       client,
		Capabilities: caps,
		LastChecked:  time.Now(),
		IsConnected:  true,
	}

	m.gateways[name] = gw
	slog.Info("gateway registered successfully", "name", name, "type", gwType)
	return gw, nil
}

// GetGateway returns a registered gateway by name.
func (m *Manager) GetGateway(name string) (*GatewayClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	gw, ok := m.gateways[name]
	if !ok || !gw.IsConnected {
		return nil, fmt.Errorf("gateway %s not found or disconnected", name)
	}
	return gw, nil
}

// ListGateways returns a summary of all registered gateways.
func (m *Manager) ListGateways() []*GatewayClient {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*GatewayClient, 0, len(m.gateways))
	for _, gw := range m.gateways {
		list = append(list, gw)
	}
	return list
}

// HealthCheckAll checks the health of all registered gateways.
func (m *Manager) HealthCheckAll(ctx context.Context) map[string]*providerv1.HealthCheckResponse {
	// Snapshot under the read lock, then make the network calls without it.
	// Holding a lock across a gRPC round trip would stall every issuance for
	// as long as the slowest gateway takes to answer.
	m.mu.RLock()
	snapshot := make(map[string]*GatewayClient, len(m.gateways))
	for name, gw := range m.gateways {
		if gw.IsConnected {
			snapshot[name] = gw
		}
	}
	m.mu.RUnlock()

	results := make(map[string]*providerv1.HealthCheckResponse, len(snapshot))
	for name, gw := range snapshot {
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := gw.Client.HealthCheck(callCtx, &providerv1.HealthCheckRequest{})
		cancel()

		m.mu.Lock()
		gw.LastChecked = time.Now()
		if err != nil {
			slog.Warn("gateway health check failed", "name", name, "error", err)
			gw.IsConnected = false
			m.mu.Unlock()
			continue
		}
		gw.LastHealth = resp
		m.mu.Unlock()

		results[name] = resp
	}
	return results
}

// Close closes all gateway connections.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, gw := range m.gateways {
		if gw.Conn != nil {
			slog.Info("closing gateway connection", "name", name)
			gw.Conn.Close()
		}
	}
	m.gateways = make(map[string]*GatewayClient)
}
