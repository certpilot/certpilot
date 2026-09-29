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

	// known is every gateway this manager has been told how to reach, whether
	// or not it answered: the config file's, and those the CA accounts name.
	// A gateway that was down when it was first dialled has no entry in
	// gateways at all, so without this the health sweep would never learn it
	// exists and nothing would connect it when it came up.
	known map[string]Endpoint
	// failedAt is when a dial to each gateway last failed, so a request that
	// needs a gateway that is down pays for one dial, not one per request.
	failedAt map[string]time.Time

	dialTimeout time.Duration
	// onDemandDial bounds a dial made for a request that is waiting on it.
	// A request path has to fit inside the server's write timeout, and a
	// gateway that answers at all answers in milliseconds.
	onDemandDial time.Duration
	redialPause  time.Duration

	stopCh   chan struct{}
	stopOnce sync.Once
}

// Endpoint is how to reach one gateway: the name it is registered under (a
// CA account's name, or a gateway's in the config file), its address, its
// provider type, and the TLS server name when the address does not carry it.
type Endpoint struct {
	Name       string
	Addr       string
	Type       string
	ServerName string
}

// NewManager creates a new plugin manager.
func NewManager(tls grpckit.TLSConfig) *Manager {
	return &Manager{
		tls:          tls,
		gateways:     make(map[string]*GatewayClient),
		known:        make(map[string]Endpoint),
		failedAt:     make(map[string]time.Time),
		stopCh:       make(chan struct{}),
		dialTimeout:  15 * time.Second,
		onDemandDial: 5 * time.Second,
		redialPause:  30 * time.Second,
	}
}

// RegisterGateway connects to a gateway plugin and retrieves its capabilities.
//
// serverName overrides the name expected in the gateway's certificate, for
// gateways dialed by IP or through a service alias. Pass "" to derive it from
// the address.
func (m *Manager) RegisterGateway(ctx context.Context, name, addr, gwType, serverName string) (*GatewayClient, error) {
	m.mu.Lock()
	if addr != "" {
		m.known[name] = Endpoint{Name: name, Addr: addr, Type: gwType, ServerName: serverName}
	}
	if existing, ok := m.gateways[name]; ok && existing.IsConnected {
		m.mu.Unlock()
		return existing, nil
	}
	m.mu.Unlock()

	// Everything from here to the swap happens without the lock. A dial to a
	// gateway that does not answer waits out its whole deadline, and every
	// issuance looks its own gateway up under this lock; holding it here once
	// stalled all of them behind one wedged gateway.
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

	dialCtx, cancel := context.WithTimeout(ctx, m.dialTimeout)
	defer cancel()

	conn, err := grpckit.Dial(dialCtx, addr, tlsCfg)
	if err != nil {
		m.mu.Lock()
		m.failedAt[name] = time.Now()
		m.mu.Unlock()
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

	m.mu.Lock()
	defer m.mu.Unlock()

	// Two callers can dial the same gateway at once now that the dial is
	// outside the lock. The first to finish wins and the other's connection
	// is closed, so there is only ever one per name.
	if existing, ok := m.gateways[name]; ok && existing.IsConnected {
		conn.Close()
		return existing, nil
	}

	// A previous entry under this name is being replaced — most often a
	// reconnect after the earlier connection was marked disconnected by a
	// failed health check. Nothing else can be holding a reference to its
	// Conn: GetGateway and ListGateways only ever hand out pointers while
	// holding this same lock, and every RPC on it either already returned or
	// is about to fail exactly as if the gateway process had restarted.
	// Leaving it open would leak one file descriptor and one goroutine pair
	// per reconnect, forever, on a connection nothing will ever use again.
	if prev, ok := m.gateways[name]; ok && prev.Conn != nil {
		prev.Conn.Close()
	}

	m.gateways[name] = gw
	delete(m.failedAt, name)
	slog.Info("gateway registered successfully", "name", name, "type", gwType)
	return gw, nil
}

// GatewayFor returns the gateway that serves a CA account, connecting to it
// if it is not connected.
//
// The lookup every caller used to repeat was "by the account's name, then by
// its provider type", and neither step could connect anything. So a CA
// account created through the API, whose gateway is registered under its own
// name, was unusable after every core restart until somebody pressed Check
// now: every issuance, renewal and revocation through it failed with "not
// connected". This dials the account's own address when nothing is connected
// under its name, and falls back to the provider type as before.
//
// A dial that fails is not retried for redialPause, so while a gateway is down
// the requests that need it fail at once rather than each waiting out a dial.
func (m *Manager) GatewayFor(ctx context.Context, ep Endpoint) (*GatewayClient, error) {
	if gw, err := m.GetGateway(ep.Name); err == nil {
		return gw, nil
	}

	var dialErr error
	if ep.Addr != "" {
		m.mu.RLock()
		failed, recently := m.failedAt[ep.Name]
		m.mu.RUnlock()
		if recently && time.Since(failed) < m.redialPause {
			dialErr = fmt.Errorf("gateway %s at %s could not be reached %s ago; not retrying yet",
				ep.Name, ep.Addr, time.Since(failed).Round(time.Second))
		} else {
			dialCtx, cancel := context.WithTimeout(ctx, m.onDemandDial)
			gw, err := m.RegisterGateway(dialCtx, ep.Name, ep.Addr, ep.Type, ep.ServerName)
			cancel()
			if err == nil {
				return gw, nil
			}
			dialErr = err
		}
	}

	if ep.Type != "" && ep.Type != ep.Name {
		if gw, err := m.GetGateway(ep.Type); err == nil {
			return gw, nil
		}
	}
	if dialErr != nil {
		return nil, dialErr
	}
	return nil, fmt.Errorf("gateway %s not found or disconnected", ep.Name)
}

// ConnectAll dials every endpoint at once and waits for them all, so startup
// costs one dial timeout at most rather than one per gateway that is down.
// A gateway that cannot be reached is logged and left to the health sweep,
// which keeps trying it.
func (m *Manager) ConnectAll(ctx context.Context, eps []Endpoint) {
	var wg sync.WaitGroup
	for _, ep := range eps {
		if ep.Addr == "" {
			continue
		}
		wg.Add(1)
		go func(ep Endpoint) {
			defer wg.Done()
			if _, err := m.RegisterGateway(ctx, ep.Name, ep.Addr, ep.Type, ep.ServerName); err != nil {
				slog.Warn("could not connect to gateway; the health sweep will keep trying",
					"name", ep.Name, "addr", ep.Addr, "error", err)
			}
		}(ep)
	}
	wg.Wait()
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
	//
	// Disconnected gateways are checked too. The sweep used to skip them, so
	// one failed check (a gateway restarting, a network blip) left a gateway
	// unusable until somebody pressed Check now, however long ago it came
	// back. Its connection redials on its own; a health check that answers is
	// what says it is usable again.
	m.mu.RLock()
	snapshot := make(map[string]*GatewayClient, len(m.gateways))
	for name, gw := range m.gateways {
		snapshot[name] = gw
	}
	var absent []Endpoint
	for name, ep := range m.known {
		if _, ok := m.gateways[name]; !ok {
			absent = append(absent, ep)
		}
	}
	m.mu.RUnlock()

	// Gateways that were down the first time they were dialled have no
	// connection to check, so they are dialled again here.
	if len(absent) > 0 {
		m.ConnectAll(ctx, absent)
		m.mu.RLock()
		for _, ep := range absent {
			if gw, ok := m.gateways[ep.Name]; ok {
				snapshot[ep.Name] = gw
			}
		}
		m.mu.RUnlock()
	}

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
		if !gw.IsConnected {
			slog.Info("gateway is answering again", "name", name)
		}
		gw.IsConnected = true
		gw.LastHealth = resp
		needsCaps := gw.Capabilities == nil
		m.mu.Unlock()

		results[name] = resp

		// Capabilities are fetched once, at registration, and never refreshed
		// — so a gateway that was merely slow to come up at startup answers
		// GetCapabilities correctly forever after and this process never asks
		// it again. That is what left supports_ca_info permanently false, and
		// CA import permanently silent, for a gateway that only needed a few
		// more seconds. Asking again here costs one RPC every sweep interval,
		// and only for a gateway that is already answering healthy but still
		// missing them.
		if needsCaps {
			m.refreshCapabilities(ctx, name, gw)
		}
	}
	return results
}

// refreshCapabilities retries GetCapabilities for a gateway that is healthy
// but has never successfully answered it. A failure here is logged and left
// for the next sweep rather than treated as a health failure of its own —
// HealthCheck just said this gateway is fine, and a second RPC failing
// immediately after is far more likely to be transient than a contradiction.
func (m *Manager) refreshCapabilities(ctx context.Context, name string, gw *GatewayClient) {
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	resp, err := gw.Client.GetCapabilities(callCtx, &providerv1.GetCapabilitiesRequest{})
	cancel()
	if err != nil {
		slog.Warn("gateway is healthy but still has not answered GetCapabilities",
			"name", name, "error", err)
		return
	}

	m.mu.Lock()
	gw.Capabilities = resp.Capabilities
	m.mu.Unlock()
	slog.Info("recovered gateway capabilities after a prior failure at registration", "name", name)
}

// Start runs HealthCheckAll on a timer.
//
// Between requests, nothing else notices a gateway that recovers on its own,
// or one that goes quiet. This is what makes
// "is_connected" on the gateway list reflect reality between those moments,
// rather than only after the next certificate request happens to fail.
func (m *Manager) Start(interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	slog.Info("starting gateway health sweep", "interval", interval)

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.HealthCheckAll(context.Background())
			case <-m.stopCh:
				return
			}
		}
	}()
}

// Stop halts the periodic health sweep. It is safe to call more than once,
// and safe to call even if Start was never called.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
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
