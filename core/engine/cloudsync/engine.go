package cloudsync

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

const (
	// tickInterval is how often due connections are looked for. Syncs are
	// measured in hours, so a minute's granularity is ample.
	tickInterval = 1 * time.Minute
	// MinSyncIntervalMinutes is the shortest permitted sync interval.
	//
	// Lower than the Certificate Transparency floor, because these are the
	// organisation's own accounts rather than somebody's free service — but not
	// trivial, because every sync is a burst of API calls that count against
	// the account's own quota, and a tool that exhausts a shared rate limit
	// breaks deployments as well as itself.
	MinSyncIntervalMinutes = 30
	// syncTimeout bounds one connection's enumeration. An account with a few
	// hundred certificates needs a call each for their bodies.
	syncTimeout = 5 * time.Minute
)

// Engine keeps cloud certificate stores inventoried.
type Engine struct {
	store   store.Store
	keyring *secrets.Keyring
	broker  *events.Broker
	tick    time.Duration
	now     func() time.Time
	// build is swapped in tests so a sync can be driven without a cloud
	// account. Production always goes through Build.
	build func(providerType string, rawConfig []byte) (Provider, error)

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// Option configures an Engine.
type Option func(*Engine)

// WithBroker publishes findings to the event stream and the alert channels.
func WithBroker(b *events.Broker) Option {
	return func(e *Engine) { e.broker = b }
}

// WithTick sets how often due connections are looked for.
func WithTick(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.tick = d
		}
	}
}

// WithProviderBuilder replaces how providers are constructed.
func WithProviderBuilder(fn func(string, []byte) (Provider, error)) Option {
	return func(e *Engine) {
		if fn != nil {
			e.build = fn
		}
	}
}

// NewEngine creates an engine.
func NewEngine(s store.Store, keyring *secrets.Keyring, opts ...Option) *Engine {
	e := &Engine{
		store:   s,
		keyring: keyring,
		tick:    tickInterval,
		now:     time.Now,
		build:   Build,
		stopCh:  make(chan struct{}),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Start begins the loop.
func (e *Engine) Start() {
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()

	e.wg.Add(1)
	go e.run()

	slog.Info("cloud inventory sync started", "tick", e.tick)
}

// Stop ends the loop. Safe to call twice, and on one that never started.
func (e *Engine) Stop() {
	if e == nil {
		return
	}
	e.stopped.Do(func() { close(e.stopCh) })
	e.wg.Wait()
}

func (e *Engine) run() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.tick)
	defer ticker.Stop()

	e.SyncDue(context.Background())
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.SyncDue(context.Background())
		}
	}
}

// SyncDue syncs every connection that is due. Exported so a test can drive it
// without waiting on a ticker.
func (e *Engine) SyncDue(ctx context.Context) {
	connections, err := e.store.GetDueCloudConnections(ctx, e.now())
	if err != nil {
		slog.Error("could not read cloud connections; no cloud store is being inventoried", "error", err)
		return
	}

	// One connection at a time. Several accounts syncing in parallel is a burst
	// of API calls from one address, which is how a deployment gets rate
	// limited across all of them at once.
	for _, conn := range connections {
		select {
		case <-e.stopCh:
			return
		default:
		}
		e.Sync(ctx, conn)
	}
}

// Sync inventories one connection and records what it found.
func (e *Engine) Sync(ctx context.Context, conn *store.CloudConnection) {
	now := e.now()
	next := now.Add(time.Duration(conn.SyncIntervalMinutes) * time.Minute)

	provider, err := e.provider(conn)
	if err != nil {
		e.fail(ctx, conn, now, next, err)
		return
	}

	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	assets, err := provider.Inventory(syncCtx)
	if err != nil {
		// Recorded as a failed *attempt*: last_synced_at moves, last_success_at
		// does not. This is why those are two columns. A connection whose
		// credentials expired three weeks ago must never read like an account
		// that simply holds no certificates.
		slog.Warn("a cloud inventory sync failed; this account was not looked at",
			"connection", conn.Name, "provider", conn.Provider, "error", err)
		e.fail(ctx, conn, now, next, err)
		return
	}

	certs := e.classify(ctx, conn, assets, now)

	added, err := e.store.UpsertCloudCertificates(ctx, certs)
	if err != nil {
		slog.Error("cloud inventory results could not be stored", "connection", conn.Name, "error", err)
		e.fail(ctx, conn, now, next, err)
		return
	}

	// Only after a sync that answered. Marking everything removed because an
	// API call failed would report an entire estate being dismantled.
	seen := make([]string, 0, len(certs))
	for _, c := range certs {
		seen = append(seen, c.ResourceID)
	}
	removed, err := e.store.MarkCloudCertificatesRemoved(ctx, conn.ID, seen, now)
	if err != nil {
		slog.Warn("could not reconcile certificates that have disappeared from this account",
			"connection", conn.Name, "error", err)
	}

	unmanaged := 0
	for _, c := range certs {
		if c.ManagementState == store.DiscoveryUnmanaged {
			unmanaged++
		}
	}

	if err := e.store.MarkCloudConnectionSynced(ctx, conn.ID, now, next, true,
		provider.Scopes(), len(certs), unmanaged, ""); err != nil {
		slog.Error("a cloud sync succeeded but the connection could not be updated",
			"connection", conn.Name, "error", err)
	}

	slog.Info("cloud inventory sync complete",
		"connection", conn.Name, "provider", conn.Provider,
		"certificates", len(certs), "new", len(added), "unmanaged", unmanaged, "removed", removed)

	e.announce(conn, certs, added)
}

func (e *Engine) fail(ctx context.Context, conn *store.CloudConnection, now, next time.Time, cause error) {
	if err := e.store.MarkCloudConnectionSynced(ctx, conn.ID, now, next, false, nil, 0, 0, cause.Error()); err != nil {
		slog.Error("could not record a failed cloud sync", "connection", conn.Name, "error", err)
	}
}

// provider opens the sealed configuration and constructs the provider.
func (e *Engine) provider(conn *store.CloudConnection) (Provider, error) {
	var raw []byte
	if conn.ConfigEncrypted != "" {
		if e.keyring == nil {
			return nil, fmt.Errorf("this connection has sealed credentials and there is no keyring to open them with")
		}
		plain, err := e.keyring.DecryptString(conn.ConfigEncrypted, secrets.ContextCloudConnectionConfig)
		if err != nil {
			return nil, fmt.Errorf("the stored credentials for this connection could not be decrypted: %w", err)
		}
		raw = []byte(plain)
	}
	return e.build(conn.Provider, raw)
}

// classify turns what a provider reported into records, deciding for each
// whether CertPilot already knows about it.
//
// Matched on the SHA-256 fingerprint, the same rule the network scanner uses.
// Not on domain name: an account frequently holds several certificates for one
// hostname, and the one that expires is a specific one of them.
func (e *Engine) classify(ctx context.Context, conn *store.CloudConnection, assets []Asset, now time.Time) []*store.CloudCertificate {
	out := make([]*store.CloudCertificate, 0, len(assets))

	for _, asset := range assets {
		cert := &store.CloudCertificate{
			ConnectionID:    conn.ID,
			ResourceID:      asset.ResourceID,
			Name:            asset.Name,
			Location:        asset.Location,
			CertificatePEM:  asset.CertificatePEM,
			RenewalMode:     asset.RenewalMode,
			WillRenew:       asset.WillRenew,
			Attached:        asset.Attached,
			AttachedTo:      asset.AttachedTo,
			SANs:            []string{},
			Findings:        []store.Finding{},
			ManagementState: store.DiscoveryUnmanaged,
			LastSeenAt:      now,
		}
		if cert.AttachedTo == nil {
			cert.AttachedTo = []string{}
		}

		if asset.CertificatePEM != "" {
			if info, err := x509util.ParseCertificatePEM([]byte(asset.CertificatePEM)); err == nil {
				cert.CommonName = info.CommonName
				cert.SubjectDN = info.SubjectDN
				cert.IssuerDN = info.IssuerDN
				cert.SerialNumber = info.SerialNumber
				cert.KeyType = info.KeyType
				cert.KeySize = info.KeySize
				cert.FingerprintSHA256 = info.FingerprintSHA256
				cert.SANs = append(cert.SANs, info.SANs...)
				notBefore, notAfter := info.NotBefore, info.NotAfter
				cert.NotBefore, cert.NotAfter = &notBefore, &notAfter
				if cert.Name == "" {
					cert.Name = info.CommonName
				}
			}
		}

		if cert.FingerprintSHA256 != "" {
			// Fail towards "unmanaged". Reporting a certificate we could not
			// check as already handled is how a lookup failure becomes an
			// outage nobody saw coming.
			managed, err := e.store.GetCertificateByFingerprint(ctx, cert.FingerprintSHA256)
			switch {
			case err != nil:
				slog.Warn("could not check a cloud certificate against inventory; reporting it as unmanaged",
					"connection", conn.Name, "resource", cert.ResourceID, "error", err)
				cert.Findings = append(cert.Findings, store.Finding{
					Code:     FindingInventoryFailed,
					Severity: events.SeverityWarning,
					Detail:   "This certificate could not be checked against the managed inventory, so it is reported as unmanaged. The lookup failed: " + err.Error(),
				})
			case managed != nil:
				cert.ManagementState = store.DiscoveryManaged
				id := managed.ID
				cert.MatchedCertificateID = &id
			}
		}

		cert.Findings = append(cert.Findings, assess(cert, asset, conn.Provider, now)...)
		out = append(out, cert)
	}
	return out
}

// announce publishes what the sync found.
//
// Two separate alerts, because they are two separate pieces of news and a team
// may well want them routed differently. "There is a certificate here nobody
// manages" is an inventory gap. "Nothing renews this and it expires in three
// weeks" is a dated outage.
func (e *Engine) announce(conn *store.CloudConnection, certs, added []*store.CloudCertificate) {
	if e.broker == nil {
		return
	}

	// Unmanaged is announced only for certificates new to this connection. A
	// sync every six hours re-reporting the same ACM inventory is how a channel
	// gets muted, taking the CA expiry alerts sharing it along too.
	newUnmanaged := make([]*store.CloudCertificate, 0)
	for _, c := range added {
		if c.ManagementState == store.DiscoveryUnmanaged {
			newUnmanaged = append(newUnmanaged, c)
		}
	}
	if len(newUnmanaged) > 0 {
		e.broker.Publish(events.Event{
			Topic:    events.TopicCloudUnmanaged,
			Severity: events.SeverityWarning,
			EntityID: conn.ID,
			Payload: map[string]any{
				"connection_id":   conn.ID,
				"connection":      conn.Name,
				"provider":        conn.Provider,
				"unmanaged_count": len(newUnmanaged),
				"certificates":    describeCerts(newUnmanaged, 10),
			},
		})
	}

	// Renewal findings are announced from the whole inventory rather than only
	// the new rows. A certificate nothing renews becomes news as its expiry
	// approaches, not on the day it was first seen — and the day it was first
	// seen is usually the day it had a year left.
	urgent := make([]*store.CloudCertificate, 0)
	for _, c := range certs {
		for _, f := range c.Findings {
			if (f.Code == FindingWillNotRenew || f.Code == FindingRenewalOverdue) &&
				f.Severity != events.SeverityInfo {
				urgent = append(urgent, c)
				break
			}
		}
	}
	if len(urgent) > 0 {
		e.broker.Publish(events.Event{
			Topic:    events.TopicCloudWillNotRenew,
			Severity: worstOf(urgent),
			EntityID: conn.ID,
			Payload: map[string]any{
				"connection_id": conn.ID,
				"connection":    conn.Name,
				"provider":      conn.Provider,
				"count":         len(urgent),
				"certificates":  describeCerts(urgent, 10),
			},
		})
	}
}

func worstOf(certs []*store.CloudCertificate) string {
	severity := events.SeverityWarning
	for _, c := range certs {
		if c.WorstSeverity() == events.SeverityCritical {
			return events.SeverityCritical
		}
	}
	return severity
}

// describeCerts names certificates the way somebody would have to look for
// them: what it is called, and where it is.
func describeCerts(certs []*store.CloudCertificate, max int) []string {
	out := make([]string, 0, max)
	for _, c := range certs {
		name := c.Name
		if name == "" {
			name = c.CommonName
		}
		if name == "" {
			name = c.ResourceID
		}
		if c.Location != "" {
			name = fmt.Sprintf("%s (%s)", name, c.Location)
		}
		out = append(out, name)
		if len(out) == max {
			break
		}
	}
	return out
}

// ValidateConnection checks a connection can run, before it is stored.
func ValidateConnection(conn *store.CloudConnection) error {
	conn.Name = strings.TrimSpace(conn.Name)
	if conn.Name == "" {
		return fmt.Errorf("a cloud connection needs a name")
	}
	conn.Provider = strings.ToLower(strings.TrimSpace(conn.Provider))

	supported := false
	for _, p := range Providers() {
		if conn.Provider == p {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("unknown cloud provider %q; supported: %s",
			conn.Provider, strings.Join(Providers(), ", "))
	}

	if conn.SyncIntervalMinutes < MinSyncIntervalMinutes {
		return fmt.Errorf(
			"the shortest sync interval is %d minutes; every sync is a burst of API calls against the account's own quota",
			MinSyncIntervalMinutes)
	}
	return nil
}
