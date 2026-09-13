package renewal

import (
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"sync"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// Constants governing how renewal advice is refreshed.
const (
	// ariTick is how often the poller looks for certificates whose advice is
	// stale. The advice itself changes on the order of hours, so this only
	// needs to be often enough to notice.
	ariTick = 5 * time.Minute
	// ariBatch bounds one pass. A large estate refreshes over several passes
	// rather than making a thousand gateway calls in one breath.
	ariBatch = 50
	// ariDefaultInterval is used when the CA does not send Retry-After.
	ariDefaultInterval = 6 * time.Hour
	// ariMinInterval floors whatever the CA asks for. A Retry-After of zero
	// would otherwise turn this into a busy loop against somebody's endpoint.
	ariMinInterval = 15 * time.Minute
	// ariUnsupportedInterval is how long to wait before asking a CA that does
	// not publish renewal information whether it has started. Long, because the
	// answer changes about once a year, but not never: a CA that adds ARI
	// support should not need a restart here to be noticed.
	ariUnsupportedInterval = 24 * time.Hour
	// ariCallTimeout bounds one gateway call.
	ariCallTimeout = 20 * time.Second
)

// ARIPoller keeps each certificate's renewal advice current.
//
// The gateway has been able to read RFC 9773 renewal information since phase 2.
// Nothing in the core ever asked, so the advice was fetched during a status
// call, logged, and thrown away. This is the part that asks, records, and acts.
//
// Two reasons it matters, and they are not equally interesting. Routinely it
// lets the CA spread renewal load, which a fixed lead time cannot: every
// certificate issued in one week otherwise renews in one week, forever.
//
// In an incident it is the only automated warning there is. A CA facing mass
// revocation pulls the affected windows into the past, and clients that read
// ARI replace their certificates within hours. Clients that do not find out by
// email — if the address on the account still belongs to somebody — and
// otherwise find out when the certificate stops working.
type ARIPoller struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	keyring   *secrets.Keyring
	broker    *events.Broker

	tick  time.Duration
	batch int
	now   func() time.Time

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// ARIOption configures a poller.
type ARIOption func(*ARIPoller)

// WithARITick sets how often stale advice is looked for.
func WithARITick(d time.Duration) ARIOption {
	return func(p *ARIPoller) {
		if d > 0 {
			p.tick = d
		}
	}
}

// WithARIBatch bounds one pass.
func WithARIBatch(n int) ARIOption {
	return func(p *ARIPoller) {
		if n > 0 {
			p.batch = n
		}
	}
}

// NewARIPoller creates a poller.
func NewARIPoller(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring, broker *events.Broker, opts ...ARIOption) *ARIPoller {
	p := &ARIPoller{
		store:     s,
		pluginMgr: pm,
		keyring:   kr,
		broker:    broker,
		tick:      ariTick,
		batch:     ariBatch,
		now:       time.Now,
		stopCh:    make(chan struct{}),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Start begins the loop.
func (p *ARIPoller) Start() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()

	p.wg.Add(1)
	go p.run()
	slog.Info("renewal information poller started", "tick", p.tick, "batch", p.batch)
}

// Stop ends the loop. Safe to call twice, and on one that never started.
func (p *ARIPoller) Stop() {
	if p == nil {
		return
	}
	p.stopped.Do(func() { close(p.stopCh) })
	p.wg.Wait()
}

func (p *ARIPoller) run() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.tick)
	defer ticker.Stop()

	p.RefreshDue(context.Background())
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.RefreshDue(context.Background())
		}
	}
}

// RefreshDue asks the CA about every certificate whose advice is stale.
// Exported so a test can drive it without a ticker.
func (p *ARIPoller) RefreshDue(ctx context.Context) {
	certs, err := p.store.GetCertificatesDueForARICheck(ctx, p.now(), p.batch)
	if err != nil {
		slog.Error("could not read certificates for a renewal information check", "error", err)
		return
	}
	for _, cert := range certs {
		select {
		case <-p.stopCh:
			return
		default:
		}
		p.Refresh(ctx, cert)
	}
}

// Refresh asks the CA about one certificate and records the answer.
func (p *ARIPoller) Refresh(ctx context.Context, cert *store.Certificate) {
	now := p.now()

	window, err := p.fetch(ctx, cert)
	if err != nil {
		// Not recorded as "unsupported": a gateway that is down and a CA that
		// does not publish renewal information are different facts, and
		// conflating them would leave a certificate reading as "this CA has
		// nothing to say" when nobody ever managed to ask.
		//
		// The existing schedule is left alone. Advice already given does not
		// stop being true because the next call failed, and clearing it would
		// silently drop every certificate back to lead-time renewal the first
		// time a gateway restarted.
		slog.Debug("could not refresh renewal information", "certificate", cert.ID, "error", err)
		p.record(ctx, cert, store.RenewalInfoUpdate{
			RenewalScheduledAt: cert.RenewalScheduledAt,
			WindowStart:        cert.ARIWindowStart,
			WindowEnd:          cert.ARIWindowEnd,
			ExplanationURL:     cert.ARIExplanationURL,
			CheckedAt:          cert.ARICheckedAt,
			NextCheckAt:        timePtr(now.Add(ariMinInterval)),
			Supported:          cert.ARISupported,
		})
		return
	}

	if window == nil {
		// Asked, and this CA does not publish renewal information. Any advice
		// it gave previously is cleared, so the certificate falls back to
		// lead-time renewal rather than keeping a window nobody stands behind.
		no := false
		p.record(ctx, cert, store.RenewalInfoUpdate{
			CheckedAt:   &now,
			NextCheckAt: timePtr(now.Add(ariUnsupportedInterval)),
			Supported:   &no,
		})
		return
	}

	start, end := window.Start.AsTime(), window.End.AsTime()
	selected := selectWithin(start, end, now)

	next := ariDefaultInterval
	if window.RetryAfterSeconds > 0 {
		next = time.Duration(window.RetryAfterSeconds) * time.Second
	}
	if next < ariMinInterval {
		// Polling harder than asked is how a client loses access to the
		// endpoint that would have warned it.
		next = ariMinInterval
	}

	yes := true
	update := store.RenewalInfoUpdate{
		RenewalScheduledAt: &selected,
		WindowStart:        &start,
		WindowEnd:          &end,
		ExplanationURL:     window.ExplanationUrl,
		CheckedAt:          &now,
		NextCheckAt:        timePtr(now.Add(next)),
		Supported:          &yes,
	}

	// The part this whole feature exists for: the CA changing its mind.
	if moved, by := pulledForward(cert, selected); moved {
		slog.Warn("a CA has brought a renewal window forward",
			"certificate", cert.ID, "common_name", cert.CommonName,
			"by", by, "explanation", window.ExplanationUrl)
		p.announceWindowMoved(cert, update, by)
	}

	p.record(ctx, cert, update)
}

// fetch asks the gateway. A nil window with a nil error means the CA was asked
// and publishes no renewal information.
func (p *ARIPoller) fetch(ctx context.Context, cert *store.Certificate) (*providerv1.RenewalWindow, error) {
	account, err := p.store.GetCAAccount(ctx, *cert.CAAccountID)
	if err != nil {
		return nil, err
	}

	gw, err := p.pluginMgr.GetGateway(account.Name)
	if err != nil {
		gw, err = p.pluginMgr.GetGateway(account.ProviderType)
		if err != nil {
			return nil, err
		}
	}

	config, err := decryptCAConfig(p.keyring, account)
	if err != nil {
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, ariCallTimeout)
	defer cancel()

	resp, err := gw.Client.GetCertificateStatus(callCtx, &providerv1.GetCertificateStatusRequest{
		CertificatePem: []byte(*cert.CertificatePEM),
		ProviderConfig: config,
	})
	if err != nil {
		return nil, err
	}
	if resp.RenewalWindow == nil || resp.RenewalWindow.Start == nil || resp.RenewalWindow.End == nil {
		return nil, nil
	}
	return resp.RenewalWindow, nil
}

func (p *ARIPoller) record(ctx context.Context, cert *store.Certificate, update store.RenewalInfoUpdate) {
	if err := p.store.UpdateCertificateRenewalInfo(ctx, cert.ID, update); err != nil {
		slog.Error("could not record renewal information", "certificate", cert.ID, "error", err)
	}
}

// selectWithin picks a uniformly random instant inside the window.
//
// Random, not the start, and that is the point of the window rather than an
// implementation detail: if every client renewed at the start, ARI would move
// the thundering herd rather than disperse it. A window already underway yields
// a time between now and its end, so a client that wakes up late does not sit
// out until the next one.
func selectWithin(start, end, now time.Time) time.Time {
	if start.Before(now) {
		start = now
	}
	if !end.After(start) {
		// A window that has already closed means renew immediately. This is
		// what a CA does during a mass revocation.
		return now
	}

	spread := end.Sub(start)
	n, err := rand.Int(rand.Reader, big.NewInt(int64(spread)))
	if err != nil {
		return start
	}
	return start.Add(time.Duration(n.Int64()))
}

// pulledForward reports whether the CA has moved this certificate's renewal
// materially earlier than it previously said.
//
// The threshold exists because the selected instant is random: two consecutive
// checks of an unchanged window will differ by minutes or hours simply because
// a different point inside it was drawn. Comparing the raw times would alert on
// that noise every few hours, which is how the one alert that matters during an
// incident gets muted before the incident.
func pulledForward(cert *store.Certificate, selected time.Time) (bool, time.Duration) {
	if cert.RenewalScheduledAt == nil {
		return false, 0
	}
	// Measured on the window's end rather than the drawn instant: the end is
	// the CA's actual deadline and does not move on its own.
	if cert.ARIWindowEnd == nil {
		return false, 0
	}

	by := cert.RenewalScheduledAt.Sub(selected)
	if by < ariMovedThreshold {
		return false, 0
	}
	return true, by
}

// ariMovedThreshold is how much earlier a window has to move before it is
// treated as the CA changing its mind rather than a new random draw.
const ariMovedThreshold = 12 * time.Hour

// announceWindowMoved publishes the one automated warning a mass revocation
// gives you.
//
// Worded as what it means rather than what happened. "The renewal window
// changed" is a fact about a JSON field; "the CA has decided this certificate
// should be replaced sooner, which usually means something is wrong with it" is
// the thing somebody has to act on.
func (p *ARIPoller) announceWindowMoved(cert *store.Certificate, update store.RenewalInfoUpdate, by time.Duration) {
	if p.broker == nil {
		return
	}

	severity := events.SeverityWarning
	// A window that has already opened means the CA wants this replaced now.
	if update.WindowStart != nil && !update.WindowStart.After(p.now()) {
		severity = events.SeverityCritical
	}

	payload := map[string]any{
		"common_name":    cert.CommonName,
		"certificate_id": cert.ID,
		"issuer_dn":      cert.IssuerDN,
		"moved_by_hours": int(by.Hours()),
		"days_remaining": cert.DaysRemaining,
	}
	if update.WindowStart != nil {
		payload["window_start"] = update.WindowStart.Format(time.RFC3339)
	}
	if update.WindowEnd != nil {
		payload["window_end"] = update.WindowEnd.Format(time.RFC3339)
	}
	if update.RenewalScheduledAt != nil {
		payload["renew_at"] = update.RenewalScheduledAt.Format(time.RFC3339)
	}
	if update.ExplanationURL != "" {
		payload["explanation_url"] = update.ExplanationURL
	}

	p.broker.Publish(events.Event{
		Topic:    events.TopicCertRenewalWindowMoved,
		Severity: severity,
		EntityID: cert.ID,
		Payload:  payload,
	})
}

func timePtr(t time.Time) *time.Time { return &t }
