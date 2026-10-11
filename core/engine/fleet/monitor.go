// Package fleet watches the hosts that are supposed to be maintaining
// themselves.
//
// The failure this exists for is quiet and specific. An agent is installed on a
// host, works, and then stops — the service was disabled during an unrelated
// incident, the host was rebuilt from an older image, the process is in a crash
// loop nobody is looking at. Nothing breaks. The certificates on that host keep
// working right up until they expire, and on any screen that lists enrolled
// agents the host looks exactly like the ones that are fine.
//
// Silence is never success. It is the one answer this whole system refuses to
// read as an all-clear, and an agent is where that principle is easiest to get
// wrong: the absence of a heartbeat is, literally, nothing happening.
package fleet

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

const (
	// defaultTick is how often the fleet is swept for agents that have gone
	// quiet. Frequent enough that a dead host is noticed in minutes; the cost
	// is one indexed query.
	defaultTick = 1 * time.Minute
	// batch bounds one sweep, so a fleet where something took out every agent
	// at once does not try to publish a thousand events in one pass.
	batch = 50
)

// Monitor reports agents that have stopped reporting.
type Monitor struct {
	store  store.Store
	broker *events.Broker

	tick time.Duration
	now  func() time.Time

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// Option configures a Monitor.
type Option func(*Monitor)

// WithTick sets how often the fleet is swept.
func WithTick(d time.Duration) Option {
	return func(m *Monitor) {
		if d > 0 {
			m.tick = d
		}
	}
}

// NewMonitor creates a fleet monitor.
func NewMonitor(s store.Store, broker *events.Broker, opts ...Option) *Monitor {
	m := &Monitor{
		store:  s,
		broker: broker,
		tick:   defaultTick,
		now:    time.Now,
		stopCh: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Start begins the sweep.
func (m *Monitor) Start() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	m.wg.Add(1)
	go m.run()
	slog.Info("fleet monitor started", "tick", m.tick, "missed_intervals", store.AgentStaleAfter)
}

// Stop ends the sweep. Safe to call twice, and on one that never started.
func (m *Monitor) Stop() {
	if m == nil {
		return
	}
	m.stopped.Do(func() { close(m.stopCh) })
	m.wg.Wait()
}

func (m *Monitor) run() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.tick)
	defer ticker.Stop()

	m.RunSweep(context.Background())
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.RunSweep(context.Background())
		}
	}
}

// RunSweep reports every agent that has gone quiet since the last one.
// Exported so a test can drive it without a ticker.
//
// Safe on every replica. The alert mark is set in the database before the event
// is published, so two replicas sweeping in the same second produce one message
// rather than two — the same shape of answer as the renewal queue's partial
// unique index, and for the same reason: no leader, no failover gap.
func (m *Monitor) RunSweep(ctx context.Context) {
	now := m.now()

	// Replay-guard rows first, and unconditionally: this runs whether or not
	// any agent has gone quiet, because the table grows with every certificate
	// request the fleet makes and nothing else deletes from it. A row is
	// useless once its timestamp window has closed — the signature is refused
	// on its own age by then.
	if removed, err := m.store.SweepAgentRequestSignatures(ctx, now); err != nil {
		// Not a reason to skip the stale-agent sweep below. The consequence of
		// this failing is a table that grows; the consequence of returning here
		// is nobody being told a host has stopped reporting.
		slog.Warn("could not sweep expired agent request signatures", "error", err)
	} else if removed > 0 {
		slog.Debug("swept expired agent request signatures", "removed", removed)
	}

	// ACME nonces that have expired. The ACME server remembers each nonce it has
	// accepted so that none works twice, and past its expiry a nonce is refused
	// on its own, so the row is no longer protecting anything. Here because this
	// is the sweep that already runs, not because it has anything to do with
	// agents.
	if removed, err := m.store.SweepACMENonces(ctx, now); err != nil {
		slog.Warn("could not sweep expired ACME nonces", "error", err)
	} else if removed > 0 {
		slog.Debug("swept expired ACME nonces", "removed", removed)
	}

	agents, err := m.store.GetStaleAgents(ctx, now, batch)
	if err != nil {
		slog.Error("could not read the agent fleet; hosts that have gone quiet are not being reported", "error", err)
		return
	}
	if len(agents) == 0 {
		return
	}

	for _, agent := range agents {
		if err := m.store.MarkAgentStaleAlerted(ctx, agent.ID, now); err != nil {
			slog.Error("could not mark an agent as reported; not announcing it",
				"agent", agent.ID, "error", err)
			continue
		}
		m.announce(agent, now)
	}

	slog.Warn("agents have stopped reporting", "count", len(agents))
}

// announce publishes one quiet host.
//
// Once, and only once, until it comes back — RecordAgentHeartbeat clears the
// mark, so an agent that returns and disappears again is reported again. A
// message every minute for a decommissioned host is how a channel gets muted,
// and the channel it shares is the one carrying CA expiry alerts.
func (m *Monitor) announce(agent *store.Agent, now time.Time) {
	if m.broker == nil {
		return
	}

	last := "never — it has not reported since it enrolled"
	if agent.LastSeenAt != nil {
		last = agent.LastSeenAt.Format(time.RFC3339)
	}

	m.broker.Publish(events.Event{
		// WARNING rather than CRITICAL. Nothing has broken yet: the
		// certificates on that host are still valid and still being served.
		// What has broken is the thing that was going to replace them, and the
		// consequence arrives on whatever schedule they expire on — which is
		// serious, and is not an outage this minute.
		Topic:    events.TopicAgentStale,
		Severity: events.SeverityWarning,
		EntityID: agent.ID,
		Payload: map[string]any{
			"name":         agent.Name,
			"hostname":     agent.Hostname,
			"last_seen":    last,
			"missing_for":  humanFor(agent.MissingFor(now) + interval(agent)*store.AgentStaleAfter),
			"promised":     interval(agent).String(),
			"last_seen_ip": agent.LastSeenIP,
		},
	})
}

func interval(agent *store.Agent) time.Duration {
	d := time.Duration(agent.HeartbeatIntervalSeconds) * time.Second
	if d <= 0 {
		d = 5 * time.Minute
	}
	return d
}

// humanFor renders a duration the way somebody would say it out loud.
//
// Go's own formatting produces "437h12m9.4s", which is accurate and which
// nobody reads as "eighteen days".
func humanFor(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute")
	case d < 48*time.Hour:
		return plural(int(d.Hours()), "hour")
	default:
		return plural(int(d.Hours()/24), "day")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
