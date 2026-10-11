package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

func seedAgent(t *testing.T, st store.Store, name string, lastSeen time.Time) *store.Agent {
	t.Helper()
	agent := &store.Agent{
		Name:                     name,
		PublicKey:                "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----",
		KeyID:                    "abc123",
		Status:                   store.AgentActive,
		HeartbeatIntervalSeconds: 300,
		EnrolledAt:               lastSeen,
	}
	if err := st.CreateAgent(context.Background(), agent); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !lastSeen.IsZero() {
		if err := st.RecordAgentHeartbeat(context.Background(), agent.ID, store.AgentHeartbeat{
			SeenAt: lastSeen, SeenIP: "10.0.0.1", IntervalSeconds: 300,
		}); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
	}
	return agent
}

func drain(sub *events.Subscription) []events.Event {
	out := []events.Event{}
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case evt, ok := <-sub.Events():
			if !ok {
				return out
			}
			out = append(out, evt)
		case <-deadline:
			return out
		}
	}
}

// TestAQuietHostIsReportedOnceAndNotAgain. A message every minute for a
// decommissioned host is how a channel gets muted, and the channel it shares is
// the one carrying CA expiry alerts.
func TestAQuietHostIsReportedOnceAndNotAgain(t *testing.T) {
	st := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicAgentStale)
	defer sub.Close()

	// Promised every five minutes, last spoke an hour ago.
	seedAgent(t, st, "web-01", time.Now().Add(-time.Hour))
	m := NewMonitor(st, broker)

	m.RunSweep(context.Background())
	m.RunSweep(context.Background())
	m.RunSweep(context.Background())

	got := drain(sub)
	if len(got) != 1 {
		t.Fatalf("expected exactly one report, got %d", len(got))
	}
	payload, _ := got[0].Payload.(map[string]any)
	if payload["name"] != "web-01" {
		t.Fatalf("the report should name the host: %#v", payload)
	}
	// Named as the consequence: the duration is what somebody reads first.
	if missing, _ := payload["missing_for"].(string); !strings.Contains(missing, "hour") {
		t.Fatalf("missing_for should be readable, got %q", missing)
	}
}

// TestAnAgentReportingOnTimeIsNotReported.
func TestAnAgentReportingOnTimeIsNotReported(t *testing.T) {
	st := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicAgentStale)
	defer sub.Close()

	// Two intervals late is not missing: a restarted service, a slow network,
	// a busy host. Three is.
	seedAgent(t, st, "web-01", time.Now().Add(-10*time.Minute))
	NewMonitor(st, broker).RunSweep(context.Background())

	if got := drain(sub); len(got) != 0 {
		t.Fatalf("an agent two intervals late should not be reported, got %d", len(got))
	}
}

// TestAnAgentThatComesBackCanGoQuietAgain. Otherwise the first outage is the
// only one anybody ever hears about.
func TestAnAgentThatComesBackCanGoQuietAgain(t *testing.T) {
	st := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicAgentStale)
	defer sub.Close()

	agent := seedAgent(t, st, "web-01", time.Now().Add(-time.Hour))
	m := NewMonitor(st, broker)
	m.RunSweep(context.Background())

	// It comes back...
	if err := st.RecordAgentHeartbeat(context.Background(), agent.ID, store.AgentHeartbeat{
		SeenAt: time.Now(), IntervalSeconds: 300,
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	m.RunSweep(context.Background())

	// ...and goes away again.
	if err := st.RecordAgentHeartbeat(context.Background(), agent.ID, store.AgentHeartbeat{
		SeenAt: time.Now().Add(-2 * time.Hour), IntervalSeconds: 300,
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	m.RunSweep(context.Background())

	if got := drain(sub); len(got) != 2 {
		t.Fatalf("expected a report for each outage, got %d", len(got))
	}
}

// TestAnAgentThatNeverReportedIsMeasuredFromEnrolment, so one that failed on
// its very first heartbeat is as visible as one that stopped after a year.
func TestAnAgentThatNeverReportedIsMeasuredFromEnrolment(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	agent := &store.Agent{
		Name: "web-01", PublicKey: "x", KeyID: "y",
		Status: store.AgentActive, HeartbeatIntervalSeconds: 300,
		EnrolledAt: time.Now().Add(-time.Hour),
	}
	if err := st.CreateAgent(ctx, agent); err != nil {
		t.Fatalf("create: %v", err)
	}

	stale, err := st.GetStaleAgents(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("stale: %v", err)
	}
	if len(stale) != 1 {
		t.Fatalf("an agent that enrolled an hour ago and never reported is missing, got %d", len(stale))
	}
}

// TestARevokedAgentIsNotReportedAsMissing. It is not maintaining that host, and
// somebody already knows — the alert would be telling them what they did.
func TestARevokedAgentIsNotReportedAsMissing(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	agent := seedAgent(t, st, "web-01", time.Now().Add(-time.Hour))
	if err := st.RevokeAgent(ctx, agent.ID, nil); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	stale, err := st.GetStaleAgents(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("stale: %v", err)
	}
	if len(stale) != 0 {
		t.Fatalf("a revoked agent should not be reported as missing, got %d", len(stale))
	}
}

// A spent ACME nonce is kept only so that it cannot be spent twice, and it
// cannot be spent at all once it has expired. Nothing else deletes the rows, so
// the sweep that already runs for the agent replay guard does.
func TestExpiredACMENoncesAreSweptAndLiveOnesAreKept(t *testing.T) {
	st := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()
	ctx := context.Background()

	expired, live := []byte("expired-nonce-hash-0000000000000"), []byte("live-nonce-hash-0000000000000000")
	if ok, err := st.ClaimACMENonce(ctx, expired, time.Now().Add(-time.Minute)); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := st.ClaimACMENonce(ctx, live, time.Now().Add(time.Hour)); err != nil || !ok {
		t.Fatal(ok, err)
	}

	NewMonitor(st, broker).RunSweep(ctx)

	if ok, _ := st.ClaimACMENonce(ctx, expired, time.Now().Add(time.Hour)); !ok {
		t.Error("the expired nonce row was not swept")
	}
	if ok, _ := st.ClaimACMENonce(ctx, live, time.Now().Add(time.Hour)); ok {
		t.Error("a live nonce was swept, so it could be spent twice")
	}
}
