// Package events provides an in-process publish/subscribe hub for changes the
// dashboard and the notification dispatcher both need to see.
//
// Producers — the CA health monitor, the renewal executor, the plugin manager —
// publish. Consumers subscribe. Nothing in the publish path can be blocked by a
// consumer, which is the whole point: a wall display on a flaky link, or a
// wedged Slack webhook, must never stall the CA health sweep. An expiring
// issuing CA is the failure this system exists to catch, and it cannot be
// allowed to go unnoticed because a screen in a corridor stopped reading.
//
// Delivery is therefore lossy by design. A subscriber that falls behind loses
// its oldest queued events and is flagged; it is expected to recover by
// re-fetching a snapshot rather than by receiving every intermediate step.
package events

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// Topics published by the core. Consumers may also subscribe to a prefix
// wildcard such as "ca.*".
const (
	TopicCAHealth      = "ca.health"
	TopicCAExpiryAlert = "ca.expiry_alert"
	// TopicCADiscovered carries a CA that has entered the inventory because a
	// gateway named it as one of its issuers, rather than because somebody
	// registered it.
	//
	// Worth an event of its own rather than folding into ca.health: a CA
	// appearing is a change in what is being monitored, and one that appears
	// already inside an expiry threshold is the most urgent thing this system
	// can find — nobody was watching it until this moment.
	TopicCADiscovered  = "ca.discovered"
	TopicCertIssued    = "cert.issued"
	TopicCertRenewed   = "cert.renewed"
	TopicCertRenewFail = "cert.renewal_failed"
	// TopicCertRenewedNonConforming carries a certificate that was renewed and
	// no longer satisfies the rules it is governed by.
	//
	// Distinct from a failure on purpose. The renewal worked; what did not is
	// the estate's compliance with a rule somebody has since tightened, and
	// renewal cannot fix every kind — a name outside a narrowed suffix list
	// cannot be dropped, because the endpoints serving it expect it.
	//
	// Refusing to renew would have been the alternative, and it is worse: an
	// expired certificate is a worse outcome than a non-conforming one, and a
	// sweep that turned a policy tightening into an outage is how people learn
	// to switch automation off.
	TopicCertRenewedNonConforming = "cert.renewed_nonconforming"
	// TopicCertRenewalWindowMoved carries the CA changing its mind about when
	// a certificate should be replaced.
	//
	// Routinely this is load spreading and not worth an alert. When a window is
	// pulled materially forward it is something else: a CA facing mass
	// revocation moves the affected windows into the past, and this is the only
	// automated warning anybody gets.
	TopicCertRenewalWindowMoved = "cert.renewal_window_moved"
	// TopicCertNotDeployed carries a renewal that succeeded and never reached
	// the server.
	//
	// Named as the consequence rather than as a failed check, because it is the
	// exact outage a renewal engine is supposed to prevent, arriving through
	// one: the inventory says ninety days remaining, the endpoint says twenty,
	// and the dashboard is green.
	TopicCertNotDeployed = "cert.not_deployed"
	// TopicCertDeployed carries a certificate that reached a target and was
	// accepted by it.
	//
	// Deliberately INFO, and deliberately not the same news as
	// TopicCertNotDeployed being absent. This says bytes were accepted by the
	// thing CertPilot talked to; whether the process in front of the users has
	// picked them up is a question only the verifier can answer, by opening a
	// connection and looking.
	TopicCertDeployed = "cert.deployed"
	// TopicCertDeployFailed carries a deployment that has stopped being a blip.
	//
	// Distinct from a renewal failure, because the fix is somewhere else and
	// usually belongs to somebody else: a renewal failure is between CertPilot
	// and a CA, a deployment failure is between CertPilot and a machine
	// somebody in the organisation operates.
	TopicCertDeployFailed = "cert.deploy_failed"
	TopicCertExpiring     = "cert.expiring"
	// TopicAgentEnrolled carries a new host joining the fleet.
	//
	// Worth an event even though it is routine, because the abnormal case looks
	// identical until somebody reads it: an agent enrolling from an address
	// nobody recognises, with a token issued for a different rollout, is the
	// shape of a stolen bootstrap credential being used.
	TopicAgentEnrolled = "agent.enrolled"
	// TopicAgentStale carries a host whose agent has stopped reporting.
	//
	// Named as the consequence rather than the observation. "Agent offline" is
	// a fact about a process; the fact that matters is that a machine still has
	// certificates on it, still has them expiring, and now has nothing
	// maintaining them — while looking exactly like a healthy host on any
	// screen that counts enrolled agents.
	TopicAgentStale = "agent.stale"
	// TopicAgentKeyExposed carries the finding no remote observer can make.
	//
	// A private key at mode 0644 means every account on that host holds the key
	// to that certificate, and rotating the certificate does not undo it — the
	// certificate has to be reissued. Nothing watching from the network can ever
	// see this; it takes one stat call from a process on the machine.
	TopicAgentKeyExposed = "agent.key_exposed"
	// TopicAgentKeyMismatch carries a certificate whose key does not belong to
	// it.
	//
	// Its own topic rather than a variant of the one above, because they are
	// different problems with different owners. An exposed key is a security
	// incident that needs the certificate reissued; a mismatched pair is a
	// service that will not come back after its next restart. A message saying
	// "one of these two things" makes the reader go and look, which is the work
	// an alert exists to save.
	TopicAgentKeyMismatch = "agent.key_mismatch"
	// TopicAgentUnmanaged carries a certificate found on a host that CertPilot
	// did not issue and is not tracking — the fourth place they hide, after
	// served, issued, and stored in a cloud.
	TopicAgentUnmanaged = "agent.unmanaged"
	// TopicAgentRequestRefused carries a host asking for a certificate it has
	// not been granted.
	//
	// Published rather than only logged, because the two things it can mean are
	// indistinguishable from inside the process: a misconfiguration somebody
	// needs to fix, or the first use of a credential taken off a host that has
	// been broken into. A person can tell those apart. Nothing here can.
	TopicAgentRequestRefused = "agent.request_refused"
	// TopicAgentInstallFailed carries a host that could not put a certificate
	// where the server reads it.
	//
	// The one deployment failure in this system that happened on the far side
	// of every firewall, reported by the only process that could see it. It
	// carries whether the previous material was put back, because a failed
	// install that rolled back is an inconvenience and one that did not is an
	// outage, and the difference has to survive into the message.
	TopicAgentInstallFailed = "agent.install_failed"
	// TopicAgentInstallUnfulfilled carries a host configured to install a
	// certificate it does not hold.
	//
	// Almost always one character wrong in a hostname, and invisible to
	// everything else: there is no binding, no certificate, and no failed
	// attempt — just a machine that will do nothing at all when the renewal it
	// is waiting for never arrives.
	TopicAgentInstallUnfulfilled = "agent.install_unfulfilled"
	TopicGatewayStatus           = "gateway.status"
	// TopicDiscoveryUnmanaged carries the one finding a discovery scan exists
	// to produce: an endpoint serving a certificate this system has never seen.
	// Published so it reaches the channels a team already configured, rather
	// than waiting to be noticed on a results page nobody has open.
	TopicDiscoveryUnmanaged = "discovery.unmanaged"
	// TopicDiscoveryChanged carries what a repeated scan found different: a
	// certificate rotated on an endpoint nobody manages, or an endpoint that
	// used to answer and no longer does.
	//
	// Distinct from TopicDiscoveryUnmanaged because the two mean different
	// things. "There is an endpoint you do not manage" may have been true for
	// years; "the certificate on it changed last night" is a fact about
	// somebody actively operating it, and it is only visible on a second scan.
	TopicDiscoveryChanged = "discovery.changed"
	// TopicCTUnmanaged carries a certificate that Certificate Transparency
	// reported for a watched domain and that nothing here issued.
	//
	// A stronger signal than its scanning equivalent. An unmanaged certificate
	// on an endpoint may be one somebody forgot to register; an unmanaged
	// certificate in CT is one that exists, is valid for your domain, and whose
	// private key is held by somebody who did not get it from this system.
	TopicCTUnmanaged = "ct.unmanaged"
	// TopicCloudUnmanaged carries a certificate found sitting in a cloud
	// store — ACM, a Key Vault, a GCP load balancer, a Kubernetes secret —
	// that this system did not put there and does not manage.
	TopicCloudUnmanaged = "cloud.unmanaged"
	// TopicCloudWillNotRenew carries the finding this part of discovery exists
	// for: the provider itself says nothing renews this certificate.
	//
	// A separate topic from the one above, because they are separate news. An
	// unmanaged certificate is an inventory gap. A certificate nothing renews
	// is a dated outage, and a team may reasonably want it routed somewhere
	// that wakes somebody up.
	TopicCloudWillNotRenew = "cloud.will_not_renew"
	// TopicDiscoveryProgress reports how far a running scan has got. Stream
	// only — see IsNotifiable.
	TopicDiscoveryProgress = "discovery.progress"
)

// streamOnlyTopics are published for dashboards and never delivered as alerts.
//
// The distinction is between news and state. A scan crossing its four hundredth
// endpoint is state: worth watching while it runs, worthless in an inbox. A
// channel left at INFO would receive one of these every few seconds for the
// length of a range scan, and a team that mutes that channel has also muted the
// CA expiry alerts that share it.
//
// Deliberately decided here rather than by every producer, and deliberately not
// by severity: an INFO event can still be news — a certificate was issued — and
// suppressing all of them would be a different, worse rule.
var streamOnlyTopics = map[string]bool{
	TopicDiscoveryProgress: true,
}

// IsNotifiable reports whether an event of this topic may be delivered to a
// notification channel.
func IsNotifiable(topic string) bool {
	return !streamOnlyTopics[topic]
}

// AllTopics lists every topic that can be delivered to a notification channel.
//
// Exists so the notification API can validate a channel's topic filter against
// something real. A typo'd topic would otherwise be accepted and produce a
// channel that matches nothing: configured on the dashboard, silent in practice,
// which is the failure alerting exists to prevent rather than introduce.
//
// Stream-only topics are absent by construction: offering a topic that can be
// selected and will never arrive is the same failure in a different disguise.
//
// Returns a copy — a caller sorting or appending to the package's own slice
// would change what every later caller sees.
func AllTopics() []string {
	return []string{
		TopicCAHealth,
		TopicCAExpiryAlert,
		TopicCertIssued,
		TopicCertRenewed,
		TopicCertRenewFail,
		TopicCertRenewalWindowMoved,
		TopicCertNotDeployed,
		TopicCertDeployed,
		TopicCertDeployFailed,
		TopicCertExpiring,
		TopicAgentEnrolled,
		TopicAgentStale,
		TopicAgentKeyExposed,
		TopicAgentKeyMismatch,
		TopicAgentUnmanaged,
		TopicAgentRequestRefused,
		TopicAgentInstallFailed,
		TopicAgentInstallUnfulfilled,
		TopicGatewayStatus,
		TopicDiscoveryUnmanaged,
		TopicDiscoveryChanged,
		TopicCTUnmanaged,
		TopicCloudUnmanaged,
		TopicCloudWillNotRenew,
	}
}

// Severity levels, matching the vocabulary used by the CA monitor and the
// frontend's severity module.
const (
	SeverityInfo     = "INFO"
	SeverityWarning  = "WARNING"
	SeverityCritical = "CRITICAL"
)

// Event is a single published change.
type Event struct {
	// ID is monotonic across the broker's lifetime. It is what an SSE client
	// echoes back as Last-Event-ID after a reconnect.
	ID uint64 `json:"id"`
	// Topic identifies what happened, e.g. "ca.expiry_alert".
	Topic string `json:"topic"`
	// Severity ranks how much attention it needs.
	Severity string `json:"severity"`
	// EntityID is the CA or certificate the event concerns, when applicable.
	EntityID string `json:"entity_id,omitempty"`
	// Payload carries topic-specific detail and must be JSON-serializable.
	Payload any `json:"payload,omitempty"`
	// Timestamp is when the event was published.
	Timestamp time.Time `json:"timestamp"`
}

// StringID renders the event ID for the SSE `id:` field.
func (e Event) StringID() string { return strconv.FormatUint(e.ID, 10) }

// defaultBuffer is how many events a subscriber may fall behind by before it
// starts losing the oldest. Large enough to absorb a health sweep across a
// few hundred CAs; small enough that a dead consumer cannot retain much.
const defaultBuffer = 256

// defaultHistory is how many recent events are retained for replay to a
// reconnecting client.
const defaultHistory = 512

// Broker fans events out to subscribers. It is safe for concurrent use.
type Broker struct {
	mu      sync.RWMutex
	subs    map[uint64]*Subscription
	nextSub uint64
	seq     uint64
	stopped bool

	// history is a ring of recent events, so a client that reconnects within
	// the window resumes rather than re-fetching everything.
	history    []Event
	historyCap int

	bufferSize int
}

// Option configures a Broker.
type Option func(*Broker)

// WithBufferSize sets how many events a single subscriber may queue.
func WithBufferSize(n int) Option {
	return func(b *Broker) {
		if n > 0 {
			b.bufferSize = n
		}
	}
}

// WithHistorySize sets how many recent events are retained for replay.
func WithHistorySize(n int) Option {
	return func(b *Broker) {
		if n >= 0 {
			b.historyCap = n
		}
	}
}

// NewBroker creates a broker.
func NewBroker(opts ...Option) *Broker {
	b := &Broker{
		subs:       make(map[uint64]*Subscription),
		bufferSize: defaultBuffer,
		historyCap: defaultHistory,
	}
	for _, opt := range opts {
		opt(b)
	}
	b.history = make([]Event, 0, b.historyCap)
	return b
}

// Subscription is one consumer's view of the stream.
type Subscription struct {
	id     uint64
	topics []string
	ch     chan Event
	broker *Broker

	// dropped counts events discarded because this subscriber fell behind.
	// Read with atomic semantics under the broker lock.
	dropped uint64
	closed  bool
}

// Events returns the channel to range over. It is closed when the subscription
// is closed or the broker stops, so a consumer can use `for evt := range`.
func (s *Subscription) Events() <-chan Event { return s.ch }

// Dropped reports how many events this subscriber has lost by falling behind.
func (s *Subscription) Dropped() uint64 {
	if s.broker == nil {
		return 0
	}
	s.broker.mu.RLock()
	defer s.broker.mu.RUnlock()
	return s.dropped
}

// Lossy reports whether this subscriber has missed anything. A consumer that
// sees true should re-fetch a full snapshot rather than assume its view is
// complete.
func (s *Subscription) Lossy() bool { return s.Dropped() > 0 }

// Close unsubscribes. It is safe to call more than once.
func (s *Subscription) Close() {
	b := s.broker
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true
	delete(b.subs, s.id)
	close(s.ch)
}

// Subscribe registers a consumer with the broker's default buffer.
//
// With no topics the subscriber receives everything. A topic ending in ".*"
// matches by prefix, so "ca.*" covers both ca.health and ca.expiry_alert.
func (b *Broker) Subscribe(topics ...string) *Subscription {
	return b.SubscribeWithBuffer(b.bufferSize, topics...)
}

// SubscribeWithBuffer registers a consumer with an explicit queue depth.
//
// Consumers have genuinely different tolerances: an SSE handler writing to a
// browser can absorb a burst and wants a deep queue, while a notification
// dispatcher making outbound HTTP calls is better off dropping intermediate
// states and reporting current reality than working through a backlog of
// alerts that have since been superseded.
func (b *Broker) SubscribeWithBuffer(buffer int, topics ...string) *Subscription {
	if b == nil {
		// A nil broker is a valid "events disabled" configuration. Hand back a
		// closed subscription so consumers terminate instead of hanging.
		ch := make(chan Event)
		close(ch)
		return &Subscription{ch: ch, closed: true}
	}
	if buffer <= 0 {
		buffer = b.bufferSize
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextSub++
	sub := &Subscription{
		id:     b.nextSub,
		topics: topics,
		ch:     make(chan Event, buffer),
		broker: b,
	}

	// A broker that has already stopped hands back a closed subscription
	// rather than one that will never deliver, so consumers terminate.
	if b.stopped {
		sub.closed = true
		close(sub.ch)
		return sub
	}

	b.subs[sub.id] = sub
	return sub
}

// Publish fans an event out to every matching subscriber.
//
// It never blocks. A subscriber whose buffer is full loses its oldest queued
// event to make room for this one: on a monitoring stream the newest state is
// what matters, and dropping the newest would mean a screen showing a CA as
// healthy after it had already gone critical.
// A nil broker discards events, so the broker can be an optional dependency
// and no producer needs a guard at its call site.
func (b *Broker) Publish(evt Event) {
	if b == nil {
		return
	}

	b.mu.Lock()

	if b.stopped {
		b.mu.Unlock()
		return
	}

	b.seq++
	evt.ID = b.seq
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}
	if evt.Severity == "" {
		evt.Severity = SeverityInfo
	}

	b.appendHistory(evt)

	targets := make([]*Subscription, 0, len(b.subs))
	for _, sub := range b.subs {
		if sub.matches(evt.Topic) {
			targets = append(targets, sub)
		}
	}

	// Sends happen under the write lock so a concurrent Close cannot close the
	// channel between the match and the send.
	for _, sub := range targets {
		select {
		case sub.ch <- evt:
		default:
			// Full. Discard the oldest, then retry once.
			select {
			case <-sub.ch:
				sub.dropped++
			default:
			}
			select {
			case sub.ch <- evt:
			default:
				sub.dropped++
			}
		}
	}

	b.mu.Unlock()
}

// PublishTopic is a convenience wrapper for the common case.
func (b *Broker) PublishTopic(topic, severity, entityID string, payload any) {
	b.Publish(Event{
		Topic:    topic,
		Severity: severity,
		EntityID: entityID,
		Payload:  payload,
	})
}

// appendHistory records an event in the replay ring. Caller holds the lock.
func (b *Broker) appendHistory(evt Event) {
	if b.historyCap == 0 {
		return
	}
	if len(b.history) < b.historyCap {
		b.history = append(b.history, evt)
		return
	}
	// Shift left by one. The ring is small and this runs under the publish
	// lock, so the copy is cheaper than the bookkeeping an index-based ring
	// would need everywhere else.
	copy(b.history, b.history[1:])
	b.history[len(b.history)-1] = evt
}

// Replay returns events published after afterID that match the given topics.
//
// The second return value reports whether the replay is complete. False means
// afterID predates the retained history, so the caller has missed events it
// cannot recover and should re-fetch a full snapshot instead.
func (b *Broker) Replay(afterID uint64, topics ...string) ([]Event, bool) {
	if b == nil {
		return nil, true
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.history) == 0 {
		// Nothing retained. Complete only if the caller is already current.
		return nil, afterID >= b.seq
	}

	// The caller's next expected event is afterID+1. If that already fell out
	// of the ring, the gap cannot be filled and the caller must resynchronise.
	complete := afterID+1 >= b.history[0].ID

	matcher := &Subscription{topics: topics}
	out := make([]Event, 0, len(b.history))
	for _, evt := range b.history {
		if evt.ID > afterID && matcher.matches(evt.Topic) {
			out = append(out, evt)
		}
	}
	return out, complete
}

// LastID reports the most recently assigned event ID.
func (b *Broker) LastID() uint64 {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.seq
}

// SubscriberCount reports how many consumers are attached, for diagnostics.
func (b *Broker) SubscriberCount() int {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Stop closes every subscription and rejects further publishing.
//
// It is idempotent, and must run before the HTTP server's own shutdown so that
// in-flight SSE handlers wake and return rather than holding the grace period
// open for its full duration.
func (b *Broker) Stop() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.stopped {
		return
	}
	b.stopped = true

	for id, sub := range b.subs {
		if !sub.closed {
			sub.closed = true
			close(sub.ch)
		}
		delete(b.subs, id)
	}
}

// matches reports whether a subscription wants a topic.
func (s *Subscription) matches(topic string) bool {
	if len(s.topics) == 0 {
		return true
	}
	for _, want := range s.topics {
		if want == topic {
			return true
		}
		if prefix, ok := strings.CutSuffix(want, "*"); ok && strings.HasPrefix(topic, prefix) {
			return true
		}
	}
	return false
}
