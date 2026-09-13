// Package discovery finds certificates nobody told CertPilot about.
//
// The distinction that shapes this package: a scan of a real estate returns
// mostly certificates the PKI team issued itself and already watches. Those
// rows are noise. The output that justifies running a scan at all is the
// endpoint serving something the inventory has never seen — because nothing
// will renew it, nobody is watching it expire, and no one can say who put it
// there. So every result carries a verdict, and the verdict is what the list is
// sorted, filtered, and alerted on.
package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/posture"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

const (
	// DefaultPort is assumed when a target names no port.
	DefaultPort = 443
	// defaultDialTimeout bounds one endpoint. Short on purpose: a scan waits
	// for its slowest host, and an unreachable address is the common case in a
	// range that was guessed at rather than inventoried.
	defaultDialTimeout = 6 * time.Second
	// defaultConcurrency caps simultaneous handshakes. High enough that a scan
	// of a rack finishes while someone is still looking at the screen, low
	// enough not to look like a SYN flood to whatever sits in front of it.
	defaultConcurrency = 12
	// defaultBatchSize is how many results are written at once. Small enough
	// that a cancelled range scan keeps nearly everything it found, large
	// enough that the write is not the slow part of scanning.
	defaultBatchSize = 25
	// flushInterval bounds how long a result can sit unwritten. A range of
	// unreachable addresses trickles in, and a scan whose stored progress does
	// not move looks stuck rather than slow.
	flushInterval = 3 * time.Second
)

// Target is one endpoint to ask.
type Target struct {
	Host string
	Port int
}

// String renders the target the way it was addressed.
func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// ParseTarget reads "host", "host:port", or "[v6]:port".
//
// Rejects rather than guesses. A target that silently became something else —
// a stray scheme turning `https://example.com` into a hostname with slashes in
// it — produces a scan that reports an unreachable endpoint and looks like a
// finding about the estate rather than a mistake in the input.
func ParseTarget(raw string, defaultPort int) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if strings.Contains(raw, "://") {
		return Target{}, fmt.Errorf("target %q looks like a URL; give a host or host:port", raw)
	}
	if strings.ContainsAny(raw, "/ \t") {
		return Target{}, fmt.Errorf("target %q contains a path or whitespace; give a host or host:port", raw)
	}
	if defaultPort <= 0 {
		defaultPort = DefaultPort
	}

	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		// No port, or a bare IPv6 address. Both are addressable as-is.
		host, portStr = strings.Trim(raw, "[]"), ""
	}
	if host == "" {
		return Target{}, fmt.Errorf("target %q has no host", raw)
	}

	port := defaultPort
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("target %q has an invalid port", raw)
		}
	}
	return Target{Host: host, Port: port}, nil
}

// Scanner performs TLS handshakes and judges what comes back against the
// certificates and CAs CertPilot already knows about.
type Scanner struct {
	store       store.Store
	broker      *events.Broker
	dialTimeout time.Duration
	concurrency int
	batchSize   int
	now         func() time.Time

	// running holds the cancel function of every scan in flight, so a run
	// somebody started by mistake can be stopped without restarting the core.
	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// Option configures a Scanner.
type Option func(*Scanner)

// WithBroker publishes progress and completion to the event stream, so a scan
// of a range is visible while it runs rather than only once it is over.
func WithBroker(b *events.Broker) Option {
	return func(s *Scanner) { s.broker = b }
}

// WithConcurrency sets how many handshakes run at once.
func WithConcurrency(n int) Option {
	return func(s *Scanner) {
		if n > 0 {
			s.concurrency = n
		}
	}
}

// WithDialTimeout bounds one endpoint.
func WithDialTimeout(d time.Duration) Option {
	return func(s *Scanner) {
		if d > 0 {
			s.dialTimeout = d
		}
	}
}

// NewScanner creates a scanner backed by the inventory in the given store.
func NewScanner(s store.Store, opts ...Option) *Scanner {
	scanner := &Scanner{
		store:       s,
		dialTimeout: defaultDialTimeout,
		concurrency: defaultConcurrency,
		batchSize:   defaultBatchSize,
		now:         time.Now,
		running:     map[string]context.CancelFunc{},
	}
	for _, opt := range opts {
		opt(scanner)
	}
	return scanner
}

// Probe is the raw observation of one endpoint, before any judgement.
type Probe struct {
	Target    Target
	ScannedAt time.Time
	// Err is set when no TLS handshake completed. The dialler's own words are
	// kept verbatim: "connection refused" and "no route to host" say different
	// things about an estate, and a scan that flattened both to "failed" would
	// hide which.
	Err error
	// Chain is what the server sent, in the order it sent it. Element zero is
	// the leaf.
	Chain       []*x509.Certificate
	Version     uint16
	CipherSuite uint16
	// CurveID is the negotiated key exchange group. Zero for a legacy RSA key
	// exchange, which is itself a finding.
	CurveID tls.CurveID
	ALPN    string
	// OfferedHybrid records whether this probe offered a post-quantum group.
	// Without it, "the server did not negotiate one" is not a statement about
	// the server.
	OfferedHybrid bool
}

// Probe completes a TLS handshake and records everything it can about it.
//
// Verification is deliberately switched off here and done afterwards, in
// analyse. A scanner that refused to look at certificates it did not trust
// would be blind to exactly the endpoints worth finding: the expired ones, the
// self-signed appliance, the host chaining to a CA nobody registered.
func (s *Scanner) Probe(ctx context.Context, target Target) *Probe {
	probe := &Probe{Target: target, ScannedAt: s.now()}

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the point is to inspect untrusted certificates
		// SNI is a hostname. Sending an IP literal is not allowed and some
		// servers reject the handshake outright, so an IP target is asked
		// without it and gets whatever the default virtual host serves.
		ServerName: sniFor(target.Host),
		// Reach back to TLS 1.0 and offer the legacy suites. Not because they
		// are acceptable — because an appliance that only speaks them is
		// precisely what a discovery scan is for, and a scanner that could not
		// connect to it would report "unreachable" and leave it undiscovered.
		MinVersion:   tls.VersionTLS10,
		CipherSuites: allCipherSuites(),
		NextProtos:   []string{"h2", "http/1.1"},
		// Stated rather than inherited, and this is the line that makes the
		// post-quantum finding mean anything.
		//
		// "This endpoint did not negotiate a hybrid group" is a fact about the
		// server only if a hybrid group was offered. Go enables X25519MLKEM768
		// by default today, so leaving this unset would work — until a release
		// changed the default, at which point every endpoint in the estate
		// would quietly start reporting as classical and the report would be
		// about the scanner.
		CurvePreferences: offeredCurves(),
	}

	dialer := &net.Dialer{Timeout: s.dialTimeout}
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", target.String())
	if err != nil {
		probe.Err = err
		return probe
	}
	defer func() { _ = conn.Close() }()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		probe.Err = fmt.Errorf("the handshake completed but the server presented no certificate")
		return probe
	}

	probe.Chain = state.PeerCertificates
	probe.Version = state.Version
	probe.CipherSuite = state.CipherSuite
	probe.CurveID = state.CurveID
	probe.ALPN = state.NegotiatedProtocol
	probe.OfferedHybrid = offeredHybrid()
	return probe
}

// offeredCurves is what every probe offers, hybrid group first.
//
// The classical groups stay, and stay after it: a scanner that offered only
// post-quantum groups would fail to connect to almost everything, and an
// endpoint it could not reach is an endpoint it cannot report on.
func offeredCurves() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519MLKEM768,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
}

// offeredHybrid reports whether the list above contains a post-quantum group,
// so the recorded observation carries the fact its own meaning depends on.
func offeredHybrid() bool {
	for _, curve := range offeredCurves() {
		if IsHybridGroup(curve) {
			return true
		}
	}
	return false
}

// IsHybridGroup reports whether a negotiated group carries a post-quantum key
// encapsulation alongside a classical exchange.
//
// Matched by name rather than by a list of numbers, because the numbers are
// still moving: X25519MLKEM768 has had more than one codepoint during
// standardisation and will acquire siblings. A name containing MLKEM is the
// stable part.
func IsHybridGroup(curve tls.CurveID) bool {
	return strings.Contains(strings.ToUpper(curve.String()), "MLKEM")
}

// GroupName renders a negotiated group for a person.
//
// Go prints an unrecognised group as its number, which is the right thing for
// a report to carry: a group this build does not know the name of is exactly
// what somebody should go and look up.
func GroupName(curve tls.CurveID) string {
	if curve == 0 {
		return ""
	}
	return curve.String()
}

// VersionName renders a TLS version.
func VersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case 0:
		return ""
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// CipherName renders a negotiated cipher suite.
func CipherName(suite uint16) string {
	if suite == 0 {
		return ""
	}
	return tls.CipherSuiteName(suite)
}

// ScanRequest is one run.
type ScanRequest struct {
	// Targets are the endpoints that will be connected to, after expansion.
	Targets []Target
	// Specs are the entries as they were typed — "10.0.0.0/24" rather than the
	// 254 addresses it became.
	//
	// Recorded instead of the expansion, and not merely to save space: a scan
	// is repeated by re-running what someone asked for, and searched for by the
	// range they remember typing. Two hundred and fifty four addresses in a
	// scan record answer neither question.
	Specs []string
	// TriggeredBy and ActorEmail attribute the run. Scanning is an outbound
	// action against someone else's infrastructure, so it is attributable by
	// construction rather than by whoever remembers to write an audit entry.
	TriggeredBy *string
	ActorEmail  *string
}

// Scan probes every target, judges each result against the inventory, and
// records the run, returning once it has finished.
//
// The scan record is written before any probing starts. A run that crashes
// halfway then leaves evidence that it was attempted, rather than looking like
// a scan nobody ever ran — which on this dashboard reads as "nothing to find".
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) (*store.DiscoveryScan, []*store.DiscoveryResult, error) {
	scan, err := s.record(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := s.track(ctx, scan.ID)
	defer cancel()

	results := s.execute(ctx, scan, req.Targets)
	return scan, results, nil
}

// Start begins a scan in the background and returns as soon as it is recorded.
//
// For anything wider than a handful of endpoints this is the only workable
// shape: a /24 on three ports is over seven hundred handshakes, which no HTTP
// client is going to wait for and no proxy would keep open if it did.
//
// The run deliberately does **not** inherit the caller's context. An HTTP
// request's context is cancelled the moment its response is written, so a scan
// started from one would be killed by its own 202.
func (s *Scanner) Start(req ScanRequest) (*store.DiscoveryScan, error) {
	scan, err := s.record(context.Background(), req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.track(context.Background(), scan.ID)

	// The caller gets its own copy, taken before the run starts.
	//
	// `execute` mutates this record continuously as results arrive — counts,
	// status, completion — and the handler serialises what it is handed into a
	// 202. Returning the live pointer means encoding a struct while another
	// goroutine writes it, which the race detector found and which produces a
	// torn response in production rather than a wrong number in a test.
	snapshot := *scan

	go func() {
		defer cancel()
		s.execute(ctx, scan, req.Targets)
	}()

	return &snapshot, nil
}

// Cancel stops a running scan. Reports whether there was one to stop.
//
// What has already been found is kept. A scan someone stopped after twenty
// seconds still looked at whatever it reached, and throwing that away would
// make cancelling something you avoid doing.
func (s *Scanner) Cancel(id string) bool {
	s.mu.Lock()
	cancel, ok := s.running[id]
	s.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// Running lists the scans in flight, for diagnostics and shutdown.
func (s *Scanner) Running() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.running))
	for id := range s.running {
		ids = append(ids, id)
	}
	return ids
}

// Stop cancels every scan in flight. Called during shutdown so a long range
// scan does not hold the grace period open.
func (s *Scanner) Stop() {
	for _, id := range s.Running() {
		s.Cancel(id)
	}
}

// record writes the scan row before any probing starts.
func (s *Scanner) record(ctx context.Context, req ScanRequest) (*store.DiscoveryScan, error) {
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("a scan needs at least one target")
	}

	started := s.now()
	// Falls back to the expanded list only when no specs were given, which is
	// the case for a caller building targets directly rather than from input.
	specs := req.Specs
	if len(specs) == 0 {
		specs = make([]string, 0, len(req.Targets))
		for _, t := range req.Targets {
			specs = append(specs, t.String())
		}
	}

	scan := &store.DiscoveryScan{
		ScanType:    store.ScanTypeNetwork,
		Targets:     specs,
		TargetCount: len(req.Targets),
		Status:      store.ScanRunning,
		StartedAt:   &started,
		TriggeredBy: req.TriggeredBy,
		ActorEmail:  req.ActorEmail,
	}
	if err := s.store.CreateDiscoveryScan(ctx, scan); err != nil {
		return nil, fmt.Errorf("recording the scan: %w", err)
	}
	return scan, nil
}

func (s *Scanner) track(parent context.Context, id string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)

	s.mu.Lock()
	s.running[id] = cancel
	s.mu.Unlock()

	return ctx, func() {
		cancel()
		s.mu.Lock()
		delete(s.running, id)
		s.mu.Unlock()
	}
}

// execute runs the worker pool, storing results as they are found.
//
// Results are written in batches rather than all at the end. A scan of a range
// takes minutes, and a run that was cancelled, crashed, or restarted through
// would otherwise have nothing to show for the endpoints it did reach — which
// is the worst possible outcome for the one it found something on.
func (s *Scanner) execute(ctx context.Context, scan *store.DiscoveryScan, targets []Target) []*store.DiscoveryResult {
	// Trust anchors are loaded once per run, not once per endpoint. A failure
	// here is not fatal: without the managed CAs an internally-issued
	// certificate reads as UNTRUSTED, which overstates the problem, and that is
	// the safer direction to be wrong in.
	anchors, err := s.loadTrustAnchors(ctx)
	if err != nil {
		slog.Warn("could not load CA authorities as trust anchors; internally-issued certificates will read as untrusted",
			"error", err)
	}

	// What these endpoints were last seen serving, in one call rather than one
	// per endpoint. A repeated scan's value is the difference, and without this
	// every run reports the estate as if it had never been looked at before.
	baseline := s.loadBaseline(ctx, targets)

	results := make([]*store.DiscoveryResult, len(targets))
	completed := make(chan int, len(targets))
	jobs := make(chan int)

	workers := s.concurrency
	if workers > len(targets) {
		workers = len(targets)
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				probe := s.Probe(ctx, targets[i])
				// A probe cut short by cancellation learned nothing. Recording
				// it would put a row saying "this endpoint did not answer"
				// against a host that was never really asked — which is a
				// finding about the estate, invented by stopping the scan.
				if probe.Err != nil && errors.Is(probe.Err, context.Canceled) {
					completed <- -1
					continue
				}
				results[i] = s.judge(ctx, probe, anchors, baseline)
				completed <- i
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := range targets {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(completed)
	}()

	stored := make([]*store.DiscoveryResult, 0, len(targets))
	batch := make([]*store.DiscoveryResult, 0, s.batchSize)
	lastFlush := s.now()

	flush := func() {
		lastFlush = s.now()
		if len(batch) == 0 {
			return
		}
		// Detached from the run's context on purpose: a cancelled scan must
		// still persist what it already found, and writing with a cancelled
		// context would discard exactly that.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()

		if err := s.store.CreateDiscoveryResults(writeCtx, batch); err != nil {
			slog.Error("a batch of scan results could not be stored", "scan_id", scan.ID, "error", err)
			scan.Error = err.Error()
		} else {
			stored = append(stored, batch...)
		}
		batch = batch[:0]

		scan.ResultsCount = len(stored)
		if err := s.store.UpdateDiscoveryScan(writeCtx, scan); err != nil {
			slog.Warn("scan progress could not be recorded", "scan_id", scan.ID, "error", err)
		}
		s.publishProgress(scan, len(targets))
	}

	for i := range completed {
		if i < 0 {
			continue // a probe abandoned when the scan was cancelled
		}
		result := results[i]
		result.ScanID = scan.ID
		switch result.ManagementState {
		case store.DiscoveryUnreachable:
			scan.UnreachableCount++
		case store.DiscoveryManaged:
			scan.ManagedCount++
		default:
			scan.UnmanagedCount++
		}

		batch = append(batch, result)
		// Flushed on a clock as well as a count. A range of unreachable
		// addresses produces results slowly and in bursts, so waiting for a
		// full batch leaves a scan reading "0 of 254" for a minute — which is
		// indistinguishable from a scan that is stuck, and gets cancelled.
		if len(batch) >= s.batchSize || s.now().Sub(lastFlush) >= flushInterval {
			flush()
		}
	}
	flush()

	finished := s.now()
	scan.CompletedAt = &finished
	scan.ResultsCount = len(stored)
	switch {
	case scan.Error != "":
		scan.Status = store.ScanFailed
	case ctx.Err() != nil:
		// Cancelled is not failed. A scan somebody stopped on purpose reached
		// what it reached, and recording that as a failure would make the
		// history lie about which runs went wrong.
		scan.Status = store.ScanCancelled
		if scan.Error == "" {
			scan.Error = fmt.Sprintf("cancelled after %d of %d endpoints", len(stored), len(targets))
		}
	default:
		scan.Status = store.ScanCompleted
	}

	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.store.UpdateDiscoveryScan(writeCtx, scan); err != nil {
		slog.Warn("scan results stored but the scan record could not be updated", "scan_id", scan.ID, "error", err)
	}
	s.publishFinished(scan, stored)

	return stored
}

// publishProgress puts the running total on the event stream.
//
// Stream-only: progress is state, not news. A channel configured at INFO would
// otherwise receive a message every few seconds for the length of a range scan,
// which is how a team learns to mute the channel that also carries CA expiry.
func (s *Scanner) publishProgress(scan *store.DiscoveryScan, total int) {
	if s.broker == nil {
		return
	}
	s.broker.Publish(events.Event{
		Topic:    events.TopicDiscoveryProgress,
		Severity: events.SeverityInfo,
		EntityID: scan.ID,
		Payload: map[string]any{
			"scan_id":         scan.ID,
			"status":          scan.Status,
			"scanned_count":   scan.ResultsCount,
			"target_count":    total,
			"unmanaged_count": scan.UnmanagedCount,
			"managed_count":   scan.ManagedCount,
		},
	})
}

func (s *Scanner) publishFinished(scan *store.DiscoveryScan, results []*store.DiscoveryResult) {
	if s.broker == nil {
		return
	}
	s.broker.Publish(events.Event{
		Topic:    events.TopicDiscoveryProgress,
		Severity: events.SeverityInfo,
		EntityID: scan.ID,
		Payload: map[string]any{
			"scan_id":         scan.ID,
			"status":          scan.Status,
			"scanned_count":   scan.ResultsCount,
			"target_count":    scan.TargetCount,
			"unmanaged_count": scan.UnmanagedCount,
			"managed_count":   scan.ManagedCount,
			"finished":        true,
		},
	})

	// The findings, separate from the progress, and published by the scanner
	// rather than by the handler — a background run has to alert on what it
	// found long after the request that started it was answered.
	if scan.UnmanagedCount > 0 {
		s.broker.Publish(events.Event{
			Topic:    events.TopicDiscoveryUnmanaged,
			Severity: events.SeverityWarning,
			EntityID: scan.ID,
			Payload: map[string]any{
				"scan_id":         scan.ID,
				"unmanaged_count": scan.UnmanagedCount,
				"scanned_count":   scan.ResultsCount,
				"hosts":           hostsWithState(results, store.DiscoveryUnmanaged, 10),
			},
		})
	}

	// Changes are their own event, not a variation on "we found something".
	//
	// "There is an endpoint you do not manage" is a fact about an estate that
	// may have been true for years. "The certificate on it changed last night"
	// is a fact about somebody who is actively operating it, and it is only
	// visible on a repeated scan — which is the entire argument for scheduling
	// one.
	changed := hostsWithFinding(results, FindingCertificateChanged, events.SeverityWarning, 10)
	gone := hostsWithFinding(results, FindingEndpointDisappeared, events.SeverityWarning, 10)
	if len(changed) == 0 && len(gone) == 0 {
		return
	}
	s.broker.Publish(events.Event{
		Topic:    events.TopicDiscoveryChanged,
		Severity: events.SeverityWarning,
		EntityID: scan.ID,
		Payload: map[string]any{
			"scan_id":           scan.ID,
			"changed_count":     len(changed),
			"disappeared_count": len(gone),
			"changed_hosts":     changed,
			"disappeared_hosts": gone,
			"scanned_count":     scan.ResultsCount,
		},
	})
}

// hostsWithState names endpoints in a given management state, capped so an
// alert stays readable rather than carrying a thousand hostnames into Slack.
func hostsWithState(results []*store.DiscoveryResult, state string, max int) []string {
	hosts := make([]string, 0, max)
	for _, r := range results {
		if r.ManagementState != state {
			continue
		}
		hosts = append(hosts, fmt.Sprintf("%s:%d", r.Host, r.Port))
		if len(hosts) == max {
			break
		}
	}
	return hosts
}

// hostsWithFinding names endpoints carrying a finding at or above a severity.
func hostsWithFinding(results []*store.DiscoveryResult, code, severity string, max int) []string {
	hosts := make([]string, 0, max)
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Code == code && f.Severity == severity {
				hosts = append(hosts, fmt.Sprintf("%s:%d", r.Host, r.Port))
				break
			}
		}
		if len(hosts) == max {
			break
		}
	}
	return hosts
}

// judge turns a probe into a result: the verdicts, the findings, and the
// evidence for both.
func (s *Scanner) judge(ctx context.Context, probe *Probe, anchors *TrustAnchors, baseline map[string]*store.DiscoveryResult) *store.DiscoveryResult {
	result := &store.DiscoveryResult{
		Host:      probe.Target.Host,
		Port:      probe.Target.Port,
		ScannedAt: probe.ScannedAt,
		SANs:      []string{},
		Findings:  []store.Finding{},
	}

	if probe.Err != nil {
		result.Reachable = false
		result.Error = probe.Err.Error()
		result.ManagementState = store.DiscoveryUnreachable
		result.TrustState = store.TrustUnknown
		// An endpoint that used to answer and now does not is the one thing
		// worth saying about a failed probe, so reconciliation runs even here.
		result.Findings = append(result.Findings, reconcile(result, baseline[probe.Target.String()])...)
		return result
	}

	result.Reachable = true
	result.ChainLength = len(probe.Chain)
	result.TLSVersion = tlsVersionName(probe.Version)
	result.CipherSuite = tls.CipherSuiteName(probe.CipherSuite)
	result.KeyExchange = keyExchangeName(probe.CurveID)
	result.ALPN = probe.ALPN

	leaf := probe.Chain[0]
	info := x509util.CertInfoFromX509(leaf)
	result.CommonName = info.CommonName
	result.SubjectDN = info.SubjectDN
	result.IssuerDN = info.IssuerDN
	result.SerialNumber = info.SerialNumber
	result.KeyType = info.KeyType
	result.KeySize = info.KeySize
	result.IsCA = info.IsCA
	result.FingerprintSHA256 = info.FingerprintSHA256
	result.SANs = allNames(leaf)
	notBefore, notAfter := leaf.NotBefore, leaf.NotAfter
	result.NotBefore = &notBefore
	result.NotAfter = &notAfter
	result.CertificatePEM = encodePEM(probe.Chain[:1])
	if len(probe.Chain) > 1 {
		result.ChainPEM = encodePEM(probe.Chain[1:])
	}

	// The verdict that matters. Fingerprint equality, not name matching: two
	// certificates for the same hostname are two different certificates, and
	// the one being served is the one that expires.
	result.ManagementState = store.DiscoveryUnmanaged
	if managed, err := s.store.GetCertificateByFingerprint(ctx, result.FingerprintSHA256); err != nil {
		// Fail towards "unmanaged". Reporting a certificate we cannot check as
		// already handled is how a lookup failure becomes an outage nobody saw
		// coming.
		slog.Warn("could not check a discovered certificate against inventory; reporting it as unmanaged",
			"host", result.Host, "error", err)
		result.Findings = append(result.Findings, store.Finding{
			Code:     "inventory_lookup_failed",
			Severity: "WARNING",
			Detail:   "This certificate could not be checked against the managed inventory, so it is reported as unmanaged. The lookup failed: " + err.Error(),
		})
	} else if managed != nil {
		result.ManagementState = store.DiscoveryManaged
		id := managed.ID
		result.MatchedCertificateID = &id
	}

	trust, findings := analyse(probe, anchors, s.now())
	result.TrustState = trust
	result.Findings = append(result.Findings, findings...)
	result.Findings = append(result.Findings, reconcile(result, baseline[probe.Target.String()])...)

	// What this handshake actually negotiated, which is the one thing about
	// an estate's cryptography that no inventory can produce. Recorded here
	// because the connection has already been made; asking again later would
	// be a second scan of somebody else's infrastructure to learn something
	// this one already knew.
	s.recordPosture(ctx, probe, result)

	return result
}

// recordPosture stores what the handshake negotiated.
//
// Failure is logged and dropped rather than failing the scan. A scan exists to
// find certificates; losing a posture row costs one line in a report and the
// next scan writes it again, while failing the run would lose the certificates
// too.
func (s *Scanner) recordPosture(ctx context.Context, probe *Probe, result *store.DiscoveryResult) {
	supportsTLS13 := probe.Version == tls.VersionTLS13
	record := &store.EndpointTLSPosture{
		Host:              probe.Target.Host,
		Port:              probe.Target.Port,
		CertificateID:     result.MatchedCertificateID,
		TLSVersion:        VersionName(probe.Version),
		CipherSuite:       CipherName(probe.CipherSuite),
		KeyExchangeGroup:  GroupName(probe.CurveID),
		HybridKeyExchange: IsHybridGroup(probe.CurveID),
		OfferedHybrid:     probe.OfferedHybrid,
		SupportsTLS13:     &supportsTLS13,
		ALPN:              probe.ALPN,
		ObservedAt:        probe.ScannedAt,
	}
	if result.ScanID != "" {
		scanID := result.ScanID
		record.ScanID = &scanID
	}

	assessment := posture.Endpoint(record.TLSVersion, record.KeyExchangeGroup,
		record.HybridKeyExchange, record.OfferedHybrid)
	record.Verdict = assessment.Verdict
	record.Summary = assessment.Summary
	if requirements, err := json.Marshal(assessment.Requirements); err == nil {
		record.Requirements = requirements
	}

	if err := s.store.UpsertEndpointTLSPosture(ctx, record); err != nil {
		slog.Warn("could not record what a handshake negotiated",
			"host", record.Host, "port", record.Port, "error", err)
	}
}

// loadBaseline reads what each target was last seen serving.
//
// A failure is not fatal: without a baseline the run reports no changes, which
// understates rather than invents. Reporting a change that did not happen would
// send somebody hunting for a rotation nobody performed.
func (s *Scanner) loadBaseline(ctx context.Context, targets []Target) map[string]*store.DiscoveryResult {
	endpoints := make([]string, 0, len(targets))
	for _, t := range targets {
		endpoints = append(endpoints, t.String())
	}

	baseline, err := s.store.GetLatestDiscoveryResults(ctx, endpoints)
	if err != nil {
		slog.Warn("could not load previous scan results; this run will not report what changed", "error", err)
		return map[string]*store.DiscoveryResult{}
	}
	return baseline
}

// TrustAnchors is the set of CAs CertPilot manages, in the form x509
// verification wants.
type TrustAnchors struct {
	// Roots holds every managed CA, root or not.
	//
	// Putting an intermediate in the root pool looks wrong and is deliberate.
	// The question being answered is not "is this chain publicly valid" but
	// "does this endpoint's certificate come from a CA this organisation
	// watches", and an issuing CA registered in CertPilot answers that on its
	// own — whether or not someone also got round to registering the root above
	// it.
	Roots *x509.CertPool
	// Certs holds the same certificates as parsed values, because building an
	// intermediate pool needs them individually and a CertPool cannot be read
	// back out.
	Certs []*x509.Certificate
	// Names maps a subject DN to the CA's name in CertPilot, so a finding can
	// say "issued by Production Issuing CA G2" rather than repeating a DN.
	Names map[string]string
	count int
}

// Empty reports whether there is nothing to verify against.
func (a *TrustAnchors) Empty() bool { return a == nil || a.count == 0 }

func (s *Scanner) loadTrustAnchors(ctx context.Context) (*TrustAnchors, error) {
	anchors := &TrustAnchors{Roots: x509.NewCertPool(), Names: map[string]string{}}

	cas, err := s.store.ListCAAuthorities(ctx, store.CAFilter{IncludePEM: true})
	if err != nil {
		return anchors, err
	}
	for _, ca := range cas {
		if ca.CertificatePEM == "" {
			continue
		}
		block, _ := pem.Decode([]byte(ca.CertificatePEM))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Debug("a registered CA's certificate could not be parsed for trust checking", "ca", ca.Name, "error", err)
			continue
		}
		anchors.Roots.AddCert(cert)
		anchors.Certs = append(anchors.Certs, cert)
		anchors.Names[cert.Subject.String()] = ca.Name
		anchors.count++
	}
	return anchors, nil
}

// sniFor returns the SNI value for a host, which is empty for IP literals.
func sniFor(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// allNames returns every name in the certificate a scan might match a target
// against — DNS names and IP addresses, plus the common name when it is not
// already among them, because plenty of internal certificates still carry the
// hostname only there.
func allNames(cert *x509.Certificate) []string {
	names := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+1)
	seen := map[string]bool{}
	appendName := func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		names = append(names, n)
	}
	for _, n := range cert.DNSNames {
		appendName(n)
	}
	for _, ip := range cert.IPAddresses {
		appendName(ip.String())
	}
	appendName(cert.Subject.CommonName)
	return names
}

func encodePEM(certs []*x509.Certificate) string {
	var b strings.Builder
	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return b.String()
		}
	}
	return b.String()
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

// keyExchangeName names the negotiated group. A zero CurveID means a legacy RSA
// key exchange was used, which carries no forward secrecy at all — worth saying
// in words rather than leaving the column empty.
func keyExchangeName(id tls.CurveID) string {
	if id == 0 {
		return "RSA key transport (no forward secrecy)"
	}
	return id.String()
}

// allCipherSuites offers everything Go can speak, insecure suites included.
//
// Only the client's offer. What matters is what the server picked, and a server
// that picks 3DES has told us something we could not have learned by refusing to
// let it.
func allCipherSuites() []uint16 {
	suites := tls.CipherSuites()
	insecure := tls.InsecureCipherSuites()
	ids := make([]uint16, 0, len(suites)+len(insecure))
	for _, s := range suites {
		ids = append(ids, s.ID)
	}
	for _, s := range insecure {
		ids = append(ids, s.ID)
	}
	return ids
}
