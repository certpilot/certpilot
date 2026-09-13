package fleet

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// Inventory records what a host reported about itself.
//
// The parsing happens here rather than on the host, and that split is the whole
// reason the agent sends PEM. This code can be fixed by deploying the core; the
// agent cannot, because it is on five hundred machines that were last touched
// in March.
type Inventory struct {
	store  store.Store
	broker *events.Broker
	now    func() time.Time
}

// NewInventory creates the recorder. The broker may be nil.
func NewInventory(s store.Store, broker *events.Broker) *Inventory {
	return &Inventory{store: s, broker: broker, now: time.Now}
}

// Result is what one report amounted to.
type Result struct {
	Seen      int `json:"seen"`
	New       int `json:"new"`
	Unmanaged int `json:"unmanaged"`
	Removed   int `json:"removed"`
	// Unreadable is how many paths the agent could not open. Surfaced rather
	// than swallowed: an agent that cannot read /etc/pki reports the same empty
	// list as a host with nothing in it.
	Unreadable int  `json:"unreadable"`
	Truncated  bool `json:"truncated"`
}

// Record ingests one host's scan.
func (i *Inventory) Record(ctx context.Context, agent *store.Agent, report agentapi.InventoryReport) (Result, error) {
	now := i.now()
	configWorked := report.ConfigScanWorked()

	records := make([]*store.AgentCertificate, 0, len(report.Certificates))
	paths := make([]string, 0, len(report.Certificates))
	unmanaged := 0

	for _, found := range report.Certificates {
		record := i.build(ctx, agent, found, configWorked, now)
		records = append(records, record)
		paths = append(paths, record.Path)
		if record.ManagementState == store.DiscoveryUnmanaged && record.Kind == agentapi.KindLeaf {
			unmanaged++
		}
	}

	created, err := i.store.UpsertAgentCertificates(ctx, records)
	if err != nil {
		return Result{}, fmt.Errorf("could not record what %s reported: %w", agent.Name, err)
	}

	// Only after a report that arrived. Marking everything removed because an
	// agent failed to send would report a host being wiped.
	removed, err := i.store.MarkAgentCertificatesRemoved(ctx, agent.ID, paths, now)
	if err != nil {
		slog.Error("could not reconcile what a host no longer has",
			"agent", agent.ID, "error", err)
	}

	if err := i.store.MarkAgentInventoried(ctx, agent.ID, store.AgentInventorySummary{
		ScannedAt: now, Seen: len(records), Unmanaged: unmanaged,
	}); err != nil {
		slog.Error("could not record that a host was inventoried", "agent", agent.ID, "error", err)
	}

	i.announce(agent, records, created)

	return Result{
		Seen: len(records), New: len(created), Unmanaged: unmanaged,
		Removed: removed, Unreadable: len(report.Errors), Truncated: report.Truncated,
	}, nil
}

// build turns one reported file into a record, with its verdict and findings.
func (i *Inventory) build(ctx context.Context, agent *store.Agent, found agentapi.Discovered,
	configWorked bool, now time.Time) *store.AgentCertificate {

	record := &store.AgentCertificate{
		AgentID:              agent.ID,
		Path:                 found.Path,
		Kind:                 found.Kind,
		CertificateCount:     found.CertificateCount,
		FingerprintSHA256:    found.Fingerprint,
		CertificatePEM:       found.CertificatePEM,
		FileMode:             found.Mode,
		FileOwner:            found.Owner,
		PrivateKeyPath:       found.PrivateKeyPath,
		PrivateKeyMode:       found.PrivateKeyMode,
		PrivateKeyInSameFile: found.PrivateKeyInSameFile,
		PrivateKeyMatches:    found.PrivateKeyMatches,
		ReferencedBy:         found.ReferencedBy,
		ManagementState:      store.DiscoveryUnmanaged,
	}
	if !found.ModifiedAt.IsZero() {
		modified := found.ModifiedAt
		record.ModifiedAt = &modified
	}

	if info, err := x509util.ParseCertificatePEM([]byte(found.CertificatePEM)); err == nil {
		record.CommonName = info.CommonName
		record.SubjectDN = info.SubjectDN
		record.IssuerDN = info.IssuerDN
		record.SerialNumber = info.SerialNumber
		record.SANs = info.SANs
		record.KeyType = info.KeyType
		record.KeySize = info.KeySize
		notBefore, notAfter := info.NotBefore, info.NotAfter
		record.NotBefore, record.NotAfter = &notBefore, &notAfter
		if record.FingerprintSHA256 == "" {
			record.FingerprintSHA256 = info.FingerprintSHA256
		}
	}

	// The verdict, decided the same way it is everywhere else in this system:
	// on the SHA-256 fingerprint. Two certificates for one hostname are two
	// certificates, and only one of them is the one that expires.
	if record.FingerprintSHA256 != "" {
		if managed, err := i.store.GetCertificateByFingerprint(ctx, record.FingerprintSHA256); err == nil && managed != nil {
			record.ManagementState = store.DiscoveryManaged
			record.MatchedCertificateID = &managed.ID
		}
	}

	// And the sharper question: is this the certificate a renewal already
	// replaced? Only asked when the file is not the current one, because a file
	// holding the current certificate cannot also be superseded by it.
	var superseded *store.Certificate
	if record.ManagementState != store.DiscoveryManaged && record.FingerprintSHA256 != "" {
		if prior, err := i.store.GetCertificateBySupersededFingerprint(ctx, record.FingerprintSHA256); err == nil {
			superseded = prior
			if prior != nil {
				// Managed, because CertPilot demonstrably issued it. Calling it
				// unmanaged would file the most actionable row on the host
				// under "we have never seen this".
				record.ManagementState = store.DiscoveryManaged
				record.MatchedCertificateID = &prior.ID
			}
		}
	}

	record.Findings = assess(record, configWorked, superseded, now)
	return record
}

// announce publishes what is worth telling somebody about.
//
// Two rules. Exposed keys and mismatched pairs are announced for every host
// that has one, however long it has been there — a private key at mode 0644 is
// not less urgent for having been that way since 2021. Everything else is
// announced only for files that are new to this host, because a scan every six
// hours re-reporting the same forty certificates is how a channel gets muted.
func (i *Inventory) announce(agent *store.Agent, all, created []*store.AgentCertificate) {
	if i.broker == nil {
		return
	}

	newPaths := make(map[string]bool, len(created))
	for _, c := range created {
		newPaths[c.Path] = true
	}

	// Two topics, because they are two problems with different owners. An
	// exposed key is a security incident that needs the certificate reissued; a
	// mismatched pair is a service that will not come back after its next
	// restart. This first shipped as one message saying "one of these two
	// things", which makes the reader go and look — the work an alert exists to
	// save.
	if exposed := withFinding(all, FindingKeyReadable); len(exposed) > 0 {
		i.announceKeys(agent, exposed, events.TopicAgentKeyExposed, FindingKeyReadable)
	}
	if mismatched := withFinding(all, FindingKeyMismatch); len(mismatched) > 0 {
		i.announceKeys(agent, mismatched, events.TopicAgentKeyMismatch, FindingKeyMismatch)
	}

	unmanaged := []*store.AgentCertificate{}
	for _, c := range created {
		if newPaths[c.Path] && hasFinding(c.Findings, FindingUnmanaged) {
			unmanaged = append(unmanaged, c)
		}
	}
	if len(unmanaged) > 0 {
		i.announceUnmanaged(agent, unmanaged)
	}
}

func (i *Inventory) announceKeys(agent *store.Agent, certs []*store.AgentCertificate, topic, code string) {
	details := make([]string, 0, len(certs))
	for _, c := range certs {
		for _, f := range c.Findings {
			if f.Code == code {
				details = append(details, f.Detail)
			}
		}
	}

	i.broker.Publish(events.Event{
		Topic:    topic,
		Severity: events.SeverityCritical,
		EntityID: agent.ID,
		Payload: map[string]any{
			"agent":    agent.Name,
			"hostname": agent.Hostname,
			"count":    len(certs),
			"paths":    pathsOf(certs),
			"detail":   strings.Join(details, " "),
		},
	})
}

// withFinding selects the records carrying one finding code.
func withFinding(certs []*store.AgentCertificate, code string) []*store.AgentCertificate {
	out := []*store.AgentCertificate{}
	for _, c := range certs {
		if hasFinding(c.Findings, code) {
			out = append(out, c)
		}
	}
	return out
}

func (i *Inventory) announceUnmanaged(agent *store.Agent, found []*store.AgentCertificate) {
	i.broker.Publish(events.Event{
		Topic:    events.TopicAgentUnmanaged,
		Severity: events.SeverityWarning,
		EntityID: agent.ID,
		Payload: map[string]any{
			"agent":    agent.Name,
			"hostname": agent.Hostname,
			"count":    len(found),
			"paths":    pathsOf(found),
			"names":    namesOf(found),
		},
	})
}

func pathsOf(certs []*store.AgentCertificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.Path)
		if len(out) == 10 {
			break
		}
	}
	return out
}

func namesOf(certs []*store.AgentCertificate) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range certs {
		if c.CommonName == "" || seen[c.CommonName] {
			continue
		}
		seen[c.CommonName] = true
		out = append(out, c.CommonName)
		if len(out) == 10 {
			break
		}
	}
	return out
}

func hasFinding(findings []store.Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
