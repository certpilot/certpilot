package fleet

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	"github.com/certpilot/certpilot/core/engine/deploy"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// Installs records where a host has put the certificates it holds.
//
// This is the step where an agent stops being something that watches a machine
// and becomes something that changes it, so the recording side is shaped by one
// question a central PKI team has to be able to answer without logging in:
// which places are holding the current certificate, which are not, and which
// have been configured to hold one that does not exist.
type Installs struct {
	store  store.Store
	broker *events.Broker
	now    func() time.Time
}

// NewInstalls creates the recorder. The broker may be nil.
func NewInstalls(s store.Store, broker *events.Broker) *Installs {
	return &Installs{store: s, broker: broker, now: time.Now}
}

// InstallResult is what one report amounted to.
type InstallResult struct {
	Destinations int `json:"destinations"`
	Installed    int `json:"installed"`
	Failed       int `json:"failed"`
	Unfulfilled  int `json:"unfulfilled"`
	// TargetID is the deployment target this host is, created on the first
	// report that declared anywhere to put a certificate.
	TargetID string `json:"target_id,omitempty"`
	// Bindings is how many certificate-to-place records this report touched.
	Bindings int `json:"bindings"`
}

// Record ingests one host's installation report.
func (in *Installs) Record(ctx context.Context, agent *store.Agent,
	report agentapi.InstallationReport) (InstallResult, error) {

	now := in.now()
	result := InstallResult{Destinations: len(report.Installations)}

	// What this host said last time, read before anything is written. Every
	// alert below is published on a transition rather than on a state, because
	// a host reports every few minutes and a destination that has been failing
	// since Tuesday must not send a message every cycle until somebody mutes
	// the channel — which is the same reasoning that made the inventory
	// announce only what was new to it.
	previous := in.previousState(ctx, agent.ID)

	records := make([]*store.AgentInstallation, 0, len(report.Installations))
	byCertificate := map[string][]agentapi.Installation{}
	unfulfilled := []agentapi.Installation{}

	for _, inst := range report.Installations {
		record := &store.AgentInstallation{
			AgentID:           agent.ID,
			Name:              inst.Name,
			CertificateName:   inst.Certificate,
			FingerprintSHA256: inst.Fingerprint,
			NotAfter:          inst.NotAfter,
			Paths:             inst.Paths,
			Status:            normalizeInstallStatus(inst.Status),
			Detail:            inst.Detail,
			Error:             inst.Error,
			RolledBack:        inst.RolledBack,
			InstalledAt:       inst.InstalledAt,
			ReloadedAt:        inst.ReloadedAt,
			ReloadCommand:     inst.ReloadCommand,
			CheckCommand:      inst.CheckCommand,
			ReportedAt:        now,
		}

		// The certificate id is checked rather than trusted. A host holds what
		// it was issued, and a certificate deleted centrally since then would
		// otherwise take the whole report down on a foreign key — losing the
		// nine destinations that were fine along with the one that was not.
		if inst.CertificateID != "" {
			if _, err := in.store.GetCertificate(ctx, inst.CertificateID); err == nil {
				id := inst.CertificateID
				record.CertificateID = &id
				byCertificate[id] = append(byCertificate[id], inst)
			} else {
				record.Detail = strings.TrimSpace(record.Detail + fmt.Sprintf(
					" (this host holds certificate %s, which CertPilot no longer has a record of)", inst.CertificateID))
			}
		}

		switch record.Status {
		case store.InstallInstalled:
			result.Installed++
		case store.InstallFailed:
			result.Failed++
		default:
			result.Unfulfilled++
			unfulfilled = append(unfulfilled, inst)
		}
		records = append(records, record)
	}

	// The target appears on the first report that declares somewhere to put a
	// certificate, and not before. A fleet of hosts that only report inventory
	// would otherwise fill the deployment target list with places nothing is
	// ever deployed to.
	var target *store.DeploymentTarget
	if len(records) > 0 {
		var err error
		target, err = in.store.EnsureAgentDeploymentTarget(ctx, agent)
		if err != nil {
			return result, fmt.Errorf("could not record %s as a place certificates go: %w", agent.Name, err)
		}
		result.TargetID = target.ID
	}

	if err := in.store.ReplaceAgentInstallations(ctx, agent.ID, records); err != nil {
		return result, fmt.Errorf("could not record what %s has installed: %w", agent.Name, err)
	}

	if target != nil {
		result.Bindings = in.reconcileBindings(ctx, agent, target, byCertificate, previous, now)
	}

	in.announceFailures(ctx, agent, report.Installations, previous)
	in.announceUnfulfilled(agent, unfulfilled, previous)

	for _, problem := range report.Errors {
		slog.Warn("a host could not read its own install destinations",
			"agent", agent.Name, "spec", report.SpecPath, "error", problem)
	}
	return result, nil
}

// reconcileBindings makes each certificate on this host a binding, so an agent
// reads as a deployment target like any other.
//
// One binding per certificate per host, with the destinations in its options. A
// certificate installed at two places on one machine is one deployment with two
// files, and it succeeds only if both did — the alternative is a binding that
// reports success while one of the two listeners is still on the old material.
func (in *Installs) reconcileBindings(ctx context.Context, agent *store.Agent,
	target *store.DeploymentTarget, byCertificate map[string][]agentapi.Installation,
	previous map[string]installState, now time.Time) int {

	// Full state, like everything else this host reports. An agent that renews
	// obtains a new certificate rather than replacing one in place, so without
	// this the binding for the certificate it replaced stays beside the new one
	// — and both say that place is holding the current certificate, which is
	// two confident sentences about one file where only one of them is true.
	keep := make([]string, 0, len(byCertificate))
	for certificateID := range byCertificate {
		keep = append(keep, certificateID)
	}
	if removed, err := in.store.PruneAgentBindings(ctx, target.ID, keep); err != nil {
		slog.Error("could not tidy up where a host used to install certificates",
			"agent", agent.Name, "target", target.ID, "error", err)
	} else if removed > 0 {
		slog.Info("a host is no longer installing a certificate it used to",
			"agent", agent.Name, "bindings_removed", removed)
	}

	count := 0
	for certificateID, installs := range byCertificate {
		names := make([]string, 0, len(installs))
		for _, inst := range installs {
			names = append(names, inst.Name)
		}
		sort.Strings(names)

		binding, err := in.store.EnsureCertificateDeployment(ctx, &store.CertificateDeployment{
			CertificateID: certificateID,
			TargetID:      target.ID,
			IsEnabled:     true,
			Options: map[string]any{
				"destinations": names,
				"installed_by": "agent",
			},
		})
		if err != nil {
			slog.Error("could not record where a host installed a certificate",
				"agent", agent.Name, "certificate", certificateID, "error", err)
			continue
		}
		count++

		outcome, changed := bindingOutcome(installs, previous, now)
		if !changed {
			// Nothing moved since the last report. Rewriting the outcome would
			// push `deployed_at` forward every few minutes, turning "when this
			// place took the certificate" into "when this host last spoke" —
			// two facts that look identical in a column and answer different
			// questions.
			continue
		}
		if err := in.store.RecordDeploymentOutcome(ctx, binding.ID, outcome); err != nil {
			slog.Error("could not record a host's installation outcome",
				"agent", agent.Name, "deployment", binding.ID, "error", err)
		}
		if err := in.store.MarkDeploymentTargetUsed(ctx, target.ID, now,
			outcome.Status == store.DeploymentDeployed, outcome.Error); err != nil {
			slog.Error("could not record that a host installed something",
				"agent", agent.Name, "target", target.ID, "error", err)
		}
		// The same loop the core's own deployments close. A host installing a
		// certificate is a deployment; whether the thing in front of the users
		// is serving it is still a separate question, and this brings the
		// answer forward from the half hour a renewal schedules.
		if outcome.Status == store.DeploymentDeployed {
			deploy.Settled(ctx, in.store, certificateID)
		}
	}
	return count
}

// bindingOutcome folds a certificate's destinations on one host into one
// outcome, and says whether anything actually moved since the last report.
func bindingOutcome(installs []agentapi.Installation, previous map[string]installState,
	now time.Time) (store.DeploymentOutcome, bool) {

	outcome := store.DeploymentOutcome{Status: store.DeploymentDeployed, At: now}
	problems := []string{}
	changed := false

	for _, inst := range installs {
		before, seen := previous[inst.Name]
		if !seen || before.status != normalizeInstallStatus(inst.Status) || before.fingerprint != inst.Fingerprint {
			changed = true
		}
		if normalizeInstallStatus(inst.Status) == store.InstallInstalled {
			outcome.Fingerprint = inst.Fingerprint
			continue
		}
		detail := inst.Error
		if detail == "" {
			detail = inst.Detail
		}
		problems = append(problems, fmt.Sprintf("%s: %s", inst.Name, detail))
	}

	if len(problems) > 0 {
		outcome.Status = store.DeploymentFailed
		outcome.Error = strings.Join(problems, "; ")
		// A fingerprint is written on success only, so a binding keeps saying
		// what that place is really holding rather than what failed to arrive.
		outcome.Fingerprint = ""
	}
	return outcome, changed
}

// ── What the previous report said ───────────────────────────

type installState struct {
	status      string
	fingerprint string
	err         string
}

func (in *Installs) previousState(ctx context.Context, agentID string) map[string]installState {
	out := map[string]installState{}
	existing, _, err := in.store.ListAgentInstallations(ctx, store.AgentInstallationFilter{
		AgentID: agentID, Limit: 500,
	})
	if err != nil {
		// An empty map means every problem in this report reads as new, which
		// is the safe direction to be wrong in: a duplicate alert costs
		// somebody a glance, and a suppressed one costs a listener.
		slog.Warn("could not read what a host previously reported installing",
			"agent", agentID, "error", err)
		return out
	}
	for _, inst := range existing {
		out[inst.Name] = installState{status: inst.Status, fingerprint: inst.FingerprintSHA256, err: inst.Error}
	}
	return out
}

// ── Announcements ───────────────────────────────────────────

// announceFailures publishes one event per destination that has just started
// failing, or whose failure has changed.
//
// Per destination rather than per host, because two destinations failing for
// two reasons are two problems: a check that refuses the certificate and a
// reload command that no longer exists have different owners and different
// fixes, and one message averaging them helps neither.
func (in *Installs) announceFailures(ctx context.Context, agent *store.Agent,
	installs []agentapi.Installation, previous map[string]installState) {

	for _, inst := range installs {
		if normalizeInstallStatus(inst.Status) != store.InstallFailed {
			if before, ok := previous[inst.Name]; ok && before.status == store.InstallFailed {
				slog.Info("a host that could not install a certificate now can",
					"agent", agent.Name, "destination", inst.Name)
			}
			continue
		}
		before, seen := previous[inst.Name]
		if seen && before.status == store.InstallFailed && before.err == inst.Error {
			continue
		}

		commonName := inst.Certificate
		if inst.CertificateID != "" {
			if cert, err := in.store.GetCertificate(ctx, inst.CertificateID); err == nil {
				commonName = cert.CommonName
			}
		}

		slog.Error("a host could not install a certificate where it is served",
			"agent", agent.Name, "destination", inst.Name, "certificate", commonName,
			"rolled_back", inst.RolledBack, "error", inst.Error)

		_ = in.store.CreateAuditLog(ctx, &store.AuditLog{
			Action:     "agent.install_failed",
			EntityType: "agent",
			EntityID:   &agent.ID,
			Details: fmt.Sprintf(`{"agent":%q,"destination":%q,"certificate":%q,"rolled_back":%t,"error":%q}`,
				agent.Name, inst.Name, commonName, inst.RolledBack, inst.Error),
		})

		if in.broker == nil {
			continue
		}
		// CRITICAL when the previous material could not be put back, because
		// that is the case where nobody knows what the listener is serving.
		severity := events.SeverityWarning
		if !inst.RolledBack {
			severity = events.SeverityCritical
		}
		in.broker.Publish(events.Event{
			Topic:    events.TopicAgentInstallFailed,
			Severity: severity,
			EntityID: agent.ID,
			Payload: map[string]any{
				"agent":       agent.Name,
				"hostname":    agent.Hostname,
				"destination": inst.Name,
				"common_name": commonName,
				"paths":       inst.Paths,
				"rolled_back": inst.RolledBack,
				"error":       inst.Error,
				"detail":      inst.Detail,
			},
		})
	}
}

// announceUnfulfilled publishes once per host for destinations declared for a
// certificate it does not hold.
//
// One event for the host rather than one per destination, unlike failures.
// These are almost always the same mistake made once — a name that does not
// match the grant — and three messages about three destinations would be three
// copies of one sentence.
func (in *Installs) announceUnfulfilled(agent *store.Agent,
	installs []agentapi.Installation, previous map[string]installState) {

	fresh := false
	names := []string{}
	destinations := []string{}
	for _, inst := range installs {
		if before, ok := previous[inst.Name]; !ok || before.status != store.InstallUnfulfilled {
			fresh = true
		}
		names = append(names, inst.Certificate)
		destinations = append(destinations, inst.Name)
	}
	if !fresh || len(names) == 0 {
		return
	}

	slog.Warn("a host is configured to install a certificate it does not hold",
		"agent", agent.Name, "names", names, "destinations", destinations)

	if in.broker == nil {
		return
	}
	in.broker.Publish(events.Event{
		Topic:    events.TopicAgentInstallUnfulfilled,
		Severity: events.SeverityWarning,
		EntityID: agent.ID,
		Payload: map[string]any{
			"agent":        agent.Name,
			"hostname":     agent.Hostname,
			"names":        names,
			"destinations": destinations,
		},
	})
}

// normalizeInstallStatus keeps an agent from writing a status the column will
// not take.
//
// An old agent talking to a new core is the ordinary case here, not the
// exception: this binary is on hosts nobody upgrades for years. An unknown
// status is recorded as unfulfilled, which reads as "this destination is not
// holding a certificate" — true of anything this core does not understand, and
// the direction that invites a look rather than assuming the best.
func normalizeInstallStatus(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case store.InstallInstalled:
		return store.InstallInstalled
	case store.InstallFailed:
		return store.InstallFailed
	default:
		return store.InstallUnfulfilled
	}
}
