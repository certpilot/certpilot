package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
)

// InstallCycle brings this host's destinations into line and tells the core.
//
// Run every cycle, and deliberately not only after a renewal. The files a
// server reads are ordinary files that other things edit: a configuration
// management run replaces them, somebody restores a backup, an incident three
// weeks ago left a key at 0644. Checking every time costs a handful of reads
// and finds all of that; checking only after a renewal finds none of it.
//
// Nothing is written and nothing is reloaded unless the bytes actually differ,
// because an agent that reloaded nginx every five minutes because it could
// would be a worse problem than the stale certificate it was fixing.
func (r *Runner) InstallCycle(ctx context.Context, reachable bool) agentapi.InstallationReport {
	spec, err := LoadInstallSpec(r.specPath)
	if err != nil {
		// Reported rather than swallowed, and it does not stop the cycle. A
		// spec file with a typo in it must be visible in the core as a host
		// that is installing nothing, not as a host with nothing to install.
		slog.Error("this host's install destinations could not be read", "path", r.specPath, "error", err)
		report := agentapi.InstallationReport{
			ReportedAt: r.now().UTC(), SpecPath: r.specPath,
			Installations: []agentapi.Installation{}, Errors: []string{err.Error()},
		}
		if reachable {
			r.sendInstallations(ctx, report)
		}
		return report
	}
	if !spec.Found {
		if r.hadSpec && reachable {
			// Said once, so the core clears the destinations it used to show.
			// Going quiet instead would leave a page reporting certificates
			// installed at places nothing is keeping up to date any more.
			slog.Info("this host no longer declares anywhere to install a certificate",
				"spec", r.specPath)
			r.sendInstallations(ctx, agentapi.InstallationReport{
				ReportedAt: r.now().UTC(), SpecPath: r.specPath,
				Installations: []agentapi.Installation{},
			})
			r.hadSpec = false
		}
		return agentapi.InstallationReport{}
	}
	r.hadSpec = true

	// Anything the core has asked for. Only worth asking when this host has
	// somewhere to put a certificate — a host with no destinations can have no
	// bindings, so there is nothing that could ever be waiting.
	var assignments []agentapi.DeploymentAssignment
	if reachable && len(spec.Destinations) > 0 {
		assignments = r.claimDeployments(ctx)
	}

	force := map[string]bool{}
	for _, a := range assignments {
		for _, name := range r.destinationsFor(spec, a) {
			force[name] = true
		}
	}

	installer := NewInstaller(spec, r.specPath, r.HeldCertificates())
	report := installer.Apply(ctx, force)

	byName := map[string]*agentapi.Installation{}
	for i := range report.Installations {
		byName[report.Installations[i].Name] = &report.Installations[i]
	}
	for _, a := range assignments {
		for _, name := range r.destinationsFor(spec, a) {
			if inst, ok := byName[name]; ok {
				inst.JobID = a.JobID
			}
		}
	}

	if reachable {
		r.sendInstallations(ctx, report)
		for _, a := range assignments {
			r.reportResult(ctx, a, r.destinationsFor(spec, a), byName)
		}
	}
	return report
}

// destinationsFor works out which of this host's destinations an assignment
// covers.
//
// The core sends the names it was last told about, which is what a binding
// records. Falling back to matching on the certificate name covers the case
// where somebody renamed a destination between the last report and this claim
// — the certificate still needs installing, and refusing to do it because a
// label changed would be pedantry with an outage on the end of it.
func (r *Runner) destinationsFor(spec InstallSpec, a agentapi.DeploymentAssignment) []string {
	declared := map[string]bool{}
	for i := range spec.Destinations {
		declared[spec.Destinations[i].Name] = true
	}

	out := []string{}
	for _, name := range a.Destinations {
		if declared[name] {
			out = append(out, name)
		}
	}
	if len(out) > 0 {
		return out
	}
	want := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.CommonName), "."))
	for i := range spec.Destinations {
		if spec.Destinations[i].Certificate == want {
			out = append(out, spec.Destinations[i].Name)
		}
	}
	return out
}

// sendInstallations reports the full state of this host's destinations.
//
// Full state rather than a delta, exactly like the inventory report: a lost
// report costs nothing because the next one carries everything, and neither
// side has to keep a cursor the other could disagree with.
func (r *Runner) sendInstallations(ctx context.Context, report agentapi.InstallationReport) {
	if err := r.client.post(ctx, "/api/v1/agent/installations", report, nil); err != nil {
		slog.Warn("could not report what this host has installed", "error", err)
	}
}

// claimDeployments asks the core whether anything is waiting for this host.
//
// A POST rather than a GET because claiming takes a lease — the job moves to
// RUNNING and stops being offered to anything else. Calling that a read would
// make it the one place in this API where a GET changes something.
func (r *Runner) claimDeployments(ctx context.Context) []agentapi.DeploymentAssignment {
	var envelope struct {
		Data []agentapi.DeploymentAssignment `json:"data"`
	}
	if err := r.client.post(ctx, "/api/v1/agent/deployments/claim", map[string]any{}, &envelope); err != nil {
		slog.Warn("could not ask the core whether any deployments are waiting", "error", err)
		return nil
	}
	for _, a := range envelope.Data {
		slog.Info("the core has asked this host to install a certificate",
			"common_name", a.CommonName, "reason", a.Reason, "job", a.JobID)
	}
	return envelope.Data
}

// reportResult tells the core what happened to one job it handed out.
//
// Always sent, including for the case the core cannot work out for itself: a
// binding whose destination this host no longer declares. The alternative is a
// job that sits leased until it times out and is retried forever against a host
// that will never do it.
func (r *Runner) reportResult(ctx context.Context, a agentapi.DeploymentAssignment,
	names []string, byName map[string]*agentapi.Installation) {

	result := agentapi.DeploymentResult{JobID: a.JobID}
	switch {
	case len(names) == 0:
		result.Error = fmt.Sprintf(
			"this host declares no destination for %s, so there is nowhere here to install it", a.CommonName)
	default:
		var failed, done []string
		for _, name := range names {
			inst, ok := byName[name]
			if !ok {
				continue
			}
			if inst.Status == agentapi.InstallInstalled {
				done = append(done, name)
				continue
			}
			detail := inst.Error
			if detail == "" {
				detail = inst.Detail
			}
			failed = append(failed, fmt.Sprintf("%s: %s", name, detail))
		}
		if len(failed) > 0 {
			result.Error = strings.Join(failed, "; ")
		} else {
			result.Success = true
			result.Detail = fmt.Sprintf("installed at %s on %s",
				strings.Join(done, ", "), Hostname())
		}
	}

	if err := r.client.post(ctx, "/api/v1/agent/deployments/result", result, nil); err != nil {
		slog.Warn("could not report the outcome of a deployment", "job", a.JobID, "error", err)
	}
}

// ForceInstall rewrites and reloads every destination whether it needs it or
// not, and reports the result.
//
// Not something the cycle ever does. It is for the two moments when a person is
// at the keyboard: just after editing the spec file, and during an incident
// when what is on disk is not trusted. Everything else goes through
// InstallCycle, which writes nothing unless the bytes differ.
func (r *Runner) ForceInstall(ctx context.Context) agentapi.InstallationReport {
	spec, err := LoadInstallSpec(r.specPath)
	if err != nil {
		return agentapi.InstallationReport{
			ReportedAt: r.now().UTC(), SpecPath: r.specPath,
			Installations: []agentapi.Installation{}, Errors: []string{err.Error()},
		}
	}
	force := map[string]bool{}
	for i := range spec.Destinations {
		force[spec.Destinations[i].Name] = true
	}
	report := NewInstaller(spec, r.specPath, r.HeldCertificates()).Apply(ctx, force)
	r.sendInstallations(ctx, report)
	return report
}
