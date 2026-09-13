package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	"github.com/certpilot/certpilot/core/engine/fleet"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// agentLease is how long a job a host has claimed stays its own.
//
// Longer than the core queue's, because the round trip is different: a core
// worker claims a job and starts within milliseconds, while an agent claims one
// on a poll, writes files, runs a check and a reload, and only then reports.
// Long enough to cover all of that with room to spare; short enough that a host
// that dies mid-install releases the job the same afternoon rather than holding
// it until somebody notices.
const agentLease = 10 * time.Minute

// maxClaimPerPoll bounds how much of an estate one host takes on at once.
const maxClaimPerPoll = 10

// ReportInstallations handles POST /api/v1/agent/installations.
//
// The full state of every destination this host declares, in one message and on
// every cycle. Full state rather than a delta, exactly like the inventory: a
// lost report costs nothing because the next one carries everything, and
// neither side keeps a cursor the other could disagree with.
//
// Nothing in this body is an instruction. It says what the host was configured
// to do and what happened when it did it, including the commands it ran — which
// travel upwards for display and have no path back down. A core that could set
// a host's reload command would be a fleet-wide remote execution channel with a
// certificate manager on the front of it.
func (h *AgentHandler) ReportInstallations(c *gin.Context) {
	agentID := c.GetString(middleware.ContextAgentID)

	var report agentapi.InstallationReport
	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent, err := h.store.GetAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	result, err := h.installs.Record(c.Request.Context(), agent, report)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "agent.installations",
		EntityType: "agent",
		EntityID:   &agent.ID,
		Details: fmt.Sprintf(`{"name":%q,"destinations":%d,"installed":%d,"failed":%d,"unfulfilled":%d}`,
			agent.Name, result.Destinations, result.Installed, result.Failed, result.Unfulfilled),
	})

	c.JSON(http.StatusOK, gin.H{
		"data":        result,
		"summary":     summarizeInstallations(agent, result),
		"server_time": time.Now().UTC().Format(time.RFC3339),
	})
}

// ClaimDeployments handles POST /api/v1/agent/deployments/claim.
//
// The inversion that makes an agent a deployment target. Every other target
// type in this system is deployed to by a core worker opening a connection; a
// host behind two firewalls is deployed to by claiming the job itself. The
// queue, the lease, the retry curve and the attempt log are the same rows —
// only the worker moves.
//
// A POST rather than a GET because claiming takes a lease: the job goes to
// RUNNING and stops being offered. Calling that a read would make it the one
// place in this API where a GET changes something.
func (h *AgentHandler) ClaimDeployments(c *gin.Context) {
	agentID := c.GetString(middleware.ContextAgentID)

	agent, err := h.store.GetAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Scoped by the id the signature proved, never by anything in the body.
	// There is no field here a host could put another host's id in.
	jobs, err := h.store.ClaimAgentDeploymentJobs(c.Request.Context(), agent.ID,
		workerNameFor(agent), agentLease, time.Now(), maxClaimPerPoll)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	out := make([]agentapi.DeploymentAssignment, 0, len(jobs))
	for _, job := range jobs {
		assignment := agentapi.DeploymentAssignment{
			JobID:         job.ID,
			DeploymentID:  job.DeploymentID,
			CertificateID: job.CertificateID,
			Fingerprint:   job.Fingerprint,
			Reason:        job.Reason,
			NotAfter:      job.NotAfter,
		}
		if cert, err := h.store.GetCertificate(c.Request.Context(), job.CertificateID); err == nil {
			assignment.CommonName = cert.CommonName
		}
		// The destinations this host itself last reported. The core is handing
		// back the machine's own words, which is the only thing it knows about
		// the inside of that machine.
		if binding, err := h.store.GetCertificateDeployment(c.Request.Context(), job.DeploymentID); err == nil {
			assignment.Destinations = destinationNames(binding.Options)
		}
		out = append(out, assignment)
	}

	if len(out) > 0 {
		_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
			Action:     "agent.deployments_claimed",
			EntityType: "agent",
			EntityID:   &agent.ID,
			Details:    fmt.Sprintf(`{"name":%q,"jobs":%d}`, agent.Name, len(out)),
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// ReportDeploymentResult handles POST /api/v1/agent/deployments/result.
//
// Goes through the same completion path as a deployment this process ran
// itself: the same retry curve, the same escalation rule, the same attempt log.
// A separate copy written for the agent path would drift from the local one
// within a release, and the pacing is the part most likely to be subtly wrong
// and least likely to be noticed.
func (h *AgentHandler) ReportDeploymentResult(c *gin.Context) {
	agentID := c.GetString(middleware.ContextAgentID)

	var result agentapi.DeploymentResult
	if err := c.ShouldBindJSON(&result); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(result.JobID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a job id is required"})
		return
	}

	agent, err := h.store.GetAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	job, err := h.store.GetDeploymentJob(c.Request.Context(), result.JobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// The job has to belong to this host. Without this check a host holding a
	// valid credential could report success for another host's deployment — and
	// the binding would record a certificate as installed on a machine that had
	// never seen it, which is exactly the kind of confident wrong answer this
	// product exists not to give.
	target, err := h.store.GetDeploymentTarget(c.Request.Context(), job.TargetID)
	if err != nil || target.AgentID == nil || *target.AgentID != agent.ID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "this deployment does not belong to this host",
			"code":  "not_permitted",
		})
		return
	}

	var cause error
	if !result.Success {
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "the host reported a failure and did not say why"
		}
		cause = fmt.Errorf("%s", message)
	}

	if h.deployQueue == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "deployments are not running on this core"})
		return
	}
	// When the host claimed it, worked back from the lease this handler grants.
	// The lease length lives here, so the arithmetic does too.
	claimedAt := time.Now()
	if job.LockedUntil != nil {
		claimedAt = job.LockedUntil.Add(-agentLease)
	}
	if err := h.deployQueue.CompleteReported(c.Request.Context(), job,
		workerNameFor(agent), claimedAt, result.Detail, cause); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	action := "cert.deployed"
	if cause != nil {
		action = "cert.deploy_failed"
	}
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "certificate",
		EntityID:   &job.CertificateID,
		Details: fmt.Sprintf(`{"agent":%q,"target":%q,"target_type":"agent","job":%q,"success":%t,"detail":%q,"error":%q}`,
			agent.Name, target.Name, job.ID, result.Success, result.Detail, result.Error),
	})

	c.JSON(http.StatusOK, gin.H{"data": gin.H{"job_id": job.ID, "recorded": true}})
}

// ── For people ──────────────────────────────────────────────

// ListInstallations handles GET /api/v1/agent-installations.
//
// The default is everything; `?attention=true` is the query a central PKI team
// actually runs, and it returns the two rows nothing else in this system can
// produce — a destination that failed on the far side of every firewall, and a
// host configured to install a certificate that does not exist.
func (h *AgentHandler) ListInstallations(c *gin.Context) {
	filter := store.AgentInstallationFilter{
		AgentID:       c.Query("agent_id"),
		CertificateID: c.Query("certificate_id"),
		Status:        strings.ToUpper(strings.TrimSpace(c.Query("status"))),
		Limit:         100,
	}
	if c.Query("attention") == "true" {
		filter.NeedsAttention = true
	}
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 {
		filter.Limit = v
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v > 0 {
		filter.Offset = v
	}

	installs, total, err := h.store.ListAgentInstallations(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    installs,
		"total":   total,
		"summary": summarizeFleetInstallations(installs, total),
	})
}

// ── Words ───────────────────────────────────────────────────

// summarizeInstallations tells a host what its report amounted to, in the terms
// that matter to whoever is watching the agent's output during a rollout.
func summarizeInstallations(agent *store.Agent, result fleet.InstallResult) string {
	if result.Destinations == 0 {
		return fmt.Sprintf("%s declares nowhere to install a certificate.", agent.Name)
	}

	parts := []string{fmt.Sprintf("%d %s", result.Installed,
		pick(int64(result.Installed), "destination holds", "destinations hold"))}
	if result.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", result.Failed))
	}
	if result.Unfulfilled > 0 {
		parts = append(parts, fmt.Sprintf("%d %s configured for a certificate this host does not hold",
			result.Unfulfilled, pick(int64(result.Unfulfilled), "is", "are")))
	}
	return fmt.Sprintf("%s: %s.", agent.Name, strings.Join(parts, ", "))
}

// summarizeFleetInstallations says what the fleet's destinations amount to.
//
// The order of the clauses is the order somebody should act in, and the
// unfulfilled count is deliberately not folded into the failures. A destination
// that failed is loud; a destination configured for a certificate nobody
// granted is silent, and will stay silent right up until the renewal it is
// waiting for does not arrive.
func summarizeFleetInstallations(installs []*store.AgentInstallation, total int64) string {
	if total == 0 {
		return "No host is installing certificates through its agent yet."
	}

	failed, unfulfilled, hosts := 0, 0, map[string]bool{}
	for _, inst := range installs {
		hosts[inst.AgentID] = true
		switch inst.Status {
		case store.InstallFailed:
			failed++
		case store.InstallUnfulfilled:
			unfulfilled++
		}
	}

	where := fmt.Sprintf("%d %s across %d %s",
		total, pick(total, "destination", "destinations"),
		len(hosts), pick(int64(len(hosts)), "host", "hosts"))

	switch {
	case failed == 0 && unfulfilled == 0:
		return fmt.Sprintf("%s, all holding the certificate the host holds.", where)
	case failed > 0 && unfulfilled > 0:
		return fmt.Sprintf("%s. %d could not be installed, and %d %s configured for a certificate the host does not hold.",
			where, failed, unfulfilled, pick(int64(unfulfilled), "is", "are"))
	case failed > 0:
		return fmt.Sprintf("%s. %d could not be installed.", where, failed)
	default:
		return fmt.Sprintf("%s. %d %s configured for a certificate the host does not hold — nothing is failing, and nothing will happen when the renewal arrives.",
			where, unfulfilled, pick(int64(unfulfilled), "is", "are"))
	}
}

// destinationNames reads the destinations out of a binding's options.
func destinationNames(options map[string]any) []string {
	raw, ok := options["destinations"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// workerNameFor identifies the host in the attempt log.
//
// The hostname the agent reported, not a replica name. "Every failure came from
// one machine" and "every machine is failing" are the same two questions the
// core queue's worker name answers, asked of a fleet instead of a deployment.
func workerNameFor(agent *store.Agent) string {
	if strings.TrimSpace(agent.Hostname) != "" {
		return fmt.Sprintf("agent %s (%s)", agent.Name, agent.Hostname)
	}
	return "agent " + agent.Name
}
