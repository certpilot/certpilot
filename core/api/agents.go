package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	"github.com/certpilot/certpilot-agent-sdk/agentauth"
	"github.com/certpilot/certpilot/core/engine/deploy"
	"github.com/certpilot/certpilot/core/engine/fleet"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// Bounds on an enrolment token.
//
// Short by default and capped hard. An enrolment token is the credential handed
// to a machine that has never spoken to CertPilot, and it only has to survive
// the length of a provisioning run. One that outlives the rollout is a live
// credential sitting in whatever template it was pasted into.
const (
	defaultEnrolTokenMinutes = 60
	maxEnrolTokenMinutes     = 7 * 24 * 60
	maxEnrolTokenUses        = 500

	// defaultHeartbeatSeconds is what an agent reports at unless it says
	// otherwise. Five minutes: often enough that a dead host is noticed within
	// a quarter of an hour, rare enough that a thousand agents are twelve
	// requests a second between them.
	defaultHeartbeatSeconds = 300
	minHeartbeatSeconds     = 30
	maxHeartbeatSeconds     = 3600
)

// AgentHandler manages agents, the tokens that enrol them, and what they
// report about the hosts they run on.
type AgentHandler struct {
	store     store.Store
	broker    *events.Broker
	inventory *fleet.Inventory
	issuer    *fleet.Issuer
	installs  *fleet.Installs
	// deployQueue is here for one method: completing a job a host ran itself.
	// The agent path goes through the queue's own retry curve and escalation
	// rule rather than a second copy of them, because the pacing is the part
	// most likely to be subtly wrong and least likely to be noticed. Nil when
	// deployments are not running on this core, which the handler says.
	deployQueue *deploy.Queue
}

// NewAgentHandler creates the handler.
func NewAgentHandler(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring,
	broker *events.Broker, deployQueue *deploy.Queue, pe *policy.Engine) *AgentHandler {
	return &AgentHandler{
		store:       s,
		broker:      broker,
		inventory:   fleet.NewInventory(s, broker),
		issuer:      fleet.NewIssuer(s, pm, kr, broker, pe),
		installs:    fleet.NewInstalls(s, broker),
		deployQueue: deployQueue,
	}
}

// ── Management, for people ──────────────────────────────────

// ListAgents handles GET /api/v1/agents.
func (h *AgentHandler) ListAgents(c *gin.Context) {
	filter := store.AgentFilter{
		Status: strings.ToUpper(c.Query("status")),
		Limit:  100,
	}
	if c.Query("stale") == "true" {
		filter.StaleOnly = true
	}
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 500 {
		filter.Limit = v
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v >= 0 {
		filter.Offset = v
	}

	agents, total, err := h.store.ListAgents(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_, stale, err := h.store.ListAgents(c.Request.Context(),
		store.AgentFilter{Status: store.AgentActive, StaleOnly: true, Limit: 1})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    agents,
		"total":   total,
		"stale":   stale,
		"summary": summarizeAgents(total, stale),
	})
}

// summarizeAgents says what the fleet amounts to.
//
// The number that matters is not how many agents are enrolled. It is how many
// of them have stopped reporting — because those hosts still have certificates
// on them, still have them expiring, and now have nothing maintaining them,
// while looking exactly like healthy hosts on a list that only counts rows.
func summarizeAgents(total, stale int64) string {
	switch {
	case total == 0:
		return "No agents are enrolled."
	// "none have stopped reporting" rather than "all reporting", which is what
	// this first said. The number this sentence is built from is the stale
	// count, so it may only make claims about staleness: an agent that enrolled
	// a minute ago and has never said a word is not yet late, and reporting it
	// as reporting is the summary asserting something nothing has observed.
	case stale == 0 && total == 1:
		return "1 agent, and it has not gone quiet."
	case stale == 0:
		return fmt.Sprintf("%d agents, none of which have gone quiet.", total)
	case stale == 1:
		return fmt.Sprintf("%d agents, and 1 has stopped reporting. That host still has certificates on it and nothing is maintaining them.", total)
	default:
		return fmt.Sprintf("%d agents, and %d have stopped reporting. Those hosts still have certificates on them and nothing is maintaining them.", total, stale)
	}
}

// GetAgent handles GET /api/v1/agents/:id.
func (h *AgentHandler) GetAgent(c *gin.Context) {
	agent, err := h.store.GetAgent(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":    agent,
		"missing": missingText(agent, time.Now()),
	})
}

func missingText(agent *store.Agent, now time.Time) string {
	if agent.Status != store.AgentActive {
		return "This agent's credential has been revoked. It can no longer speak to CertPilot."
	}
	promised := time.Duration(agent.HeartbeatIntervalSeconds) * time.Second
	if agent.LastSeenAt == nil && agent.MissingFor(now) <= 0 {
		// Enrolled and not yet heard from. Said as its own state rather than
		// folded into "reporting as expected", which would be this record
		// vouching for something that has not happened.
		return fmt.Sprintf(
			"Enrolled at %s and has not reported yet. It promised every %s; if nothing arrives it will be flagged.",
			agent.EnrolledAt.Format(time.RFC3339), promised)
	}
	if over := agent.MissingFor(now); over > 0 {
		last := "since it enrolled"
		if agent.LastSeenAt != nil {
			last = "since " + agent.LastSeenAt.Format(time.RFC3339)
		}
		return fmt.Sprintf(
			"This agent has not reported %s. It promised every %s; whatever certificates are on that host are not being maintained.",
			last, promised)
	}
	return "Reporting as expected."
}

// RevokeAgent handles POST /api/v1/agents/:id/revoke.
//
// Revocation, not deletion. The record stays: an agent that had to be revoked
// is exactly the one somebody will want to read the history of afterwards.
func (h *AgentHandler) RevokeAgent(c *gin.Context) {
	agent, err := h.store.GetAgent(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	actor, _ := actorOf(c)
	if err := h.store.RevokeAgent(c.Request.Context(), agent.ID, actor); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent.revoked", agent.ID, fmt.Sprintf(`{"name":%q,"key_id":%q}`, agent.Name, agent.KeyID))

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf(
			"%s can no longer speak to CertPilot. Whatever certificates are on that host stay where they are and stop being maintained.",
			agent.Name),
	})
}

// DeleteAgent handles DELETE /api/v1/agents/:id.
//
// Refused while the agent is active. Deleting the row would not stop the
// credential — the agent would simply be an unknown id — but it would remove
// every record that it ever existed, which is the wrong order to do those two
// things in.
func (h *AgentHandler) DeleteAgent(c *gin.Context) {
	agent, err := h.store.GetAgent(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if agent.Status == store.AgentActive {
		c.JSON(http.StatusConflict, gin.H{
			"error": "revoke this agent before deleting it, so the credential is withdrawn before the record of it is",
		})
		return
	}
	if err := h.store.DeleteAgent(c.Request.Context(), agent.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent.deleted", agent.ID, fmt.Sprintf(`{"name":%q}`, agent.Name))
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Agent %q deleted.", agent.Name)})
}

// ── Enrolment tokens ────────────────────────────────────────

// ListEnrolTokens handles GET /api/v1/agent-enrol-tokens.
func (h *AgentHandler) ListEnrolTokens(c *gin.Context) {
	tokens, err := h.store.ListAgentEnrolTokens(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	views := make([]gin.H, 0, len(tokens))
	live := 0
	for _, t := range tokens {
		usable, why := t.Usable(now)
		if usable {
			live++
			why = "usable"
		}
		views = append(views, gin.H{"token": t, "state": why})
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  views,
		"total": len(views),
		// The count that matters: how many doors are open right now.
		"usable": live,
	})
}

type createEnrolTokenRequest struct {
	Name string `json:"name" binding:"required"`
	// ExpiresInMinutes defaults to 60 and is capped at a week.
	ExpiresInMinutes int `json:"expires_in_minutes"`
	// MaxUses defaults to 1.
	MaxUses int               `json:"max_uses"`
	Labels  map[string]string `json:"labels"`
}

// CreateEnrolToken handles POST /api/v1/agent-enrol-tokens.
//
// The raw token is returned exactly once, here. A credential the server can
// hand out again is a credential the server is storing.
func (h *AgentHandler) CreateEnrolToken(c *gin.Context) {
	var req createEnrolTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "a name is required — it is what identifies which rollout to revoke",
		})
		return
	}

	minutes := req.ExpiresInMinutes
	if minutes <= 0 {
		minutes = defaultEnrolTokenMinutes
	}
	if minutes > maxEnrolTokenMinutes {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"an enrolment token may live at most %d minutes (a week). It only has to survive a provisioning run, and one that outlives the rollout is a live credential in whatever template it was pasted into",
				maxEnrolTokenMinutes),
		})
		return
	}

	uses := req.MaxUses
	if uses <= 0 {
		uses = 1
	}
	if uses > maxEnrolTokenUses {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("max_uses may be at most %d", maxEnrolTokenUses),
		})
		return
	}

	raw, err := newEnrolToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actor, _ := actorOf(c)
	token := &store.AgentEnrolToken{
		Name:      req.Name,
		TokenHash: hashEnrolToken(raw),
		ExpiresAt: time.Now().Add(time.Duration(minutes) * time.Minute),
		MaxUses:   uses,
		Labels:    req.Labels,
		CreatedBy: actor,
	}
	if err := h.store.CreateAgentEnrolToken(c.Request.Context(), token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent_enrol_token.created", token.ID,
		fmt.Sprintf(`{"name":%q,"max_uses":%d,"expires_at":%q}`,
			token.Name, token.MaxUses, token.ExpiresAt.Format(time.RFC3339)))

	c.JSON(http.StatusCreated, gin.H{
		"data":  token,
		"token": raw,
		"message": fmt.Sprintf(
			"This token is shown once and cannot be recovered. It enrols %s and expires at %s.",
			usesText(uses), token.ExpiresAt.Format(time.RFC3339)),
	})
}

func usesText(n int) string {
	if n == 1 {
		return "one agent"
	}
	return fmt.Sprintf("up to %d agents", n)
}

// RevokeEnrolToken handles DELETE /api/v1/agent-enrol-tokens/:id.
func (h *AgentHandler) RevokeEnrolToken(c *gin.Context) {
	actor, _ := actorOf(c)
	if err := h.store.RevokeAgentEnrolToken(c.Request.Context(), c.Param("id"), actor); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent_enrol_token.revoked", c.Param("id"), `{}`)
	c.JSON(http.StatusOK, gin.H{
		"message": "Revoked. Agents already enrolled with it are unaffected — their credential is their own key, not this token.",
	})
}

// ── The agent's own endpoints ───────────────────────────────

type enrolRequest struct {
	Token string `json:"token" binding:"required"`
	// PublicKey is the agent's own, generated on its host. The private half is
	// not sent, not asked for, and has no field to arrive in.
	PublicKey string `json:"public_key" binding:"required"`

	Name                     string `json:"name"`
	Hostname                 string `json:"hostname"`
	Platform                 string `json:"platform"`
	Version                  string `json:"version"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
}

// Enrol handles POST /api/v1/agent/enrol.
//
// The only agent endpoint that is not signed, because the agent has no identity
// yet — this is the request that gives it one. It is authenticated by the
// enrolment token instead, which is why that token is one-use and short-lived.
func (h *AgentHandler) Enrol(c *gin.Context) {
	var req enrolRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The key is parsed before the token is spent. A malformed key would
	// otherwise consume a one-use token and leave the operator with nothing to
	// retry with.
	key, err := agentauth.ParsePublicKey(req.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("public_key must be a PEM Ed25519 public key: %v", err),
		})
		return
	}

	now := time.Now()
	token, err := h.store.GetAgentEnrolTokenByHash(c.Request.Context(), hashEnrolToken(req.Token))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if token == nil {
		// Nothing more specific for a token that does not exist. A holder of a
		// real token gets told why it failed below; a guesser gets one
		// sentence, and guessing a 256-bit token is not a strategy anyway.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "this enrolment token is not valid"})
		return
	}
	if usable, why := token.Usable(now); !usable {
		c.JSON(http.StatusUnauthorized, gin.H{"error": why})
		return
	}

	// Spent conditionally in the database. Two hosts booting from the same
	// image enrol in the same second, and a check followed by a write would let
	// a one-use token enrol both — which is the one property it exists to have.
	spent, err := h.store.ConsumeAgentEnrolToken(c.Request.Context(), token.ID, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !spent {
		c.JSON(http.StatusConflict, gin.H{
			"error": "this enrolment token was used up while this request was in flight",
		})
		return
	}

	interval := req.HeartbeatIntervalSeconds
	switch {
	case interval <= 0:
		interval = defaultHeartbeatSeconds
	case interval < minHeartbeatSeconds:
		interval = minHeartbeatSeconds
	case interval > maxHeartbeatSeconds:
		interval = maxHeartbeatSeconds
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(req.Hostname)
	}
	if name == "" {
		name = "unnamed agent"
	}

	agent := &store.Agent{
		Name:                     name,
		Hostname:                 strings.TrimSpace(req.Hostname),
		Platform:                 strings.TrimSpace(req.Platform),
		Version:                  strings.TrimSpace(req.Version),
		PublicKey:                req.PublicKey,
		KeyID:                    agentauth.KeyID(key),
		Status:                   store.AgentActive,
		Labels:                   token.Labels,
		EnrolTokenID:             &token.ID,
		EnrolledFrom:             c.ClientIP(),
		HeartbeatIntervalSeconds: interval,
	}
	if err := h.store.CreateAgent(c.Request.Context(), agent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "agent.enrolled",
		EntityType: "agent",
		EntityID:   &agent.ID,
		Details: fmt.Sprintf(`{"name":%q,"key_id":%q,"from":%q,"token":%q}`,
			agent.Name, agent.KeyID, agent.EnrolledFrom, token.Name),
	})

	if h.broker != nil {
		h.broker.Publish(events.Event{
			Topic:    events.TopicAgentEnrolled,
			Severity: events.SeverityInfo,
			EntityID: agent.ID,
			Payload: map[string]any{
				"name":     agent.Name,
				"hostname": agent.Hostname,
				"platform": agent.Platform,
				"key_id":   agent.KeyID,
				"from":     agent.EnrolledFrom,
				"token":    token.Name,
			},
		})
	}

	c.JSON(http.StatusCreated, gin.H{
		"agent_id":                   agent.ID,
		"name":                       agent.Name,
		"key_id":                     agent.KeyID,
		"heartbeat_interval_seconds": agent.HeartbeatIntervalSeconds,
		"server_time":                now.UTC().Format(time.RFC3339),
	})
}

type heartbeatRequest struct {
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Hostname        string `json:"hostname"`
	IntervalSeconds int    `json:"interval_seconds"`
}

// Heartbeat handles POST /api/v1/agent/heartbeat.
//
// Signed with the agent's own key, like everything an agent does after
// enrolment. The response carries the server's clock: drift is far and away the
// commonest reason a signature will not verify, and an agent that can see the
// difference can say so instead of reporting "unauthorized" forever.
func (h *AgentHandler) Heartbeat(c *gin.Context) {
	agentID := c.GetString(middleware.ContextAgentID)

	var req heartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	interval := req.IntervalSeconds
	if interval > 0 && interval < minHeartbeatSeconds {
		interval = minHeartbeatSeconds
	}
	if interval > maxHeartbeatSeconds {
		interval = maxHeartbeatSeconds
	}

	now := time.Now()
	if err := h.store.RecordAgentHeartbeat(c.Request.Context(), agentID, store.AgentHeartbeat{
		Version:         strings.TrimSpace(req.Version),
		Platform:        strings.TrimSpace(req.Platform),
		Hostname:        strings.TrimSpace(req.Hostname),
		IntervalSeconds: interval,
		SeenAt:          now,
		SeenIP:          c.ClientIP(),
	}); err != nil {
		// The middleware already checked the agent is active, so getting here
		// means it was revoked between then and now — which is exactly when a
		// revocation is most worth taking effect.
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agent_id":    agentID,
		"server_time": now.UTC().Format(time.RFC3339),
	})
}

// ── Helpers ─────────────────────────────────────────────────

// newEnrolToken mints 256 bits of randomness, base64url without padding.
func newEnrolToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("could not generate an enrolment token: %w", err)
	}
	return "cpe_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashEnrolToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func (h *AgentHandler) audit(c *gin.Context, action, entityID, details string) {
	actor, email := actorOf(c)
	entity := entityID
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "agent",
		EntityID:   &entity,
		ActorID:    actor,
		ActorEmail: email,
		Details:    details,
	})
}

// ── What the hosts are holding ──────────────────────────────

// Inventory handles POST /api/v1/agent/inventory.
//
// Signed with the agent's key, like everything after enrolment. The body is a
// list of certificates as PEM plus the facts only a process on the host can
// see — permissions, ownership, whether a matching key is beside it. There is
// no field a private key could arrive in.
func (h *AgentHandler) Inventory(c *gin.Context) {
	agentID := c.GetString(middleware.ContextAgentID)

	var report agentapi.InventoryReport
	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent, err := h.store.GetAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	result, err := h.inventory.Record(c.Request.Context(), agent, report)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "agent.inventory",
		EntityType: "agent",
		EntityID:   &agent.ID,
		Details: fmt.Sprintf(`{"name":%q,"seen":%d,"new":%d,"unmanaged":%d,"removed":%d}`,
			agent.Name, result.Seen, result.New, result.Unmanaged, result.Removed),
	})

	c.JSON(http.StatusOK, gin.H{"data": result, "server_time": time.Now().UTC().Format(time.RFC3339)})
}

// ListCertificates handles GET /api/v1/agent-certificates.
//
// Across the fleet by default, or one host with ?agent_id=. The filters that
// matter are the finding codes: `?finding=private_key_readable` is the query
// that produces the list nothing else in this system can produce.
func (h *AgentHandler) ListCertificates(c *gin.Context) {
	filter := store.AgentCertificateFilter{
		AgentID:         c.Query("agent_id"),
		ManagementState: strings.ToUpper(c.Query("state")),
		Kind:            strings.ToLower(c.Query("kind")),
		Finding:         c.Query("finding"),
		IncludeRemoved:  c.Query("include_removed") == "true",
		Limit:           100,
	}
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 500 {
		filter.Limit = v
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v >= 0 {
		filter.Offset = v
	}

	certs, total, err := h.store.ListAgentCertificates(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Counted in the database rather than over the page, so a summary is about
	// the estate and not about the first hundred rows of it.
	counts := map[string]int64{}
	for _, code := range []string{
		fleet.FindingKeyReadable, fleet.FindingKeyMismatch,
		fleet.FindingUnmanaged, fleet.FindingSuperseded, fleet.FindingExpired,
	} {
		scoped := filter
		scoped.Finding, scoped.Limit = code, 1
		if _, n, err := h.store.ListAgentCertificates(c.Request.Context(), scoped); err == nil {
			counts[code] = n
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     certs,
		"total":    total,
		"findings": counts,
		"summary":  summarizeHostCertificates(total, counts),
	})
}

// summarizeHostCertificates leads with the finding nothing else can make.
//
// Ordered by consequence rather than by count. An exposed private key is not
// something rotating the certificate fixes — the certificate has to be
// reissued — so it goes first however few there are, and an inventory number
// goes last however large it is.
func summarizeHostCertificates(total int64, counts map[string]int64) string {
	if total == 0 {
		return "No host has reported a certificate file yet."
	}

	parts := []string{}
	clause := func(code, one, many string) {
		if n := counts[code]; n > 0 {
			parts = append(parts, filesText(n)+" "+pick(n, one, many))
		}
	}
	clause(fleet.FindingKeyReadable,
		"has a private key other accounts on its host can read",
		"have private keys other accounts on their hosts can read")
	clause(fleet.FindingKeyMismatch,
		"has a key that does not match it, so the next restart of whatever serves it will fail",
		"have keys that do not match them, so the next restart of whatever serves them will fail")
	clause(fleet.FindingSuperseded,
		"still holds a certificate a renewal already replaced",
		"still hold certificates a renewal already replaced")
	clause(fleet.FindingExpired, "has expired", "have expired")
	clause(fleet.FindingUnmanaged,
		"is not managed by CertPilot", "are not managed by CertPilot")

	if len(parts) == 0 {
		return fmt.Sprintf("%s across the fleet, and nothing to report about any of them.", filesText(total))
	}
	return fmt.Sprintf("%s across the fleet. %s.", filesText(total),
		capitalise(strings.Join(parts, "; ")))
}

func filesText(n int64) string {
	if n == 1 {
		return "1 certificate file"
	}
	return fmt.Sprintf("%d certificate files", n)
}

// pick agrees the verb with the count.
//
// Written out rather than assembled, because every attempt to build English
// agreement from fragments produces "2 certificate files has", which is what
// this shipped doing and what a live run read back.
func pick(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// labelText renders a selector the way somebody would write it.
func labelText(labels map[string]string) string {
	if len(labels) == 0 {
		return "no labels"
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ", ")
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ── What a host may ask for ─────────────────────────────────

// ListGrants handles GET /api/v1/agent-grants.
func (h *AgentHandler) ListGrants(c *gin.Context) {
	grants, err := h.store.ListTemplateGrants(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	live := 0
	for _, g := range grants {
		if g.Live() {
			live++
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": grants, "total": len(grants), "live": live})
}

type grantRequest struct {
	Name string `json:"name" binding:"required"`

	// TemplateID is what this grant is permission for, by slug or by uuid.
	//
	// Everything a grant used to carry about the certificate itself —
	// ca_account_id, min_key_size, allowed_key_types, validity_days,
	// renew_before_days — lives on the template now. A second rulebook
	// reachable only by agents is how a host came to be able to obtain a
	// certificate the policy engine would have refused a person.
	TemplateID string `json:"template_id" binding:"required"`

	// SubjectKind defaults to AGENT, which is what every grant was.
	SubjectKind   string            `json:"subject_kind" binding:"omitempty,oneof=AGENT ROLE TEAM USER"`
	AgentID       string            `json:"agent_id"`
	LabelSelector map[string]string `json:"label_selector"`
	Role          string            `json:"role"`
	Team          string            `json:"team"`
	UserID        string            `json:"user_id"`

	Names []string `json:"names" binding:"required"`
}

// CreateGrant handles POST /api/v1/agent-grants.
//
// The one place an operator decides what a host may obtain from the
// organisation's CA. Every check here is about making that decision explicit
// rather than accidental.
func (h *AgentHandler) CreateGrant(c *gin.Context) {
	var req grantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	kind := req.SubjectKind
	if kind == "" {
		kind = store.GrantSubjectAgent
	}
	if err := grantNamesASubject(kind, req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	names := make([]string, 0, len(req.Names))
	for _, name := range req.Names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		// A grant permitting every name makes the agent credential equivalent
		// to the CA behind it. There is no way to write "I meant it" that is
		// better than listing the domains.
		if name == "*" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "a grant may not permit `*`. Any host holding it could obtain a certificate for any name your CA will sign — list the domains, or the wildcard beneath them",
			})
			return
		}
		if strings.Count(name, "*") > 1 || (strings.Contains(name, "*") && !strings.HasPrefix(name, "*.")) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("%q is not a name or a wildcard. Wildcards look like `*.example.com` and match one level", name),
			})
			return
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a grant needs at least one name"})
		return
	}

	// Resolved rather than trusted, and by slug as well as by id, because a
	// pipeline naming `internal-mtls` should not have to carry a uuid.
	template, err := h.resolveTemplate(c.Request.Context(), req.TemplateID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.AgentID != "" {
		if _, err := h.store.GetAgent(c.Request.Context(), req.AgentID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	grant := &store.TemplateGrant{
		Name:          strings.TrimSpace(req.Name),
		TemplateID:    template.ID,
		SubjectKind:   kind,
		LabelSelector: req.LabelSelector,
		Names:         names,
		IsEnabled:     true,
	}
	if req.AgentID != "" {
		grant.AgentID = &req.AgentID
	}
	if v := strings.TrimSpace(req.Role); v != "" {
		grant.Role = &v
	}
	if v := strings.TrimSpace(req.Team); v != "" {
		grant.Team = &v
	}
	if req.UserID != "" {
		grant.UserID = &req.UserID
	}

	actor, _ := actorOf(c)
	grant.CreatedBy = actor

	if err := h.store.CreateTemplateGrant(c.Request.Context(), grant); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent_grant.created", grant.ID, fmt.Sprintf(
		`{"name":%q,"names":%q,"agent_id":%q,"labels":%q}`,
		grant.Name, strings.Join(grant.Names, ","), req.AgentID, labelText(req.LabelSelector)))

	c.JSON(http.StatusCreated, gin.H{
		"data":    grant,
		"message": grantMessage(grant),
	})
}

// grantMessage says what was just permitted, in the terms it will be used in.
func grantMessage(grant *store.TemplateGrant) string {
	// Rendered rather than printed. Go's map formatting produced
	// "map[env:prod tier:web]" in a sentence meant for a person.
	who := "every agent labelled " + labelText(grant.LabelSelector)
	if grant.AgentID != nil {
		who = "one agent"
	}
	return fmt.Sprintf(
		"%s may now obtain certificates for %s, with keys generated on the host. CertPilot will never hold those private keys.",
		capitalise(who), strings.Join(grant.Names, ", "))
}

// RevokeGrant handles DELETE /api/v1/agent-grants/:id.
func (h *AgentHandler) RevokeGrant(c *gin.Context) {
	actor, _ := actorOf(c)
	if err := h.store.RevokeTemplateGrant(c.Request.Context(), c.Param("id"), actor); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent_grant.revoked", c.Param("id"), `{}`)
	c.JSON(http.StatusOK, gin.H{
		"message": "Revoked. Certificates already issued under it keep working until they expire; nothing will replace them.",
	})
}

// ── Issuance ────────────────────────────────────────────────

// RequestCertificate handles POST /api/v1/agent/certificates.
//
// The point of the whole agent. The key was generated on the host that will use
// it and has never left; what arrives here is a request. CertPilot signs it if
// an operator granted this host those names, and never holds a secret it could
// lose, copy, or be compelled to produce.
func (h *AgentHandler) RequestCertificate(c *gin.Context) {
	agentID := c.GetString(middleware.ContextAgentID)

	var req fleet.Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent, err := h.store.GetAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Bounded under the server's write timeout, like everything else that
	// reaches out during a request: an ACME order can take a while, and a
	// truncated response would leave the host unsure whether a certificate had
	// been issued in its name.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()

	issued, err := h.issuer.Issue(ctx, agent, req)
	if err != nil {
		// 403, not 400. The request was well-formed; it was not permitted, and
		// the two are different things for whoever is reading the agent's log.
		//
		// The code distinguishes this from the other 403 an agent can get — a
		// revoked credential — because the right response to each is the
		// opposite: fix the grant, or stop for good.
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error(), "code": "not_permitted"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": issued})
}

// grantNamesASubject refuses a grant that targets nothing.
//
// One that matched nothing would sit in the list looking like permission
// somebody had given, which is the same defect whichever kind of subject it
// claims to name. The schema enforces this too; refusing here means an operator
// gets a sentence rather than a constraint name.
func grantNamesASubject(kind string, req grantRequest) error {
	switch kind {
	case store.GrantSubjectAgent:
		if req.AgentID == "" && len(req.LabelSelector) == 0 {
			return fmt.Errorf(
				"an AGENT grant needs either agent_id or label_selector — one that targets " +
					"nothing would sit in the list looking like permission somebody had given")
		}
	case store.GrantSubjectRole:
		if strings.TrimSpace(req.Role) == "" {
			return fmt.Errorf("a ROLE grant needs a role")
		}
	case store.GrantSubjectTeam:
		if strings.TrimSpace(req.Team) == "" {
			return fmt.Errorf("a TEAM grant needs a team")
		}
	case store.GrantSubjectUser:
		if req.UserID == "" {
			return fmt.Errorf("a USER grant needs a user_id")
		}
	default:
		return fmt.Errorf("subject_kind %q is not one of AGENT, ROLE, TEAM, USER", kind)
	}
	return nil
}

// resolveTemplate accepts a slug or a uuid.
func (h *AgentHandler) resolveTemplate(ctx context.Context, ref string) (*store.CertificateTemplate, error) {
	if t, err := h.store.GetCertificateTemplate(ctx, ref); err == nil {
		return t, nil
	}
	t, err := h.store.GetCertificateTemplateBySlug(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("no certificate template named %q for this grant to permit", ref)
	}
	return t, nil
}
