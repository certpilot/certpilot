package middleware

import (
	"bytes"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentauth"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// Context key set by AgentAuth.
const (
	// ContextAgentID identifies the agent that signed the request.
	//
	// Deliberately not ContextUserID and deliberately not accompanied by a
	// role. An agent is not a user with fewer permissions; it is a different
	// kind of caller entirely, and giving it a role would make it eligible for
	// every route that gates on one.
	ContextAgentID = "agent_id"
	// AuthMethodAgent is recorded on audit entries an agent caused.
	AuthMethodAgent = "agent"
	// CodeAgentRevoked marks the one 403 an agent must never retry.
	CodeAgentRevoked = "agent_revoked"
	// CodeAgentReplay marks a request the core has already seen. Distinct from
	// an ordinary 401 because the agent's response should be different: its own
	// retries sign afresh and never collide, so seeing this means something
	// else is re-sending its traffic.
	CodeAgentReplay = "agent_replay"
)

// maxAgentBody bounds a signed request.
//
// The body has to be buffered whole before the signature over its hash can be
// checked, so an unbounded one is a way to make the core allocate as much
// memory as an attacker likes before it has proved anything at all.
const maxAgentBody = 1 << 20

// AgentAuth authenticates a request signed by an agent's own key.
//
// This middleware is mounted only on the agent route group and never on the
// human API, and the human authenticator is never mounted here. The two kinds
// of caller are kept completely apart on purpose: an agent credential must not
// be usable to read the estate, and a person's bearer token must not be usable
// to speak as a host.
//
// Every refusal is a flat 401 with one sentence. The reason goes to the log,
// where an operator can see it, and not onto the wire, where it would tell a
// caller which of the four checks to work on next.
func AgentAuth(st store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		refuse := func(reason string, args ...any) {
			slog.Warn("refused an agent request: "+reason,
				append(args, "path", c.Request.URL.Path, "ip", c.ClientIP())...)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "this request was not accepted as coming from an enrolled agent",
			})
		}

		agentID := c.GetHeader(agentauth.AgentHeader)
		signature := c.GetHeader(agentauth.SignatureHeader)
		rawTS := c.GetHeader(agentauth.TimestampHeader)
		if agentID == "" || signature == "" || rawTS == "" {
			refuse("the signature headers were not all present")
			return
		}

		timestamp, err := strconv.ParseInt(rawTS, 10, 64)
		if err != nil {
			refuse("the timestamp header is not a number", "value", rawTS)
			return
		}

		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxAgentBody+1))
		if err != nil {
			refuse("the request body could not be read", "error", err)
			return
		}
		if len(body) > maxAgentBody {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body is too large",
			})
			return
		}
		// Put it back for the handler. The signature covers a hash of these
		// exact bytes, so the handler must decode the same ones — re-reading
		// from the network is not an option and re-encoding would be a
		// different body.
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		agent, err := st.GetAgent(c.Request.Context(), agentID)
		if err != nil {
			refuse("no such agent", "agent", agentID)
			return
		}

		key, err := agentauth.ParsePublicKey(agent.PublicKey)
		if err != nil {
			refuse("the stored public key could not be parsed", "agent", agentID, "error", err)
			return
		}

		// The signature is checked before the agent's status, and the order is
		// load-bearing in both directions.
		//
		// Checking status first would make a revoked agent distinguishable from
		// an unknown one to anybody who can guess an id, turning this endpoint
		// into a way to enumerate the fleet. Checking it second means the only
		// caller who ever learns "you were revoked" is the one holding the
		// private key — which is the agent itself, and precisely who needs to
		// be told, because otherwise it retries a withdrawn credential every
		// few minutes for as long as the host stays up.
		//
		// The path signed is the path requested, so a signature made for one
		// route cannot be replayed against another.
		if err := agentauth.Verify(key, c.Request.Method, c.Request.URL.Path,
			timestamp, signature, body, agentauth.DefaultTolerance); err != nil {
			refuse("the signature did not verify", "agent", agentID, "error", err)
			return
		}

		if agent.Status != store.AgentActive {
			// 403 rather than 401, and the one place this middleware says what
			// is actually wrong. The caller has proved it holds the key, so
			// there is nothing left to withhold from it: the agent binary reads
			// this and stops, instead of knocking every five minutes forever.
			slog.Info("a revoked agent is still calling",
				"agent", agentID, "revoked_at", agent.RevokedAt,
				"path", c.Request.URL.Path, "ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "this agent's credential has been revoked",
				// A machine-readable code, because 403 is the right status for
				// this *and* for "you may not have that certificate", and the
				// two call for opposite responses: stop for good, or report a
				// policy problem somebody can fix. An agent that could not tell
				// them apart shut itself down over a missing grant.
				"code": CodeAgentRevoked,
			})
			return
		}

		// Replay, last of all.
		//
		// After the signature, because writing a row before verifying one would
		// let anybody who can reach this endpoint fill the table with unsigned
		// garbage — a replay defence turned into a way to exhaust the disk.
		// After the status check, because a revoked agent must be told it is
		// revoked whatever else is true of its request; being told "you already
		// sent this" leaves it retrying a withdrawn credential for ever.
		//
		// The signature is the nonce. Ed25519 is deterministic, so two
		// identical requests carry identical signatures, and a signature covers
		// the method, path, timestamp and body it was made for. That is the
		// uniqueness a separate nonce header would have given, without a
		// protocol version every deployed agent would have to catch up with.
		if replayGuarded(c.Request.URL.Path) {
			digest := sha256.Sum256([]byte(signature))
			fresh, err := st.ClaimAgentRequestSignature(c.Request.Context(), agentID, digest[:],
				time.Unix(timestamp, 0).Add(agentauth.DefaultTolerance))
			if err != nil {
				// Fail closed. Being unable to tell a first request from a
				// replay is not a reason to assume the friendlier of the two on
				// the endpoint that issues certificates.
				slog.Error("could not check an agent request for replay; refusing it",
					"agent", agentID, "path", c.Request.URL.Path, "error", err)
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
					"error": "this request could not be checked against recent ones and was not accepted",
				})
				return
			}
			if !fresh {
				slog.Warn("refused a replayed agent request",
					"agent", agentID, "path", c.Request.URL.Path, "ip", c.ClientIP())
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "this request has already been made; it was not accepted a second time",
					"code":  CodeAgentReplay,
				})
				return
			}
		}

		c.Set(ContextAgentID, agent.ID)
		c.Set(ContextAuthMethod, AuthMethodAgent)
		c.Next()
	}
}

// AgentClock is what the core tells an agent about its own time.
//
// Returned on every accepted request, because clock drift is the single
// commonest cause of a signature that will not verify, and an agent that can
// see the difference can say so instead of reporting "unauthorized" forever.
func AgentClock() time.Time { return time.Now() }

// replayExempt lists the agent endpoints where refusing a repeat would be
// wrong, and everything not listed is guarded.
//
// The list is exemptions rather than opt-ins on purpose. An agent route added
// tomorrow is protected without anybody remembering to protect it, which is the
// only way this stays true — the same reasoning that keeps display tokens
// refused by default on everything but GET.
//
// Why exempt anything at all: a signature covers a one-second timestamp, so two
// genuinely distinct requests with identical bodies in the same second are
// byte-identical and the core cannot tell them apart. On a report that is the
// wrong answer — an agent retrying a heartbeat after a network timeout re-sends
// the request it already signed, and refusing it turns a recovered blip into a
// failure. On an endpoint that issues a certificate it is the right answer,
// because the cost of being wrong runs the other way: a second certificate
// against the CA's rate limit, into the inventory, and for a public CA into the
// CT logs.
var replayExempt = map[string]struct{}{
	// Idempotent reports. Replaying one re-states something already true.
	"/api/v1/agent/heartbeat":          {},
	"/api/v1/agent/inventory":          {},
	"/api/v1/agent/installations":      {},
	"/api/v1/agent/deployments/result": {},
}

func replayGuarded(path string) bool {
	_, exempt := replayExempt[path]
	return !exempt
}

// ReplayExemptPaths exposes the exemption list so a test can hold it against
// the routes that actually exist. Returns a copy: an exemption added at runtime
// would be an exemption nobody reviewed.
func ReplayExemptPaths() map[string]struct{} {
	out := make(map[string]struct{}, len(replayExempt))
	for path := range replayExempt {
		out[path] = struct{}{}
	}
	return out
}
