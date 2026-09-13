package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentauth"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/gin-gonic/gin"
)

// replayable builds one signed request and returns a function that sends that
// exact request as many times as a test asks. Re-signing would produce a new
// timestamp and a different signature, which is what an agent's own retry does
// and is precisely the case that must keep working.
func replayable(r *gin.Engine, agentID string, key ed25519.PrivateKey, path string, payload any) func() *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	ts := time.Now().Unix()
	signature := agentauth.Sign(key, http.MethodPost, path, ts, body)

	return func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(agentauth.AgentHeader, agentID)
		req.Header.Set(agentauth.TimestampHeader, fmt.Sprint(ts))
		req.Header.Set(agentauth.SignatureHeader, signature)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
}

// The endpoint the replay guard exists for. A request captured off the wire and
// sent again gets a second certificate signed for the same names — against the
// CA's rate limit, into the inventory, and for a public CA into the CT logs.
func TestAReplayedCertificateRequestIsRefused(t *testing.T) {
	r, _ := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)
	agentID, key := enrolAgent(t, r, token, "web-01")

	send := replayable(r, agentID, key, "/api/v1/agent/certificates", gin.H{
		"common_name": "app.example.test",
		"csr_pem":     "-----BEGIN CERTIFICATE REQUEST-----\nnot a real csr\n-----END CERTIFICATE REQUEST-----",
	})

	first := send()
	// The grant is missing, so this is refused on policy — which is fine and is
	// not the point. What matters is that the *second* attempt is refused for a
	// different reason, and that reason is replay.
	if first.Code == http.StatusUnauthorized {
		t.Fatalf("the first attempt must not be refused as a replay: %s", first.Body.String())
	}

	second := send()
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed certificate request = %d, want 401: %s", second.Code, second.Body.String())
	}
	if !contains(second.Body.String(), middleware.CodeAgentReplay) {
		t.Errorf("the refusal must say it was a replay, so an agent can tell it from a policy failure: %s",
			second.Body.String())
	}
}

// Claiming leases work. Replaying a claim takes it twice.
func TestAReplayedDeploymentClaimIsRefused(t *testing.T) {
	r, _ := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)
	agentID, key := enrolAgent(t, r, token, "web-01")

	send := replayable(r, agentID, key, "/api/v1/agent/deployments/claim", gin.H{"max": 1})
	if w := send(); w.Code == http.StatusUnauthorized {
		t.Fatalf("the first claim must not be refused as a replay: %s", w.Body.String())
	}
	if w := send(); w.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed claim = %d, want 401: %s", w.Code, w.Body.String())
	}
}

// The other half, and the reason the guard is not simply on everything.
//
// A signature covers a one-second timestamp, so an agent retrying a heartbeat
// after a network timeout re-sends bytes it already signed. Refusing that turns
// a recovered blip into a failure, and buys nothing: the report says the same
// thing twice.
func TestARepeatedReportIsNotRefused(t *testing.T) {
	r, _ := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)
	agentID, key := enrolAgent(t, r, token, "web-01")

	for _, path := range []string{
		"/api/v1/agent/heartbeat",
		"/api/v1/agent/inventory",
	} {
		send := replayable(r, agentID, key, path, gin.H{})
		if w := send(); w.Code != http.StatusOK {
			t.Fatalf("%s first = %d: %s", path, w.Code, w.Body.String())
		}
		if w := send(); w.Code == http.StatusUnauthorized {
			t.Errorf("%s must tolerate an identical retry, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}

// A revoked agent must be told it is revoked, whatever else is true of its
// request. Being told "you already sent this" leaves it retrying a withdrawn
// credential for as long as the host stays up — the ordering this asserts is
// the difference.
func TestARevokedAgentIsToldSoEvenOnAReplay(t *testing.T) {
	r, _ := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)
	agentID, key := enrolAgent(t, r, token, "web-01")

	send := replayable(r, agentID, key, "/api/v1/agent/certificates", gin.H{
		"common_name": "app.example.test",
	})
	send()

	if w := do(r, http.MethodPost, "/api/v1/agents/"+agentID+"/revoke", gin.H{}, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}

	w := send()
	if w.Code != http.StatusForbidden {
		t.Fatalf("a revoked agent replaying = %d, want 403: %s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), middleware.CodeAgentRevoked) {
		t.Errorf("the refusal must say the credential was revoked: %s", w.Body.String())
	}
}

// An unsigned request must never reach the replay table. If it could, anybody
// able to reach the endpoint could fill the disk with garbage — a replay
// defence turned into a denial of service.
func TestAnUnsignedRequestIsNotRecorded(t *testing.T) {
	r, st := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)
	agentID, key := enrolAgent(t, r, token, "web-01")

	body, _ := json.Marshal(gin.H{"common_name": "app.example.test"})
	ts := time.Now().Unix()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(agentauth.AgentHeader, agentID)
	req.Header.Set(agentauth.TimestampHeader, fmt.Sprint(ts))
	req.Header.Set(agentauth.SignatureHeader, "not-a-signature")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an unsigned request = %d, want 401", w.Code)
	}

	// Nothing was recorded, so a genuine request signing the same bytes still
	// works. Asked through the store rather than by inspection, because that is
	// the property that matters.
	digest := []byte("not-a-signature")
	fresh, err := st.ClaimAgentRequestSignature(t.Context(), agentID, digest, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Error("an unverified signature was recorded; anybody who can reach this endpoint could fill the table")
	}
	_ = key
}

// Rows must not accumulate. The table grows with every certificate request the
// fleet makes and nothing else deletes from it.
func TestExpiredReplayRowsAreSwept(t *testing.T) {
	_, st := realRouter(t)

	past := time.Now().Add(-time.Hour)
	if _, err := st.ClaimAgentRequestSignature(t.Context(), "some-agent", []byte("old"), past); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimAgentRequestSignature(t.Context(), "some-agent", []byte("current"),
		time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	removed, err := st.SweepAgentRequestSignatures(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("expected the expired row to be swept and the current one kept, removed %d", removed)
	}

	// The expired one is forgotten, which is correct: past its window the
	// timestamp check refuses the request on its own.
	fresh, err := st.ClaimAgentRequestSignature(t.Context(), "some-agent", []byte("old"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Error("a swept row was still remembered")
	}
}

// The exemption list is written by hand and the routes are written elsewhere.
// This is what stops the two drifting: a new agent route is guarded by default,
// and an exemption naming a route that no longer exists is a stale exemption
// somebody should look at.
func TestEveryReplayExemptionNamesARealRoute(t *testing.T) {
	r, _ := realRouter(t)

	registered := map[string]bool{}
	for _, route := range r.Routes() {
		registered[route.Path] = true
	}

	for path := range middleware.ReplayExemptPaths() {
		if !registered[path] {
			t.Errorf("%s is exempt from the replay guard but is not a route; the exemption is stale", path)
		}
	}
}
