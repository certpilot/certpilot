package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentauth"
	"github.com/gin-gonic/gin"
)

// mintEnrolToken creates a token through the real admin API and returns the raw
// value, which is available only in that one response.
func mintEnrolToken(t *testing.T, r *gin.Engine, name string, maxUses int) (raw, id string) {
	t.Helper()
	w := do(r, http.MethodPost, "/api/v1/agent-enrol-tokens",
		gin.H{"name": name, "max_uses": maxUses}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint token: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
		Data  struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Token, resp.Data.ID
}

// enrolAgent runs a real enrolment, generating the key the way the agent binary
// does, and returns the identity.
func enrolAgent(t *testing.T, r *gin.Engine, token, name string) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := agentauth.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubPEM, err := agentauth.EncodePublicKey(pub)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	w := do(r, http.MethodPost, "/api/v1/agent/enrol", gin.H{
		"token": token, "public_key": pubPEM, "name": name,
		"hostname": name, "platform": "linux/amd64", "version": "0.1.0",
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("enrol: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.AgentID, priv
}

// signedPost makes the request an agent would make.
func signedPost(r *gin.Engine, agentID string, key ed25519.PrivateKey, path string, payload any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ts := time.Now().Unix()
	req.Header.Set(agentauth.AgentHeader, agentID)
	req.Header.Set(agentauth.TimestampHeader, fmt.Sprint(ts))
	req.Header.Set(agentauth.SignatureHeader, agentauth.Sign(key, http.MethodPost, path, ts, body))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestAnEnrolmentTokenIsSpentOnce is the property the whole bootstrap rests on.
func TestAnEnrolmentTokenIsSpentOnce(t *testing.T) {
	r, _ := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)

	enrolAgent(t, r, token, "web-01")

	pub, _, _ := agentauth.GenerateKey()
	pubPEM, _ := agentauth.EncodePublicKey(pub)
	w := do(r, http.MethodPost, "/api/v1/agent/enrol",
		gin.H{"token": token, "public_key": pubPEM, "name": "web-02"}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a spent token must be refused, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "already been used") {
		t.Fatalf("the refusal should say why: %s", w.Body.String())
	}
}

// TestAMalformedKeyDoesNotBurnTheToken. Otherwise a typo in a provisioning
// script leaves the operator holding a one-use token that has been spent on
// nothing.
func TestAMalformedKeyDoesNotBurnTheToken(t *testing.T) {
	r, _ := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)

	w := do(r, http.MethodPost, "/api/v1/agent/enrol",
		gin.H{"token": token, "public_key": "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// The token still works.
	enrolAgent(t, r, token, "web-01")
}

// TestOnlyASignedRequestIsAcceptedAsAnAgent walks the ways a caller might try
// to be one without holding the key.
func TestOnlyASignedRequestIsAcceptedAsAnAgent(t *testing.T) {
	r, _ := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 2)
	agentID, key := enrolAgent(t, r, token, "web-01")

	if w := signedPost(r, agentID, key, "/api/v1/agent/heartbeat", gin.H{"version": "0.1.0"}); w.Code != http.StatusOK {
		t.Fatalf("a properly signed heartbeat should be accepted, got %d: %s", w.Code, w.Body.String())
	}

	t.Run("no signature at all", func(t *testing.T) {
		w := do(r, http.MethodPost, "/api/v1/agent/heartbeat", gin.H{"version": "0.1.0"}, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("another agent's key", func(t *testing.T) {
		_, otherKey := enrolAgent(t, r, token, "web-02")
		w := signedPost(r, agentID, otherKey, "/api/v1/agent/heartbeat", gin.H{"version": "0.1.0"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("a body swapped after signing", func(t *testing.T) {
		body, _ := json.Marshal(gin.H{"version": "0.1.0"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat",
			bytes.NewReader([]byte(`{"version":"tampered"}`)))
		ts := time.Now().Unix()
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(agentauth.AgentHeader, agentID)
		req.Header.Set(agentauth.TimestampHeader, fmt.Sprint(ts))
		req.Header.Set(agentauth.SignatureHeader,
			agentauth.Sign(key, http.MethodPost, "/api/v1/agent/heartbeat", ts, body))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("a stale timestamp", func(t *testing.T) {
		body, _ := json.Marshal(gin.H{"version": "0.1.0"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", bytes.NewReader(body))
		ts := time.Now().Add(-time.Hour).Unix()
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(agentauth.AgentHeader, agentID)
		req.Header.Set(agentauth.TimestampHeader, fmt.Sprint(ts))
		req.Header.Set(agentauth.SignatureHeader,
			agentauth.Sign(key, http.MethodPost, "/api/v1/agent/heartbeat", ts, body))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	// Every refusal says the same thing. Which of the four checks failed goes
	// to the log, not to the caller.
	w := do(r, http.MethodPost, "/api/v1/agent/heartbeat", gin.H{}, nil)
	if !strings.Contains(w.Body.String(), "not accepted as coming from an enrolled agent") {
		t.Fatalf("the refusal should be uniform, got: %s", w.Body.String())
	}
}

// TestARevokedAgentStopsBeingOne, including the record of when it last spoke:
// a withdrawn credential still calling must not keep a host looking healthy.
func TestARevokedAgentStopsBeingOne(t *testing.T) {
	r, st := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)
	agentID, key := enrolAgent(t, r, token, "web-01")

	if w := signedPost(r, agentID, key, "/api/v1/agent/heartbeat", gin.H{}); w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
	}
	before, err := st.GetAgent(t.Context(), agentID)
	if err != nil || before.LastSeenAt == nil {
		t.Fatalf("the first heartbeat should have been recorded: %v", err)
	}

	if w := do(r, http.MethodPost, "/api/v1/agents/"+agentID+"/revoke", gin.H{}, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}

	// 403, not 401, and it says so — because this caller proved it holds the
	// key, so there is nothing left to withhold. The agent binary reads this
	// and stops, rather than knocking every few minutes for as long as the host
	// stays up. An earlier version checked status before the signature and
	// answered a flat 401, and the agent had no way to tell a withdrawn
	// credential from a misconfiguration.
	w := signedPost(r, agentID, key, "/api/v1/agent/heartbeat", gin.H{})
	if w.Code != http.StatusForbidden {
		t.Fatalf("a revoked agent should be told so, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "revoked") {
		t.Fatalf("the refusal should say why: %s", w.Body.String())
	}

	// But only to somebody holding the key. Without a valid signature a revoked
	// agent is indistinguishable from one that never existed, so this endpoint
	// cannot be used to enumerate the fleet.
	if w := do(r, http.MethodPost, "/api/v1/agent/heartbeat", gin.H{}, nil); w.Code != http.StatusUnauthorized ||
		strings.Contains(w.Body.String(), "revoked") {
		t.Fatalf("an unsigned probe must learn nothing, got %d: %s", w.Code, w.Body.String())
	}

	after, _ := st.GetAgent(t.Context(), agentID)
	if !after.LastSeenAt.Equal(*before.LastSeenAt) {
		t.Fatal("a revoked agent's calls must not move last_seen_at")
	}
}

// TestAnAgentIsRevokedBeforeItIsForgotten. Deleting the row would not withdraw
// the credential, and doing it first removes every record that it existed.
func TestAnAgentIsRevokedBeforeItIsForgotten(t *testing.T) {
	r, _ := realRouter(t)
	token, _ := mintEnrolToken(t, r, "rollout", 1)
	agentID, _ := enrolAgent(t, r, token, "web-01")

	w := do(r, http.MethodDelete, "/api/v1/agents/"+agentID, nil, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("deleting an active agent should be refused, got %d: %s", w.Code, w.Body.String())
	}

	do(r, http.MethodPost, "/api/v1/agents/"+agentID+"/revoke", gin.H{}, nil)
	if w := do(r, http.MethodDelete, "/api/v1/agents/"+agentID, nil, nil); w.Code != http.StatusOK {
		t.Fatalf("a revoked agent should be deletable, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTheFleetSummaryCountsWhatMatters — not how many agents are enrolled, but
// how many have stopped reporting.
func TestTheFleetSummaryCountsWhatMatters(t *testing.T) {
	cases := []struct {
		total, stale int64
		want         string
	}{
		{0, 0, "No agents are enrolled."},
		// The wording a live run corrected: this sentence is built from the
		// stale count, so it may only speak about staleness. An agent that
		// enrolled a minute ago has not reported, and claiming it is reporting
		// is the summary vouching for something nothing has observed.
		{4, 0, "4 agents, none of which have gone quiet."},
		{1, 0, "1 agent, and it has not gone quiet."},
		{4, 1, "1 has stopped reporting"},
		{4, 2, "2 have stopped reporting"},
	}
	for _, tc := range cases {
		got := summarizeAgents(tc.total, tc.stale)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("total=%d stale=%d: expected %q in %q", tc.total, tc.stale, tc.want, got)
		}
	}
}

// TestAnEnrolmentTokenCannotOutliveARollout.
func TestAnEnrolmentTokenCannotOutliveARollout(t *testing.T) {
	r, _ := realRouter(t)
	w := do(r, http.MethodPost, "/api/v1/agent-enrol-tokens",
		gin.H{"name": "forever", "expires_in_minutes": 60 * 24 * 400}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "at most") {
		t.Fatalf("the refusal should name the cap: %s", w.Body.String())
	}
}

// TestTheTokenIsShownOnceAndThenOnlyItsHashIsKept.
func TestTheTokenIsShownOnceAndThenOnlyItsHashIsKept(t *testing.T) {
	r, _ := realRouter(t)
	raw, id := mintEnrolToken(t, r, "rollout", 1)

	w := do(r, http.MethodGet, "/api/v1/agent-enrol-tokens", nil, nil)
	body := w.Body.String()
	if strings.Contains(body, raw) {
		t.Fatal("the raw token came back from the list")
	}
	if strings.Contains(body, "token_hash") {
		t.Fatalf("the hash should not be serialized either: %s", body)
	}
	if !strings.Contains(body, id) {
		t.Fatalf("the token record should be listed: %s", body)
	}
}

// TestTheFleetInventorySummaryAgrees.
//
// Assembling English agreement from fragments produces "2 certificate files
// has", which is exactly what this shipped doing and what the first live run
// read back.
func TestTheFleetInventorySummaryAgrees(t *testing.T) {
	cases := []struct {
		total  int64
		counts map[string]int64
		want   []string
	}{
		{0, nil, []string{"No host has reported"}},
		{7, map[string]int64{"private_key_readable": 2, "unmanaged": 6},
			[]string{"2 certificate files have private keys", "6 certificate files are not managed"}},
		{3, map[string]int64{"private_key_readable": 1, "unmanaged": 1},
			[]string{"1 certificate file has a private key", "1 certificate file is not managed"}},
		{4, map[string]int64{}, []string{"nothing to report about any of them"}},
	}

	for _, tc := range cases {
		got := summarizeHostCertificates(tc.total, tc.counts)
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Fatalf("expected %q in %q", want, got)
			}
		}
	}
}
