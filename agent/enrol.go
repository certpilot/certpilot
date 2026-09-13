package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentauth"
)

// EnrolOptions is what a person supplies when joining a host to CertPilot.
type EnrolOptions struct {
	Server    string
	Token     string
	Name      string
	StateDir  string
	Interval  time.Duration
	ScanPaths []string
}

// EnrolResult is what the core said.
type EnrolResult struct {
	AgentID                  string `json:"agent_id"`
	Name                     string `json:"name"`
	KeyID                    string `json:"key_id"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	ServerTime               string `json:"server_time"`
}

// Enrol joins this host to a CertPilot core.
//
// The keypair is generated here, on this machine, before anything is sent. Only
// the public half is transmitted, and there is no field in the request for the
// private one — not as a precaution but as the architecture: this is the first
// key CertPilot never sees, and the certificate keys that follow work the same
// way.
//
// Refuses to overwrite an existing identity. Re-enrolling silently would leave
// the old agent's record on the core with a key nothing holds any more —
// present in the fleet list, apparently healthy, reporting nothing, which is
// precisely the state the fleet monitor exists to make visible.
func Enrol(ctx context.Context, opts EnrolOptions) (*EnrolResult, error) {
	if strings.TrimSpace(opts.Server) == "" {
		return nil, fmt.Errorf("--server is required: the CertPilot core this host should report to")
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, fmt.Errorf("--token is required: an enrolment token from `POST /api/v1/agent-enrol-tokens`")
	}
	if Enrolled(opts.StateDir) {
		return nil, fmt.Errorf(
			"this host is already enrolled (%s). Revoke it in CertPilot and remove that directory to enrol again",
			opts.StateDir)
	}

	pub, priv, err := agentauth.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate this agent's identity key: %w", err)
	}
	publicPEM, err := agentauth.EncodePublicKey(pub)
	if err != nil {
		return nil, err
	}

	interval := int(opts.Interval.Seconds())
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = Hostname()
	}

	payload := map[string]any{
		"token":                      strings.TrimSpace(opts.Token),
		"public_key":                 publicPEM,
		"name":                       name,
		"hostname":                   Hostname(),
		"platform":                   Platform(),
		"version":                    Version,
		"heartbeat_interval_seconds": interval,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	server := strings.TrimRight(opts.Server, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/agent/enrol", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certpilot-agent/"+Version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", server, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The core's refusals here are written to be read by whoever is doing
		// the rollout, so they are passed through rather than replaced.
		return nil, fmt.Errorf("enrolment was refused (%d): %s", resp.StatusCode, oneLine(raw))
	}

	var result EnrolResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("the core's response could not be read: %w", err)
	}
	if result.AgentID == "" {
		return nil, fmt.Errorf("the core accepted the enrolment but returned no agent id")
	}

	// Written only after the core has accepted. An identity saved before the
	// call would leave a key on disk for an agent that does not exist, and the
	// refusal above to overwrite would then block the retry.
	if err := SaveIdentity(opts.StateDir, priv, State{
		AgentID:                  result.AgentID,
		Server:                   server,
		Name:                     result.Name,
		KeyID:                    result.KeyID,
		HeartbeatIntervalSeconds: result.HeartbeatIntervalSeconds,
		EnrolledAt:               time.Now(),
		ScanPaths:                opts.ScanPaths,
	}); err != nil {
		return nil, fmt.Errorf(
			"enrolled as %s, but the identity could not be saved — revoke that agent in CertPilot and try again: %w",
			result.AgentID, err)
	}
	return &result, nil
}
