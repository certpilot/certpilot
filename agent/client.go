package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentauth"
)

// Client talks to the core as one agent.
type Client struct {
	server  string
	agentID string
	key     ed25519.PrivateKey
	http    *http.Client
}

// NewClient creates a client for an enrolled agent.
func NewClient(server, agentID string, key ed25519.PrivateKey) *Client {
	return &Client{
		server:  strings.TrimRight(server, "/"),
		agentID: agentID,
		key:     key,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// ErrRevoked is returned when the core says this agent's credential has been
// withdrawn.
//
// A distinct error because the right response is different from every other
// failure: there is no amount of retrying that fixes it, and an agent that
// keeps trying is a revoked credential still knocking on the door every five
// minutes for however long the host stays up.
var ErrRevoked = fmt.Errorf("this agent's credential has been revoked")

// ErrClockSkew is returned when the core refused a request and its own clock
// disagrees with this host's by more than the signing tolerance.
//
// Worth its own error because it is the commonest cause of a signature that
// will not verify and the least obvious from the message the server can safely
// return. The core deliberately answers a flat 401 without saying which check
// failed — so the agent works it out from the Date header, which every HTTP
// response carries anyway.
var ErrClockSkew = fmt.Errorf("this host's clock is too far from the server's for its signatures to be accepted")

// post sends a signed request and decodes the response.
func (c *Client) post(ctx context.Context, path string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// The path signed is the path requested, so a signature made for one route
	// cannot be lifted onto another.
	parsed, err := url.Parse(c.server + path)
	if err != nil {
		return fmt.Errorf("server address is not valid: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	timestamp := time.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certpilot-agent/"+Version)
	req.Header.Set(agentauth.AgentHeader, c.agentID)
	req.Header.Set(agentauth.TimestampHeader, fmt.Sprint(timestamp))
	req.Header.Set(agentauth.SignatureHeader,
		agentauth.Sign(c.key, http.MethodPost, parsed.Path, timestamp, body))

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", c.server, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	switch {
	case resp.StatusCode == http.StatusForbidden:
		// 403 means two things and they call for opposite responses: a revoked
		// credential is terminal, and a request the grants do not permit is a
		// policy problem somebody can fix while this agent keeps running. The
		// status code cannot carry that distinction, so the body does.
		if bodyCode(raw) == "agent_revoked" {
			return ErrRevoked
		}
		return fmt.Errorf("%s", oneLine(raw))
	case resp.StatusCode == http.StatusUnauthorized:
		if skewed(resp, time.Now()) {
			return ErrClockSkew
		}
		return fmt.Errorf("the core did not accept this agent's signature (%d): %s",
			resp.StatusCode, oneLine(raw))
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return fmt.Errorf("%s returned %d: %s", path, resp.StatusCode, oneLine(raw))
	}

	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("the core's response could not be read: %w", err)
		}
	}
	return nil
}

// skewed reports whether the server's clock is far enough from this host's to
// explain a refusal.
//
// Read from the standard Date header rather than from anything CertPilot
// invented, so it works even for a response that carries no body — and so the
// agent is not relying on the core to volunteer a diagnostic on a request it
// just refused.
func skewed(resp *http.Response, now time.Time) bool {
	served, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return false
	}
	drift := now.Sub(served)
	if drift < 0 {
		drift = -drift
	}
	return drift > agentauth.DefaultTolerance
}

// bodyCode reads the machine-readable code out of an error response.
func bodyCode(raw []byte) string {
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &body)
	return body.Code
}

// oneLine renders an error body as a single readable line.
//
// The core's refusals here are written to be read by whoever is operating the
// host, so the message is passed through rather than replaced with one of this
// program's own.
func oneLine(raw []byte) string {
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && body.Error != "" {
		return body.Error
	}
	return compact(raw)
}

func compact(raw []byte) string {
	text := strings.Join(strings.Fields(string(raw)), " ")
	if len(text) > 200 {
		return text[:200] + "…"
	}
	if text == "" {
		return "no detail"
	}
	return text
}
