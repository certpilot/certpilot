// Package agent is the CertPilot host agent: the part that runs on the machines
// where certificates actually live.
//
// It exists because those machines are the ones nothing can reach inwards, and
// because the private key should never have travelled to them in the first
// place. Everything here is built around one property that the rest of the
// system cannot provide on its own:
//
//	The keys are generated on the host and never leave it.
//
// The agent's own identity key is the first instance of that, not an exception
// to it. It is generated during enrolment, the public half is sent, and the
// private half stays in a file on the host for the life of the agent.
package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentauth"
)

// Version is what the agent reports about itself, on enrolment, on every
// heartbeat, and in its User-Agent.
//
// A var rather than a const so a release build can stamp it:
//
//	-ldflags "-X github.com/certpilot/certpilot/agent.Version=1.2.3"
//
// It was a const, which meant every agent ever built reported 0.1.0 whatever it
// actually was — and this value is the one an operator uses to answer "which of
// these five hundred hosts is running something old", which is the question the
// fleet view exists for. A number nobody updates at release time answers it
// wrongly and confidently.
//
// The default keeps the -dev suffix on purpose. An unstamped build is a
// development build, and saying so is better than claiming to be the release it
// was branched from.
var Version = "0.1.0-dev"

// File names inside the state directory.
const (
	keyFile   = "agent.key"
	stateFile = "agent.json"
)

// State is what the agent remembers between runs.
//
// Deliberately small, and deliberately not a copy of the server's record. What
// the agent needs is where to call, who it is, and how often it promised to
// speak. Everything else about it lives on the core, which is where somebody
// looks when they want to know.
type State struct {
	AgentID                  string    `json:"agent_id"`
	Server                   string    `json:"server"`
	Name                     string    `json:"name"`
	KeyID                    string    `json:"key_id"`
	HeartbeatIntervalSeconds int       `json:"heartbeat_interval_seconds"`
	EnrolledAt               time.Time `json:"enrolled_at"`
	// ScanPaths is where this host keeps certificates, if it is anywhere
	// unusual. Empty means the defaults, which is what almost every host wants.
	ScanPaths []string `json:"scan_paths,omitempty"`
}

// DefaultStateDir is where the agent keeps its key and its identity.
//
// Under /var/lib when running as root, because that is where a system service's
// state belongs and because it is not backed up to somebody's home directory by
// accident. Under $HOME otherwise, so that trying the agent out does not
// require privileges it will not need again.
func DefaultStateDir() string {
	if dir := strings.TrimSpace(os.Getenv("CERTPILOT_AGENT_STATE")); dir != "" {
		return dir
	}
	if os.Geteuid() == 0 {
		return "/var/lib/certpilot-agent"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".certpilot-agent"
	}
	return filepath.Join(home, ".certpilot-agent")
}

// Platform describes this host, for the fleet list.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

// Hostname reports this machine's name, or empty if it cannot be determined.
func Hostname() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}

// SaveIdentity writes the key and the state, both readable only by their owner.
//
// The directory is created 0700 rather than 0755. A world-readable directory
// holding a 0600 key is not a leak today and is one the moment somebody adds a
// second file to it without thinking, which is exactly what the rest of this
// phase is going to do.
func SaveIdentity(dir string, key ed25519.PrivateKey, state State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("could not create the state directory %s: %w", dir, err)
	}

	encoded, err := agentauth.EncodePrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), []byte(encoded), 0o600); err != nil {
		return fmt.Errorf("could not write the identity key: %w", err)
	}

	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, stateFile), append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("could not write the agent state: %w", err)
	}
	return nil
}

// LoadIdentity reads the key and state back, refusing a key anybody else can
// read.
//
// Refused rather than warned about. A private key with group or world
// permissions is not a smaller version of a secure one — every other account on
// that host can now speak to CertPilot as this machine — and an agent that
// carries on after printing a warning is an agent whose warning nobody reads.
func LoadIdentity(dir string) (ed25519.PrivateKey, State, error) {
	var state State

	keyPath := filepath.Join(dir, keyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, state, fmt.Errorf(
			"no identity in %s — run `certpilot-agent enrol` on this host first: %w", dir, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, state, fmt.Errorf(
			"%s is mode %04o, which lets other accounts on this host read this agent's identity key. Run: chmod 600 %s",
			keyPath, mode, keyPath)
	}

	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, state, err
	}
	key, err := agentauth.ParsePrivateKey(string(raw))
	if err != nil {
		return nil, state, fmt.Errorf("the identity key in %s could not be read: %w", keyPath, err)
	}

	body, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return nil, state, fmt.Errorf("the agent state in %s could not be read: %w", dir, err)
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, state, fmt.Errorf("the agent state in %s is not valid JSON: %w", dir, err)
	}
	if state.AgentID == "" || state.Server == "" {
		return nil, state, fmt.Errorf("the agent state in %s is incomplete; re-enrol this host", dir)
	}
	return key, state, nil
}

// Enrolled reports whether this host already has an identity.
func Enrolled(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, stateFile))
	return err == nil
}
