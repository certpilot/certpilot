package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentauth"
)

// TestAnIdentitySurvivesARestart — which is every restart of every host the
// agent is installed on.
func TestAnIdentitySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := agentauth.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	state := State{
		AgentID: "abc", Server: "https://core:8080", Name: "web-01",
		KeyID: "deadbeef", HeartbeatIntervalSeconds: 300, EnrolledAt: time.Now(),
	}
	if err := SaveIdentity(dir, priv, state); err != nil {
		t.Fatalf("save: %v", err)
	}

	loadedKey, loadedState, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loadedKey.Equal(priv) {
		t.Fatal("the key did not come back")
	}
	if loadedState.AgentID != state.AgentID || loadedState.Server != state.Server {
		t.Fatalf("the state did not come back: %#v", loadedState)
	}
}

// TestTheDirectoryAndKeyAreOwnerOnly. The directory matters as much as the
// file: a world-readable directory holding a 0600 key is not a leak today and
// becomes one the moment a second file is written into it without thinking.
func TestTheDirectoryAndKeyAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	_, priv, _ := agentauth.GenerateKey()
	if err := SaveIdentity(dir, priv, State{AgentID: "a", Server: "s"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	for path, want := range map[string]os.FileMode{
		dir:                           0o700,
		filepath.Join(dir, keyFile):   0o600,
		filepath.Join(dir, stateFile): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s is mode %04o, want %04o", path, got, want)
		}
	}
}

// TestAReadableKeyIsRefusedRatherThanWarnedAbout.
//
// A private key other accounts on the host can read is not a slightly less
// secure agent — every one of those accounts can now speak to CertPilot as this
// machine. An agent that carried on after printing a warning would be an agent
// whose warning nobody reads.
func TestAReadableKeyIsRefusedRatherThanWarnedAbout(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := agentauth.GenerateKey()
	if err := SaveIdentity(dir, priv, State{AgentID: "a", Server: "s"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, keyFile), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, _, err := LoadIdentity(dir)
	if err == nil {
		t.Fatal("a world-readable identity key must be refused")
	}
	// The message has to contain the fix, because whoever hits this is trying
	// to get an agent running and not to read about file modes.
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("the error should say how to fix it, got: %v", err)
	}
}

// TestAHostWithNoIdentitySaysWhatToRun.
func TestAHostWithNoIdentitySaysWhatToRun(t *testing.T) {
	_, _, err := LoadIdentity(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "enrol") {
		t.Fatalf("the error should point at enrolment, got: %v", err)
	}
	if Enrolled(t.TempDir()) {
		t.Fatal("an empty directory is not an enrolled host")
	}
}
