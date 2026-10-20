package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/pkg/config"
)

// logging.level and logging.format were documented, parsed and then ignored:
// the core logged text at debug level whatever the file said.
func TestTheConfiguredFormatIsTheOneWritten(t *testing.T) {
	var out bytes.Buffer
	logger := newLogger(config.LoggingConfig{Level: "info", Format: "json"}, &out)
	logger.Info("renewal queued", "certificate", "web.example.com")

	var entry map[string]any
	if err := json.Unmarshal(out.Bytes(), &entry); err != nil {
		t.Fatalf("logging.format json wrote something that is not JSON: %q", out.String())
	}
	if entry["msg"] != "renewal queued" || entry["certificate"] != "web.example.com" {
		t.Fatalf("JSON entry = %v", entry)
	}
}

func TestTheConfiguredLevelIsTheFloor(t *testing.T) {
	var out bytes.Buffer
	logger := newLogger(config.LoggingConfig{Level: "warn", Format: "text"}, &out)
	logger.Debug("dialing gateway")
	logger.Info("renewal queued")
	logger.Warn("gateway unreachable")

	got := out.String()
	if strings.Contains(got, "dialing gateway") || strings.Contains(got, "renewal queued") {
		t.Fatalf("logging.level warn wrote debug or info lines:\n%s", got)
	}
	if !strings.Contains(got, "gateway unreachable") {
		t.Fatalf("logging.level warn dropped a warning:\n%s", got)
	}
}

func TestNoLoggingSectionMeansInfoAsText(t *testing.T) {
	var out bytes.Buffer
	logger := newLogger(config.LoggingConfig{}, &out)
	logger.Debug("dialing gateway")
	logger.Info("renewal queued")

	got := out.String()
	if strings.Contains(got, "dialing gateway") {
		t.Fatalf("with no level set, debug lines were written:\n%s", got)
	}
	if !strings.HasPrefix(got, "time=") {
		t.Fatalf("with no format set, want text, got:\n%s", got)
	}
}
