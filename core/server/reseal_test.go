package server

import (
	"context"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/pkg/config"
)

// Re-sealing the in-memory store would report success over data that is gone
// when the process exits.
func TestResealNeedsADatabase(t *testing.T) {
	_, _, err := Reseal(context.Background(), &config.CoreConfig{}, "")
	if err == nil || !strings.Contains(err.Error(), "database") {
		t.Fatalf("Reseal with no database = %v, want a refusal that names the database", err)
	}
}
