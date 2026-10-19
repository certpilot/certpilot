package config

import (
	"strings"
	"testing"
)

// A misspelt level or format used to be accepted and ignored. Now that both
// are applied, a value that means nothing is refused at load.
func TestAnUnknownLoggingSettingIsRefused(t *testing.T) {
	for _, lc := range []LoggingConfig{{Level: "verbose"}, {Format: "logfmt"}} {
		cfg := validDevelopmentConfig()
		cfg.Logging = lc
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "logging.") {
			t.Errorf("%+v: got %v, want a refusal naming the logging setting", lc, err)
		}
	}
	for _, lc := range []LoggingConfig{{}, {Level: "DEBUG", Format: "json"}, {Level: "error", Format: "text"}} {
		cfg := validDevelopmentConfig()
		cfg.Logging = lc
		if err := cfg.Validate(); err != nil {
			t.Errorf("%+v was refused: %v", lc, err)
		}
	}
}
