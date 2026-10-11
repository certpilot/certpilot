package config

import (
	"strings"
	"testing"
)

func validDevelopmentConfig() *CoreConfig {
	return &CoreConfig{
		Server:  ServerConfig{Mode: "development", Port: 8080},
		Secrets: SecretsConfig{KEKProvider: "env"},
	}
}

func TestACMEIsOffUnlessAnOperatorTurnsItOn(t *testing.T) {
	if (ACMEConfig{}).Enabled {
		t.Fatal("ACME opens unauthenticated endpoints; it must not be on by default")
	}
}

func TestProductionACMENeedsTheAddressClientsUse(t *testing.T) {
	for name, url := range map[string]string{
		"none":       "",
		"plain http": "http://certpilot.example.com",
	} {
		cfg := validDevelopmentConfig()
		cfg.Server.Mode = "production"
		cfg.ACME = ACMEConfig{Enabled: true, ExternalURL: url}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "acme.external_url") {
			t.Errorf("%s: got %v, want a refusal naming acme.external_url", name, err)
		}
	}

	cfg := validDevelopmentConfig()
	cfg.Server.Mode = "production"
	cfg.ACME = ACMEConfig{Enabled: true, ExternalURL: "https://certpilot.example.com"}
	if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "acme") {
		t.Errorf("a complete ACME configuration was refused: %v", err)
	}
}

func TestDevelopmentACMEMayDeriveItsOwnAddress(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.ACME = ACMEConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Errorf("development ACME with no external_url was refused: %v", err)
	}
}
