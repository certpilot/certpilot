package config

import (
	"strings"
	"testing"
)

func TestATrustedProxyMustBeAnAddressOrARange(t *testing.T) {
	for _, entry := range []string{"nginx", "10.0.0.0/33", "", "10.0.0.1:8080"} {
		cfg := validDevelopmentConfig()
		cfg.Server.TrustedProxies = []string{entry}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "server.trusted_proxies") {
			t.Errorf("%q: got %v, want a refusal naming server.trusted_proxies", entry, err)
		}
	}

	cfg := validDevelopmentConfig()
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8", "192.0.2.10", "2001:db8::/32"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid addresses and ranges were refused: %v", err)
	}
}

// Trusting every address is what gin did by default, and it is the bug this
// setting exists to remove. In production it is refused outright.
func TestProductionRefusesToTrustEveryAddress(t *testing.T) {
	for _, everything := range []string{"0.0.0.0/0", "::/0"} {
		cfg := validDevelopmentConfig()
		cfg.Server.Mode = "production"
		cfg.Server.TrustedProxies = []string{everything}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "server.trusted_proxies") {
			t.Errorf("%s: got %v, want a refusal naming server.trusted_proxies", everything, err)
		}
	}
}
