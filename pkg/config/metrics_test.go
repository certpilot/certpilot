package config

import (
	"strings"
	"testing"
)

func TestMetricsAreOffUnlessAnAddressIsGiven(t *testing.T) {
	if (MetricsConfig{}).Listen != "" {
		t.Fatal("metrics must not be served unless an operator asks for them")
	}
}

func TestTheMetricsAddressMustBeHostAndPort(t *testing.T) {
	for _, listen := range []string{"9464", "metrics", "0.0.0.0:http-alt", ":99999"} {
		cfg := validDevelopmentConfig()
		cfg.Metrics.Listen = listen
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "metrics.listen") {
			t.Errorf("%q: got %v, want a refusal naming metrics.listen", listen, err)
		}
	}
	for _, listen := range []string{":9464", "127.0.0.1:9464", "0.0.0.0:9464", "[::1]:9464"} {
		cfg := validDevelopmentConfig()
		cfg.Metrics.Listen = listen
		if err := cfg.Validate(); err != nil {
			t.Errorf("%q was refused: %v", listen, err)
		}
	}
}

// The estate's shape — how many CAs are critical, which gateways are down — is
// not something to serve to the whole network unauthenticated in production.
func TestProductionMetricsOffLoopbackNeedAToken(t *testing.T) {
	for _, listen := range []string{":9464", "0.0.0.0:9464", "10.0.0.5:9464"} {
		cfg := validDevelopmentConfig()
		cfg.Server.Mode = "production"
		cfg.Metrics.Listen = listen
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "metrics.bearer_token") {
			t.Errorf("%q without a token: got %v, want a refusal naming metrics.bearer_token", listen, err)
		}
		cfg.Metrics.BearerToken = "a-long-random-token"
		if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "metrics") {
			t.Errorf("%q with a token was refused: %v", listen, err)
		}
	}
	for _, listen := range []string{"127.0.0.1:9464", "[::1]:9464", "localhost:9464"} {
		cfg := validDevelopmentConfig()
		cfg.Server.Mode = "production"
		cfg.Metrics.Listen = listen
		if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "metrics") {
			t.Errorf("loopback %q without a token was refused: %v", listen, err)
		}
	}
}
