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
