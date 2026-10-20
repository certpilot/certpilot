package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
)

// clientIPFrom sends one request through an engine built the way the server
// builds its own and returns the address the handlers would see.
func clientIPFrom(t *testing.T, cfg config.ServerConfig, remoteAddr, forwardedFor string) string {
	t.Helper()
	engine, err := newEngine(cfg)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	engine.GET("/ip", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })

	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = remoteAddr
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec.Body.String()
}

// The address a client claims is not the address it connected from. Without
// a proxy in front, believing the header lets anybody pick the address their
// rate limit is counted against and the one written into the audit log.
func TestAForwardedForHeaderIsIgnoredWhenNoProxyIsTrusted(t *testing.T) {
	got := clientIPFrom(t, config.ServerConfig{}, "203.0.113.9:40000", "198.51.100.1")
	if got != "203.0.113.9" {
		t.Fatalf("client address = %q, want the connecting address 203.0.113.9", got)
	}
}

func TestATrustedProxySaysWhoTheClientIs(t *testing.T) {
	cfg := config.ServerConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	got := clientIPFrom(t, cfg, "10.1.2.3:40000", "198.51.100.1")
	if got != "198.51.100.1" {
		t.Fatalf("client address = %q, want 198.51.100.1 as the trusted proxy reported it", got)
	}
}

// nginx's $proxy_add_x_forwarded_for appends to whatever the client sent, so
// the header arrives as "<anything the client wrote>, <the real client>". Only
// the entry the trusted proxy added may be believed.
func TestAClientCannotPrependAnAddressThroughATrustedProxy(t *testing.T) {
	cfg := config.ServerConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	got := clientIPFrom(t, cfg, "10.1.2.3:40000", "192.0.2.77, 198.51.100.1")
	if got != "198.51.100.1" {
		t.Fatalf("client address = %q, want 198.51.100.1, the entry the proxy added", got)
	}
}

func TestAnUntrustedPeerCannotSpeakForAnotherClient(t *testing.T) {
	cfg := config.ServerConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	got := clientIPFrom(t, cfg, "203.0.113.9:40000", "198.51.100.1")
	if got != "203.0.113.9" {
		t.Fatalf("client address = %q, want 203.0.113.9: that peer is not a trusted proxy", got)
	}
}

// The failure this exists for: an unauthenticated caller rotating the header
// on every request got a fresh rate-limit bucket each time.
func TestRotatingForwardedForDoesNotEscapeTheRateLimit(t *testing.T) {
	engine, err := newEngine(config.ServerConfig{})
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{Rate: 0.001, Burst: 2})
	defer limiter.Stop()
	engine.Use(limiter.Middleware())
	engine.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	var last int
	for i, forged := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.9:40000"
		req.Header.Set("X-Forwarded-For", forged)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		last = rec.Code
		if i < 2 && rec.Code != http.StatusOK {
			t.Fatalf("request %d inside the burst = %d", i+1, rec.Code)
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("third request from one address under a new forged header = %d, want 429", last)
	}
}
