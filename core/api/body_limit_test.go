package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// oversizedLogin is a sign-in whose body is padded past the limit. Sign-in is
// the endpoint that matters: it is unauthenticated, so anybody can send it,
// and before the limit its handler read the whole body into memory to decode
// it, however large.
func oversizedLogin(size int) []byte {
	pad := strings.Repeat("x", size)
	return []byte(`{"email": "you@example.com", "password": "` + pad + `"}`)
}

func TestADeclaredOversizedBodyIsRefused(t *testing.T) {
	r, _, _ := realRouterWithPlugins(t)
	body := oversizedLogin(maxRequestBody + 1)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a %d-byte sign-in = %d, want 413", len(body), rec.Code)
	}
}

// A chunked body carries no Content-Length, so the size is only known by
// reading it. It has to be cut off at the limit rather than read to the end.
func TestAnUndeclaredOversizedBodyIsCutOff(t *testing.T) {
	r, _, _ := realRouterWithPlugins(t)
	// Four times the limit, so reading it all is distinguishable from stopping.
	counted := &countingReader{r: bytes.NewReader(oversizedLogin(4 * maxRequestBody))}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", counted)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an undeclared oversized sign-in = %d, want 413", rec.Code)
	}
	if counted.n > maxRequestBody+64<<10 {
		t.Fatalf("read %d bytes of the body, want it cut off near the %d-byte limit", counted.n, maxRequestBody)
	}
}

func TestABodyUnderTheLimitStillReachesItsHandler(t *testing.T) {
	r, _, _ := realRouterWithPlugins(t)
	rec := do(r, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "nobody@example.com", "password": "wrong"},
		map[string]string{"Cookie": "none=1"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an ordinary failed sign-in = %d, want 401 from the handler", rec.Code)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
