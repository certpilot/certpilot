package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/certpilot/certpilot/pkg/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// rotatingProvider is a JWKS endpoint whose published keys can change, the way
// an identity provider's do when it rotates, and which counts how often it is
// asked.
type rotatingProvider struct {
	mu      sync.Mutex
	keys    map[string]*ecdsa.PrivateKey
	order   []string
	fetches atomic.Int64
	srv     *httptest.Server
}

func newRotatingProvider(t *testing.T) *rotatingProvider {
	t.Helper()
	p := &rotatingProvider{keys: map[string]*ecdsa.PrivateKey{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		p.fetches.Add(1)
		p.mu.Lock()
		defer p.mu.Unlock()
		set := jwk.NewSet()
		for _, kid := range p.order {
			pub, err := jwk.Import(p.keys[kid].Public())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = pub.Set(jwk.KeyIDKey, kid)
			_ = pub.Set(jwk.AlgorithmKey, "ES256")
			_ = set.AddKey(pub)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// publish adds a signing key, as a provider does when it rotates: the new key
// signs from now on, and the old one stays published so tokens it signed keep
// verifying until they expire.
func (p *rotatingProvider) publish(t *testing.T, kid string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[kid] = key
	p.order = append(p.order, kid)
}

func (p *rotatingProvider) sign(t *testing.T, kid string) string {
	t.Helper()
	p.mu.Lock()
	key := p.keys[kid]
	p.mu.Unlock()
	if key == nil {
		// A key the provider never published: what a forged or garbage token
		// carries.
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatalf("generate key: %v", err)
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, validClaims(RoleOperator))
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// A provider that rotates its signing key starts signing with the new one at
// once. Keycloak does exactly that, and scripts/live-oidc.sh caught the core
// refusing every token and every sign-in after it did: the key set was cached
// for at least fifteen minutes and a key id it had not seen was simply "not in
// the set". An outage of sign-in for as long as the cache interval, every time
// the provider rotates, on a schedule the CertPilot operator does not control.
func TestAKeyTheProviderHasJustRotatedToIsAcceptedAtOnce(t *testing.T) {
	p := newRotatingProvider(t)
	p.publish(t, "first")
	a := newTestAuth(t, config.AuthConfig{JWKSURL: p.srv.URL})

	if w := runRequest(a, "Bearer "+p.sign(t, "first")); w.Code != http.StatusOK {
		t.Fatalf("before rotation: status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	p.publish(t, "second")

	if w := runRequest(a, "Bearer "+p.sign(t, "second")); w.Code != http.StatusOK {
		t.Fatalf("a token signed with the provider's new key: status = %d, want 200 (body: %s)",
			w.Code, w.Body.String())
	}
	if w := runRequest(a, "Bearer "+p.sign(t, "first")); w.Code != http.StatusOK {
		t.Fatalf("a token signed with the still-published old key: status = %d, want 200", w.Code)
	}
}

// Looking again on an unknown key id must not become a way to make the core
// hammer the identity provider. A caller can put any kid it likes in a token
// it does not have to be able to sign, so the second look is bounded.
func TestUnknownKeyIDsDoNotMakeTheCoreHammerTheProvider(t *testing.T) {
	p := newRotatingProvider(t)
	p.publish(t, "real")
	a := newTestAuth(t, config.AuthConfig{JWKSURL: p.srv.URL})

	if w := runRequest(a, "Bearer "+p.sign(t, "real")); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	before := p.fetches.Load()

	for i := range 50 {
		if w := runRequest(a, "Bearer "+p.sign(t, fmt.Sprintf("invented-%d", i))); w.Code != http.StatusUnauthorized {
			t.Fatalf("a token with an invented key id: status = %d, want 401", w.Code)
		}
	}

	if extra := p.fetches.Load() - before; extra > 1 {
		t.Fatalf("fifty tokens with invented key ids made the core fetch the key set %d more times; want at most one", extra)
	}
}
