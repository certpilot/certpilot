package acmeserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
)

func (f *fixture) keyChangeURL() string { return f.srv.URL + "/acme/web/key-change" }

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTheDirectoryAdvertisesKeyChange(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.directoryURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var dir struct {
		KeyChange string `json:"keyChange"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&dir)
	if dir.KeyChange != f.keyChangeURL() {
		t.Errorf("keyChange %q", dir.KeyChange)
	}
}

func TestAnAccountCanChangeItsKey(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	ctx := context.Background()
	before, err := c.GetReg(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	oldKey := c.Key

	if err := c.AccountKeyRollover(ctx, newKey(t)); err != nil {
		t.Fatalf("rollover: %v", err)
	}

	after, err := c.GetReg(ctx, "")
	if err != nil || after.URI != before.URI {
		t.Fatalf("the new key finds %+v, %v; want the same account", after, err)
	}
	if _, err := c.AuthorizeOrder(ctx, acme.DomainIDs("web.example.com")); err != nil {
		t.Errorf("the account cannot order with its new key: %v", err)
	}

	old := &acme.Client{Key: oldKey, DirectoryURL: f.directoryURL()}
	if _, err := old.GetReg(ctx, ""); !errors.Is(err, acme.ErrNoAccount) && problemType(err) != "urn:ietf:params:acme:error:accountDoesNotExist" {
		t.Errorf("the old key still finds the account: %v", err)
	}
}

// Taking a key another account has would leave one key naming two accounts.
// RFC 8555 §7.3.5 says 409 with the other account's URL.
func TestAKeyAnotherAccountHasIsAConflict(t *testing.T) {
	f := newFixture(t)
	a := f.registered()
	b := f.client()
	acctB, err := register(b, "kid-b", f.credential("kid-b"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	err = a.AccountKeyRollover(ctx, b.Key)
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusConflict {
		t.Fatalf("got %v, want 409", err)
	}
	if loc := ae.Header.Get("Location"); loc != acctB.URI {
		t.Errorf("Location %q, want the account that has the key, %s", loc, acctB.URI)
	}
	if _, err := a.GetReg(ctx, ""); err != nil {
		t.Errorf("a refused rollover changed the account's key: %v", err)
	}
}

// The inner JWS is what proves the client holds the new key and meant it for
// this account. Each part of it is checked, and a request that gets any of it
// wrong leaves the account exactly as it was.
func TestAKeyChangeThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		inner func(f *fixture, acctURL string, oldKey, newKey *ecdsa.PrivateKey) []byte
		want  string
		says  string
	}{
		{"the inner request is signed for another URL", func(f *fixture, acct string, oldKey, nk *ecdsa.PrivateKey) []byte {
			return signedPost(f.t, nk, map[string]any{"alg": "ES256", "jwk": publicJWK(f.t, nk), "url": acct},
				innerPayload(f.t, acct, oldKey))
		}, "malformed", "signed for this URL"},
		{"the inner request names another account", func(f *fixture, acct string, oldKey, nk *ecdsa.PrivateKey) []byte {
			return signedPost(f.t, nk, map[string]any{"alg": "ES256", "jwk": publicJWK(f.t, nk), "url": f.keyChangeURL()},
				innerPayload(f.t, acct+"-other", oldKey))
		}, "unauthorized", "different account"},
		{"oldKey is not the account's key", func(f *fixture, acct string, _, nk *ecdsa.PrivateKey) []byte {
			return signedPost(f.t, nk, map[string]any{"alg": "ES256", "jwk": publicJWK(f.t, nk), "url": f.keyChangeURL()},
				innerPayload(f.t, acct, newKey(f.t)))
		}, "unauthorized", "current key"},
		{"the inner request carries a nonce", func(f *fixture, acct string, oldKey, nk *ecdsa.PrivateKey) []byte {
			return signedPost(f.t, nk, map[string]any{"alg": "ES256", "jwk": publicJWK(f.t, nk), "url": f.keyChangeURL(), "nonce": f.nonce()},
				innerPayload(f.t, acct, oldKey))
		}, "malformed", "nonce"},
		{"the inner request is not signed by the key it carries", func(f *fixture, acct string, oldKey, nk *ecdsa.PrivateKey) []byte {
			return signedPost(f.t, newKey(f.t), map[string]any{"alg": "ES256", "jwk": publicJWK(f.t, nk), "url": f.keyChangeURL()},
				innerPayload(f.t, acct, oldKey))
		}, "malformed", "does not verify"},
		{"the inner request names the account instead of carrying a key", func(f *fixture, acct string, oldKey, nk *ecdsa.PrivateKey) []byte {
			return signedPost(f.t, nk, map[string]any{"alg": "ES256", "kid": acct, "url": f.keyChangeURL()},
				innerPayload(f.t, acct, oldKey))
		}, "malformed", `"jwk"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.client()
			acct, err := register(c, "kid-1", f.credential("kid-1"))
			if err != nil {
				t.Fatal(err)
			}
			oldKey := c.Key.(*ecdsa.PrivateKey)
			inner := tc.inner(f, acct.URI, oldKey, newKey(t))
			body := signedPost(t, oldKey, map[string]any{
				"alg": "ES256", "nonce": f.nonce(), "kid": acct.URI, "url": f.keyChangeURL(),
			}, inner)
			_, got := post(t, f.keyChangeURL(), body)
			detail, _ := got["detail"].(string)
			if got["type"] != "urn:ietf:params:acme:error:"+tc.want || !strings.Contains(detail, tc.says) {
				t.Fatalf("got %v, want %s saying %q", got, tc.want, tc.says)
			}
			if _, err := c.GetReg(context.Background(), ""); err != nil {
				t.Errorf("the account's key changed anyway: %v", err)
			}
		})
	}
}

func innerPayload(t *testing.T, account string, oldKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"account": account, "oldKey": publicJWK(t, oldKey)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
