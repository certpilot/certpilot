package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestMeSaysAPasswordSignInIsOne.
//
// Settings → Access said "Identity provider" for everybody, including someone
// who had just typed a local password into CertPilot's own sign-in form. The
// console had no way to know better: /me reported a browser session as
// "session" whichever way it was made. Whether it was a local password or a
// single sign-on is a question an administrator reads that line to answer.
func TestMeSaysAPasswordSignInIsOne(t *testing.T) {
	r, _ := realRouter(t)

	created := do(r, http.MethodPost, "/api/v1/users", map[string]any{
		"email": "local@example.com", "role": "viewer",
	}, nil)
	if created.Code != http.StatusCreated {
		t.Fatalf("creating the local account = %d: %s", created.Code, created.Body.String())
	}
	var account struct {
		InitialPassword string `json:"initial_password"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &account); err != nil {
		t.Fatalf("decode: %v", err)
	}

	login := do(r, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": "local@example.com", "password": account.InitialPassword,
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in with the password = %d: %s", login.Code, login.Body.String())
	}
	cookie := strings.Split(login.Header().Get("Set-Cookie"), ";")[0]
	if cookie == "" {
		t.Fatal("signing in set no session cookie")
	}

	me := do(r, http.MethodGet, "/api/v1/me", nil, map[string]string{"Cookie": cookie})
	if me.Code != http.StatusOK {
		t.Fatalf("/me = %d: %s", me.Code, me.Body.String())
	}
	var body struct {
		Email  string `json:"email"`
		SignIn string `json:"sign_in"`
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(me.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Email != "local@example.com" {
		t.Fatalf("/me answered for %q, not the account that signed in", body.Email)
	}
	if body.SignIn != "password" {
		t.Fatalf("sign_in = %q, want password", body.SignIn)
	}
	if body.Issuer != "" {
		t.Fatalf("issuer = %q for a local account, which has none to name", body.Issuer)
	}
}

// TestMeNamesTheIssuerOfABearerToken. A token from an identity provider is
// the other way in, and the issuer is what tells an administrator which one.
func TestMeNamesTheIssuerOfABearerToken(t *testing.T) {
	r, _ := realRouter(t)

	me := do(r, http.MethodGet, "/api/v1/me", nil, nil)
	if me.Code != http.StatusOK {
		t.Fatalf("/me = %d: %s", me.Code, me.Body.String())
	}
	var body struct {
		SignIn string `json:"sign_in"`
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(me.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.SignIn != "bearer" || body.Issuer != apiTestIssuer {
		t.Fatalf("sign_in = %q, issuer = %q; want bearer from %s", body.SignIn, body.Issuer, apiTestIssuer)
	}
}

// TestSignInMethod covers the one case the HTTP tests cannot reach without an
// identity provider to redeem a code: a browser session made by single sign-on.
func TestSignInMethod(t *testing.T) {
	cases := []struct{ authMethod, issuer, want string }{
		{"session", "certpilot-local", "password"},
		{"session", "https://id.example.com/realms/pki", "sso"},
		{"bearer", "https://id.example.com/realms/pki", "bearer"},
		{"display_token", "", "display_token"},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := signInMethod(c.authMethod, c.issuer); got != c.want {
			t.Errorf("signInMethod(%q, %q) = %q, want %q", c.authMethod, c.issuer, got, c.want)
		}
	}
}
