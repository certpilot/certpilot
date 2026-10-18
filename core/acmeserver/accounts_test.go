package acmeserver_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	"github.com/certpilot/certpilot/core/acmeserver"
	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"golang.org/x/crypto/acme"
)

// These tests drive the server with the Go ACME client, which is a real client
// written by somebody else, and with hand-built requests for the refusals the
// client would never send.

type fixture struct {
	t        *testing.T
	st       store.Store
	kr       *secrets.Keyring
	srv      *httptest.Server
	template *store.CertificateTemplate
	gw       *fakeGateway
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	gw := startGateway(t)
	pm := pluginmgr.NewManager(grpckit.TLSConfig{Insecure: true})
	t.Cleanup(pm.Close)

	st := store.NewMemoryStore()
	ca := &store.CAAccount{Name: "acme-test-ca", ProviderType: "selfsigned", GatewayAddr: gw.addr,
		ConfigEncrypted: "", Status: "CONNECTED"}
	if err := st.CreateCAAccount(ctx, ca); err != nil {
		t.Fatal(err)
	}
	if _, err := pm.RegisterGateway(ctx, ca.Name, gw.addr, "selfsigned", ""); err != nil {
		t.Fatal(err)
	}
	tpl := &store.CertificateTemplate{
		Slug: "web", Name: "Web", Version: 1, IsEnabled: true, CAAccountID: ca.ID,
		SubjectMode: store.SubjectModeSupplied, AllowedKeyTypes: []string{"RSA", "ECDSA"},
		KeyCustodyRequired: store.KeyCustodyAny, RenewBeforeDays: 30,
		SANRules: store.SANRules{Suffixes: []string{".example.com"}},
	}
	if err := st.CreateCertificateTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	kr, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}

	engine := gin.New()
	acmeserver.New(acmeserver.Config{
		Store: st, Keyring: kr,
		Resolver: issuance.NewResolver(st, policy.NewEngine(st)),
		Signer:   issuance.NewSigner(pm, kr),
		Revoker:  issuance.NewRevoker(st, pm, kr),
	}).Register(engine)
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return &fixture{t: t, st: st, kr: kr, srv: srv, template: tpl, gw: gw}
}

func (f *fixture) directoryURL() string { return f.srv.URL + "/acme/web/directory" }

// credential makes an EAB credential the way an administrator's request would
// and returns its HMAC key.
func (f *fixture) credential(kid string) []byte {
	f.t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.t.Fatal(err)
	}
	sealed, err := f.kr.Encrypt(key, secrets.ContextACMEEABKey)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.st.CreateACMEEABCredential(context.Background(), &store.ACMEEABCredential{
		KID: kid, Name: kid, TemplateID: f.template.ID, HMACKeySealed: sealed,
	}); err != nil {
		f.t.Fatal(err)
	}
	return key
}

func (f *fixture) client() *acme.Client {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	return &acme.Client{Key: key, DirectoryURL: f.directoryURL()}
}

func register(c *acme.Client, kid string, hmacKey []byte) (*acme.Account, error) {
	return c.Register(context.Background(), &acme.Account{
		Contact:                []string{"mailto:ops@example.com"},
		ExternalAccountBinding: &acme.ExternalAccountBinding{KID: kid, Key: hmacKey},
	}, acme.AcceptTOS)
}

func problemType(err error) string {
	var ae *acme.Error
	if errors.As(err, &ae) {
		return ae.ProblemType
	}
	return ""
}

func TestTheDirectoryAdvertisesAccountsAndSaysBindingIsRequired(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.directoryURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var dir struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
		Meta       struct {
			ExternalAccountRequired bool `json:"externalAccountRequired"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatal(err)
	}
	if dir.NewNonce != f.srv.URL+"/acme/web/new-nonce" || dir.NewAccount != f.srv.URL+"/acme/web/new-account" {
		t.Errorf("directory URLs are not absolute and under the template: %+v", dir)
	}
	if dir.NewOrder != f.srv.URL+"/acme/web/new-order" {
		t.Errorf("newOrder %q: clients treat its absence as 'not an RFC 8555 server'", dir.NewOrder)
	}
	if !dir.Meta.ExternalAccountRequired {
		t.Error("the directory does not say registration needs an external account binding")
	}
}

func TestAnUnknownTemplateHasNoDirectory(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.srv.URL + "/acme/nope/directory")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
}

func TestNonceEndpointsHandOutANonceAndNeverCacheIt(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, _ := http.NewRequest(method, f.srv.URL+"/acme/web/new-nonce", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.Header.Get("Replay-Nonce") == "" {
			t.Errorf("%s: no Replay-Nonce", method)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", method, resp.Header.Get("Cache-Control"))
		}
	}
}

func TestAClientWithACredentialCanRegister(t *testing.T) {
	f := newFixture(t)
	hmac := f.credential("kid-1")
	c := f.client()

	acct, err := register(c, "kid-1", hmac)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if acct.Status != acme.StatusValid {
		t.Errorf("status %q, want valid", acct.Status)
	}
	if !strings.HasPrefix(acct.URI, f.srv.URL+"/acme/web/account/") {
		t.Errorf("account URL %q is not under the template", acct.URI)
	}

	stored, err := f.st.GetACMEEABCredentialByKID(context.Background(), "kid-1")
	if err != nil || stored.AccountID == nil {
		t.Fatalf("the credential does not record the account it made: %+v, %v", stored, err)
	}
}

func TestRegisteringAgainWithTheSameKeyFindsTheSameAccount(t *testing.T) {
	f := newFixture(t)
	hmac := f.credential("kid-1")
	c := f.client()
	first, err := register(c, "kid-1", hmac)
	if err != nil {
		t.Fatal(err)
	}
	_, err = register(c, "kid-1", hmac)
	if !errors.Is(err, acme.ErrAccountAlreadyExists) {
		t.Fatalf("second registration returned %v, want ErrAccountAlreadyExists", err)
	}
	got, err := c.GetReg(context.Background(), "")
	if err != nil || got.URI != first.URI {
		t.Errorf("looking the account up by key found %v, %v; want %s", got, err, first.URI)
	}
}

func TestRegistrationWithoutABindingIsRefused(t *testing.T) {
	f := newFixture(t)
	_, err := f.client().Register(context.Background(), &acme.Account{}, acme.AcceptTOS)
	if problemType(err) != "urn:ietf:params:acme:error:externalAccountRequired" {
		t.Fatalf("got %v, want externalAccountRequired", err)
	}
}

func TestRegistrationWithTheWrongKeyIsRefused(t *testing.T) {
	f := newFixture(t)
	f.credential("kid-1")
	wrong := bytes.Repeat([]byte{7}, 32)
	_, err := register(f.client(), "kid-1", wrong)
	if problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized", err)
	}
	if accounts, _ := f.st.GetACMEEABCredentialByKID(context.Background(), "kid-1"); accounts.AccountID != nil {
		t.Error("a refused registration still made an account")
	}
}

func TestRegistrationWithAnUnknownCredentialIsRefused(t *testing.T) {
	f := newFixture(t)
	_, err := register(f.client(), "never-issued", bytes.Repeat([]byte{1}, 32))
	if problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized", err)
	}
}

func TestARevokedCredentialCannotRegister(t *testing.T) {
	f := newFixture(t)
	hmac := f.credential("kid-1")
	stored, _ := f.st.GetACMEEABCredentialByKID(context.Background(), "kid-1")
	if _, err := f.st.RevokeACMEEABCredential(context.Background(), stored.ID, nil); err != nil {
		t.Fatal(err)
	}
	_, err := register(f.client(), "kid-1", hmac)
	if problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized", err)
	}
}

func TestACredentialForAnotherTemplateCannotRegisterHere(t *testing.T) {
	f := newFixture(t)
	other := *f.template
	other.ID, other.Slug, other.Name = "", "other", "Other"
	if err := f.st.CreateCertificateTemplate(context.Background(), &other); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{3}, 32)
	sealed, _ := f.kr.Encrypt(key, secrets.ContextACMEEABKey)
	if err := f.st.CreateACMEEABCredential(context.Background(), &store.ACMEEABCredential{
		KID: "kid-other", Name: "x", TemplateID: other.ID, HMACKeySealed: sealed,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := register(f.client(), "kid-other", key)
	if problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized: a credential must only work for its own template", err)
	}
}

func TestOneCredentialCannotMakeASecondAccountWithAnotherKey(t *testing.T) {
	f := newFixture(t)
	hmac := f.credential("kid-1")
	if _, err := register(f.client(), "kid-1", hmac); err != nil {
		t.Fatal(err)
	}
	_, err := register(f.client(), "kid-1", hmac)
	if problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized: a leaked credential must not mint accounts", err)
	}
}

func TestAnAccountCanBeReadUpdatedAndDeactivated(t *testing.T) {
	f := newFixture(t)
	hmac := f.credential("kid-1")
	c := f.client()
	acct, err := register(c, "kid-1", hmac)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	got, err := c.GetReg(ctx, acct.URI)
	if err != nil || len(got.Contact) != 1 || got.Contact[0] != "mailto:ops@example.com" {
		t.Fatalf("read: %+v, %v", got, err)
	}

	got.Contact = []string{"mailto:new@example.com"}
	updated, err := c.UpdateReg(ctx, got)
	if err != nil || len(updated.Contact) != 1 || updated.Contact[0] != "mailto:new@example.com" {
		t.Fatalf("update: %+v, %v", updated, err)
	}

	if err := c.DeactivateReg(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	stored, _ := f.st.GetACMEAccount(ctx, acct.URI[strings.LastIndex(acct.URI, "/")+1:])
	if stored.Status != store.ACMEAccountDeactivated {
		t.Errorf("stored status %q, want deactivated", stored.Status)
	}
	if _, err := c.GetReg(ctx, acct.URI); problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("a deactivated account could still read itself: %v", err)
	}
}

func TestAnAccountCannotActOnAnotherAccount(t *testing.T) {
	f := newFixture(t)
	a := f.client()
	acctA, err := register(a, "kid-a", f.credential("kid-a"))
	if err != nil {
		t.Fatal(err)
	}
	keyB := f.client()
	acctB, err := register(keyB, "kid-b", f.credential("kid-b"))
	if err != nil {
		t.Fatal(err)
	}
	b := keyB.Key.(*ecdsa.PrivateKey)

	// b names itself correctly, and asks for a's account.
	body := signedPost(t, b, map[string]any{
		"alg": "ES256", "nonce": f.nonce(), "kid": acctB.URI, "url": acctA.URI,
	}, nil)
	_, got := post(t, acctA.URI, body)
	if got["type"] != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("b read a's account: %v", got)
	}

	// b names a as itself but signs with its own key.
	body = signedPost(t, b, map[string]any{
		"alg": "ES256", "nonce": f.nonce(), "kid": acctA.URI, "url": acctA.URI,
	}, nil)
	_, got = post(t, acctA.URI, body)
	if got["type"] != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("b passed itself off as a: %v", got)
	}
}

// ── Requests the client would never send ────────────────────

func (f *fixture) nonce() string {
	f.t.Helper()
	resp, err := http.Head(f.srv.URL + "/acme/web/new-nonce")
	if err != nil {
		f.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Replay-Nonce")
}

// signedPost builds a flattened JWS over payload with the given protected
// headers, signed by key.
func signedPost(t *testing.T, key *ecdsa.PrivateKey, headers map[string]any, payload []byte) []byte {
	t.Helper()
	hdrs := jws.NewHeaders()
	for k, v := range headers {
		if err := hdrs.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdrs)), jws.WithJSON())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func publicJWK(t *testing.T, key *ecdsa.PrivateKey) jwk.Key {
	t.Helper()
	k, err := jwk.Import(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func post(t *testing.T, url string, body []byte) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/jose+json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

func TestANonceCannotBeUsedTwice(t *testing.T) {
	f := newFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	url := f.srv.URL + "/acme/web/new-account"
	body := signedPost(t, key, map[string]any{
		"alg": "ES256", "nonce": f.nonce(), "url": url, "jwk": publicJWK(t, key),
	}, []byte(`{"onlyReturnExisting":true}`))

	_, first := post(t, url, body)
	if first["type"] != "urn:ietf:params:acme:error:accountDoesNotExist" {
		t.Fatalf("first use: %v", first)
	}
	resp, second := post(t, url, body)
	if second["type"] != "urn:ietf:params:acme:error:badNonce" {
		t.Fatalf("second use: %v, want badNonce", second)
	}
	if resp.Header.Get("Replay-Nonce") == "" {
		t.Error("a badNonce response must carry a fresh nonce so the client can retry")
	}
}

func TestAForgedNonceIsRefused(t *testing.T) {
	f := newFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	url := f.srv.URL + "/acme/web/new-account"
	forged := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 64))
	body := signedPost(t, key, map[string]any{
		"alg": "ES256", "nonce": forged, "url": url, "jwk": publicJWK(t, key),
	}, []byte(`{}`))
	_, got := post(t, url, body)
	if got["type"] != "urn:ietf:params:acme:error:badNonce" {
		t.Fatalf("got %v, want badNonce", got)
	}
}

func TestARequestSignedForAnotherURLIsRefused(t *testing.T) {
	f := newFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := signedPost(t, key, map[string]any{
		"alg": "ES256", "nonce": f.nonce(), "url": "https://elsewhere.example/acme/web/new-account",
		"jwk": publicJWK(t, key),
	}, []byte(`{}`))
	_, got := post(t, f.srv.URL+"/acme/web/new-account", body)
	if got["type"] != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized: a signature for one URL must not work on another", got)
	}
}

func TestAnHMACSignedRequestIsRefused(t *testing.T) {
	f := newFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	url := f.srv.URL + "/acme/web/new-account"
	hdrs := jws.NewHeaders()
	_ = hdrs.Set("nonce", f.nonce())
	_ = hdrs.Set("url", url)
	_ = hdrs.Set("jwk", publicJWK(t, key))
	body, err := jws.Sign([]byte(`{}`), jws.WithKey(jwa.HS256(), []byte("sixteen byte key"), jws.WithProtectedHeaders(hdrs)), jws.WithJSON())
	if err != nil {
		t.Fatal(err)
	}
	_, got := post(t, url, body)
	if got["type"] != "urn:ietf:params:acme:error:badSignatureAlgorithm" {
		t.Fatalf("got %v, want badSignatureAlgorithm: an account key must be asymmetric", got)
	}
}

func TestAPrivateKeyInAJWKIsRefused(t *testing.T) {
	f := newFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	url := f.srv.URL + "/acme/web/new-account"
	private, _ := jwk.Import(key)
	body := signedPost(t, key, map[string]any{
		"alg": "ES256", "nonce": f.nonce(), "url": url, "jwk": private,
	}, []byte(`{}`))
	_, got := post(t, url, body)
	if got["type"] != "urn:ietf:params:acme:error:malformed" {
		t.Fatalf("got %v, want malformed: a client that sends its private key should be told", got)
	}
}

var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)

func TestADeactivatedAccountCannotSignRequestsAnyMore(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	acct, err := register(c, "kid-1", f.credential("kid-1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeactivateReg(context.Background()); err != nil {
		t.Fatal(err)
	}
	key := c.Key.(*ecdsa.PrivateKey)
	body := signedPost(t, key, map[string]any{
		"alg": "ES256", "nonce": f.nonce(), "kid": acct.URI, "url": acct.URI,
	}, nil)
	_, got := post(t, acct.URI, body)
	if got["type"] != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("a deactivated account read itself: %v", got)
	}
}

// A binding is only worth anything if it is for the key being registered.
// Otherwise one captured binding registers any key its holder likes.
func TestABindingMadeForAnotherKeyIsRefused(t *testing.T) {
	f := newFixture(t)
	hmacKey := f.credential("kid-1")
	url := f.srv.URL + "/acme/web/new-account"

	mine, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	theirs, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// A valid binding, for their key.
	bindingHeaders := jws.NewHeaders()
	_ = bindingHeaders.Set("kid", "kid-1")
	_ = bindingHeaders.Set("url", url)
	theirJWK, _ := json.Marshal(publicJWK(t, theirs))
	binding, err := jws.Sign(theirJWK, jws.WithKey(jwa.HS256(), hmacKey, jws.WithProtectedHeaders(bindingHeaders)), jws.WithJSON())
	if err != nil {
		t.Fatal(err)
	}

	// Presented while registering my key.
	payload, _ := json.Marshal(map[string]any{"externalAccountBinding": json.RawMessage(binding)})
	body := signedPost(t, mine, map[string]any{
		"alg": "ES256", "nonce": f.nonce(), "url": url, "jwk": publicJWK(t, mine),
	}, payload)
	_, got := post(t, url, body)
	if got["type"] != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized", got)
	}
}
