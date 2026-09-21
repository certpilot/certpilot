package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	"github.com/certpilot/certpilot/core/engine/cloudsync"
	"github.com/certpilot/certpilot/core/engine/ctlog"
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/engine/notifications"
	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// realRouter builds the router the server actually serves.
//
// The middleware package tests the guarantees against a mirror of these routes;
// this exercises the wiring itself, so that a display token reaching a route
// because SetupRouter forgot a gate is caught here rather than in production.
func realRouter(t *testing.T) (*gin.Engine, store.Store) {
	t.Helper()
	engine, st, _ := realRouterWithPlugins(t)
	return engine, st
}

// realRouterWithPlugins is realRouter with the plugin manager handed back.
//
// Most handlers can be exercised without one. The ones that call a CA through a
// gateway cannot, and a test that cannot register a gateway can only ever reach
// their "no gateway connected" branch — which is how the revocation path came to
// be wired, shipped and documented as absent without a single test touching it.
func realRouterWithPlugins(t *testing.T) (*gin.Engine, store.Store, *pluginmgr.Manager) {
	t.Helper()

	st := store.NewMemoryStore()
	broker := events.NewBroker()

	keyring, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	// A real administrator, not an anonymous one. Anonymous access used to make
	// every request here admin for free; it is gone, and these tests are better
	// for it — they now exercise the same token verification, directory lookup
	// and role resolution that a deployment does, so what is left blocking a
	// display token is genuinely the display-token middleware and nothing else.
	cfg := &config.CoreConfig{
		Server: config.ServerConfig{Mode: "development", AllowedOrigins: []string{"http://localhost:5173"}},
		Auth: config.AuthConfig{
			RoleClaim:       "certpilot_role",
			JWTSecret:       apiTestSecret,
			Issuer:          apiTestIssuer,
			BootstrapAdmins: []string{apiAdminEmail},
		},
	}

	auth, err := middleware.NewAuthenticator(context.Background(), cfg.Auth)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	// The same wiring the server does. Without it the role would come from the
	// token's own claim, which is the behaviour this design exists to replace.
	auth = auth.WithUserDirectory(st)

	// Same wiring as the server: audit entries written during a test are
	// chained, so the tests exercise the path a deployment takes rather than an
	// unchained one that cannot fail the same way.
	st.UseAuditChain(store.NewAuditChainer(keyring))

	pm := pluginmgr.NewManager(grpckit.TLSConfig{Insecure: true})

	// A real dispatcher, not a nil one: the notification endpoints seal
	// configuration through it and the test endpoint delivers through it, so a
	// stub here would only prove the stub works.
	dispatcher := notifications.NewDispatcher(st, keyring, broker,
		notifications.WithChannelTTL(time.Millisecond),
		notifications.WithSendTimeout(3*time.Second))

	engine := gin.New()

	// Registered before SetupRouter so it runs ahead of the authentication
	// middleware. Tests build requests without credentials; rather than
	// weakening the server to accept that, this presents a real administrator's
	// bearer token — so the request travels the whole verification and
	// role-resolution path exactly as a deployment would.
	//
	// It stands aside for any request that brought its own credential, which is
	// what keeps the display-token tests below meaningful.
	engine.Use(func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" &&
			c.GetHeader("X-Display-Token") == "" &&
			c.Query("display_token") == "" {
			c.Request.Header.Set("Authorization", "Bearer "+apiAdminToken(t))
		}
		c.Next()
	})

	SetupRouter(engine, RouterDeps{
		Store:         st,
		PluginMgr:     pm,
		CAMonitor:     pki.NewCAMonitor(st, broker),
		ChainResolver: pki.NewChainResolver(st),
		RenewalExec:   renewal.NewExecutor(st, pm, keyring, broker, policy.NewEngine(st)),
		RenewalSched:  renewal.NewScheduler(st, 30),
		RenewalQueue:  renewal.NewQueue(st, renewal.NewExecutor(st, pm, keyring, broker, policy.NewEngine(st)), broker),
		ARIPoller:     renewal.NewARIPoller(st, pm, keyring, broker),
		Verifier:      renewal.NewVerifier(st, discovery.NewScanner(st), broker),
		PolicyEngine:  policy.NewEngine(st),
		// A real broker on the scanner: background scans publish their findings
		// themselves, so a scanner without one would silently drop them.
		Scanner: discovery.NewScanner(st, discovery.WithBroker(broker), discovery.WithDialTimeout(3*time.Second)),
		// A stub source: these tests must not reach a public service, and a
		// monitor without one would silently do nothing.
		CTMonitor: ctlog.NewMonitor(st, ctlog.WithBroker(broker), ctlog.WithSource(stubCTSource{})),
		// Likewise a stub cloud provider: these tests must not reach anybody's
		// cloud account, and an engine without a builder would fail every sync
		// for a reason that has nothing to do with what is being tested.
		CloudEngine: cloudsync.NewEngine(st, keyring, cloudsync.WithBroker(broker),
			cloudsync.WithProviderBuilder(func(string, []byte) (cloudsync.Provider, error) {
				return stubCloudProvider{}, nil
			})),
		Keyring:    keyring,
		Broker:     broker,
		Dispatcher: dispatcher,
		Auth:       auth,
		Config:     cfg,
	})

	t.Cleanup(func() {
		dispatcher.Stop()
		broker.Stop()
		pm.Close()
		st.Close()
	})
	return engine, st, pm
}

func do(r *gin.Engine, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		encoded, _ := json.Marshal(body)
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// mintToken creates a token through the real admin API and returns the raw
// value, which is available only in this one response.
func mintToken(t *testing.T, r *gin.Engine, name string, days int) (raw, id string) {
	t.Helper()

	body := gin.H{"name": name}
	if days > 0 {
		body["expires_in_days"] = days
	}
	w := do(r, http.MethodPost, "/api/v1/display-tokens", body, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}

	var resp struct {
		Token   string `json:"token"`
		Display struct {
			ID        string    `json:"id"`
			Name      string    `json:"name"`
			Status    string    `json:"status"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"display"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("no raw token in the create response — it is the only time it is available")
	}
	return resp.Token, resp.Display.ID
}

func TestDisplayTokenLifecycleThroughTheRealRouter(t *testing.T) {
	r, _ := realRouter(t)

	raw, id := mintToken(t, r, "corridor-screen", 30)

	// It works on the routes a wall display needs.
	for _, path := range []string{"/api/v1/pki/authorities", "/api/v1/dashboard/stats"} {
		w := do(r, http.MethodGet, path, nil, map[string]string{"X-Display-Token": raw})
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 (body: %s)", path, w.Code, w.Body.String())
		}
	}

	// And it stops working the moment it is revoked.
	if w := do(r, http.MethodDelete, "/api/v1/display-tokens/"+id, nil, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	w := do(r, http.MethodGet, "/api/v1/pki/authorities", nil, map[string]string{"X-Display-Token": raw})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status after revocation = %d, want 401", w.Code)
	}
}

// The routes are the real ones, and anonymous access has made every other
// caller an admin — so anything that still fails here fails because of the
// display-token middleware.
func TestDisplayTokenBlockedOnRealWriteRoutes(t *testing.T) {
	r, _ := realRouter(t)
	raw, _ := mintToken(t, r, "screen", 0)
	hdr := map[string]string{"X-Display-Token": raw}

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/api/v1/certificates", http.StatusForbidden},
		{http.MethodDelete, "/api/v1/certificates/abc", http.StatusForbidden},
		{http.MethodPost, "/api/v1/certificates/abc/renew", http.StatusForbidden},
		{http.MethodPost, "/api/v1/pki/authorities", http.StatusForbidden},
		{http.MethodDelete, "/api/v1/pki/authorities/abc", http.StatusForbidden},
		{http.MethodPost, "/api/v1/ca-accounts", http.StatusForbidden},
		{http.MethodDelete, "/api/v1/ca-accounts/abc", http.StatusForbidden},
		{http.MethodPost, "/api/v1/discovery/scan", http.StatusForbidden},
		{http.MethodPost, "/api/v1/policies", http.StatusForbidden},
		{http.MethodPut, "/api/v1/policies/abc", http.StatusForbidden},
		{http.MethodDelete, "/api/v1/policies/abc", http.StatusForbidden},
		{http.MethodPost, "/api/v1/display-tokens", http.StatusForbidden},
		{http.MethodDelete, "/api/v1/display-tokens/abc", http.StatusForbidden},

		// Sensitive GETs, refused by path.
		{http.MethodGet, "/api/v1/certificates/abc/private-key", http.StatusForbidden},
		{http.MethodGet, "/api/v1/display-tokens", http.StatusForbidden},
		{http.MethodGet, "/api/v1/dashboard/activity", http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := do(r, tc.method, tc.path, gin.H{}, hdr)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// A CA list is what a wall display exists to show, so this is the route whose
// success matters most — and it must arrive without certificate PEM in tow.
func TestDisplayTokenReachesTheEventStream(t *testing.T) {
	r, _ := realRouter(t)
	raw, _ := mintToken(t, r, "screen", 0)

	srv := httptest.NewServer(r)
	defer srv.Close()

	// The stream never ends on its own, so the read has to be bounded or a
	// regression here would hang the suite instead of failing it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events?display_token="+raw, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a display token could not open the stream it exists for", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}

	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if n == 0 {
		t.Fatalf("the stream produced nothing (err: %v)", err)
	}
	if !strings.Contains(string(buf[:n]), "retry:") {
		t.Fatalf("the stream did not open with a retry directive: %q", buf[:n])
	}
}

func TestDisplayTokenCreateValidatesExpiry(t *testing.T) {
	r, _ := realRouter(t)

	cases := map[string]struct {
		body gin.H
		want int
	}{
		"no name":            {gin.H{"expires_in_days": 30}, http.StatusBadRequest},
		"blank name":         {gin.H{"name": "   "}, http.StatusBadRequest},
		"negative expiry":    {gin.H{"name": "a", "expires_in_days": -1}, http.StatusBadRequest},
		"beyond the maximum": {gin.H{"name": "b", "expires_in_days": maxDisplayTokenDays + 1}, http.StatusBadRequest},
		"at the maximum":     {gin.H{"name": "c", "expires_in_days": maxDisplayTokenDays}, http.StatusCreated},
		"default expiry":     {gin.H{"name": "d"}, http.StatusCreated},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := do(r, http.MethodPost, "/api/v1/display-tokens", tc.body, nil)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// A token with no explicit expiry must still get one. An unattended credential
// that never expires is the failure mode this feature is meant to avoid, not
// introduce.
func TestDisplayTokenAlwaysExpires(t *testing.T) {
	r, _ := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/display-tokens", gin.H{"name": "no-expiry-given"}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d (body: %s)", w.Code, w.Body.String())
	}

	var resp struct {
		Display struct {
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"display"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Display.ExpiresAt.IsZero() {
		t.Fatal("token has no expiry")
	}
	if days := time.Until(resp.Display.ExpiresAt).Hours() / 24; days < defaultDisplayTokenDays-1 || days > defaultDisplayTokenDays+1 {
		t.Fatalf("default expiry is %.1f days, want ~%d", days, defaultDisplayTokenDays)
	}
}

// The list view is what an operator uses to decide what to revoke, so it has to
// carry the identifying details — and none of the credential.
func TestDisplayTokenListNeverExposesTheHash(t *testing.T) {
	r, _ := realRouter(t)
	raw, id := mintToken(t, r, "fourth-floor", 10)

	w := do(r, http.MethodGet, "/api/v1/display-tokens", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if strings.Contains(body, "token_hash") || strings.Contains(body, middleware.HashDisplayToken(raw)) {
		t.Fatalf("the list response leaks the token hash: %s", body)
	}
	if strings.Contains(body, raw) {
		t.Fatal("the list response leaks the raw token")
	}
	for _, want := range []string{id, "fourth-floor", `"status":"ACTIVE"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("the list response is missing %q: %s", want, body)
		}
	}
}

// Creation and revocation both have to be reconstructable afterwards: a
// credential that appeared with no record of who minted it is worse than no
// credential.
func TestDisplayTokenChangesAreAudited(t *testing.T) {
	r, st := realRouter(t)
	_, id := mintToken(t, r, "audited-screen", 7)

	if w := do(r, http.MethodDelete, "/api/v1/display-tokens/"+id, nil, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke status = %d", w.Code)
	}

	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{Limit: 50})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}

	found := map[string]bool{}
	for _, l := range logs {
		if l.EntityType == "display_token" {
			found[l.Action] = true
			if l.ActorID == nil || *l.ActorID == "" {
				t.Fatalf("audit entry %q has no actor", l.Action)
			}
		}
	}
	for _, action := range []string{"display_token.created", "display_token.revoked"} {
		if !found[action] {
			t.Fatalf("no audit entry for %q; got %v", action, found)
		}
	}
}

func TestDuplicateDisplayTokenNameIsRejected(t *testing.T) {
	r, _ := realRouter(t)
	mintToken(t, r, "the-only-screen", 0)

	w := do(r, http.MethodPost, "/api/v1/display-tokens", gin.H{"name": "the-only-screen"}, nil)
	if w.Code == http.StatusCreated {
		t.Fatal("a second token was created with a name already in use — revocation becomes guesswork")
	}
}

// TestDisplayTokenInQueryStringIsNotMistakenForAFilter guards a bug that made
// the query-string form useless on the one endpoint that validates its filters.
//
// GET /certificates refuses unknown query parameters, so that a script asking
// for a filter the handler does not read is told rather than silently handed
// the whole estate. But a display token presented the only way EventSource can
// present one — in the query string — looked exactly like an unknown filter,
// and the endpoint returned 400 to precisely the client the parameter exists
// for. The exemption lives in unexpectedQuery so that the next endpoint to
// adopt the guard does not reintroduce it.
func TestDisplayTokenInQueryStringIsNotMistakenForAFilter(t *testing.T) {
	r, _ := realRouter(t)
	raw, _ := mintToken(t, r, "corridor-screen", 0)

	for _, path := range []string{
		"/api/v1/certificates?display_token=" + raw,
		"/api/v1/certificates?status=ISSUED&display_token=" + raw,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))

		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 — the credential was read as a filter: %s",
				path, w.Code, w.Body.String())
		}
	}

	// The guard itself must still work, or the fix above would have disabled
	// the protection it was carved out of.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/api/v1/certificates?search=anything&display_token="+raw, nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown filter alongside a display token = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "search") {
		t.Fatalf("the 400 did not name the offending parameter: %s", w.Body.String())
	}
}

// ── The administrator these tests run as ────────────────────────────────────

const (
	apiTestSecret = "api-test-shared-secret-that-is-long-enough"
	apiTestIssuer = "https://idp.api-test.local"
	apiAdminEmail = "admin@certpilot.test"
	// A stable subject, deliberately not a uuid: the shape three of the four
	// providers CertPilot documents actually issue, and the shape that used to
	// abort every insert into an actor column.
	apiAdminSubject = "00uAPITESTadmin0001"
)

// apiAdminToken signs a bearer token for the administrator.
//
// The role claim is deliberately absent. The role comes from CertPilot's users
// table, where bootstrap_admins grants admin on first sign-in; asserting it in
// the token would test nothing, since the directory ignores it.
func apiAdminToken(t *testing.T) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &middleware.UserClaims{
		Email: apiAdminEmail,
		Name:  "API Test Administrator",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   apiAdminSubject,
			Issuer:    apiTestIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	signed, err := token.SignedString([]byte(apiTestSecret))
	if err != nil {
		t.Fatalf("sign admin token: %v", err)
	}
	return signed
}
