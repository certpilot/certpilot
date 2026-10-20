package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func noGateways() map[string]bool { return nil }

// The estate gauges are read from the store at scrape time, so they agree with
// the dashboard by construction rather than by two counters kept in step.
func TestTheEstateIsWhatTheStoreSays(t *testing.T) {
	st := store.NewMemoryStore()
	want, err := st.GetDashboardStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want.TotalCertificates == 0 || want.TotalCAs == 0 {
		t.Fatal("the sample store is empty; this test would assert zeros")
	}

	m := New(st, noGateways)
	exposition := scrape(t, m)

	pending, _, _ := st.ListRenewalJobs(context.Background(), store.RenewalJobFilter{Status: store.RenewalPending})
	for series, value := range map[string]int64{
		`certpilot_renewal_jobs{status="PENDING"}`: int64(len(pending)),
		`certpilot_certificates{state="healthy"}`:  want.HealthyCerts,
		`certpilot_certificates{state="expiring"}`: want.ExpiringSoonCerts,
		`certpilot_certificates{state="expired"}`:  want.ExpiredCerts,
		`certpilot_authorities{state="healthy"}`:   want.HealthyCAs,
		`certpilot_authorities{state="warning"}`:   want.WarningCAs,
		`certpilot_authorities{state="critical"}`:  want.CriticalCAs,
		`certpilot_authorities{state="expired"}`:   want.ExpiredCAs,
		`certpilot_authorities{state="unknown"}`:   want.UnknownCAs,
		`certpilot_store_up`:                       1,
	} {
		line := series + " " + itoa(value)
		if !strings.Contains(exposition, "\n"+line+"\n") {
			t.Errorf("missing %q", line)
		}
	}
}

type brokenStore struct{ store.Store }

func (brokenStore) GetDashboardStats(context.Context) (*store.DashboardStats, error) {
	return nil, errors.New("connection refused")
}

// A scrape that cannot read the store has to say so. Reporting zero
// certificates would read as an estate that is fine and empty.
func TestAStoreThatCannotAnswerIsReportedAsDownNotAsEmpty(t *testing.T) {
	m := New(brokenStore{store.NewMemoryStore()}, noGateways)
	exposition := scrape(t, m)

	if !strings.Contains(exposition, "\ncertpilot_store_up 0\n") {
		t.Error("certpilot_store_up is not 0 for a store that failed")
	}
	if strings.Contains(exposition, "certpilot_certificates{") {
		t.Error("certificate gauges were reported from a store that could not be read")
	}
}

func TestEachGatewaysConnectionIsReported(t *testing.T) {
	m := New(store.NewMemoryStore(), func() map[string]bool {
		return map[string]bool{"letsencrypt": true, "vault": false}
	})
	exposition := scrape(t, m)
	for _, line := range []string{
		`certpilot_gateway_connected{gateway="letsencrypt"} 1`,
		`certpilot_gateway_connected{gateway="vault"} 0`,
	} {
		if !strings.Contains(exposition, "\n"+line+"\n") {
			t.Errorf("missing %q", line)
		}
	}
}

// Labelled by the route template, not the path: one series per certificate id
// would grow with the estate until Prometheus fell over.
func TestRequestsAreCountedByRouteNotByPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := New(store.NewMemoryStore(), noGateways)
	r := gin.New()
	r.Use(m.Middleware())
	r.GET("/api/v1/certificates/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, path := range []string{"/api/v1/certificates/a", "/api/v1/certificates/b", "/nowhere/1", "/nowhere/2"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}

	if got := testutil.ToFloat64(m.requests.WithLabelValues("GET", "/api/v1/certificates/:id", "200")); got != 2 {
		t.Errorf("requests to the certificate route = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("GET", "unmatched", "404")); got != 2 {
		t.Errorf("unmatched requests = %v, want 2 under one label", got)
	}
	if n := testutil.CollectAndCount(m.requests); n != 2 {
		t.Errorf("request series = %d, want 2", n)
	}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d", rec.Code)
	}
	return "\n" + rec.Body.String()
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

// A configured gateway that has never connected is not in the plugin
// manager's map at all, so it would have had no series, and an alert on
// certpilot_gateway_connected == 0 would never fire for the gateway that was
// down from the start.
func TestAConfiguredGatewayThatNeverConnectedReadsZero(t *testing.T) {
	states := WithConfigured([]string{"selfsigned", "letsencrypt"}, func() map[string]bool {
		return map[string]bool{"letsencrypt": true}
	})
	got := states()
	if v, ok := got["selfsigned"]; !ok || v {
		t.Fatalf("never-connected selfsigned = %v (present %v), want present and false", v, ok)
	}
	if !got["letsencrypt"] {
		t.Fatal("a connected gateway was reported as disconnected")
	}
}

// The method is the client's to choose, so it cannot be a label as sent: a
// scanner inventing methods would mint a series per invention.
func TestAnInventedMethodDoesNotMintASeries(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := New(store.NewMemoryStore(), noGateways)
	r := gin.New()
	r.Use(m.Middleware())
	for _, method := range []string{"FOO1", "FOO2", "BREW", "GET"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, "/nowhere", nil))
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("OTHER", "unmatched", "404")); got != 3 {
		t.Errorf("invented methods = %v, want 3 under OTHER", got)
	}
	if n := testutil.CollectAndCount(m.requests); n != 2 {
		t.Errorf("request series = %d, want 2 (OTHER and GET)", n)
	}
}

type countingStore struct {
	store.Store
	calls int
}

func (c *countingStore) GetDashboardStats(ctx context.Context) (*store.DashboardStats, error) {
	c.calls++
	return c.Store.GetDashboardStats(ctx)
}

// Each scrape costs several queries. Whoever can reach the port should not be
// able to turn scrape requests into database load one for one.
func TestScrapesInQuickSuccessionReadTheStoreOnce(t *testing.T) {
	st := &countingStore{Store: store.NewMemoryStore()}
	m := New(st, noGateways)
	for range 5 {
		scrape(t, m)
	}
	if st.calls != 1 {
		t.Fatalf("five scrapes read the store %d times, want 1", st.calls)
	}
}

func TestATokenIsRequiredWhenOneIsSet(t *testing.T) {
	m := New(store.NewMemoryStore(), noGateways, WithBearerToken("s3cret-token"))
	for name, header := range map[string]string{"none": "", "wrong": "Bearer nope", "basic": "Basic czNjcmV0LXRva2Vu"} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		m.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: /metrics = %d, want 401", name, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret-token")
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("with the token, /metrics = %d, want 200", rec.Code)
	}
}
