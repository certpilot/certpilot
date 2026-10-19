// Package metrics exposes the core's state to Prometheus.
//
// Two kinds of series. The estate — certificates and CAs by state, the renewal
// and deployment queues, gateway connections — is read from the store and the
// plugin manager at scrape time, so it agrees with the dashboard by
// construction rather than by two counters being kept in step, and every
// replica reports the same numbers (aggregate with max, not sum). Requests are
// counted as they happen, per replica.
//
// Served on its own listener (metrics.listen), never on the API's: a scrape
// endpoint is unauthenticated by convention, and the estate's shape is not
// something to publish through the console's proxy.
package metrics

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// scrapeTimeout bounds the store reads one scrape makes. Prometheus's own
// default timeout is ten seconds; a scrape that waits on a stuck database for
// longer than this reports the store as down instead.
const scrapeTimeout = 5 * time.Second

// Metrics owns the registry and the request instruments.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// New builds the registry. gateways reports each gateway's connection state by
// name; it is called on every scrape.
func New(st store.Store, gateways func() map[string]bool) *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "certpilot_http_requests_total",
			Help: "HTTP requests served, by method, route template and status code.",
		}, []string{"method", "route", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "certpilot_http_request_duration_seconds",
			Help:    "Time to serve an HTTP request, by method and route template. Excludes the event stream.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
	}
	m.registry.MustRegister(
		m.requests,
		m.duration,
		&estate{store: st, gateways: gateways},
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Handler serves the exposition.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Middleware counts and times requests.
//
// The route label is the template gin matched ("/api/v1/certificates/:id"),
// never the path: a label per certificate id would grow with the estate. A
// request that matched nothing is "unmatched", for the same reason — a scanner
// walking random paths must not mint series.
func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		method := c.Request.Method
		m.requests.WithLabelValues(method, route, strconv.Itoa(c.Writer.Status())).Inc()
		// The event stream is held open for hours; its duration would swamp
		// every bucket and say nothing.
		if route != "/api/v1/events" {
			m.duration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
		}
	}
}

var (
	certificatesDesc = prometheus.NewDesc("certpilot_certificates",
		"Managed certificates, by state: healthy, expiring (inside its renewal lead), expired.",
		[]string{"state"}, nil)
	authoritiesDesc = prometheus.NewDesc("certpilot_authorities",
		"Monitored certificate authorities, by health: healthy, warning, critical, expired, unknown.",
		[]string{"state"}, nil)
	renewalJobsDesc = prometheus.NewDesc("certpilot_renewal_jobs",
		"Renewal jobs by status. FAILED is the history of terminal failures, not only today's.",
		[]string{"status"}, nil)
	renewalEscalatedDesc = prometheus.NewDesc("certpilot_renewal_jobs_escalated",
		"Renewal jobs that need a person to look at them.", nil, nil)
	deploymentJobsDesc = prometheus.NewDesc("certpilot_deployment_jobs",
		"Deployment jobs by status.", []string{"status"}, nil)
	gatewayDesc = prometheus.NewDesc("certpilot_gateway_connected",
		"1 if the core is connected to the gateway, 0 if not.", []string{"gateway"}, nil)
	storeUpDesc = prometheus.NewDesc("certpilot_store_up",
		"1 if the last scrape could read the store, 0 if not. The estate series are absent when it is 0.",
		nil, nil)
)

// estate is a collector that reads the current state on every scrape.
type estate struct {
	store    store.Store
	gateways func() map[string]bool
}

func (e *estate) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{certificatesDesc, authoritiesDesc, renewalJobsDesc,
		renewalEscalatedDesc, deploymentJobsDesc, gatewayDesc, storeUpDesc} {
		ch <- d
	}
}

func (e *estate) Collect(ch chan<- prometheus.Metric) {
	for name, connected := range e.gateways() {
		ch <- prometheus.MustNewConstMetric(gatewayDesc, prometheus.GaugeValue, boolValue(connected), name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()

	// All or nothing: a scrape that read half the estate would publish a
	// picture nobody could tell was partial. Zero certificates must mean zero
	// certificates, never "the query failed".
	var out []prometheus.Metric
	err := func() error {
		stats, err := e.store.GetDashboardStats(ctx)
		if err != nil {
			return err
		}
		gauge := func(d *prometheus.Desc, v int64, label ...string) {
			out = append(out, prometheus.MustNewConstMetric(d, prometheus.GaugeValue, float64(v), label...))
		}
		gauge(certificatesDesc, stats.HealthyCerts, "healthy")
		gauge(certificatesDesc, stats.ExpiringSoonCerts, "expiring")
		gauge(certificatesDesc, stats.ExpiredCerts, "expired")
		gauge(authoritiesDesc, stats.HealthyCAs, "healthy")
		gauge(authoritiesDesc, stats.WarningCAs, "warning")
		gauge(authoritiesDesc, stats.CriticalCAs, "critical")
		gauge(authoritiesDesc, stats.ExpiredCAs, "expired")
		gauge(authoritiesDesc, stats.UnknownCAs, "unknown")

		for _, status := range []string{store.RenewalPending, store.RenewalRunning, store.RenewalFailed} {
			_, n, err := e.store.ListRenewalJobs(ctx, store.RenewalJobFilter{Status: status, Limit: 1})
			if err != nil {
				return err
			}
			gauge(renewalJobsDesc, n, status)
		}
		_, n, err := e.store.ListRenewalJobs(ctx, store.RenewalJobFilter{EscalatedOnly: true, Limit: 1})
		if err != nil {
			return err
		}
		gauge(renewalEscalatedDesc, n)

		for _, status := range []string{store.DeployPending, store.DeployRunning, store.DeployFailed} {
			_, n, err := e.store.ListDeploymentJobs(ctx, store.DeploymentJobFilter{Status: status, Limit: 1})
			if err != nil {
				return err
			}
			gauge(deploymentJobsDesc, n, status)
		}
		return nil
	}()
	if err != nil {
		slog.Warn("metrics: could not read the estate from the store", "error", err)
		ch <- prometheus.MustNewConstMetric(storeUpDesc, prometheus.GaugeValue, 0)
		return
	}
	for _, metric := range out {
		ch <- metric
	}
	ch <- prometheus.MustNewConstMetric(storeUpDesc, prometheus.GaugeValue, 1)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// WithConfigured adds every configured gateway name that the plugin manager
// does not know about yet, as disconnected. The manager only tracks a gateway
// once it has connected, so one that was down from the start would otherwise
// have no series at all.
func WithConfigured(names []string, states func() map[string]bool) func() map[string]bool {
	return func() map[string]bool {
		out := states()
		if out == nil {
			out = make(map[string]bool, len(names))
		}
		for _, name := range names {
			if _, ok := out[name]; !ok {
				out[name] = false
			}
		}
		return out
	}
}
