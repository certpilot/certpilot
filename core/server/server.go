package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	"github.com/certpilot/certpilot/core/api"
	"github.com/certpilot/certpilot/core/engine/cloudsync"
	"github.com/certpilot/certpilot/core/engine/ctlog"
	"github.com/certpilot/certpilot/core/engine/deploy"
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/engine/fleet"
	"github.com/certpilot/certpilot/core/engine/notifications"
	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/posture"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// Server encapsulates the HTTP API server and background engines.
type Server struct {
	httpServer   *http.Server
	store        store.Store
	pluginMgr    *pluginmgr.Manager
	caMonitor    *pki.CAMonitor
	caImporter   *pki.Importer
	dispatcher   *notifications.Dispatcher
	broker       *events.Broker
	renewalSched *renewal.Scheduler
	renewalQueue *renewal.Queue
	ariPoller    *renewal.ARIPoller
	verifier     *renewal.Verifier
	scanner      *discovery.Scanner
	discoverySch *discovery.Scheduler
	ctMonitor    *ctlog.Monitor
	cloudEngine  *cloudsync.Engine
	deployQueue  *deploy.Queue
	assessor     *posture.Assessor
	fleetMonitor *fleet.Monitor
	rateLimiter  *middleware.RateLimiter
	cfg          *config.CoreConfig
}

// NewServer initializes the store, keyring, plugin manager, background engines,
// and HTTP routes.
func NewServer(ctx context.Context, cfg *config.CoreConfig, dbConnStr string) (*Server, error) {
	if cfg.Server.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	// 1. Store. A failed database connection is fatal when one was configured:
	// silently falling back to an in-memory store would let a production
	// deployment come up healthy and lose every certificate it issued.
	var st store.Store
	usingMemoryStore := false
	if dbConnStr != "" {
		pgStore, err := store.NewPostgresStore(ctx, dbConnStr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to the database: %w", err)
		}
		st = pgStore
	} else {
		if cfg.Server.IsProduction() {
			return nil, fmt.Errorf("no database connection string configured; production mode requires a database")
		}
		slog.Warn("no database configured; using the in-memory store with sample data. Nothing is persisted")
		st = store.NewMemoryStore()
		usingMemoryStore = true
	}

	// 2. Keyring. Certificate private keys and CA credentials are sealed before
	// they reach the store, so a keyring is required whenever the store is.
	keyring, err := loadKeyring(ctx, cfg.Secrets, usingMemoryStore)
	if err != nil {
		st.Close()
		return nil, err
	}

	// The audit log is chained with a subkey of the same KEK. Wired here rather
	// than at store construction because the store is built first — and wired
	// unconditionally, because an audit log that is only sometimes
	// tamper-evident is one nobody can reason about.
	st.UseAuditChain(store.NewAuditChainer(keyring))

	// 3. Plugin manager.
	gwTLS := grpckit.TLSConfig{
		CertFile: cfg.Plugins.TLS.CertFile,
		KeyFile:  cfg.Plugins.TLS.KeyFile,
		CAFile:   cfg.Plugins.TLS.CAFile,
		Insecure: cfg.Plugins.TLS.Insecure,
	}
	if err := gwTLS.Validate(); err != nil {
		st.Close()
		return nil, fmt.Errorf("gateway TLS configuration is invalid: %w (generate development material with: make dev-certs)", err)
	}
	pm := pluginmgr.NewManager(gwTLS)

	for _, gw := range cfg.Plugins.Gateways {
		if gw.Addr == "" {
			continue
		}
		if _, err := pm.RegisterGateway(ctx, gw.Name, gw.Addr, gw.Type, gw.ServerName); err != nil {
			// A gateway that is down at startup is expected — it may simply
			// not be running yet — so this is a warning, and reconnection
			// happens on demand.
			slog.Warn("could not connect to configured gateway at startup",
				"name", gw.Name, "addr", gw.Addr, "error", err)
		}
	}

	// 4. Engines.
	//
	// The broker fans changes out to the dashboard stream and the notification
	// dispatcher. Nothing in the publish path can be blocked by a consumer, so
	// a stalled screen cannot stall the CA health sweep.
	broker := events.NewBroker()

	caMonitor := pki.NewCAMonitor(st, broker)
	// The other half of knowing about a CA: the monitor watches the ones that
	// are recorded, and this is what records them. Until it existed, the CA
	// signing an entire estate was in the inventory only if somebody had
	// pasted its certificate in by hand.
	caImporter := pki.NewImporter(st, pm, keyring, broker)
	chainResolver := pki.NewChainResolver(st)
	// Declared here rather than further down because renewal needs it. That is
	// the point of this change: the sweep is the only component that touches
	// every managed certificate on a timer, so it is the only place a policy
	// change can reach an estate that already exists.
	policyEng := policy.NewEngine(st)
	renewalExec := renewal.NewExecutor(st, pm, keyring, broker, policyEng)
	// The sweep finds what is due and enqueues it; the queue runs it. Both
	// safe on every replica: enqueues collide on a partial unique index and
	// claims use FOR UPDATE SKIP LOCKED, so nothing here needs a leader — and
	// so nothing here has a failover window during which no certificate renews.
	renewalSched := renewal.NewScheduler(st, cfg.Renewal.DefaultLeadDays)
	renewalQueue := renewal.NewQueue(st, renewalExec, broker)
	// The gateway has been able to read RFC 9773 renewal information since
	// phase 2; nothing ever asked. This is the part that asks — and that
	// notices when a CA pulls a window forward, which during a mass revocation
	// is the only automated warning anybody gets.
	ariPoller := renewal.NewARIPoller(st, pm, keyring, broker)
	// The scanner publishes progress so a range scan is visible while it runs,
	// not only once it is over.
	scanner := discovery.NewScanner(st, discovery.WithBroker(broker))
	// And the part that closes the loop: a renewal is not done when the
	// certificate is stored, it is done when the thing serving it is serving
	// it. Uses the discovery scanner, because "what is this endpoint actually
	// presenting" is a question already answered well.
	verifier := renewal.NewVerifier(st, scanner, broker)
	// Discovery run once is a snapshot; run on a schedule it is monitoring.
	discoverySch := discovery.NewScheduler(st, scanner)
	// Certificate Transparency reaches what a scan cannot: certificates issued
	// for these domains that were never deployed anywhere CertPilot can see.
	ctMonitor := ctlog.NewMonitor(st, ctlog.WithBroker(broker))
	// And the third place: certificates that are stored rather than served —
	// in ACM, a Key Vault, a GCP load balancer, a Kubernetes secret — which no
	// scan has an address for and no transparency log will ever mention if
	// they came from an internal CA.
	cloudEngine := cloudsync.NewEngine(st, keyring, cloudsync.WithBroker(broker))
	// And the other half of renewal. Everything above observes; this changes
	// something that is already carrying traffic, so it is a durable queue with
	// leases and an attempt log for exactly the reasons renewal is.
	deployExec := deploy.NewExecutor(st, keyring, broker)
	deployQueue := deploy.NewQueue(st, deployExec, broker)
	// Cryptographic posture. A sweep rather than a hook at issuance: there are
	// six ways a certificate arrives in this system and a hook on each would be
	// six places to forget.
	assessor := posture.NewAssessor(st)
	// And the hosts that are supposed to be maintaining themselves. An agent
	// that stopped reporting looks exactly like a healthy one on a list that
	// counts enrolled agents, which is why something has to go and look.
	fleetMonitor := fleet.NewMonitor(st, broker)

	// The dispatcher is an ordinary broker subscriber. That is the point: it
	// makes outbound HTTP and SMTP calls, and a wedged destination can only cost
	// it its own place in the queue, never stall the CA health sweep.
	dispatcher := notifications.NewDispatcher(st, keyring, broker)

	// 5. Authentication.
	authenticator, err := middleware.NewAuthenticator(ctx, cfg.Auth)
	if err != nil {
		st.Close()
		return nil, err
	}
	// The identity provider says who somebody is; CertPilot says what they may
	// do. Without this the role falls back to whatever claim the token carries,
	// which puts every promotion and demotion in the hands of an administrator
	// of the provider rather than of the team that owns the CA hierarchy.
	authenticator = authenticator.WithUserDirectory(st)

	// A negative rate is an explicit opt-out, for a deployment with something
	// in front of it already shaping traffic. Zero means the defaults, so an
	// operator who has never thought about it still gets a limit.
	var limiter *middleware.RateLimiter
	if cfg.Auth.RateLimitPerSecond >= 0 {
		rlCfg := middleware.DefaultAPIRateLimit
		if cfg.Auth.RateLimitPerSecond > 0 {
			rlCfg.Rate = cfg.Auth.RateLimitPerSecond
		}
		if cfg.Auth.RateLimitBurst > 0 {
			rlCfg.Burst = cfg.Auth.RateLimitBurst
		}
		limiter = middleware.NewRateLimiter(rlCfg)
	}

	// Before the router is built, so that an instance nobody can sign in to is
	// reported at start-up rather than discovered at the login screen.
	if err := bootstrapFirstAdmin(ctx, st, cfg.Auth); err != nil {
		st.Close()
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// 6. HTTP router.
	engine := gin.New()
	// Not gin.Logger(): it writes the full request target, and display tokens
	// travel in the query string because EventSource cannot set a header.
	engine.Use(middleware.RequestLogger())

	api.SetupRouter(engine, api.RouterDeps{
		Store:         st,
		PluginMgr:     pm,
		CAMonitor:     caMonitor,
		CAImporter:    caImporter,
		ChainResolver: chainResolver,
		RenewalExec:   renewalExec,
		RenewalSched:  renewalSched,
		RenewalQueue:  renewalQueue,
		DeployQueue:   deployQueue,
		ARIPoller:     ariPoller,
		Verifier:      verifier,
		PolicyEngine:  policyEng,
		Scanner:       scanner,
		CTMonitor:     ctMonitor,
		CloudEngine:   cloudEngine,
		Keyring:       keyring,
		Broker:        broker,
		Dispatcher:    dispatcher,
		Auth:          authenticator,
		RateLimiter:   limiter,
		Config:        cfg,
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return &Server{
		httpServer:   httpSrv,
		store:        st,
		pluginMgr:    pm,
		caMonitor:    caMonitor,
		caImporter:   caImporter,
		dispatcher:   dispatcher,
		broker:       broker,
		renewalSched: renewalSched,
		renewalQueue: renewalQueue,
		ariPoller:    ariPoller,
		verifier:     verifier,
		scanner:      scanner,
		discoverySch: discoverySch,
		ctMonitor:    ctMonitor,
		cloudEngine:  cloudEngine,
		deployQueue:  deployQueue,
		assessor:     assessor,
		fleetMonitor: fleetMonitor,
		rateLimiter:  limiter,
		cfg:          cfg,
	}, nil
}

// loadKeyring resolves the key encryption key.
//
// An ephemeral key is acceptable only alongside the in-memory store, where
// nothing outlives the process anyway. Against a real database it would render
// every stored secret unreadable on restart, so it is refused.
func loadKeyring(ctx context.Context, cfg config.SecretsConfig, usingMemoryStore bool) (*secrets.Keyring, error) {
	provider, err := kekProvider(cfg)
	if err != nil {
		return nil, err
	}

	keyring, err := secrets.LoadKeyringFrom(ctx, provider)
	if err == nil {
		// The provider is named in the log. On a machine where somebody has
		// just moved the key out of the environment, "which one did it
		// actually use" is the first question, and the answer must not require
		// reading the configuration back.
		slog.Info("loaded secret encryption keyring",
			"key_id", keyring.PrimaryKeyID(), "provider", provider.Name())
		return keyring, nil
	}

	if !errors.Is(err, secrets.ErrNoKey) {
		return nil, err
	}

	// Only the environment provider falls through to an ephemeral key. A
	// configured file or Vault provider that produced nothing is a
	// misconfiguration somebody needs to fix, and quietly inventing a key would
	// hide it behind a working start-up.
	if _, isEnv := provider.(secrets.EnvProvider); !isEnv {
		return nil, fmt.Errorf(
			"no key encryption key was returned by %s. CertPilot stores certificate private keys "+
				"and CA credentials encrypted at rest and will not start without one", provider.Name())
	}

	if !usingMemoryStore {
		return nil, fmt.Errorf(
			"CERTPILOT_KEK is not set. CertPilot stores certificate private keys and CA credentials " +
				"encrypted at rest and will not start without a key. Generate one with: make generate-kek, " +
				"or set secrets.kek_provider to read it from a file or from Vault")
	}

	keyring, err = secrets.NewEphemeralKeyring()
	if err != nil {
		return nil, err
	}
	slog.Warn("CERTPILOT_KEK is not set; using an ephemeral key alongside the in-memory store. " +
		"Set CERTPILOT_KEK before configuring a database")
	return keyring, nil
}

// kekProvider turns configuration into the thing that fetches the key.
//
// The configuration has already been validated, so a bad provider name cannot
// reach here — but the default is spelled out rather than left to a fallthrough,
// because "unrecognised, so use the environment" is exactly how a typo in
// kek_provider would leave the key in an env var somebody believed they had
// stopped using.
func kekProvider(cfg config.SecretsConfig) (secrets.Provider, error) {
	switch cfg.KEKProvider {
	case "", "env":
		return secrets.EnvProvider{}, nil

	case "file":
		return secrets.FileProvider{
			Path:         cfg.KEKFile,
			RetiredPaths: cfg.KEKRetiredFiles,
		}, nil

	case "vault":
		client, err := vaultClient(cfg.Vault)
		if err != nil {
			return nil, err
		}
		return secrets.VaultProvider{
			Address:      cfg.Vault.Address,
			Path:         cfg.Vault.Path,
			Field:        cfg.Vault.Field,
			RetiredField: cfg.Vault.RetiredField,
			Token:        cfg.Vault.Token,
			TokenFile:    cfg.Vault.TokenFile,
			Namespace:    cfg.Vault.Namespace,
			Client:       client,
		}, nil

	default:
		return nil, fmt.Errorf("secrets.kek_provider %q is not one of env, file, vault", cfg.KEKProvider)
	}
}

// vaultClient builds the HTTP client, pinning Vault's CA when one is given.
func vaultClient(cfg config.VaultSecretsConfig) (*http.Client, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	if cfg.CACert == "" {
		return client, nil
	}

	pem, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("could not read secrets.vault.ca_cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("secrets.vault.ca_cert (%s) contains no certificates", cfg.CACert)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	client.Transport = transport
	return client, nil
}

// Start begins the HTTP server and background schedulers.
func (s *Server) Start() error {
	scanInterval := time.Duration(s.cfg.Renewal.ScanInterval) * time.Minute
	if scanInterval <= 0 {
		scanInterval = time.Hour
	}
	s.renewalSched.Start(scanInterval)
	s.renewalQueue.Start()
	s.ariPoller.Start()
	s.verifier.Start()

	// An expiring CA takes down everything it signs, so this sweep has to run
	// on a timer rather than waiting for someone to open the dashboard.
	caInterval := time.Duration(s.cfg.PKI.CAHealthCheckInterval) * time.Minute
	if caInterval <= 0 {
		caInterval = 6 * time.Hour
	}
	s.caMonitor.Start(caInterval)
	// Slower than the health sweep on purpose: a mount's issuers change when
	// somebody rotates a CA, which is a thing that happens a few times a
	// decade. What changes daily is how long they have left, and that is the
	// monitor's job on rows this has already created.
	s.caImporter.Start(12 * time.Hour)

	// Its own interval comes from each schedule, so this only needs to wake
	// often enough to notice one is due. A fresh install has no schedules and
	// this loop does nothing but one indexed query a minute.
	s.discoverySch.Start()
	s.ctMonitor.Start()
	s.cloudEngine.Start()
	s.deployQueue.Start()
	s.assessor.Start()
	s.fleetMonitor.Start()

	// After the producers, so nothing is published before there is anything
	// subscribed to deliver it.
	s.dispatcher.Start()

	slog.Info("CertPilot Core HTTP API listening", "addr", s.httpServer.Addr, "mode", s.cfg.Server.Mode)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server, background schedulers, and store pool.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down CertPilot Core")
	// The sweep first, so nothing new is enqueued while the queue drains. A job
	// enqueued during shutdown is not lost — that is the point of the table —
	// but a worker claiming one it has no time to finish leaves a lease to
	// expire before another replica can pick it up.
	s.renewalSched.Stop()
	s.renewalQueue.Stop()
	s.ariPoller.Stop()
	s.verifier.Stop()
	s.caMonitor.Stop()
	s.caImporter.Stop()
	s.discoverySch.Stop()
	s.ctMonitor.Stop()
	s.cloudEngine.Stop()
	// After the renewal queue, which is what enqueues most deployments: a
	// deployment enqueued during shutdown is not lost, but a worker claiming
	// one it has no time to finish leaves a lease to expire before another
	// replica can take it.
	s.deployQueue.Stop()
	s.assessor.Stop()
	s.fleetMonitor.Stop()
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	// A range scan can run for minutes. Left alone it would hold the grace
	// period open and then be killed mid-write anyway; cancelled, it records
	// what it found and stops.
	s.scanner.Stop()
	// After the producers and before the broker: it must stop being fed before
	// it stops draining, and it writes audit records so it has to finish while
	// the store is still open.
	s.dispatcher.Stop()
	// Before the HTTP shutdown, so in-flight event-stream handlers wake and
	// return rather than holding the grace period open for its full duration.
	s.broker.Stop()
	s.pluginMgr.Close()
	s.store.Close()
	return s.httpServer.Shutdown(ctx)
}
