package api

import (
	"github.com/certpilot/certpilot/core/engine/cloudsync"
	"github.com/certpilot/certpilot/core/engine/ctlog"
	"github.com/certpilot/certpilot/core/engine/deploy"
	"github.com/certpilot/certpilot/core/engine/discovery"
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

// RouterDeps carries everything the API layer needs.
//
// This is a struct rather than a long parameter list because the previous
// signature had reached nine positional arguments, two of which were a string
// and a bool sitting next to each other — the shape where a call site silently
// swaps them.
type RouterDeps struct {
	Store         store.Store
	PluginMgr     *pluginmgr.Manager
	CAMonitor     *pki.CAMonitor
	CAImporter    *pki.Importer
	ChainResolver *pki.ChainResolver
	RenewalExec   *renewal.Executor
	RenewalSched  *renewal.Scheduler
	RenewalQueue  *renewal.Queue
	// DeployQueue is used by one route: the one where a host reports what it
	// did with a job it claimed. Completing that job through the queue's own
	// retry curve is what keeps the agent path and the local one from drifting.
	DeployQueue  *deploy.Queue
	ARIPoller    *renewal.ARIPoller
	Verifier     *renewal.Verifier
	PolicyEngine *policy.Engine
	Scanner      *discovery.Scanner
	CTMonitor    *ctlog.Monitor
	CloudEngine  *cloudsync.Engine
	Keyring      *secrets.Keyring
	Broker       *events.Broker
	Dispatcher   *notifications.Dispatcher
	Auth         *middleware.Authenticator
	RateLimiter  *middleware.RateLimiter
	Config       *config.CoreConfig
}

// SetupRouter configures all REST API routes and attaches middleware.
func SetupRouter(engine *gin.Engine, deps RouterDeps) {
	engine.Use(gin.Recovery())
	engine.Use(middleware.SecurityHeaders())

	// Ahead of authentication, so an unauthenticated flood costs a map lookup
	// rather than a JWKS fetch or an Argon2id derivation. The key falls back to
	// the client address until an identity is established, and prefers the
	// identity once one is — a credential should not escape its limit by
	// arriving from more addresses.
	if limiter := deps.RateLimiter; limiter != nil {
		engine.Use(limiter.Middleware())
	}

	engine.Use(middleware.CORS(deps.Config.Server.AllowedOrigins))

	// ── Health ──
	// Public, and deliberately says nothing about internals.
	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "certpilot-core"})
	})

	certHandler := NewCertificateHandler(deps.Store, deps.PluginMgr, deps.RenewalExec, deps.RenewalSched, deps.PolicyEngine, deps.Keyring, deps.Broker)
	metadataHandler := NewMetadataHandler(deps.Store)
	renewalHandler := NewRenewalHandler(deps.Store, deps.RenewalSched, deps.ARIPoller, deps.Verifier)
	caHandler := NewCAHandler(deps.Store, deps.CAMonitor, deps.CAImporter, deps.ChainResolver)
	caAccHandler := NewCAAccountHandler(deps.Store, deps.PluginMgr, deps.Keyring, deps.CAImporter)
	dashHandler := NewDashboardHandler(deps.Store)
	auditHandler := NewAuditHandler(deps.Store)
	discHandler := NewDiscoveryHandler(deps.Store, deps.Scanner)
	policyHandler := NewPolicyHandler(deps.Store)
	templateHandler := NewTemplateHandler(deps.Store, deps.PolicyEngine)
	eventsHandler := NewEventsHandler(deps.Store, deps.Broker)
	displayHandler := NewDisplayTokenHandler(deps.Store)
	notifHandler := NewNotificationHandler(deps.Store, deps.Keyring, deps.Dispatcher)
	ackHandler := NewAcknowledgementHandler(deps.Store)
	agentHandler := NewAgentHandler(deps.Store, deps.PluginMgr, deps.Keyring, deps.Broker, deps.DeployQueue)
	ctHandler := NewCTHandler(deps.Store, deps.CTMonitor)
	cloudHandler := NewCloudHandler(deps.Store, deps.CloudEngine, deps.Keyring)
	deployHandler := NewDeploymentHandler(deps.Store, deps.Keyring)
	postureHandler := NewPostureHandler(deps.Store, posture.ToolVersion)
	sessionHandler := NewSessionHandler(deps.Store, deps.Config.Auth, deps.Auth)
	userHandler := NewUserHandler(deps.Store)

	// ── Sign-in discovery ──
	// Public, and necessarily so: this is what a browser reads before it holds
	// any credential. It carries the issuer and client id, which are public by
	// construction in authorization code with PKCE — the user's own browser
	// sends both to the provider in a URL they can read.
	engine.GET("/api/v1/auth/config", sessionHandler.Config)

	// Sign-in itself cannot require being signed in. It is rate-limited by the
	// per-account lockout in the store rather than by middleware, because the
	// core runs as several replicas and an in-process counter would reset with
	// every request that landed on a different one.
	engine.POST("/api/v1/auth/login", sessionHandler.Login)

	// The core redeems the authorization code, the browser does not.
	//
	// A single-page application that redeems it itself receives a refresh token
	// and has nowhere safe to keep it — every storage a page can reach is
	// readable by script on that origin. Doing the exchange here means the
	// browser gets a session cookie and never handles a token at all.
	engine.POST("/api/v1/auth/callback", sessionHandler.Callback)

	// ── The agent API ──
	//
	// A separate group with its own authentication, mounted before the human
	// API and sharing none of its middleware. That separation is the point: an
	// agent credential must not be usable to read the estate, and a person's
	// bearer token must not be usable to speak as a host. Neither the OIDC
	// authenticator nor the display-token middleware runs here, and AgentAuth
	// runs nowhere else.
	agentGroup := engine.Group("/api/v1/agent")
	{
		// Enrolment is the one agent call that is not signed, because the agent
		// has no identity yet — this is the request that gives it one. It is
		// authenticated by a one-use enrolment token instead.
		agentGroup.POST("/enrol", agentHandler.Enrol)

		signed := agentGroup.Group("", middleware.AgentAuth(deps.Store))
		signed.POST("/heartbeat", agentHandler.Heartbeat)
		// What is on the host. Certificates as PEM plus the facts only a
		// process on the machine can see; no field a private key could arrive
		// in.
		signed.POST("/inventory", agentHandler.Inventory)
		// The point of the agent: the host generated the key, and sends only a
		// request. CertPilot signs what an operator granted this host and never
		// holds a private key it could lose or be compelled to produce.
		signed.POST("/certificates", agentHandler.RequestCertificate)
		// Where the host put them, and what happened when it did. Reported
		// upwards only: there is deliberately no route by which this core can
		// tell a host which files to write or what command to run.
		signed.POST("/installations", agentHandler.ReportInstallations)
		// The inversion that makes an agent a deployment target. Every other
		// target is deployed to by a core worker opening a connection; a host
		// behind two firewalls claims the job itself, off the same queue, with
		// the same lease and the same retry curve.
		signed.POST("/deployments/claim", agentHandler.ClaimDeployments)
		signed.POST("/deployments/result", agentHandler.ReportDeploymentResult)
	}

	v1 := engine.Group("/api/v1")
	// Display tokens are resolved first, and only take effect when no
	// Authorization header was sent. The middleware itself refuses anything
	// that is not a GET and refuses the sensitive read paths outright, so the
	// read-only property does not depend on every route below getting its role
	// gate right.
	// Order matters, and it is the same rule in both cases: an explicit
	// credential beats an ambient one. A cookie sitting in a browser must never
	// override a request that presented a token, or the audit log records the
	// wrong person.
	v1.Use(middleware.DisplayTokenAuth(deps.Store))
	v1.Use(middleware.SessionAuth(deps.Store))
	v1.Use(deps.Auth.Middleware())
	{
		// ── Live event stream ──
		// Any authenticated reader may watch; the stream carries CA and
		// certificate state, never secrets or actor identity.
		v1.GET("/events", eventsHandler.Stream)

		// ── The caller's own identity ──
		// The role reported here is the one from CertPilot's users table, not
		// the one in the token. A frontend that decoded the JWT itself would
		// keep showing controls for a role the API had stopped honouring.
		v1.GET("/me", sessionHandler.Me)
		v1.POST("/auth/logout", sessionHandler.Logout)
		// Changing a password requires the current one even though the caller
		// is already authenticated: a session left open on an unattended
		// machine should not be enough to lock its owner out of their account.
		v1.POST("/auth/password", sessionHandler.ChangePassword)

		// ── Dashboard ──
		v1.GET("/dashboard/stats", dashHandler.Stats)
		v1.GET("/dashboard/expiring", dashHandler.Expiring)
		v1.GET("/dashboard/activity", dashHandler.Activity)

		// ── Audit record integrity ──
		// Whether the audit log has been altered, as distinct from what it
		// says. Admin only: the people who could tamper with it are the ones
		// this answer would implicate, and telling them whether the check
		// passes is telling them whether a rewrite worked.
		v1.GET("/audit/verify", middleware.RequireRole(middleware.RoleAdmin), auditHandler.Verify)

		// ── Certificates ──
		v1.GET("/certificates", certHandler.List)
		v1.POST("/certificates", middleware.RequireRole(middleware.RoleOperator), certHandler.Create)
		v1.GET("/certificates/:id", certHandler.Get)
		// The only mutable part of a certificate: the decisions people record
		// about it, not the facts the CA established.
		v1.PATCH("/certificates/:id", middleware.RequireRole(middleware.RoleOperator), certHandler.UpdateMetadata)
		v1.POST("/certificates/:id/renew", middleware.RequireRole(middleware.RoleOperator), certHandler.Renew)
		// Exporting a private key is admin-only and audited: it is the one
		// operation that removes a secret from the system's custody.
		// Revocation is admin, and it is the operation DELETE was being used
		// for. It tells the CA first and records only what the CA accepted, so
		// a certificate can never read REVOKED here while still answering
		// handshakes in production.
		v1.POST("/certificates/:id/revoke", middleware.RequireRole(middleware.RoleAdmin), certHandler.Revoke)
		v1.GET("/certificates/:id/private-key", middleware.RequireRole(middleware.RoleAdmin), certHandler.PrivateKey)
		v1.DELETE("/certificates/:id", middleware.RequireRole(middleware.RoleAdmin), certHandler.Delete)

		// ── PKI / CA Management ──
		v1.GET("/pki/authorities", caHandler.List)
		v1.POST("/pki/authorities", middleware.RequireRole(middleware.RoleOperator), caHandler.Create)
		// Before the :id routes. Gin matches a static segment ahead of a
		// parameter at the same position, and registering it after would still
		// work — but reading it after would suggest an authority called
		// "import", which is the kind of thing somebody eventually tries.
		v1.POST("/pki/authorities/import", middleware.RequireRole(middleware.RoleOperator), caHandler.ImportIssuers)
		v1.GET("/pki/authorities/:id", caHandler.Get)
		v1.GET("/pki/authorities/:id/chain", caHandler.Chain)
		v1.POST("/pki/authorities/:id/check", middleware.RequireRole(middleware.RoleOperator), caHandler.CheckHealth)
		v1.DELETE("/pki/authorities/:id", middleware.RequireRole(middleware.RoleAdmin), caHandler.Delete)
		v1.GET("/pki/tree", caHandler.HierarchyTree)
		// Acknowledgement is an operator action: it is a statement that a
		// human has looked, and it needs a human's name against it.
		v1.POST("/pki/authorities/:id/acknowledge", middleware.RequireRole(middleware.RoleOperator), ackHandler.Acknowledge)
		v1.DELETE("/pki/authorities/:id/acknowledge", middleware.RequireRole(middleware.RoleOperator), ackHandler.Withdraw)
		v1.GET("/pki/authorities/:id/acknowledgements", ackHandler.History)
		v1.PUT("/pki/authorities/:id/owner", middleware.RequireRole(middleware.RoleOperator), ackHandler.SetOwner)

		// ── CA Accounts & Gateways ──
		v1.GET("/ca-accounts", caAccHandler.List)
		v1.POST("/ca-accounts", middleware.RequireRole(middleware.RoleOperator), caAccHandler.Create)
		v1.POST("/ca-accounts/:id/health", middleware.RequireRole(middleware.RoleOperator), caAccHandler.HealthCheck)
		v1.DELETE("/ca-accounts/:id", middleware.RequireRole(middleware.RoleAdmin), caAccHandler.Delete)
		// Narrow on purpose: the only field on a CA account that can change
		// without re-validating the configuration through the gateway.
		v1.PUT("/ca-accounts/:id/rate-limit", middleware.RequireRole(middleware.RoleOperator), caAccHandler.SetRateLimit)
		v1.GET("/gateways", caAccHandler.ListGateways)

		// ── Discovery ──
		// Scanning is operator, not viewer: it opens connections to third-party
		// infrastructure from CertPilot's address, which is an action taken in
		// the organisation's name rather than a read of its own state.
		v1.POST("/discovery/scan", middleware.RequireRole(middleware.RoleOperator), discHandler.Scan)
		v1.POST("/discovery/import", middleware.RequireRole(middleware.RoleOperator), discHandler.Import)
		// Reading what past scans found is open to any authenticated user. It
		// is estate state, the same as the CA list.
		v1.GET("/discovery/scans", discHandler.ListScans)
		v1.GET("/discovery/scans/:id", discHandler.GetScan)
		// Stopping a scan is an operator action for the same reason starting one
		// is: it changes what CertPilot is doing to somebody else's network.
		v1.POST("/discovery/scans/:id/cancel", middleware.RequireRole(middleware.RoleOperator), discHandler.CancelScan)
		v1.GET("/discovery/results", discHandler.ListResults)
		// Schedules. Reading is open to any authenticated user; writing is
		// operator, because a schedule is a standing instruction to connect to
		// somebody else's network on a timer.
		v1.GET("/discovery/schedules", discHandler.ListSchedules)
		v1.POST("/discovery/schedules", middleware.RequireRole(middleware.RoleOperator), discHandler.CreateSchedule)
		v1.PUT("/discovery/schedules/:id", middleware.RequireRole(middleware.RoleOperator), discHandler.UpdateSchedule)
		v1.DELETE("/discovery/schedules/:id", middleware.RequireRole(middleware.RoleAdmin), discHandler.DeleteSchedule)
		v1.POST("/discovery/schedules/:id/run", middleware.RequireRole(middleware.RoleOperator), discHandler.RunSchedule)

		// ── Certificate Transparency ──
		// The half of discovery a network scan cannot reach: what has been
		// issued in your name, whether or not it was ever deployed.
		v1.GET("/ct/monitors", ctHandler.ListMonitors)
		v1.POST("/ct/monitors", middleware.RequireRole(middleware.RoleOperator), ctHandler.CreateMonitor)
		v1.PUT("/ct/monitors/:id", middleware.RequireRole(middleware.RoleOperator), ctHandler.UpdateMonitor)
		v1.DELETE("/ct/monitors/:id", middleware.RequireRole(middleware.RoleAdmin), ctHandler.DeleteMonitor)
		v1.POST("/ct/monitors/:id/check", middleware.RequireRole(middleware.RoleOperator), ctHandler.CheckMonitor)
		v1.GET("/ct/certificates", ctHandler.ListCertificates)

		// ── Cloud inventory ──
		// The third place certificates hide: stored rather than served, in an
		// account a scan has no address for. Reading is open to any
		// authenticated user — the list never carries the sealed credentials.
		v1.GET("/cloud/connections", cloudHandler.ListConnections)
		v1.POST("/cloud/connections", middleware.RequireRole(middleware.RoleOperator), cloudHandler.CreateConnection)
		v1.PUT("/cloud/connections/:id", middleware.RequireRole(middleware.RoleOperator), cloudHandler.UpdateConnection)
		v1.DELETE("/cloud/connections/:id", middleware.RequireRole(middleware.RoleAdmin), cloudHandler.DeleteConnection)
		// Reaching out to somebody else's account with stored credentials is an
		// action, not a read, which is why it is a POST and gated at operator.
		v1.POST("/cloud/connections/:id/sync", middleware.RequireRole(middleware.RoleOperator), cloudHandler.SyncConnection)
		v1.GET("/cloud/certificates", cloudHandler.ListCertificates)
		v1.POST("/cloud/import", middleware.RequireRole(middleware.RoleOperator), cloudHandler.ImportCertificate)

		// ── Renewal queue ──
		// Renewal is the only part of this system that changes the world, so
		// what it is about to do is readable rather than inferred from logs.
		v1.GET("/renewals", renewalHandler.List)
		v1.GET("/renewals/:id", renewalHandler.Get)
		// Cancelling stops a renewal somebody asked for. Admin, because the
		// certificate then goes back to expiring on its own with nothing
		// scheduled to stop it.
		v1.DELETE("/renewals/:id", middleware.RequireRole(middleware.RoleAdmin), renewalHandler.Cancel)
		// Ask the CA now what it thinks about one certificate. Reaching out to
		// somebody else's CA is an action, not a read.
		v1.POST("/certificates/:id/renewal-info", middleware.RequireRole(middleware.RoleOperator), renewalHandler.RefreshRenewalInfo)
		// Check now whether a renewal actually reached the servers it was for.
		v1.POST("/certificates/:id/verify", middleware.RequireRole(middleware.RoleOperator), renewalHandler.Verify)

		// ── Deployment ──
		// The other half of renewal. Everything above this line observes;
		// this changes something that is already carrying traffic, which is
		// why every write here is operator or admin and every one is audited.
		//
		// Reading is open to any authenticated user: the target list carries
		// names, types, and whether a target receives private keys — never the
		// sealed credentials themselves.
		v1.GET("/deployment-targets", deployHandler.ListTargets)
		v1.POST("/deployment-targets", middleware.RequireRole(middleware.RoleOperator), deployHandler.CreateTarget)
		v1.PUT("/deployment-targets/:id", middleware.RequireRole(middleware.RoleOperator), deployHandler.UpdateTarget)
		// Admin to delete: removing a target silently stops every certificate
		// bound to it from being deployed anywhere, and renewals carry on
		// looking healthy.
		v1.DELETE("/deployment-targets/:id", middleware.RequireRole(middleware.RoleAdmin), deployHandler.DeleteTarget)

		// Where one certificate goes. Bound and unbound at operator, because a
		// binding is a standing instruction to write to somebody's machine.
		v1.GET("/certificates/:id/targets", deployHandler.ListBindings)
		v1.POST("/certificates/:id/targets", middleware.RequireRole(middleware.RoleOperator), deployHandler.CreateBinding)
		v1.DELETE("/certificates/:id/targets/:bindingId", middleware.RequireRole(middleware.RoleOperator), deployHandler.DeleteBinding)
		// Install it now. Queues rather than deploys: a certificate on eight
		// targets is eight outbound calls that may each need a reload, and a
		// synchronous handler would be cut off partway with half an estate
		// updated and no way to say which half.
		v1.POST("/certificates/:id/deploy", middleware.RequireRole(middleware.RoleOperator), deployHandler.Deploy)

		// Cryptographic posture. The ordering of this section is the argument
		// it makes: what is losing something today, then what needs a plan.
		v1.GET("/posture", postureHandler.Summary)
		v1.GET("/posture/endpoints", postureHandler.Endpoints)
		// CycloneDX 1.6, because the point of a CBOM is that something other
		// than CertPilot reads it.
		v1.GET("/posture/cbom", postureHandler.CBOM)

		v1.GET("/deployments", deployHandler.ListJobs)
		v1.GET("/deployments/:id", deployHandler.GetJob)
		v1.DELETE("/deployments/:id", middleware.RequireRole(middleware.RoleAdmin), deployHandler.CancelJob)

		// ── Agents ──
		// The fleet, for people. Reading is open to any authenticated user: an
		// agent row carries a public key and a last-seen time, and who is
		// watching the estate is not a secret.
		v1.GET("/agents", agentHandler.ListAgents)
		v1.GET("/agents/:id", agentHandler.GetAgent)
		// Revoking is admin: it withdraws a credential that can act on a host.
		v1.POST("/agents/:id/revoke", middleware.RequireRole(middleware.RoleAdmin), agentHandler.RevokeAgent)
		v1.DELETE("/agents/:id", middleware.RequireRole(middleware.RoleAdmin), agentHandler.DeleteAgent)

		// The fourth place certificates hide: a file on a disk, behind two
		// firewalls, that no scan, no transparency log, and no cloud API will
		// ever mention. Reading is open to any authenticated user — it carries
		// paths and permissions, never key material.
		v1.GET("/agent-certificates", agentHandler.ListCertificates)
		// Where the fleet has put its certificates. `?attention=true` returns
		// the two rows nothing else in this system can produce: a destination
		// that failed on the far side of every firewall, and a host configured
		// to install a certificate that does not exist.
		v1.GET("/agent-installations", agentHandler.ListInstallations)

		// What a host may ask for. Readable by any authenticated user — a grant
		// is a statement of policy and holds no secret — and written by an
		// operator, because it decides what the organisation's CA will sign on
		// a machine's say-so.
		v1.GET("/agent-grants", agentHandler.ListGrants)
		v1.POST("/agent-grants", middleware.RequireRole(middleware.RoleOperator), agentHandler.CreateGrant)
		v1.DELETE("/agent-grants/:id", middleware.RequireRole(middleware.RoleOperator), agentHandler.RevokeGrant)

		// Enrolment tokens are admin throughout, including the list. The hash
		// is useless on its own, but a list of live tokens is a map of which
		// doors are currently open.
		v1.GET("/agent-enrol-tokens", middleware.RequireRole(middleware.RoleAdmin), agentHandler.ListEnrolTokens)
		v1.POST("/agent-enrol-tokens", middleware.RequireRole(middleware.RoleAdmin), agentHandler.CreateEnrolToken)
		v1.DELETE("/agent-enrol-tokens/:id", middleware.RequireRole(middleware.RoleAdmin), agentHandler.RevokeEnrolToken)

		// ── Accounts ──
		//
		// Admin throughout, including the list. A list of accounts is a map of
		// who can do what to the CA hierarchy, and it is exactly what somebody
		// who has taken over one account wants next.
		v1.GET("/users", middleware.RequireRole(middleware.RoleAdmin), userHandler.List)
		v1.POST("/users", middleware.RequireRole(middleware.RoleAdmin), userHandler.Create)
		v1.PATCH("/users/:id", middleware.RequireRole(middleware.RoleAdmin), userHandler.Update)
		// Resetting somebody else's password does not require the old one —
		// that is the point, it is the path back from a locked-out colleague.
		v1.POST("/users/:id/password", middleware.RequireRole(middleware.RoleAdmin), userHandler.ResetPassword)

		// ── Display Tokens ──
		// Admin-only throughout: minting a credential that authenticates to
		// the API is an administrative act even though what it grants is
		// read-only.
		v1.GET("/display-tokens", middleware.RequireRole(middleware.RoleAdmin), displayHandler.List)
		v1.POST("/display-tokens", middleware.RequireRole(middleware.RoleAdmin), displayHandler.Create)
		v1.DELETE("/display-tokens/:id", middleware.RequireRole(middleware.RoleAdmin), displayHandler.Revoke)

		// ── Notification channels ──
		// Reading is open to any authenticated user: the list carries names,
		// types, and thresholds, never the sealed credentials. Writing is
		// operator, deletion admin — removing a channel silently stops alerts
		// reaching whoever depended on it.
		v1.GET("/notification-channels", notifHandler.List)
		v1.POST("/notification-channels", middleware.RequireRole(middleware.RoleOperator), notifHandler.Create)
		v1.PUT("/notification-channels/:id", middleware.RequireRole(middleware.RoleOperator), notifHandler.Update)
		v1.DELETE("/notification-channels/:id", middleware.RequireRole(middleware.RoleAdmin), notifHandler.Delete)
		// Sending a real alert to a real destination is an action, not a read,
		// which is why it is a POST and gated at operator.
		v1.POST("/notification-channels/:id/test", middleware.RequireRole(middleware.RoleOperator), notifHandler.Test)

		// ── Custom metadata fields ──
		//
		// Readable by anyone, because a viewer needs the labels to make sense of
		// the values on a certificate. Defining them is admin-only: a required
		// field changes what everyone else has to supply to get a certificate.
		v1.GET("/metadata-fields", metadataHandler.List)
		v1.POST("/metadata-fields", middleware.RequireRole(middleware.RoleAdmin), metadataHandler.Create)
		v1.PUT("/metadata-fields/:id", middleware.RequireRole(middleware.RoleAdmin), metadataHandler.Update)
		v1.DELETE("/metadata-fields/:id", middleware.RequireRole(middleware.RoleAdmin), metadataHandler.Archive)

		// ── Policies ──
		v1.GET("/policies", policyHandler.List)
		v1.GET("/policies/:id", policyHandler.Get)
		v1.POST("/policies", middleware.RequireRole(middleware.RoleOperator), policyHandler.Create)
		v1.PUT("/policies/:id", middleware.RequireRole(middleware.RoleOperator), policyHandler.Update)
		v1.DELETE("/policies/:id", middleware.RequireRole(middleware.RoleAdmin), policyHandler.Delete)

		// ── Certificate templates ──
		//
		// Writes are admin-only, where a policy is operator-writable. A policy
		// can only ever refuse more than it did; a template also supplies
		// values and decides whether the requester may set the subject, and
		// that last one is the difference between a template and a way to get
		// a certificate for somebody else's name.
		v1.GET("/certificate-templates", templateHandler.List)
		v1.GET("/certificate-templates/:id", templateHandler.Get)
		v1.POST("/certificate-templates", middleware.RequireRole(middleware.RoleAdmin), templateHandler.Create)
		v1.PUT("/certificate-templates/:id", middleware.RequireRole(middleware.RoleAdmin), templateHandler.Update)
		v1.DELETE("/certificate-templates/:id", middleware.RequireRole(middleware.RoleAdmin), templateHandler.Delete)
	}
}
