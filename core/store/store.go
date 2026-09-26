package store

import (
	"context"
	"time"
)

// Store defines all database operations for CertPilot.
type Store interface {
	// ── Certificates ────────────────────────────────────────
	ListCertificates(ctx context.Context, filter CertificateFilter) ([]*Certificate, int64, error)
	GetCertificate(ctx context.Context, id string) (*Certificate, error)
	GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error)
	CreateCertificate(ctx context.Context, cert *Certificate) error
	UpdateCertificate(ctx context.Context, cert *Certificate) error
	// UpdateCertificateMetadata writes the operator-owned fields and nothing
	// else. Narrow rather than a full UpdateCertificate because everything else
	// on the row is a fact about the certificate itself — serial, expiry,
	// fingerprint — and a full-object write from a form is how a stale copy in
	// a browser tab overwrites what a renewal just recorded.
	UpdateCertificateMetadata(ctx context.Context, id string, update CertificateMetadataUpdate) (*Certificate, error)

	// ── Custom metadata fields ──
	ListMetadataFields(ctx context.Context, includeArchived bool) ([]*MetadataField, error)
	GetMetadataField(ctx context.Context, id string) (*MetadataField, error)
	CreateMetadataField(ctx context.Context, field *MetadataField) error
	UpdateMetadataField(ctx context.Context, field *MetadataField) error
	// ArchiveMetadataField retires a field without deleting it, so the values
	// certificates already hold keep something that can label them.
	ArchiveMetadataField(ctx context.Context, id string) error

	// ── Users ───────────────────────────────────────────────────────────────
	//
	// ResolveUser is called on every authenticated request, so it both reads
	// and writes: a subject with no row is given one, which is what makes a
	// first sign-in work without an invitation step. It returns the stored
	// user, whose role is the one that governs the request — the token's own
	// role claim is not consulted.
	ResolveUser(ctx context.Context, identity UserIdentity, bootstrapAdmins []string) (*User, error)
	GetUser(ctx context.Context, id string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	// SetUserRole and SetUserStatus are the administrative half, kept separate
	// from ResolveUser so that a sign-in can never change a role.
	SetUserRole(ctx context.Context, id, role string) (*User, error)
	SetUserStatus(ctx context.Context, id, status string) (*User, error)
	// TouchUser records that a subject was seen, without the cost of a write
	// on every single request. See the postgres implementation.
	TouchUser(ctx context.Context, id string, seenAt time.Time) error

	// ── Local accounts and sessions ─────────────────────────────────────────
	//
	// AuthenticatePassword does the whole sign-in in one place: it finds the
	// account, checks the lock, verifies the password, and records the outcome.
	// Split across the caller it would be four round trips with a race in the
	// middle of them, and the lockout counter is only meaningful if the check
	// and the increment cannot be interleaved.
	AuthenticatePassword(ctx context.Context, email, password string) (*User, LoginOutcome, error)
	SetUserPassword(ctx context.Context, id, password string, mustChange bool) error
	UserByEmail(ctx context.Context, email string) (*User, error)
	CountUsers(ctx context.Context) (int, error)
	// CountPasswordAccounts is what bootstrap keys off, not CountUsers.
	// An instance upgraded from a token-only build has users but no passwords,
	// and keying off the table being empty would leave nobody able to sign in.
	CountPasswordAccounts(ctx context.Context) (int, error)

	CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time, userAgent, ip string) (*Session, error)
	// SessionByHash returns the session and its user together: every
	// authenticated request needs both, and two queries would let a session
	// outlive a suspension by the width of the gap between them.
	SessionByHash(ctx context.Context, tokenHash string) (*Session, *User, error)
	RevokeSession(ctx context.Context, tokenHash string) error
	// RevokeSessionsForUser ends every session an account holds, which is what
	// suspending somebody has to do to mean anything.
	RevokeSessionsForUser(ctx context.Context, userID string) (int, error)
	TouchSession(ctx context.Context, id string, seenAt time.Time, ip string) error

	// MarkCertificateRevoked records a revocation that the CA has already
	// accepted. It is deliberately not called until the gateway has confirmed:
	// a row marked REVOKED while the certificate is still live at the CA is the
	// exact failure the old DELETE produced, and it is worse than no record at
	// all because it stops anybody looking.
	MarkCertificateRevoked(ctx context.Context, id string, reason int, actorID string) (*Certificate, error)
	DeleteCertificate(ctx context.Context, id string) error
	GetCertificatesDueForRenewal(ctx context.Context, leadDays int) ([]*Certificate, error)
	// GetCertificatePrivateKey reads the sealed private key for one
	// certificate, and is the only way to obtain it.
	//
	// Deliberately not a field on the records the other readers return: those
	// run on every dashboard refresh, and a secret that is loaded constantly is
	// a secret that eventually gets logged, cached, or serialized by accident.
	// Returns "" when no key is stored, which is the normal case for imported,
	// discovered, and CSR-based certificates.
	GetCertificatePrivateKey(ctx context.Context, id string) (string, error)

	// ── CA Authorities ──────────────────────────────────────
	ListCAAuthorities(ctx context.Context, filter CAFilter) ([]*CAAuthority, error)
	GetCAAuthority(ctx context.Context, id string) (*CAAuthority, error)
	// GetCAAuthorityByFingerprint returns nil, nil when nothing matches.
	//
	// Absence is the ordinary answer rather than an error: the importer asks
	// this about every issuer a gateway offers, and most of the time the answer
	// is "not yet".
	GetCAAuthorityByFingerprint(ctx context.Context, fingerprint string) (*CAAuthority, error)
	CreateCAAuthority(ctx context.Context, ca *CAAuthority) error
	UpdateCAAuthority(ctx context.Context, ca *CAAuthority) error
	DeleteCAAuthority(ctx context.Context, id string) error
	GetCAChain(ctx context.Context, id string) ([]*CAAuthority, error)

	// ── CA Accounts ─────────────────────────────────────────
	ListCAAccounts(ctx context.Context) ([]*CAAccount, error)
	GetCAAccount(ctx context.Context, id string) (*CAAccount, error)
	CreateCAAccount(ctx context.Context, acc *CAAccount) error
	UpdateCAAccount(ctx context.Context, acc *CAAccount) error
	DeleteCAAccount(ctx context.Context, id string) error

	// ── Deployment targets ──────────────────────────────────
	//
	// Deployment is the second thing in this system that changes the world, and
	// the more dangerous of the two: renewal creates new material, deployment
	// replaces material that is currently carrying traffic.
	ListDeploymentTargets(ctx context.Context) ([]*DeploymentTarget, error)
	GetDeploymentTarget(ctx context.Context, id string) (*DeploymentTarget, error)
	CreateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error
	UpdateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error
	DeleteDeploymentTarget(ctx context.Context, id string) error
	// MarkDeploymentTargetUsed records the outcome of one deploy against the
	// target itself.
	//
	// Narrow rather than a full-row write, and separate from the binding's own
	// outcome: the queue runs concurrently with whoever is editing the target,
	// and a worker holding a copy from before an edit must not be able to write
	// stale credentials back as a side effect of recording that it deployed.
	MarkDeploymentTargetUsed(ctx context.Context, id string, at time.Time, success bool, detail string) error

	// ── Certificate ↔ target bindings ───────────────────────
	//
	// Where a certificate goes, one row per place. Migration 001 modelled this
	// as a single column on the certificate; one wildcard on six load balancers
	// is six deployments with six outcomes, and a single deployed_at would
	// average them into a number that is true of nowhere.
	ListCertificateDeployments(ctx context.Context, certificateID string) ([]*CertificateDeployment, error)
	GetCertificateDeployment(ctx context.Context, id string) (*CertificateDeployment, error)
	CreateCertificateDeployment(ctx context.Context, d *CertificateDeployment) error
	DeleteCertificateDeployment(ctx context.Context, id string) error
	// RecordDeploymentOutcome writes what one attempt did to one binding.
	RecordDeploymentOutcome(ctx context.Context, id string, outcome DeploymentOutcome) error

	// ── Deployment queue ────────────────────────────────────

	// EnqueueDeployment creates a job unless one is already outstanding for
	// this binding.
	//
	// Per binding, not per certificate. That is the one place the renewal
	// queue's shape would have been actively wrong: a certificate bound to six
	// targets needs six jobs outstanding at once, and a constraint copied from
	// renewal would have deployed to the first and silently dropped five.
	EnqueueDeployment(ctx context.Context, job *DeploymentJob) (created bool, err error)
	// ClaimDeploymentJob takes the most urgent ready job and leases it.
	ClaimDeploymentJob(ctx context.Context, worker string, lease time.Duration, now time.Time) (*DeploymentJob, error)
	// ExtendDeploymentLease keeps a long-running job's claim alive.
	ExtendDeploymentLease(ctx context.Context, id, worker string, until time.Time) error
	// CompleteDeploymentJob records the outcome of an attempt.
	CompleteDeploymentJob(ctx context.Context, id string, status string, attempt DeploymentAttempt,
		runAfter time.Time, escalate bool) error
	GetDeploymentJob(ctx context.Context, id string) (*DeploymentJob, error)
	ListDeploymentJobs(ctx context.Context, filter DeploymentJobFilter) ([]*DeploymentJob, int64, error)
	// CancelDeploymentJob stops an outstanding job.
	CancelDeploymentJob(ctx context.Context, id string) error

	// ── Policies ────────────────────────────────────────────
	ListPolicies(ctx context.Context) ([]*Policy, error)
	GetPolicy(ctx context.Context, id string) (*Policy, error)
	CreatePolicy(ctx context.Context, p *Policy) error
	UpdatePolicy(ctx context.Context, p *Policy) error
	DeletePolicy(ctx context.Context, id string) error

	// ── Certificate templates ───────────────────────────────
	ListCertificateTemplates(ctx context.Context) ([]*CertificateTemplate, error)
	GetCertificateTemplate(ctx context.Context, id string) (*CertificateTemplate, error)
	// GetCertificateTemplateBySlug resolves the stable machine name. This is
	// how an agent or a CI job names a template; the id is not something a
	// pipeline should have to carry.
	GetCertificateTemplateBySlug(ctx context.Context, slug string) (*CertificateTemplate, error)
	CreateCertificateTemplate(ctx context.Context, t *CertificateTemplate) error
	// UpdateCertificateTemplate writes the record and bumps Version when a rule
	// changed. Name and description are not rules, so renaming does not
	// invalidate the certificates issued under it.
	UpdateCertificateTemplate(ctx context.Context, t *CertificateTemplate) error
	DeleteCertificateTemplate(ctx context.Context, id string) error

	// ── Display Tokens ──────────────────────────────────────
	ListDisplayTokens(ctx context.Context) ([]*DisplayToken, error)
	// GetDisplayTokenByHash resolves a presented token. It returns the record
	// whatever its lifecycle state — revocation and expiry are decided by the
	// caller, so that "this token was revoked" is distinguishable from "this
	// token never existed" in the logs, while both stay a flat 401 on the wire.
	GetDisplayTokenByHash(ctx context.Context, tokenHash string) (*DisplayToken, error)
	CreateDisplayToken(ctx context.Context, t *DisplayToken) error
	RevokeDisplayToken(ctx context.Context, id string, revokedBy *string) error
	// TouchDisplayToken records where and when a token was last used, so a
	// credential in use somewhere unexpected is discoverable.
	TouchDisplayToken(ctx context.Context, id string, seenAt time.Time, ip string) error

	// ── Notification Channels ───────────────────────────────
	ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, id string) (*NotificationChannel, error)
	CreateNotificationChannel(ctx context.Context, ch *NotificationChannel) error
	UpdateNotificationChannel(ctx context.Context, ch *NotificationChannel) error
	DeleteNotificationChannel(ctx context.Context, id string) error
	// MarkNotificationChannelSent records a successful delivery. Separate from
	// UpdateNotificationChannel so the dispatcher, which runs concurrently with
	// whoever is editing the channel, cannot write back a stale configuration
	// as a side effect of recording that a message went out.
	MarkNotificationChannelSent(ctx context.Context, id string, sentAt time.Time) error

	// ── Alert Acknowledgements ──────────────────────────────

	// CreateAcknowledgement records that a human has seen an alert.
	CreateAcknowledgement(ctx context.Context, ack *AlertAcknowledgement) error
	// GetActiveAcknowledgement returns the newest un-revoked acknowledgement
	// for an entity, or nil when there is none.
	//
	// Returns the record regardless of threshold, because whether it still
	// applies is a decision only the caller can make — it depends on which
	// threshold the alert is being raised at, and AlertAcknowledgement.IsActive
	// is where that comparison lives.
	GetActiveAcknowledgement(ctx context.Context, entityType, entityID string) (*AlertAcknowledgement, error)
	// ListAcknowledgements returns the history for an entity, newest first,
	// including revoked ones. Who acknowledged what and when is what an
	// incident review reads.
	ListAcknowledgements(ctx context.Context, entityType, entityID string) ([]*AlertAcknowledgement, error)
	// GetActiveAcknowledgements resolves acknowledgements for many entities in
	// one query, so the CA list does not issue one per row.
	GetActiveAcknowledgements(ctx context.Context, entityType string, entityIDs []string) (map[string]*AlertAcknowledgement, error)
	// RevokeAcknowledgement withdraws one, keeping the record that it was made.
	RevokeAcknowledgement(ctx context.Context, id string, revokedBy *string) error

	// ── Discovery ───────────────────────────────────────────

	// CreateDiscoveryScan records a run before it starts, so a scan that
	// crashes halfway leaves evidence that it was attempted.
	CreateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error
	// UpdateDiscoveryScan writes the outcome: status, counts, completion.
	UpdateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error
	GetDiscoveryScan(ctx context.Context, id string) (*DiscoveryScan, error)
	ListDiscoveryScans(ctx context.Context, limit, offset int) ([]*DiscoveryScan, int64, error)
	// CreateDiscoveryResults writes a run's findings in one call. Batched
	// because a scan produces one row per endpoint and a per-row round trip
	// would make the write slower than the scanning.
	CreateDiscoveryResults(ctx context.Context, results []*DiscoveryResult) error
	ListDiscoveryResults(ctx context.Context, filter DiscoveryResultFilter) ([]*DiscoveryResult, int64, error)
	GetDiscoveryResult(ctx context.Context, id string) (*DiscoveryResult, error)
	// MarkDiscoveryResultImported links a result to the certificate someone
	// adopted it into, so the same endpoint stops being reported as an
	// unmanaged finding on the next scan.
	MarkDiscoveryResultImported(ctx context.Context, id, certificateID string) error
	// GetLatestDiscoveryResults returns what each of these endpoints was last
	// seen serving, keyed by "host:port".
	//
	// This is what makes a repeated scan worth more than the first one: the
	// value of the second run is not the list, it is the difference. Loaded in
	// one call before the run, not per endpoint during it.
	GetLatestDiscoveryResults(ctx context.Context, endpoints []string) (map[string]*DiscoveryResult, error)

	// ── Discovery schedules ─────────────────────────────────

	ListDiscoverySchedules(ctx context.Context) ([]*DiscoverySchedule, error)
	GetDiscoverySchedule(ctx context.Context, id string) (*DiscoverySchedule, error)
	CreateDiscoverySchedule(ctx context.Context, s *DiscoverySchedule) error
	UpdateDiscoverySchedule(ctx context.Context, s *DiscoverySchedule) error
	DeleteDiscoverySchedule(ctx context.Context, id string) error
	// GetDueDiscoverySchedules returns the schedules that should run now.
	GetDueDiscoverySchedules(ctx context.Context, now time.Time) ([]*DiscoverySchedule, error)
	// MarkDiscoveryScheduleRun records an attempt and moves the schedule on.
	//
	// Separate from UpdateDiscoverySchedule so the scheduler, which runs
	// concurrently with whoever is editing the schedule, cannot write back a
	// stale definition as a side effect of recording that it ran.
	MarkDiscoveryScheduleRun(ctx context.Context, id string, ranAt, nextRunAt time.Time, scanID *string, runErr string) error

	// ── Certificate Transparency ────────────────────────────

	ListCTMonitors(ctx context.Context) ([]*CTMonitor, error)
	GetCTMonitor(ctx context.Context, id string) (*CTMonitor, error)
	CreateCTMonitor(ctx context.Context, m *CTMonitor) error
	UpdateCTMonitor(ctx context.Context, m *CTMonitor) error
	DeleteCTMonitor(ctx context.Context, id string) error
	GetDueCTMonitors(ctx context.Context, now time.Time) ([]*CTMonitor, error)
	// MarkCTMonitorChecked records the outcome of one check.
	//
	// Takes `success` explicitly rather than inferring it from an error string,
	// because the two timestamps it maintains answer different questions: when
	// did we last try, and when did we last actually learn anything. A monitor
	// that has been unable to reach the log for a week must not look like one
	// that has found nothing for a week.
	MarkCTMonitorChecked(ctx context.Context, id string, checkedAt, nextCheckAt time.Time,
		success bool, lastEntryID *int64, seen, unmanaged int, checkErr string) error

	// RecordCTCertificates stores what a check found, ignoring entries already
	// known. Returns only the ones that were new, which is what an alert is
	// built from — re-reporting the same certificate every six hours is how a
	// channel gets muted.
	RecordCTCertificates(ctx context.Context, certs []*CTCertificate) ([]*CTCertificate, error)
	ListCTCertificates(ctx context.Context, filter CTCertificateFilter) ([]*CTCertificate, int64, error)

	// ── Cloud inventory ─────────────────────────────────────
	ListCloudConnections(ctx context.Context) ([]*CloudConnection, error)
	GetCloudConnection(ctx context.Context, id string) (*CloudConnection, error)
	CreateCloudConnection(ctx context.Context, conn *CloudConnection) error
	UpdateCloudConnection(ctx context.Context, conn *CloudConnection) error
	DeleteCloudConnection(ctx context.Context, id string) error
	GetDueCloudConnections(ctx context.Context, now time.Time) ([]*CloudConnection, error)
	// MarkCloudConnectionSynced records the outcome of one sync.
	//
	// syncedAt always moves; the success timestamp moves only when the provider
	// actually answered. Everything on screen that says "this account is being
	// watched" is really saying "we last heard from it at this time", and a
	// connection with expired credentials must not read as a quiet one.
	//
	// scopes is what the sync enumerated, in the provider's own words, so a
	// short result is never mistaken for a small estate.
	MarkCloudConnectionSynced(ctx context.Context, id string, syncedAt, nextSyncAt time.Time,
		success bool, scopes []string, seen, unmanaged int, syncErr string) error

	// UpsertCloudCertificates writes what a sync found, keyed on the provider's
	// own resource id. Returns only the certificates that were new to this
	// connection — an alert is built from those, because a sync every six hours
	// re-reporting the same ACM inventory is how a channel gets muted.
	UpsertCloudCertificates(ctx context.Context, certs []*CloudCertificate) ([]*CloudCertificate, error)
	// MarkCloudCertificatesRemoved flags the certificates a successful sync did
	// not find any more. Called only after a sync that answered: marking
	// everything removed because an API call failed would report an estate
	// being dismantled.
	MarkCloudCertificatesRemoved(ctx context.Context, connectionID string, seenResourceIDs []string, at time.Time) (int, error)
	ListCloudCertificates(ctx context.Context, filter CloudCertificateFilter) ([]*CloudCertificate, int64, error)
	GetCloudCertificate(ctx context.Context, id string) (*CloudCertificate, error)
	// MarkCloudCertificateImported links a cloud certificate to the inventory
	// record somebody adopted it into, and settles its verdict.
	MarkCloudCertificateImported(ctx context.Context, id, certificateID string) error

	// ── Renewal queue ───────────────────────────────────────
	//
	// Renewal is the only part of this system that changes the world, so it
	// exists as durable rows rather than as calls: a process that dies
	// mid-renewal leaves behind something another process can pick up.

	// EnqueueRenewal creates a job unless one is already outstanding for this
	// certificate.
	//
	// Returns the existing job and false when there is one. This — rather than
	// leader election — is what makes the scheduler safe to run on every
	// replica: two of them enqueueing the same renewal in the same second is a
	// no-op for the second, not a duplicate issuance against a weekly rate
	// limit.
	EnqueueRenewal(ctx context.Context, job *RenewalJob) (created bool, err error)
	// ClaimRenewalJob takes the most urgent ready job and leases it.
	//
	// Ready means pending and due, or running with an expired lease — a worker
	// that was killed releases its job by the lease running out rather than by
	// anything having to reap it. Returns nil when the queue has nothing ready,
	// which is the ordinary case and not an error.
	ClaimRenewalJob(ctx context.Context, worker string, lease time.Duration, now time.Time) (*RenewalJob, error)
	// ExtendRenewalLease keeps a long-running job's claim alive. An ACME order
	// waiting on DNS propagation can outlive a short lease, and having it
	// stolen mid-flight is how one renewal becomes two certificates.
	ExtendRenewalLease(ctx context.Context, id, worker string, until time.Time) error
	// CompleteRenewalJob records the outcome of an attempt.
	//
	// A failed attempt that will be retried stays outstanding with run_after
	// moved forward; a terminal one is closed. The attempt is appended to the
	// log either way, because the history is what distinguishes a blip from a
	// fortnight of the same error.
	CompleteRenewalJob(ctx context.Context, id string, status string, attempt RenewalAttempt,
		runAfter time.Time, escalate bool) error
	GetRenewalJob(ctx context.Context, id string) (*RenewalJob, error)
	ListRenewalJobs(ctx context.Context, filter RenewalJobFilter) ([]*RenewalJob, int64, error)
	// CancelRenewalJob stops an outstanding job. Never used for failures — a
	// renewal nobody cancelled must keep trying.
	CancelRenewalJob(ctx context.Context, id string) error
	// DeferRenewalJob puts a claimed job back without counting the claim as an
	// attempt.
	//
	// Used when a CA's rate limit has no room. A deferral is not a failure —
	// nothing was tried — and recording it as one would inflate the attempt
	// count and escalate a certificate that is not broken.
	DeferRenewalJob(ctx context.Context, id string, runAfter time.Time, reason string, escalate bool) error
	// CountRecentRenewals reports how many renewals this CA account has
	// completed inside the window, and when the oldest of them ages out of it.
	//
	// Counted in the database rather than per process: N replicas each holding
	// their own token bucket would allow N times the limit, which for a public
	// CA means the whole organisation loses issuance for a week.
	CountRecentRenewals(ctx context.Context, caAccountID string, since time.Time) (count int, oldest *time.Time, err error)

	// ── Renewal information (RFC 9773) ──────────────────────

	// GetCertificatesDueForARICheck returns certificates whose renewal advice
	// should be refreshed — only ones that could act on the answer.
	GetCertificatesDueForARICheck(ctx context.Context, now time.Time, limit int) ([]*Certificate, error)
	// UpdateCertificateRenewalInfo records what the CA last said about when to
	// renew one certificate.
	//
	// Narrow rather than a full UpdateCertificate: the poller runs continuously
	// and concurrently with everything else, and a full-row write would let a
	// stale copy in its hand overwrite a renewal that completed while it was
	// asking.
	UpdateCertificateRenewalInfo(ctx context.Context, id string, info RenewalInfoUpdate) error

	// ── Post-renewal verification ───────────────────────────

	// GetCertificatesDueForVerification returns certificates whose deployment
	// should be checked.
	GetCertificatesDueForVerification(ctx context.Context, now time.Time, limit int) ([]*Certificate, error)
	// UpdateCertificateVerification records the outcome of one pass.
	UpdateCertificateVerification(ctx context.Context, id string, update VerificationUpdate) error
	// GetEndpointsServingCertificate returns the endpoints discovery last
	// observed serving one certificate — the only endpoints CertPilot has any
	// business connecting to in order to check a renewal reached them.
	GetEndpointsServingCertificate(ctx context.Context, certificateID, fingerprint string) ([]string, error)

	// ── Cryptographic posture ───────────────────────────────

	// UpsertEndpointTLSPosture records what one handshake negotiated, keyed on
	// host and port so a rescan updates rather than accumulates.
	UpsertEndpointTLSPosture(ctx context.Context, p *EndpointTLSPosture) error
	ListEndpointTLSPosture(ctx context.Context, filter EndpointTLSPostureFilter) ([]*EndpointTLSPosture, int64, error)
	// CountTLSPostureByVerdict is what the headline sentence is built from:
	// "142 of your endpoints do not negotiate a post-quantum key exchange".
	CountTLSPostureByVerdict(ctx context.Context) (map[string]int64, error)
	// ListCertificatesForAssessment returns certificates whose posture has not
	// been worked out, or was worked out before the certificate last changed.
	ListCertificatesForAssessment(ctx context.Context, limit int) ([]*Certificate, error)
	// UpdateCertificatePosture writes one assessment.
	UpdateCertificatePosture(ctx context.Context, id string, update CertificatePostureUpdate) error

	// ── Agents ──────────────────────────────────────────────
	//
	// The most security-critical records in the schema: an agent credential
	// will be able to ask for a certificate for a hostname and install it. What
	// is stored is a public key the agent generated on its own host, so this
	// database holds nothing that could impersonate one.

	ListAgents(ctx context.Context, filter AgentFilter) ([]*Agent, int64, error)
	GetAgent(ctx context.Context, id string) (*Agent, error)
	CreateAgent(ctx context.Context, a *Agent) error
	RevokeAgent(ctx context.Context, id string, revokedBy *string) error
	DeleteAgent(ctx context.Context, id string) error
	// RecordAgentHeartbeat writes what an agent last reported about itself.
	//
	// Narrow rather than a full-row write: heartbeats arrive continuously and
	// concurrently with whoever is renaming or revoking an agent, and a full
	// update would let a revoked agent's own heartbeat write its status back.
	RecordAgentHeartbeat(ctx context.Context, id string, hb AgentHeartbeat) error
	// GetStaleAgents returns the agents that have stopped reporting.
	//
	// Measured against each agent's own promised interval. A host whose agent
	// died three weeks ago still has certificates on it, still has them
	// expiring, and now has nothing maintaining them — and on a screen that only
	// lists what is enrolled it looks exactly like a healthy one.
	GetStaleAgents(ctx context.Context, now time.Time, limit int) ([]*Agent, error)
	// MarkAgentStaleAlerted records that an agent has been reported missing, so
	// the alert fires once rather than on every sweep.
	MarkAgentStaleAlerted(ctx context.Context, id string, at time.Time) error

	// ── What is on the hosts ────────────────────────────────

	// UpsertAgentCertificates writes what one host scan found, keyed on the
	// path it was found at. Returns only the entries that were new to this
	// agent, because an alert is built from those — a scan every six hours
	// re-reporting the same forty files is how a channel gets muted.
	UpsertAgentCertificates(ctx context.Context, certs []*AgentCertificate) ([]*AgentCertificate, error)
	// MarkAgentCertificatesRemoved flags the files a scan that succeeded did
	// not find any more. Called only after a scan that answered: marking
	// everything removed because an agent failed would report a host being
	// wiped.
	MarkAgentCertificatesRemoved(ctx context.Context, agentID string, seenPaths []string, at time.Time) (int, error)
	ListAgentCertificates(ctx context.Context, filter AgentCertificateFilter) ([]*AgentCertificate, int64, error)
	// MarkAgentInventoried records that a host reported, and how much it had.
	MarkAgentInventoried(ctx context.Context, id string, summary AgentInventorySummary) error
	// GetCertificateBySupersededFingerprint finds the managed certificate that
	// a given fingerprint used to be — the one a renewal replaced.
	//
	// This is what turns a file on a disk into the sharpest thing an inventory
	// can say: not "here is a certificate you do not manage" but "here is the
	// certificate you renewed last week, still sitting on this host". Returns
	// nil when nothing matches, which is the ordinary case.
	GetCertificateBySupersededFingerprint(ctx context.Context, fingerprint string) (*Certificate, error)

	// ── What each host has installed where ─────────────────

	// EnsureAgentDeploymentTarget returns the deployment target that is this
	// agent, creating it the first time the host reports a destination.
	//
	// Created by a report rather than by an operator filling in a form. Four
	// hundred hosts are four hundred targets, and a product that asks somebody
	// to create them by hand gets a script that creates them by hand — the same
	// reasoning that made agent grants match on labels rather than host ids.
	EnsureAgentDeploymentTarget(ctx context.Context, agent *Agent) (*DeploymentTarget, error)
	// ReplaceAgentInstallations writes the full state of one host's
	// destinations, removing any it no longer declares.
	//
	// Full state rather than a delta, exactly like the inventory: a lost report
	// costs nothing because the next one carries everything, and neither side
	// keeps a cursor the other could disagree with.
	ReplaceAgentInstallations(ctx context.Context, agentID string, installs []*AgentInstallation) error
	ListAgentInstallations(ctx context.Context, filter AgentInstallationFilter) ([]*AgentInstallation, int64, error)
	// EnsureCertificateDeployment returns the binding for a certificate at a
	// target, creating it if this is the first time the two have met.
	EnsureCertificateDeployment(ctx context.Context, d *CertificateDeployment) (*CertificateDeployment, error)
	// ClaimAgentDeploymentJobs leases the jobs waiting for one host.
	//
	// The counterpart of ClaimDeploymentJob, and the reason that one excludes
	// agent targets. A job for a host behind two firewalls cannot be run by a
	// core worker, and a worker that claimed one would fail it repeatedly until
	// the attempt budget ran out — loudly wrong about something that works.
	ClaimAgentDeploymentJobs(ctx context.Context, agentID, worker string,
		lease time.Duration, now time.Time, limit int) ([]*DeploymentJob, error)
	// PruneAgentBindings removes the bindings on one agent's target for
	// certificates that host is no longer installing.
	//
	// The agent reports full state, so the bindings have to be full state too.
	// Without this, an agent that renews leaves the binding for the certificate
	// it replaced sitting beside the new one, and both say that place is
	// holding the current certificate — one of which is false, asserted with
	// exactly the same confidence as the true one.
	//
	// Scoped to a target rather than general, because a binding an operator
	// created on a webhook target is a standing instruction that nothing should
	// delete on a host's say-so.
	PruneAgentBindings(ctx context.Context, targetID string, keepCertificateIDs []string) (int, error)

	// ── What a host may ask for ─────────────────────────────
	//
	// Nothing is issued to an agent that an operator has not granted in
	// advance. A credential that could request any name is a way to obtain a
	// certificate for the payroll system from a compromised web server, signed
	// by the organisation's own CA.

	ListTemplateGrants(ctx context.Context) ([]*TemplateGrant, error)
	GetTemplateGrant(ctx context.Context, id string) (*TemplateGrant, error)
	CreateTemplateGrant(ctx context.Context, g *TemplateGrant) error
	RevokeTemplateGrant(ctx context.Context, id string, revokedBy *string) error
	// GetGrantsForAgent returns the live grants that apply to one host, by id
	// or by label. Matching happens here rather than at every call site,
	// because "which grants apply" is the question an authorisation decision
	// rests on and it must have exactly one answer.
	GetGrantsForAgent(ctx context.Context, agentID string) ([]*TemplateGrant, error)

	ListAgentEnrolTokens(ctx context.Context) ([]*AgentEnrolToken, error)
	CreateAgentEnrolToken(ctx context.Context, t *AgentEnrolToken) error
	// GetAgentEnrolTokenByHash resolves a presented token. It returns the record
	// whatever its lifecycle state, so "revoked" is distinguishable from "never
	// existed" in the log while both stay a flat refusal on the wire.
	GetAgentEnrolTokenByHash(ctx context.Context, tokenHash string) (*AgentEnrolToken, error)
	// ConsumeAgentEnrolToken increments the use count, and only if there is a
	// use left.
	//
	// Conditional in the database rather than checked and then written: two
	// hosts booting from the same image enrol in the same second, and a
	// read-then-write would let a one-use token enrol both.
	ConsumeAgentEnrolToken(ctx context.Context, id string, now time.Time) (bool, error)
	RevokeAgentEnrolToken(ctx context.Context, id string, revokedBy *string) error

	// ClaimAgentRequestSignature records a signature and reports whether this
	// is the first time it has been seen. False means the request is a replay.
	//
	// Atomic for the same reason ConsumeAgentEnrolToken is: two copies of one
	// captured request can arrive at two replicas in the same millisecond, and
	// a read-then-write would let both through.
	ClaimAgentRequestSignature(ctx context.Context, agentID string, signatureHash []byte, expiresAt time.Time) (bool, error)
	// SweepAgentRequestSignatures drops rows past their expiry. Once the
	// timestamp window has closed the request is refused on its own, so the row
	// is no longer protecting anything.
	SweepAgentRequestSignatures(ctx context.Context, now time.Time) (int64, error)

	// ── Audit Logs ──────────────────────────────────────────
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, filter AuditLogFilter) ([]*AuditLog, int64, error)

	// UseAuditChain installs the key that makes new audit entries
	// tamper-evident. It is on the interface rather than a constructor argument
	// because the store is built before the keyring is loaded, and on the
	// interface rather than one implementation because a store that chains only
	// in memory would let the conformance suite agree with itself while the
	// real database wrote nothing.
	UseAuditChain(chainer *AuditChainer)
	// VerifyAuditChain walks the chain from a sequence number and reports the
	// first break. A limit of zero walks to the end.
	VerifyAuditChain(ctx context.Context, from int64, limit int) (*AuditChainReport, error)

	// ── Dashboard ───────────────────────────────────────────
	GetDashboardStats(ctx context.Context) (*DashboardStats, error)

	// Lifecycle
	Close()
}

// CertificateFilter defines query filtering options for certificates.
type CertificateFilter struct {
	Status      string
	Environment string
	// CommonName matches any of a certificate's names, the common name or any
	// SAN, by substring and ignoring case. Named for the query parameter it
	// came from; a certificate with no common name is found by its SANs (#108).
	CommonName  string
	CAAccountID string
	Limit       int
	Offset      int
}

// CA list sort orders.
const (
	// CASortUrgency puts the CA closest to expiry first. This is the order the
	// health view is built on: the question a PKI team asks a wall display is
	// "what breaks first", and a list sorted by name buries that answer
	// somewhere in the middle.
	CASortUrgency = "urgency"
	// CASortName is alphabetical, for the inventory view where someone is
	// looking for a specific CA rather than for trouble.
	CASortName = "name"
)

// CAFilter defines query filtering options for CA authorities.
type CAFilter struct {
	// Status matches exactly: HEALTHY, WARNING, CRITICAL, EXPIRED, UNKNOWN.
	Status string
	// ExpiringWithinDays keeps only CAs whose certificate expires within the
	// window. Zero means no window.
	//
	// Evaluated against not_after rather than the stored days_remaining
	// column: days_remaining is a snapshot written by the health sweep and is
	// wrong by however long it has been since the last one. A filter that
	// reports yesterday's urgency on a dashboard defeats the purpose.
	ExpiringWithinDays int
	// IncludeExpired controls whether already-expired CAs pass the
	// ExpiringWithinDays window. They do by default — an expired issuing CA is
	// the most urgent row on the screen, not one to filter out for having gone
	// past zero.
	ExcludeExpired bool
	// Sort is CASortUrgency or CASortName. Empty means CASortName.
	Sort string

	// IncludePEM asks for the certificate_pem column.
	//
	// Off by default: it is several kilobytes per CA, no dashboard renders it,
	// and the event-stream snapshot that carries this data is re-sent on every
	// client reconnect and every resynchronise. Only the health sweep, which
	// re-parses the certificate, needs it.
	IncludePEM bool
}

// AuditLogFilter defines query filtering options for audit log entries.
//
// Filtering exists chiefly so CA alerts are reachable. They share a table with
// every certificate issued, and at the issuance rates 47-day certificates imply
// a day's routine traffic buries a week of expiry warnings.
type AuditLogFilter struct {
	// Actions matches any of the listed actions. Empty means all of them.
	Actions []string
	// EntityType and EntityID narrow to one object's history.
	EntityType string
	EntityID   string
	// Since keeps entries at or after this instant. Zero means no lower bound.
	Since time.Time
	Limit int
	// Offset paginates. Note that new entries arrive at the head, so a deep
	// offset walked slowly will re-show rows; for a feed, filter by Since.
	Offset int
}

// RenewalInfoUpdate is what one ARI check learned.
type RenewalInfoUpdate struct {
	// RenewalScheduledAt is the instant chosen inside the CA's window. Nil when
	// the CA had no advice, which clears any stale schedule and returns the
	// certificate to lead-time renewal.
	RenewalScheduledAt *time.Time
	WindowStart        *time.Time
	WindowEnd          *time.Time
	ExplanationURL     string
	CheckedAt          *time.Time
	NextCheckAt        *time.Time
	// Supported is three-valued: nil unknown, false asked and unsupported.
	Supported *bool
}

// RenewalSafetyFloorDays is the point past which the CA's advice stops being
// able to defer a renewal.
//
// However far out a CA suggests renewing, a certificate this close to expiry
// renews anyway. A CA that publishes a bad window — or a poller that stopped
// running and left a stale one behind — must not be able to talk this system
// out of renewing something that is about to stop working.
const RenewalSafetyFloorDays = 7

// CertificateMetadataUpdate is the set of fields an operator owns on a
// certificate. Pointers so an omitted field is left alone rather than cleared —
// a form that submits only what it edited must not blank the rest.
type CertificateMetadataUpdate struct {
	Environment *string
	Team        *string
	Tags        *[]string
	Metadata    map[string]any
}
