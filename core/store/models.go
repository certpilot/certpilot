// Package store provides database access models and queries for CertPilot.
package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CAAuthority represents a Certificate Authority record.
type CAAuthority struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	CAType             string     `json:"ca_type"` // ROOT, INTERMEDIATE, ISSUING
	SubjectDN          string     `json:"subject_dn"`
	IssuerDN           string     `json:"issuer_dn"`
	SerialNumber       string     `json:"serial_number,omitempty"`
	NotBefore          time.Time  `json:"not_before"`
	NotAfter           time.Time  `json:"not_after"`
	DaysRemaining      int        `json:"days_remaining"`
	KeyType            string     `json:"key_type"`
	KeySize            int        `json:"key_size"`
	FingerprintSHA256  string     `json:"fingerprint_sha256"`
	CertificatePEM     string     `json:"certificate_pem"`
	ParentCAID         *string    `json:"parent_ca_id,omitempty"`
	CRLDistributionURL string     `json:"crl_distribution_url,omitempty"`
	OCSPResponderURL   string     `json:"ocsp_responder_url,omitempty"`
	IsCRLFresh         bool       `json:"is_crl_fresh"`
	CRLLastChecked     *time.Time `json:"crl_last_checked,omitempty"`
	// IsOCSPResponsive means a verified answer was obtained, not that an HTTP
	// request succeeded. Before migration 033 it meant the latter, which any
	// web server at that address could satisfy.
	IsOCSPResponsive bool       `json:"is_ocsp_responsive"`
	OCSPLastChecked  *time.Time `json:"ocsp_last_checked,omitempty"`
	// OCSPStatus is what the responder said about this CA certificate: GOOD,
	// REVOKED or UNKNOWN. Empty means never asked, which is not the same as
	// UNKNOWN — that is the responder disclaiming knowledge of a certificate it
	// ought to know about.
	OCSPStatus    string     `json:"ocsp_status,omitempty"`
	OCSPRevokedAt *time.Time `json:"ocsp_revoked_at,omitempty"`
	// OCSPLastError says why the last check produced no verified answer. "The
	// responder is unreachable" and "something answered and it was not the CA"
	// are different problems, and a boolean cannot tell them apart.
	OCSPLastError           string     `json:"ocsp_last_error,omitempty"`
	CertificatesIssuedCount int64      `json:"certificates_issued_count"`
	AlertThresholds         string     `json:"alert_thresholds,omitempty"` // JSON string
	LastAlertSentAt         *time.Time `json:"last_alert_sent_at,omitempty"`
	LastAlertThreshold      *int       `json:"last_alert_threshold,omitempty"`
	Status                  string     `json:"status"` // HEALTHY, WARNING, CRITICAL, EXPIRED, UNKNOWN
	CAAccountID             *string    `json:"ca_account_id,omitempty"`
	// OwnerTeam and OwnerEmail say who to call. Free text: team names and
	// distribution lists do not live in CertPilot, and a foreign key to
	// something it does not own would mean either an import step or a wrong
	// answer on a row someone is reading at 2am.
	OwnerTeam  *string `json:"owner_team,omitempty"`
	OwnerEmail *string `json:"owner_email,omitempty"`
	Tags       string  `json:"tags,omitempty"`
	Notes      string  `json:"notes,omitempty"`
	// Source says who put this row here: a person, or a gateway that was asked
	// for its issuers. The importer refreshes what a certificate says about
	// itself and must never touch what an operator decided — the name they
	// chose, the thresholds they tuned, the team they put on it — so it needs
	// to know which rows are its own.
	Source string `json:"source,omitempty"`
	// LastSeenAt is when a gateway last reported this CA among its issuers.
	// An old value means the CA has been rotated out of the mount it came
	// from. It is not deleted: it signed certificates that are still being
	// served, and its expiry is still the date those stop working.
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	// Acknowledgement is the current acknowledgement, when the caller asked for
	// it to be resolved. Not a stored column — see AlertAcknowledgement.
	Acknowledgement *AlertAcknowledgement `json:"acknowledgement,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

// Where a CA authority record came from.
const (
	CASourceManual  = "MANUAL"
	CASourceGateway = "GATEWAY"
)

// Entity types an acknowledgement can cover.
const (
	AckEntityCAAuthority = "ca_authority"
	AckEntityCertificate = "certificate"
)

// AlertAcknowledgement records that a human has seen an alert and, optionally,
// that delivery should stay quiet for a while.
//
// The rule this type exists to enforce: **silencing suppresses delivery, never
// display.** An acknowledged CA still appears on the dashboard and in the wall
// view, marked as acknowledged and by whom. Hiding a problem because someone
// clicked a button is how CAs expire in organisations that believed they were
// monitoring them.
type AlertAcknowledgement struct {
	ID         string `json:"id"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	// Threshold is the expiry threshold, in days, that this acknowledgement
	// covers. Nil means it is not tied to one.
	//
	// This is the field that makes acknowledgement safe rather than dangerous.
	// Acknowledging a CA at 30 days must not silence its 7-day alert: the
	// situation has materially worsened, and the earlier "yes, we know" was an
	// answer to a different question.
	Threshold           *int       `json:"threshold,omitempty"`
	AcknowledgedBy      *string    `json:"acknowledged_by,omitempty"`
	AcknowledgedByEmail *string    `json:"acknowledged_by_email,omitempty"`
	AcknowledgedAt      time.Time  `json:"acknowledged_at"`
	Note                string     `json:"note,omitempty"`
	SilenceUntil        *time.Time `json:"silence_until,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevokedBy           *string    `json:"revoked_by,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// IsActive reports whether this acknowledgement still stands at the given
// instant, for an alert at the given threshold.
//
// `currentThreshold` is the threshold the alert is being raised at. A nil value
// means the caller is asking about the entity generally rather than about one
// alert.
func (a *AlertAcknowledgement) IsActive(now time.Time, currentThreshold *int) bool {
	if a == nil || a.RevokedAt != nil {
		return false
	}
	// A tighter threshold than the one acknowledged is a new situation, not a
	// repeat of the acknowledged one.
	if a.Threshold != nil && currentThreshold != nil && *currentThreshold < *a.Threshold {
		return false
	}
	return true
}

// SuppressesDelivery reports whether an alert should stay out of Slack and
// email right now.
//
// Deliberately distinct from IsActive: acknowledging without silencing is the
// common case — the alert stops being *new*, but still goes out — and only an
// explicit `silence_until` in the future stops delivery.
func (a *AlertAcknowledgement) SuppressesDelivery(now time.Time, currentThreshold *int) bool {
	if !a.IsActive(now, currentThreshold) {
		return false
	}
	return a.SilenceUntil != nil && a.SilenceUntil.After(now)
}

// CAAccount represents a Gateway Connection configuration.
type CAAccount struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ProviderType string `json:"provider_type"` // acme, vault, selfsigned, etc.
	GatewayAddr  string `json:"gateway_addr"`
	// ConfigEncrypted holds the sealed CA credentials. It is never serialized
	// to API clients: the ciphertext is not a secret by itself, but shipping
	// it to every dashboard reader turns one compromised KEK into a total
	// credential loss instead of requiring database access as well.
	ConfigEncrypted string `json:"-"`
	IsDefault       bool   `json:"is_default"`
	Status          string `json:"status"` // CONNECTED, DISCONNECTED, ERROR

	// RenewalRateLimit is how many certificates this account may successfully
	// renew inside RenewalRateWindowHours. Zero means unlimited.
	//
	// Unlimited is the right default. Inventing a conservative limit for a CA
	// whose real limits nobody has entered would delay renewals for a
	// constraint that does not exist, and a certificate that expired because
	// this tool was being cautious is the worst outcome available.
	RenewalRateLimit int `json:"renewal_rate_limit"`
	// RenewalRateWindowHours is the rolling window the limit is counted over.
	//
	// Hours rather than a named period, because providers do not agree on what
	// a period is — a rolling week for certificates, a rolling three hours for
	// orders — and hours is the only shape that describes all of them without
	// lying about any of them.
	RenewalRateWindowHours int        `json:"renewal_rate_window_hours"`
	LastHealthAt           *time.Time `json:"last_health_at,omitempty"`
	CreatedBy              *string    `json:"created_by,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// Certificate represents a managed TLS certificate.
type Certificate struct {
	ID                 string     `json:"id"`
	FingerprintSHA256  string     `json:"fingerprint_sha256"`
	CommonName         string     `json:"common_name"`
	SANs               []string   `json:"sans"`
	SerialNumber       string     `json:"serial_number,omitempty"`
	IssuerDN           string     `json:"issuer_dn,omitempty"`
	NotBefore          *time.Time `json:"not_before,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	DaysRemaining      int        `json:"days_remaining"`
	KeyType            string     `json:"key_type,omitempty"`
	KeySize            int        `json:"key_size,omitempty"`
	Status             string     `json:"status"` // PENDING, ISSUED, EXPIRING, EXPIRED, REVOKED, RENEWAL_FAILED
	AutoRenew          bool       `json:"auto_renew"`
	RenewalLeadDays    int        `json:"renewal_lead_days"`
	LastRenewalAttempt *time.Time `json:"last_renewal_attempt,omitempty"`
	RenewalError       *string    `json:"renewal_error,omitempty"`
	RenewalCount       int        `json:"renewal_count"`
	CAAccountID        *string    `json:"ca_account_id,omitempty"`
	CAAuthorityID      *string    `json:"ca_authority_id,omitempty"`
	DeploymentTargetID *string    `json:"deployment_target_id,omitempty"`
	// PrivateKeyEncrypted holds the sealed private key. It is never serialized
	// in a list or detail response; retrieving a key is a separate,
	// admin-only, audited operation.
	PrivateKeyEncrypted *string  `json:"-"`
	CertificatePEM      *string  `json:"certificate_pem,omitempty"`
	ChainPEM            *string  `json:"chain_pem,omitempty"`
	DiscoveredVia       string   `json:"discovered_via"` // MANUAL, SCAN, CT_LOG, IMPORT, REQUESTED
	Environment         string   `json:"environment,omitempty"`
	Team                string   `json:"team,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	// Metadata holds values for the admin-defined MetadataFields, keyed by
	// field key. Always non-nil after a read so a template can index it
	// without a guard.
	Metadata  map[string]any `json:"metadata"`
	CreatedBy *string        `json:"created_by,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	// KeyCustody says who holds the private key: CERTPILOT (sealed here),
	// AGENT (on a host, never anywhere else), or EXTERNAL (somebody we cannot
	// name). Until agents existed, "no key stored" meant only the last of
	// those; it now also means the best of the three.
	KeyCustody string `json:"key_custody,omitempty"`
	// KeyHolderAgentID is which host, when the answer is AGENT.
	KeyHolderAgentID *string `json:"key_holder_agent_id,omitempty"`

	// RenewalScheduledAt is when this certificate should next be renewed,
	// whoever decided it. Nil means nobody has been told anything and the lead
	// time applies.
	//
	// When ARI supplied it, this is a random instant inside the CA's suggested
	// window rather than its start. The randomness is the point of the window:
	// if every client renewed at the start, ARI would move the thundering herd
	// rather than disperse it.
	RenewalScheduledAt *time.Time `json:"renewal_scheduled_at,omitempty"`

	// The CA's renewal advice, as last read. ARIWindowStart and ARIWindowEnd
	// bound the window; ARIExplanationURL is the CA's link to a reason, set
	// when a window has been brought forward — which is exactly when somebody
	// wants to know why.
	ARIWindowStart    *time.Time `json:"ari_window_start,omitempty"`
	ARIWindowEnd      *time.Time `json:"ari_window_end,omitempty"`
	ARIExplanationURL string     `json:"ari_explanation_url,omitempty"`
	ARICheckedAt      *time.Time `json:"ari_checked_at,omitempty"`
	ARINextCheckAt    *time.Time `json:"ari_next_check_at,omitempty"`
	// ARISupported is three-valued on purpose. Nil means nobody has asked yet;
	// false means the CA was asked and does not publish renewal information.
	// Collapsing those would make a CA that has never been checked look
	// identical to one that has nothing to say.
	ARISupported *bool `json:"ari_supported,omitempty"`

	// VerificationState answers the only question that matters after a
	// renewal: is the thing in front of the users actually serving the new
	// certificate?
	//
	// PENDING, VERIFIED, STALE, UNREACHABLE, NO_ENDPOINTS. A renewal that
	// stored a certificate the server never picked up is the failure this
	// product exists to prevent, produced by this product — the inventory says
	// ninety days remaining and the endpoint says twenty.
	VerificationState string `json:"verification_state,omitempty"`

	// Cryptographic posture, written by the assessment sweep rather than at
	// issuance, so a certificate that arrives by any of the six routes into
	// this system is assessed the same way.
	SignatureAlgorithm    string          `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm    string          `json:"public_key_algorithm,omitempty"`
	PostureVerdict        string          `json:"posture_verdict,omitempty"`
	PostureSummary        string          `json:"posture_summary,omitempty"`
	PostureRequirements   json.RawMessage `json:"posture_requirements,omitempty"`
	QuantumReadinessScore *int            `json:"quantum_readiness_score,omitempty"`
	QuantumAssessedAt     *time.Time      `json:"quantum_assessed_at,omitempty"`

	// Revocation. RevokedAt and Status must agree — the schema enforces it,
	// because a row carrying a revocation timestamp while still reading ISSUED
	// is the disagreement that makes somebody trust the wrong one.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// RevocationReason is the RFC 5280 CRLReason, stored as the integer the
	// standard defines because that is what reaches the CRL and the OCSP
	// responder.
	RevocationReason *int   `json:"revocation_reason,omitempty"`
	RevokedBy        string `json:"revoked_by,omitempty"`
	// VerifyAfter is when the next check may run, set on a successful renewal
	// to now plus a grace period: a deployment done by hand does not happen in
	// the same second as the issuance.
	VerifyAfter          *time.Time `json:"verify_after,omitempty"`
	LastVerifiedAt       *time.Time `json:"last_verified_at,omitempty"`
	VerificationAttempts int        `json:"verification_attempts"`
	// VerificationDetail names the endpoints and what they were serving, so the
	// state does not have to be interpreted from a code.
	VerificationDetail string `json:"verification_detail,omitempty"`
	// PreviousFingerprint is what this certificate replaced, captured at
	// renewal. It is what makes "still serving the old one" distinguishable
	// from "something else entirely is here" — and the second is a different
	// problem deserving different words.
	PreviousFingerprint string `json:"previous_fingerprint,omitempty"`
}

// DeploymentTarget is one place certificates are installed.
//
// Deployment is where CertPilot stops observing and starts changing something
// that is currently carrying traffic, so a target carries more than an address:
// whether it is switched on, what went wrong last time, and whether private key
// material passes through it.
type DeploymentTarget struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	TargetType  string `json:"target_type"` // webhook, kubernetes, aws_acm, azure_kv, gcp_lb, filesystem
	// ConfigEncrypted is sealed with the keyring under
	// secrets.ContextDeploymentConfig. Read access to this row is not access to
	// whatever the target authenticates against.
	ConfigEncrypted string `json:"-"`
	IsEnabled       bool   `json:"is_enabled"`

	// DeploysPrivateKey records whether this target receives key material.
	//
	// Stored rather than derived from the sealed config, so "where does this
	// organisation ship private keys" is answerable by reading the target list
	// — without the KEK, and without decrypting anything.
	DeploysPrivateKey bool `json:"deploys_private_key"`

	// DeployOrder is which rollout wave this target belongs to. Lower goes
	// first, and a wave does not start until every earlier one has finished.
	//
	// Zero for everything by default, which is one wave and the behaviour that
	// existed before waves did. A canary is a target on its own in the lowest
	// wave: one target, exactly one attempt, declared rather than inferred.
	DeployOrder int `json:"deploy_order"`

	// CloudConnectionID names the account whose credentials this target
	// borrows, for the target types that borrow one.
	//
	// A plain column rather than a field inside the sealed config, and for the
	// same reason DeploysPrivateKey is one: "which cloud accounts can this
	// system write to" has to be answerable by reading the target list, without
	// the KEK and without decrypting anything.
	CloudConnectionID *string `json:"cloud_connection_id,omitempty"`

	// AgentID is set when this target is a host running the agent.
	//
	// It changes who does the work rather than what the work is. Everything
	// else in this table is deployed to by a core worker opening a connection;
	// an agent target is deployed to by the host itself claiming the job,
	// because the whole reason that host runs an agent is that nothing can
	// reach inwards to it. The core queue skips these for that reason.
	AgentID *string `json:"agent_id,omitempty"`

	// Attempted versus succeeded. A target that has been failing all week must
	// not read as one that simply has had nothing to do.
	LastDeploymentAt     *time.Time `json:"last_deployment_at,omitempty"`
	LastDeploymentStatus *string    `json:"last_deployment_status,omitempty"`
	LastDeploymentError  string     `json:"last_deployment_error,omitempty"`
	LastSuccessAt        *time.Time `json:"last_success_at,omitempty"`

	CreatedBy *string   `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Policy represents a security/compliance policy rule.
type Policy struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	IsEnabled     bool      `json:"is_enabled"`
	RuleType      string    `json:"rule_type"`
	RuleConfig    string    `json:"rule_config"` // JSON string
	DomainPattern string    `json:"domain_pattern,omitempty"`
	Severity      string    `json:"severity"` // INFO, WARNING, BLOCK
	CreatedBy     *string   `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Subject dispositions for CertificateTemplate.SubjectMode.
//
// There is deliberately no third value meaning "anything goes". That is
// SubjectModeConstrained with no constraints written, and it should look as
// empty as it is rather than carry a name that sounds deliberate.
const (
	// SubjectModeSupplied means the template provides the subject and the
	// requester may not set it. The default, and the safe one: AD CS calls the
	// alternative "Supply in the request", and combining it with broad
	// enrolment rights is ESC1.
	SubjectModeSupplied = "SUPPLIED"
	// SubjectModeConstrained means the requester provides the subject and it is
	// validated against the template.
	SubjectModeConstrained = "CONSTRAINED"
)

// KeyCustodyAny leaves custody to the request. The other three values are the
// KeyCustody* constants, asserted by a template about a class of certificate.
const KeyCustodyAny = "ANY"

// CommonNameRule constrains the certificate's common name.
//
// Required is a pointer because absent and false are different answers. A
// template that has never mentioned the common name has not decided it is
// optional, and a Go zero value would quietly make that decision.
type CommonNameRule struct {
	Required          *bool    `json:"required,omitempty"`
	Suffixes          []string `json:"suffixes,omitempty"`
	ForbiddenPatterns []string `json:"forbidden_patterns,omitempty"`
}

// SANRules constrains the subject alternative names.
type SANRules struct {
	// Types permitted: DNS, IP, email, URI. Empty means the template does not
	// restrict them.
	Types    []string `json:"types,omitempty"`
	Suffixes []string `json:"suffixes,omitempty"`
	// AllowWildcards is a pointer for the same reason Required is: a template
	// that never mentioned wildcards has not permitted or forbidden them.
	AllowWildcards *bool `json:"allow_wildcards,omitempty"`
	MaxNames       int   `json:"max_names,omitempty"`
}

// CertificateTemplate is what a kind of certificate looks like.
//
// Policies are the floor the whole estate must clear. A template is one use
// case above it — an internal mTLS certificate for a service mesh and a public
// TLS certificate for a marketing site share almost nothing, and a single list
// of rules true of both can only contain what they share.
//
// Unlike a policy, a template can do three things to a field rather than one:
// supply it, constrain it, or pass it through. That third axis is why this
// exists and is what Engine.EvaluateRequest cannot express.
//
// Every numeric bound here treats zero as "not constrained by this template".
// A default of 2048 would look safe and would be a rule nobody wrote.
type CertificateTemplate struct {
	ID string `json:"id"`
	// Slug is the stable machine name an agent or a CI job refers to. It
	// survives a rename; Name does not.
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Version is bumped whenever a rule changes, never by a rename.
	// Certificates record the version they were issued under, so "this
	// certificate violates its template" can be answered alongside "... which
	// has been edited twice since".
	Version   int  `json:"version"`
	IsEnabled bool `json:"is_enabled"`

	// CAAccountID is part of the template rather than the request: a requester
	// who could pick its own issuer could pick the cheapest, the least logged,
	// or the one with the widest trust.
	CAAccountID string `json:"ca_account_id"`
	// CAProfile names the CA's own template when it has one — a Vault role, an
	// ACME profile, an AWS Private CA template ARN. Nothing reads it yet.
	CAProfile string `json:"ca_profile,omitempty"`

	SubjectMode     string            `json:"subject_mode"`
	SubjectDefaults map[string]string `json:"subject_defaults"`
	CommonNameRule  CommonNameRule    `json:"common_name_rule"`
	SANRules        SANRules          `json:"san_rules"`

	AllowedKeyTypes []string `json:"allowed_key_types"`
	RSAMinBits      int      `json:"rsa_min_bits"`
	RSAMaxBits      int      `json:"rsa_max_bits"`
	// ECDSACurves names curves rather than counting bits. An RSA modulus and an
	// ECDSA curve order are not comparable numbers, and one column meaning both
	// is how "at least 2048" ends up rejecting P-384.
	ECDSACurves []string `json:"ecdsa_curves"`
	// CSRRequired means the requester must bring its own key. CertPilot never
	// holds one for a certificate issued under this template.
	CSRRequired bool `json:"csr_required"`
	// KeyCustodyRequired is ANY, or one of the KeyCustody* values asserted
	// about every certificate this template issues.
	KeyCustodyRequired string `json:"key_custody_required"`

	// ValidityDays is supplied: the requester does not choose.
	// MaxValidityDays is the ceiling for when they may. Zero means neither.
	ValidityDays    int  `json:"validity_days"`
	MaxValidityDays int  `json:"max_validity_days"`
	RenewBeforeDays int  `json:"renew_before_days"`
	AutoRenew       bool `json:"auto_renew"`

	// RequireMetadata names MetadataField keys a request must answer. Separate
	// from MetadataField.IsRequired, which is estate-wide: a change ticket may
	// be required for a production certificate and meaningless for a
	// short-lived test one, and that is a property of the template.
	RequireMetadata    []string `json:"require_metadata"`
	DefaultEnvironment string   `json:"default_environment,omitempty"`
	DefaultTeam        string   `json:"default_team,omitempty"`
	DefaultTags        []string `json:"default_tags"`

	CreatedBy *string   `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Live reports whether this template may issue anything right now.
func (t *CertificateTemplate) Live() bool {
	return t != nil && t.IsEnabled
}

// AuditLog represents an immutable audit log entry.
type AuditLog struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	EntityType string    `json:"entity_type"`
	EntityID   *string   `json:"entity_id,omitempty"`
	ActorID    *string   `json:"actor_id,omitempty"`
	ActorEmail *string   `json:"actor_email,omitempty"`
	Details    string    `json:"details,omitempty"` // JSON string
	IPAddress  *string   `json:"ip_address,omitempty"`
	CreatedAt  time.Time `json:"created_at"`

	// Seq is the entry's position in the tamper-evidence chain, assigned by the
	// store. Gapless, so a deleted entry shows up as a hole rather than simply
	// not being there. Zero for entries written before the chain existed.
	Seq int64 `json:"seq,omitempty"`
	// EntryHash is this entry's keyed tag; PrevHash is the tag of the entry
	// before it. PrevHash is not serialised because it is only meaningful while
	// walking the chain, and a caller that wants to check the record should ask
	// the verifier rather than reassemble the walk itself.
	EntryHash []byte `json:"entry_hash,omitempty"`
	PrevHash  []byte `json:"-"`
	// ChainKeyID names the KEK whose subkey produced EntryHash, so a chain
	// written before a key rotation stays verifiable afterwards.
	ChainKeyID string `json:"-"`
}

// DisplayToken is a long-lived, read-only credential for an unattended screen.
//
// It exists because a browser's EventSource cannot set an Authorization header,
// and because the alternative — an operator session left logged in on a machine
// in a corridor — carries the authority to issue, revoke, and export private
// keys. This credential carries none of that: the role it grants is hardcoded
// to viewer and the middleware refuses it on anything but a GET.
type DisplayToken struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// TokenHash is never serialized. It is not directly usable as a
	// credential, but shipping it to API clients would let anyone who can read
	// a list response confirm a guessed token offline.
	TokenHash  string     `json:"-"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	LastSeenIP *string    `json:"last_seen_ip,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  *string    `json:"revoked_by,omitempty"`
	CreatedBy  *string    `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Display token lifecycle states.
const (
	DisplayTokenActive  = "ACTIVE"
	DisplayTokenExpired = "EXPIRED"
	DisplayTokenRevoked = "REVOKED"
)

// Status reports the token's lifecycle state at the given instant.
//
// Revocation outranks expiry: a token that was revoked and has since also
// expired should still read as revoked, because that is the fact someone
// reviewing the list needs to see.
func (t *DisplayToken) Status(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return DisplayTokenRevoked
	case !t.ExpiresAt.After(now):
		return DisplayTokenExpired
	default:
		return DisplayTokenActive
	}
}

// IsUsable reports whether the token may authenticate a request.
func (t *DisplayToken) IsUsable(now time.Time) bool {
	return t.Status(now) == DisplayTokenActive
}

// NotificationChannel is a destination alerts are delivered to.
type NotificationChannel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ChannelType string `json:"channel_type"` // email, slack, webhook
	// ConfigEncrypted holds the sealed destination credentials — a Slack
	// webhook URL, an SMTP password. Never serialized, for the same reason as
	// CAAccount.ConfigEncrypted: a webhook URL is a bearer credential.
	ConfigEncrypted string `json:"-"`
	IsEnabled       bool   `json:"is_enabled"`
	// SeverityThreshold is the minimum severity this channel delivers.
	SeverityThreshold string `json:"severity_threshold"` // INFO, WARNING, CRITICAL
	// Topics restricts which event topics reach this channel. Empty means all
	// of them — a channel that matches nothing looks configured and delivers
	// nothing, which is the failure this whole subsystem exists to avoid.
	Topics     []string   `json:"topics"`
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
	CreatedBy  *string    `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Severity ordering, lowest first. Used to compare a channel's threshold
// against an event.
var severityRank = map[string]int{
	"INFO":     0,
	"WARNING":  1,
	"CRITICAL": 2,
}

// Accepts reports whether an event of this topic and severity should be
// delivered to the channel.
//
// A channel that is disabled accepts nothing. An unrecognised severity is
// treated as CRITICAL rather than dropped: failing to deliver an alert because
// its severity was spelled unexpectedly is the worse of the two mistakes.
func (c *NotificationChannel) Accepts(topic, severity string) bool {
	if !c.IsEnabled {
		return false
	}

	rank, ok := severityRank[severity]
	if !ok {
		rank = severityRank["CRITICAL"]
	}
	threshold, ok := severityRank[c.SeverityThreshold]
	if !ok {
		threshold = severityRank["WARNING"]
	}
	if rank < threshold {
		return false
	}

	if len(c.Topics) == 0 {
		return true
	}
	for _, t := range c.Topics {
		if t == topic {
			return true
		}
	}
	return false
}

// Discovery scan types, matching the check constraint on discovery_scans.
const (
	ScanTypeNetwork = "network"
	ScanTypeCTLog   = "ct_log"
	ScanTypeCloud   = "cloud"
)

// Discovery scan lifecycle states.
const (
	ScanPending   = "PENDING"
	ScanRunning   = "RUNNING"
	ScanCompleted = "COMPLETED"
	ScanFailed    = "FAILED"
	// ScanCancelled is distinct from ScanFailed on purpose. A scan somebody
	// stopped deliberately reached what it reached; recording that as a failure
	// would make the history lie about which runs went wrong, and the history
	// is what tells you whether scanning is working.
	ScanCancelled = "CANCELLED"
)

// Whether CertPilot already knows about a discovered certificate.
//
// This is the verdict discovery exists to produce. A scan of a real estate
// returns mostly certificates the team issued itself; the rows that matter are
// the ones it did not.
const (
	// DiscoveryManaged means the served certificate's fingerprint matches a
	// row in `certificates`.
	DiscoveryManaged = "MANAGED"
	// DiscoveryUnmanaged means it does not. Something is serving TLS with a
	// certificate this system has never seen, and nothing will renew it.
	DiscoveryUnmanaged = "UNMANAGED"
	// DiscoveryUnreachable means the endpoint did not complete a TLS
	// handshake, so there is no certificate to judge.
	DiscoveryUnreachable = "UNREACHABLE"
)

// What the served chain terminates in.
const (
	// TrustPublic — verifies against the host's public root store.
	TrustPublic = "PUBLIC"
	// TrustInternal — verifies against a CA registered in CertPilot. This is
	// the normal answer inside an organisation running private PKI, and it is
	// the one that ties an endpoint to a CA whose expiry is being watched.
	TrustInternal = "INTERNAL"
	// TrustSelfSigned — the leaf signed itself. Common on appliances and
	// forgotten test rigs, and a fair description of "nobody is managing this".
	TrustSelfSigned = "SELF_SIGNED"
	// TrustUntrusted — chains to neither. Either an intermediate is missing
	// from the served chain, or the issuing CA is one nobody has registered.
	TrustUntrusted = "UNTRUSTED"
	// TrustUnknown — not established, because the endpoint was unreachable.
	TrustUnknown = "UNKNOWN"
)

// Finding is one thing wrong with a discovered endpoint.
//
// Stored with the result rather than recomputed on read. A result is a record
// of what was observed at a moment; deriving findings at read time would mean a
// scan from March silently re-judged by today's rules, against a certificate
// that has since been replaced.
type Finding struct {
	// Code is a stable machine-readable identifier, e.g. "hostname_mismatch".
	Code string `json:"code"`
	// Severity is INFO, WARNING, or CRITICAL — the same vocabulary the event
	// stream and the notification channels use, so a finding can be routed
	// without translation.
	Severity string `json:"severity"`
	// Detail is a sentence someone can act on, naming the specific values
	// involved. "RSA-1024" beats "weak key".
	Detail string `json:"detail"`
}

// DiscoveryScan is one run of the scanner over a set of targets.
type DiscoveryScan struct {
	ID       string `json:"id"`
	ScanType string `json:"scan_type"`
	// Targets is what was asked for, as given. Kept verbatim so a scan can be
	// repeated and so an unexpected result can be traced back to the input
	// that produced it.
	Targets []string `json:"targets"`
	Status  string   `json:"status"`
	// TargetCount is how many endpoints the run set out to reach, once the
	// targets expanded — `10.0.0.0/24` is 254 of them. Without it a running
	// scan can say how many endpoints have answered but not out of how many,
	// and a scan whose end nobody can see is one people cancel out of doubt
	// rather than intent.
	TargetCount  int `json:"target_count"`
	ResultsCount int `json:"results_count"`
	// The three counts partition ResultsCount. UnmanagedCount is the headline:
	// it is the number a PKI team reads first and the only one that implies
	// work.
	UnmanagedCount   int        `json:"unmanaged_count"`
	ManagedCount     int        `json:"managed_count"`
	UnreachableCount int        `json:"unreachable_count"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	Error            string     `json:"error,omitempty"`
	TriggeredBy      *string    `json:"triggered_by,omitempty"`
	ActorEmail       *string    `json:"actor_email,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// DiscoveryResult is what one endpoint was serving when it was asked.
type DiscoveryResult struct {
	ID     string `json:"id"`
	ScanID string `json:"scan_id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`

	// Reachable is false when no TLS handshake completed. Error then carries
	// the dialler's own words — "connection refused" and "certificate signed
	// by unknown authority" are different problems and only one of them is
	// about certificates.
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`

	ManagementState string `json:"management_state"`
	TrustState      string `json:"trust_state"`
	// MatchedCertificateID names the managed certificate this fingerprint
	// belongs to, when there is one.
	MatchedCertificateID *string `json:"matched_certificate_id,omitempty"`

	CommonName        string     `json:"common_name,omitempty"`
	SubjectDN         string     `json:"subject_dn,omitempty"`
	SANs              []string   `json:"sans"`
	IssuerDN          string     `json:"issuer_dn,omitempty"`
	SerialNumber      string     `json:"serial_number,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	KeyType           string     `json:"key_type,omitempty"`
	KeySize           int        `json:"key_size,omitempty"`
	IsCA              bool       `json:"is_ca"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	CertificatePEM    string     `json:"certificate_pem,omitempty"`
	ChainPEM          string     `json:"chain_pem,omitempty"`
	// ChainLength is how many certificates the server sent, leaf included. One
	// means it sent no intermediates, which works only for clients that
	// already happen to hold them.
	ChainLength int `json:"chain_length"`

	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	// KeyExchange is the negotiated group, e.g. "X25519MLKEM768". Recorded on
	// every scan because it is unrecoverable afterwards and is the basis of
	// any later answer about quantum readiness.
	KeyExchange string `json:"key_exchange,omitempty"`
	ALPN        string `json:"alpn,omitempty"`

	Findings []Finding `json:"findings"`

	IsImported            bool      `json:"is_imported"`
	ImportedCertificateID *string   `json:"imported_certificate_id,omitempty"`
	ScannedAt             time.Time `json:"scanned_at"`
	CreatedAt             time.Time `json:"created_at"`
}

// WorstSeverity returns the highest severity among the result's findings, or
// "" when there are none. Used to sort a result list by how much attention it
// needs rather than by hostname.
func (r *DiscoveryResult) WorstSeverity() string {
	worst := ""
	worstRank := -1
	for _, f := range r.Findings {
		rank, ok := severityRank[f.Severity]
		if !ok {
			continue
		}
		if rank > worstRank {
			worstRank, worst = rank, f.Severity
		}
	}
	return worst
}

// DiscoverySchedule is a scan that runs by itself.
//
// Discovery run once is a snapshot; run repeatedly it is monitoring. The
// finding it exists to produce is created continuously — by deployments nobody
// mentioned and appliances nobody registered — so catching it means looking
// again without anyone remembering to.
type DiscoverySchedule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Targets as typed, not expanded. A schedule is edited by the person who
	// wrote it, and re-reading 254 addresses is not editing.
	Targets []string `json:"targets"`
	Ports   []int    `json:"ports"`
	// IntervalMinutes is how often it runs. Not a cron expression: an interval
	// is what a PKI team wants, and a cron field is a small language whose
	// mistakes are silent — a schedule meant to run nightly that instead runs
	// yearly looks identical on screen to one that works.
	IntervalMinutes int  `json:"interval_minutes"`
	IsEnabled       bool `json:"is_enabled"`
	// LastRunAt is when a run last started, not finished. The next run is
	// computed from it, so a long scan does not push its own schedule later
	// every time it runs.
	LastRunAt  *time.Time `json:"last_run_at,omitempty"`
	NextRunAt  *time.Time `json:"next_run_at,omitempty"`
	LastScanID *string    `json:"last_scan_id,omitempty"`
	// LastError is why the last run did not happen. Kept on the schedule so a
	// list can show which one has quietly stopped working: a schedule that
	// fails every night and is never read is worse than no schedule, because it
	// is the appearance of coverage.
	LastError string    `json:"last_error,omitempty"`
	CreatedBy *string   `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Due reports whether the schedule should run now.
func (s *DiscoverySchedule) Due(now time.Time) bool {
	if s == nil || !s.IsEnabled {
		return false
	}
	// A schedule that has never run is due immediately. Someone who has just
	// created one wants to know it works, not to find out tomorrow.
	if s.NextRunAt == nil {
		return true
	}
	return !s.NextRunAt.After(now)
}

// CTMonitor watches Certificate Transparency for one domain.
//
// Network scanning answers "what is being served on the addresses I told you
// about". CT answers a larger question: what has been issued in your name at
// all — by any CA, to anyone, whether or not it was ever deployed. A developer
// who obtained a certificate for api.corp.example.com with a personal ACME
// account appears in no scan of any range, and in CT within minutes.
type CTMonitor struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	// IncludeSubdomains watches *.example.com alongside example.com. On by
	// default: the subdomain nobody registered is the one worth finding.
	IncludeSubdomains bool `json:"include_subdomains"`
	IsEnabled         bool `json:"is_enabled"`
	// CheckIntervalMinutes is how often the log is queried. Floored higher than
	// a scan's interval, because the logs are read through a free community
	// service and polling it hard is how everyone loses access to it.
	CheckIntervalMinutes int `json:"check_interval_minutes"`

	// LastCheckedAt is when a check was last attempted. LastSuccessAt is when
	// one last answered.
	//
	// Keeping these apart is the point of the type. Collapsed into one, a
	// monitor that has been unable to reach the log for a week looks exactly
	// like a monitor that has found nothing for a week — and one of those means
	// nobody is being told about certificates issued in their name.
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	NextCheckAt   *time.Time `json:"next_check_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`

	// LastEntryID is the newest log entry already seen, so a later check asks
	// for what is new rather than re-reading years of history.
	LastEntryID      *int64    `json:"last_entry_id,omitempty"`
	CertificatesSeen int       `json:"certificates_seen"`
	UnmanagedSeen    int       `json:"unmanaged_seen"`
	CreatedBy        *string   `json:"created_by,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Due reports whether the monitor should be checked now.
func (m *CTMonitor) Due(now time.Time) bool {
	if m == nil || !m.IsEnabled {
		return false
	}
	if m.NextCheckAt == nil {
		return true
	}
	return !m.NextCheckAt.After(now)
}

// Stale reports whether it has been too long since a check actually answered.
//
// Separate from LastError: a monitor can fail silently by simply never being
// run — a core that was down, a loop that stopped — and "no error recorded"
// would then read as healthy.
func (m *CTMonitor) Stale(now time.Time) bool {
	if m == nil || !m.IsEnabled {
		return false
	}
	if m.LastSuccessAt == nil {
		// Never succeeded. Only stale once it has had time to try.
		return m.CreatedAt.Add(2 * time.Duration(m.CheckIntervalMinutes) * time.Minute).Before(now)
	}
	return m.LastSuccessAt.Add(3 * time.Duration(m.CheckIntervalMinutes) * time.Minute).Before(now)
}

// CTCertificate is one certificate a log reported for a watched domain.
type CTCertificate struct {
	ID        string `json:"id"`
	MonitorID string `json:"monitor_id"`
	// EntryID identifies the log entry, and is what makes a re-check idempotent.
	EntryID  *int64     `json:"entry_id,omitempty"`
	LoggedAt *time.Time `json:"logged_at,omitempty"`

	SerialNumber string     `json:"serial_number,omitempty"`
	IssuerDN     string     `json:"issuer_dn,omitempty"`
	CommonName   string     `json:"common_name,omitempty"`
	SANs         []string   `json:"sans"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`

	// ManagementState is MANAGED or UNMANAGED. Unmanaged here is a stronger
	// signal than on a scan result: a certificate valid for your domain exists,
	// somebody holds its private key, and nothing in this system issued it.
	ManagementState      string  `json:"management_state"`
	MatchedCertificateID *string `json:"matched_certificate_id,omitempty"`
	// IsPrecertificate marks the pre-issuance log entry. A precertificate and
	// its final certificate are two entries for one certificate; recorded
	// rather than dropped, but flagged so a count of findings is not doubled.
	IsPrecertificate bool `json:"is_precertificate"`

	FirstSeenAt time.Time `json:"first_seen_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// CTCertificateFilter narrows a list of CT findings.
type CTCertificateFilter struct {
	MonitorID       string
	ManagementState string
	// ExcludePrecertificates hides the pre-issuance entry when its final
	// certificate is also present, so one certificate counts once.
	ExcludePrecertificates bool
	Limit                  int
	Offset                 int
}

// DiscoveryResultFilter narrows a result list.
type DiscoveryResultFilter struct {
	// ScanID restricts to one run. Empty means across every scan, which is how
	// "everything unmanaged we have ever found" is asked.
	ScanID string
	// ManagementState is MANAGED, UNMANAGED, or UNREACHABLE.
	ManagementState string
	// TrustState is PUBLIC, INTERNAL, SELF_SIGNED, UNTRUSTED, or UNKNOWN.
	TrustState string
	// Host matches exactly.
	Host string
	// UnimportedOnly hides results someone has already adopted into inventory.
	UnimportedOnly bool
	// LatestPerEndpoint keeps only the newest observation of each host and
	// port.
	//
	// Without it, "everything we have found and not adopted" counts an endpoint
	// once per scan that ever touched it — so a nightly schedule turns one
	// unmanaged certificate into thirty findings, and the number stops meaning
	// anything. A result is a record of a moment; the outstanding-work list is
	// a question about now.
	LatestPerEndpoint bool
	Limit             int
	Offset            int
}

// DashboardStats holds summary statistics for the overview dashboard.
//
// The five CA counts partition the estate: every CA lands in exactly one, and
// they sum to TotalCAs. That matters more than it looks. Before this split,
// one implementation folded UNKNOWN into CriticalCAs and the other dropped it
// entirely, so the same database produced different numbers depending on which
// store was running — and a dashboard whose figures do not add up is one nobody
// trusts enough to act on.
type DashboardStats struct {
	TotalCertificates int64 `json:"total_certificates"`
	HealthyCerts      int64 `json:"healthy_certs"`
	ExpiringSoonCerts int64 `json:"expiring_soon_certs"`
	ExpiredCerts      int64 `json:"expired_certs"`
	TotalCAs          int64 `json:"total_cas"`
	HealthyCAs        int64 `json:"healthy_cas"`
	WarningCAs        int64 `json:"warning_cas"`
	CriticalCAs       int64 `json:"critical_cas"`
	ExpiredCAs        int64 `json:"expired_cas"`
	// UnknownCAs counts authorities that have never been checked, or whose
	// certificate could not be parsed. Shown rather than hidden: a CA nobody
	// can assess is not a healthy one.
	UnknownCAs int64 `json:"unknown_cas"`
	TotalScans int64 `json:"total_scans"`
}

// Cloud provider identifiers. The value is stored, so these are part of the
// schema's check constraint and cannot be renamed casually.
const (
	CloudProviderAWSACM        = "aws_acm"
	CloudProviderAzureKeyVault = "azure_key_vault"
	CloudProviderGCP           = "gcp"
	CloudProviderKubernetes    = "kubernetes"
)

// CloudConnection is one place certificates are stored that CertPilot did not
// put them.
//
// Credentials never live on this type in the clear: ConfigEncrypted is sealed
// with the keyring before it reaches the store, and carries `json:"-"` so that
// no handler can return it by forgetting to strip it.
type CloudConnection struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	// ConfigEncrypted holds the sealed provider credentials. Never serialised.
	ConfigEncrypted string `json:"-"`

	IsEnabled           bool `json:"is_enabled"`
	SyncIntervalMinutes int  `json:"sync_interval_minutes"`

	// LastSyncedAt is when a sync was last attempted; LastSuccessAt when one
	// last answered.
	//
	// The same split CTMonitor carries, for the same reason. A connection whose
	// credentials expired three weeks ago must not read like an account that
	// simply has no certificates in it — one of those is an all-clear and the
	// other is a blind spot.
	LastSyncedAt  *time.Time `json:"last_synced_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	NextSyncAt    *time.Time `json:"next_sync_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`

	// Scopes is what the last successful sync actually enumerated, in the
	// provider's own words.
	//
	// A cloud account has several places a certificate can sit, and a tool that
	// covers one of them while presenting itself as covering the provider
	// commits this product's original sin in a new place: a short list that
	// reads as a small estate when it is really a narrow search.
	Scopes []string `json:"scopes"`

	CertificatesSeen int       `json:"certificates_seen"`
	UnmanagedSeen    int       `json:"unmanaged_seen"`
	CreatedBy        *string   `json:"created_by,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Due reports whether this connection should be synced now.
func (c *CloudConnection) Due(now time.Time) bool {
	if c == nil || !c.IsEnabled {
		return false
	}
	if c.NextSyncAt == nil {
		return true
	}
	return !c.NextSyncAt.After(now)
}

// Stale reports that this connection has not answered in long enough that its
// silence means nothing.
//
// Three intervals, matching CTMonitor: one missed sync is a blip, three in a
// row is a connection nobody is maintaining.
func (c *CloudConnection) Stale(now time.Time) bool {
	if c == nil || !c.IsEnabled {
		return false
	}
	if c.LastSuccessAt == nil {
		// Never succeeded. Only stale once it has had time to try, so a
		// connection added a minute ago is not immediately an alarm.
		return c.CreatedAt.Add(2 * time.Duration(c.SyncIntervalMinutes) * time.Minute).Before(now)
	}
	return c.LastSuccessAt.Add(3 * time.Duration(c.SyncIntervalMinutes) * time.Minute).Before(now)
}

// CloudCertificate is one certificate found sitting in a cloud store.
type CloudCertificate struct {
	ID           string `json:"id"`
	ConnectionID string `json:"connection_id"`
	// ResourceID is the provider's own identifier — an ARN, a Key Vault
	// certificate id, a GCP self-link, a namespace/name. Unique per connection,
	// which is what makes a repeated sync an update rather than a duplicate.
	ResourceID string `json:"resource_id"`
	Name       string `json:"name,omitempty"`
	// Location is region, vault, or cluster — wherever the provider says this
	// lives. It is the first thing somebody needs in order to go and look.
	Location string `json:"location,omitempty"`

	CommonName        string     `json:"common_name,omitempty"`
	SubjectDN         string     `json:"subject_dn,omitempty"`
	IssuerDN          string     `json:"issuer_dn,omitempty"`
	SerialNumber      string     `json:"serial_number,omitempty"`
	SANs              []string   `json:"sans"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	KeyType           string     `json:"key_type,omitempty"`
	KeySize           int        `json:"key_size,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	CertificatePEM    string     `json:"certificate_pem,omitempty"`

	ManagementState      string  `json:"management_state"`
	MatchedCertificateID *string `json:"matched_certificate_id,omitempty"`

	// RenewalMode is what the provider says, verbatim — "IMPORTED",
	// "SELF_MANAGED", "AutoRenew", "cert-manager". Kept as the provider's own
	// word rather than reduced to a boolean, because that word is what somebody
	// has to go and find in their own console.
	RenewalMode string `json:"renewal_mode,omitempty"`
	// WillRenew is whether the provider itself renews this. Nil means the
	// provider did not say, which is not the same as no.
	WillRenew *bool `json:"will_renew,omitempty"`

	// Attached reports whether anything is using it. Nil means the provider
	// could not be asked — a Key Vault has no notion of attachment at all — and
	// that is deliberately distinct from false, which means nothing is using it.
	Attached   *bool    `json:"attached,omitempty"`
	AttachedTo []string `json:"attached_to"`

	Findings []Finding `json:"findings"`

	IsImported            bool    `json:"is_imported"`
	ImportedCertificateID *string `json:"imported_certificate_id,omitempty"`

	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	// RemovedAt is set when a sync that succeeded no longer found it. The row
	// is kept: a certificate that disappeared from the store is information,
	// and deleting it takes its own history along with it.
	RemovedAt *time.Time `json:"removed_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// WorstSeverity returns the highest severity among this certificate's findings.
func (c *CloudCertificate) WorstSeverity() string {
	rank := map[string]int{"INFO": 1, "WARNING": 2, "CRITICAL": 3}
	worst := ""
	for _, f := range c.Findings {
		if rank[f.Severity] > rank[worst] {
			worst = f.Severity
		}
	}
	return worst
}

// CloudCertificateFilter narrows a listing.
type CloudCertificateFilter struct {
	ConnectionID    string
	ManagementState string
	// FindingCode returns only certificates carrying this finding, which is how
	// "show me everything nothing will renew" is asked.
	FindingCode string
	// IncludeRemoved brings back certificates that have since disappeared from
	// the provider. Off by default: the list is about what is there now.
	IncludeRemoved bool
	UnimportedOnly bool
	Limit          int
	Offset         int
}

// Renewal job states.
const (
	RenewalPending   = "PENDING"
	RenewalRunning   = "RUNNING"
	RenewalSucceeded = "SUCCEEDED"
	RenewalFailed    = "FAILED"
	RenewalCancelled = "CANCELLED"
)

// Why a renewal job exists.
const (
	RenewalReasonScheduled = "SCHEDULED"
	RenewalReasonManual    = "MANUAL"
	RenewalReasonARI       = "ARI"
	RenewalReasonRetry     = "RETRY"
)

// RenewalAttempt is one try at a renewal, kept whether it worked or not.
//
// The list of these is the point. "This has failed eleven times in six days
// with the same DNS error" is a sentence somebody can act on; "last error:
// timeout" cannot distinguish a blip from a fortnight of silence.
type RenewalAttempt struct {
	Number     int       `json:"number"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	// Deferred marks an entry where no renewal was attempted at all — the CA's
	// rate limit had no room, so the job was put back.
	//
	// Kept distinct from a failure, and not counted as an attempt, because they
	// mean opposite things. A deferral is the system working: it declined to
	// spend a limit that would have suspended issuance for everyone. Counting
	// it as a failure would inflate the attempt count and escalate a
	// certificate that is not broken, which teaches people that escalation does
	// not mean anything.
	Deferred bool   `json:"deferred,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Worker names the process that made the attempt, so a failure isolated to
	// one replica is visible as one.
	Worker string `json:"worker,omitempty"`
	Error  string `json:"error,omitempty"`
}

// RenewalJob is one renewal that has been asked for and not yet finished.
//
// Renewal is the only part of this system that changes the world; everything
// else observes. So it exists as a row rather than as a call: a process that
// dies mid-renewal leaves behind something another process can pick up, rather
// than a certificate whose fate nobody recorded.
type RenewalJob struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	Reason        string `json:"reason"`
	Status        string `json:"status"`

	// RunAfter is when this job may next be attempted. Retries move it
	// forward; nothing else does.
	RunAfter time.Time `json:"run_after"`
	Attempts int       `json:"attempts"`

	// LockedBy and LockedUntil are the lease. A worker that is killed does not
	// need reaping — its claim expires and another worker takes the job.
	LockedBy    *string    `json:"locked_by,omitempty"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`

	LastError  string           `json:"last_error,omitempty"`
	AttemptLog []RenewalAttempt `json:"attempt_log"`

	// NotAfter is the deadline this job is racing, copied from the certificate
	// at enqueue. Denormalised so the queue can be ordered by urgency on every
	// claim without a join.
	NotAfter *time.Time `json:"not_after,omitempty"`

	// CAAccountID is which account's rate limit this renewal spends,
	// denormalised at enqueue for the same reason NotAfter is: it is read on
	// every pacing decision.
	CAAccountID *string `json:"ca_account_id,omitempty"`

	// FingerprintAtEnqueue is what the certificate was when the job was
	// created. The crash guard: if the certificate has moved on its own, the
	// renewal already happened and a retry must not issue a second one.
	FingerprintAtEnqueue string `json:"fingerprint_at_enqueue,omitempty"`

	// EscalatedAt marks a job a person should look at, so alerting does not
	// have to re-derive that from attempt counts.
	EscalatedAt *time.Time `json:"escalated_at,omitempty"`

	TriggeredBy *string `json:"triggered_by,omitempty"`
	ActorEmail  *string `json:"actor_email,omitempty"`

	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Outstanding reports whether this job still has work left in it.
func (j *RenewalJob) Outstanding() bool {
	return j != nil && (j.Status == RenewalPending || j.Status == RenewalRunning)
}

// RunwayHours is how long is left before the certificate this job is renewing
// expires. Negative once it has.
//
// The number that should decide everything about how this job is treated: how
// urgently it is retried, how loudly it is reported, and whether a failure is a
// nuisance or an outage in waiting.
func (j *RenewalJob) RunwayHours(now time.Time) float64 {
	if j == nil || j.NotAfter == nil {
		return 0
	}
	return j.NotAfter.Sub(now).Hours()
}

// RenewalJobFilter narrows a listing.
type RenewalJobFilter struct {
	CertificateID string
	Status        string
	// OutstandingOnly returns the queue rather than its history.
	OutstandingOnly bool
	// EscalatedOnly returns the jobs somebody needs to look at.
	EscalatedOnly bool
	Limit         int
	Offset        int
}

// Verification states for a renewed certificate.
const (
	VerificationPending     = "PENDING"
	VerificationVerified    = "VERIFIED"
	VerificationStale       = "STALE"
	VerificationUnreachable = "UNREACHABLE"
	VerificationNoEndpoints = "NO_ENDPOINTS"
)

// VerificationUpdate is what one verification pass learned — or, when a renewal
// schedules the first one, what it should look for.
type VerificationUpdate struct {
	State       string
	Detail      string
	CheckedAt   time.Time
	VerifyAfter *time.Time
	Attempts    int
	// PreviousFingerprint is written only when non-empty, because it is set
	// once by the renewal that scheduled the check and must survive every pass
	// that follows.
	PreviousFingerprint string
}

// ── Deployment ──────────────────────────────────────────────

// Binding states: what one place was last known to be holding.
const (
	DeploymentPending  = "PENDING"
	DeploymentDeployed = "DEPLOYED"
	DeploymentFailed   = "FAILED"
)

// Deployment job states.
const (
	DeployPending   = "PENDING"
	DeployRunning   = "RUNNING"
	DeploySucceeded = "SUCCEEDED"
	DeployFailed    = "FAILED"
	DeployCancelled = "CANCELLED"
)

// Why a deployment job exists.
const (
	DeployReasonRenewal = "RENEWAL"
	DeployReasonManual  = "MANUAL"
	DeployReasonRetry   = "RETRY"
	DeployReasonDrift   = "DRIFT"
)

// CertificateDeployment binds one certificate to one target.
//
// The binding, rather than a column on the certificate, because one wildcard on
// six load balancers is six deployments with six outcomes. A single deployed_at
// on the certificate would average them into a number that is true of nowhere.
type CertificateDeployment struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	TargetID      string `json:"target_id"`
	IsEnabled     bool   `json:"is_enabled"`

	// DeployOnRenewal is whether a renewal installs here by itself.
	//
	// A binding created now defaults to true — "install this certificate there"
	// obviously includes "when it changes". Bindings that predate the feature
	// were set to false by migration 023, because an upgrade that silently
	// began writing to production servers would be the fleet-wide mistake this
	// switch exists to bound, delivered by a package manager.
	DeployOnRenewal bool `json:"deploy_on_renewal"`

	// Options is per-binding placement — which secret in which namespace, which
	// path. Deliberately not a place for credentials: those belong to the
	// target, which is the thing that holds a connection.
	Options map[string]any `json:"options,omitempty"`

	// DeployedFingerprint is what this place was last confirmed to hold.
	//
	// Confirmed by a deploy that returned success, which is a claim about what
	// was sent — not evidence about what is being served. The evidence comes
	// from the verifier, which opens a connection and looks.
	DeployedFingerprint string     `json:"deployed_fingerprint,omitempty"`
	DeployedAt          *time.Time `json:"deployed_at,omitempty"`

	LastStatus string `json:"last_status,omitempty"`
	LastError  string `json:"last_error,omitempty"`

	// TargetName and TargetType are joined in for listings, so a page showing
	// where a certificate goes does not have to issue one lookup per row.
	TargetName string `json:"target_name,omitempty"`
	TargetType string `json:"target_type,omitempty"`

	CreatedBy *string   `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DeploymentOutcome is what one deploy attempt did to a binding.
//
// Narrow rather than a full row write: the queue runs concurrently with
// whoever is editing the binding, and a full-row update would let a stale copy
// in a worker's hand overwrite an options change made while it was deploying.
type DeploymentOutcome struct {
	Status string
	// Fingerprint is written only on success, and is what the target now holds.
	Fingerprint string
	Error       string
	At          time.Time
}

// DeploymentAttempt is one try at installing a certificate somewhere.
type DeploymentAttempt struct {
	Number     int       `json:"number"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	// Worker names the process that made the attempt, so a failure isolated to
	// one replica is visible as one.
	Worker string `json:"worker,omitempty"`
	// Detail is what the target said on success — the secret that was written,
	// the status the receiver returned. Kept because "it worked" without a
	// subject is not something anybody can check.
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// DeploymentJob is one installation that has been asked for and not finished.
//
// Durable for the same reason a renewal is: a process that dies mid-deploy must
// leave behind something another process can pick up. Held per binding rather
// than per certificate — one certificate going to six targets is six jobs, all
// outstanding at once.
type DeploymentJob struct {
	ID            string `json:"id"`
	DeploymentID  string `json:"deployment_id"`
	CertificateID string `json:"certificate_id"`
	TargetID      string `json:"target_id"`
	Reason        string `json:"reason"`
	Status        string `json:"status"`

	RunAfter time.Time `json:"run_after"`
	Attempts int       `json:"attempts"`

	LockedBy    *string    `json:"locked_by,omitempty"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`

	LastError  string              `json:"last_error,omitempty"`
	AttemptLog []DeploymentAttempt `json:"attempt_log"`

	// DeployOrder is the wave this job belongs to, copied from the target when
	// the rollout was enqueued. Copied rather than looked up, so that
	// reordering a target cannot change the plan of a rollout already under
	// way — which is how production ends up with a certificate staging never
	// accepted.
	DeployOrder int `json:"deploy_order"`

	// Fingerprint is what this job is trying to install, captured at enqueue.
	// Not read off the certificate at run time: a job enqueued by a renewal is
	// for that renewal's certificate, and if a newer one exists there is a
	// newer job behind this one.
	Fingerprint string `json:"fingerprint,omitempty"`
	// NotAfter is the expiry being raced, so the queue orders by urgency
	// without a join.
	NotAfter *time.Time `json:"not_after,omitempty"`

	EscalatedAt *time.Time `json:"escalated_at,omitempty"`

	TriggeredBy *string `json:"triggered_by,omitempty"`
	ActorEmail  *string `json:"actor_email,omitempty"`

	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Outstanding reports whether this job still has work left in it.
func (j *DeploymentJob) Outstanding() bool {
	return j != nil && (j.Status == DeployPending || j.Status == DeployRunning)
}

// DeploymentJobFilter narrows a listing.
type DeploymentJobFilter struct {
	CertificateID string
	TargetID      string
	DeploymentID  string
	Status        string
	// OutstandingOnly returns the queue rather than its history.
	OutstandingOnly bool
	// EscalatedOnly returns the jobs somebody needs to look at.
	EscalatedOnly bool
	Limit         int
	Offset        int
}

// ── Cryptographic posture ───────────────────────────────────

// EndpointTLSPosture is what one handshake with one endpoint actually
// negotiated.
//
// The only table in this system whose contents cannot be derived from an
// inventory. What a certificate is signed with is in the certificate; what an
// endpoint negotiates is a property of a running server and its configuration,
// and it takes a real connection to find out.
type EndpointTLSPosture struct {
	ID            string  `json:"id"`
	Host          string  `json:"host"`
	Port          int     `json:"port"`
	CertificateID *string `json:"certificate_id,omitempty"`
	ScanID        *string `json:"scan_id,omitempty"`

	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	// KeyExchangeGroup is the negotiated group — "X25519MLKEM768", "x25519".
	KeyExchangeGroup string `json:"key_exchange_group,omitempty"`
	// HybridKeyExchange is whether that group carries a post-quantum key
	// encapsulation, which is the single fact in this record that protects
	// traffic being recorded today.
	HybridKeyExchange bool `json:"hybrid_key_exchange"`
	// OfferedHybrid is whether CertPilot offered one. Without it,
	// HybridKeyExchange being false is a fact about CertPilot rather than about
	// the endpoint.
	OfferedHybrid bool   `json:"offered_hybrid"`
	SupportsTLS13 *bool  `json:"supports_tls13,omitempty"`
	ALPN          string `json:"alpn,omitempty"`

	Verdict      string          `json:"verdict,omitempty"`
	Summary      string          `json:"summary,omitempty"`
	Requirements json.RawMessage `json:"requirements,omitempty"`

	ObservedAt time.Time `json:"observed_at"`
}

// EndpointTLSPostureFilter narrows a listing.
type EndpointTLSPostureFilter struct {
	Host    string
	Verdict string
	// ExposedOnly returns the endpoints losing something today: traffic to them
	// is protected by a key exchange a future quantum computer breaks
	// retroactively.
	ExposedOnly bool
	Limit       int
	Offset      int
}

// CertificatePostureUpdate is what one assessment concluded.
//
// A narrow writer rather than fields on the certificate row, for the reason
// migration 016 taught: UpdateCertificate has an explicit column list, and
// adding to the model without adding to that list drops the value in silence.
type CertificatePostureUpdate struct {
	Verdict            string
	Summary            string
	Score              int
	Requirements       json.RawMessage
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	AssessedAt         time.Time
}

// ── Agents ──────────────────────────────────────────────────

// defaultAgentHeartbeatSeconds is what an agent reports at when nothing said
// otherwise.
//
// Defined here rather than in each store, because the two applying different
// floors is how a value the database refuses gets accepted in memory — which is
// exactly what happened before the conformance suite existed.
const defaultAgentHeartbeatSeconds = 300

// Agent lifecycle states.
const (
	AgentActive  = "ACTIVE"
	AgentRevoked = "REVOKED"
)

// Agent is one host running the CertPilot agent.
//
// The credential is a public key. The agent generated the pair on its own host
// during enrolment and has never sent the private half anywhere, so this record
// — and the whole database it sits in — holds nothing that could impersonate
// it. That is the same argument that makes local key generation the point of
// the agent at all; the identity key is simply the first key CertPilot never
// sees.
type Agent struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Hostname string `json:"hostname,omitempty"`
	Platform string `json:"platform,omitempty"`
	Version  string `json:"version,omitempty"`

	// PublicKey is PEM. Returned by the API on purpose: an operator comparing
	// it against what the agent printed on the host is how "is the thing
	// enrolled under this name the machine I ran the command on" gets answered.
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`

	Status string            `json:"status"`
	Labels map[string]string `json:"labels,omitempty"`

	EnrolTokenID *string   `json:"enrol_token_id,omitempty"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	EnrolledFrom string    `json:"enrolled_from,omitempty"`

	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	LastSeenIP string     `json:"last_seen_ip,omitempty"`
	// HeartbeatIntervalSeconds is what this agent said it would report at.
	// Staleness is measured against that rather than one global number that is
	// wrong for every agent configured differently.
	HeartbeatIntervalSeconds int        `json:"heartbeat_interval_seconds"`
	StaleAlertedAt           *time.Time `json:"stale_alerted_at,omitempty"`

	// LastInventoryAt is when this host last managed to report what is on it.
	// Distinct from LastSeenAt for the reason every "last synced" column in this
	// schema is: a host that has not been scanned since March must not read as a
	// host with nothing on it.
	LastInventoryAt  *time.Time `json:"last_inventory_at,omitempty"`
	CertificatesSeen int        `json:"certificates_seen"`
	UnmanagedSeen    int        `json:"unmanaged_seen"`

	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy *string    `json:"revoked_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// MissingFor reports how long past its promised reporting interval this agent
// is. Zero or negative means it is reporting as expected.
//
// The grace factor is the point. An agent that promised to report every five
// minutes and last spoke six minutes ago is not missing — it is a restarted
// service, a slow network, or a host that was busy. Three intervals is late
// enough that something is actually wrong and short enough to matter.
func (a *Agent) MissingFor(now time.Time) time.Duration {
	if a == nil || a.Status != AgentActive {
		return 0
	}
	interval := time.Duration(a.HeartbeatIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	// An agent that enrolled and never reported is measured from enrolment, so
	// one that failed on its very first heartbeat is as visible as one that
	// stopped after a year.
	last := a.EnrolledAt
	if a.LastSeenAt != nil && a.LastSeenAt.After(last) {
		last = *a.LastSeenAt
	}
	return now.Sub(last.Add(AgentStaleAfter * interval))
}

// AgentStaleAfter is how many promised intervals an agent may miss before it is
// treated as gone.
const AgentStaleAfter = 3

// AgentFilter narrows a listing.
type AgentFilter struct {
	Status string
	// StaleOnly returns the agents that have stopped reporting — the ones that
	// mean a host is no longer being maintained.
	StaleOnly bool
	Limit     int
	Offset    int
}

// AgentEnrolToken is a credential handed to a machine that has never spoken to
// CertPilot.
//
// Deliberately not the same credential the agent uses afterwards. A bootstrap
// secret and an operating secret have different blast radii, and a long-lived
// shared enrolment token pasted into a configuration management template is a
// credential in a git repository.
type AgentEnrolToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`

	MaxUses int `json:"max_uses"`
	Uses    int `json:"uses"`

	Labels map[string]string `json:"labels,omitempty"`

	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy *string    `json:"revoked_by,omitempty"`
	CreatedBy *string    `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Usable reports whether this token may still enrol an agent, and why not when
// it may not.
//
// One function rather than three checks at the call site, because "expired",
// "revoked", and "used up" are three ways for the same request to be refused
// and the caller has to get all three right every time it asks.
func (t *AgentEnrolToken) Usable(now time.Time) (bool, string) {
	switch {
	case t == nil:
		return false, "no such enrolment token"
	case t.RevokedAt != nil:
		return false, "this enrolment token was revoked"
	case !t.ExpiresAt.After(now):
		return false, "this enrolment token expired"
	case t.Uses >= t.MaxUses:
		return false, "this enrolment token has already been used the number of times it allows"
	}
	return true, ""
}

// AgentHeartbeat is what an agent reports about itself.
type AgentHeartbeat struct {
	Version  string
	Platform string
	Hostname string
	// IntervalSeconds is what the agent says it will report at next. Taken from
	// the agent rather than configured centrally, because the agent is the only
	// thing that knows what it was actually told to do.
	IntervalSeconds int
	SeenAt          time.Time
	SeenIP          string
}

// AgentCertificate is one certificate file found on one host.
//
// The fourth place certificates hide, after served, issued, and stored in a
// cloud: a file on a disk. And the only one where the observer is running on
// the machine, which is what makes the two fields nobody else can produce
// possible — the private key's permissions, and whether it matches.
//
// There is no private key here, and no field one could travel in.
type AgentCertificate struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	Path    string `json:"path"`

	// Kind is leaf, ca, or bundle. A trust store is recorded as one row that
	// says so rather than as a hundred findings about roots the distribution
	// manages.
	Kind             string `json:"kind"`
	CertificateCount int    `json:"certificate_count"`

	CommonName        string     `json:"common_name,omitempty"`
	SubjectDN         string     `json:"subject_dn,omitempty"`
	IssuerDN          string     `json:"issuer_dn,omitempty"`
	SerialNumber      string     `json:"serial_number,omitempty"`
	SANs              []string   `json:"sans,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	KeyType           string     `json:"key_type,omitempty"`
	KeySize           int        `json:"key_size,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	CertificatePEM    string     `json:"certificate_pem,omitempty"`

	// What only a process on the host can see.
	FileMode   string     `json:"file_mode,omitempty"`
	FileOwner  string     `json:"file_owner,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`

	PrivateKeyPath       string `json:"private_key_path,omitempty"`
	PrivateKeyMode       string `json:"private_key_mode,omitempty"`
	PrivateKeyInSameFile bool   `json:"private_key_in_same_file"`
	PrivateKeyMatches    bool   `json:"private_key_matches"`

	// ReferencedBy is which server configurations name this file. Found by text
	// search, so an empty list means "not matched", not "nothing uses this".
	ReferencedBy []string `json:"referenced_by,omitempty"`

	ManagementState      string  `json:"management_state"`
	MatchedCertificateID *string `json:"matched_certificate_id,omitempty"`

	Findings []Finding `json:"findings"`

	// AgentName is joined in for listings that span hosts, so a page of
	// findings does not need one lookup per row to say where they are.
	AgentName string `json:"agent_name,omitempty"`

	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	RemovedAt   *time.Time `json:"removed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// AgentCertificateFilter narrows a listing.
type AgentCertificateFilter struct {
	AgentID         string
	ManagementState string
	Kind            string
	// Finding matches rows carrying a finding with this code.
	Finding string
	// IncludeRemoved brings back files a later scan no longer found.
	IncludeRemoved bool
	Limit          int
	Offset         int
}

// What one declared destination on a host is currently doing.
const (
	InstallInstalled   = "INSTALLED"
	InstallFailed      = "FAILED"
	InstallUnfulfilled = "UNFULFILLED"
)

// AgentInstallation is one named place on one host that a certificate goes.
//
// The host's own view, kept beside the central one rather than instead of it.
// `CertificateDeployment` answers "what is this certificate's state at that
// place" in the same shape as every other target type, which is what makes an
// agent a deployment target like any other. This answers a question that only
// exists for agents: this machine has been configured to install a certificate
// nobody granted it, and nothing else in the system can see that.
//
// There is no command field this can be written *from*. ReloadCommand arrives
// from the host for display and travels in one direction only; a core that
// could set it would be a fleet-wide remote execution channel with a
// certificate manager on the front.
type AgentInstallation struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`

	// Name is the destination's name in the host's spec — "nginx", "haproxy".
	Name string `json:"name"`
	// CertificateName is the name the spec asks for, as written. Kept even when
	// nothing matched it, because the unmatched string is the finding.
	CertificateName string `json:"certificate_name"`

	CertificateID     *string    `json:"certificate_id,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`

	// Paths are the files this destination writes, in the order it writes them.
	Paths []string `json:"paths,omitempty"`

	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"last_error,omitempty"`

	// RolledBack records that a failed attempt put the previous material back.
	// Separate from the error: an install that failed and restored what was
	// working is an inconvenience, one that did not is an outage, and a single
	// status cannot say which.
	RolledBack bool `json:"rolled_back"`

	InstalledAt *time.Time `json:"installed_at,omitempty"`
	ReloadedAt  *time.Time `json:"reloaded_at,omitempty"`

	ReloadCommand string `json:"reload_command,omitempty"`
	CheckCommand  string `json:"check_command,omitempty"`

	// AgentName and Hostname are joined in for listings, so a page of what the
	// fleet has installed does not issue one lookup per row.
	AgentName string `json:"agent_name,omitempty"`
	Hostname  string `json:"hostname,omitempty"`

	ReportedAt time.Time `json:"reported_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AgentInstallationFilter narrows a listing.
type AgentInstallationFilter struct {
	AgentID       string
	CertificateID string
	Status        string
	// NeedsAttention returns the two rows a central team actually wants: what
	// is broken, and what is configured for a certificate that does not exist.
	NeedsAttention bool
	Limit          int
	Offset         int
}

// AgentInventorySummary is what one scan of one host amounted to.
type AgentInventorySummary struct {
	ScannedAt time.Time
	Seen      int
	Unmanaged int
}

// Who holds a certificate's private key.
const (
	// KeyCustodyCertPilot means the key is sealed in this database —
	// exportable, and therefore a thing that can be lost, copied, or subpoenaed.
	KeyCustodyCertPilot = "CERTPILOT"
	// KeyCustodyAgent means the key is on a host and has never been anywhere
	// else. CertPilot could not produce it if ordered to.
	KeyCustodyAgent = "AGENT"
	// KeyCustodyExternal means somebody holds it and it is not us: discovered,
	// imported, or issued elsewhere.
	KeyCustodyExternal = "EXTERNAL"
)

// AgentGrant is what a host is allowed to ask for.
//
// The security question that matters, and getting it wrong is worse than not
// having an agent at all. A credential that can request any name is a way to
// obtain a certificate for the payroll system from a compromised web server,
// signed by the organisation's own CA, looking exactly like every other
// issuance in the log.
type AgentGrant struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// AgentID targets one host. LabelSelector targets every agent carrying
	// these labels — which come from the enrolment token rather than from the
	// agent, so a host cannot label itself into somebody else's grant.
	AgentID       *string           `json:"agent_id,omitempty"`
	LabelSelector map[string]string `json:"label_selector,omitempty"`

	// Names permitted, as exact hostnames or single-level wildcards.
	Names []string `json:"names"`

	// CAAccountID is part of the grant rather than chosen by the agent: one
	// that could pick its own issuer could pick the cheapest, the least logged,
	// or the one with the widest trust.
	CAAccountID string `json:"ca_account_id"`

	MinKeySize      int      `json:"min_key_size"`
	AllowedKeyTypes []string `json:"allowed_key_types"`
	ValidityDays    int      `json:"validity_days"`
	RenewBeforeDays int      `json:"renew_before_days"`

	IsEnabled bool       `json:"is_enabled"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy *string    `json:"revoked_by,omitempty"`
	CreatedBy *string    `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Live reports whether this grant is currently permission for anything.
func (g *AgentGrant) Live() bool {
	return g != nil && g.IsEnabled && g.RevokedAt == nil
}

// AppliesTo reports whether this grant covers an agent.
//
// A label selector matches when every key it names matches. An empty selector
// on a grant with no agent cannot happen — the schema refuses it — because a
// grant matching nothing would sit in the list looking like permission somebody
// had given.
func (g *AgentGrant) AppliesTo(agent *Agent) bool {
	if g == nil || agent == nil || !g.Live() {
		return false
	}
	if g.AgentID != nil && *g.AgentID == agent.ID {
		return true
	}
	if len(g.LabelSelector) == 0 {
		return false
	}
	for key, want := range g.LabelSelector {
		if agent.Labels[key] != want {
			return false
		}
	}
	return true
}

// Covers reports whether this grant permits a hostname.
//
// Wildcards match one level, exactly as they do in a certificate:
// `*.example.com` covers `a.example.com`, and deliberately covers neither
// `a.b.example.com` nor `example.com`. Following the same rule certificates
// follow is what makes a grant mean what the person who wrote it thinks.
func (g *AgentGrant) Covers(name string) bool {
	if g == nil || name == "" {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))

	for _, pattern := range g.Names {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == name {
			return true
		}
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		suffix := pattern[1:] // ".example.com"
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		label := name[:len(name)-len(suffix)]
		if label != "" && !strings.Contains(label, ".") {
			return true
		}
	}
	return false
}

// MinEllipticBits is the floor for elliptic keys, whatever a grant says.
//
// P-256 is the smallest curve anybody should be using and every curve above it
// is larger, so there is nothing for a grant to tighten here — which is
// fortunate, because a grant cannot express a curve.
const MinEllipticBits = 256

// AllowsKey reports whether a key is of a permitted type and strong enough.
//
// The type is checked first, and MinKeySize is applied only to RSA. **Key sizes
// are not comparable across algorithms**: a P-256 key is considerably stronger
// than RSA-2048, and the integer 256 is smaller than 2048. One number compared
// against both refuses the stronger key for being the smaller number, which is
// how this was first written and what a test caught.
//
// So a grant's MinKeySize means RSA bits, elliptic keys are floored at the
// smallest curve worth using, and a grant that wants to require P-384
// specifically cannot say so — recorded as a known gap rather than papered over
// with a number that means two different things.
func (g *AgentGrant) AllowsKey(keyType string, keySize int) (bool, string) {
	if g == nil {
		return false, "no grant"
	}

	if len(g.AllowedKeyTypes) > 0 {
		permitted := false
		for _, allowed := range g.AllowedKeyTypes {
			if strings.EqualFold(allowed, keyType) {
				permitted = true
				break
			}
		}
		if !permitted {
			return false, fmt.Sprintf("this grant permits %s and the request carries %s",
				strings.Join(g.AllowedKeyTypes, ", "), keyType)
		}
	}

	switch strings.ToUpper(keyType) {
	case "RSA":
		floor := g.MinKeySize
		if floor < 2048 {
			// Nothing below this is worth signing, whatever a grant written
			// years ago happens to say.
			floor = 2048
		}
		if keySize < floor {
			return false, fmt.Sprintf("this grant requires at least %d-bit RSA and the request carries %d",
				floor, keySize)
		}
	default:
		if keySize < MinEllipticBits {
			return false, fmt.Sprintf("an elliptic key must be at least %d bits and the request carries %d",
				MinEllipticBits, keySize)
		}
	}
	return true, ""
}

// ── Custom metadata ────────────────────────────────────────

// Field type vocabulary for MetadataField.
const (
	MetadataText        = "TEXT"
	MetadataSelect      = "SELECT"
	MetadataMultiSelect = "MULTI_SELECT"
	MetadataBoolean     = "BOOLEAN"
)

// Display vocabulary for how a single choice is drawn.
const (
	MetadataDisplayDropdown = "DROPDOWN"
	MetadataDisplayRadio    = "RADIO"
)

// MetadataOption is one choice on a SELECT or MULTI_SELECT field.
//
// Value and Label are separate so a label can be reworded without rewriting
// every certificate that holds the value. Value is fixed at creation.
type MetadataOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// MetadataField is one question every certificate can answer.
//
// What a PKI team needs to slice its inventory by belongs to that team — cost
// centre, change ticket, data classification, which product line — and a fixed
// schema guesses at it and is wrong everywhere. An admin defines the fields.
type MetadataField struct {
	ID string `json:"id"`
	// Key is the immutable machine name certificates store their values under.
	Key       string           `json:"key"`
	Label     string           `json:"label"`
	FieldType string           `json:"field_type"`
	Options   []MetadataOption `json:"options"`
	Display   string           `json:"display"`
	HelpText  string           `json:"help_text,omitempty"`
	// IsRequired is enforced when a certificate is requested, never
	// retroactively: adding a required field must not invalidate the estate.
	IsRequired bool `json:"is_required"`
	SortOrder  int  `json:"sort_order"`
	// IsArchived fields stop being offered and keep labelling stored values.
	IsArchived bool      `json:"is_archived"`
	CreatedBy  *string   `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// HasOption reports whether value is one this field offers.
func (f *MetadataField) HasOption(value string) bool {
	for _, o := range f.Options {
		if o.Value == value {
			return true
		}
	}
	return false
}

// User is CertPilot's own record of a person who has signed in.
//
// The identity provider remains the authority on who somebody is; this is the
// authority on what they may do here. Roles used to come from a claim on the
// token, which meant that promoting a colleague required an administrator of
// the identity provider and took effect only when that person's token next
// refreshed — the wrong ownership for a team that runs the CA hierarchy but
// rarely runs Okta.
type User struct {
	ID string `json:"id"`
	// Issuer and Subject together are the identity. A subject is unique only
	// within the issuer that minted it, so neither half means anything alone.
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`

	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`

	Role   string `json:"role"`
	Status string `json:"status"`
	// RoleSource distinguishes a deliberate grant from a default and from a
	// bootstrap, so a users list can be read without guessing.
	RoleSource string `json:"role_source"`
	// MustChangePassword marks a credential the holder did not choose — the
	// generated one printed at first start. Not a control in itself; it is what
	// lets the UI insist rather than hope.
	MustChangePassword bool `json:"must_change_password"`

	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// LocalIssuer marks an account that exists only in CertPilot.
//
// Stored in the column an identity provider's issuer goes in, so that a local
// account and a federated one cannot collide even if a provider ever issued
// the same subject.
const LocalIssuer = "certpilot-local"

// RBAC roles, in ascending order of privilege.
//
// Declared here as well as in core/server/middleware because middleware
// imports this package and the dependency cannot run the other way. The three
// definitions that must agree are these constants, middleware.Role*, and the
// CHECK constraint on users.role in migration 028 — a Go constant a CHECK
// refuses is the oldest defect class in this store, and it fails at runtime on
// the write, not at compile time.
const (
	RoleViewer   = "viewer"
	RoleAuditor  = "auditor"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// ValidRole reports whether a role is one the store will accept, so a handler
// can refuse a bad value with a message instead of surfacing a CHECK violation.
func ValidRole(role string) bool {
	switch role {
	case RoleViewer, RoleAuditor, RoleOperator, RoleAdmin:
		return true
	}
	return false
}

// User status values. Suspension is not deletion: removing the row would
// orphan every audit entry attributed to that subject.
const (
	UserStatusActive    = "ACTIVE"
	UserStatusSuspended = "SUSPENDED"
)

// How a user came to hold the role they hold.
const (
	RoleSourceDefault   = "DEFAULT"
	RoleSourceBootstrap = "BOOTSTRAP"
	RoleSourceAssigned  = "ASSIGNED"
)

// IsActive reports whether this user may act at all.
func (u *User) IsActive() bool { return u.Status == UserStatusActive }

// UserIdentity is what an authenticated request knows about its caller before
// the store has been consulted.
type UserIdentity struct {
	Issuer      string
	Subject     string
	Email       string
	DisplayName string
}

// Session is a signed-in browser.
//
// Rows rather than signed tokens, so that the core holds no key capable of
// forging one and so a session can be ended the instant an account is
// suspended. The raw token exists only in the cookie; what is stored is its
// SHA-256 hash, compared in constant time — the same design as DisplayToken.
type Session struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// TokenHash is hex-encoded SHA-256. The raw token is returned once, at
	// creation, and never again.
	TokenHash string `json:"-"`

	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	LastSeenIP string     `json:"last_seen_ip,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// IsUsable reports whether this session may still authenticate a request.
func (s *Session) IsUsable(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// LoginOutcome is why a password sign-in did not succeed.
//
// The distinctions exist for the audit log and for the operator reading it. The
// caller is told only that sign-in failed: telling somebody that an address
// exists but the password was wrong is how an attacker enumerates accounts, and
// telling them an account is locked tells them their guessing is working.
type LoginOutcome int

const (
	LoginOK LoginOutcome = iota
	LoginNoSuchAccount
	LoginWrongPassword
	LoginLockedOut
	LoginSuspended
	LoginNoPasswordSet
)

// LoginLockout is the throttle applied to password sign-in.
//
// Held in the database rather than in process memory because the core runs as
// several replicas behind a load balancer, and an attacker spreading attempts
// across them would reset an in-memory counter with every request. CertPilot
// has no rate limiting, so this is the only thing standing between a password
// endpoint and an unlimited guessing oracle.
const (
	MaxFailedLogins = 8
	LockoutWindow   = 15 * time.Minute
)

// RevocationReasons are the RFC 5280 CRLReason codes CertPilot accepts.
//
// The set is ACME's, which is the narrowest of the three gateways and therefore
// the one that works everywhere. certificateHold (6) is deliberately excluded:
// it is reversible, nothing here can lift a hold, and offering it would let
// somebody believe they had suspended a certificate this system can never
// un-suspend.
var RevocationReasons = map[int]string{
	0: "unspecified",
	1: "keyCompromise",
	3: "affiliationChanged",
	4: "superseded",
	5: "cessationOfOperation",
	9: "privilegeWithdrawn",
}

// ValidRevocationReason reports whether a reason code may be used.
func ValidRevocationReason(reason int) bool {
	_, ok := RevocationReasons[reason]
	return ok
}
