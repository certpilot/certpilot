/**
 * API response types, mirroring core/store/models.go.
 *
 * The views previously typed every response as `any` and bound field names that
 * the backend never returns — `common_name` on a CA (it is `name`),
 * `key_algorithm` (`key_type`), `certs_issued` (`certificates_issued_count`),
 * `issuer` (`issuer_dn`). Those render blank or zero against a live backend and
 * nothing catches it, because `any` silences the compiler.
 *
 * Keep these in sync with the Go structs. `vue-tsc` then fails the build when a
 * template binds a field that does not exist.
 */

import type { CaStatus, CaType, CertStatus } from './severity'

/** core/store/models.go — CAAuthority */
export interface CaAuthority {
  id: string
  name: string
  ca_type: CaType
  subject_dn: string
  issuer_dn: string
  serial_number?: string
  not_before: string
  not_after: string
  days_remaining: number
  key_type: string
  key_size: number
  fingerprint_sha256: string
  certificate_pem: string
  parent_ca_id?: string | null
  crl_distribution_url?: string
  ocsp_responder_url?: string
  is_crl_fresh: boolean
  crl_last_checked?: string
  is_ocsp_responsive: boolean
  ocsp_last_checked?: string
  /**
   * What the responder said about this CA certificate itself.
   *
   * The OCSP URL in a certificate names the responder run by the authority
   * above it, so this is the answer to "has my parent revoked me" — the
   * highest-consequence fact about an intermediate. Absent means never asked,
   * which is not the same as UNKNOWN.
   */
  ocsp_status?: 'GOOD' | 'REVOKED' | 'UNKNOWN'
  ocsp_revoked_at?: string
  /** Why the last check produced no verified answer. */
  ocsp_last_error?: string
  certificates_issued_count: number
  alert_thresholds?: string
  last_alert_sent_at?: string
  last_alert_threshold?: number
  status: CaStatus
  ca_account_id?: string | null
  /** Who to call. Free text — team names do not live in CertPilot. */
  owner_team?: string | null
  owner_email?: string | null
  /**
   * The acknowledgement that currently applies, when one does.
   *
   * Resolved server-side against the CA's *current* threshold, so an
   * acknowledgement made at 30 days is absent once the CA has crossed 7 —
   * showing it as still acknowledged would be the false reassurance this
   * feature exists to avoid creating.
   */
  acknowledgement?: AlertAcknowledgement | null
  tags?: string
  notes?: string
  created_at: string
  updated_at: string
}

/**
 * core/store/models.go — AlertAcknowledgement.
 *
 * A record that a human has looked. **Silencing suppresses delivery, never
 * display**: an acknowledged CA still appears everywhere it appeared before,
 * marked. Nothing in the UI may filter a row out on the strength of this.
 */
export interface AlertAcknowledgement {
  id: string
  entity_type: 'ca_authority' | 'certificate'
  entity_id: string
  /** The expiry threshold in days this covers. A tighter one alerts again. */
  threshold?: number | null
  acknowledged_by?: string
  acknowledged_by_email?: string
  acknowledged_at: string
  note?: string
  /** Delivery is suppressed until this instant. Absent means not silenced. */
  silence_until?: string | null
  revoked_at?: string | null
  revoked_by?: string | null
  created_at: string
}

/** core/store/models.go — Certificate */
export interface Certificate {
  id: string
  fingerprint_sha256: string
  common_name: string
  sans: string[]
  serial_number?: string
  issuer_dn?: string
  not_before?: string
  not_after?: string
  days_remaining: number
  key_type?: string
  key_size?: number
  status: CertStatus
  auto_renew: boolean
  renewal_lead_days: number
  last_renewal_attempt?: string
  renewal_error?: string
  renewal_count: number
  ca_account_id?: string | null
  ca_authority_id?: string | null
  certificate_pem?: string
  chain_pem?: string
  discovered_via: 'MANUAL' | 'SCAN' | 'CT_LOG' | 'IMPORT' | 'REQUESTED' | 'AGENT' | 'CLOUD'
  /**
   * Who holds the private key — core/store/models.go KeyCustody*.
   *
   * The only honest basis for offering an export. Provenance cannot answer it:
   * a CSR-signed certificate is `REQUESTED` like any other and CertPilot holds
   * no key for it, so a UI keying off `discovered_via` would offer a download
   * that can only 404.
   */
  key_custody?: 'CERTPILOT' | 'AGENT' | 'EXTERNAL'
  /**
   * When the CA confirmed the revocation — core/store/models.go Certificate.
   *
   * The schema enforces that this and `status = 'REVOKED'` agree, so a record
   * can never read REVOKED while the certificate still answers handshakes.
   */
  revoked_at?: string | null
  /** The RFC 5280 CRLReason code it was revoked under. */
  revocation_reason?: number | null
  revoked_by?: string
  /** Values for the admin-defined MetadataFields, keyed by field key. */
  metadata?: Record<string, unknown>
  key_holder_agent_id?: string | null
  environment?: string
  team?: string
  tags?: string[]
  created_at: string
  updated_at: string
}

/** core/store/models.go — CAAccount. `config_encrypted` is never serialized. */
export interface CaAccount {
  id: string
  name: string
  provider_type: string
  gateway_addr: string
  /** Overrides the name expected in the gateway's TLS certificate. Empty means derive it from gateway_addr. */
  server_name?: string
  is_default: boolean
  status: 'CONNECTED' | 'DISCONNECTED' | 'ERROR'
  last_health_at?: string
  created_at: string
  updated_at: string
}

/** core/store/models.go — AuditLog. Note the timestamp field is `created_at`. */
export interface AuditLog {
  id: string
  action: string
  entity_type: string
  entity_id?: string
  actor_id?: string
  actor_email?: string
  /** JSON-encoded string, not an object. Parse with `parseDetails`. */
  details?: string
  ip_address?: string
  created_at: string
}

/** Shape of `details` on a `ca.expiry_alert` — core/engine/pki/ca_monitor.go */
export interface CaExpiryAlertDetails {
  ca_name: string
  ca_type: CaType
  days_remaining: number
  threshold: number
  severity: 'WARNING' | 'CRITICAL'
  not_after: string
}

/** Safely parses an audit log's JSON `details` field. */
export function parseDetails<T = Record<string, unknown>>(details?: string): T | null {
  if (!details) return null
  try {
    return JSON.parse(details) as T
  } catch {
    return null
  }
}

/** core/store/models.go — DashboardStats */
export interface DashboardStats {
  total_certificates: number
  healthy_certs: number
  expiring_soon_certs: number
  expired_certs: number
  total_cas: number
  healthy_cas: number
  warning_cas: number
  critical_cas: number
  /** Already expired. Split out from critical_cas: one can still be replaced
   *  in an orderly way, the other is already an outage. */
  expired_cas: number
  /** Never checked, or whose certificate could not be parsed. Counted and
   *  shown rather than hidden — a CA nobody can assess is not a healthy one. */
  unknown_cas: number
  total_scans: number
}

/**
 * core/store/models.go — NotificationChannel.
 *
 * `config_encrypted` is deliberately absent: it carries `json:"-"` server-side
 * because a Slack webhook URL and an SMTP password are bearer credentials. The
 * config is write-only from a client's point of view.
 */
export interface NotificationChannel {
  id: string
  name: string
  channel_type: 'slack' | 'webhook' | 'email'
  is_enabled: boolean
  severity_threshold: 'INFO' | 'WARNING' | 'CRITICAL'
  /** Empty means every topic. */
  topics: string[]
  last_sent_at?: string
  created_at: string
  updated_at: string
}

/** GET /api/v1/notification-channels — core/api/notifications.go */
export interface NotificationChannelList {
  data: NotificationChannel[]
  total: number
  supported_types: string[]
  topics: string[]
}

/** POST /api/v1/notification-channels/:id/test */
export interface NotificationTestResult {
  delivered: boolean
  message?: string
  error?: string
}

// ── Discovery ─────────────────────────────────────────────

/** One thing wrong with a discovered endpoint — core/store/models.go Finding */
export interface Finding {
  code: string
  severity: 'INFO' | 'WARNING' | 'CRITICAL'
  detail: string
}

/** core/store/models.go — DiscoveryScan */
export interface DiscoveryScan {
  id: string
  scan_type: 'network' | 'ct_log' | 'cloud'
  /** As typed. A CIDR stays a CIDR here; `target_count` says what it became. */
  targets: string[]
  /** CANCELLED is distinct from FAILED: somebody stopped it on purpose. */
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED'
  /** How many endpoints the run set out to reach, after expansion. */
  target_count: number
  results_count: number
  /** The headline. The only count that implies work. */
  unmanaged_count: number
  managed_count: number
  unreachable_count: number
  started_at?: string
  completed_at?: string
  error?: string
  actor_email?: string | null
  created_at: string
}

/**
 * core/store/models.go — DiscoveryResult.
 *
 * `management_state` is the verdict the whole feature exists to produce:
 * UNMANAGED means something is serving TLS with a certificate this system has
 * never seen, so nothing renews it and nobody is watching it expire.
 */
export interface DiscoveryResult {
  id: string
  scan_id: string
  host: string
  port: number
  reachable: boolean
  error?: string
  management_state: 'MANAGED' | 'UNMANAGED' | 'UNREACHABLE'
  trust_state: 'PUBLIC' | 'INTERNAL' | 'SELF_SIGNED' | 'UNTRUSTED' | 'UNKNOWN'
  matched_certificate_id?: string | null
  common_name?: string
  subject_dn?: string
  sans: string[]
  issuer_dn?: string
  serial_number?: string
  not_before?: string
  not_after?: string
  key_type?: string
  key_size?: number
  is_ca: boolean
  fingerprint_sha256?: string
  certificate_pem?: string
  chain_pem?: string
  chain_length: number
  tls_version?: string
  cipher_suite?: string
  /** The negotiated group, e.g. "X25519MLKEM768". Unrecoverable after the scan. */
  key_exchange?: string
  alpn?: string
  findings: Finding[]
  is_imported: boolean
  imported_certificate_id?: string | null
  scanned_at: string
  created_at: string
}

/**
 * core/store/models.go — DiscoverySchedule.
 *
 * An interval, not a cron expression: a cron field is a small language whose
 * mistakes are silent, and a schedule meant to run nightly that instead runs
 * yearly looks identical on screen to one that works.
 */
export interface DiscoverySchedule {
  id: string
  name: string
  /** As typed — "10.0.0.0/24", not the 254 addresses it becomes. */
  targets: string[]
  ports: number[]
  interval_minutes: number
  is_enabled: boolean
  /** When a run last *started*. The next run is computed from this. */
  last_run_at?: string | null
  next_run_at?: string | null
  last_scan_id?: string | null
  /** Why the last run did not happen. A schedule failing nightly and never
   *  read is worse than none: it is the appearance of coverage. */
  last_error?: string
  created_at: string
  updated_at: string
}

/** GET /api/v1/discovery/schedules */
export interface DiscoveryScheduleList {
  data: DiscoverySchedule[]
  total: number
  min_interval_minutes: number
}

/** POST /api/v1/discovery/scan and GET /api/v1/discovery/scans/:id */
export interface DiscoveryScanResponse {
  scan: DiscoveryScan
  data: DiscoveryResult[]
  total: number
  /** A sentence, because the counts alone cannot distinguish "nothing
   *  answered" from "everything is managed". */
  summary: string
  /** How many endpoints the targets expanded to. A /24 is 254. */
  target_count?: number
  /** Present on a 202: the run is in the background, poll this. */
  poll?: string
}

/**
 * core/store/models.go — CTMonitor.
 *
 * Note the two timestamps. `last_checked_at` is when a check was last
 * attempted, `last_success_at` when one last answered. A UI that shows only the
 * first lets a monitor that cannot reach the log read exactly like one that is
 * finding nothing — and only one of those means nobody is being told about
 * certificates issued in your name.
 */
export interface CTMonitor {
  id: string
  domain: string
  include_subdomains: boolean
  is_enabled: boolean
  check_interval_minutes: number
  last_checked_at?: string | null
  last_success_at?: string | null
  next_check_at?: string | null
  last_error?: string
  last_entry_id?: number | null
  /** Counted per certificate, not per log entry. */
  certificates_seen: number
  unmanaged_seen: number
  created_at: string
  updated_at: string
}

/** core/store/models.go — CTCertificate */
export interface CTCertificate {
  id: string
  monitor_id: string
  entry_id?: number | null
  logged_at?: string | null
  serial_number?: string
  issuer_dn?: string
  common_name?: string
  sans: string[]
  not_before?: string | null
  not_after?: string | null
  /** UNMANAGED here is stronger than on a scan: the certificate exists, is
   *  valid for your domain, and nothing here issued it. */
  management_state: 'MANAGED' | 'UNMANAGED'
  matched_certificate_id?: string | null
  /** The pre-issuance log entry. Hidden by default so one certificate counts
   *  once — before this existed a live check reported 18 where there are 9. */
  is_precertificate: boolean
  first_seen_at: string
  created_at: string
}

/** GET /api/v1/ct/monitors */
export interface CTMonitorList {
  data: CTMonitor[]
  total: number
  min_interval_minutes: number
  /** Domains whose checks have stopped answering. Nothing is watching them. */
  stale_domains: string[]
  warning?: string
}

/** core/store/models.go — Policy */
export interface Policy {
  id: string
  name: string
  description?: string
  is_enabled: boolean
  rule_type: string
  rule_config: string
  domain_pattern?: string
  severity: 'INFO' | 'WARNING' | 'BLOCK'
  created_at: string
  updated_at: string
}

/** core/store/models.go — CommonNameRule */
export interface CommonNameRule {
  /**
   * Absent and false are different answers. A template that has never
   * mentioned the common name has not decided it is optional.
   */
  required?: boolean
  suffixes?: string[]
  forbidden_patterns?: string[]
}

/** core/store/models.go — SANRules */
export interface SANRules {
  /** DNS, IP, email, URI. Empty means the template does not restrict them. */
  types?: string[]
  suffixes?: string[]
  /** A pointer in Go, for the same reason `required` is above. */
  allow_wildcards?: boolean
  max_names?: number
}

/**
 * core/store/models.go — CertificateTemplate
 *
 * Every numeric bound treats zero as "not constrained by this template". A
 * default of 2048 would look safe and would be a rule nobody wrote.
 */
export interface CertificateTemplate {
  id: string
  /** The stable machine name. What a pipeline names; survives a rename. */
  slug: string
  name: string
  description?: string
  /** Bumped when a rule changes, never by a rename. */
  version: number
  is_enabled: boolean

  ca_account_id: string
  ca_profile?: string

  subject_mode: 'SUPPLIED' | 'CONSTRAINED'
  subject_defaults: Record<string, string>
  common_name_rule: CommonNameRule
  san_rules: SANRules

  allowed_key_types: string[]
  rsa_min_bits: number
  rsa_max_bits: number
  ecdsa_curves: string[]
  csr_required: boolean
  key_custody_required: 'ANY' | 'CERTPILOT' | 'AGENT' | 'EXTERNAL'

  validity_days: number
  max_validity_days: number
  renew_before_days: number
  auto_renew: boolean

  require_metadata: string[]
  default_environment?: string
  default_team?: string
  default_tags: string[]

  created_at: string
  updated_at: string
}

/** core/store/models.go — TemplateGrant */
export interface TemplateGrant {
  id: string
  name: string
  template_id: string
  subject_kind: 'AGENT' | 'ROLE' | 'TEAM' | 'USER'
  agent_id?: string
  label_selector?: Record<string, string>
  role?: string
  team?: string
  user_id?: string
  names: string[]
  is_enabled: boolean
  revoked_at?: string
}

/** Gateway summary from GET /api/v1/gateways — core/api/ca_accounts.go */
export interface GatewaySummary {
  name: string
  addr: string
  type: string
  is_connected: boolean
  capabilities: ProviderCapabilities | null
  last_checked: string
}

export interface ProviderCapabilities {
  provider_name: string
  provider_version: string
  provider_type: string
  supports_wildcard: boolean
  supports_multi_domain: boolean
  supported_key_types: string[]
  supported_challenges: string[]
  validation_levels: string[]
  supports_revocation: boolean
  supports_ca_info: boolean
  description: string
}

// ── Live event stream ─────────────────────────────────────
//
// Shapes carried by GET /api/v1/events. Keep in sync with core/api/events.go
// and core/events/broker.go.

/**
 * The per-CA payload in a stream snapshot — core/api/events.go `caSummary`.
 *
 * Deliberately a subset of CaAuthority: the snapshot is re-sent on every
 * connect and every resynchronise, so it omits `certificate_pem` and the other
 * kilobyte fields a dashboard never draws.
 */
export interface CaSummary {
  id: string
  name: string
  ca_type: CaType
  status: CaStatus
  days_remaining: number
  not_after: string
  is_crl_fresh: boolean
  has_crl: boolean
  certificates_issued_count: number
  last_alert_threshold?: number
  parent_ca_id?: string | null
}

/** The `snapshot` event — complete current state, sent on connect. */
export interface StreamSnapshot {
  stats: DashboardStats
  cas: CaSummary[]
  /** Server clock, so a client can detect skew before judging its own staleness. */
  server_time: string
  last_event_id: number
}

/** Topics published by the core — core/events/broker.go. */
export type StreamTopic =
  | 'ca.health'
  | 'ca.expiry_alert'
  | 'cert.issued'
  | 'cert.renewed'
  | 'cert.renewal_failed'
  | 'cert.expiring'
  | 'gateway.status'
  | 'discovery.unmanaged'
  | 'discovery.changed'
  | 'discovery.progress'
  | 'ct.unmanaged'

/** One published change — core/events/broker.go `Event`. */
export interface StreamEvent {
  id: number
  /** Typed loosely: an unrecognised topic must render, not crash the feed. */
  topic: StreamTopic | string
  severity: 'INFO' | 'WARNING' | 'CRITICAL'
  entity_id?: string
  payload?: Record<string, unknown>
  timestamp: string
}

/** Payload of `ca.health` — core/engine/pki/ca_monitor.go */
export interface CaHealthPayload {
  ca_name: string
  ca_type: CaType
  previous_status: CaStatus
  status: CaStatus
  days_remaining: number
  is_crl_fresh: boolean
  not_after: string
}

/** Payload of `ca.expiry_alert` — core/engine/pki/ca_monitor.go */
export interface CaExpiryAlertPayload {
  ca_name: string
  ca_type: CaType
  days_remaining: number
  threshold: number
  severity: 'WARNING' | 'CRITICAL'
  not_after: string
}

/** Payload of the `cert.*` topics. Fields vary by topic; all are optional. */
export interface CertEventPayload {
  common_name?: string
  serial_number?: string
  days_remaining?: number
  not_after?: string
  gateway?: string
  renewal_count?: number
  error?: string
}

/** Most list endpoints wrap results this way. `GET /dashboard/stats` does not. */
export interface ListResponse<T> {
  data: T[]
  total: number
}

/** The empty list, for endpoints that legitimately return nothing yet. */
export function emptyList<T>(): ListResponse<T> {
  return { data: [], total: 0 }
}

// ── Custom metadata ────────────────────────────────────────

/** core/store/models.go — MetadataField.FieldType. */
export type MetadataFieldType = 'TEXT' | 'SELECT' | 'MULTI_SELECT' | 'BOOLEAN'

/**
 * How a single choice is drawn. The same data either way — a list of eight
 * options reads better as a dropdown and a list of two as radio buttons, and
 * which one is a judgement the person defining the field makes.
 */
export type MetadataDisplay = 'DROPDOWN' | 'RADIO'

export interface MetadataOption {
  /** Immutable. Certificates store this, so relabelling never rewrites them. */
  value: string
  label: string
}

/** core/store/models.go — MetadataField. */
export interface MetadataField {
  id: string
  /** The immutable machine name certificates key their values on. */
  key: string
  label: string
  field_type: MetadataFieldType
  options: MetadataOption[]
  display: MetadataDisplay
  help_text?: string
  is_required: boolean
  sort_order: number
  /** Archived fields stop being offered and keep labelling stored values. */
  is_archived: boolean
  created_at: string
  updated_at: string
}

/**
 * Renders a stored value using its field definition.
 *
 * Never prints the raw stored value: `tier_1` is what the database holds and
 * "Tier 1" is what it means, and a table showing the former makes the labels an
 * admin carefully chose pointless.
 */
export function formatMetadataValue(field: MetadataField, value: unknown): string {
  if (value === null || value === undefined || value === '') return '—'
  switch (field.field_type) {
    case 'BOOLEAN':
      return value ? 'Yes' : 'No'
    case 'SELECT':
      return field.options.find((o) => o.value === value)?.label ?? String(value)
    case 'MULTI_SELECT': {
      const chosen = Array.isArray(value) ? value : [value]
      if (!chosen.length) return '—'
      return chosen
        .map((v) => field.options.find((o) => o.value === v)?.label ?? String(v))
        .join(', ')
    }
    default:
      return String(value)
  }
}
