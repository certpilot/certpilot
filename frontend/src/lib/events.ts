/**
 * Rendering for live stream events.
 *
 * Kept out of the store and out of the views because three surfaces will show
 * the same event — the alert list, the dashboard feed, and the wall display —
 * and three copies of "what does cert.renewal_failed mean" would drift the way
 * the four copies of the severity mapping did.
 */

import type { Severity } from './severity'
import { parseDetails } from './types'
import type {
  AuditLog,
  CaExpiryAlertDetails,
  CaExpiryAlertPayload,
  CaHealthPayload,
  CertEventPayload,
  StreamEvent,
} from './types'

/**
 * Severity of an event, from the severity the *server* assigned.
 *
 * Deliberately not recomputed from the payload. The core decided this was
 * critical when it published it, and a dashboard that reaches a different
 * verdict than the thing that sends the alerts is worse than one that simply
 * mirrors it.
 */
export function eventSeverity(event: StreamEvent): Severity {
  switch (event.severity) {
    case 'CRITICAL':
      return 'critical'
    case 'WARNING':
      return 'warning'
    case 'INFO':
      return 'ok'
    default:
      return 'unknown'
  }
}

/** True for events a PKI team needs to act on, as opposed to routine noise. */
export function isActionable(event: StreamEvent): boolean {
  return event.severity === 'WARNING' || event.severity === 'CRITICAL'
}

/** One-line description of an event, for a feed. */
export function describeEvent(event: StreamEvent): string {
  const payload = event.payload ?? {}

  switch (event.topic) {
    case 'ca.health': {
      const p = payload as unknown as CaHealthPayload
      const name = p.ca_name ?? 'A certificate authority'
      if (p.previous_status && p.status) {
        return `${name} moved from ${humanize(p.previous_status)} to ${humanize(p.status)}`
      }
      return `${name} is now ${humanize(p.status)}`
    }

    case 'ca.expiry_alert': {
      const p = payload as unknown as CaExpiryAlertPayload
      const name = p.ca_name ?? 'A certificate authority'
      // The threshold matters: it is why this fired now rather than yesterday,
      // and it is what an operator silences or adjusts.
      return `${name} expires in ${p.days_remaining} days — crossed the ${p.threshold}-day threshold`
    }

    case 'cert.issued': {
      const p = payload as unknown as CertEventPayload
      return `Issued ${p.common_name || 'a certificate'}${p.gateway ? ` via ${p.gateway}` : ''}`
    }

    case 'cert.renewed': {
      const p = payload as unknown as CertEventPayload
      return `Renewed ${p.common_name || 'a certificate'}${
        p.days_remaining !== undefined ? ` — valid for ${p.days_remaining} more days` : ''
      }`
    }

    case 'cert.renewal_failed': {
      const p = payload as unknown as CertEventPayload
      const subject = p.common_name || 'a certificate'
      return `Renewal failed for ${subject}${p.error ? `: ${p.error}` : ''}`
    }

    case 'cert.expiring': {
      const p = payload as unknown as CertEventPayload
      return `${p.common_name || 'A certificate'} expires in ${p.days_remaining ?? '?'} days`
    }

    case 'gateway.status': {
      const p = payload as { name?: string; connected?: boolean }
      return `Gateway ${p.name ?? 'unknown'} is ${p.connected ? 'connected' : 'unreachable'}`
    }

    default:
      // An unrecognised topic still renders. A future core publishing something
      // this build has never heard of should show up as an unfamiliar line, not
      // vanish from the feed.
      return event.topic
  }
}

/** Short label for the entity kind an event concerns. */
export function eventCategory(event: StreamEvent): string {
  if (event.topic.startsWith('ca.')) return 'CA'
  if (event.topic.startsWith('cert.')) return 'Certificate'
  if (event.topic.startsWith('gateway.')) return 'Gateway'
  return 'Event'
}

function humanize(value: string | undefined): string {
  if (!value) return 'unknown'
  return value.toLowerCase()
}

/**
 * Renders an audit entry as a sentence, with CA alerts given their real detail.
 *
 * Lived inside DashboardView, which meant every other surface that showed audit
 * rows either duplicated it or printed the raw `cert.renewal_failed` action
 * string at the reader. It belongs beside describeEvent: the two answer the same
 * question about the same vocabulary, one for the live stream and one for the
 * recorded log.
 */
export function describeAudit(log: AuditLog, nameOf?: (log: AuditLog) => string | undefined): string {
  if (log.action === 'ca.expiry_alert') {
    const d = parseDetails<CaExpiryAlertDetails>(log.details)
    if (d) return `${d.ca_name} expires in ${d.days_remaining} days (${d.threshold}-day threshold)`
  }
  const d = parseDetails<{ cn?: string; ca_name?: string; error?: string }>(log.details)
  // `||`, not `??`: a certificate with no common name is recorded with an empty
  // one, which is true, and shown as nothing, which is not useful (#108). A
  // caller holding the certificates can name it; otherwise its kind will do.
  const subject = d?.cn || nameOf?.(log) || d?.ca_name || log.entity_type
  switch (log.action) {
    case 'cert.issued':
      return `Issued ${subject}`
    case 'cert.renewed':
      return `Renewed ${subject}`
    case 'cert.renewal_failed':
      return `Renewal failed for ${subject}${d?.error ? `: ${d.error}` : ''}`
    case 'cert.deleted':
      return `Deleted ${subject}`
    case 'cert.private_key_exported':
      return `Private key exported for ${subject}`
    case 'ca_account.created':
      return `CA account ${subject} registered`
    default:
      return `${log.action} — ${subject}`
  }
}

/** Severity of a recorded audit entry, matching describeAudit's vocabulary. */
export function auditSeverity(log: AuditLog): Severity {
  if (log.action === 'ca.expiry_alert') {
    const d = parseDetails<CaExpiryAlertDetails>(log.details)
    return d?.severity === 'CRITICAL' ? 'critical' : 'warning'
  }
  if (log.action.endsWith('_failed')) return 'critical'
  if (log.action === 'cert.private_key_exported') return 'warning'
  return 'ok'
}
