/**
 * Shared formatting helpers.
 *
 * These were reimplemented in four views with subtly different behaviour —
 * notably `daysUntil`, which several views recomputed client-side even though
 * the API already returns `days_remaining`. Recomputing invites drift between
 * what the dashboard shows and what the alerting engine decided.
 */

/** Formats an ISO timestamp as a short absolute date. */
export function formatDate(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

/** Formats an ISO timestamp as date and time, for audit trails. */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

/** Clock time only — used by the "last updated" indicator. */
export function formatTime(value: Date | string | null | undefined): string {
  if (!value) return '—'
  const date = typeof value === 'string' ? new Date(value) : value
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

/** "3 minutes ago", "yesterday" — for activity feeds. */
export function formatRelative(value: string | Date | null | undefined): string {
  if (!value) return '—'
  const date = typeof value === 'string' ? new Date(value) : value
  if (Number.isNaN(date.getTime())) return '—'

  const seconds = Math.round((Date.now() - date.getTime()) / 1000)
  if (seconds < 45) return 'just now'

  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 7],
    ['week', 4.35],
    ['month', 12],
    ['year', Number.POSITIVE_INFINITY],
  ]

  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  let amount = seconds
  for (const [unit, step] of units) {
    if (Math.abs(amount) < step) {
      return formatter.format(-Math.round(amount), unit)
    }
    amount /= step
  }
  return formatter.format(-Math.round(amount), 'year')
}

/**
 * Renders a remaining-days count.
 *
 * Prefer the API's `days_remaining` over recomputing from `not_after`: the
 * server is what decided the alert threshold, and a dashboard that disagrees
 * with the alert is worse than one that simply mirrors it.
 */
export function formatDays(days: number | null | undefined): string {
  if (days === null || days === undefined || Number.isNaN(days)) return '—'
  if (days < 0) return 'expired'
  if (days === 0) return 'today'
  if (days === 1) return '1 day'
  return `${days} days`
}

/** Compact form for dense tables: "89d". */
export function formatDaysShort(days: number | null | undefined): string {
  if (days === null || days === undefined || Number.isNaN(days)) return '—'
  if (days < 0) return 'exp'
  return `${days}d`
}

/** Truncates a long distinguished name for display, keeping the front. */
export function truncate(value: string | null | undefined, max = 48): string {
  if (!value) return '—'
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`
}

/**
 * What to call a certificate: its common name, or its first SAN when it has
 * none. Conforming CAs are dropping the subject common name — Pebble already
 * issues without one by default — so an empty one is a real certificate with a
 * real name, not a blank row (#108).
 */
export function certName(cert: { common_name?: string | null; sans?: string[] | null }): string {
  return cert.common_name || cert.sans?.[0] || '(no name)'
}

/** Extracts the CN from a distinguished name, falling back to the whole string. */
export function commonNameFromDN(dn: string | null | undefined): string {
  if (!dn) return '—'
  const match = dn.match(/CN=([^,]+)/i)
  return match ? match[1].trim() : dn
}
