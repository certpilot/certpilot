<script setup lang="ts">
import { computed, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import { useCasStore } from '@/stores/cas'
import { useEventStream } from '@/composables/useEventStream'
import DataState from '@/components/common/DataState.vue'
import PanelBox from '@/components/ui/PanelBox.vue'
import Readout from '@/components/ui/Readout.vue'
import SevChip from '@/components/ui/SevChip.vue'
import ExpiryHorizon, { type HorizonItem } from '@/components/horizon/ExpiryHorizon.vue'
import { caSeverity, certUrgency, sevBg, sevClass, compareSeverity } from '@/lib/severity'
import { certName, commonNameFromDN, formatDaysShort, formatRelative, truncate } from '@/lib/format'
import { describeAudit } from '@/lib/events'
import type { AuditLog, Certificate, ListResponse } from '@/lib/types'

/**
 * The horizon.
 *
 * The old dashboard was six equal-sized tiles and two doughnut charts. It could
 * tell you that four things were critical; it could not tell you *which*, or
 * how soon, without navigating away — and a chart of "certificates by key
 * algorithm" answers a question nobody on a PKI team has ever been paged about.
 *
 * What this page answers, in order: is anything about to expire, what is it,
 * and is the picture I am looking at current.
 */

const api = useApi()
const router = useRouter()
const cas = useCasStore()
const stream = useEventStream()

const certs = useAsyncData<ListResponse<Certificate>>((s) =>
  api.get<ListResponse<Certificate>>('/api/v1/certificates', s),
)
const activity = useAsyncData<ListResponse<AuditLog>>((s) =>
  api.get<ListResponse<AuditLog>>('/api/v1/dashboard/activity', s),
)

const certificates = computed(() => certs.data.value?.data ?? [])

// The activity feed records a certificate's common name as it was, which for a
// SAN-only certificate is empty. Named here from the inventory already loaded
// rather than by rewriting what the audit log says (#108).
const certNames = computed(() => new Map(certificates.value.map((c) => [c.id, certName(c)])))
function auditName(entry: AuditLog): string | undefined {
  return entry.entity_type === 'certificate' ? certNames.value.get(entry.entity_id) : undefined
}

function refreshAll() {
  void cas.refresh()
  void certs.refresh()
  void activity.refresh()
}

// Certificate events change this page's own panels, not just the store's, so
// reconcile them here rather than polling. refresh() aborts any request it
// supersedes, so a burst of issuance collapses into one round trip.
const stopListening = stream.onEvent((event) => {
  if (event.topic.startsWith('cert.')) {
    void certs.refresh()
    void activity.refresh()
  }
})
// Unregistered on unmount: the stream outlives this view, and a handler left
// behind would keep refetching for a page no longer on screen.
onUnmounted(stopListening)

// ── The horizon ─────────────────────────────────────────

const horizonItems = computed<HorizonItem[]>(() => [
  ...cas.authorities.map((ca) => ({
    id: `ca:${ca.id}`,
    label: ca.name,
    days: ca.days_remaining,
    severity: caSeverity(ca.status),
    lane: 'authorities' as const,
    meta: `${ca.ca_type} · ${ca.certificates_issued_count.toLocaleString()} issued`,
  })),
  ...certificates.value.map((cert) => ({
    id: `cert:${cert.id}`,
    label: certName(cert),
    days: cert.days_remaining,
    severity: certUrgency(cert),
    lane: 'certificates' as const,
    meta: cert.environment ? cert.environment.toUpperCase() : undefined,
  })),
])

function openMark(id: string) {
  router.push(id.startsWith('ca:') ? '/ca-health' : '/certificates')
}

// ── Readouts ────────────────────────────────────────────

const stats = computed(() => cas.summary)

/**
 * Everything that needs a person, authorities and certificates together,
 * worst first.
 *
 * Deliberately one list rather than two panels. The question is "what do I do
 * next", and splitting it by object type makes the reader merge two orderings
 * in their head to answer it.
 */
const attention = computed(() => {
  const rows = [
    ...cas.authorities.map((ca) => ({
      key: `ca:${ca.id}`,
      kind: 'CA' as const,
      name: ca.name,
      detail: ca.ca_type,
      days: ca.days_remaining,
      severity: caSeverity(ca.status),
      to: '/ca-health',
    })),
    ...certificates.value.map((cert) => ({
      key: `cert:${cert.id}`,
      kind: 'CERT' as const,
      name: certName(cert),
      detail: commonNameFromDN(cert.issuer_dn),
      days: cert.days_remaining,
      severity: certUrgency(cert),
      to: '/certificates',
    })),
  ].filter((row) => row.severity === 'critical' || row.severity === 'warning')

  return rows.sort((a, b) => {
    const bySeverity = compareSeverity(a.severity, b.severity)
    return bySeverity !== 0 ? bySeverity : a.days - b.days
  })
})

const events = computed(() => activity.data.value?.data ?? [])

const anyError = computed(() => cas.error ?? certs.error.value ?? activity.error.value)
const anyLoading = computed(() => cas.loading || certs.loading.value || activity.loading.value)
const anyLoaded = computed(() => cas.loaded && certs.loaded.value)
</script>

<template>
  <DataState
    :loading="anyLoading"
    :error="anyError"
    :loaded="anyLoaded"
    @retry="refreshAll"
  >
    <!-- The hero. Everything being monitored, on one time axis. -->
    <ExpiryHorizon :items="horizonItems" @select="openMark" />

    <!-- Totals. Only the counts that describe a problem carry colour; the rest
         are neutral, so a screen with nothing wrong has no colour on it at all
         and one with a critical CA has exactly one thing glowing. -->
    <div class="readout-strip">
      <Readout
        :value="stats.critical_cas + stats.expired_cas"
        label="Authorities critical"
        :severity="stats.critical_cas + stats.expired_cas > 0 ? 'critical' : undefined"
      />
      <Readout
        :value="stats.warning_cas"
        label="Authorities warning"
        :severity="stats.warning_cas > 0 ? 'warning' : undefined"
      />
      <Readout :value="stats.total_cas" label="Authorities total" />
      <Readout
        :value="stats.expired_certs"
        label="Certificates expired"
        :severity="stats.expired_certs > 0 ? 'critical' : undefined"
      />
      <Readout
        :value="stats.expiring_soon_certs"
        label="Certificates expiring"
        :severity="stats.expiring_soon_certs > 0 ? 'warning' : undefined"
      />
      <Readout :value="stats.total_certificates" label="Certificates total" />
    </div>

    <div class="grid gap-3 lg:grid-cols-[1.6fr_1fr] min-w-0">
      <PanelBox
        label="Needs attention"
        :note="attention.length ? `${attention.length} items` : 'all clear'"
        :note-severity="attention.length ? 'critical' : 'ok'"
        flush
      >
        <div class="max-h-[22rem] overflow-y-auto">
          <table v-if="attention.length" class="tbl">
            <thead>
              <tr>
                <th class="rail"></th>
                <th>Object</th>
                <th>Kind</th>
                <th>Detail</th>
                <th class="num">Left</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in attention"
                :key="row.key"
                class="cursor-pointer"
                @click="router.push(row.to)"
              >
                <td class="rail" :class="sevBg(row.severity)"></td>
                <td class="cell-primary max-w-[18rem] truncate">{{ row.name }}</td>
                <td class="label-micro">{{ row.kind }}</td>
                <td class="max-w-[14rem] truncate">{{ truncate(row.detail, 32) }}</td>
                <td class="num" :class="sevClass(row.severity)">
                  {{ formatDaysShort(row.days) }}
                </td>
                <td><SevChip :severity="row.severity" /></td>
              </tr>
            </tbody>
          </table>

          <!-- An empty state that makes a claim has to be able to back it. This
               one says what was checked and when, because "all clear" from a
               tool that has stopped polling is the lie this product exists to
               prevent. -->
          <p v-else class="empty-note prose-ui">
            No authority or certificate is inside a warning threshold.
            <span class="block label-micro mt-1">
              {{ cas.authorities.length }} authorities and
              {{ certificates.length }} certificates checked
            </span>
          </p>
        </div>
      </PanelBox>

      <PanelBox label="Activity" flush>
        <div class="max-h-[22rem] overflow-y-auto">
          <ul v-if="events.length" class="feed">
            <li v-for="entry in events" :key="entry.id" class="feed-row">
              <span class="feed-time">{{ formatRelative(entry.created_at) }}</span>
              <span class="feed-text">{{ describeAudit(entry, auditName) }}</span>
            </li>
          </ul>
          <p v-else class="empty-note prose-ui">Nothing has been recorded yet.</p>
        </div>
      </PanelBox>
    </div>
  </DataState>
</template>

<style scoped>
/* One rule between readouts rather than six bordered boxes. The figures are a
   related set being compared, and boxing each of them says the opposite. */
.readout-strip {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
  gap: 1px;
  background: var(--line);
  border: 1px solid var(--line);
}

.readout-strip > * {
  background: var(--ink-panel);
  padding: 0.625rem 0.75rem;
}

.empty-note {
  padding: 1.5rem 0.75rem;
  font-size: var(--fs-small);
  color: var(--text-muted);
  text-align: center;
}

.feed {
  display: flex;
  flex-direction: column;
}

.feed-row {
  display: flex;
  align-items: baseline;
  gap: 0.625rem;
  padding: 0.3125rem 0.625rem;
  border-bottom: 1px solid var(--line);
  font-size: var(--fs-small);
}

.feed-time {
  flex: none;
  width: 6.5rem;
  font-size: var(--fs-micro);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-muted);
}

.feed-text {
  color: var(--text-secondary);
  min-width: 0;
  word-break: break-word;
}
</style>
