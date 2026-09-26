<script setup lang="ts">
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import PanelBox from '@/components/ui/PanelBox.vue'
import SevChip from '@/components/ui/SevChip.vue'
import {
  Plus, Search, RotateCw, CircleX, ShieldCheck, Download, KeyRound, FileSignature, Ban,
} from 'lucide-vue-next'
import {
  certStateLabel, certUrgency, compareSeverity, sevBg, sevClass,
} from '@/lib/severity'
import { certName, formatDate, formatDaysShort, truncate } from '@/lib/format'
import { downloadText, fullChain, pemFilename } from '@/lib/download'
import { useAuthStore } from '@/stores/auth'
import MetadataInput from '@/components/metadata/MetadataInput.vue'
import { formatMetadataValue } from '@/lib/types'
import type { CaAccount, Certificate, ListResponse, MetadataField } from '@/lib/types'

const api = useApi()
const auth = useAuthStore()

const certs = useAsyncData<ListResponse<Certificate>>((s) =>
  api.get<ListResponse<Certificate>>('/api/v1/certificates', s),
)
// Needed for the request form: ca_account_id is required by the API.
const accounts = useAsyncData<ListResponse<CaAccount>>((s) =>
  api.get<ListResponse<CaAccount>>('/api/v1/ca-accounts', s),
)
// Archived fields included: a certificate may hold a value for one, and without
// the definition the panel could only print the raw stored value with no label.
const metaFields = useAsyncData<ListResponse<MetadataField>>((s) =>
  api.get<ListResponse<MetadataField>>('/api/v1/metadata-fields?include_archived=true', s),
)

const certificates = computed(() => certs.data.value?.data ?? [])
const caAccounts = computed(() => accounts.data.value?.data ?? [])
const allFields = computed(() => metaFields.data.value?.data ?? [])
/** Offered on new certificates and in the editor. */
const liveFields = computed(() => allFields.value.filter((f) => !f.is_archived))

const searchQuery = ref('')
const filterStatus = ref<'all' | 'ok' | 'warning' | 'critical'>('all')

/**
 * Metadata filters, one selected value per field.
 *
 * The reason for letting people define fields at all: an inventory you cannot
 * slice is a list. Applied client-side over the already-fetched list, like the
 * search box beside it.
 */
const metaFilter = ref<Record<string, string>>({})

const activeMetaFilters = computed(() =>
  Object.entries(metaFilter.value).filter(([, v]) => v !== ''),
)

function clearMetaFilters() {
  metaFilter.value = {}
}

/** Distinct answers actually present, so a filter never offers an empty result. */
function answersInUse(field: MetadataField): { value: string; label: string }[] {
  const seen = new Set<string>()
  for (const cert of certificates.value) {
    const raw = cert.metadata?.[field.key]
    if (raw === undefined || raw === null || raw === '') continue
    for (const v of Array.isArray(raw) ? raw : [raw]) seen.add(String(v))
  }
  return [...seen]
    .map((value) => ({
      value,
      label: field.options.find((o) => o.value === value)?.label
        ?? (field.field_type === 'BOOLEAN' ? (value === 'true' ? 'Yes' : 'No') : value),
    }))
    .sort((a, b) => a.label.localeCompare(b.label))
}

function matchesMetadata(cert: Certificate): boolean {
  return activeMetaFilters.value.every(([key, wanted]) => {
    const raw = cert.metadata?.[key]
    if (raw === undefined || raw === null) return false
    if (Array.isArray(raw)) return raw.map(String).includes(wanted)
    return String(raw) === wanted
  })
}

// Filters group by severity rather than by exact status: an operator scanning
// for trouble wants "everything critical", not to remember that REVOKED and
// RENEWAL_FAILED both belong in that bucket.
const filtered = computed(() => {
  const q = searchQuery.value.trim().toLowerCase()
  return certificates.value
    .filter((c) => {
      const matchesSearch =
        !q ||
        c.common_name.toLowerCase().includes(q) ||
        c.sans?.some((san) => san.toLowerCase().includes(q)) ||
        (c.serial_number ?? '').toLowerCase().includes(q)
      const matchesStatus =
        filterStatus.value === 'all' || certUrgency(c) === filterStatus.value
      return matchesSearch && matchesStatus && matchesMetadata(c)
    })
    .sort((a, b) => {
      const bySeverity = compareSeverity(certUrgency(a), certUrgency(b))
      return bySeverity !== 0 ? bySeverity : a.days_remaining - b.days_remaining
    })
})

const counts = computed(() => {
  const all = certificates.value
  return {
    all: all.length,
    ok: all.filter((c) => certUrgency(c) === 'ok').length,
    warning: all.filter((c) => certUrgency(c) === 'warning').length,
    critical: all.filter((c) => certUrgency(c) === 'critical').length,
  }
})

// ── Request ───────────────────────────────────────────────
const showRequest = ref(false)
const requesting = ref(false)
const requestError = ref<string | null>(null)

const blankRequest = () => ({
  common_name: '',
  sans: '',
  ca_account_id: '',
  key_type: 'ECDSA',
  key_size: '256',
  validity_days: '90',
  environment: '',
  team: '',
  auto_renew: true,
})
/** Values being entered on the request form, keyed by field key. */
const reqMeta = ref<Record<string, unknown>>({})
const reqForm = ref(blankRequest())

// RSA and ECDSA have entirely different meaningful key sizes; offering 2048 for
// an EC key produces a request the gateway will reject.
const keySizeOptions = computed(() =>
  reqForm.value.key_type === 'RSA' ? ['2048', '3072', '4096'] : ['256', '384', '521'],
)

function onKeyTypeChange() {
  reqForm.value.key_size = reqForm.value.key_type === 'RSA' ? '2048' : '256'
}

async function requestCert() {
  requesting.value = true
  requestError.value = null
  try {
    await api.post('/api/v1/certificates', {
      common_name: reqForm.value.common_name,
      sans: reqForm.value.sans.split(',').map((d) => d.trim()).filter(Boolean),
      ca_account_id: reqForm.value.ca_account_id,
      key_type: reqForm.value.key_type,
      key_size: Number(reqForm.value.key_size),
      validity_days: Number(reqForm.value.validity_days),
      environment: reqForm.value.environment || undefined,
      team: reqForm.value.team || undefined,
      auto_renew: reqForm.value.auto_renew,
      metadata: reqMeta.value,
    })
    showRequest.value = false
    reqForm.value = blankRequest()
    reqMeta.value = {}
    await certs.refresh()
  } catch (err) {
    requestError.value = err instanceof Error ? err.message : String(err)
  } finally {
    requesting.value = false
  }
}

// ── Renew ─────────────────────────────────────────────────
const renewingId = ref<string | null>(null)
const actionError = ref<string | null>(null)

async function renewCert(cert: Certificate) {
  renewingId.value = cert.id
  actionError.value = null
  try {
    await api.post(`/api/v1/certificates/${cert.id}/renew`)
    await certs.refresh()
  } catch (err) {
    actionError.value = `Renewing ${certName(cert)} failed: ${
      err instanceof Error ? err.message : String(err)
    }`
  } finally {
    renewingId.value = null
  }
}

const selected = ref<Certificate | null>(null)

// ── Exporting ─────────────────────────────────────────────

const exportError = ref<string | null>(null)
const exportingKey = ref(false)

/**
 * Whether an export can succeed.
 *
 * Read from key_custody rather than from provenance. A CSR-signed certificate
 * is `REQUESTED` like every other one and CertPilot holds no key for it, so a
 * button keyed off `discovered_via` would offer a download that can only 404 —
 * and on this of all operations, an offer that fails is worse than no offer.
 */
function holdsKey(cert: Certificate): boolean {
  return cert.key_custody === 'CERTPILOT'
}

/** Why the key cannot be exported, in the terms the reader needs. */
function keyCustodyNote(cert: Certificate): string {
  switch (cert.key_custody) {
    case 'AGENT':
      return 'The key was generated on the host that uses it and has never left. CertPilot cannot produce it.'
    case 'CERTPILOT':
      return 'Sealed in the database. Exporting is admin-only and writes an audit record.'
    default:
      return 'Issued from a signing request or imported — the key never reached CertPilot.'
  }
}

async function exportPrivateKey(cert: Certificate) {
  exportingKey.value = true
  exportError.value = null
  try {
    const res = await api.get<{ common_name: string; private_key_pem: string }>(
      `/api/v1/certificates/${cert.id}/private-key`,
    )
    // Fetched on demand and never held in component state: a key parked in a
    // reactive ref survives in the heap and in the devtools inspector for as
    // long as the page is open.
    downloadText(pemFilename(certName(cert), 'key'), res.private_key_pem)
  } catch (err) {
    exportError.value = err instanceof Error ? err.message : String(err)
  } finally {
    exportingKey.value = false
  }
}

// ── Revoking ────────────────────────────────

/**
 * The reasons the core accepts, in the order it lists them.
 *
 * Deliberately not every RFC 5280 code: the core takes the subset a CA will
 * act on and refuses the rest with a 400, so offering `certificateHold` here
 * would be offering a choice that can only fail. The descriptions are what
 * distinguishes them for somebody deciding at 2am, which is the only time
 * most people read this list.
 */
const REVOCATION_REASONS: { code: number; name: string; what: string }[] = [
  { code: 1, name: 'keyCompromise', what: 'The private key is, or may be, in somebody else\u2019s hands.' },
  { code: 4, name: 'superseded', what: 'Replaced by another certificate. The ordinary reason for a planned rotation.' },
  { code: 5, name: 'cessationOfOperation', what: 'The service it was issued for is being retired.' },
  { code: 3, name: 'affiliationChanged', what: 'The subject\u2019s name or organisation changed.' },
  { code: 9, name: 'privilegeWithdrawn', what: 'The holder is no longer entitled to it.' },
  { code: 0, name: 'unspecified', what: 'No reason recorded. Every other option tells the next reader more.' },
]

const revoking = ref(false)
const revokeError = ref<string | null>(null)
const revokeTarget = ref<Certificate | null>(null)
const revokeReason = ref<number | null>(null)

/**
 * What auto-renew actually means for this certificate.
 *
 * The renewal sweep and the ARI poller both select on
 * `status IN ('ISSUED', 'EXPIRING', 'RENEWAL_FAILED')`, so a revoked or expired
 * certificate is never picked up however its flag reads. Rendering the stored
 * flag alone put "Yes, 30 days ahead" on a revoked certificate — a promise
 * nothing in the system will keep, on the one record where somebody is most
 * likely to be checking whether it is still going to do something.
 */
function autoRenewNote(cert: Certificate): string {
  if (!cert.auto_renew) return 'No'
  if (cert.status === 'REVOKED') return 'Set, but revoked certificates are never renewed'
  if (cert.status === 'EXPIRED') return 'Set, but expired certificates are never renewed'
  return `Yes, ${cert.renewal_lead_days} days ahead`
}

/** The stored reason as a name, for a certificate that is already revoked. */
function revocationReasonName(code: number | null | undefined): string {
  if (code === null || code === undefined) return 'not recorded'
  return REVOCATION_REASONS.find((r) => r.code === code)?.name ?? `reason ${code}`
}

/**
 * Whether revoking this one can succeed.
 *
 * The core refuses a certificate it holds no copy of, and one with no CA
 * account, because neither can be sent to a CA — usually a discovered
 * certificate. Offering the button anyway would produce a 400 on the one
 * operation where a failed attempt reads as "something is wrong with the
 * estate" rather than "wrong button".
 */
function canRevoke(cert: Certificate): boolean {
  return cert.status !== 'REVOKED' && !!cert.ca_account_id
}

/** Why it cannot be revoked here, in the terms the reader needs. */
function revokeRefusal(cert: Certificate): string {
  if (cert.status === 'REVOKED') return 'Already revoked.'
  return (
    'Not bound to a CA account, so there is nowhere to send a revocation — ' +
    'this was discovered rather than issued here. Revoke it at the issuing CA.'
  )
}

function openRevoke(cert: Certificate) {
  revokeTarget.value = cert
  // Deliberately unset. The core requires a reason rather than defaulting it,
  // and pre-selecting one here would put that choice back to a default by the
  // back door — "unspecified" would become the commonest reason in the estate.
  revokeReason.value = null
  revokeError.value = null
}

function closeRevoke() {
  if (revoking.value) return
  revokeTarget.value = null
  revokeError.value = null
}

async function confirmRevoke() {
  const cert = revokeTarget.value
  if (!cert || revokeReason.value === null) return

  revoking.value = true
  revokeError.value = null
  try {
    await api.post(`/api/v1/certificates/${cert.id}/revoke`, { reason: revokeReason.value })
    await certs.refresh()
    // Reopened from the refreshed list rather than patched in place: the CA
    // decides what actually happened, and the record the core wrote back is
    // the only honest thing to show.
    if (selected.value?.id === cert.id) {
      selected.value = certificates.value.find((c) => c.id === cert.id) ?? null
    }
    revokeTarget.value = null
  } catch (err) {
    // Left open, with the error and the chosen reason intact. Every failure on
    // this path leaves the certificate exactly as it was, so the operator is
    // one corrected click from trying again rather than starting over.
    revokeError.value = err instanceof Error ? err.message : String(err)
  } finally {
    revoking.value = false
  }
}

/**
 * The list view omits the PEM, so a download needs the full record.
 *
 * Fetching it here rather than widening the list query keeps the certificate
 * bodies out of a response that returns every certificate in the estate.
 */
async function withPEM(cert: Certificate): Promise<Certificate> {
  if (cert.certificate_pem) return cert
  return api.get<Certificate>(`/api/v1/certificates/${cert.id}`)
}

async function exportPEM(cert: Certificate, what: 'cert' | 'chain' | 'fullchain') {
  exportError.value = null
  try {
    const full = await withPEM(cert)
    if (!full.certificate_pem) throw new Error('no certificate body is stored for this record')
    switch (what) {
      case 'cert':
        downloadText(pemFilename(certName(full), 'crt'), full.certificate_pem)
        break
      case 'chain':
        if (!full.chain_pem) throw new Error('no issuer chain is stored for this certificate')
        downloadText(pemFilename(certName(full), 'chain.crt'), full.chain_pem)
        break
      case 'fullchain':
        downloadText(
          pemFilename(certName(full), 'fullchain.crt'),
          fullChain(full.certificate_pem, full.chain_pem),
        )
        break
    }
  } catch (err) {
    exportError.value = err instanceof Error ? err.message : String(err)
  }
}

// ── Editing what an operator owns ─────────────────────────

/**
 * A certificate record has two halves, and only one of them is anybody's to
 * change. Serial, fingerprint, expiry and renewal state are facts the CA
 * established; environment, team, tags and the custom fields are decisions
 * somebody made and may need to correct. Until now there was no way to correct
 * any of them — a certificate outlives the team that requested it, and a record
 * that cannot be fixed becomes a record nobody trusts.
 */
const editingMeta = ref(false)
const savingMeta = ref(false)
const metaError = ref<string | null>(null)
const metaDraft = ref<{
  environment: string
  team: string
  tags: string
  metadata: Record<string, unknown>
}>({ environment: '', team: '', tags: '', metadata: {} })

function startEditMeta(cert: Certificate) {
  metaError.value = null
  editingMeta.value = true
  metaDraft.value = {
    environment: cert.environment ?? '',
    team: cert.team ?? '',
    tags: (cert.tags ?? []).join(', '),
    metadata: { ...(cert.metadata ?? {}) },
  }
}

async function saveMeta(cert: Certificate) {
  savingMeta.value = true
  metaError.value = null
  try {
    // Only what this form owns is sent. The endpoint leaves an omitted field
    // alone, so a stale tab cannot blank something it never displayed.
    const updated = await api.patch<Certificate>(`/api/v1/certificates/${cert.id}`, {
      environment: metaDraft.value.environment,
      team: metaDraft.value.team,
      tags: metaDraft.value.tags.split(',').map((t) => t.trim()).filter(Boolean),
      metadata: metaDraft.value.metadata,
    })
    selected.value = updated
    editingMeta.value = false
    await certs.refresh()
  } catch (err) {
    metaError.value = err instanceof Error ? err.message : String(err)
  } finally {
    savingMeta.value = false
  }
}

/** Fields with a value on this certificate, archived ones included. */
function answeredFields(cert: Certificate): MetadataField[] {
  return allFields.value.filter((f) => {
    const v = cert.metadata?.[f.key]
    return v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length)
  })
}

// ── Signing an existing request ───────────────────────────

/**
 * Two ways to get a certificate, and they are genuinely different operations.
 *
 * "Generate" has CertPilot produce the key and keep it. "Sign" takes a request
 * whose key was made somewhere else — an HSM, a load balancer, a team whose
 * policy forbids a key leaving their host — and never sees the secret at all.
 * Presenting the second as an option on the first would hide that the choice
 * decides who holds the key for the certificate's whole life.
 */
type RequestMode = 'generate' | 'sign'
const requestMode = ref<RequestMode>('generate')
const csrText = ref('')

function setMode(mode: RequestMode) {
  requestMode.value = mode
  requestError.value = null
}

async function readCSRFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  csrText.value = await file.text()
  input.value = ''
}

/** Names and key come from the request itself, so those fields are not asked for. */
async function signCSR() {
  requesting.value = true
  requestError.value = null
  try {
    await api.post('/api/v1/certificates', {
      csr_pem: csrText.value,
      ca_account_id: reqForm.value.ca_account_id,
      validity_days: Number(reqForm.value.validity_days),
      environment: reqForm.value.environment || undefined,
      team: reqForm.value.team || undefined,
      metadata: reqMeta.value,
      // Renewal needs a key to produce a new certificate with, and there is no
      // key here. Offering it would schedule a renewal that can only fail.
      auto_renew: false,
    })
    showRequest.value = false
    csrText.value = ''
    reqForm.value = blankRequest()
    reqMeta.value = {}
    await certs.refresh()
  } catch (err) {
    requestError.value = err instanceof Error ? err.message : String(err)
  } finally {
    requesting.value = false
  }
}
</script>


<template>
  <div class="flex flex-col gap-3 min-w-0">
    <div class="page-head">
      <div class="min-w-0">
        <h1 class="label-rail">Certificate inventory</h1>
        <p class="page-sub prose-ui">Managed certificates, most urgent first.</p>
      </div>
      <div class="flex items-center gap-2 shrink-0">
        <button
          class="btn-console"
          :disabled="certs.loading.value"
          @click="certs.refresh()"
        >
          <RotateCw class="w-3 h-3" :class="certs.loading.value && 'animate-spin'" />
          Refresh
        </button>
        <button class="btn-console" data-variant="signal" @click="showRequest = true">
          <Plus class="w-3 h-3" /> Request
        </button>
      </div>
    </div>

    <div v-if="actionError" role="alert" class="action-error">
      <CircleX class="w-3.5 h-3.5 shrink-0 sev-critical" />
      <span>{{ actionError }}</span>
    </div>

    <DataState
      :loading="certs.loading.value"
      :error="certs.error.value"
      :loaded="certs.loaded.value"
      @retry="certs.refresh()"
    >
      <!-- Counts and filter are the same control. Four separate stat tiles that
           also happen to filter is two mental models for one object. -->
      <div class="filter-bar">
        <button
          v-for="tile in [
            { key: 'all', label: 'All', value: counts.all, tone: '' },
            { key: 'critical', label: 'Needs attention', value: counts.critical, tone: 'sev-critical' },
            { key: 'warning', label: 'Expiring', value: counts.warning, tone: 'sev-warning' },
            { key: 'ok', label: 'Healthy', value: counts.ok, tone: 'sev-ok' },
          ]"
          :key="tile.key"
          type="button"
          class="filter-chip"
          :data-active="filterStatus === tile.key || undefined"
          @click="filterStatus = tile.key as typeof filterStatus"
        >
          {{ tile.label }}
          <span
            class="filter-count"
            :class="filterStatus === tile.key || tile.value === 0 ? '' : tile.tone"
          >{{ tile.value }}</span>
        </button>

        <label class="filter-search">
          <Search class="w-3 h-3 shrink-0" style="color: var(--text-muted)" />
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Common name, SAN, or serial"
          />
        </label>
      </div>

      <!-- Slicing by what this organisation defined. Only fields that some
           certificate actually answers are offered, so a filter never presents
           a choice that can only return nothing. -->
      <div v-if="liveFields.length" class="meta-filter">
        <template v-for="field in liveFields" :key="field.id">
          <label v-if="answersInUse(field).length" class="meta-filter-item">
            <span class="label-micro">{{ field.label }}</span>
            <select
              class="input-console"
              :value="metaFilter[field.key] ?? ''"
              @change="metaFilter[field.key] = ($event.target as HTMLSelectElement).value"
            >
              <option value="">Any</option>
              <option v-for="a in answersInUse(field)" :key="a.value" :value="a.value">
                {{ a.label }}
              </option>
            </select>
          </label>
        </template>
        <button
          v-if="activeMetaFilters.length"
          class="btn-console self-end"
          @click="clearMetaFilters"
        >
          Clear
        </button>
      </div>

      <!-- Table beside detail rather than a modal over it. A modal makes you
           forget the list to read one row; the split keeps the ordering — the
           thing this page is for — on screen while you inspect. -->
      <div class="split" :data-open="selected ? true : undefined">
        <PanelBox
          label="Certificates"
          :note="`${filtered.length} shown`"
          flush
        >
          <div class="table-scroll">
            <table class="tbl">
              <thead>
                <tr>
                  <th class="rail"></th>
                  <th>Common name</th>
                  <th>Issuer</th>
                  <th>Key</th>
                  <th>Expires</th>
                  <th class="num">Left</th>
                  <th>Status</th>
                  <th class="num">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="cert in filtered"
                  :key="cert.id"
                  :data-selected="selected?.id === cert.id || undefined"
                  class="cursor-pointer"
                  @click="selected = cert"
                >
                  <td class="rail" :class="sevBg(certUrgency(cert))"></td>
                  <td class="cell-primary max-w-[16rem] truncate">
                    {{ certName(cert) }}
                    <span v-if="cert.sans?.length > 1" style="color: var(--text-muted)">
                      +{{ cert.sans.length - 1 }}
                    </span>
                  </td>
                  <td class="max-w-[14rem] truncate">{{ truncate(cert.issuer_dn, 30) }}</td>
                  <td>
                    {{ cert.key_type
                    }}<template v-if="cert.key_size">-{{ cert.key_size }}</template>
                  </td>
                  <td>{{ formatDate(cert.not_after) }}</td>
                  <td class="num" :class="sevClass(certUrgency(cert))">
                    {{ formatDaysShort(cert.days_remaining) }}
                  </td>
                  <td>
                    <SevChip
                      :severity="certUrgency(cert)"
                      :label="certStateLabel(cert)"
                    />
                  </td>
                  <td class="num">
                    <button
                      class="row-action"
                      title="Renew now"
                      :disabled="renewingId === cert.id"
                      @click.stop="renewCert(cert)"
                    >
                      <RotateCw
                        class="w-3.5 h-3.5"
                        :class="renewingId === cert.id && 'animate-spin'"
                      />
                    </button>
                  </td>
                </tr>
                <tr v-if="!filtered.length">
                  <td colspan="8">
                    <div class="empty-state">
                      <ShieldCheck class="w-6 h-6" style="color: var(--text-muted)" />
                      <p class="prose-ui">
                        {{
                          certificates.length
                            ? 'No certificates match this filter.'
                            : 'No certificates yet. Request one to get started.'
                        }}
                      </p>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </PanelBox>

        <!-- Detail -->
        <PanelBox v-if="selected" label="Detail">
          <template #actions>
            <button class="btn-console" @click="selected = null">Close</button>
          </template>

          <div class="flex flex-col gap-3 min-w-0">
            <div class="flex items-center gap-2 flex-wrap min-w-0">
              <span class="detail-title">{{ certName(selected) }}</span>
              <SevChip
                :severity="certUrgency(selected)"
                :label="certStateLabel(selected)"
              />
            </div>

            <!-- Export. The reason most people open this panel, so it is above
                 the metadata rather than buried under it. -->
            <div class="export">
              <div class="export-row">
                <button class="btn-console" @click="exportPEM(selected, 'fullchain')">
                  <Download class="w-3 h-3" /> Full chain
                </button>
                <button class="btn-console" @click="exportPEM(selected, 'cert')">
                  <Download class="w-3 h-3" /> Certificate
                </button>
                <button
                  class="btn-console"
                  :disabled="!selected.chain_pem && !!selected.certificate_pem"
                  @click="exportPEM(selected, 'chain')"
                >
                  <Download class="w-3 h-3" /> Chain
                </button>
              </div>
              <!-- Named because it is the one people get wrong by hand: nginx
                   and HAProxy want leaf first, issuers after, in one file. -->
              <p class="field-help">
                Full chain is leaf then issuers — what nginx and HAProxy expect.
              </p>

              <div class="export-key">
                <button
                  v-if="holdsKey(selected) && auth.isAdmin"
                  class="btn-console"
                  :disabled="exportingKey"
                  @click="exportPrivateKey(selected)"
                >
                  <KeyRound class="w-3 h-3" />
                  {{ exportingKey ? 'Exporting…' : 'Private key' }}
                </button>
                <!-- Both refusals are stated, and they are different facts. One
                     is "you may not"; the other is "nobody can". Rendering them
                     as the same greyed-out button would let an operator spend an
                     afternoon chasing a permission that would not have helped. -->
                <span v-else-if="holdsKey(selected)" class="export-refusal">
                  Private key export is admin-only
                </span>
                <span v-else class="export-refusal">No private key to export</span>
                <span class="field-help">{{ keyCustodyNote(selected) }}</span>
              </div>

              <p v-if="exportError" role="alert" class="export-error">{{ exportError }}</p>
            </div>

            <!-- Revocation. Below export because far more people come here to
                 download something than to revoke, and above the immutable
                 facts because it is the one thing on this panel that changes
                 the world rather than describing it. -->
            <div class="revoke-block">
              <div class="meta-head">
                <span class="label-rail">Revocation</span>
              </div>

              <!-- Already revoked: the most important thing that ever happened
                   to this certificate, so the panel states it rather than
                   leaving the reader to infer it from a chip in the header. -->
              <template v-if="selected.status === 'REVOKED'">
                <dl class="kv">
                  <dt>Revoked</dt>
                  <dd>{{ selected.revoked_at ? formatDate(selected.revoked_at) : 'date not recorded' }}</dd>
                  <dt>Reason</dt>
                  <dd>{{ revocationReasonName(selected.revocation_reason) }}</dd>
                </dl>
                <p class="field-help">
                  The CA confirmed this before CertPilot recorded it. The audit
                  log names the account that asked.
                </p>
              </template>

              <template v-else>
                <button
                  v-if="canRevoke(selected) && auth.isAdmin"
                  class="btn-console btn-danger"
                  @click="openRevoke(selected)"
                >
                  <Ban class="w-3 h-3" /> Revoke
                </button>
                <!-- Three different facts, stated as three different things.
                     "You may not", "nobody can from here", and "already done"
                     send an operator to three different places; one greyed-out
                     button would send them all to the same wrong one. -->
                <span v-else-if="canRevoke(selected)" class="export-refusal">
                  Revoking is admin-only
                </span>
                <span v-else class="export-refusal">{{ revokeRefusal(selected) }}</span>
                <p class="field-help">
                  Tells the CA first and records the result only if the CA agreed.
                  Deleting the record instead would leave the certificate live.
                </p>
              </template>
            </div>

            <!-- Metadata, above the immutable facts. It is the part somebody
                 came here to change; the serial is not. -->
            <div class="meta-block">
              <div class="meta-head">
                <span class="label-rail">Metadata</span>
                <button
                  v-if="!editingMeta && auth.canWrite"
                  class="btn-console"
                  @click="startEditMeta(selected)"
                >
                  Edit
                </button>
              </div>

              <p v-if="metaError" role="alert" class="export-error">{{ metaError }}</p>

              <template v-if="editingMeta">
                <div class="grid gap-2 sm:grid-cols-2">
                  <div class="field">
                    <label class="label-micro" for="ed-env">Environment</label>
                    <select id="ed-env" v-model="metaDraft.environment" class="input-console">
                      <option value="">— not set —</option>
                      <option value="production">production</option>
                      <option value="staging">staging</option>
                      <option value="development">development</option>
                    </select>
                  </div>
                  <div class="field">
                    <label class="label-micro" for="ed-team">Owning team</label>
                    <input id="ed-team" v-model="metaDraft.team" type="text" class="input-console" />
                  </div>
                </div>
                <div class="field">
                  <label class="label-micro" for="ed-tags">Tags</label>
                  <input id="ed-tags" v-model="metaDraft.tags" type="text" class="input-console" />
                  <p class="field-help">Comma separated.</p>
                </div>

                <MetadataInput
                  v-for="field in liveFields"
                  :key="field.id"
                  :field="field"
                  :model-value="metaDraft.metadata[field.key]"
                  @update:model-value="metaDraft.metadata[field.key] = $event"
                />

                <div class="flex justify-end gap-2">
                  <button class="btn-console" @click="editingMeta = false">Cancel</button>
                  <button
                    class="btn-console"
                    data-variant="signal"
                    :disabled="savingMeta"
                    @click="saveMeta(selected)"
                  >
                    {{ savingMeta ? 'Saving…' : 'Save' }}
                  </button>
                </div>
              </template>

              <dl v-else class="detail-list">
                <div>
                  <dt class="label-micro">Environment</dt>
                  <dd>{{ selected.environment || '—' }}</dd>
                </div>
                <div>
                  <dt class="label-micro">Team</dt>
                  <dd>{{ selected.team || '—' }}</dd>
                </div>
                <div v-if="selected.tags?.length" class="detail-wide">
                  <dt class="label-micro">Tags</dt>
                  <dd>{{ selected.tags.join(', ') }}</dd>
                </div>
                <div v-for="field in answeredFields(selected)" :key="field.id">
                  <dt class="label-micro">
                    {{ field.label }}
                    <span v-if="field.is_archived" class="sev-unknown">(archived)</span>
                  </dt>
                  <!-- The label, never the stored value: tier_1 is what the
                       database holds and "Tier 1" is what it means. -->
                  <dd>{{ formatMetadataValue(field, selected.metadata?.[field.key]) }}</dd>
                </div>
              </dl>
            </div>

            <dl class="detail-list">
              <div class="detail-wide">
                <dt class="label-micro">Subject alternative names</dt>
                <dd>{{ selected.sans?.join(', ') || '—' }}</dd>
              </div>
              <div class="detail-wide">
                <dt class="label-micro">Serial</dt>
                <dd class="break-all">{{ selected.serial_number || '—' }}</dd>
              </div>
              <div>
                <dt class="label-micro">Key</dt>
                <dd>{{ selected.key_type }}-{{ selected.key_size }}</dd>
              </div>
              <div>
                <dt class="label-micro">Key held by</dt>
                <dd>
                  {{
                    selected.key_custody === 'CERTPILOT'
                      ? 'CertPilot'
                      : selected.key_custody === 'AGENT'
                        ? 'The host'
                        : 'Elsewhere'
                  }}
                </dd>
              </div>
              <div>
                <dt class="label-micro">Renewals</dt>
                <dd>{{ selected.renewal_count }}</dd>
              </div>
              <div>
                <dt class="label-micro">Issued</dt>
                <dd>{{ formatDate(selected.not_before) }}</dd>
              </div>
              <div>
                <dt class="label-micro">Expires</dt>
                <dd>{{ formatDate(selected.not_after) }}</dd>
              </div>
              <div class="detail-wide">
                <dt class="label-micro">Auto renew</dt>
                <dd>{{ autoRenewNote(selected) }}</dd>
              </div>
              <div class="detail-wide">
                <dt class="label-micro">Issuer</dt>
                <dd class="break-all">{{ selected.issuer_dn || '—' }}</dd>
              </div>
              <div v-if="selected.renewal_error" class="detail-wide">
                <dt class="label-micro sev-critical">Last renewal error</dt>
                <dd class="sev-critical break-words">{{ selected.renewal_error }}</dd>
              </div>
            </dl>
          </div>
        </PanelBox>
      </div>
    </DataState>

    <!-- Request. A modal is right here: it is a create action with its own
         validity, not a thing to compare against the list behind it. -->
    <div v-if="showRequest" class="modal-scrim" @click.self="showRequest = false">
      <PanelBox label="New certificate" class="modal-panel">
        <div v-if="requestError" role="alert" class="action-error mb-3">
          <CircleX class="w-3.5 h-3.5 shrink-0 sev-critical" />
          <span>{{ requestError }}</span>
        </div>

        <!-- Two operations, not one with an option. The choice decides who
             holds the private key for the certificate's whole life, which is
             not a detail to bury inside a form. -->
        <div class="mode-switch">
          <button
            type="button"
            class="mode-option"
            :data-active="requestMode === 'generate' || undefined"
            @click="setMode('generate')"
          >
            <KeyRound class="w-3.5 h-3.5" />
            <span class="mode-title">Generate a key</span>
            <span class="mode-note">CertPilot creates the key and seals it here</span>
          </button>
          <button
            type="button"
            class="mode-option"
            :data-active="requestMode === 'sign' || undefined"
            @click="setMode('sign')"
          >
            <FileSignature class="w-3.5 h-3.5" />
            <span class="mode-title">Sign a request</span>
            <span class="mode-note">Your key stays where it is — CertPilot never sees it</span>
          </button>
        </div>

        <form
          class="flex flex-col gap-2.5"
          @submit.prevent="requestMode === 'sign' ? signCSR() : requestCert()"
        >
          <template v-if="requestMode === 'sign'">
            <div class="field">
              <label class="label-micro" for="csr">Signing request</label>
              <p class="field-help">
                The names, key type and key size are read from the request itself, so they are
                not asked for here.
              </p>
              <textarea
                id="csr"
                v-model="csrText"
                required
                rows="7"
                spellcheck="false"
                placeholder="-----BEGIN CERTIFICATE REQUEST-----"
                class="input-console csr-input"
              ></textarea>
              <div class="flex items-center gap-2 flex-wrap">
                <label class="btn-console cursor-pointer">
                  Load .csr file
                  <input type="file" accept=".csr,.pem,.req,.txt" class="hidden" @change="readCSRFile" />
                </label>
                <span class="field-help" data-tone="warning">
                  Never paste a private key here — the server refuses it and logs the attempt.
                </span>
              </div>
            </div>
          </template>

          <template v-else>
            <div class="field">
              <label class="label-micro" for="cn">Common name</label>
              <input
                id="cn"
                v-model="reqForm.common_name"
                type="text"
                required
                placeholder="app.example.com"
                class="input-console"
              />
            </div>

            <div class="field">
              <label class="label-micro" for="sans">Additional names</label>
              <p class="field-help">Comma separated.</p>
              <input
                id="sans"
                v-model="reqForm.sans"
                type="text"
                placeholder="www.example.com, api.example.com"
                class="input-console"
              />
            </div>
          </template>

          <div class="field">
            <label class="label-micro" for="ca-account">Issue from</label>
            <select id="ca-account" v-model="reqForm.ca_account_id" required class="input-console">
              <option value="" disabled>Select a CA account</option>
              <option v-for="acc in caAccounts" :key="acc.id" :value="acc.id">
                {{ acc.name }} ({{ acc.provider_type }})
              </option>
            </select>
            <p v-if="accounts.loaded.value && !caAccounts.length" class="field-help" data-tone="warning">
              No CA accounts configured — add one on the Gateways page first.
            </p>
          </div>

          <div class="grid gap-2" :class="requestMode === 'sign' ? 'grid-cols-1' : 'grid-cols-3'">
            <div v-if="requestMode !== 'sign'" class="field">
              <label class="label-micro" for="kt">Key type</label>
              <select
                id="kt"
                v-model="reqForm.key_type"
                class="input-console"
                @change="onKeyTypeChange"
              >
                <option value="ECDSA">ECDSA</option>
                <option value="RSA">RSA</option>
              </select>
            </div>
            <div v-if="requestMode !== 'sign'" class="field">
              <label class="label-micro" for="ks">Key size</label>
              <select id="ks" v-model="reqForm.key_size" class="input-console">
                <option v-for="size in keySizeOptions" :key="size" :value="size">{{ size }}</option>
              </select>
            </div>
            <div class="field">
              <label class="label-micro" for="vd">Validity (days)</label>
              <input
                id="vd"
                v-model="reqForm.validity_days"
                type="number"
                min="1"
                max="398"
                class="input-console"
              />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-2">
            <div class="field">
              <label class="label-micro" for="env">Environment</label>
              <input
                id="env"
                v-model="reqForm.environment"
                type="text"
                placeholder="production"
                class="input-console"
              />
            </div>
            <div class="field">
              <label class="label-micro" for="team">Owning team</label>
              <input
                id="team"
                v-model="reqForm.team"
                type="text"
                placeholder="Platform Engineering"
                class="input-console"
              />
            </div>
          </div>

          <!-- Whatever this organisation decided it needs to know. Required
               ones are enforced by the server at issuance. -->
          <MetadataInput
            v-for="field in liveFields"
            :key="field.id"
            :field="field"
            :model-value="reqMeta[field.key]"
            @update:model-value="reqMeta[field.key] = $event"
          />

          <label
            v-if="requestMode !== 'sign'"
            class="flex items-center gap-2 cursor-pointer"
            style="font-size: var(--fs-small)"
          >
            <input v-model="reqForm.auto_renew" type="checkbox" />
            Renew automatically before expiry
          </label>
          <!-- Automatic renewal needs a key to build the next certificate with,
               and there is none here. Offering the checkbox would schedule a
               renewal that can only fail, months from now, unattended. -->
          <p v-else class="field-help">
            Automatic renewal is unavailable: renewing needs the private key, which stays with
            you. Send a new request before this one expires.
          </p>

          <div class="flex justify-end gap-2 pt-1">
            <button type="button" class="btn-console" @click="showRequest = false">Cancel</button>
            <button type="submit" class="btn-console" data-variant="signal" :disabled="requesting">
              <template v-if="requesting">Working…</template>
              <template v-else>{{ requestMode === 'sign' ? 'Sign request' : 'Request' }}</template>
            </button>
          </div>
        </form>
      </PanelBox>
    </div>

    <!-- Revoke dialog.
         Two deliberate steps from a table row: open the certificate, then open
         this. A revocation cannot be undone, and a one-click action on a row is
         one mis-aimed cursor away from revoking the wrong certificate. -->
    <div
      v-if="revokeTarget"
      class="dialog-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="revoke-title"
      @click.self="closeRevoke"
      @keydown.esc="closeRevoke"
    >
      <div class="dialog-panel">
        <header class="panel-head">
          <span id="revoke-title" class="label-rail">Revoke certificate</span>
        </header>

        <form @submit.prevent="confirmRevoke">
          <div class="dialog-body flex flex-col gap-3">
            <!-- Named in full. The dialog is modal, so this is the only thing
                 on screen saying which certificate is about to be revoked. -->
            <dl class="kv">
              <dt>Common name</dt>
              <dd>{{ certName(revokeTarget) }}</dd>
              <dt v-if="revokeTarget.serial_number">Serial</dt>
              <dd v-if="revokeTarget.serial_number">{{ revokeTarget.serial_number }}</dd>
              <dt>Expires</dt>
              <dd>{{ revokeTarget.not_after ? formatDate(revokeTarget.not_after) : '—' }}</dd>
            </dl>

            <p class="field-help">
              CertPilot asks the CA first and records the result only if the CA
              agreed. If anything fails, nothing changes and you can try again.
              <strong>This cannot be undone</strong> — a revoked certificate
              cannot be un-revoked, only replaced.
            </p>

            <div class="field">
              <span class="label-micro">Reason</span>
              <!-- Radios rather than a select. The reason is the part of this
                   operation that survives: it is what tells the next reader
                   whether a key was compromised or a service was retired, and
                   a collapsed select invites taking whatever is on top. -->
              <div class="reason-list">
                <label v-for="r in REVOCATION_REASONS" :key="r.code" class="reason">
                  <input
                    v-model="revokeReason"
                    type="radio"
                    name="revoke-reason"
                    class="radio-console"
                    :value="r.code"
                  />
                  <span>
                    <span class="reason-name">{{ r.name }}</span>
                    <span class="field-help">{{ r.what }}</span>
                  </span>
                </label>
              </div>
            </div>

            <p v-if="revokeError" role="alert" class="export-error">{{ revokeError }}</p>
          </div>

          <div class="dialog-foot">
            <button type="button" class="btn-console" :disabled="revoking" @click="closeRevoke">
              Cancel
            </button>
            <!-- Disabled until a reason is chosen, because the core requires
                 one and a request without it is a guaranteed 400. -->
            <button
              type="submit"
              class="btn-console btn-danger"
              :disabled="revoking || revokeReason === null"
            >
              <template v-if="revoking">Asking the CA…</template>
              <template v-else>Revoke</template>
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<style scoped>
.page-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--line);
}

.page-sub {
  font-size: var(--fs-small);
  color: var(--text-muted);
  margin-top: 0.25rem;
}

.action-error {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.625rem;
  font-size: var(--fs-small);
  background: var(--sev-critical-wash);
  border: 1px solid var(--sev-critical);
  border-left-width: 3px;
  word-break: break-word;
}

.filter-bar {
  display: flex;
  align-items: stretch;
  gap: 1px;
  flex-wrap: wrap;
  background: var(--line);
  border: 1px solid var(--line);
}

.filter-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.3rem 0.625rem;
  font-size: var(--fs-micro);
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-weight: 600;
  color: var(--text-muted);
  background: var(--ink-panel);
  border: 0;
  cursor: pointer;
}

.filter-chip:hover {
  color: var(--text-primary);
  background: var(--ink-hover);
}

.filter-chip[data-active] {
  color: var(--text-primary);
  background: var(--ink-raised);
  box-shadow: inset 0 -2px 0 0 var(--signal);
}

.filter-count {
  font-weight: 700;
  font-size: var(--fs-label);
}

.filter-search {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin-left: auto;
  padding: 0 0.5rem;
  background: var(--ink-panel);
}

.filter-search input {
  background: none;
  border: 0;
  outline: none;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--fs-small);
  width: 14rem;
}

.filter-search input::placeholder {
  color: var(--text-muted);
}

.split {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 0.75rem;
  min-width: 0;
}

@media (min-width: 1280px) {
  .split[data-open] {
    grid-template-columns: minmax(0, 1fr) 22rem;
  }
}

.table-scroll {
  overflow-x: auto;
  max-height: calc(100vh - 15rem);
  overflow-y: auto;
}

.row-action {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  color: var(--text-muted);
  background: none;
  border: 0;
  cursor: pointer;
}

.row-action:hover:not(:disabled) {
  color: var(--text-primary);
}

.row-action:disabled {
  opacity: 0.4;
}

.detail-title {
  font-size: var(--fs-body);
  font-weight: 600;
  color: var(--text-primary);
  word-break: break-all;
}

.detail-list {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.625rem 0.75rem;
  font-size: var(--fs-small);
}

.detail-wide {
  grid-column: 1 / -1;
}

.detail-list dd {
  color: var(--text-secondary);
  margin-top: 0.15rem;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 2.5rem 1rem;
  text-align: center;
  font-size: var(--fs-small);
  color: var(--text-muted);
}

.modal-scrim {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 3rem 1rem;
  background: rgb(0 0 0 / 0.65);
  overflow-y: auto;
}

.modal-panel {
  width: 100%;
  max-width: 30rem;
}

.meta-filter {
  display: flex;
  align-items: flex-end;
  gap: 0.5rem;
  flex-wrap: wrap;
  padding: 0.5rem 0.625rem;
  background: var(--ink-panel);
  border: 1px solid var(--line);
}

.meta-filter-item {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

/* A select sizes to its widest option, so a field whose answers are all short
   collapses to a box narrower than its own label. */
.meta-filter-item select {
  min-width: 9rem;
}

.meta-block {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.5rem;
  background: var(--ink-raised);
  border: 1px solid var(--line);
}

.meta-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  min-width: 0;
}

.mode-switch {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1px;
  background: var(--line);
  border: 1px solid var(--line);
  margin-bottom: 0.75rem;
}

.mode-option {
  display: grid;
  grid-template-columns: auto 1fr;
  grid-template-areas: 'icon title' 'icon note';
  align-items: center;
  gap: 0.1rem 0.5rem;
  padding: 0.5rem 0.625rem;
  text-align: left;
  background: var(--ink-panel);
  border: 0;
  color: var(--text-muted);
  cursor: pointer;
}

.mode-option > svg {
  grid-area: icon;
}

.mode-option:hover {
  background: var(--ink-hover);
}

.mode-option[data-active] {
  color: var(--text-primary);
  background: var(--ink-raised);
  box-shadow: inset 0 -2px 0 0 var(--signal);
}

.mode-title {
  grid-area: title;
  font-size: var(--fs-small);
  font-weight: 600;
}

.mode-note {
  grid-area: note;
  font-size: var(--fs-micro);
  color: var(--text-muted);
  line-height: 1.3;
}

.csr-input {
  font-size: var(--fs-micro);
  line-height: 1.4;
  resize: vertical;
  white-space: pre;
  overflow-wrap: normal;
  overflow-x: auto;
}

.export {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 0.5rem;
  background: var(--ink-raised);
  border: 1px solid var(--line);
}

.export-row {
  display: flex;
  gap: 0.375rem;
  flex-wrap: wrap;
}

.revoke-block {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  align-items: flex-start;
  padding: 0.5rem;
  background: var(--ink-raised);
  border: 1px solid var(--line);
}

.reason-list {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.reason {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.5rem;
  align-items: start;
  cursor: pointer;
}

.reason > span {
  display: flex;
  flex-direction: column;
  gap: 0.0625rem;
}

.reason-name {
  font-size: var(--fs-small);
}

.export-key {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  align-items: flex-start;
  padding-top: 0.375rem;
  border-top: 1px solid var(--line);
}

.export-note {
  font-size: var(--fs-micro);
  color: var(--text-muted);
  line-height: 1.35;
}

.export-refusal {
  font-size: var(--fs-small);
  color: var(--text-secondary);
  font-weight: 600;
}

.export-error {
  font-size: var(--fs-micro);
  color: var(--sev-critical);
  word-break: break-word;
}
</style>
