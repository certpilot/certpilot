<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { AlertTriangle, Check, Copy, KeyRound, Plus, Radio } from 'lucide-vue-next'
import { useApi } from '@/composables/useApi'
import { formatDateTime } from '@/lib/format'
import DataState from '@/components/common/DataState.vue'
import type { AcmeCredential, AcmeCredentialList, CertificateTemplate, ListResponse } from '@/lib/types'

/**
 * ACME clients, for an administrator.
 *
 * One credential lets one ACME client (certbot, acme.sh, lego, Caddy) register
 * under one template, and the template decides what it may be issued. Revoking
 * it cuts that client off. The HMAC key is shown once, at creation: the core
 * keeps it sealed and has no way to show it again.
 */

const api = useApi()

const credentials = ref<AcmeCredential[]>([])
const enabled = ref(true)
const templates = ref<CertificateTemplate[]>([])
const loading = ref(true)
const loaded = ref(false)
const error = ref<string | null>(null)

const busy = ref<string | null>(null)
const actionError = ref<string | null>(null)

const creating = ref(false)
const newName = ref('')
const newTemplate = ref('')

// Shown once, kept until dismissed: a key that vanishes on a timer is a
// credential somebody has to revoke and make again.
const revealed = ref<{ name: string; kid: string; hmacKey: string; directoryURL: string } | null>(null)
const copied = ref<string | null>(null)

const enabledTemplates = computed(() => templates.value.filter((t) => t.is_enabled))

async function load() {
  loading.value = true
  error.value = null
  try {
    const [list, tpls] = await Promise.all([
      api.get<AcmeCredentialList>('/api/v1/acme/credentials'),
      api.get<ListResponse<CertificateTemplate>>('/api/v1/certificate-templates'),
    ])
    credentials.value = list.data ?? []
    enabled.value = list.enabled
    templates.value = tpls.data ?? []
    loaded.value = true
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function create() {
  busy.value = 'new'
  actionError.value = null
  try {
    const res = await api.post<{ data: AcmeCredential; hmac_key: string; directory_url: string }>(
      '/api/v1/acme/credentials',
      { name: newName.value.trim(), template: newTemplate.value },
    )
    revealed.value = {
      name: res.data.name,
      kid: res.data.kid,
      hmacKey: res.hmac_key,
      directoryURL: res.directory_url,
    }
    newName.value = ''
    newTemplate.value = ''
    creating.value = false
    await load()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = null
  }
}

async function revoke(cred: AcmeCredential) {
  const what = cred.account_id
    ? `Revoke "${cred.name}"? The client registered with it can no longer order certificates.`
    : `Revoke "${cred.name}"? No client will be able to register with it.`
  if (!window.confirm(what)) return
  busy.value = cred.id
  actionError.value = null
  try {
    await api.delete(`/api/v1/acme/credentials/${cred.id}`)
    await load()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = null
  }
}

async function copy(what: string, value: string) {
  await navigator.clipboard.writeText(value)
  copied.value = what
  setTimeout(() => (copied.value = null), 1600)
}

/** The certbot command for a credential just made, with its real values. */
const certbotCommand = computed(() => {
  const r = revealed.value
  if (!r) return ''
  return `certbot register --server ${r.directoryURL} --eab-kid ${r.kid} --eab-hmac-key ${r.hmacKey} --email you@example.com`
})

function state(cred: AcmeCredential): { label: string; cls: string } {
  if (cred.revoked_at) return { label: 'REVOKED', cls: 'sev-critical' }
  if (cred.account_id) return { label: 'IN USE', cls: 'sev-ok' }
  return { label: 'UNUSED', cls: 'text-[color:var(--text-muted)]' }
}
</script>

<template>
  <section class="panel">
    <header class="panel-head">
      <div class="flex items-center gap-2">
        <Radio class="w-4 h-4" style="color: var(--signal)" />
        <h2 class="label-rail">ACME clients</h2>
      </div>
      <button v-if="!creating" class="btn-console" @click="creating = true">
        <Plus class="w-3 h-3" />
        Add client
      </button>
    </header>

    <p class="field-help panel-intro">
      A credential lets one ACME client — certbot, acme.sh, lego, Caddy — register under one
      template. The template decides which names, keys and lifetimes it can be issued. The client
      keeps its key; CertPilot records the certificate and alerts on it like any other.
    </p>

    <!-- Off is said, not hidden: a credential made now works for no client
         until the endpoint is switched on, and certbot's error would not say why. -->
    <div v-if="loaded && !enabled" role="status" class="notice-off">
      <AlertTriangle class="w-4 h-4 shrink-0 sev-warning" />
      <p class="field-help">
        The ACME endpoint is switched off, so no client can use these credentials yet. Set
        <code>acme.enabled: true</code> in the core's configuration and restart it.
      </p>
    </div>

    <div v-if="revealed" class="reveal">
      <KeyRound class="w-4 h-4 shrink-0" style="color: var(--sev-warning)" />
      <div class="flex-1 min-w-0 flex flex-col gap-2">
        <p class="label-rail sev-warning">Credential for {{ revealed.name }}</p>
        <div class="kv-row">
          <span class="label-micro">Directory</span>
          <code class="reveal-value">{{ revealed.directoryURL }}</code>
        </div>
        <div class="kv-row">
          <span class="label-micro">Key ID</span>
          <code class="reveal-value">{{ revealed.kid }}</code>
        </div>
        <div class="kv-row">
          <span class="label-micro">HMAC key</span>
          <code class="reveal-value">{{ revealed.hmacKey }}</code>
        </div>
        <div class="kv-row">
          <span class="label-micro">certbot</span>
          <code class="reveal-value command">{{ certbotCommand }}</code>
        </div>
        <p class="field-help">
          The HMAC key is shown once and cannot be recovered. Losing it means revoking this
          credential and making another.
        </p>
      </div>
      <div class="flex flex-col gap-1">
        <button class="btn-console" @click="copy('key', revealed.hmacKey)">
          <component :is="copied === 'key' ? Check : Copy" class="w-3 h-3" />
          {{ copied === 'key' ? 'Copied' : 'Copy key' }}
        </button>
        <button class="btn-console" @click="copy('cmd', certbotCommand)">
          <component :is="copied === 'cmd' ? Check : Copy" class="w-3 h-3" />
          {{ copied === 'cmd' ? 'Copied' : 'Copy command' }}
        </button>
        <button class="btn-console" @click="revealed = null">Dismiss</button>
      </div>
    </div>

    <form v-if="creating" class="create-row" @submit.prevent="create">
      <input
        v-model="newName"
        required
        placeholder="Who it is for, e.g. web team certbot"
        class="input-console flex-1"
        aria-label="Name"
      />
      <select v-model="newTemplate" required class="input-console" aria-label="Template">
        <option value="" disabled>Template</option>
        <option v-for="t in enabledTemplates" :key="t.id" :value="t.slug">{{ t.name }} ({{ t.slug }})</option>
      </select>
      <button class="btn-console" type="submit" :disabled="busy === 'new'">
        {{ busy === 'new' ? 'Creating…' : 'Create' }}
      </button>
      <button class="btn-console" type="button" @click="creating = false">Cancel</button>
    </form>

    <div v-if="actionError" role="alert" class="action-error">
      <AlertTriangle class="w-4 h-4 shrink-0 sev-critical" />
      <p class="state-error-detail">{{ actionError }}</p>
    </div>

    <DataState :loading="loading" :error="error" :loaded="loaded" @retry="load">
      <table v-if="credentials.length" class="tbl">
        <thead>
          <tr>
            <th>Client</th>
            <th>Template</th>
            <th>Directory</th>
            <th>Created</th>
            <th>State</th>
            <th class="text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          <!-- Revoked credentials stay listed, marked, so the list still says
               who once had access. -->
          <tr v-for="cred in credentials" :key="cred.id" :class="{ revoked: cred.revoked_at }">
            <td>
              <div class="who">{{ cred.name }}</div>
              <!-- The key ID and the slug are case-sensitive, so neither goes
                   through an uppercase label style: copied from there, they
                   would be wrong. -->
              <div><span class="label-micro">Key ID</span> <code class="exact">{{ cred.kid }}</code></div>
            </td>
            <td>
              <code v-if="cred.template" class="exact slug">{{ cred.template }}</code>
              <span v-else class="label-micro sev-warning">template deleted</span>
            </td>
            <td><code class="url">{{ cred.directory_url }}</code></td>
            <td class="tabular">{{ formatDateTime(cred.created_at) }}</td>
            <td><span :class="state(cred).cls">{{ state(cred).label }}</span></td>
            <td class="text-right">
              <button
                v-if="!cred.revoked_at"
                class="btn-console"
                :disabled="busy === cred.id"
                @click="revoke(cred)"
              >
                Revoke
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <p v-else class="field-help">
        No ACME clients yet. Nothing can register at the ACME endpoint until a credential is made
        here.
      </p>
    </DataState>
  </section>
</template>

<style scoped>
.panel {
  background: var(--ink-panel);
  border: 1px solid var(--line);
  padding: 0.875rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.panel-intro { margin-top: -0.25rem; }

.create-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
}

.reveal {
  display: flex;
  align-items: flex-start;
  gap: 0.625rem;
  padding: 0.75rem;
  border: 1px solid var(--sev-warning);
  background: var(--sev-warning-wash);
}

.kv-row {
  display: grid;
  grid-template-columns: 6rem 1fr;
  gap: 0.5rem;
  align-items: baseline;
}

.reveal-value {
  font-family: var(--font-mono);
  font-size: var(--fs-small);
  color: var(--text-primary);
  user-select: all;
  overflow-wrap: anywhere;
}

.command { white-space: pre-wrap; }

.notice-off,
.action-error {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  padding: 0.5rem 0.625rem;
}

.notice-off {
  border: 1px solid var(--sev-warning);
  background: var(--sev-warning-wash);
}

.action-error {
  border: 1px solid var(--sev-critical);
  background: var(--sev-critical-wash);
}

.who {
  font-family: var(--font-mono);
  font-size: var(--fs-small);
  color: var(--text-primary);
}

.exact {
  font-family: var(--font-mono);
  font-size: var(--fs-micro);
  color: var(--text-secondary);
  text-transform: none;
  letter-spacing: 0;
}

.slug { color: var(--text-primary); font-size: var(--fs-small); }

.url {
  font-family: var(--font-mono);
  font-size: var(--fs-micro);
  color: var(--text-muted);
  overflow-wrap: anywhere;
}

.tabular { font-variant-numeric: tabular-nums; }

.revoked { opacity: 0.62; }
</style>
