<script setup lang="ts">
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import { Sliders, Plus, RotateCw, CircleX, Trash2 } from 'lucide-vue-next'
import { parseDetails, type ListResponse, type Policy } from '@/lib/types'

const api = useApi()

const policies = useAsyncData<ListResponse<Policy>>((s) =>
  api.get<ListResponse<Policy>>('/api/v1/policies', s),
)
const policyList = computed(() => policies.data.value?.data ?? [])

/**
 * Every rule type the engine evaluates, and no others.
 *
 * This list used to be three long, with a note explaining that the schema also
 * permitted key_type, naming and approval_required while nothing implemented
 * them. Two of those now work. approval_required stays absent because there is
 * still no approval workflow behind it, and the API no longer accepts one.
 */
const RULE_TYPES = [
  { value: 'key_size', label: 'Minimum key size', hint: 'A floor per algorithm — RSA bits and ECDSA curve are set separately' },
  { value: 'key_type', label: 'Allowed key types', hint: 'Which algorithms may be used at all' },
  { value: 'max_lifetime', label: 'Lifetime bounds', hint: 'Caps requested validity, and can set a floor' },
  { value: 'ca_restriction', label: 'Allowed CA providers', hint: 'Restricts which gateways may issue' },
  { value: 'naming', label: 'Naming rules', hint: 'Which names a certificate may carry, and how many' },
] as const

/** The algorithms this build supports, from pkg/crypto. */
const KEY_TYPES = ['RSA', 'ECDSA', 'Ed25519'] as const

const SEVERITIES = [
  { value: 'INFO', label: 'Info', hint: 'Recorded on the request, allowed' },
  { value: 'WARNING', label: 'Warning', hint: 'Returned with the certificate, allowed' },
  { value: 'BLOCK', label: 'Block', hint: 'Refuses the request outright' },
] as const

function ruleLabel(type: string) {
  return RULE_TYPES.find((r) => r.value === type)?.label ?? type
}

function severityBadgeClass(severity: string) {
  switch (severity) {
    case 'BLOCK': return 'sev-critical'
    case 'WARNING': return 'sev-warning'
    default: return 'sev-unknown'
  }
}

/** Renders the JSON rule_config as a readable sentence. */
function describeRule(policy: Policy): string {
  const cfg = parseDetails<Record<string, unknown>>(policy.rule_config)
  if (!cfg) return policy.rule_config || '—'
  switch (policy.rule_type) {
    case 'key_size': {
      const parts: string[] = []
      const rsa = cfg.rsa_min_bits ?? cfg.min_key_size
      if (rsa) parts.push(`RSA at least ${rsa} bits`)
      if (cfg.ecdsa_min_bits) parts.push(`ECDSA at least P-${cfg.ecdsa_min_bits}`)
      return parts.join(', ') || policy.rule_config
    }
    case 'key_type': {
      const allowed = cfg.allowed_key_types as string[] | undefined
      const forbidden = cfg.forbidden_key_types as string[] | undefined
      const parts: string[] = []
      if (allowed?.length) parts.push(`Only ${allowed.join(', ')}`)
      if (forbidden?.length) parts.push(`Never ${forbidden.join(', ')}`)
      return parts.join(', ') || policy.rule_config
    }
    case 'max_lifetime': {
      const parts: string[] = []
      if (cfg.max_days) parts.push(`at most ${cfg.max_days} days`)
      if (cfg.min_days) parts.push(`at least ${cfg.min_days} days`)
      return parts.length ? `Validity ${parts.join(', ')}` : policy.rule_config
    }
    case 'ca_restriction':
      return `May only be issued by: ${(cfg.allowed_providers as string[])?.join(', ')}`
    case 'naming': {
      const parts: string[] = []
      const suffixes = cfg.allowed_suffixes as string[] | undefined
      const forbidden = cfg.forbidden_patterns as string[] | undefined
      if (suffixes?.length) parts.push(`names under ${suffixes.join(', ')}`)
      if (forbidden?.length) parts.push(`never ${forbidden.join(', ')}`)
      if (cfg.allow_wildcards === false) parts.push('no wildcards')
      if (cfg.max_sans) parts.push(`at most ${cfg.max_sans} names`)
      return parts.join(', ') || policy.rule_config
    }
    default:
      return policy.rule_config
  }
}

// ── Create ────────────────────────────────────────────────
const showCreate = ref(false)
const saving = ref(false)
const createError = ref<string | null>(null)

const blankForm = () => ({
  name: '',
  description: '',
  rule_type: 'key_size' as (typeof RULE_TYPES)[number]['value'],
  severity: 'WARNING' as (typeof SEVERITIES)[number]['value'],
  domain_pattern: '*',
  is_enabled: true,
  min_key_size: '2048',
  ecdsa_min_bits: '256',
  allowed_key_types: ['RSA', 'ECDSA', 'Ed25519'] as string[],
  max_days: '90',
  min_days: '',
  allowed_providers: 'acme',
  allowed_suffixes: '',
  forbidden_patterns: '',
  allow_wildcards: true,
  max_sans: '',
})

/** Comma-separated text to a trimmed list, dropping empties. */
const toList = (s: string) => s.split(',').map((v) => v.trim()).filter(Boolean)
const form = ref(blankForm())

/** Builds the JSON `rule_config` the engine expects for the chosen rule type. */
function buildRuleConfig(): string {
  switch (form.value.rule_type) {
    case 'key_size':
      // Both floors, because RSA bits and ECDSA curve bits are different units
      // and one number cannot express a minimum for both.
      return JSON.stringify({
        rsa_min_bits: Number(form.value.min_key_size),
        ecdsa_min_bits: Number(form.value.ecdsa_min_bits),
      })
    case 'key_type':
      return JSON.stringify({ allowed_key_types: form.value.allowed_key_types })
    case 'max_lifetime':
      return JSON.stringify({
        max_days: Number(form.value.max_days),
        ...(form.value.min_days ? { min_days: Number(form.value.min_days) } : {}),
      })
    case 'ca_restriction':
      return JSON.stringify({
        allowed_providers: toList(form.value.allowed_providers),
      })
    case 'naming':
      return JSON.stringify({
        ...(form.value.allowed_suffixes
          ? { allowed_suffixes: toList(form.value.allowed_suffixes) } : {}),
        ...(form.value.forbidden_patterns
          ? { forbidden_patterns: toList(form.value.forbidden_patterns) } : {}),
        // Sent only when it is the constraint being expressed: the engine reads
        // an absent allow_wildcards as "not this policy's concern", so always
        // sending false would make every naming rule ban wildcards.
        ...(form.value.allow_wildcards ? {} : { allow_wildcards: false }),
        ...(form.value.max_sans ? { max_sans: Number(form.value.max_sans) } : {}),
      })
  }
}

async function createPolicy() {
  saving.value = true
  createError.value = null
  try {
    await api.post('/api/v1/policies', {
      name: form.value.name,
      description: form.value.description || undefined,
      rule_type: form.value.rule_type,
      rule_config: buildRuleConfig(),
      domain_pattern: form.value.domain_pattern || undefined,
      severity: form.value.severity,
      is_enabled: form.value.is_enabled,
    })
    showCreate.value = false
    form.value = blankForm()
    await policies.refresh()
  } catch (err) {
    createError.value = err instanceof Error ? err.message : String(err)
  } finally {
    saving.value = false
  }
}

// ── Enable / disable / delete ─────────────────────────────
const busyId = ref<string | null>(null)
const actionError = ref<string | null>(null)

// The enable switch was previously bound with :checked and no handler, so it
// looked interactive and changed nothing.
async function toggleEnabled(policy: Policy) {
  busyId.value = policy.id
  actionError.value = null
  try {
    await api.put(`/api/v1/policies/${policy.id}`, {
      ...policy,
      is_enabled: !policy.is_enabled,
    })
    await policies.refresh()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busyId.value = null
  }
}

async function removePolicy(policy: Policy) {
  if (!confirm(`Delete the policy "${policy.name}"?`)) return
  busyId.value = policy.id
  actionError.value = null
  try {
    await api.delete(`/api/v1/policies/${policy.id}`)
    await policies.refresh()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busyId.value = null
  }
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <p class="text-sm text-[color:var(--text-muted)]">
        Rules evaluated when a certificate is requested
      </p>
      <div class="flex items-center gap-2">
        <button class="btn-console gap-1.5" :disabled="policies.loading.value" @click="policies.refresh()">
          <RotateCw class="w-3.5 h-3.5" :class="policies.loading.value && 'animate-spin'" />
          Refresh
        </button>
        <button class="btn-console btn-signal gap-2" @click="showCreate = true">
          <Plus class="w-4 h-4" /> Create policy
        </button>
      </div>
    </div>

    <div v-if="actionError" role="alert" class="notice" data-tone="critical">
      <CircleX class="w-5 h-5 shrink-0" />
      <span class="text-sm break-words">{{ actionError }}</span>
    </div>

    <div role="alert" class="notice" data-tone="signal">
      <Sliders class="w-4 h-4 shrink-0" />
      <span class="text-xs">
        Evaluated on every issuance path, and again at renewal — a certificate whose key no
        longer clears a floor is renewed with one that does. Only
        <span class="font-mono">BLOCK</span> refuses a request; other severities are returned
        alongside the certificate.
      </span>
    </div>

    <DataState
      :loading="policies.loading.value"
      :error="policies.error.value"
      :loaded="policies.loaded.value"
      @retry="policies.refresh()"
    >
      <div v-if="policyList.length" class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div
          v-for="policy in policyList" :key="policy.id"
          class="panel border"
          :class="!policy.is_enabled && 'opacity-60'"
        >
          <div class="panel-body p-4 gap-2">
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <div class="font-bold text-sm truncate">{{ policy.name }}</div>
                <div class="text-[11px] text-[color:var(--text-muted)]">{{ ruleLabel(policy.rule_type) }}</div>
              </div>
              <span class="tag shrink-0" :class="severityBadgeClass(policy.severity)">
                {{ policy.severity }}
              </span>
            </div>

            <p v-if="policy.description" class="text-xs text-[color:var(--text-secondary)]">{{ policy.description }}</p>
            <p class="text-xs font-mono px-2 py-1.5 break-words">
              {{ describeRule(policy) }}
            </p>
            <p class="text-[11px] text-[color:var(--text-muted)]">
              Applies to <span class="font-mono">{{ policy.domain_pattern || '*' }}</span>
            </p>

            <div class="flex items-center justify-between mt-1">
              <label class="label cursor-pointer justify-start gap-2 py-0">
                <input
                  type="checkbox" class="toggle-console toggle-primary"
                  :checked="policy.is_enabled" :disabled="busyId === policy.id"
                  @change="toggleEnabled(policy)"
                />
                <span class="label-micro">
                  {{ policy.is_enabled ? 'Enabled' : 'Disabled' }}
                </span>
              </label>
              <button
                class="btn-console sev-critical" :disabled="busyId === policy.id"
                @click="removePolicy(policy)"
              >
                <Trash2 class="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="p-3">
        <div class="empty-console">
          <strong>No policies are defined.</strong>
          Every request is accepted: any key size, any lifetime, any certificate
          authority. Nothing is being enforced here, which is not the same as
          nothing being wrong.
        </div>
      </div>
    </DataState>

    <!-- Create modal -->
    <div
      v-if="showCreate"
      class="dialog-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-policy-title"
      @click.self="showCreate = false"
      @keydown.esc="showCreate = false"
    >
      <div class="dialog-panel !max-w-md">
        <header class="panel-head">
          <span id="create-policy-title" class="label-rail">Create policy</span>
        </header>
        <form @submit.prevent="createPolicy">
          <div class="dialog-body flex flex-col gap-3">
            <div v-if="createError" role="alert" class="notice" data-tone="critical">
              <CircleX class="w-4 h-4 notice-icon" />
              <span class="break-words">{{ createError }}</span>
            </div>

          <div class="field">
            <label class="label-micro" for="p-name">Name</label>
            <input
              id="p-name" v-model="form.name" type="text" required
              placeholder="Minimum RSA 2048" class="input-console"
            />
          </div>

          <div class="field">
            <label class="label-micro" for="p-desc">Description</label>
            <input
              id="p-desc" v-model="form.description" type="text"
              class="input-console"
            />
          </div>

          <div class="field">
            <label class="label-micro" for="p-type">Rule</label>
            <select id="p-type" v-model="form.rule_type" class="select-console">
              <option v-for="r in RULE_TYPES" :key="r.value" :value="r.value">{{ r.label }}</option>
            </select>
            <p class="text-[11px] text-[color:var(--text-muted)] mt-1">
              {{ RULE_TYPES.find((r) => r.value === form.rule_type)?.hint }}
            </p>
          </div>

          <template v-if="form.rule_type === 'key_size'">
            <div class="grid grid-cols-2 gap-3">
              <div class="field">
                <label class="label-micro" for="p-keysize">Minimum RSA key size</label>
                <select id="p-keysize" v-model="form.min_key_size" class="select-console">
                  <option value="2048">2048 bits</option>
                  <option value="3072">3072 bits</option>
                  <option value="4096">4096 bits</option>
                </select>
              </div>
              <div class="field">
                <label class="label-micro" for="p-ecdsa">Minimum ECDSA curve</label>
                <select id="p-ecdsa" v-model="form.ecdsa_min_bits" class="select-console">
                  <option value="256">P-256</option>
                  <option value="384">P-384</option>
                  <option value="521">P-521</option>
                </select>
              </div>
            </div>
            <p class="field-help">
              Set separately because the numbers are not comparable: 256 is a strong
              ECDSA key and a broken RSA one. Ed25519 has one size, so a floor cannot
              apply to it — use an allowed key types rule to permit or forbid it.
            </p>
          </template>

          <template v-else-if="form.rule_type === 'key_type'">
            <div class="field">
              <span class="label-micro">Allowed key types</span>
              <div class="flex gap-4 mt-1">
                <label v-for="kt in KEY_TYPES" :key="kt" class="flex items-center gap-1.5">
                  <input
                    type="checkbox" :value="kt" v-model="form.allowed_key_types"
                    class="accent-[color:var(--signal)]"
                  />
                  <span class="text-xs">{{ kt }}</span>
                </label>
              </div>
              <p class="field-help">
                Anything not ticked is refused. A request whose key type this build does
                not recognise is refused too, rather than assumed acceptable.
              </p>
            </div>
          </template>

          <template v-else-if="form.rule_type === 'max_lifetime'">
            <div class="grid grid-cols-2 gap-3">
              <div class="field">
                <label class="label-micro" for="p-maxdays">Maximum validity (days)</label>
                <input
                  id="p-maxdays" v-model="form.max_days" type="number" min="1" max="398"
                  class="input-console"
                />
              </div>
              <div class="field">
                <label class="label-micro" for="p-mindays">Minimum (optional)</label>
                <input
                  id="p-mindays" v-model="form.min_days" type="number" min="1" max="398"
                  placeholder="none" class="input-console"
                />
              </div>
            </div>
            <p class="field-help">
              Public TLS maximum is 200 days from March 2026, 100 from 2027, 47 from 2029.
            </p>
          </template>

          <template v-else-if="form.rule_type === 'naming'">
            <div class="field">
              <label class="label-micro" for="p-suffixes">Allowed suffixes</label>
              <span class="field-help">Comma separated. Matched on a label boundary, so example.com does not admit evil-example.com.</span>
              <input
                id="p-suffixes" v-model="form.allowed_suffixes" type="text"
                placeholder="example.com, corp.example.com" class="input-console"
              />
            </div>
            <div class="field">
              <label class="label-micro" for="p-forbidden">Forbidden patterns</label>
              <span class="field-help">Comma separated. An exact name, or a leading *. wildcard.</span>
              <input
                id="p-forbidden" v-model="form.forbidden_patterns" type="text"
                placeholder="*.internal, localhost" class="input-console"
              />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div class="field">
                <label class="label-micro" for="p-maxsans">Maximum names (optional)</label>
                <input
                  id="p-maxsans" v-model="form.max_sans" type="number" min="1"
                  placeholder="unlimited" class="input-console"
                />
              </div>
              <div class="field">
                <span class="label-micro">Wildcards</span>
                <label class="flex items-center gap-1.5 mt-1">
                  <input
                    type="checkbox" v-model="form.allow_wildcards"
                    class="accent-[color:var(--signal)]"
                  />
                  <span class="text-xs">Allow *.name certificates</span>
                </label>
              </div>
            </div>
          </template>

          <div v-else class="field">
            <label class="label-micro" for="p-providers">Allowed providers</label>
              <span class="field-help">Comma separated</span>
            <input
              id="p-providers" v-model="form.allowed_providers" type="text"
              placeholder="acme, vault" class="input-console"
            />
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div class="field">
              <label class="label-micro" for="p-sev">Severity</label>
              <select id="p-sev" v-model="form.severity" class="select-console">
                <option v-for="s in SEVERITIES" :key="s.value" :value="s.value">{{ s.label }}</option>
              </select>
            </div>
            <div class="field">
              <label class="label-micro" for="p-domain">Domain pattern</label>
              <input
                id="p-domain" v-model="form.domain_pattern" type="text"
                placeholder="*.prod.example.com" class="input-console"
              />
            </div>
          </div>
          <p class="text-[11px] text-[color:var(--text-muted)] -mt-1">
            {{ SEVERITIES.find((s) => s.value === form.severity)?.hint }}
          </p>

            <label class="flex items-center gap-2 cursor-pointer">
              <input v-model="form.is_enabled" type="checkbox" class="check-console" />
              <span class="label-micro">Enabled</span>
            </label>
          </div>

          <div class="dialog-foot">
            <button type="button" class="btn-console" @click="showCreate = false">Cancel</button>
            <button type="submit" class="btn-console btn-signal" :disabled="saving">
              <span v-if="saving" class="spinner-console"></span>
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
