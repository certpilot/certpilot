<script setup lang="ts">
/**
 * Certificate templates, and who may use them.
 *
 * `agent_grants` has been API-only since migration 020 — the permission
 * deciding what an entire fleet may obtain from the organisation's CA had no
 * screen at all. Templates must not repeat that: an operator who cannot see a
 * control cannot review one, and a control nobody reviews drifts to whatever
 * the last person needed.
 *
 * Three things this screen exists to make obvious, in this order:
 *
 *  1. Which CA account signs it. The highest-consequence field, and not the
 *     requester's choice — so it is on the row, not behind a click.
 *  2. The disposition of each field. Supplied, constrained, or passed through.
 *     A template that passes the subject through is a more dangerous object
 *     than one that supplies it, and that has to be visible while scrolling.
 *  3. What it would refuse. Computed from the rules as they stand, because a
 *     list of fields is not the same as knowing what happens to a request.
 */
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import PanelBox from '@/components/ui/PanelBox.vue'
import { FileText, RotateCw, CircleX, ShieldCheck, KeyRound, Users, ChevronRight } from 'lucide-vue-next'
import type { CaAccount, CertificateTemplate, ListResponse, TemplateGrant } from '@/lib/types'

const api = useApi()

const templates = useAsyncData<ListResponse<CertificateTemplate>>((s) =>
  api.get<ListResponse<CertificateTemplate>>('/api/v1/certificate-templates', s),
)
const accounts = useAsyncData<ListResponse<CaAccount>>((s) =>
  api.get<ListResponse<CaAccount>>('/api/v1/ca-accounts', s),
)
const grants = useAsyncData<ListResponse<TemplateGrant>>((s) =>
  api.get<ListResponse<TemplateGrant>>('/api/v1/agent-grants', s),
)

const list = computed(() => templates.data.value?.data ?? [])
const actionError = ref('')
const expanded = ref<string | null>(null)

function accountName(id: string): string {
  return accounts.data.value?.data?.find((a) => a.id === id)?.name ?? 'an account that no longer exists'
}

function grantsFor(templateId: string): TemplateGrant[] {
  return (grants.data.value?.data ?? []).filter((g) => g.template_id === templateId)
}

/**
 * Which of the three things a template does to the subject.
 *
 * SUPPLIED with nothing to supply constrains nothing, and saying "supplied"
 * about an empty list would overstate it — this is the field an operator is
 * most likely to misread, so it reads as what it actually is.
 */
function subjectDisposition(t: CertificateTemplate): { label: string; tone: string; hint: string } {
  const supplies = Object.keys(t.subject_defaults ?? {}).length > 0
  if (t.subject_mode === 'CONSTRAINED') {
    return {
      label: 'Requester sets the subject',
      tone: 'sev-warning',
      hint: 'A signing request may carry its own organisation and it will be honoured.',
    }
  }
  if (!supplies) {
    return {
      label: 'Subject unconstrained',
      tone: 'sev-unknown',
      hint: 'Nothing is supplied and nothing is checked. Name an organisation to assert one.',
    }
  }
  return {
    label: 'Template supplies the subject',
    tone: 'sev-ok',
    hint: 'A signing request that disagrees is refused — it cannot be rewritten once signed.',
  }
}

/** The key rules as one sentence, or the honest absence of them. */
function describeKey(t: CertificateTemplate): string {
  const parts: string[] = []
  parts.push((t.allowed_key_types ?? []).join(', ') || 'any type')
  // Zero means unconstrained, so a bound that is not set is not a bound. The
  // first cut rendered "RSA 3072–any bits", which reads like a range with a
  // missing end rather than a floor with no ceiling.
  if (t.rsa_min_bits > 0 && t.rsa_max_bits > 0) {
    parts.push(`RSA ${t.rsa_min_bits}–${t.rsa_max_bits} bits`)
  } else if (t.rsa_min_bits > 0) {
    parts.push(`RSA ${t.rsa_min_bits} bits or more`)
  } else if (t.rsa_max_bits > 0) {
    parts.push(`RSA up to ${t.rsa_max_bits} bits`)
  }
  if ((t.ecdsa_curves ?? []).length && t.ecdsa_curves.length < 3) {
    parts.push(t.ecdsa_curves.join(', '))
  }
  return parts.join(' · ')
}

function describeLifetime(t: CertificateTemplate): string {
  if (t.validity_days > 0) return `${t.validity_days} days, supplied`
  if (t.max_validity_days > 0) return `up to ${t.max_validity_days} days, requested`
  return 'whatever the CA gives'
}

function describeNames(t: CertificateTemplate): string {
  const cn = t.common_name_rule ?? {}
  const san = t.san_rules ?? {}
  const suffixes = [...(cn.suffixes ?? []), ...(san.suffixes ?? [])]
  const parts: string[] = []
  if (suffixes.length) parts.push(`under ${suffixes.join(', ')}`)
  else parts.push('any name')
  if (san.allow_wildcards === false) parts.push('no wildcards')
  if (san.allow_wildcards === true) parts.push('wildcards allowed')
  if (san.max_names) parts.push(`at most ${san.max_names}`)
  if ((san.types ?? []).length) parts.push((san.types ?? []).join('/') + ' only')
  return parts.join(' · ')
}

/**
 * "an RSA key", "a P-256 key".
 *
 * Sound, not spelling. RSA is read out as "ar-ess-ay", so it takes "an" despite
 * starting with a consonant — as do the other letters whose names open with a
 * vowel. Small, and it is the first line an operator reads on this screen.
 */
function article(word: string): string {
  const first = word.charAt(0).toUpperCase()
  return 'AEIOUFHLMNRSX'.includes(first) ? 'an' : 'a'
}

/**
 * What this template would refuse, as sentences.
 *
 * Computed from the rules rather than written by hand, so it cannot drift from
 * them. A field list tells an operator what they typed; this tells them what
 * will happen to somebody's request, which is the thing they are actually
 * deciding.
 */
function wouldRefuse(t: CertificateTemplate): string[] {
  const out: string[] = []
  const types = t.allowed_key_types ?? []
  const missing = ['RSA', 'ECDSA', 'Ed25519'].filter(
    (k) => !types.some((a) => a.toUpperCase() === k.toUpperCase()),
  )
  if (missing.length) out.push(`${article(missing[0])} ${missing.join(' or ')} key`)
  if (t.rsa_min_bits > 0) out.push(`an RSA key below ${t.rsa_min_bits} bits`)
  if ((t.ecdsa_curves ?? []).length && t.ecdsa_curves.length < 3) {
    const absent = ['P-256', 'P-384', 'P-521'].filter((c) => !t.ecdsa_curves.includes(c))
    // Phrased like every other entry in this list. A bare "P-256 and P-521"
    // reads as a fact about the template rather than something it refuses.
    if (absent.length) out.push(`a ${absent.join(' or ')} key`)
  }
  const cn = t.common_name_rule ?? {}
  const san = t.san_rules ?? {}
  const suffixes = [...(cn.suffixes ?? []), ...(san.suffixes ?? [])]
  if (suffixes.length) out.push(`any name outside ${suffixes.join(', ')}`)
  if (san.allow_wildcards === false) out.push('a wildcard name')
  if (san.max_names) out.push(`more than ${san.max_names} names`)
  if (t.max_validity_days > 0) out.push(`a request for more than ${t.max_validity_days} days`)
  if (t.csr_required) out.push('a request without a signing request')
  if (t.key_custody_required !== 'ANY') {
    out.push(`a key held anywhere but ${t.key_custody_required}`)
  }
  for (const key of t.require_metadata ?? []) out.push(`a request not answering ${key}`)
  if (t.subject_mode === 'SUPPLIED' && Object.keys(t.subject_defaults ?? {}).length) {
    const pairs = Object.entries(t.subject_defaults).map(([k, v]) => `${k}=${v}`)
    out.push(`a signing request whose subject disagrees with ${pairs.join(', ')}`)
  }
  return out
}

function refreshAll() {
  actionError.value = ''
  templates.refresh()
  accounts.refresh()
  grants.refresh()
}

function toggle(id: string) {
  expanded.value = expanded.value === id ? null : id
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <p class="text-sm text-[color:var(--text-muted)]">
        What a kind of certificate looks like, and who may ask for one
      </p>
      <button class="btn-console gap-1.5" :disabled="templates.loading.value" @click="refreshAll()">
        <RotateCw class="w-3.5 h-3.5" :class="templates.loading.value && 'animate-spin'" />
        Refresh
      </button>
    </div>

    <div v-if="actionError" role="alert" class="notice" data-tone="critical">
      <CircleX class="w-5 h-5 shrink-0" />
      <span class="text-sm break-words">{{ actionError }}</span>
    </div>

    <div role="alert" class="notice" data-tone="signal">
      <ShieldCheck class="w-4 h-4 shrink-0" />
      <span class="text-xs">
        A template is the rules for one kind of certificate. The estate-wide floor in
        Policies applies on top of it and cannot be widened here — a template that could
        never clear the floor is refused when it is saved, not when somebody needs a
        certificate.
      </span>
    </div>

    <DataState
      :loading="templates.loading.value"
      :error="templates.error.value"
      :loaded="templates.loaded.value"
      @retry="refreshAll()"
    >
      <PanelBox v-if="list.length" label="Templates" :note="`${list.length} DEFINED`" flush>
        <table class="tbl">
          <thead>
            <tr>
              <th>Template</th>
              <th>Signed by</th>
              <th>Key</th>
              <th>Names</th>
              <th>Lifetime</th>
              <th>Subject</th>
              <th>Used by</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="t in list" :key="t.id">
              <tr
                :data-selected="expanded === t.id"
                class="cursor-pointer"
                :class="!t.is_enabled && 'opacity-60'"
                tabindex="0"
                role="button"
                :aria-expanded="expanded === t.id"
                :aria-label="`${t.name}, ${wouldRefuse(t).length} rules`"
                @click="toggle(t.id)"
                @keydown.enter.prevent="toggle(t.id)"
                @keydown.space.prevent="toggle(t.id)"
              >
                <td>
                  <div class="flex items-center gap-1.5">
                    <ChevronRight
                      class="w-3 h-3 shrink-0 transition-transform text-[color:var(--text-muted)]"
                      :class="expanded === t.id && 'rotate-90'"
                    />
                    <span class="font-bold">{{ t.name }}</span>
                  </div>
                  <div class="label-micro pl-[18px]">{{ t.slug }} · v{{ t.version }}</div>
                </td>
                <!-- On the row, not behind a click: a requester never chooses it. -->
                <td class="font-mono text-xs">{{ accountName(t.ca_account_id) }}</td>
                <td class="text-xs">{{ describeKey(t) }}</td>
                <td class="text-xs">{{ describeNames(t) }}</td>
                <td class="text-xs">{{ describeLifetime(t) }}</td>
                <td>
                  <span class="tag" :class="subjectDisposition(t).tone">
                    {{ subjectDisposition(t).label }}
                  </span>
                </td>
                <td class="text-xs">
                  <span v-if="grantsFor(t.id).length" class="inline-flex items-center gap-1">
                    <Users class="w-3 h-3" />{{ grantsFor(t.id).length }}
                  </span>
                  <span v-else class="text-[color:var(--text-muted)]">nobody yet</span>
                </td>
              </tr>

              <tr v-if="expanded === t.id" :key="t.id + '-detail'">
                <td colspan="7" class="p-0">
                  <div class="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div>
                      <p class="label-micro mb-2">This template would refuse</p>
                      <ul v-if="wouldRefuse(t).length" class="space-y-1">
                        <li
                          v-for="reason in wouldRefuse(t)" :key="reason"
                          class="text-xs flex items-start gap-2"
                        >
                          <CircleX class="w-3 h-3 mt-0.5 shrink-0 text-[color:var(--sev-critical)]" />
                          <span>{{ reason }}</span>
                        </li>
                      </ul>
                      <p v-else class="field-help">
                        Nothing. This template constrains no part of a request — the
                        estate-wide floor in Policies is the only thing judging it.
                      </p>
                    </div>

                    <div>
                      <p class="label-micro mb-2">Who may use it</p>
                      <ul v-if="grantsFor(t.id).length" class="space-y-1">
                        <li
                          v-for="g in grantsFor(t.id)" :key="g.id"
                          class="text-xs flex items-start gap-2"
                        >
                          <Users class="w-3 h-3 mt-0.5 shrink-0" />
                          <span>
                            <span class="font-bold">{{ g.name }}</span>
                            — {{ g.subject_kind.toLowerCase() }}, for
                            <span class="font-mono">{{ g.names.join(', ') }}</span>
                            <span v-if="g.revoked_at" class="text-[color:var(--sev-critical)]"> (revoked)</span>
                          </span>
                        </li>
                      </ul>
                      <p v-else class="field-help">
                        No grant names this template, so nothing can issue under it yet.
                        A grant says who may ask and for which names.
                      </p>

                      <p class="label-micro mt-4 mb-2">Also</p>
                      <p class="field-help">
                        <KeyRound class="w-3 h-3 inline" />
                        {{ subjectDisposition(t).hint }}
                      </p>
                      <p v-if="t.ca_profile" class="field-help">
                        Issued under the CA's own profile
                        <span class="font-mono">{{ t.ca_profile }}</span>.
                      </p>
                    </div>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </PanelBox>

      <PanelBox v-else label="Templates">
        <div class="flex items-start gap-3">
          <FileText class="w-5 h-5 shrink-0 text-[color:var(--text-muted)]" />
          <div>
            <p class="text-sm font-bold mb-1">No templates yet</p>
            <p class="field-help">
              Every CA account has a generated default that constrains nothing, so
              requests naming no template keep working. Writing one is how a kind of
              certificate gets its own rules — create it with
              <span class="font-mono">POST /api/v1/certificate-templates</span>.
            </p>
          </div>
        </div>
      </PanelBox>
    </DataState>
  </div>
</template>
