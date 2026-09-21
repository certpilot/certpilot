<script setup lang="ts">
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import PanelBox from '@/components/ui/PanelBox.vue'
import SevChip from '@/components/ui/SevChip.vue'
import {
  Cpu, Plus, CircleX, RotateCw, Server, Stamp, Trash2,
} from 'lucide-vue-next'
import { formatDateTime } from '@/lib/format'
import type { CaAccount, GatewaySummary, ListResponse } from '@/lib/types'

const api = useApi()

// The correct routes are /gateways and /ca-accounts. This view previously
// called /gateways/accounts for both read and write; neither route has ever
// existed, so both requests 404'd and the page silently showed demo rows.
const gateways = useAsyncData<ListResponse<GatewaySummary>>((s) =>
  api.get<ListResponse<GatewaySummary>>('/api/v1/gateways', s),
)
const accounts = useAsyncData<ListResponse<CaAccount>>((s) =>
  api.get<ListResponse<CaAccount>>('/api/v1/ca-accounts', s),
)

const gatewayList = computed(() => gateways.data.value?.data ?? [])
const accountList = computed(() => accounts.data.value?.data ?? [])

const loading = computed(() => gateways.loading.value || accounts.loading.value)
const loaded = computed(() => gateways.loaded.value && accounts.loaded.value)
const error = computed(() => gateways.error.value ?? accounts.error.value)

function refreshAll() {
  void gateways.refresh()
  void accounts.refresh()
}

function providerIcon(type: string) {
  switch (type) {
    case 'vault': return Server
    case 'selfsigned': return Stamp
    default: return Cpu
  }
}

/** Gateways the core is connected to, for the account form's dropdown. */
const connectedGateways = computed(() => gatewayList.value.filter((g) => g.is_connected))

// ── Add CA account ────────────────────────────────────────
const showAdd = ref(false)
const saving = ref(false)
const addError = ref<string | null>(null)
const addWarnings = ref<string[]>([])

const blankForm = () => ({
  name: '',
  provider_type: 'acme',
  gateway_addr: '',
  server_name: '',
  // Provider-specific settings, sealed by the core before storage.
  directory_url: 'letsencrypt-staging',
  email: '',
  challenge: 'dns-01',
  dns_provider: 'cloudflare',
  api_token: '',
  webhook_url: '',
  webhook_secret: '',
  validity_days: '90',
  // Vault: what config.go on the gateway actually reads. Address, mount and
  // role cover an ordinary PKI mount; the auth fields are exclusive per
  // auth_method, so only the ones for the selected method are sent.
  vault_address: '',
  vault_namespace: '',
  vault_mount: 'pki',
  vault_role: '',
  vault_auth_method: 'token',
  vault_token: '',
  vault_role_id: '',
  vault_secret_id: '',
  vault_kubernetes_role: '',
})
const form = ref(blankForm())

const isAcme = computed(() => form.value.provider_type === 'acme')
const usesDns = computed(() => isAcme.value && form.value.challenge === 'dns-01')
const isVault = computed(() => form.value.provider_type === 'vault')

/** Builds the provider-specific `config` blob the gateway will validate. */
function buildConfig(): Record<string, unknown> {
  if (isVault.value) {
    const config: Record<string, unknown> = {
      address: form.value.vault_address,
      mount: form.value.vault_mount,
      role: form.value.vault_role,
      auth_method: form.value.vault_auth_method,
    }
    if (form.value.vault_namespace) config.namespace = form.value.vault_namespace

    // Exclusive by auth_method: the gateway's Config only reads the fields
    // for the method actually selected, and sending the others is at best
    // ignored and at worst a stray credential sealed into storage for a path
    // that will never use it.
    switch (form.value.vault_auth_method) {
      case 'token':
        config.token = form.value.vault_token
        break
      case 'approle':
        config.role_id = form.value.vault_role_id
        config.secret_id = form.value.vault_secret_id
        break
      case 'kubernetes':
        config.kubernetes_role = form.value.vault_kubernetes_role
        break
    }
    return config
  }

  if (!isAcme.value) {
    return { validity_days: Number(form.value.validity_days) }
  }

  const config: Record<string, unknown> = {
    directory_url: form.value.directory_url,
    email: form.value.email,
    challenge: form.value.challenge,
  }

  if (form.value.challenge === 'dns-01') {
    config.dns_provider = form.value.dns_provider
    config.dns_config =
      form.value.dns_provider === 'cloudflare'
        ? { api_token: form.value.api_token }
        : { url: form.value.webhook_url, signing_secret: form.value.webhook_secret }
  }

  return config
}

async function addAccount() {
  saving.value = true
  addError.value = null
  addWarnings.value = []
  try {
    // The core connects to the gateway and asks it to validate this config
    // before storing anything, so a wrong token is reported here rather than
    // during an unattended renewal months from now.
    const res = await api.post<{ warnings?: string[] }>('/api/v1/ca-accounts', {
      name: form.value.name,
      provider_type: form.value.provider_type,
      gateway_addr: form.value.gateway_addr,
      server_name: form.value.server_name || undefined,
      config: buildConfig(),
    })
    addWarnings.value = res?.warnings ?? []
    if (!addWarnings.value.length) {
      showAdd.value = false
      form.value = blankForm()
    }
    refreshAll()
  } catch (err) {
    addError.value = err instanceof Error ? err.message : String(err)
  } finally {
    saving.value = false
  }
}

// ── Health probe / delete ─────────────────────────────────
const busyId = ref<string | null>(null)
const actionError = ref<string | null>(null)

async function probe(account: CaAccount) {
  busyId.value = account.id
  actionError.value = null
  try {
    await api.post(`/api/v1/ca-accounts/${account.id}/health`)
    await accounts.refresh()
  } catch (err) {
    actionError.value = `Health check for ${account.name} failed: ${
      err instanceof Error ? err.message : String(err)
    }`
  } finally {
    busyId.value = null
  }
}

async function removeAccount(account: CaAccount) {
  if (!confirm(`Remove the CA account "${account.name}"? Certificates it issued are kept.`)) return
  busyId.value = account.id
  actionError.value = null
  try {
    await api.delete(`/api/v1/ca-accounts/${account.id}`)
    await accounts.refresh()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busyId.value = null
  }
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <div class="toolbar justify-between">
      <p class="prose-ui text-[length:var(--fs-small)] text-[color:var(--text-muted)]">
        Gateway plugins and the CA accounts that issue through them
      </p>
      <div class="toolbar">
        <button class="btn-console" :disabled="loading" @click="refreshAll">
          <RotateCw class="w-3 h-3" :class="loading && 'animate-spin'" />
          Refresh
        </button>
        <button
          class="btn-console"
          data-variant="signal"
          :disabled="!connectedGateways.length"
          :title="connectedGateways.length ? '' : 'Start a gateway process first'"
          @click="showAdd = true"
        >
          <Plus class="w-3 h-3" /> Add CA account
        </button>
      </div>
    </div>

    <div v-if="actionError" role="alert" class="notice" data-tone="critical">
      <CircleX class="w-4 h-4 notice-icon" />
      <span class="break-words">{{ actionError }}</span>
    </div>

    <DataState :loading="loading" :error="error" :loaded="loaded" @retry="refreshAll">
      <div class="flex flex-col gap-3">
        <!-- Gateway processes -->
        <PanelBox
          label="Gateway plugins"
          :note="gatewayList.length ? `${connectedGateways.length}/${gatewayList.length} CONNECTED` : ''"
          :note-severity="gatewayList.length && !connectedGateways.length ? 'critical' : 'unknown'"
          flush
        >
          <div v-if="gatewayList.length" class="overflow-x-auto">
            <table class="tbl">
              <thead>
                <tr>
                  <th class="rail"></th>
                  <th>Gateway</th>
                  <th>Address</th>
                  <th>Capabilities</th>
                  <th>Link</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="gw in gatewayList" :key="gw.name">
                  <td class="rail" :class="gw.is_connected ? 'sev-bg-ok' : 'sev-bg-critical'"></td>
                  <td class="cell-primary">
                    <span class="flex items-center gap-2 min-w-0">
                      <component
                        :is="providerIcon(gw.type)"
                        class="w-3.5 h-3.5 shrink-0 text-[color:var(--text-muted)]"
                      />
                      <span class="truncate">{{ gw.name }}</span>
                    </span>
                    <span
                      v-if="gw.capabilities?.description"
                      class="field-help block mt-0.5"
                    >{{ gw.capabilities.description }}</span>
                  </td>
                  <td>{{ gw.addr }}</td>
                  <td class="!whitespace-normal">
                    <span v-if="gw.capabilities" class="flex flex-wrap gap-1">
                      <span
                        v-for="ch in gw.capabilities.supported_challenges" :key="ch"
                        class="tag"
                      >{{ ch }}</span>
                      <span
                        v-for="kt in gw.capabilities.supported_key_types" :key="kt"
                        class="tag"
                      >{{ kt }}</span>
                    </span>
                    <span v-else class="text-[color:var(--text-muted)]">—</span>
                  </td>
                  <td>
                    <SevChip
                      :severity="gw.is_connected ? 'ok' : 'critical'"
                      :label="gw.is_connected ? 'Connected' : 'Disconnected'"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!--
            Empty because no gateway process is running, which is a different
            statement from "all gateways are healthy". Says which command starts
            one rather than leaving the reader to find it.
          -->
          <div v-else class="p-3">
            <div class="empty-console">
              <strong>No gateways are connected.</strong>
              Nothing can be issued until at least one gateway process is running.
              Start one with <code>make run-gateway-acme</code>, and check it is listed
              under <code>plugins.gateways</code> in your config.
            </div>
          </div>
        </PanelBox>

        <!-- CA accounts -->
        <PanelBox
          label="CA accounts"
          :note="accountList.length ? `${accountList.length} CONFIGURED` : ''"
          flush
        >
          <div v-if="accountList.length" class="overflow-x-auto">
            <table class="tbl">
              <thead>
                <tr>
                  <th class="rail"></th>
                  <th>Name</th>
                  <th>Provider</th>
                  <th>Gateway</th>
                  <th>Status</th>
                  <th>Last checked</th>
                  <th class="num">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="acc in accountList" :key="acc.id">
                  <td
                    class="rail"
                    :class="{
                      'sev-bg-ok': acc.status === 'CONNECTED',
                      'sev-bg-critical': acc.status === 'ERROR',
                      'sev-bg-unknown': acc.status === 'DISCONNECTED',
                    }"
                  ></td>
                  <td class="cell-primary">
                    {{ acc.name }}
                    <span v-if="acc.is_default" class="tag ml-1.5">default</span>
                  </td>
                  <td>{{ acc.provider_type }}</td>
                  <td>{{ acc.gateway_addr }}</td>
                  <td>
                    <SevChip
                      :severity="
                        acc.status === 'CONNECTED' ? 'ok'
                        : acc.status === 'ERROR' ? 'critical'
                        : 'unknown'
                      "
                      :label="acc.status"
                    />
                  </td>
                  <td>{{ formatDateTime(acc.last_health_at) }}</td>
                  <td class="num">
                    <span class="inline-flex items-center gap-1 justify-end">
                      <button
                        class="btn-console !px-1.5" title="Check now"
                        :disabled="busyId === acc.id" @click="probe(acc)"
                      >
                        <span v-if="busyId === acc.id" class="spinner-console"></span>
                        <RotateCw v-else class="w-3 h-3" />
                      </button>
                      <button
                        class="btn-console !px-1.5 sev-critical" title="Remove"
                        :disabled="busyId === acc.id" @click="removeAccount(acc)"
                      >
                        <Trash2 class="w-3 h-3" />
                      </button>
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div v-else class="p-3">
            <div class="empty-console">
              <strong>No CA accounts are configured.</strong>
              This is empty because none has been added, not because issuance is
              healthy. Add an account to start issuing certificates through a gateway.
            </div>
          </div>
        </PanelBox>
      </div>
    </DataState>

    <!-- Add account dialog -->
    <div
      v-if="showAdd"
      class="dialog-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="add-account-title"
      @click.self="showAdd = false"
      @keydown.esc="showAdd = false"
    >
      <div class="dialog-panel">
        <header class="panel-head">
          <span id="add-account-title" class="label-rail">Add CA account</span>
        </header>

        <form @submit.prevent="addAccount">
          <div class="dialog-body flex flex-col gap-3">
            <p class="field-help">
              Credentials are validated by the gateway, then encrypted before storage.
              They are never returned by the API.
            </p>

            <div v-if="addError" role="alert" class="notice" data-tone="critical">
              <CircleX class="w-4 h-4 notice-icon" />
              <span class="break-words">{{ addError }}</span>
            </div>
            <div v-if="addWarnings.length" role="alert" class="notice" data-tone="warning">
              <div>
                <p class="font-semibold">Saved with warnings</p>
                <ul class="list-disc list-inside">
                  <li v-for="w in addWarnings" :key="w">{{ w }}</li>
                </ul>
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div class="field">
                <label class="label-micro" for="acc-name">Name</label>
                <input
                  id="acc-name" v-model="form.name" type="text" required
                  placeholder="letsencrypt-prod" class="input-console"
                />
              </div>
              <div class="field">
                <label class="label-micro" for="acc-type">Provider</label>
                <select id="acc-type" v-model="form.provider_type" class="select-console">
                  <option value="acme">ACME</option>
                  <option value="vault">HashiCorp Vault</option>
                  <option value="selfsigned">Self-signed (dev)</option>
                </select>
              </div>
            </div>

            <div class="field">
              <label class="label-micro" for="acc-gw">Gateway</label>
              <select id="acc-gw" v-model="form.gateway_addr" required class="select-console">
                <option value="" disabled>Select a connected gateway</option>
                <option v-for="gw in connectedGateways" :key="gw.name" :value="gw.addr">
                  {{ gw.name }} — {{ gw.addr }}
                </option>
              </select>
            </div>

            <template v-if="isAcme">
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div class="field">
                  <label class="label-micro" for="acc-dir">Directory</label>
                  <select id="acc-dir" v-model="form.directory_url" class="select-console">
                    <option value="letsencrypt-staging">Let's Encrypt staging</option>
                    <option value="letsencrypt">Let's Encrypt production</option>
                    <option value="zerossl">ZeroSSL</option>
                    <option value="buypass">BuyPass</option>
                    <option value="google">Google Trust Services</option>
                  </select>
                </div>
                <div class="field">
                  <label class="label-micro" for="acc-ch">Challenge</label>
                  <select id="acc-ch" v-model="form.challenge" class="select-console">
                    <option value="dns-01">dns-01 (needed for wildcards)</option>
                    <option value="http-01">http-01</option>
                  </select>
                </div>
              </div>

              <div class="field">
                <label class="label-micro" for="acc-email">Contact email</label>
                <input
                  id="acc-email" v-model="form.email" type="email" required
                  placeholder="pki@example.com" class="input-console"
                />
              </div>

              <template v-if="usesDns">
                <div class="field">
                  <label class="label-micro" for="acc-dns">DNS provider</label>
                  <select id="acc-dns" v-model="form.dns_provider" class="select-console">
                    <option value="cloudflare">Cloudflare</option>
                    <option value="webhook">Webhook (any other provider)</option>
                  </select>
                </div>

                <div v-if="form.dns_provider === 'cloudflare'" class="field">
                  <label class="label-micro" for="acc-token">Cloudflare API token</label>
                  <input
                    id="acc-token" v-model="form.api_token" type="password" required
                    class="input-console"
                  />
                  <span class="field-help">Needs Zone:Read and DNS:Edit.</span>
                </div>
                <template v-else>
                  <div class="field">
                    <label class="label-micro" for="acc-hook">Webhook URL</label>
                    <input
                      id="acc-hook" v-model="form.webhook_url" type="url" required
                      placeholder="https://dns-hook.internal/acme" class="input-console"
                    />
                  </div>
                  <div class="field">
                    <label class="label-micro" for="acc-secret">HMAC signing secret</label>
                    <input
                      id="acc-secret" v-model="form.webhook_secret" type="password"
                      class="input-console"
                    />
                    <span class="field-help">
                      Recommended. Without it the hook cannot tell your core from anyone else.
                    </span>
                  </div>
                </template>
              </template>
            </template>

            <template v-else-if="isVault">
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div class="field">
                  <label class="label-micro" for="acc-vault-addr">Vault address</label>
                  <input
                    id="acc-vault-addr" v-model="form.vault_address" type="url" required
                    placeholder="https://vault.internal:8200" class="input-console"
                  />
                </div>
                <div class="field">
                  <label class="label-micro" for="acc-vault-mount">PKI mount</label>
                  <input
                    id="acc-vault-mount" v-model="form.vault_mount" type="text" required
                    placeholder="pki" class="input-console"
                  />
                </div>
              </div>

              <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div class="field">
                  <label class="label-micro" for="acc-vault-role">Role</label>
                  <input
                    id="acc-vault-role" v-model="form.vault_role" type="text" required
                    class="input-console"
                  />
                </div>
                <div class="field">
                  <label class="label-micro" for="acc-vault-namespace">Namespace</label>
                  <input
                    id="acc-vault-namespace" v-model="form.vault_namespace" type="text"
                    placeholder="Vault Enterprise only" class="input-console"
                  />
                </div>
              </div>

              <div class="field">
                <label class="label-micro" for="acc-vault-auth">Auth method</label>
                <select id="acc-vault-auth" v-model="form.vault_auth_method" class="select-console">
                  <option value="token">Token</option>
                  <option value="approle">AppRole</option>
                  <option value="kubernetes">Kubernetes</option>
                </select>
              </div>

              <div v-if="form.vault_auth_method === 'token'" class="field">
                <label class="label-micro" for="acc-vault-token">Vault token</label>
                <input
                  id="acc-vault-token" v-model="form.vault_token" type="password" required
                  class="input-console"
                />
              </div>

              <div v-else-if="form.vault_auth_method === 'approle'" class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div class="field">
                  <label class="label-micro" for="acc-vault-role-id">Role ID</label>
                  <input
                    id="acc-vault-role-id" v-model="form.vault_role_id" type="text" required
                    class="input-console"
                  />
                </div>
                <div class="field">
                  <label class="label-micro" for="acc-vault-secret-id">Secret ID</label>
                  <input
                    id="acc-vault-secret-id" v-model="form.vault_secret_id" type="password" required
                    class="input-console"
                  />
                </div>
              </div>

              <div v-else class="field">
                <label class="label-micro" for="acc-vault-k8s-role">Kubernetes role</label>
                <input
                  id="acc-vault-k8s-role" v-model="form.vault_kubernetes_role" type="text" required
                  class="input-console"
                />
                <span class="field-help">
                  Uses this pod's own service account token; nothing else to enter here.
                </span>
              </div>
            </template>

            <div v-else class="field">
              <label class="label-micro" for="acc-validity">Validity (days)</label>
              <input
                id="acc-validity" v-model="form.validity_days" type="number" min="1"
                class="input-console"
              />
            </div>
          </div>

          <div class="dialog-foot">
            <button type="button" class="btn-console" @click="showAdd = false">Cancel</button>
            <button type="submit" class="btn-console" data-variant="signal" :disabled="saving">
              <span v-if="saving" class="spinner-console"></span>
              Add account
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
