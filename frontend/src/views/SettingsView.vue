<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import { describeSignIn } from '@/lib/signin'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import DataState from '@/components/common/DataState.vue'
import PanelBox from '@/components/ui/PanelBox.vue'
import NotificationChannels from '@/components/settings/NotificationChannels.vue'
import MetadataFields from '@/components/settings/MetadataFields.vue'
import UsersPanel from '@/components/settings/UsersPanel.vue'
import AuditIntegrity from '@/components/settings/AuditIntegrity.vue'
import {
  Server, Cpu, ShieldCheck, CircleCheck, CircleX, RotateCw, Palette, UserCog,
} from 'lucide-vue-next'
import { formatDateTime } from '@/lib/format'
import type { GatewaySummary, ListResponse } from '@/lib/types'

/**
 * This page reports live state only.
 *
 * It previously rendered a hardcoded table — "localhost:8443", ":50051",
 * a database region, "Connection Pool 10 / 20", and a connected
 * "Vault Provider" for a gateway that does not exist in this repository — built
 * from a non-reactive array that read a ref before it was ever populated. On a
 * settings page that is worse than showing nothing, because it invites someone
 * to trust a port number that was never real.
 */

const api = useApi()
const auth = useAuthStore()
const theme = useThemeStore()
const { role, me, isAuthEnabled } = storeToRefs(auth)
const { currentTheme } = storeToRefs(theme)

// The health endpoint is /healthz and is unversioned; this page used to call
// /api/v1/health, which has never existed.
const health = useAsyncData<{ status: string; service: string }>((s) =>
  api.get<{ status: string; service: string }>('/healthz', s),
)

const gateways = useAsyncData<ListResponse<GatewaySummary>>((s) =>
  api.get<ListResponse<GatewaySummary>>('/api/v1/gateways', s),
)

const gatewayList = computed(() => gateways.data.value?.data ?? [])
const loading = computed(() => health.loading.value || gateways.loading.value)
const loaded = computed(() => health.loaded.value && gateways.loaded.value)
const error = computed(() => health.error.value ?? gateways.error.value)

const apiReachable = computed(() => health.data.value?.status === 'ok')

function refreshAll() {
  void health.refresh()
  void gateways.refresh()
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <p class="text-sm text-[color:var(--text-muted)]">Live system state and local preferences</p>
      <button class="btn-console gap-1.5" :disabled="loading" @click="refreshAll">
        <RotateCw class="w-3.5 h-3.5" :class="loading && 'animate-spin'" />
        Refresh
      </button>
    </div>

    <DataState :loading="loading" :error="error" :loaded="loaded" @retry="refreshAll">
      <!-- Control plane -->
      <PanelBox label="Control plane">
        <template #actions><Server class="w-3.5 h-3.5 shrink-0 text-[color:var(--text-muted)]" /></template>
        <div class="flex flex-col gap-3">
          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div class="flex items-center justify-between gap-3">
              <dt class="text-[color:var(--text-muted)]">Core API</dt>
              <dd class="flex items-center gap-1.5">
                <CircleCheck v-if="apiReachable" class="w-3.5 h-3.5 sev-ok" />
                <CircleX v-else class="w-3.5 h-3.5 sev-critical" />
                {{ apiReachable ? 'Reachable' : 'Unreachable' }}
              </dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="text-[color:var(--text-muted)]">Service</dt>
              <dd class="font-mono">{{ health.data.value?.service ?? '—' }}</dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="text-[color:var(--text-muted)]">Last checked</dt>
              <dd class="font-mono">{{ formatDateTime(health.lastLoadedAt.value?.toISOString()) }}</dd>
            </div>
          </dl>
          <p class="text-[11px] opacity-50">
            Database and encryption-key state are not exposed by the API. They are reported in the
            core's startup logs.
          </p>
        </div>
      </PanelBox>

      <!-- Gateways -->
      <PanelBox label="Gateway plugins">
        <template #actions><Cpu class="w-3.5 h-3.5 shrink-0 text-[color:var(--text-muted)]" /></template>
        <div class="flex flex-col gap-3">
          <ul v-if="gatewayList.length" class="divide-y divide-[color:var(--line)] text-[length:var(--fs-small)]">
            <li
              v-for="gw in gatewayList" :key="gw.name"
              class="flex items-center justify-between gap-3 py-2 first:pt-0 last:pb-0"
            >
              <div class="min-w-0">
                <div class="font-medium truncate">{{ gw.name }}</div>
                <div class="font-mono text-[color:var(--text-muted)] truncate">{{ gw.addr }} · {{ gw.type }}</div>
              </div>
              <span
                class="tag shrink-0"
                :class="gw.is_connected ? 'sev-ok' : 'sev-critical'"
              >{{ gw.is_connected ? 'Connected' : 'Disconnected' }}</span>
            </li>
          </ul>
          <p v-else class="text-xs text-[color:var(--text-muted)]">
            No gateways connected. Configure them under
            <span class="font-mono">plugins.gateways</span> and start the processes.
          </p>
        </div>
      </PanelBox>

      <!-- Access -->
      <PanelBox label="Access">
        <template #actions><UserCog class="w-3.5 h-3.5 shrink-0 text-[color:var(--text-muted)]" /></template>
        <div class="flex flex-col gap-3">
          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div class="flex items-center justify-between gap-3">
              <dt class="text-[color:var(--text-muted)]">Authentication</dt>
              <dd>{{ describeSignIn(me) }}</dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="text-[color:var(--text-muted)]">Signed in as</dt>
              <dd class="font-mono truncate">{{ me?.email ?? '—' }}</dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="text-[color:var(--text-muted)]">Role</dt>
              <dd><span class="tag">{{ role }}</span></dd>
            </div>
          </dl>
          <div
            v-if="!isAuthEnabled" role="alert"
            class="notice py-2" data-tone="warning"
          >
            <ShieldCheck class="w-4 h-4 shrink-0" />
            <span class="text-xs">
              Anonymous access treats every request as admin. The core refuses this outside
              development mode on a loopback address.
            </span>
          </div>
        </div>
      </PanelBox>

      <!-- Alert delivery -->
      <UsersPanel v-if="auth.isAdmin" />

      <!-- Admin only, like the endpoint behind it: the people who could alter
           the audit log are the ones this answer would implicate. -->
      <AuditIntegrity v-if="auth.isAdmin" />

      <MetadataFields />

      <NotificationChannels />

      <!-- Preferences -->
      <PanelBox label="Appearance">
        <template #actions><Palette class="w-3.5 h-3.5 shrink-0 text-[color:var(--text-muted)]" /></template>
        <div class="flex flex-col gap-3">
          <div class="flex items-center justify-between gap-3">
            <span class="text-xs text-[color:var(--text-muted)]">Theme</span>
            <div class="toolbar !gap-1">
              <button
                class="btn-console"
                :class="currentTheme === 'light' ? 'btn-active' : ''"
                @click="theme.setTheme('light')"
              >Light</button>
              <button
                class="btn-console"
                :class="currentTheme === 'dark' ? 'btn-active' : ''"
                @click="theme.setTheme('dark')"
              >Dark</button>
            </div>
          </div>
          <p class="text-[11px] opacity-50">Stored in this browser only.</p>
        </div>
      </PanelBox>
    </DataState>
  </div>
</template>
