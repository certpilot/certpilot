<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { Bell, LogOut, Monitor, RefreshCw, SunMoon } from 'lucide-vue-next'
import { useAlertsStore } from '@/stores/alerts'
import { useAuthStore } from '@/stores/auth'
import { useCasStore } from '@/stores/cas'
import { useThemeStore } from '@/stores/theme'
import { useEventStream } from '@/composables/useEventStream'
import { describeEvent, eventSeverity } from '@/lib/events'
import { formatRelative, formatTime } from '@/lib/format'

/**
 * One rail across the top, replacing the sidebar and the toolbar.
 *
 * The old chrome spent 240px of every screen on a nav list of eight items that
 * never changes, plus a second 56px row for a page title repeating the nav item
 * already highlighted beside it. On a tool whose job is showing a fleet of
 * certificates, that is the wrong trade: the rail here is 40px total and the
 * space goes to data.
 *
 * The rail is also the status instrument. Whether the feed is alive, when it
 * last spoke, and how many authorities need a person are readable from every
 * page without going to look — which is the whole argument for a UI over a CLI
 * for this audience.
 */

const route = useRoute()
const alerts = useAlertsStore()
const auth = useAuthStore()

// Names the person and the role together. A screen showing a name but not a
// role invites somebody to attempt an action their session cannot perform and
// read the refusal as a fault.
const identityTitle = computed(() => {
  if (!auth.isAuthenticated) return 'Not signed in'
  return `${auth.displayName} · ${auth.role} · click to sign out`
})
const cas = useCasStore()
const theme = useThemeStore()
const stream = useEventStream()

const nav = [
  { label: 'Horizon', path: '/' },
  { label: 'CA Health', path: '/ca-health' },
  { label: 'Authorities', path: '/pki' },
  { label: 'Certificates', path: '/certificates' },
  { label: 'Gateways', path: '/gateways' },
  { label: 'Discovery', path: '/discovery' },
  { label: 'Policies', path: '/policies' },
  // Next to Policies on purpose: the floor and the rules above it are one
  // subject, and an operator looking at either wants the other in view.
  { label: 'Templates', path: '/templates' },
  { label: 'Settings', path: '/settings' },
]

function isActive(path: string) {
  return path === '/' ? route.path === '/' : route.path.startsWith(path)
}

const attention = computed(() => cas.needingAttention)

/**
 * The feed indicator.
 *
 * A monitoring product must never show a status light wired to a constant — the
 * previous rail had a hardcoded green "Online" badge that could not say anything
 * else, which is worse than no light at all.
 */
const feed = computed(() => {
  switch (stream.status.value) {
    case 'live':
      return { label: 'Live', severity: 'ok' as const, alive: true }
    case 'reconnecting':
      return { label: 'Reconnecting', severity: 'warning' as const, alive: false }
    case 'stale':
      return { label: 'No contact', severity: 'critical' as const, alive: false }
    default:
      return { label: 'Connecting', severity: 'unknown' as const, alive: false }
  }
})

const lastUpdate = computed(() => formatTime(cas.lastUpdatedAt))

// ── Alerts popover ───────────────────────────────────────
const alertsOpen = ref(false)
const alertsRef = ref<HTMLElement | null>(null)
const recent = computed(() => alerts.actionable.slice(0, 10))

function toggleAlerts() {
  alertsOpen.value = !alertsOpen.value
  if (alertsOpen.value) alerts.acknowledge()
}

function onDocumentClick(event: MouseEvent) {
  if (!alertsOpen.value) return
  if (alertsRef.value && !alertsRef.value.contains(event.target as Node)) {
    alertsOpen.value = false
  }
}

function onEscape(event: KeyboardEvent) {
  if (event.key === 'Escape') alertsOpen.value = false
}

onMounted(() => {
  document.addEventListener('click', onDocumentClick)
  document.addEventListener('keydown', onEscape)
})

onBeforeUnmount(() => {
  document.removeEventListener('click', onDocumentClick)
  document.removeEventListener('keydown', onEscape)
})
</script>

<template>
  <header class="rail">
    <!-- Wordmark. The bar beside it carries the worst severity in the estate,
         so the brand itself reports status — visible on every page, including
         the ones that show nothing about CAs. -->
    <div class="rail-brand">
      <span
        class="rail-brand-bar"
        :class="attention > 0 ? 'sev-bg-critical' : 'sev-bg-ok'"
        aria-hidden="true"
      />
      <span class="rail-wordmark">CertPilot</span>
    </div>

    <nav class="rail-nav">
      <router-link
        v-for="item in nav"
        :key="item.path"
        :to="item.path"
        class="rail-link"
        :data-active="isActive(item.path) || undefined"
      >
        {{ item.label }}
        <span
          v-if="item.path === '/ca-health' && attention > 0"
          class="rail-count sev-critical"
        >{{ attention }}</span>
      </router-link>
    </nav>

    <div class="rail-status">
      <!-- Data age, stated plainly. A dashboard that has stopped updating must
           never be readable as one that is up to date. -->
      <span class="rail-clock" :title="`Last update ${lastUpdate}`">{{ lastUpdate }}</span>

      <span class="rail-feed" :class="`sev-${feed.severity}`">
        <span
          class="dot"
          :class="[`sev-bg-${feed.severity}`, feed.alive && 'breathe']"
          aria-hidden="true"
        />
        {{ feed.label }}
      </span>

      <button
        class="rail-icon"
        title="Refresh now"
        :disabled="cas.loading"
        @click="cas.refresh()"
      >
        <RefreshCw class="w-3.5 h-3.5" :class="cas.loading && 'animate-spin'" />
      </button>

      <div ref="alertsRef" class="rail-alerts">
        <button class="rail-icon" title="Live alerts" @click="toggleAlerts">
          <Bell class="w-3.5 h-3.5" />
          <span
            v-if="alerts.unacknowledgedCount > 0"
            class="rail-badge"
            :class="alerts.peakSeverity === 'critical' ? 'sev-bg-critical' : 'sev-bg-warning'"
          >{{ alerts.unacknowledgedCount }}</span>
        </button>

        <div v-if="alertsOpen" class="rail-popover">
          <div class="rail-popover-head">
            <span class="label-rail">Live alerts</span>
            <button v-if="alerts.feed.length" class="btn-console" @click="alerts.clear()">
              Clear
            </button>
          </div>
          <ul v-if="recent.length" class="rail-popover-list">
            <li v-for="event in recent" :key="event.id" class="rail-alert">
              <span
                class="dot mt-1.5"
                :class="`sev-bg-${eventSeverity(event)}`"
                aria-hidden="true"
              />
              <span class="min-w-0">
                <span class="block break-words">{{ describeEvent(event) }}</span>
                <span class="label-micro">{{ formatRelative(event.timestamp) }}</span>
              </span>
            </li>
          </ul>
          <!-- "Nothing yet" is a claim about this session only, and says so. A
               feed that started when the tab opened must never be read as a
               statement that the estate is healthy. -->
          <p v-else class="rail-popover-empty prose-ui">
            Nothing has needed attention since this page was opened.
          </p>
        </div>
      </div>

      <router-link to="/display" class="rail-icon" title="Wall display">
        <Monitor class="w-3.5 h-3.5" />
      </router-link>

      <button
        class="rail-icon"
        :title="`Switch to ${theme.currentTheme === 'dark' ? 'light' : 'dark'} theme`"
        @click="theme.toggleTheme()"
      >
        <SunMoon class="w-3.5 h-3.5" />
      </button>

      <!-- Who the API thinks you are, and the role it will actually enforce.
           Shown together on purpose: a screen that displays a name but not a
           role invites somebody to attempt an action their session cannot
           perform and read the refusal as a fault. -->
      <div class="rail-identity" :title="identityTitle">
        <span class="rail-role">{{ auth.role }}</span>
        <span v-if="auth.me?.email" class="rail-who">{{ auth.me.email }}</span>
      </div>

      <!-- Labelled, not an icon alone. Signing out of a console that can export
           private keys is not a control to make somebody hunt for, and an
           unlabelled glyph in a row of unlabelled glyphs is exactly that. -->
      <button
        v-if="auth.isAuthenticated"
        class="rail-signout"
        title="Sign out"
        @click="auth.signOut()"
      >
        <LogOut class="w-3.5 h-3.5" />
        <span>Sign out</span>
      </button>
    </div>
  </header>
</template>

<style scoped>
.rail {
  display: flex;
  align-items: stretch;
  gap: 1rem;
  height: 46px;
  padding-right: 0.75rem;
  background: var(--ink-rail);
  border-bottom: 1px solid var(--line-strong);
  user-select: none;
  flex: none;
}

.rail-brand {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding-left: 0.75rem;
  flex: none;
}

.rail-brand-bar {
  width: 3px;
  height: 18px;
}

.rail-wordmark {
  font-size: var(--fs-small);
  font-weight: 600;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--text-primary);
}

.rail-nav {
  display: flex;
  align-items: stretch;
  min-width: 0;
  overflow-x: auto;
  scrollbar-width: none;
}

.rail-nav::-webkit-scrollbar {
  display: none;
}

.rail-link {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0 0.7rem;
  font-size: var(--fs-label);
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-weight: 500;
  color: var(--text-muted);
  white-space: nowrap;
  border-bottom: 2px solid transparent;
  transition: color 0.1s;
}

.rail-link:hover {
  color: var(--text-secondary);
}

/* Active is a rule under the label, not a filled pill. The rule is the console
   convention and it costs no colour, which stays reserved for severity. */
.rail-link[data-active] {
  color: var(--text-primary);
  border-bottom-color: var(--signal);
}

.rail-count {
  font-size: var(--fs-micro);
  font-weight: 700;
}

.rail-status {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-left: auto;
  flex: none;
}

.rail-clock {
  font-size: var(--fs-label);
  color: var(--text-muted);
  letter-spacing: 0.05em;
}

.rail-feed {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: var(--fs-micro);
  letter-spacing: 0.14em;
  text-transform: uppercase;
  font-weight: 600;
}

.rail-icon {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  color: var(--text-muted);
  background: none;
  border: 0;
  cursor: pointer;
  transition: color 0.1s;
}

.rail-icon:hover:not(:disabled) {
  color: var(--text-primary);
}

.rail-icon:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.rail-badge {
  position: absolute;
  top: 1px;
  right: 0;
  min-width: 12px;
  height: 12px;
  padding: 0 2px;
  font-size: var(--fs-micro);
  font-weight: 700;
  line-height: 12px;
  text-align: center;
  color: var(--ink-page);
}

.rail-alerts {
  position: relative;
}

.rail-popover {
  position: absolute;
  top: calc(100% + 6px);
  right: 0;
  z-index: 60;
  width: 22rem;
  background: var(--ink-panel);
  border: 1px solid var(--line-strong);
  padding: 0.5rem;
}

.rail-popover-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}

.rail-popover-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  max-height: 20rem;
  overflow-y: auto;
}

.rail-alert {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  font-size: var(--fs-small);
  color: var(--text-secondary);
}

.rail-popover-empty {
  padding: 0.75rem 0.25rem;
  font-size: var(--fs-small);
  color: var(--text-muted);
}

.rail-signout {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0 0.5rem;
  height: 22px;
  align-self: center;
  background: transparent;
  border: 1px solid var(--line-strong);
  border-radius: 2px;
  color: var(--text-secondary);
  font-size: var(--fs-micro);
  letter-spacing: 0.04em;
  text-transform: uppercase;
  cursor: pointer;
  white-space: nowrap;
}

.rail-signout:hover {
  background: var(--ink-hover);
  color: var(--text-primary);
  border-color: var(--text-muted);
}

.rail-identity {
  display: flex;
  flex-direction: column;
  justify-content: center;
  line-height: 1.15;
  min-width: 0;
}

.rail-who {
  font-size: var(--fs-micro);
  color: var(--text-muted);
  max-width: 14rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.rail-role {
  font-size: var(--fs-micro);
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-muted);
  padding-left: 0.25rem;
  border-left: 1px solid var(--line);
}
</style>
