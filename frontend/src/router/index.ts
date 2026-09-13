import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import DashboardView from '@/views/DashboardView.vue'
import PkiOverviewView from '@/views/PkiOverviewView.vue'
import CaHealthView from '@/views/CaHealthView.vue'
import CertificatesView from '@/views/CertificatesView.vue'
import GatewaysView from '@/views/GatewaysView.vue'
import DiscoveryView from '@/views/DiscoveryView.vue'
import PoliciesView from '@/views/PoliciesView.vue'
import TemplatesView from '@/views/TemplatesView.vue'
import SettingsView from '@/views/SettingsView.vue'
import DisplayView from '@/views/DisplayView.vue'
import LoginView from '@/views/LoginView.vue'
import AuthCallbackView from '@/views/AuthCallbackView.vue'
import { DISPLAY_TOKEN_PARAM, captureDisplayToken } from '@/lib/displayToken'
import { useAuthStore } from '@/stores/auth'
import { hasResumableSession } from '@/lib/oidc'

declare module 'vue-router' {
  interface RouteMeta {
    /** Whether to draw the sidebar and toolbar. False for wall displays. */
    chrome?: boolean
    /** Browser tab title. A PKI team runs several of these side by side. */
    title?: string
    /**
     * Reachable without a session. Only sign-in itself and the wall display,
     * which carries its own credential.
     */
    public?: boolean
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: LoginView,
    meta: { chrome: false, public: true, title: 'Sign in' },
  },
  {
    path: '/auth/callback',
    name: 'auth-callback',
    component: AuthCallbackView,
    meta: { chrome: false, public: true, title: 'Signing in' },
  },
  { path: '/', name: 'dashboard', component: DashboardView, meta: { title: 'Dashboard' } },
  {
    path: '/ca-health',
    name: 'ca-health',
    component: CaHealthView,
    meta: { title: 'CA Health' },
  },
  { path: '/pki', name: 'pki', component: PkiOverviewView, meta: { title: 'Authorities' } },
  {
    path: '/certificates',
    name: 'certificates',
    component: CertificatesView,
    meta: { title: 'Certificates' },
  },
  { path: '/gateways', name: 'gateways', component: GatewaysView, meta: { title: 'Gateways' } },
  { path: '/discovery', name: 'discovery', component: DiscoveryView, meta: { title: 'Discovery' } },
  { path: '/policies', name: 'policies', component: PoliciesView, meta: { title: 'Policies' } },
  {
    path: '/templates',
    name: 'templates',
    component: TemplatesView,
    meta: { title: 'Templates' },
  },
  { path: '/settings', name: 'settings', component: SettingsView, meta: { title: 'Settings' } },
  {
    // The unattended wall screen. No sidebar, no toolbar, nothing clickable that
    // could leave a corridor display parked on a page nobody meant it to be on.
    path: '/display',
    name: 'display',
    component: DisplayView,
    meta: { chrome: false, public: true, title: 'CA Health Wall' },
  },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
})

/**
 * The first navigation guard in this app, doing two jobs.
 *
 * **Capturing the kiosk credential.** A wall display is launched at
 * `/display?display_token=cpd_…`; the token is moved into session storage and
 * removed from the address bar. A query string is the weakest place for a
 * secret — it reaches history, `Referer` headers, and any photograph of the
 * screen — and the kiosk relaunches from its own configured URL, so removing it
 * from the visible one costs nothing. See lib/displayToken.ts.
 *
 * **Not** gating `/display` on holding a token. The core decides whether a
 * credential is valid, and a client-side check could only guess: it would block
 * a revoked token a friendlier error than the honest one the server returns.
 * The view renders the server's rejection instead.
 */
router.beforeEach(async (to) => {
  const raw = to.query[DISPLAY_TOKEN_PARAM]
  if (typeof raw === 'string' && captureDisplayToken(raw)) {
    const query = { ...to.query }
    delete query[DISPLAY_TOKEN_PARAM]
    return { path: to.path, query, hash: to.hash, replace: true }
  }

  // `/display` is public here for the same reason it always was: it carries a
  // kiosk token rather than a session, and the core is the authority on whether
  // that token is good. Sending a wall screen to a login page it can never
  // complete would replace a loud, honest server rejection with a silent one.
  if (to.meta.public) return true

  const auth = useAuthStore()

  // Resolved once per page load. The guard runs on every navigation, and
  // re-asking the API on each one would put a round trip in front of every
  // click in the application.
  if (!auth.config) await auth.init()

  // No exception for any mode. This check used to stand aside when the core
  // reported "anonymous", and that reading survived the removal of anonymous
  // access — leaving every instance open in the browser while the API refused
  // each request, so the console rendered as a wall of "this request carried no
  // credential" instead of a sign-in page.
  if (auth.isAuthenticated) return true

  // `next` is carried so that a link into a deep page survives the round trip
  // through the identity provider. Losing it is how a paged operator ends up on
  // the dashboard hunting for the CA they were sent to look at.
  //
  // "Your session ended" is only true if there was one. Saying it to somebody
  // opening CertPilot for the first time describes something that never
  // happened, and invites them to go looking for the fault.
  const query: Record<string, string> = { next: to.fullPath }
  if (hasResumableSession()) query.reason = 'expired'

  return { name: 'login', query, replace: true }
})

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} · CertPilot` : 'CertPilot'
})
