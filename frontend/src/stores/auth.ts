import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import {
  loadAuthConfig,
  beginSignIn,
  signOut as oidcSignOut,
  clearTokens,
  rememberSignIn,
  type AuthConfig,
} from '@/lib/oidc'

/** RBAC roles, matching the backend. */
export type Role = 'admin' | 'operator' | 'auditor' | 'viewer'

const WRITE_ROLES: Role[] = ['admin', 'operator']

/** What GET /api/v1/me returns. */
interface Me {
  subject: string
  email?: string
  display_name?: string
  role: Role
  auth_method: string
  user_id?: string
  role_source?: string
  /** How this person signed in: password, sso, bearer or display_token. */
  sign_in?: string
  /** The identity provider behind it; absent for a local account. */
  issuer?: string
  must_change_password?: boolean
}

export const useAuthStore = defineStore('auth', () => {
  const config = ref<AuthConfig | null>(null)
  const me = ref<Me | null>(null)

  // Least privilege until the API says otherwise. Showing an unauthenticated
  // visitor admin controls invites actions the API will reject, and mirrors the
  // backend rule that an unrecognised role falls back to viewer.
  const role = ref<Role>('viewer')
  const loading = ref(true)
  const error = ref<string | null>(null)

  const mode = computed(() => config.value?.mode ?? 'password')

  /**
   * Whether this instance expects people to sign in.
   *
   * Always true. It is kept as a name rather than deleted because it reads at
   * the call sites, and because the honest answer changed: it used to be false
   * for anonymous development, which is what hid the sign-out control and left
   * the console with no way out of a session.
   */
  const isAuthEnabled = computed(() => true)

  /** True when single sign-on is offered in addition to a password. */
  const hasSSO = computed(() => mode.value === 'oidc')
  const isAuthenticated = ref(false)

  const canWrite = computed(() => WRITE_ROLES.includes(role.value))
  const isAdmin = computed(() => role.value === 'admin')

  const displayName = computed(
    () => me.value?.display_name || me.value?.email || me.value?.subject || 'Unknown',
  )

  /**
   * Asks the API who the caller is.
   *
   * The role is read from here and never decoded out of the token. The role
   * that governs a request is the one in CertPilot's users table, so a UI that
   * trusted the token's own claim would keep offering controls for a role the
   * API had stopped honouring the moment somebody was demoted.
   */
  async function loadMe(): Promise<boolean> {
    // same-origin so the session cookie travels. It is httpOnly, so this is the
    // only way the page can find out whether it has one at all — and since the
    // core took over redeeming the authorization code, it is the only credential
    // the browser has for either kind of sign-in.
    const response = await fetch('/api/v1/me', { credentials: 'same-origin' })
    if (!response.ok) {
      me.value = null
      role.value = 'viewer'
      isAuthenticated.value = false
      return false
    }

    me.value = (await response.json()) as Me
    role.value = me.value.role
    isAuthenticated.value = true
    return true
  }

  async function init(): Promise<void> {
    loading.value = true
    error.value = null
    try {
      config.value = await loadAuthConfig()

      // Always asked, because a session cookie is httpOnly and therefore
      // invisible to this code. There is no way to know whether one exists
      // except to try, and a 401 here is an ordinary answer rather than a
      // fault.
      await loadMe()
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
      isAuthenticated.value = false
    } finally {
      loading.value = false
    }
  }

  async function signIn(returnTo?: string): Promise<void> {
    await beginSignIn(returnTo)
  }

  /**
   * Signs in with a local account.
   *
   * Returns the failure message rather than throwing, because every one of them
   * is meant to be shown to the person typing — and the API deliberately gives
   * the same message for a wrong password as for an address that does not
   * exist, so there is nothing here worth interpreting further.
   */
  async function signInWithPassword(email: string, password: string): Promise<string | null> {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ email, password }),
    })

    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      return body.error || `Sign-in failed with status ${response.status}`
    }

    me.value = (await response.json()) as Me
    role.value = me.value.role
    isAuthenticated.value = true
    rememberSignIn()
    return null
  }

  /** True when the account is using a password it did not choose. */
  const mustChangePassword = computed(() => me.value?.must_change_password === true)

  async function signOut(): Promise<void> {
    const wasFederated = me.value?.auth_method === 'bearer'

    // Ends the server-side session and clears the cookie. Done before the
    // local state is dropped so that a failure here is still visible.
    await fetch('/api/v1/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
    }).catch(() => undefined)

    me.value = null
    role.value = 'viewer'
    isAuthenticated.value = false

    // Only federated sessions go back through the provider. Ending a local
    // password session there would be a redirect to somebody else's login page
    // for no reason.
    if (wasFederated) {
      await oidcSignOut()
      return
    }
    clearTokens()
  }

  /**
   * Drops local credentials without contacting the provider.
   *
   * Used when the API rejects a token: the session is already over, and
   * redirecting through the provider's logout at that point would lose
   * whatever the operator was looking at for no benefit.
   */
  function forgetSession(): void {
    clearTokens()
    me.value = null
    role.value = 'viewer'
    isAuthenticated.value = false
  }

  return {
    config,
    me,
    role,
    loading,
    error,
    mode,
    isAuthEnabled,
    hasSSO,
    isAuthenticated,
    canWrite,
    isAdmin,
    displayName,
    mustChangePassword,
    init,
    loadMe,
    signIn,
    signInWithPassword,
    signOut,
    forgetSession,
  }
})
