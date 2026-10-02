/**
 * What Settings → Access says about how somebody signed in.
 *
 * Read from what /api/v1/me reports rather than from how this instance is
 * configured. An instance offering single sign-on still has local accounts, and
 * the line said "Identity provider" to somebody who had just typed a password.
 */

interface SignedIn {
  sign_in?: string
  issuer?: string
}

/** The provider's host when the issuer is a URL, the issuer itself otherwise. */
function providerName(issuer: string | undefined): string {
  if (!issuer) return ''
  try {
    return new URL(issuer).host || issuer
  } catch {
    return issuer
  }
}

export function describeSignIn(me: SignedIn | null | undefined): string {
  if (!me) return '—'
  const provider = providerName(me.issuer)
  const via = (label: string) => (provider ? `${label} (${provider})` : label)
  switch (me.sign_in) {
    case 'password':
      return 'Password (local account)'
    case 'sso':
      return via('Single sign-on')
    case 'bearer':
      return via('Bearer token')
    case 'display_token':
      return 'Display token'
    default:
      // A core that predates sign_in. Saying which way would be a guess.
      return 'Signed in'
  }
}
