/**
 * Checks what Settings → Access says about how somebody signed in.
 *
 * Run: node scripts/check-signin.mjs   (or `make test-frontend` from the repo root)
 *
 * It said "Identity provider" for everybody, including somebody who had just
 * typed a local password into CertPilot's own form. An administrator reads that
 * line to find out which way a person got in, so it has to come from what the
 * core reports, and say nothing it cannot back.
 */

import { describeSignIn } from '../src/lib/signin.ts'

let failures = 0
function check(name, actual, expected) {
  if (actual === expected) {
    console.log(`  ok   ${name}`)
  } else {
    failures++
    console.log(`  FAIL ${name}\n         want ${JSON.stringify(expected)}\n         got  ${JSON.stringify(actual)}`)
  }
}

check('a local password', describeSignIn({ sign_in: 'password' }), 'Password (local account)')
check('single sign-on names the provider by host',
  describeSignIn({ sign_in: 'sso', issuer: 'https://id.example.com/realms/pki' }), 'Single sign-on (id.example.com)')
check('single sign-on with an issuer that is not a URL',
  describeSignIn({ sign_in: 'sso', issuer: 'corporate-idp' }), 'Single sign-on (corporate-idp)')
check('a bearer token', describeSignIn({ sign_in: 'bearer', issuer: 'https://id.example.com' }), 'Bearer token (id.example.com)')
check('a wall display', describeSignIn({ sign_in: 'display_token' }), 'Display token')
// A core from before sign_in existed: say nothing rather than guess.
check('a core that does not report it', describeSignIn({ auth_method: 'session' }), 'Signed in')
check('nobody', describeSignIn(null), '—')

if (failures) {
  console.log(`\n${failures} failed`)
  process.exit(1)
}
console.log('\nsign-in label: all checks passed')
