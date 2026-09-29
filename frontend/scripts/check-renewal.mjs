/**
 * Checks how the certificate inventory waits for a renewal it asked for.
 *
 * Run: node scripts/check-renewal.mjs   (or `make test-frontend` from the repo root)
 *
 * Renew now is accepted with a 202 and a queued job, and the queue runs it a
 * few seconds later. The console refreshed the list the moment the job was
 * accepted, before anything had changed, so the open detail panel went on
 * showing the old serial and renewal count until somebody reloaded the page.
 * It looked as if the button had done nothing.
 */

import { waitForRenewal, rebind } from '../src/lib/renewal.ts'

let failures = 0
function check(name, actual, expected) {
  const a = JSON.stringify(actual)
  const e = JSON.stringify(expected)
  if (a === e) {
    console.log(`  ok   ${name}`)
  } else {
    failures++
    console.log(`  FAIL ${name}\n         want ${e}\n         got  ${a}`)
  }
}

// A fake queue: the job answers these statuses, one per poll.
function queue(statuses) {
  let i = 0
  const calls = { n: 0 }
  const get = async () => {
    calls.n++
    const status = statuses[Math.min(i++, statuses.length - 1)]
    return { job: { status }, summary: `job is ${status}` }
  }
  return { get, calls }
}
const now = (() => { let t = 0; return { now: () => t, sleep: async ms => { t += ms } } })

{
  const q = queue(['PENDING', 'RUNNING', 'SUCCEEDED'])
  const clock = now()
  const r = await waitForRenewal(q.get, { interval: 1000, timeout: 30000, ...clock })
  check('waits through PENDING and RUNNING to the outcome', r, { done: true, status: 'SUCCEEDED', summary: 'job is SUCCEEDED' })
  check('asks once per status', q.calls.n, 3)
}
{
  const q = queue(['PENDING', 'FAILED'])
  const r = await waitForRenewal(q.get, { interval: 1000, timeout: 30000, ...now() })
  check('a failure is an outcome, reported with its summary', r, { done: true, status: 'FAILED', summary: 'job is FAILED' })
}
{
  const q = queue(['CANCELLED'])
  const r = await waitForRenewal(q.get, { interval: 1000, timeout: 30000, ...now() })
  check('a cancelled job is an outcome', r.status, 'CANCELLED')
}
{
  // A job held back by a CA's rate limit stays PENDING. Give up waiting, say
  // so, and let the queue carry on without the page.
  const q = queue(['PENDING'])
  const r = await waitForRenewal(q.get, { interval: 1000, timeout: 5000, ...now() })
  check('stops waiting after the timeout, still queued', r, { done: false, status: 'PENDING', summary: 'job is PENDING' })
  check('and did not poll past it', q.calls.n <= 6, true)
}

// The detail panel holds its own copy of the record, so refreshing the list
// alone left it showing the old one.
{
  const oldCopy = { id: 'a', serial_number: 'old', renewal_count: 1 }
  const list = [{ id: 'b' }, { id: 'a', serial_number: 'new', renewal_count: 2 }]
  check('rebinds the open record to its refreshed copy', rebind(list, oldCopy), list[1])
  check('keeps nothing open when nothing was', rebind(list, null), null)
  check('keeps the old copy if the record left the list', rebind([{ id: 'b' }], oldCopy), oldCopy)
}

if (failures) {
  console.log(`\n${failures} failed`)
  process.exit(1)
}
console.log('\nrenewal wait: all checks passed')
