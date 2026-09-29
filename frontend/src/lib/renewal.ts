/**
 * Waiting for a renewal the console asked for.
 *
 * Renew now is accepted with a 202 and a queued job, and a queue worker runs it
 * a few seconds later. The inventory used to refresh the moment the job was
 * accepted, before anything had changed, so the open detail panel went on
 * showing the old serial and renewal count, and the button looked as if it had
 * done nothing. This waits for the job to finish, then the caller refreshes.
 */

/** The states a renewal job does not leave. */
const FINISHED = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED'])

export interface JobReading {
  job: { status: string }
  summary?: string
}

export interface WaitResult {
  /** Whether the job reached an outcome while this was waiting. */
  done: boolean
  status: string
  summary: string
}

interface WaitOptions {
  interval?: number
  timeout?: number
  now?: () => number
  sleep?: (ms: number) => Promise<void>
}

/**
 * Polls a renewal job until it finishes or the wait runs out.
 *
 * Running out is not a failure. A job held back by a CA's rate limit stays
 * queued for as long as the limit lasts; the page stops waiting and says so,
 * and the queue carries on without it.
 */
export async function waitForRenewal(
  read: () => Promise<JobReading>,
  {
    interval = 1500,
    timeout = 45_000,
    now = () => Date.now(),
    sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms)),
  }: WaitOptions = {},
): Promise<WaitResult> {
  const deadline = now() + timeout
  for (;;) {
    const { job, summary } = await read()
    const result = { status: job.status, summary: summary ?? job.status }
    if (FINISHED.has(job.status)) return { done: true, ...result }
    if (now() + interval > deadline) return { done: false, ...result }
    await sleep(interval)
  }
}

/**
 * The refreshed copy of the record a detail panel has open.
 *
 * The panel holds its own copy, so refreshing the list alone left it showing
 * the old one. If the record has left the list, the old copy is kept rather
 * than closing the panel under somebody's cursor.
 */
export function rebind<T extends { id: string }>(list: readonly T[], open: T | null): T | null {
  if (!open) return null
  return list.find((item) => item.id === open.id) ?? open
}
