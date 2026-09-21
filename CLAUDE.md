# CertPilot — working notes

Open-source PKI and certificate lifecycle management. **The audience is a central
PKI team inside an organisation**: the group that owns the CA hierarchy and gets
paged when something expires. That audience decides most arguments in this
codebase — the UI is not a convenience layer over a CLI, it is the product
surface, because an expiring issuing CA takes down everything it ever signed and
no amount of certificate automation helps once that has happened.

This file is what a new session needs before touching anything. Depth lives in
[`docs/`](docs/README.md); it is written and current, prefer reading it over
re-deriving from source.

---

## Traps that will cost you tool calls

**The Bash working directory persists between calls.** A `cd core` in one call
is still in effect in the next one. Prefix commands with
`cd /Volumes/Mervin/certpilot` when the location matters. This has bitten
repeatedly, most memorably by making a heredoc write a file into the wrong
directory and silently succeed.

**`go build ./...` from the repo root does nothing useful.** This is a Go
workspace with two modules — `core` and `pkg`. Build and test from inside a
module, or use the Makefile, which loops over them.

**The frontend dev server is Vite on `:3000`, not 5173.** It proxies `/api` and
`/healthz` to `:8080`.

**`config.dev.yaml` is gitignored** and does not exist on a fresh clone; the core
falls back to built-in development defaults. Do not assume its contents.

**Zsh is the shell.** Unquoted globs that match nothing are a hard error, not a
literal — `grep foo *.go` fails when there are no `.go` files in the cwd.

---

## Layout

Two Go modules in a workspace (`go.work`, Go 1.26.6) plus a Vue frontend. The
host agent, the gateways and both SDKs are separate repositories, resolved as
dependencies.

| Path | What it is |
|:---|:---|
| `pkg/` | Shared, and only what is genuinely shared: `config`, `secrets` (envelope encryption), `passwords`, `revocation`, `webhooksig` |
| `core/` | The control plane. API, store, plugin manager, and the background engines |
| *(separate repositories)* | CA adapters, each its own repository, module, image and process, speaking one gRPC contract: [selfsigned](https://github.com/certpilot/certpilot-gateway-selfsigned), [acme](https://github.com/certpilot/certpilot-gateway-acme), [vault](https://github.com/certpilot/certpilot-gateway-vault) |
| *(separate repository)* | [The host agent](https://github.com/certpilot/certpilot-agent): generates keys locally, sends CSRs, installs and reloads. `scripts/agent-lifecycle.sh` is what runs a released one against this core |
| `frontend/` | Vue 3 + Vite + Tailwind 4 + Pinia |
| `migrations/` | Numbered `.sql` files, applied by `certpilot-core --migrate` |
| `docs/` | Written, current, and worth reading |

**The API reference is published as a separate site** from
[`certpilot/certpilot-docs`](https://github.com/certpilot/certpilot-docs)
(VitePress, GitHub Pages). Its endpoint tables are *generated* into
`docs/routes.json` by two passes: `scripts/extract-routes.py` reads
`core/api/router.go` for what exists and who may call it, and
`scripts/schemagen` reads the handlers for what to send and what comes back.
CI checks it for staleness — so **run `make routes` after adding a route**.
Only the second pass writes the file, so a failed run damages nothing.
`docs/api-reference.md` stays here as the deeper per-resource guide.

**That site vendors the pages in `docs/` too**, and is told to re-sync by
`.github/workflows/docs-sync.yml` whenever one changes on `main` — so a page
edited here is published within minutes rather than on the site's weekly cron.
Adding a *new* page needs one line in the site's `PAGES` list and one in its
sidebar; its sync fails loudly and names the file until both exist, which is
the fix for eleven pages that sat unpublished because nothing checked.

`core/engine/` holds the background engines: `pki` (CA health and issuer
import), `renewal`, `issuance`, `discovery`, `ctlog`, `cloudsync`, `deploy`,
`fleet`, `notifications`, `policy`, `posture`. They are started by
`core/server` and publish to an in-process broker (`core/events`) that feeds
the SSE endpoint. The directory listing is the inventory — a count written
beside it drifts on its own, and the one that used to be here had.

`core/api/` holds the handlers behind the routes in `router.go`.
`docs/routes.json` is the generated inventory of both, and `make routes`
rebuilds it — read that rather than a number written here, which is how the
ones that used to be here came to be wrong.

---

## Commands

```bash
make dev      # PostgreSQL + self-signed gateway + API + frontend, one terminal
make seed     # fill a running instance with a realistic estate; idempotent
make test     # both modules
make lint     # gofmt + go vet + staticcheck
make migrate  # apply outstanding migrations (never run automatically)
make routes   # regenerate docs/routes.json after changing the router
make help     # the rest
```

`make dev` starts the local Homebrew PostgreSQL if it is not running, creates
`certpilot_dev`, applies all migrations (there is no prelude: every migration
applies to a stock PostgreSQL server),
generates a development KEK once into `.certpilot/dev-kek` and reuses it, then
runs the gateway (`:9091`), the API (`:8080`) and the frontend (`:3000`).
Ctrl-C stops everything and stops PostgreSQL only if the script started it.

Export `CERTPILOT_DB_URL` first to use a different database; the entire
bootstrap is skipped when you do.

**The demo data is meant to stay.** Do not clear the database at the end of a
task. `make seed` is idempotent and deletes nothing, so re-run it rather than
starting from empty.

---

## Things that are true and non-obvious

**The store is plain PostgreSQL, and only that.** Every migration applies to a
stock PostgreSQL 14+ server with no extensions, no prelude and no platform
objects. Migration 001 used to reference `auth.users`, the `authenticated` role
and a `supabase_realtime` publication, which meant a fresh database could not be
built without stubbing those first; that is gone, and
`TestNoMigrationDependsOnSupabase` fails the build if any of it returns.

**The server never migrates itself.** A schema change is something an operator
runs, not a side effect of a replica restarting mid-deploy.

**Where the KEK comes from is configurable** — `secrets.kek_provider` is `env`
(default), `file`, or `vault`, in `pkg/secrets/provider.go`. Moving between them
is a configuration change, not a migration: the same key value from a different
source opens existing ciphertext. A key file writable by group or other is
refused; world-readable is only warned about, because Kubernetes mounts secret
volumes 0644. Only `env` falls back to an ephemeral key — a configured `file` or
`vault` provider that returns nothing is fatal, or a misconfiguration would hide
behind a successful start.

**Private keys and CA credentials are sealed with `CERTPILOT_KEK`** before they
reach the database (`pkg/secrets`, envelope encryption, `CPS1` magic). Losing the
KEK makes every stored secret unrecoverable. The core refuses to start against a
database without one.

**There is no anonymous mode, including locally.** `auth.allow_anonymous` is
refused by configuration validation, not ignored. On first start the core
creates the account in `auth.bootstrap_admins`, generates a password and prints
it once; `make dev` also writes it to `.certpilot/dev-admin`. The bootstrap
re-runs whenever **no active account has a password**, which is both the upgrade
path and the recovery path.

**The core redeems the OIDC authorization code, not the browser.** `POST
/auth/callback` takes the code, the PKCE verifier and the nonce; the core
exchanges them, verifies the ID token against the client id and that nonce, and
returns the same session cookie a password sign-in gets. The browser therefore
holds no access token, no refresh token and no ID token — `lib/oidc.ts` builds
an authorization URL and checks `state`, and that is all it does. The provider's
refresh token is discarded rather than stored: CertPilot's session is the
durable credential, so a federated session outlives revocation at the provider
until it expires, and suspending the account is what ends it immediately.

**Browser sessions are rows, not tokens.** An opaque value in an `HttpOnly`,
`SameSite=Strict` cookie, stored as a SHA-256 hash — so the core holds no key
that can forge one, and suspending somebody ends their session immediately.
Sign-in is throttled in the database (8 failures, 15 minutes) because there are
several replicas and no rate limiting.

**The identity provider says who you are; CertPilot says what you may do.**
Roles live in the `users` table keyed on `(issuer, subject)`, not in a token
claim — `app_metadata.certpilot_role` is ignored when a directory is wired in.
A sign-in never writes a role, so `auth.bootstrap_admins` grants a first one and
never maintains it. A subject is opaque text, **not a uuid**: Okta, Google and
Auth0 all issue non-uuid subjects, which is what migration 028 widened every
actor column for. `GET /me` is the only honest source of a role for the UI.

**Accounts are managed in Settings → Accounts** (admin only, including the
list). The last active admin cannot be demoted or suspended — the only way back
from that is SQL, which is what the screen exists to remove. Suspending revokes
every session immediately. A generated password sets `must_change_password`,
which raises a modal that cannot be dismissed.

**The audit log is chained with a key the database does not hold.** Each entry
carries a gapless `seq`, the previous entry's tag, and an HMAC-SHA256 tag over
both, keyed from a subkey of `CERTPILOT_KEK`. So a database-only attacker can
alter a row and cannot forge a tag that agrees with it. `details` is `text`, not
`jsonb`, precisely because jsonb rewrites the bytes it is given and the tag
would stop matching. Entries predating migration 031 are deliberately left
unchained, and `GET /audit/verify` counts them rather than pretending they are
covered. Writing takes a transaction-scoped advisory lock: without it two
replicas chain from the same predecessor and one entry is lost.

**Revocation tells the CA first and records only what the CA accepted.**
`POST /certificates/:id/revoke` (admin). A row can never read `REVOKED` while
the certificate still answers handshakes — the schema enforces that `status =
'REVOKED'` and `revoked_at is not null` agree. `DELETE` now refuses a live
certificate and points at revoke; `?forget=true` is the deliberate override for
a certificate you want to stop tracking while it stays live.

**The CA health sweep asks whether each CA has been revoked, and verifies the
signature.** The OCSP URL in a certificate's AIA is the *parent's* responder, so
for an intermediate the question is "has my parent revoked me" —
`pkg/revocation` builds a real request and `ocsp.ParseResponseForCert` checks the
signature, the delegation, and that the answer is about the right certificate.
A revoked CA is forced to `CRITICAL` on every sweep from the *recorded* status,
not from the check's own result: `CheckCA` recomputes status from expiry each
time, so keying off the result let a known-revoked CA return to `HEALTHY` the
moment its responder blipped. A failed check never clears a recorded revocation.

**A replayed agent request is refused, and the signature is the nonce.** Ed25519
is deterministic, so an identical request carries an identical signature; the
core stores the ones it has accepted (`agent_request_signatures`) and refuses a
repeat. No protocol change, so deployed agents are unaffected. Guarded by
default with an *exemption* list in `middleware/agent.go` — heartbeat, inventory,
installations, deployments/result — because a one-second timestamp means an
agent's own retry is byte-identical to a replay, and refusing that on a report
turns a recovered blip into a failure. Checked after the revocation check, so a
withdrawn credential is always told so.

**`key_custody` on a certificate says who holds the private key** — `CERTPILOT`,
`AGENT`, or `EXTERNAL`. Provenance (`discovered_via`) cannot answer that
question: a CSR-signed certificate is `REQUESTED` like any other and CertPilot
holds no key for it. Anything deciding whether a key can be exported must read
custody.

**`lib/severity.ts` and `core/engine/pki/ca_monitor.go` are the only places that
decide severity.** Four copies of that mapping once drifted apart across views;
two panels disagreeing about whether a CA is in trouble is a correctness bug, not
a cosmetic one.

**The core is the authority on severity, and the UI mirrors it.** Prefer the
API's `days_remaining` over recomputing from `not_after`. The exception, and it
is deliberate: a certificate's *urgency* combines its status with its own
`renewal_lead_days`, because the core leaves a certificate `ISSUED` until a
renewal sweep moves it while `/dashboard/stats` already counts it as expiring.

**Deployment order is declared on the target, carried by the job.**
`deployment_targets.deploy_order` — lower first, zero by default, which is one
wave and the behaviour that existed before. A job copies the wave at enqueue
rather than joining it at claim time, so reordering a target cannot change a
rollout already under way. A canary is a target on its own in the lowest wave:
exactly one attempt, declared rather than inferred.

Two gates, in `ClaimDeploymentJob` **and** `ClaimAgentDeploymentJobs` — an agent
target is still a target, and gating one path only would let the declared order
hold for half the estate. Within a wave a terminally failed job stops blocking
its peers; across waves it does not, because the point of "staging, then
production" is that a certificate staging refused must not reach production.
That cross-wave gate counts only the *latest* job per binding: keyed on
`status = 'FAILED'` alone it blocked production for ever after one bad
afternoon, and a terminally failed job cannot be cancelled, so there was no way
out. The way out is to fix the target and deploy again.

**Durable queues** (renewal, deployment) use a partial unique index plus
`ON CONFLICT DO NOTHING` and `FOR UPDATE SKIP LOCKED`. No leader election; any
replica can run them.

---

## House style

Prose comments that say **why**, not what. The codebase is full of comments
explaining the failure a piece of code prevents, often naming the bug that
motivated it. Match that; it is the most valuable thing in the repo.

Commit messages are long and explain the reasoning, the failure mode, and what
was verified. Look at recent history before writing one.

British spelling in prose and comments. Proper nouns keep their capitals in
error strings, which is why `ST1005` is disabled in `staticcheck.conf`.

Errors are written for the operator who will read them at 2am. Name the cause,
not just the symptom.

---

## Verification norms

**Unit tests passing is not evidence the thing works.** This project has a
history of green suites over broken behaviour:

- `sys/health` was decoded through the wrong envelope, so every real Vault
  reported "not initialized" — and the fake wrapped it the same way, so the
  tests agreed.
- `GetCAChain` had been broken against any real database since migration 006;
  the in-memory store had no such column and never noticed.
- The store conformance suite used to fabricate the platform objects migration
  001 needed, so it never noticed that the schema could not be created without
  them.

So: **run it against the real thing.** The stack starts in about ten seconds and
`make seed` gives it something to work on. For UI work, screenshot it — headless
Chrome is at `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
and screenshotting has caught real defects that reading the code did not
(uncoloured severity cells losing a CSS specificity fight, a red chip labelled
"ISSUED", sentences rendered in an uppercase tracked label style).

**Every store test runs against both implementations**, enforced by
`TestStoreTestsRunAgainstBothImplementations` in `preflight_test.go`. Building a
`MemoryStore` directly in a store test is a failure with a short allow-list —
`discovery_test.go` and `cloud_test.go` did it for a year and hid four defects,
including an adopted cloud certificate silently reverting to unmanaged on every
sync while a test called `TestImportSurvivesTheNextSync` passed.

**The four store defect classes**, all found the hard way, all worth checking
when touching the store: a Go constant a CHECK constraint refuses; a model field
a writer silently drops; empty string versus NULL; a parameter PostgreSQL types
differently than expected. See [`docs/database.md`](docs/database.md).

---

## Frontend

Vue 3, Pinia, Tailwind 4, chart.js, lucide icons. **daisyUI is gone** — the
conversion finished, the plugin and both retheme blocks were removed from
`main.css`, and the dependency was dropped. The stylesheet halved as a result
(143 kB to 65 kB). If you find a `btn`, `card`, `badge`, `modal` or `alert`
class anywhere, it is dead markup, not a component.

**The design is an operations console, not an admin template.** Three rules, all
enforced in `src/assets/styles/main.css`:

1. **Colour means severity.** Warm colour only where something needs a person; a
   cool blue (`--signal`) for what is interactive or alive. Healthy green is
   deliberately desaturated — at full saturation it is the loudest thing on a
   screen where almost everything is fine.
2. **Time is the organising dimension.** Monospace is the primary face with
   tabular numerals throughout. Type sizes come from `--fs-micro/label/small/body`;
   never hard-code a pixel size.
3. **Sharp edges, tight density.** 2px radius. Roughly thirty-five rows on a
   27-inch screen.

The hero on the dashboard is `ExpiryHorizon.vue`: one **logarithmic** time axis
from now to ten years, authorities above and certificates below. Log spacing is
the whole design — on a linear axis everything expiring inside a quarter
collapses into the first two percent of the width.

Severity utility classes are tripled (`.sev-critical.sev-critical.sev-critical`)
to win specificity fights against `.tbl tbody td` and scoped component styles.
That is deliberate; do not "simplify" it.

Sign-in is OpenID Connect, authorization code with PKCE, in `lib/oidc.ts`. The
frontend reads the issuer and client id from `/auth/config` rather than from
build-time environment variables, so one instance is described by one file.

**Every view is on the console idiom.** The six that were still daisyUI —
`PkiOverviewView`, `GatewaysView`, `DiscoveryView`, `PoliciesView`,
`SettingsView`, `DisplayView` — were converted, along with the settings
components and `ConnectionIndicator`.

The primitives that conversion needed live in `main.css` under CONSOLE
PRIMITIVES: `.select-console`, `.textarea-console`, `.check-console`,
`.toggle-console`, `.field`, `.notice` (replaces `alert`), `.tag`, `.toolbar`,
`.dialog-*` (replaces `modal`), `.tabs-console`, `.empty-console`, `.skel`,
`.spinner-console`, `.meter` and `.kv`. Three token groups back them:
`--dur-*`/`--ease-out` for motion and `--sp-*` for spacing rhythm.

**`.tag` is not `.chip`.** `.chip` carries severity and is bordered in the
severity colour; `.tag` is inert metadata — a key type, a gateway kind. They
were being used interchangeably, which is how a red-bordered chip reading
"ISSUED" reached the screen once already.

`DisplayView` is the unattended wall screen: no chrome, authenticates with a
kiosk display token, and must degrade loudly when the feed dies.

---

## Rules that look like details and are not

**A dashboard that stops updating must look broken, not healthy.** A frozen
screen showing green manufactures false confidence. `.surface-stale` drains the
colour out of the content when the SSE feed goes stale; the wall display gets a
pulsing band. Do not soften either.

**Acknowledging never hides anything.** An acknowledged CA stays exactly where it
was in the urgency order, marked. Filtering it out is how CAs expire in
organisations that believed they were monitoring them.

**An empty state must not read as a healthy one.** "No CAs are being monitored"
says explicitly that the page is empty because nothing was imported, not because
everything is fine.

**A failed fetch must never render as an empty list.** `useAsyncData` makes an
error a first-class state; `DataState` shows it even when stale data is still on
screen.

**Required metadata is enforced at issuance only**, never on an edit — otherwise
adding a required field makes the whole estate unsaveable.

---

## Known gaps

Documented, not secretly broken. Do not "discover" these as findings.

**Blocked on this machine, not on the code:** the Key Vault and F5 deployers
need a real Azure tenant and a real F5 to test against, and the Docker assets
need a container runtime.

- The audit chain has no external anchor — an attacker holding both the
  database and the KEK can rewrite it wholesale, or truncate the newest entries.
- Key Vault and F5 deployers are unit-tested only.
- The KEK is held in the core's memory. It can be loaded from a file or from
  Vault, but delegated unwrapping (transit/KMS) needs a `CPS2` envelope.
- Deployment waves are per certificate; two rollouts do not coordinate.
- Docker assets were fixed but never built — no container runtime on this machine.

---

## Secrets

`.env` is gitignored and holds `CERTPILOT_DB_URL` and `CERTPILOT_KEK`. **`make dev` does not read it** — it uses the local PostgreSQL
instead, and no Go code loads `.env`. Never print, commit, or echo its contents.

Two items the owner has deferred: the database password has not been rotated,
and `CERTPILOT_KEK` is not stored anywhere durable.
