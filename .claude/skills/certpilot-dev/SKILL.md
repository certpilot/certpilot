---
name: CertPilot development
description: Working procedures for the CertPilot codebase — running the stack, verifying changes against a real database and real CAs, adding a gateway or a migration, the store defect taxonomy, the frontend design system, and the live-testing recipes that catch what unit tests miss. Load when doing substantial work on this repository.
version: 1.0.0
tags: [certpilot, pki, go, vue, postgresql, vault, acme]
---

# CertPilot development

Orientation lives in [`CLAUDE.md`](../../../CLAUDE.md) and is loaded every
session. This is the deeper layer: how to actually do the work here without
rediscovering it.

Read [`docs/`](../../../docs/README.md) before source. It is written, current,
and someone verified every claim in it against the code.

---

## Screenshotting an authenticated page

`--screenshot` cannot sign in and inherits the system appearance, which is why
the light theme went unverified for so long. Drive Chrome over CDP instead —
Node 22+ has a global `WebSocket`, so nothing needs installing:

```
chrome --headless --remote-debugging-port=9222 --remote-allow-origins='*' \
       --user-data-dir=/tmp/prof about:blank &
```

Then `POST /api/v1/auth/login` with `fetch`, take the `certpilot_session` cookie
out of `Set-Cookie`, and plant it with `Network.setCookie` — it is httpOnly, so
the page cannot be made to set it. `Emulation.setEmulatedMedia` with
`prefers-color-scheme` forces either theme regardless of the system.

A working copy is in the session scratchpad as `theme-shot.mjs`.

## Running and verifying

### The loop that catches real defects

```bash
./scripts/dev.sh &          # ~10s to a listening API
./scripts/seed-demo.sh      # a realistic estate; idempotent
# ... make a change ...
curl -s localhost:8080/api/v1/certificates | python3 -m json.tool | head
```

Then stop it by signalling the **process group**, not the script — `go run`
spawns a compiled binary as a child and killing the parent orphans it:

```bash
PG=$(ps -o pgid= -p $(pgrep -f "scripts/dev.sh" | head -1) | tr -d ' ')
kill -INT -"$PG"
```

Confirm the ports actually released (`3000`, `8080`, `9091`) before starting
again; a stale listener produces confusing failures on the next run.

### Screenshotting the UI

Headless Chrome is present and catches things reading the code does not.

```bash
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless=new --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=2 --window-size=1600,900 \
  --virtual-time-budget=6000 --screenshot=out.png http://127.0.0.1:3000/
```

Then read `out.png` with the Read tool. Defects found this way that tests and
type-checking both passed over: severity colours losing a CSS specificity fight
so remaining-days cells rendered in the ordinary text colour; a chip coloured
critical but labelled `ISSUED`; multi-line sentences set in an uppercase tracked
label style; a filter `<select>` bound to an absent key rendering blank.

`--screenshot` cannot click. Over CDP it can: `Runtime.evaluate` with an
expression that finds the element and calls `.click()` opens whatever needs
opening, and nothing in the tree has to be touched.

```js
await send('Runtime.evaluate', {
  expression: `[...document.querySelectorAll('tbody tr[role=button]')]
    .find(r => r.textContent.includes('Internal mTLS'))?.click()`,
})
```

The older advice — patch the component to open the panel, screenshot, restore
from a copy saved first, grep to prove the harness is gone — still works and is
still the fallback for something genuinely unreachable. It is no longer the
first thing to try, because a temporary edit to a real component is a thing that
can be committed by accident and this is not.

The system is in dark mode and `--screenshot` inherits it, so *this* method
cannot photograph the light theme. Say so rather than implying it was checked.

The CDP method above can. `Emulation.setEmulatedMedia` with
`prefers-color-scheme` forces either theme regardless of the system, and it
works whether or not the page needs a session — so a view was shot in both
themes by pointing the same script at it twice. Reach for CDP rather than
`--screenshot` whenever the theme matters, which is any change to a surface.

### Live-testing a gateway against a real CA

Vault is installed via `brew tap hashicorp/tap` (it is no longer in
homebrew-core). `scripts/lab-vault.sh`, in the Vault gateway's repository,
builds a root, a healthy intermediate, a
deliberately-expiring one, a `no_store` role and an AppRole; `--env` prints the
variables its `live_test.go` looks for. Those tests skip unless
`CERTPILOT_TEST_VAULT_ADDR`, `_ROLE_ID` and `_SECRET_ID` are set.

Facts about Vault that cost time to learn:

- `sys/health` is **not** wrapped in the `data` envelope. Decoding it through
  the envelope yields a zero value, which reads as "not initialized" for a Vault
  that is up and answering.
- Vault **refuses** to sign past its issuer's expiry rather than truncating.
  Every renewal through that mount fails at once.
- Serials are colon-separated hex from `big.Int.Bytes()`; Go's `Text(16)` drops
  leading zeros, so pad to even length before regrouping.
- On a `no_store` role, revoking **by serial** 400s and revoking **by
  certificate** succeeds. The two are different operations with different
  requirements.

---

## The store

Two implementations — `postgres.go` and `inmemory.go` — behind one interface,
kept honest by `conformance_test.go`. Point `CERTPILOT_TEST_DB_URL` at a
throwaway server to include PostgreSQL; the harness creates and drops databases
and refuses URLs containing `supabase.co`, `rds.amazonaws.com` or `neon.tech`.

### The four defect classes

Every one of these shipped at least once. Check for all four when touching the
store.

| | Class | How it shows up |
|:---|:---|:---|
| **A** | A Go constant a CHECK constraint refuses | Raw `SQLSTATE 23514` reaching the user, e.g. `environment: "lab"` |
| **B** | A model field a writer silently drops | The value round-trips in memory and vanishes against PostgreSQL |
| **C** | Empty string versus NULL | `coalesce` on read hides a writer that stored `''` where the code expects NULL |
| **D** | A parameter PostgreSQL types differently | `$1::jsonb` versus `$1`, and `COALESCE($1::text, col)` needing the cast |

**The in-memory store enforces no constraints**, so testing against it alone
finds none of these. It is also the reason `GetCAChain` was broken against every
real database from migration 006 until someone ran it.

When adding a column, touch all four places or the value is lost: the `SELECT`
column list, the scanner, the `INSERT`, and the `UPDATE`. A `COALESCE($n::type,
col)` in the `UPDATE` is usually right for anything a partial writer might not
carry — renewal builds a record from a gateway response and would otherwise wipe
operator-owned fields on every rotation.

### Migrations

Numbered, sequential, checksummed. `Migrate` reports `Applied`, `Skipped` and
`Drifted`; a drifted file is **not** re-run — reconcile it with a new migration.

Guard everything: `create table if not exists`, `add column if not exists`, and
a `do $$ … pg_constraint … $$` block for a CHECK, since PostgreSQL has no
`add constraint if not exists`.

The store is plain PostgreSQL. A migration that needs anything a stock server
does not have does not belong in `migrations/`, and `TestNoMigrationDependsOnSupabase`
fails the build if one appears.

---

## Adding a gateway

The contract is [`provider.proto`](https://github.com/certpilot/certpilot-gateway-sdk/blob/main/proto/provider/v1/provider.proto), implemented by three
gateways already; `docs/writing-a-gateway.md` walks it end to end.

Points that matter:

- **`csr_pem` is part of the contract** and all three gateways honour it. When
  present, sign the key you were given rather than generating one.
- `GetCAInfo` feeds the CA inventory. Return the issuers behind the account and
  they become monitored, thresholded and alerted on like everything else.
- The core-to-gateway channel carries CSRs, private keys and CA credentials, so
  it is mutually authenticated by default. `make dev-certs` writes development
  material; `--insecure` is loopback-only and warns loudly.
- Each gateway is its own **repository** now, with its own module, Dockerfile
  and published image. Nothing is added to `go.work` or the `MODULES` list —
  the core depends on `certpilot-gateway-sdk` and reaches a gateway over the
  network, and `make dev` fetches the self-signed one at a pinned release.

A gateway holds **no credential of its own**. Each CA account carries the
identity it issues under, so the process is authorised to sign nothing.

---

## Certificate metadata

An admin defines the fields (`metadata_fields`), and certificates answer them in
a jsonb column with a GIN index. Four types: `TEXT`, `SELECT`, `MULTI_SELECT`,
`BOOLEAN`; a single choice draws as `DROPDOWN` or `RADIO`.

Invariants, each of which prevents a specific way of destroying data:

- **Keys and option values are immutable.** Labels are free to change; the value
  stored on a certificate never does. Otherwise a reworded option silently
  reclassifies history.
- **Fields archive, never delete.** A stored value with no definition is a value
  nothing can label.
- **A field's type is fixed after creation.** Changing it makes stored values
  unreadable rather than stale.
- **Required is enforced at issuance only.** Enforcing it on edits makes the
  whole estate unsaveable the moment somebody adds a field.
- **An unknown key is an error, not a silent drop.** A value under a misspelled
  key never appears on a form and never matches a filter.

`validateMetadata` in `core/api/metadata.go` holds all of this and has tests
covering each case.

---

## Frontend design system

`src/assets/styles/main.css` is the source of truth. Read its header comment
before changing anything visual.

### Tokens, never literals

```
--fs-micro | --fs-label | --fs-small | --fs-body   type scale
--ink-page/panel/rail/raised/hover                  surfaces
--line, --line-strong                               rules
--text-primary/secondary/muted                      text
--sev-critical/warning/ok/unknown                   severity, and only severity
--signal                                            interactive and alive
```

A hard-coded pixel size or hex colour in a component is a bug. The type scale
exists because the first cut shipped 9px labels that were unreadable on a real
screen at a normal distance.

### Components

- `ui/PanelBox.vue` — the only container. No cards, no shadows, no radius.
- `ui/SevChip.vue`, `ui/Readout.vue` — severity chip and large figure.
- `common/DataState.vue` — loading, error and first-load states. An error shows
  even when stale data is still on screen.
- `metadata/MetadataInput.vue` — all four field types in one component.
- `horizon/ExpiryHorizon.vue` — the logarithmic time axis.

### Classes with a reason

- `.field-help` for sentences, `.label-micro` for short headings. `label-micro`
  uppercases and tracks, which destroys word shape in anything with a verb.
- `.sev-*` are tripled for specificity. Leave them alone.
- `.substrate` is the faint ruled ground behind the horizon.
- `.surface-stale` and `.wall-alarm` are the degraded states. Both are meant to
  be uncomfortable.

### Converting a remaining view

Six views are still daisyUI. The pattern: keep the script logic, replace
`severityBadge`/`severityText`/`severityBorder` with `sevClass`/`sevBg`, swap
`card`/`btn`/`badge`/`table` for `PanelBox`/`.btn-console`/`SevChip`/`.tbl`, and
move explanatory text to `.field-help`. Screenshot before and after.

---

## Writing here

Comments explain **why**, and usually name the failure they prevent. This is the
strongest convention in the repo — a comment restating the code is worse than
none.

Commit messages are long. They state the problem, the reasoning, the failure
mode avoided, and what was verified live. `git log` has many examples.

When reporting work: say what was verified and how, and say plainly what was not.
"Fixed but unverified because no container runtime is available" is a better
sentence than one that implies a build happened.
