# REST API reference

> **There is also a documentation site**, at
> <https://certpilot.github.io/certpilot-docs/>, built from
> [`certpilot-docs`](https://github.com/certpilot/certpilot-docs). Its endpoint
> tables are generated from `core/api/router.go` and the handlers themselves,
> via [`scripts/extract-routes.py`](../scripts/extract-routes.py) and
> [`scripts/schemagen`](../scripts/schemagen/main.go), so they cannot drift
> from the router.
>
> This file remains the deeper guide: it explains what each resource *means* —
> discovery verdicts, ARI, the deployment queue's retry curve — which the
> generated site does not yet cover. Keep both in mind when editing.

All endpoints are under `/api/v1` and speak JSON. Four routes are
unauthenticated, and each has to be:

| | |
|:---|:---|
| `GET /healthz` | A liveness probe runs before anything can sign in, and deliberately says nothing about internals |
| `GET /api/v1/auth/config` | What a browser reads to find out *how* to sign in, before it holds anything to sign in with |
| `POST /api/v1/auth/login` | Sign-in cannot require being signed in; it is rate-limited instead |
| `POST /api/v1/auth/callback` | The identity provider redirects here with an authorization code, which the core redeems |

Every other route is a 401 without a credential. If you are restricting access
at a reverse proxy, the three `auth` routes have to stay reachable or nobody
can sign in.

## Authentication

```
Authorization: Bearer <token>
```

Tokens are verified against `auth.jwks_url` (preferred) or `auth.jwt_secret`
(legacy shared secret). An invalid or expired token is always rejected — there
is no development mode in which a bad token is accepted.

There is no anonymous mode, including locally. A request with no credential is
a 401, in every build and every configuration. `auth.allow_anonymous` is still
read, and setting it now refuses to start rather than being ignored: an
operator who has it set believes their instance is open, and silently dropping
it would leave them believing that until somebody was refused.

### From the command line

The examples in these guides use a cookie jar, because a password sign-in is
the one credential every CertPilot has — a bearer token needs an identity
provider, and an evaluation running `make dev` does not have one yet.

```bash
JAR=$(mktemp)
curl -sS -c "$JAR" -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email": "you@example.com", "password": "..."}'
```

`make dev` writes the generated administrator credential to
`.certpilot/dev-admin`, and `scripts/dev-session.sh` does the above with it —
`source scripts/dev-session.sh && JAR=$(dev_session http://localhost:8080 .certpilot)`.

Every subsequent example then carries `-b "$JAR"`:

```bash
curl -sS -b "$JAR" localhost:8080/api/v1/certificates
```

Substitute `-H "Authorization: Bearer $TOKEN"` for `-b "$JAR"` anywhere, if you
have an identity provider issuing tokens. The two are interchangeable in every
example here; the session cookie is used because it needs nothing but CertPilot
itself.

`scripts/check-doc-examples.py` checks every example in `docs/` against
`docs/routes.json`: that the route exists, and that an example carries a
credential when its route requires one. `make test-docs` runs it.

### Authenticating an unattended screen

A screen in a corridor has nobody to sign in at it, and leaving an operator
session logged in there would hand it the authority to issue, revoke, and export
private keys. A display token is a separate credential for exactly that case.

```
X-Display-Token: cpd_<43 characters>
```

or, for clients that cannot set headers — `EventSource` is the one that matters
— in the query string:

```
GET /api/v1/events?display_token=cpd_...
```

Prefer the header. A query string reaches access logs, `Referer` headers, and
browser history; `RequestLogger` redacts this parameter for that reason, and
CertPilot's own frontend streams over `fetch` so that it can use the header.

A request carrying an `Authorization` header is never resolved as a display
token, whatever else it presents. That precedence is what stops a token left in
a bookmark from quietly masking an operator's identity in the audit log — and it
means an invalid bearer token fails as an invalid bearer token rather than being
rescued by a display token in the URL.

It is **not** a second way to authenticate as a user. The middleware that
resolves it enforces three things centrally, so no individual route has to
remember them:

| | |
|:---|:---|
| Role | Always `viewer`. Not configurable and not derived from any input |
| Methods | `GET` only. Any other method is 403, on every route |
| Refused paths | `/certificates/:id/private-key`, `/display-tokens`, `/dashboard/activity` — refused by path, independently of their own role gate |

An `Authorization` header takes precedence: a display token left in a bookmarked
URL cannot silently downgrade a real session or misattribute its actions.
A display token that is unknown, revoked, or expired is a 401 and does *not*
fall through to anonymous access.

Tokens expire (90 days by default, 365 maximum), are revocable, and record
`last_seen_at` / `last_seen_ip` so a credential in use somewhere unexpected is
visible. The query-string form reaches access logs by nature, which is why the
core's request logger redacts it — but it is also why this credential grants
nothing but read access.

## Authorization

Roles come from `app_metadata.certpilot_role`. `admin` passes every check.

| Role | Read | Issue / renew / revoke | Delete | Export private keys |
|:---|:---:|:---:|:---:|:---:|
| `admin` | ✅ | ✅ | ✅ | ✅ |
| `operator` | ✅ | ✅ | — | — |
| `auditor` | ✅ | — | — | — |
| `viewer` | ✅ | — | — | — |

## Secrets in responses

Two fields are never serialized on any endpoint:

- `certificates.private_key_encrypted`
- `ca_accounts.config_encrypted`

Private keys are retrievable only through the dedicated export endpoint, which
is admin-only and writes an audit record. CA credentials are not retrievable at
all — supply a replacement configuration instead.

## Errors

```json
{ "error": "human-readable description" }
```

| Code | Meaning |
|:---|:---|
| 400 | Malformed request, or a gateway rejected the configuration |
| 401 | Missing, malformed, invalid, or expired token |
| 403 | Role not permitted, or the request was blocked by a policy |
| 404 | Not found |
| 500 | Internal failure — including "the policy engine could not be consulted", which fails closed |
| 502 | The gateway is unreachable, failed, or returned something invalid |
| 503 | Gateway health check failed |

---

## Live event stream

```
GET /api/v1/events   Server-Sent Events
```

Opens with a `retry:` directive and a `snapshot` event carrying current
dashboard statistics and a CA summary per authority, so a client never renders
from an empty store. Live events follow, and a `: heartbeat` comment every 15
seconds keeps intermediaries from reaping the connection — and lets a client
tell "nothing is happening" from "I have stopped receiving", which on a wall
display is the difference that matters.

```
event: ca.expiry_alert
id: 42
data: {"id":42,"topic":"ca.expiry_alert","severity":"CRITICAL","entity_id":"...","payload":{...}}
```

Topics: `ca.health`, `ca.expiry_alert`, `cert.issued`, `cert.renewed`,
`cert.renewal_failed`, `cert.expiring`, `gateway.status`.

Reconnecting clients send `Last-Event-ID` (or `?last_event_id=`) and are
replayed from that point. When the gap is larger than the broker's history, or a
client falls behind mid-stream, the server sends `event: resync` followed by a
fresh snapshot rather than deltas onto a stale base — a dashboard that looks
live and is wrong is worse than one that admits it lost its place.

The snapshot deliberately omits `certificate_pem`: it is kilobytes per CA, it is
re-sent on every resync, and no dashboard uses it.

> Behind a reverse proxy, buffering must be off for this route or the stream
> arrives in chunks and the display looks frozen. See
> [`deploy/docker/nginx.conf`](../deploy/docker/nginx.conf).

## Dashboard

```
GET /api/v1/dashboard/stats      Summary counts for certificates and CAs
GET /api/v1/dashboard/expiring   Certificates inside the renewal lead window
GET /api/v1/dashboard/activity   Recent audit events
```

### Statistics

The five CA counts partition the estate — every authority lands in exactly one,
and they sum to `total_cas`:

| Field | |
|:---|:---|
| `healthy_cas` | |
| `warning_cas` | |
| `critical_cas` | Close to expiry. Still replaceable in an orderly way |
| `expired_cas` | Already an outage. Separate from critical because the response differs |
| `unknown_cas` | Never checked, or the certificate could not be parsed |

`unknown_cas` is reported rather than folded away: a CA nobody can assess is not
a healthy one, and hiding it is how a green dashboard covers an unmonitored CA.

### Activity

```
GET /api/v1/dashboard/activity?action=ca.expiry_alert&limit=50
```

| Parameter | |
|:---|:---|
| `action` | Repeatable, or comma-separated. Matches any of the listed actions |
| `entity_type`, `entity_id` | Narrow to one object's history |
| `since` | RFC 3339 timestamp, inclusive lower bound |
| `limit` | 1–500, default 20 |
| `offset` | |

`total` counts the filtered set, not the table, so a client paging through CA
alerts is told how many alerts exist rather than how large the audit log is.

Filtering is what makes CA alerts reachable. They share a table with every
issuance, so without it the newest twenty rows on a busy day contain no alerts
at all — they were recorded, and never seen. An unparseable `since`, `limit`, or
`offset` is a 400 rather than a silently ignored parameter: a filter that
quietly does nothing is worse than one that fails, because the caller believes
they are looking at a narrowed view.

> Refused to kiosk display tokens. Audit entries carry actor identity, and
> "alice@example.com deleted a certificate" does not belong on a corridor
> screen. Signed-in `viewer` accounts are not restricted.

## Certificates

```
GET    /api/v1/certificates                  List
POST   /api/v1/certificates                  Request and issue          (operator)
GET    /api/v1/certificates/:id              Detail
POST   /api/v1/certificates/:id/renew        Renew now                  (operator)
GET    /api/v1/certificates/:id/private-key  Export the key             (admin, audited)
POST   /api/v1/certificates/:id/revoke       Revoke at the CA           (admin, audited)
DELETE /api/v1/certificates/:id              Delete the record          (admin, audited)
```

`GET /certificates` filters on `status`, `environment`, `common_name`,
`ca_account_id`.

Despite its name, `common_name` matches **any** of a certificate's names, the
subject common name or any SAN, by substring and ignoring case. Conforming CAs
are dropping the common name (Pebble already issues without one), and a
certificate whose only name is in its SANs must still be findable by it. A
certificate matches once however many of its names do.

### Issuing

```http
POST /api/v1/certificates
```

```json
{
  "common_name": "app.example.com",
  "sans": ["www.app.example.com"],
  "ca_account_id": "uuid",
  "key_type": "ECDSA",
  "key_size": 256,
  "validity_days": 90,
  "environment": "production",
  "team": "platform",
  "auto_renew": true,
  "renewal_lead_days": 30
}
```

What happens, in order: the CA account is loaded, policy is evaluated, the
gateway is located, its stored configuration is decrypted for exactly this one
call, issuance is requested, and the returned certificate is **parsed before it
is stored**. A gateway that returns anything other than a valid X.509
certificate produces a 502 rather than a record marked `ISSUED`.

Metadata on the stored record — serial, issuer, validity dates, fingerprint,
key type and size — is read from the certificate itself, not from what the
gateway claimed.

If the gateway returns a private key, it is sealed before it touches the
database. Supplying your own CSR avoids this entirely and is the better pattern:
the key then stays wherever it was generated.

Returns `201`. When non-blocking policy violations were recorded, the body is
`{"certificate": {...}, "policy_violations": [...]}` instead of the bare record —
a policy that finds something must say so even when it does not block.

### Renewing

`POST /certificates/:id/renew` runs the same path. The key is rotated and the
new one persisted; a renewal that produced a certificate without storing its
matching key would leave a record that looks healthy and cannot terminate TLS.
That is only possible for a key CertPilot already holds: a certificate whose
`key_custody` is `AGENT` or `EXTERNAL` is refused with `400`, and renewed by
whoever holds its key (see [Asking for one](#asking-for-one)).

On failure the record is marked `RENEWAL_FAILED` with `renewal_error` set, and
the previous certificate is left intact.

### Exporting a private key

```http
GET /api/v1/certificates/:id/private-key
```

```json
{ "common_name": "app.example.com", "private_key_pem": "-----BEGIN..." }
```

Admin only. Writes `cert.private_key_exported` to the audit log with the actor
and client IP. Returns 404 when no key is stored — which is the normal case for
imported, discovered, or CSR-based certificates.

### Revoking

```http
POST /api/v1/certificates/:id/revoke
```

```json
{ "reason": 1 }
```

Admin only. **The CA is told first, and the record is updated only if the CA
agreed.** The ordering is the guarantee: a record reading `REVOKED` beside a
certificate that still answers handshakes is worse than either alternative, so
every failure on this path leaves the record untouched and says so.

`reason` is required. Accepted codes are `0` unspecified, `1` keyCompromise,
`3` affiliationChanged, `4` superseded, `5` cessationOfOperation, `9`
privilegeWithdrawn — the subset of RFC 5280 a CA will act on. Anything else is
a 400 listing them, so a caller does not have to go and read the RFC.

| Status | When |
|:---|:---|
| `200` | Revoked at the CA and recorded |
| `400` | Missing or unaccepted reason; no stored copy of the certificate; or no CA account to send it to |
| `404` | No such certificate |
| `409` | Already revoked — the CA is not asked again |
| `502` | Gateway not connected, or the CA declined. Nothing has been changed |
| `500` | The CA revoked it and the record could not be written. The certificate is dead and the record is wrong until the write succeeds |

Writes `certificate.revoked` to the audit log with the actor, reason code and
fingerprint, and publishes `cert.revoked` on the event stream so a wall display
reflects it without waiting for a sweep.

`DELETE /certificates/:id` is not a substitute: it removes the record and the
certificate stays valid at the CA. It refuses a live certificate with a 409 that
names this endpoint; `?forget=true` overrides that deliberately.

## PKI and CA authorities

```
GET    /api/v1/pki/authorities            List monitored CAs
POST   /api/v1/pki/authorities            Register a CA               (operator)
POST   /api/v1/pki/authorities/import     Import CAs from gateways    (operator)
GET    /api/v1/pki/authorities/:id        Detail
GET    /api/v1/pki/authorities/:id/chain  Trust chain to the root
POST   /api/v1/pki/authorities/:id/check  Health, CRL, and OCSP check (operator)
DELETE /api/v1/pki/authorities/:id        Remove                      (admin)
GET    /api/v1/pki/tree                   Hierarchy for visualization
```

### Importing the CAs behind a CA account

```http
POST /api/v1/pki/authorities/import
POST /api/v1/pki/authorities/import?account=vault-issuing
```

Asks every connected gateway that reports `supports_ca_info` for its issuers and
records them. This runs on its own timer and when a CA account is created; the
endpoint is for the moment after somebody has rotated an issuer and wants to see
it land rather than wait.

```json
{
  "summary": {"added": 2, "refreshed": 0},
  "data": [{
    "account": "vault-issuing",
    "outcomes": [
      {"name": "pki-int/Corp Root CA", "action": "added", "days_remaining": 3649},
      {"name": "pki-int/Corp Issuing CA", "action": "added", "days_remaining": 1824}
    ]
  }]
}
```

An imported CA carries `source: "GATEWAY"` and `last_seen_at`. A sweep refreshes
what the certificate says and never overwrites the name, alert thresholds,
owning team, tags or notes — those are what an operator decided. A CA that stops
being offered is not deleted: it signed certificates that are still being
served, so `last_seen_at` goes stale instead.

Entries a gateway names without sending a certificate are skipped with a reason.
There is no expiry to monitor and nothing to identify them by, and the ACME
gateway returns exactly this — ACME publishes no endpoint listing issuers.

`GET /pki/authorities` filters and sorts:

| Parameter | |
|:---|:---|
| `status` | `HEALTHY`, `WARNING`, `CRITICAL`, `EXPIRED`, `UNKNOWN` |
| `expiring_within_days` | Keeps CAs expiring inside the window |
| `sort` | `urgency` (soonest expiry first) or `name` (default) |

`urgency` is the order the CA health view is built on: the question a team
watching a wall display is asking is which authority fails first, and an
alphabetical list answers a different one.

The expiry window is evaluated against `not_after`, not the stored
`days_remaining`. That column is a snapshot written by the health sweep and is
stale by however long it has been since the last one — a CA whose sweep has not
run since registration would otherwise report itself comfortable while expiring
next week.

The list omits `certificate_pem`; the detail endpoint still returns it. It is
kilobytes per CA, no client renders it, and the list is re-read on every
dashboard refresh.

> The CRL freshness check is real. The OCSP check currently issues a plain GET
> rather than an RFC 6960 request and reports a responder as healthy when it
> should not — see the README's known gaps.

### The hierarchy

`GET /pki/tree` returns roots with their children attached recursively. Each
node carries the authority, its `children`, and its `depth` — issuing steps from
the root of its own chain, so a root is `0`.

```json
{
  "authority": { "id": "...", "name": "Corporate Root", "...": "..." },
  "depth": 0,
  "children": [
    { "authority": { "name": "Corporate Intermediate" }, "depth": 1, "children": [] }
  ]
}
```

Three guarantees, because the interesting cases here are malformed hierarchies
rather than well-formed ones:

- **Every registered CA appears exactly once**, including ones whose parentage is
  wrong. A CA missing from a monitoring view is the one nobody notices expiring.
- **The response is always acyclic and always serialisable.** A CA naming itself,
  or a ring of CAs naming each other, is broken out to the top level rather than
  reproduced as a loop.
- **The order is stable.** Siblings sort by name, then id, so the tree does not
  reshuffle itself between identical requests.

A CA that could not be placed under a real root is returned at the top level with
`"detached": true` and a `detached_reason` naming the problem:

| Reason | Meaning |
|:---|:---|
| `its issuing CA is not registered in CertPilot` | Ordinary — a root held offline, or an intermediate imported on its own |
| `this CA is recorded as its own issuer` | Bad data. `parent_ca_id` points at the CA itself |
| `its issuer chain forms a loop, so it has no root` | Bad data. Two or more CAs name each other |

The last two are also logged at `WARN` by the core, since they mean the recorded
hierarchy is wrong rather than merely incomplete.

## CA accounts and gateways

```
GET    /api/v1/ca-accounts             List
POST   /api/v1/ca-accounts             Register                (operator)
POST   /api/v1/ca-accounts/:id/health  Probe the gateway       (operator)
DELETE /api/v1/ca-accounts/:id         Remove                  (admin)
GET    /api/v1/gateways                Connected gateways and capabilities
```

### Registering

```json
{
  "name": "letsencrypt-prod",
  "provider_type": "acme",
  "gateway_addr": "acme-gateway:9092",
  "server_name": "acme-gateway",
  "config": {
    "directory_url": "letsencrypt",
    "email": "ops@example.com",
    "challenge": "dns-01",
    "dns_provider": "cloudflare",
    "dns_config": {"api_token": "..."}
  },
  "is_default": false
}
```

The core connects over mTLS, calls the gateway's `ValidateConfig`, and stores
nothing if the gateway rejects it — a 400 comes back listing what is wrong.
Warnings do not block and are returned alongside the created account.

`config` is sealed with AES-256-GCM before storage and decrypted only to
populate a single outbound gRPC call. It is not readable back through the API.

`server_name` overrides the name expected in the gateway's TLS certificate;
omit it to derive from the host part of `gateway_addr`.

## Discovery

```
POST   /api/v1/discovery/scan                Scan endpoints and judge what they serve  (operator)
POST   /api/v1/discovery/import              Adopt a finding into inventory            (operator)
POST   /api/v1/discovery/scans/:id/cancel    Stop a running scan                       (operator)
GET    /api/v1/discovery/scans               Scan history
GET    /api/v1/discovery/scans/:id           One run and its results
GET    /api/v1/discovery/results             Current findings, one row per endpoint
GET    /api/v1/discovery/schedules           Scheduled scans
POST   /api/v1/discovery/schedules           Create one                                (operator)
PUT    /api/v1/discovery/schedules/:id       Edit one                                  (operator)
DELETE /api/v1/discovery/schedules/:id       Remove one                                (admin)
POST   /api/v1/discovery/schedules/:id/run   Run it now, without moving its schedule   (operator)
```

Scanning is operator-gated because it opens connections to third-party
infrastructure from CertPilot's address. Every run is recorded in the audit log
with the targets it was given, so "who asked us to connect to that" is
answerable afterwards. One request is capped at 256 targets.

```json
POST /api/v1/discovery/scan
{ "targets": ["example.com", "10.0.0.0/24", "10.0.0.4-40:8443"], "ports": [443, 8443] }
```

Each entry may be a host, `host:port`, a CIDR network, or an inclusive address
range — `10.0.0.4-10.0.0.40` or the abbreviated `10.0.0.4-40`. A network or
range may name its own port. `ports` applies to everything that does not, and
multiplies the endpoint count. `host: "…"` is accepted as the single-target form.

Everything is expanded and checked before anything is connected to: a malformed
entry fails the whole request rather than leaving you unsure which part of your
list was reached. Network and broadcast addresses are skipped for IPv4 prefixes
wider than /31, so `10.0.0.0/24` is 254 endpoints and not 256.

Two limits apply. A request carries at most **256 entries**, and those may
expand to at most **4096 endpoints**. The second is the one that matters: a
misplaced digit turns `10.0.0.0/24` into `10.0.0.0/8`, and the refusal names the
size so the typo is visible rather than merely denied.

```
10.0.0.0/8 covers 16777216 addresses, past the 4096-endpoint limit for one
scan; narrow it
```

### Small scans wait, wide scans do not

At **32 endpoints or fewer** the scan runs while you wait and returns `200` with
its results. Above that it goes to the background and returns `202` with a poll
URL. The response says which happened without you having to read the status
code — `scan.status` is `COMPLETED` or `RUNNING`:

```json
{
  "scan": { "id": "…", "status": "RUNNING", "target_count": 254, "results_count": 0 },
  "poll": "/api/v1/discovery/scans/<id>",
  "summary": "Scanning 254 endpoints in the background. Results appear as they are found."
}
```

Results are written as they are found, not at the end, so polling shows real
progress and a run that is interrupted keeps what it reached. Progress is also
published to the event stream as `discovery.progress` — **stream only**: it is
never delivered to a notification channel, because a range scan would otherwise
put a message in Slack every few seconds for minutes, and a team that mutes that
channel has also muted CA expiry.

```
POST /api/v1/discovery/scans/:id/cancel
```

Cancelling keeps everything already found and records the run as `CANCELLED`,
not `FAILED` — the history has to distinguish "somebody stopped it" from
"something went wrong". Endpoints abandoned mid-probe are **not** recorded as
unreachable: they were never really asked, and a row saying otherwise would be a
finding about the estate invented by stopping the scan. Cancelling a run that
has already finished is not an error; the response names its actual status.

The scan record keeps the targets **as they were typed** — `10.0.0.0/24`, not
254 addresses — with `target_count` carrying how far that expanded. A scan is
repeated by re-running what was asked for and found again by the range someone
remembers typing.

The response carries the run, the results, and a sentence:

```json
{
  "scan": { "results_count": 7, "unmanaged_count": 6, "managed_count": 0, "unreachable_count": 1 },
  "data": [ … ],
  "summary": "6 certificate(s) are being served that CertPilot does not manage. Nothing renews them."
}
```

The `summary` exists because the counts alone are ambiguous in the one direction
that matters: an estate where nothing answered and an estate where everything is
managed both produce zero unmanaged results.

### The verdicts

Each result carries two, and they answer different questions.

`management_state` — **`MANAGED`** when the served certificate's SHA-256
fingerprint matches a row in `certificates`, **`UNMANAGED`** when it does not,
**`UNREACHABLE`** when no handshake completed. Matched on fingerprint, not on
name: two certificates for the same hostname are two different certificates, and
the one being served is the one that expires. An inventory lookup that fails
reports `UNMANAGED`, with a finding saying so — calling something managed that
could not be checked is how a lookup error becomes an outage.

`trust_state` — **`PUBLIC`**, **`INTERNAL`** (chains to a CA registered in
CertPilot), **`SELF_SIGNED`**, **`UNTRUSTED`** (neither), or **`UNKNOWN`**.
Internal trust is decided on signatures rather than by path building, so an
expired certificate still reports the CA that issued it instead of reading as a
rogue issuer.

### Findings

`findings` is an array of `{code, severity, detail}`. Codes are stable:
`expired`, `not_yet_valid`, `expiring_soon`, `hostname_mismatch`, `self_signed`,
`untrusted_issuer`, `incomplete_chain`, `weak_key`, `weak_signature`,
`legacy_tls`, `weak_cipher`, `no_forward_secrecy`, `long_validity`,
`internal_issuer`, `inventory_lookup_failed`.

`weak_signature` covers the whole served chain, not just the leaf: a SHA-1
intermediate breaks a connection as completely as a SHA-1 leaf, and is the more
common of the two. Self-signed certificates are skipped, since a root's own
signature is never verified by anything.

A classical key exchange is deliberately **not** a finding. It is true of nearly
every endpoint alive, and a finding on every row is not a finding. The
negotiated group is recorded verbatim in `key_exchange` instead — that column is
what a posture report reads.

### Import

```json
POST /api/v1/discovery/import
{ "result_id": "…", "team": "Platform", "environment": "production" }
```

`certificate_pem` is accepted instead, for a certificate someone has in hand.

**`auto_renew` is always false on import, whatever was requested.** CertPilot
holds no private key for something it merely observed, so a record claiming it
will renew itself is a promise the system cannot keep — and the moment you find
out is expiry. The response says so in words. Importing the same certificate
twice converges on one record and returns 200 rather than a conflict.

Publishes `discovery.unmanaged` (WARNING) when a run finds anything unmanaged,
so the finding reaches the channels a team already configured instead of waiting
to be noticed on a page nobody has open.

### Scheduled scans

```json
POST /api/v1/discovery/schedules
{ "name": "nightly perimeter", "targets": ["10.0.0.0/24"], "interval_minutes": 1440 }
```

An interval, not a cron expression. A cron field is a small language whose
mistakes are silent, and a schedule meant to run nightly that instead runs
yearly looks identical on screen to one that works. The floor is 15 minutes;
below that a scan of the same range is indistinguishable from a denial of
service aimed at your own estate.

Targets are expanded and validated **when the schedule is saved**, not when it
first fires — including a check that the run can finish before the next one
starts. A schedule that looks configured and silently never scans is worse than
no schedule, and 3am on the night it mattered is the wrong time to find out its
targets do not parse.

A new schedule runs within the minute, so you can see it work rather than find
out tomorrow. `last_run_at`, `next_run_at`, `last_scan_id`, and `last_error` are
on every schedule: one that fails every night and is never read is the
appearance of coverage. `POST …/run` starts it immediately **without** moving
its schedule — testing what you just wrote should not silently push tonight's
run to tomorrow.

> Two replicas both run every schedule. Leader election over Postgres advisory
> locks arrives with the renewal engine in phase 4, which has the same gap.

### What a repeated scan adds

The second run of a scan is not worth much as a list. It is worth what it says
has **changed**, and three findings exist only on a re-scan:

| Code | |
|:---|:---|
| `certificate_changed` | The endpoint is serving a different certificate. **WARNING** when CertPilot manages neither the old nor the new one — something out there is renewing certificates without going through this system, so somebody knows how to replace it. **INFO** when the new one is managed, because that is a renewal it performed |
| `endpoint_disappeared` | It answered last time and does not now: either it moved and the scan no longer covers it, or it is down |
| `endpoint_appeared` | It did not answer last time and does now |

A first scan reports none of these. Every endpoint is new the first time, and a
run whose findings are all "this is new" is one nobody reads twice.

Changes publish `discovery.changed` (WARNING), separate from
`discovery.unmanaged`: "there is an endpoint you do not manage" may have been
true for years, while "the certificate on it changed last night" is a fact about
somebody actively operating it.

### One row per endpoint

`GET /discovery/results` returns the **latest observation of each endpoint** by
default. A nightly schedule records the same unmanaged certificate every night,
and counting each of those as a separate finding turns one problem into thirty
until the number stops meaning anything.

The collapse happens *before* the filters, which is the part that is easy to get
backwards: filtering first would answer "the most recent time this endpoint was
unmanaged" and keep asking for work that has already been done. Pass
`latest=false` for the full history, which is what an investigation wants.

## Certificate Transparency

```
GET    /api/v1/ct/monitors             Watched domains
POST   /api/v1/ct/monitors             Watch one                    (operator)
PUT    /api/v1/ct/monitors/:id         Edit one                     (operator)
DELETE /api/v1/ct/monitors/:id         Stop watching                (admin)
POST   /api/v1/ct/monitors/:id/check   Check now                    (operator)
GET    /api/v1/ct/certificates         What the logs have reported
```

This is the half of discovery a network scan cannot reach. A scan answers "what
is being served on the addresses I told you about". CT answers **what has been
issued in your name at all** — by any CA, to anyone, whether or not it was ever
deployed and whether or not the machine is reachable from CertPilot. A developer
who obtained a certificate for `api.corp.example.com` with a personal ACME
account appears in no scan of any range, and appears in CT within minutes,
because every publicly-trusted CA is required to log there.

```json
POST /api/v1/ct/monitors
{ "domain": "example.com", "include_subdomains": true, "check_interval_minutes": 360 }
```

Give the domain itself — `*.example.com` is refused, because subdomains are what
`include_subdomains` is for. The floor on the interval is **60 minutes**, higher
than a scan's, for a different reason: the logs are read through a free
community service, and polling it harder is how an organisation loses access to
it and then finds out nothing at all.

### Checked, versus answered

Every monitor carries **both** `last_checked_at` and `last_success_at`, and the
list surfaces `stale_domains` derived from them.

Collapsing those into one field is the failure this whole product exists to
prevent, in miniature: a monitor that has been unable to reach the log for a
week would look exactly like a monitor that has found nothing for a week, and
one of those means nobody is being told about certificates issued in their name.
For the same reason `POST …/check` answers **502** when the index is
unreachable, with its own words and the sentence *"The check did not complete,
so nothing was learned about this domain. It is not the same as finding no
certificates."*

### One certificate, two log entries

A precertificate and its final certificate are logged separately and share a
serial number. The index publishes no field saying which is which, so the
earlier entry for a serial is labelled `is_precertificate` — precertificates are
always logged first. Both rows are kept, because "this was pre-logged then
issued" is real information, but `GET /ct/certificates` hides the pre-issuance
row by default and the counts are per certificate.

This is not cosmetic. Before it existed, a live check of `badssl.com` reported
**18** certificates where there are **9**, and a headline number wrong by a
factor of two is one people act on. Pass `include_precertificates=true` for the
raw log entries.

### Matching your own certificates

Findings are matched to inventory on **serial number**, since the log index does
not publish a SHA-256 fingerprint. The two sides format serials differently —
CertPilot stores unpadded lowercase hex, indexes pad and upper-case them — so
both are normalised before comparison. Getting that wrong would report this
system's own certificates as ones nobody manages, and a findings list full of
your own certificates is one nobody reads.

An unmanaged finding publishes `ct.unmanaged` (WARNING), and only for
certificates that are **new to that monitor**. Check windows overlap by design,
and an alert repeating the same certificate every six hours is how a channel
gets muted — taking the CA expiry alerts sharing it along with it.

> Cloud inventory (ACM, Azure Key Vault, GCP, Kubernetes secrets) is not
> implemented yet.

## Cloud inventory

```
GET    /api/v1/cloud/connections             Configured accounts
POST   /api/v1/cloud/connections             Add one                      (operator)
PUT    /api/v1/cloud/connections/:id         Edit one                     (operator)
DELETE /api/v1/cloud/connections/:id         Remove one                   (admin)
POST   /api/v1/cloud/connections/:id/sync    Sync now                     (operator)
GET    /api/v1/cloud/certificates            What the accounts hold
POST   /api/v1/cloud/import                  Adopt one into inventory     (operator)
```

The third place certificates hide. A scan finds what is **served**; Certificate
Transparency finds what a public CA **issued**; neither finds what is merely
**stored** — in ACM, in a Key Vault, in a Google load balancer, in a Kubernetes
secret, attached to an address nobody scanned or attached to nothing at all.

### What each provider needs

```json
POST /api/v1/cloud/connections
{ "name": "prod-eu", "provider": "aws_acm", "sync_interval_minutes": 360,
  "config": { "region": "eu-west-1",
              "role_arn": "arn:aws:iam::1234:role/certpilot-read",
              "web_identity_token_file": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" } }
```

| `provider` | `config` | Credentials |
|:---|:---|:---|
| `aws_acm` | `region` | `access_key_id` + `secret_access_key` (+ `session_token`), or `role_arn` + `web_identity_token_file` |
| `azure_key_vault` | `vault_url` | `tenant_id` + `client_id` + `client_secret`, or `managed_identity: true` |
| `gcp` | `project_id` | `service_account_json`, or `use_metadata_server: true` |
| `kubernetes` | `api_url`, optional `namespaces`, `ca_cert` | `token`, or `in_cluster: true` |

Read-only permissions are enough everywhere, and the narrower the better —
`acm:ListCertificates` and `acm:GetCertificate`; `certificates/get` and
`certificates/list` on the vault; `compute.sslCertificates.list`; `get` and
`list` on secrets and ingresses.

`config` is validated **before** it is sealed, so a missing region or a
malformed service account key is a 400 while somebody is typing it, rather than
a sync failure six hours later that reads on a dashboard like the account
refusing the connection. It is then encrypted with the keyring under its own
context string. No endpoint returns it, the listing does not carry the sealed
blob either, and the audit entry records the act rather than the credential.

The floor on `sync_interval_minutes` is **30**. Lower than Certificate
Transparency's, because these are your own accounts rather than somebody's free
service — but not trivial, because every sync is a burst of API calls against a
quota your deployments share.

### The finding this exists for

Not "here is another certificate". This:

| Provider | Renews | Does not renew, and looks identical |
|:---|:---|:---|
| AWS ACM | Amazon-issued and still validating | anything **imported** — `RenewalEligibility: INELIGIBLE` |
| Azure Key Vault | a policy with an `AutoRenew` action | policy issuer `Unknown` — uploaded as a PFX, no issuer to go back to |
| Google Cloud | `MANAGED` | `SELF_MANAGED` |
| Kubernetes | secrets cert-manager annotates | every other `kubernetes.io/tls` secret |

Findings carry the provider's own word for it, because that word is what
somebody has to go and find in their console:

```json
{ "code": "will_not_renew", "severity": "CRITICAL",
  "detail": "Nothing renews this certificate: AWS Certificate Manager reports it as \"IMPORTED\". It expires in 2 weeks, and it will simply stop working then unless somebody replaces it by hand." }
```

Severity tracks **time, not category** — `INFO` beyond 90 days, `WARNING` inside
it, `CRITICAL` inside 30 — because a finding that appears on every row is the
noise that stops people reading the list. `will_not_renew` is raised alongside
`expired` rather than instead of it: an expired certificate cert-manager is
about to replace and an expired certificate nobody will ever replace need
opposite responses.

The inverse is the sharpest finding here. `renewal_overdue` fires when a
provider says it renews a certificate and has not, within a week of expiry —
automatic renewal has failed, and nothing else in the system would have said so.

Filter on any of them:

```
GET /api/v1/cloud/certificates?finding=will_not_renew
GET /api/v1/cloud/certificates?management_state=UNMANAGED&unimported=true
```

### Scopes, or what was not looked at

Every successful sync records what it enumerated, in the provider's own words,
and the sync response returns it:

```json
"scopes": [
  "AWS Certificate Manager in eu-west-1 only — certificates in other regions are not visible to this connection",
  "each certificate's PEM body, to match it against inventory by fingerprint"
]
```

ACM is regional. GCP Certificate Manager is **not** covered — the GCP connection
reads `compute.sslCertificates`, and says so. A tool that covers one corner of a
provider while presenting itself as covering the provider produces a short list
that reads as a small estate when it is really a narrow search.

### Synced, versus answered

As with Certificate Transparency, `last_synced_at` and `last_success_at` are
separate columns and the listing surfaces `stale_connections`. A connection
whose credentials lapsed three days ago still attempts every hour, so its "last
synced" is a minute old and means nothing.

`POST …/sync` answers **502** when the provider does not, carrying the
provider's own words and the sentence *"The sync did not complete, so nothing
was learned about this account. It is not the same as finding no
certificates."* It is bounded at 25 seconds, under the server's write timeout,
so the response is never truncated into an empty body that reads as success.

A failed sync also never concludes that the estate was dismantled: certificates
are only marked as gone after a sync that answered, and an answer containing
nothing at all is treated as suspect rather than as an empty account.

### Attachment is three-valued

`attached` is `true`, `false`, or **absent**. Absent means the provider could
not be asked — a Key Vault has no notion of what is serving its certificates,
and a Kubernetes connection without read access to ingresses cannot tell either.
Reporting "nothing is using this" in those cases would be inventing a finding.
`false` is a real one: nobody will notice it expire, and it is still there to be
attached to something during an incident.

### Certificates that disappear

A certificate a successful sync no longer finds is marked `removed_at` and drops
out of the default listing. The row is kept — that a certificate vanished from a
production account is information, and deleting it takes its own history along
with it. `?include_removed=true` brings them back.

### Import

```json
POST /api/v1/cloud/import
{ "cloud_certificate_id": "…", "team": "Payments", "environment": "production" }
```

The certificate becomes a watched inventory record with
`discovered_via: "CLOUD"` and `auto_renew: false` — always false, whatever was
asked for. CertPilot holds no private key for something it read out of somebody
else's store. The response says so, and adds the reason it was found in the
first place: *"Note that the provider does not renew it either."*

## Renewal queue

```
GET    /api/v1/renewals                     What is queued, most urgent first
GET    /api/v1/renewals/:id                 One job, with every attempt
DELETE /api/v1/renewals/:id                 Cancel it                       (admin)
POST   /api/v1/certificates/:id/renew       Queue a renewal                 (operator)
```

Renewal is the only part of this system that changes the world. Everything else
observes. So it is not a call the scheduler makes — it is a durable row that
somebody owns, and a process that dies mid-renewal leaves behind something
another process can pick up.

### Asking for one

```json
POST /api/v1/certificates/{id}/renew
→ 202 Accepted
{ "data": { "id": "…", "status": "PENDING", "reason": "MANUAL", "attempts": 0 },
  "message": "Queued. Watch it at GET /api/v1/renewals/…" }
```

**202, not 200.** This endpoint used to call the gateway inline and return the
renewed certificate, which read well and was wrong in three ways: an ACME order
with a DNS challenge outlives the server's 30-second write timeout, so the
caller got a truncated response for a renewal that was still running; a failure
meant one attempt and no record of it; and a core that restarted mid-request
left nothing behind at all.

Pressing it twice returns **the same job**:

```json
{ "data": { "id": "…same id…" },
  "message": "A renewal for this certificate is already queued; this did not start a second one." }
```

Two certificates issued because somebody clicked twice is a real way to spend a
weekly rate limit. A certificate with no CA account — anything discovered rather
than issued — is refused with **400** at this point rather than becoming a job
that fails forever.

So is a certificate whose private key CertPilot does not hold, again with
**400**. When `key_custody` is `AGENT`, the refusal names the agent and says how
to renew it on that host (`certpilot-agent request --name …`). When it is
`EXTERNAL`, it asks for a new signing request from whoever holds the key. A
renewal here always ends with the gateway generating a fresh keypair. For these
certificates, CertPilot would then hold a key it promised never to hold, and
the record would describe a certificate the key holder is not serving. A job
for one that was queued some other way is cancelled, not retried.

### Where a job stands

```json
GET /api/v1/renewals/{id}
{ "data": { "status": "PENDING", "attempts": 3, "run_after": "…",
            "escalated_at": "…", "not_after": "…",
            "attempt_log": [
              { "number": 1, "started_at": "…", "duration_ms": 412,
                "worker": "core-7c9f/1", "error": "dial tcp 10.0.0.5:9091: connection refused" }
            ] },
  "summary": "Failed 3 time(s), with 41 hours left before this certificate expires. Retrying in 8 minutes. The most recent error was: …" }
```

The **whole attempt log**, not just the last error. "This has failed eleven
times in six days with the same DNS error" is a sentence somebody can act on;
`last_error: timeout` cannot tell a blip from a fortnight of silence. Each entry
names the worker that made it, because one replica failing and every replica
failing are different problems.

The log is capped at the 50 most recent attempts, so a renewal retrying for
weeks does not grow without limit inside a row a dashboard reads constantly. The
attempt count is kept separately and is not capped.

### What the queue does with failure

A failed attempt leaves the job **PENDING** with `run_after` moved forward.
There is no attempt count at which a certificate stops needing to be renewed,
and a queue that gives up on its own goes quiet exactly when it matters.

The delay is the **smaller** of two answers: what exponential backoff says
(2 minutes doubling to a 6-hour ceiling), and what the deadline allows — the
remaining runway divided into a budget of 24 more attempts.

| Runway | Delay |
|:---|:---|
| a month | ~6 hours, the ordinary ceiling |
| a day | ~1 hour |
| an hour | a few minutes |
| already expired | the 60-second floor |

Every backoff library assumes there is no deadline. A certificate has one, and
as it approaches the cost of *not* retrying grows without bound while the cost
of retrying stays flat, so backing off further is exactly wrong. Never faster
than 60 seconds, though: a CA answering the same error once a second will not
answer differently on the two hundredth try.

Jittered ±20% either way. Forty renewals failing against one CA outage and all
coming back at the same instant is how a transient failure becomes a rate-limit
suspension.

`escalated_at` is set when a failure stops being a blip — three attempts, or a
single failure with less than seven days of runway, because close to expiry
there may not be room for many more attempts. The `cert.renewal_failed` alert
fires **once**, on escalation, not per attempt.

```
GET /api/v1/renewals?escalated=true
```

The listing surfaces a `warning` naming them: *"3 renewal(s) have been failing
long enough to need attention … Each of these is a certificate on a countdown."*

The listing defaults to outstanding jobs only — the question is almost always
"what is about to happen", not "what happened last month". `?outstanding=false`
returns the history.

### Renewal information (RFC 9773)

```
POST /api/v1/certificates/{id}/renewal-info      Ask the CA now      (operator)
```

A CA publishes a window it would like each certificate replaced inside.
CertPilot polls it, picks a **random instant** within the window rather than
renewing at its start — renewing at the start would move the thundering herd
rather than disperse it — and honours the CA's `Retry-After` when polling again,
floored at 15 minutes.

```json
{ "data": { "ari_supported": true,
            "ari_window_start": "2026-08-19T21:16:26Z",
            "ari_window_end":   "2026-08-20T09:16:26Z",
            "renewal_scheduled_at": "2026-08-20T03:03:48Z",
            "ari_next_check_at": "2026-08-19T03:16:26Z",
            "ari_explanation_url": "" },
  "summary": "The CA suggests renewing this certificate in 29 hours, and CertPilot picked a random moment inside its window rather than the start so that renewals do not cluster." }
```

`ari_supported` is **three-valued** and the summary says which state you are in:

| Value | Meaning |
|:---|:---|
| `null` | nobody has asked this CA yet; the lead time applies |
| `false` | asked, and this CA publishes nothing — *"it will not be able to warn you if it revokes this certificate in bulk"* |
| `true` | asked, and `renewal_scheduled_at` came from the CA |

Collapsing the first two would make a CA nobody has reached look identical to
one with nothing to say. A gateway that is *down* is recorded as neither: the
existing advice is left alone and retried, because a window does not stop being
true because the next call failed.

The advice overrides the configured lead time in both directions — it can bring
a renewal forward and hold one back — but **never past a seven-day safety
floor**, or past a third of the certificate's lifetime when that is shorter. A
six-day certificate is inside seven days from the moment it is issued, so an
unbounded floor would renew it on every sweep whatever the CA advised. Inside that window a certificate renews regardless of what the CA
suggested, so a bad window, or a stale one left by a poller that stopped
running, cannot defer something about to expire.

Only certificates that could act on the answer are polled: renewed
automatically, issued by a CA account, and with a stored body to name to that
CA. Asking about anything else spends somebody's rate limit to learn nothing.

#### When the CA changes its mind

This is what the feature is for. A CA facing mass revocation pulls the affected
windows into the past, and for anyone not reading ARI that is an email to
whatever address is on the account.

A window brought **materially** forward — more than 12 hours, so an ordinary
re-draw inside an unchanged window is not mistaken for one — publishes
`cert.renewal_window_moved`, CRITICAL when the window has already opened:

> **ari-lab.example.com: the CA wants this replaced sooner**
>
> ARI Lab Issuing CA has brought this certificate's renewal window forward by
> about 3 days. A CA does that when something is wrong with a certificate it
> issued — most often a bulk revocation. CertPilot has rescheduled the renewal;
> check the explanation before assuming it is routine.

The alert carries the CA's own `explanationURL` when it sends one, and the
renewal moment with a **time** on it rather than only a date — during a
revocation, "in 55 minutes" and "sometime on 18 August" are different
instructions.

### Post-renewal verification

```
POST /api/v1/certificates/{id}/verify        Check the servers now     (operator)
```

A renewal is not done when the certificate is stored. It is done when the thing
serving it is serving it — and a renewal does not deploy itself, so a successful
renewal routinely leaves a new certificate in the database and the old one in
front of the users, expiring on the old schedule under a green dashboard.

Every successful renewal schedules a check 30 minutes later (a deployment done
by hand does not happen in the same second as the issuance) and re-probes **the
endpoints discovery has actually observed serving that certificate**.

```json
409 Conflict
{ "state": "STALE",
  "summary": "127.0.0.1:9500 is still serving the certificate this renewal replaced. The new certificate exists in CertPilot and has not reached the server, so what users get expires on the old schedule." }
```

**409, not 200.** The status code carries the same news the body does, because a
script that only checks the code is the one most likely to be running this in a
pipeline.

| `verification_state` | Meaning |
|:---|:---|
| `PENDING` | renewed, inside the grace period |
| `VERIFIED` | every known endpoint serves the renewed certificate |
| `STALE` | an endpoint is serving something else — see below |
| `UNREACHABLE` | endpoints are known and did not answer |
| `NO_ENDPOINTS` | discovery has never observed this certificate anywhere |

`STALE` distinguishes three cases, because they need different actions:

- **still on the certificate this renewal replaced** — install the new one
- **an older certificate for this name** — renewals have been landing nowhere
  for more than one cycle
- **a certificate for a different name entirely** — something other than this
  certificate is terminating TLS there

Endpoints come from discovery, never from the certificate's SANs. Probing
hostnames read out of certificate data would have CertPilot opening connections
nobody asked for, to names that may not resolve to anything it should be
touching. A certificate discovery has never seen is `NO_ENDPOINTS` with the
sentence that fixes it — *"run a discovery scan that covers wherever it is
deployed"* — rather than a guess. **"We cannot verify this" is useful; a
fabricated verification is not.**

Silence is never success. An endpoint that does not answer is `UNREACHABLE`, and
a certificate where some endpoints serve the new one while others stay quiet is
*not* verified — the quiet ones are exactly the ones that might still be on the
old certificate.

The `cert.not_deployed` alert fires **once**, on the first check that finds it
stale. An unresolved certificate is rechecked on a widening schedule (30m, 1h,
4h, 12h, 24h) and then the verifier stops asking — but not reporting: the state
stays on the record.

### Rate limits: deferred is not failed

```
PUT /api/v1/ca-accounts/{id}/rate-limit          (operator)
{ "renewal_rate_limit": 50, "renewal_rate_window_hours": 168 }
```

A public CA counts certificates per registered domain per week, and exhausting
that suspends issuance for the whole organisation — at exactly the moment
somebody is reissuing to fix an outage. `0` means unlimited and is the default,
deliberately: inventing a limit for a CA whose real limits nobody entered would
delay renewals for a constraint that does not exist.

A renewal with no slot available is **deferred**, and a deferral is carefully
not a failure:

- `attempts` is not incremented — the claim's increment is undone, because
  nothing was tried
- `last_error` is left holding whatever real failure came before it
- nothing escalates: a job that waited nine times has not failed nine times
- `run_after` is set to the moment the oldest renewal ages out of the window, so
  it returns exactly once rather than polling

```json
{ "attempt_log": [ { "deferred": true,
    "reason": "letsencrypt-prod has renewed 50 certificate(s) in the last 168 hours, which is its limit of 50. A slot opens at 2026-08-25T20:53:33+02:00." } ] }
```

The listing counts them separately as `waiting_on_rate_limit`, because a waiting
renewal is the pacing working and a stuck one is a certificate on a countdown.

Counted in the database rather than in a per-process token bucket: N replicas
each holding their own would allow N times the limit. A limit that cannot be
*read* never blocks a renewal — turning a database hiccup into an expiry is a
much worse trade than being one certificate over a quota.

**When the quota outlasts the certificate** it is not a deferral at all, and the
alert says so in different words, because retrying will not fix it:

> `step7-filter-probe.example.com` cannot be renewed because the CA account's
> renewal rate limit is full until 29 November 2028, and it expires on
> 18 August 2027. Retrying will not fix this: the limit has to be raised, or
> this certificate moved to another CA account.

Published once, when it is first noticed — months before the day, not on the
morning it happens.

### Ordering, leases, and why there is no leader

Jobs are claimed **by the deadline being raced, not by age**. A certificate
expiring tomorrow outranks one enqueued an hour earlier with a month left.

A claim is a **lease** — `locked_by` and `locked_until`. A worker killed
mid-renewal does not need to be cleaned up after: its claim expires and another
worker takes the job. Long renewals heartbeat to extend it, so an ACME order
waiting on DNS propagation is not stolen mid-flight.

There is no leader election and no advisory lock. Enqueues collide on a partial
unique index (`at most one outstanding job per certificate`) and claims use
`FOR UPDATE SKIP LOCKED`, so N replicas can all run the sweep and all run
workers without duplicating anything. A leader would be a single point of
failure with a window after it dies during which nothing renews at all, which is
a strange thing to build into the component whose entire job is that nothing
lapses.

### Cancelling

```
DELETE /api/v1/renewals/{id}
{ "message": "Renewal cancelled. Nothing is now scheduled to replace this certificate before it expires." }
```

Admin, and the response says what it costs. Cancelling is never how a failure is
handled — a renewal nobody cancelled keeps trying.

## Deployment

```
GET    /api/v1/deployment-targets                      List targets              (any)
POST   /api/v1/deployment-targets                      Create                   (operator)
PUT    /api/v1/deployment-targets/:id                  Update                   (operator)
DELETE /api/v1/deployment-targets/:id                  Delete                   (admin)

GET    /api/v1/certificates/:id/targets                Where it goes            (any)
POST   /api/v1/certificates/:id/targets                Bind to a target         (operator)
DELETE /api/v1/certificates/:id/targets/:bindingId     Unbind                   (operator)
POST   /api/v1/certificates/:id/deploy                 Install it now           (operator)

GET    /api/v1/deployments                             The deployment queue     (any)
GET    /api/v1/deployments/:id                         One job                  (any)
DELETE /api/v1/deployments/:id                         Cancel                   (admin)
```

Everything above deployment in this document observes. This changes something
that is already carrying traffic:

> Renewal creates new material. Deployment replaces material that is currently
> in use.

### Targets, and the column that answers a security question

```json
POST /api/v1/deployment-targets
{
  "name": "lab nginx",
  "description": "receiver that writes /etc/nginx/certs and reloads",
  "target_type": "webhook",
  "config": {
    "url": "https://deploy.internal/install",
    "signing_secret": "at-least-sixteen-characters",
    "include_private_key": true,
    "headers": {"X-Tenant": "eu"}
  }
}
```

The configuration is sealed with the keyring under
`secrets.ContextDeploymentConfig` and never leaves the process. What the list
*does* carry is `deploys_private_key`:

```json
GET /api/v1/deployment-targets
{ "count": 6, "carrying_private_key": 1, "supported_types": ["webhook"], "data": [ … ] }
```

A plain column, set when the target is created, deliberately not derived from
the sealed config at read time. **"Which places does this organisation ship
private keys to" is a question a security team should be able to answer with a
SELECT** — without the KEK, and without something that can decrypt every
deployment credential in the system having to be involved.

`supported_types` is shorter than what the schema permits. `deployment_targets`
has allowed `filesystem`, `aws_acm`, `kubernetes`, `gcp_lb` and `azure_kv` since
migration 001; accepting one because a check constraint tolerates it would
create a target that can be configured, bound, and queued, and that fails at the
last possible moment.

### The webhook deployer

The escape hatch: anything you can put fifteen lines of HTTP handler in front of
is a deployment target. The body is a documented, stable shape:

```json
{
  "event": "cert.deploy",
  "certificate_id": "…",
  "common_name": "app.example.com",
  "sans": ["app.example.com"],
  "serial_number": "…",
  "fingerprint_sha256": "…",
  "not_before": "2026-08-21T00:06:47Z",
  "not_after": "2027-08-21T00:06:47Z",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n…",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n…",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n…",
  "options": {"path": "/etc/nginx/certs/app"},
  "timestamp": "2026-08-21T00:06:17Z",
  "source": "certpilot"
}
```

`options` is the binding's own placement, passed through verbatim, so one target
can serve many certificates that land in different places on it.

Signed exactly as an alert webhook is — `X-CertPilot-Signature` is the hex
HMAC-SHA256 of `<unix-seconds> "." <raw body>`, with `X-CertPilot-Timestamp`
carrying the seconds. One scheme, one implementation
([`pkg/webhooksig`](../pkg/webhooksig)), so a receiver written once works for
both.

Two rules here are stricter than on a notification webhook, and both follow from
what this endpoint can *do* rather than what it carries:

- **`signing_secret` is mandatory.** An unsigned alert webhook means a receiver
  might act on a fabricated alert. An unsigned deployment webhook means anyone
  who can reach the receiver can install their certificate and their key under
  your hostname.
- **`include_private_key` cannot be combined with a plain-http URL** unless the
  host is a loopback address, where there is no wire to intercept. A hostname
  that merely resolves to loopback today does not count: what a name points at
  when the deployment actually runs is not what it points at now.

### Binding: one row per place

```json
POST /api/v1/certificates/{id}/targets
{ "target_id": "…", "options": {"path": "/etc/nginx/certs/app"} }
```

```json
201 Created
{ "message": "app.example.com will be deployed to lab nginx. Binding does not install it — POST /certificates/{id}/deploy does." }
```

A binding to a target that carries the private key is refused when CertPilot
holds no key for the certificate. Caught here rather than at deploy time,
because otherwise it is a configuration that fails on every renewal forever and
is discovered the week it matters.

Asking where a certificate stands is a question about places:

```json
GET /api/v1/certificates/{id}/targets
{ "count": 2,
  "summary": "2 targets: 1 up to date, 1 holding an older certificate." }
```

That sentence costs no network — it compares recorded fingerprints. Post-renewal
verification reaches the same kind of conclusion by opening a connection. Two
independent kinds of evidence, and they should agree.

The summary also reports failure, not only state:

```
"All 1 target hold the current certificate. The last deployment to 1 target failed."
```

Both halves are needed. This shipped reporting only the first, and a live run
produced *"All 1 target hold the current certificate"* over a deployment that
had failed three times and escalated.

### Deploying

```json
POST /api/v1/certificates/{id}/deploy
202 Accepted
{ "queued": 1,
  "message": "app.example.com: queued for 1 target; 1 target already had a deployment outstanding; 1 target switched off and skipped." }
```

Queued rather than deployed: eight targets is eight machines that may each need
a reload, and a synchronous handler would be cut off by the server's write
timeout somewhere in the middle, leaving half an estate updated and the client
with no way to know which half.

The message accounts for what did *not* happen too. A flat "queued" over an
estate where three of five targets were switched off is the kind of half-truth
that gets believed.

**What is deployed is the certificate as it stands now**, not the fingerprint
the job recorded when it was created. If a second renewal happened while the job
waited, installing what the job was created for would push an older certificate
to a live listener — and that renewal's own enqueue may have been a no-op,
because the binding already had a job outstanding. The captured fingerprint is
provenance, never a selector.

### The queue

```json
GET /api/v1/deployments?certificate_id=…&outstanding=true
{ "total": 1, "outstanding": 1, "escalated": 1,
  "summary": "1 deployment is failing: app.example.com at lab nginx (3 attempts). The certificates are fine; what serves them is not being updated." }
```

Durable rows with leases, an attempt log, and deadline-aware backoff — the same
machinery as the renewal queue, because a certificate that has been renewed and
not installed runs down exactly the clock of one that was never renewed at all.

A failing deployment stays `PENDING`. There is no attempt count at which a
certificate stops needing to be where it is served from. It escalates instead —
after three failures, or after one when there is less than a week of runway —
and `cert.deploy_failed` fires once, at that moment:

```
CRITICAL — Cannot install app.example.com at lab nginx

app.example.com has failed to install at lab nginx 3 times. The certificate is
fine; what is serving it is not being updated, so it expires on the schedule of
whatever is there now.
```

A failed deploy never moves the binding's `deployed_fingerprint`. The place is
still holding whatever it was holding, and overwriting it with the fingerprint
that failed to arrive would be the record claiming a deployment that did not
happen.

One thing differs from the renewal queue, and it is the load-bearing line: the
partial unique index is on the **binding**, not the certificate. Renewal allows
one outstanding job per certificate because a second renewal issues a second
certificate. A certificate bound to six targets needs six jobs outstanding at
once, and copying renewal's constraint would have deployed to the first and
dropped five in silence.

### Deploying on renewal

```json
POST /api/v1/certificates/{id}/targets
{ "target_id": "…", "deploy_on_renewal": true }
```

`deploy_on_renewal` defaults to **true** for a binding created now, and is
**false** for every binding that existed before migration 023. That is not a
contradiction: a binding made from here on is made by somebody who knows the
feature exists, and an upgrade must not silently begin writing to production
servers. The binding summary says which is which, because a switch nobody turns
on is a feature nobody has:

```
4 targets: 3 up to date, 1 never deployed. 1 target will not be updated when it
renews, and will hold an older certificate until deployed by hand.
```

A renewal and this endpoint go through the same planner and differ in one field,
the reason. Two code paths would mean the automatic one diverging from the one
people test by hand.

### A failing target halts the rollout

**A deployment that has not itself failed waits while another for the same
certificate has.** The first target attempted therefore becomes a canary on
every certificate, with nobody having configured anything, and a bad certificate
reaches at most as many targets as there are workers — two per replica — rather
than all of them. When the failure clears, the rest resume on their own.

Two failures do not hold each other still: the rule exempts jobs that have
themselves failed, or the retry curve would never run.

Because a deliberate halt and a broken queue look identical from outside, the
escalation says which it is:

> *1 other target is waiting behind it and will not be attempted until this one
> succeeds: a failing target stops the rollout rather than letting a bad
> certificate march through the estate.*

There is no way to express ordering — "staging first, then production" — and no
way to make the canary exactly one rather than one per worker. Both are recorded
as gaps rather than implied.

### The loop that proves it landed

A deployment's success is a claim that bytes were accepted. The verifier's is
evidence from a handshake. Once **every** place a certificate is bound to holds
it, its check moves from the half hour a renewal schedules to three minutes —
not to zero, because a verification that ran the instant a deployer returned
would report the reload it did not wait for, and not at all on a partial
rollout, because that is a STALE nobody needed to see.

### Cloud targets

```
aws_acm           borrows an AWS connection      binding needs certificate_arn
azure_key_vault   borrows an Azure connection    binding needs certificate_name
f5                its own host and credentials   binding needs name
```

All three terminate TLS, so all three carry the private key and all three appear
in the answer to *"where does this organisation ship private keys"*.

**A cloud target names a connection instead of holding credentials.**

```json
POST /api/v1/deployment-targets
{ "name": "acm-eu-west-1", "target_type": "aws_acm",
  "config": { "connection_id": "…" } }
```

Anything else is refused. Two copies of one account's credentials — one in
`cloud_connections` for discovery, one here for deployment — is one rotation
away from a system that can read an account it can no longer write to. The
target's sealed config holds the connection id and nothing else; `region`,
`vault_url` and the credentials are read from the connection at deploy time, and
the connection wins on any collision.

`deployment_targets.cloud_connection_id` is a plain column beside the sealed
blob, for the reason `deploys_private_key` is: *"which cloud accounts can this
system write to"* has to be answerable with a SELECT by somebody who does not
hold the KEK.

### The one mistake all three share

| | The one-field mistake | What is actually being served |
|:---|:---|:---|
| ACM | `ImportCertificate` with no `CertificateArn` | Every listener still points at the old ARN |
| Key Vault | Import under a new name | Whatever reads the old name is on the old certificate |
| F5 | Install under a new crypto-store name | The client-SSL profile references the previous one |

In all three the API returns 200, the attempt log records a success, and the
console shows a fresh green certificate beside the old one. So the identifier of
what is being replaced is required per binding and refused **at binding time**:

```
400  an ACM deployment needs certificate_arn: the ARN of the certificate to
     replace. Importing without one creates a new certificate that no load
     balancer is pointing at, and the old one goes on being served until it
     expires
```

ACM additionally refuses the *result*: an import returning a different ARN means
AWS created rather than replaced, which is the same failure arriving as a
success. On a real replacement it reads back what is attached —
`(issued, in use by 1 resource(s))`, or a warning that nothing is using this ARN
at all.

**The F5 deployer does not touch the client-SSL profile.** It installs over the
crypto-store name the profile already references, which is the deployment.
Repointing a profile at a *different* certificate changes what a virtual server
serves and belongs to whoever owns that virtual server.

Its management address must be `https`, because the certificate and its private
key travel over it. `insecure_skip_verify` is available for the very common case
of a BIG-IP presenting its own admin-generated certificate — allowed, because
refusing outright means somebody copies the certificate by hand instead, and
named in `Describe()` so it is never invisible.

### Cancelling a deployment

```
DELETE /api/v1/deployments/{id}
{ "message": "Deployment cancelled. The target keeps whatever certificate it already has, and nothing will update it." }
```

Deleting a *target* says the same thing more loudly, because the bindings
cascade with it and the certificates carry on renewing perfectly happily while
reaching nothing.

## Agents

Two APIs, kept completely apart.

```
# For people (OIDC bearer token, as everywhere else in this document)
GET    /api/v1/agents                        The fleet                   (any)
GET    /api/v1/agents/:id                    One host                    (any)
POST   /api/v1/agents/:id/revoke             Withdraw its credential     (admin)
DELETE /api/v1/agents/:id                    Forget it, once revoked     (admin)
GET    /api/v1/agent-enrol-tokens            Which doors are open        (admin)
POST   /api/v1/agent-enrol-tokens            Mint one                    (admin)
DELETE /api/v1/agent-enrol-tokens/:id        Revoke it                   (admin)

# For agents (signed with the agent's own key)
POST   /api/v1/agent/enrol                   Join                        (enrolment token)
POST   /api/v1/agent/heartbeat               Report                      (signed)
```

The separation is the point. `AgentAuth` is mounted only on `/api/v1/agent/*`
and nowhere else; the OIDC authenticator and the display-token middleware are
not mounted there at all. An agent credential cannot read the estate, and a
person's bearer token cannot speak as a host.

### How an agent proves who it is

The agent generates an Ed25519 keypair on its own host during enrolment and
sends only the public half. There is no field in any request for a private key.
The core therefore stores nothing that can impersonate an agent — a database
that leaks yields public keys.

**Not mTLS**, and that is a decision. The core is routinely deployed behind a
reverse proxy; client-certificate authentication terminates at the proxy and
reaches the application as a header, which anything that can reach the core
directly can forge. An application-layer signature is verified by the process
that acts on the request, so it survives every proxy, ingress, and mesh in
between. TLS is still expected on the wire — this authenticates, it does not
encrypt.

Three headers:

```
X-CertPilot-Agent:     <agent id>
X-CertPilot-Timestamp: <unix seconds>
X-CertPilot-Signature: <base64 Ed25519 signature>
```

over exactly these bytes:

```
certpilot-agent-v1 \n
POST               \n
/api/v1/agent/heartbeat \n
1774137600         \n
<hex sha256 of the request body>
```

The scheme name is *inside* the signed bytes, so a verifier that one day
supports two cannot be talked into checking a v2 signature with v1 rules. The
path is inside them, so a heartbeat's signature cannot be lifted onto a route
that does something. An empty body is hashed rather than skipped, so "no body"
and "an empty body" are not interchangeable.

**Replay is prevented on the endpoints where it changes something.** The core
records the signatures it has accepted — in the database, not in a replica's
memory, because a check one replica performs alone implies a property that does
not hold across a deployment of two — and refuses a repeat on
`POST /agent/certificates` and `POST /agent/deployments/claim`.

Heartbeats, inventory, installation reports and deployment results are exempt.
A signature covers a one-second timestamp, so an agent retrying after a network
timeout re-sends bytes it already signed; on a report those are indistinguishable
from a replay and refusing the retry turns a recovered blip into a failure.

A refused replay answers `401` with `"code": "agent_replay"`. An agent's own
retries sign afresh with a new timestamp and never collide, so seeing this means
something else is re-sending its traffic.

The reference implementation is [`certpilot-agent-sdk/agentauth`](https://github.com/certpilot/certpilot-agent-sdk/tree/main/agentauth), and
`SigningString` is written out as its own exported function precisely so an
agent in another language can reproduce it byte for byte.

### Enrolment

```json
POST /api/v1/agent-enrol-tokens
{ "name": "june rollout", "expires_in_minutes": 60, "max_uses": 1,
  "labels": {"env": "production"} }
```
```json
201 Created
{ "token": "cpe_…",
  "message": "This token is shown once and cannot be recovered. It enrols one agent and expires at 2026-08-22T02:19:55Z." }
```

One use and one hour by default, capped at a week. An enrolment token only has
to survive a provisioning run; one that outlives the rollout is a live
credential in whatever template it was pasted into. It is spent by a conditional
`UPDATE` rather than a read followed by a write, because two hosts booting from
the same image enrol in the same second — and a one-use token that enrols both
is not one-use.

A malformed public key is rejected *before* the token is spent, so a typo in a
provisioning script does not leave the operator holding a burnt token.

```json
POST /api/v1/agent/enrol
{ "token": "cpe_…", "public_key": "-----BEGIN PUBLIC KEY-----\n…",
  "name": "web-01", "hostname": "web-01", "platform": "linux/amd64",
  "version": "0.1.0", "heartbeat_interval_seconds": 300 }
```

Labels come from the *token*, not the request, so an agent cannot label itself
into a group somebody else's policy is written against.

### Revocation, and who gets told

```
POST /api/v1/agents/{id}/revoke
{ "message": "web-01 can no longer speak to CertPilot. Whatever certificates are on that host stay where they are and stop being maintained." }
```

A revoked agent's next signed request gets **403 with the reason**. Every other
refusal — unknown agent, bad signature, stale clock, missing headers — is a flat
`401` with one uniform sentence, and which check failed goes to the log.

The ordering is load-bearing: **the signature is verified before the agent's
status is looked at.** Checking status first would let anyone who can guess an
id distinguish a revoked agent from an unknown one, which is a fleet-enumeration
oracle. Checking it second means the only caller ever told "you have been
revoked" is the one holding the private key — which is the agent, and precisely
who needs to know, because otherwise it retries a withdrawn credential every few
minutes for as long as the host stays up.

Deleting an agent is refused while it is active: removing the row does not
withdraw the credential, and doing it first destroys every record that the agent
existed.

### The fleet, and hosts that go quiet

```json
GET /api/v1/agents
{ "total": 42, "stale": 1,
  "summary": "42 agents, and 1 has stopped reporting. That host still has certificates on it and nothing is maintaining them." }
```

The number that matters is not how many agents are enrolled. A host whose agent
died three weeks ago still has certificates on it, still has them expiring, and
now has nothing maintaining them — and it looks exactly like a healthy host on a
list that counts rows.

Staleness is measured against **what each agent itself promised**, not one
global number that is wrong for every agent configured differently, and an agent
is late after three missed intervals — a restarted service or a busy host misses
one or two. An agent that enrolled and never reported is measured from
enrolment, so one that failed on its very first heartbeat is as visible as one
that stopped after a year. A revoked agent is not reported as missing: somebody
already knows.

`agent.stale` fires once, and again only if the agent comes back and goes away
a second time.

### What is on the hosts

```
POST /api/v1/agent/inventory        An agent reports its host   (signed)
GET  /api/v1/agent-certificates     What the fleet is holding   (any)
```

The fourth place certificates hide, after served, issued, and stored in a cloud:
a file on a disk that no scan, no transparency log, and no cloud API will ever
mention.

The agent sends certificates as **PEM, unparsed**, plus the facts only a process
on the host can produce. Parsing centrally is deliberate — the agent runs on
machines nobody upgrades for years, and parsing logic on five hundred of them
cannot be fixed. **There is no field a private key could travel in**: the agent
parses one only far enough to derive its public half and compare.

```json
GET /api/v1/agent-certificates
{ "total": 7,
  "findings": { "private_key_readable": 2, "private_key_mismatch": 1, "unmanaged": 6 },
  "summary": "7 certificate files across the fleet. 2 certificate files have private keys other accounts on their hosts can read; 1 certificate file has a key that does not match it, so the next restart of whatever serves it will fail; 6 certificate files are not managed by CertPilot." }
```

Filters: `?agent_id=`, `?state=MANAGED|UNMANAGED`, `?kind=leaf|ca|bundle`,
`?finding=<code>`, `?include_removed=true`. The finding filter runs as jsonb
containment in the database, so it works on an estate of thousands.

| Finding | What it means |
|:---|:---|
| `private_key_readable` | Other accounts on that host can read the key. **Reissue** — renewing does not undo it, and neither does changing the mode afterwards |
| `private_key_mismatch` | The key beside the certificate does not belong to it. The next restart of whatever serves it will fail |
| `superseded` | This file holds a certificate a renewal already replaced |
| `private_key_missing` | A leaf with no key beside it, so this host cannot serve it. Usually a copy left by a migration |
| `unmanaged` | CertPilot did not issue it and is not tracking it |
| `expired` / `expiring_soon` | Raised to CRITICAL when a server configuration names the file |
| `unreferenced` | No configuration on the host was found naming it. Only claimed on hosts where the heuristic matched something else |

`private_key_readable` is the one nothing else in this system can produce. A
network scan sees what an endpoint presents; it cannot see that the key behind
it is mode 0644.

`kind` keeps trust stores from drowning the rest: a host's `ca-certificates`
file is one row saying it holds 143 roots, not 143 findings about a package
nobody edited. Findings apply to `leaf` and `ca`, never `bundle`.

A certificate is classified as `ca` only if it is a CA **and carries no DNS or
IP names**. OpenSSL's `req -x509` sets `basicConstraints CA:TRUE` by default, so
most self-signed certificates on an internal estate claim to be authorities
while plainly serving a hostname; trusting that claim made almost everything on
such a host skip the leaf findings.

Two topics, not one: `agent.key_exposed` is a security incident needing the
certificate reissued, `agent.key_mismatch` is an outage waiting for an unrelated
restart. They have different owners, and a message saying "one of these two
things" makes the reader go and look — which is the work an alert exists to
save.

### Certificates with keys CertPilot has never seen

```
GET    /api/v1/agent-grants           What hosts may ask for      (any)
POST   /api/v1/agent-grants           Grant it                    (operator)
DELETE /api/v1/agent-grants/:id       Revoke it                   (operator)
POST   /api/v1/agent/certificates     A host asks                 (signed)
```

The agent generates the key on the host, signs a CSR with it, and sends only the
request. CertPilot never sees the key, and `GET /certificates/:id/private-key`
answers **404** — truthfully.

`certificates.key_custody` says who holds it: `CERTPILOT` (sealed here, and
therefore losable, copyable, subpoenable), `AGENT` (on a host, never anywhere
else), `EXTERNAL` (somebody has it and it is not us). Until agents existed, "no
key stored" meant only the last of those.

### Grants

```json
POST /api/v1/agent-grants
{ "name": "web tier hosts",
  "label_selector": {"tier": "web", "env": "prod"},
  "names": ["*.web.example.com"],
  "ca_account_id": "…",
  "min_key_size": 2048,
  "allowed_key_types": ["ECDSA", "RSA"],
  "validity_days": 90,
  "renew_before_days": 30 }
```

A grant targets one agent (`agent_id`) or a set of labels — and **the labels
come from the enrolment token, not from the agent**, so a host cannot label
itself into a grant written for another tier. Four hundred web servers are one
grant.

Wildcards match one level, exactly as certificates' do: `*.web.example.com`
covers `a.web.example.com` and covers neither `a.b.web.example.com` nor
`web.example.com`. Following the same rule certificates follow is what makes a
grant mean what its author thinks.

`*` is **refused**. A grant permitting every name makes the agent credential
equivalent to the CA behind it.

`min_key_size` means **RSA bits**. Key sizes are not comparable across
algorithms — a P-256 key is considerably stronger than RSA-2048 and 256 is a
smaller integer than 2048 — so elliptic keys are floored at P-256 instead. A
grant cannot require a specific curve; that is a known gap rather than a number
that means two things.

### What is checked on a request

| Check | Why |
|:---|:---|
| The CSR signature verifies | Otherwise anyone reaching the endpoint could obtain a certificate for somebody else's public key — which is a certificate issued to that somebody else |
| Every name is covered, **common name included** | A request with permitted SANs and an unpermitted CN would produce a certificate for a name nobody granted |
| **One** grant covers the whole request | Assembling permission from several would let a host combine one tier's names with another tier's CA account |
| No `basicConstraints CA:TRUE`, no `keyCertSign` | Refused, not stripped. A correct CA ignores CSR extensions — but that is a hope about code that may be a third-party gateway next year, not a control |
| DNS names only | IP, email, and URI names are validated differently and a grant has no way to express them |
| The gateway returned **no** private key | If it did, it ignored the CSR and generated its own pair; storing that leaves the host's certificate and the database's key mismatched, both looking fine |

A refusal is `403` with `"code": "not_permitted"`, and publishes
`agent.request_refused`. The other 403 an agent can get is `"code":
"agent_revoked"` — the codes exist because the right response to each is the
opposite: fix the grant, or stop for good. An agent that could not tell them
apart shut itself down over a missing grant.

### Renewal

The agent renews its own, because rotating means generating a key and only the
host has one. The core's renewal sweep excludes both `key_custody = 'AGENT'` and
`key_custody = 'EXTERNAL'` — the two cases where CertPilot does not hold the key
and so cannot rotate it. Without that the queue would claim those jobs and fail
forever.

An externally held key is renewed by whoever holds it, by submitting a new
signing request. A certificate with no recorded custody stays eligible: that
means nobody wrote one down, not that somebody else holds the key.

*When* is the core's decision, returned as `renew_after` and derived from the
grant's `renew_before_days`. A host that picked its own moment could decide to
renew hourly, and four hundred of them would be a denial of service against the
CA.

`renew_after` always falls inside the certificate's own lifetime, and never in
its first third. A lead time longer than two thirds of the lifetime is replaced
by renewing when a third remains, so a six-day certificate under the default 30
days renews at day four. Without that bound, a certificate shorter than its lead
time was handed a `renew_after` that had already passed, and the host renewed it
on every cycle ([#109](https://github.com/certpilot/certpilot/issues/109)).

### Installing, and reloading

```
GET  /api/v1/agent-installations           Where the fleet put them    (any)
POST /api/v1/agent/installations           A host reports              (signed)
POST /api/v1/agent/deployments/claim       A host takes work           (signed)
POST /api/v1/agent/deployments/result      A host says what happened   (signed)
```

A certificate in the agent's state directory is not a certificate nginx is
serving. This is the step that closes that gap, and it is the first time the
agent writes to a file another process depends on — so it is governed by phase
6's sentence: *renewal creates new material; deployment replaces material that
is currently carrying traffic.*

**Where a certificate goes, and what to run afterwards, is declared on the host
— never sent by the core.** There is no wire format for a destination in
`certpilot-agent-sdk/agentapi`, deliberately, because a core that could hand a host a command to
run would be a fleet-wide remote execution channel with a certificate manager on
the front of it. The core may say *"install certificate X"*; it may never say
*"and here is what to run".*

```json
/etc/certpilot/installs.json
{ "destinations": [
    { "name": "nginx",
      "certificate": "shop.example.com",
      "cert_path": "/etc/nginx/ssl/shop.crt",
      "key_path":  "/etc/nginx/ssl/shop.key",
      "chain_path": "/etc/nginx/ssl/chain.pem",
      "owner": "root", "group": "www-data",
      "cert_mode": "0644", "key_mode": "0640",
      "check":  ["/usr/sbin/nginx", "-t"],
      "reload": ["/usr/sbin/nginx", "-s", "reload"] } ] }
```

`cert_path` and `key_path` may be the same file, which is the layout HAProxy
wants. That file then takes the **key's** mode whatever `cert_mode` says —
because it holds a private key, and 0644 is exactly what step 4b keeps finding
on it.

### Install, check, then reload — in that order

`check` is the most valuable line in the file. The certificate is written, the
server is asked whether it can live with it, and only then is the running
process told to pick it up. A check that fails costs a rollback of files nothing
has read yet; the same failure without a check costs a listener.

| | |
|:---|:---|
| Every file is written to a temporary name **in its own directory** and renamed over the target | A reader sees the old contents or the new ones, never half of either. Rename is atomic within a filesystem and not across one, which is why the temporary file is not in `/tmp` |
| What was there is kept **in memory**, not in a `.bak` | A private key copied to `server.key.bak` is a private key nobody is tracking |
| A failed `check` restores the files and never reloads | Nothing was ever loaded, so the running process is still on what worked |
| A failed `reload` restores the files **and reloads again** | The process is running on material that is no longer on disk; putting the files back is not enough on its own |
| Nothing is written or reloaded when the bytes already match | An agent that reloaded nginx every five minutes because it could would be a worse problem than the stale certificate it was fixing |
| The declared mode and ownership are enforced **without** a write or a reload | A key somebody chmodded to 0644 during an incident is the finding step 4b reports as CRITICAL, and this is the one process in the system that can quietly put it back |

The agent refuses a `key_mode` that is world-readable, at load, naming the mode.
**It must not create the finding it exists to report** — and the fix for that
finding is reissuance, not a later `chmod`.

Commands are an argument vector run with no shell and a bare `PATH`, and
`argv[0]` must be absolute: this very often runs as root out of a systemd unit
whose `PATH` is not the one the person editing the file was looking at.

### An agent is a deployment target like any other

```
POST /api/v1/certificates/{id}/deploy    →  202, a job per binding
```

Every other target type is deployed to by a core worker opening a connection. A
host behind two firewalls **claims the job itself** — same queue, same lease,
same retry curve, same attempt log. Only the worker moves, and the attempt log
names the machine rather than a replica.

The core's own claim query excludes agent targets. A worker that took one would
fail it until the attempt budget ran out, being loudly wrong about something
that in fact works.

The target appears on its own, the first time a host reports a destination —
four hundred hosts are four hundred targets, and a product that asks somebody to
create them by hand gets a script that creates them by hand. It is created with
`deploys_private_key: false`, and that is a fact rather than a default: the key
was generated on that host and is already there, so agent hosts are correctly
absent from the answer to *"where does this organisation ship private keys"*.

Reporting on a job belonging to another host is `403 {"code":
"not_permitted"}`. Without that check a host with a valid credential could mark
another machine's deployment as done, and the binding would record a certificate
as installed somewhere that had never seen it.

### The status nothing else can produce

```
GET /api/v1/agent-installations?attention=true
```

| Status | |
|:---|:---|
| `INSTALLED` | This destination holds what the host holds |
| `FAILED` | The last attempt did not finish. `rolled_back` says whether the previous material was put back — an inconvenience or an outage, and a single status cannot say which |
| `UNFULFILLED` | **This host is configured to install a certificate it does not hold** |

The last one is the reason this endpoint exists. A remote scanner sees what a
listener serves; the issuance record sees what was asked for. Neither can see
that a machine has been configured for a name nobody granted it — there is no
binding, no certificate and no failed attempt, just a host that will do nothing
at all when the renewal it is waiting for never arrives. It is almost always one
character.

Reports are **full state**, like the inventory: a lost one costs nothing because
the next carries everything. Bindings are reconciled to match, so an agent that
renews does not leave the binding for the certificate it replaced sitting beside
the new one — both claiming that place holds the current certificate.

Alerts fire on **transitions**, not on states. A destination that has been
failing since Tuesday must not send a message every cycle until somebody mutes
the channel that also carries CA expiry alerts.

## Cryptographic posture

```
GET /api/v1/posture             The headline, and what to do first
GET /api/v1/posture/endpoints   What each handshake negotiated (?exposed=true)
GET /api/v1/posture/cbom        CycloneDX 1.6
```

One distinction governs this section, and most reporting on the subject has it
backwards:

> A classical **signature** is a problem in the 2030s. A classical **key
> exchange** is a problem this afternoon.

Nobody forges a handshake that already happened, so an RSA-signed certificate
expiring in ninety days is a plan, not a risk. Traffic under a classical key
exchange is being recorded now. So the headline is about handshakes:

```
3 of 6 scanned endpoints do not negotiate a post-quantum key exchange. Traffic
to them can be recorded today and decrypted whenever a quantum computer arrives
— and unlike certificate algorithms, that is a cost being paid now rather than a
deadline in the 2030s.
```

That answer needs a real connection to a real server, so it is collected by the
discovery scanner during the handshake it was already making.

### offered_hybrid, and why it is the important column

| | |
|:---|:---|
| `hybrid_key_exchange` | The negotiated group carries ML-KEM |
| `offered_hybrid` | **CertPilot offered one** |

Without the second, the first being false is a fact about CertPilot rather than
about the endpoint. Go enables X25519MLKEM768 by default and that default can
change in a release, so the scanner states its curve preferences explicitly and
records what it offered against every observation.

### Verdicts

| Verdict | |
|:---|:---|
| `EXPOSED` | Offered a post-quantum group and did not take it. Traffic here is being recorded now |
| `HYBRID` | Negotiated one. Protected against harvest-now-decrypt-later |
| `CLASSICAL` | An ordinary certificate, or a handshake that offered nothing to conclude from |
| `READY` | Post-quantum throughout |
| `WEAK` | Broken against **ordinary** computers today — SHA-1, RSA-1024. Not a quantum problem, and reported ahead of every quantum one |

A TLS 1.2 endpoint is told apart from a TLS 1.3 one that declined, because there
is no hybrid key exchange below 1.3: *"enabling a group will not fix it — this
endpoint needs TLS 1.3."* Those are different jobs and read identically unless
the message says so.

### The score

**The percentage of applicable CNSA 2.0 requirements met — not a risk score.** A
certificate scoring zero is the normal state of nearly every certificate in
production today, and presenting that as an alarm is how a report gets muted.
What it is for is measuring movement: the same estate, six months later.

CNSA 2.0's suite is written out in the source so it can be checked against the
NSA's publication. The transition **dates are deliberately absent**: they have
been revised, differ by category of system, and a compliance tool that invents a
deadline is worse than one that reports none.

SHA-256 is reported as a shortfall rather than a break — Grover halves the
effective preimage resistance, giving 128 bits where the suite asks for 192.
Lumping it in with SHA-1 would be false and would teach the reader to ignore the
whole category.

### CBOM

CycloneDX 1.6, validated against the published JSON schema in the test suite
rather than against a reading of it.

Algorithms are emitted **once** and referenced by every certificate that uses
them, with a `dependencies` graph linking the two. That is the only reason the
document is worth producing over a list: *"what does moving off SHA-256 touch"*
becomes a graph query somebody else's tool can answer.

`nistQuantumSecurityLevel` is `0` for classical algorithms rather than omitted,
so a reader can tell "a quantum computer breaks this" from "nobody assessed it".
The serial number is derived from the contents, so two exports of an unchanged
estate are byte-identical and a diff means something.

Post-quantum **issuance** is not implemented: `crypto/mldsa` is not in Go 1.26
and `crypto/x509` cannot build an ML-DSA certificate.

## Ownership and acknowledgement

```
PUT    /api/v1/pki/authorities/:id/owner             Set the owning team    (operator)
POST   /api/v1/pki/authorities/:id/acknowledge       Acknowledge            (operator)
DELETE /api/v1/pki/authorities/:id/acknowledge       Withdraw               (operator)
GET    /api/v1/pki/authorities/:id/acknowledgements  History
```

**Silencing suppresses delivery, never display.** An acknowledged CA still
appears on `/pki/authorities`, on the CA health view, and on the wall display,
with its status unchanged and an `acknowledgement` object attached. Nothing here
removes a row. Hiding a problem because someone clicked a button is how CAs
expire in organisations that believed they were monitoring them.

### Acknowledging

```json
{"note": "replacement issued, cutover Thursday", "silence_days": 7, "threshold": 14}
```

| Field | |
|:---|:---|
| `note` | Why. The most useful field: it turns a red row from an unanswered alarm into a status, and stops the next person re-investigating |
| `silence_days` | Suppress **delivery** for this many days. `0` (the default) acknowledges without silencing — the alert stops being new and still goes out. Capped at 90 |
| `threshold` | The expiry threshold in days this covers. Defaults to the CA's current `last_alert_threshold` |

There is no indefinite silence. A permanent one is indistinguishable from
deleting the alert, and the CA goes on expiring while the team believes it is
monitored.

**An acknowledgement is bound to its threshold.** Silencing a CA at 30 days does
not silence its 7-day alert: the situation has materially worsened, and the
earlier "yes, we know" answered a different question. The same rule governs
display — a CA that has since crossed a tighter threshold stops showing as
acknowledged, because the annotation would otherwise become the false
reassurance the feature exists to prevent.

The response states what was and was not changed, because "acknowledged" is
ambiguous and the ambiguity is the dangerous part:

```json
{
  "data": {"id": "…", "threshold": 7, "silence_until": "2026-08-24T09:48:18Z", "note": "…"},
  "note": "This certificate authority still appears on the dashboard and the wall display, now marked as acknowledged. Delivery is suppressed until 24 August 2026 09:48 CEST, but only for the 7-day threshold: if it crosses a tighter one, it alerts again."
}
```

Withdrawal marks rather than deletes: a CA acknowledged in error and then
un-acknowledged is something an incident review wants to see, not a row that
quietly disappeared. `GET …/acknowledgements` returns the full history, newest
first, revoked entries included.

If the acknowledgement lookup fails, the alert is **delivered anyway**. The cost
of a duplicate notification is an annoyed engineer; the cost of a suppressed one
is an expired CA.

### Ownership

```json
{"owner_team": "Platform Security", "owner_email": "pki@example.com"}
```

Both are free text — team names and distribution lists do not live in CertPilot.
Send an empty string to clear either: ownership moving to nobody is a real state,
and one worth seeing on the dashboard rather than silently keeping the old team's
name. A CA with no owner renders as "Nobody", not as a blank cell.

## Notification channels

```
GET    /api/v1/notification-channels          List channels
POST   /api/v1/notification-channels          Create                      (operator)
PUT    /api/v1/notification-channels/:id      Update                      (operator)
DELETE /api/v1/notification-channels/:id      Delete                      (admin)
POST   /api/v1/notification-channels/:id/test Send a real test alert      (operator)
```

Three channel types have a notifier: `slack`, `webhook`, `email`. Migration 001
also permitted `teams` and `pagerduty`; neither is implemented and 004 narrowed
the constraint, because a channel of a type nothing can deliver looks configured
on the dashboard and silently drops every alert routed to it.

`config` carries the destination's settings and is **write-only**. It is
validated by the notifier, sealed with the keyring, and never returned — not by
the create response and not by the list. Omit it on an update to keep what is
stored; send it to replace it wholesale.

| Field | |
|:---|:---|
| `name` | Required. What names the channel in a delivery failure |
| `channel_type` | `slack`, `webhook`, or `email` |
| `severity_threshold` | `INFO`, `WARNING` (default), or `CRITICAL` — the minimum this channel delivers |
| `topics` | Event topics to accept. **Empty means all**, which is the useful default. An unknown topic is rejected rather than accepted and ignored |
| `is_enabled` | Defaults to true on create |

Configuration per type:

```jsonc
// slack — webhook_url must be https; it is a bearer credential
{"webhook_url": "https://hooks.slack.com/services/...", "username": "", "icon_emoji": ""}

// webhook
{"url": "https://receiver.example.com/hook",
 "signing_secret": "at least 16 characters",
 "headers": {"X-Tenant": "acme"},
 "allow_insecure_http": false}

// email
{"host": "smtp.example.com", "port": 587,
 "username": "", "password": "",
 "from": "pki@example.com", "to": ["oncall@example.com"],
 "encryption": "starttls",   // or "tls" (465) or "none"
 "insecure_skip_verify": false}
```

### Testing a channel

`POST /notification-channels/:id/test` sends a real, clearly labelled test alert.
It does not retry and returns the destination's own complaint verbatim:

```json
{"delivered": false, "error": "Slack returned 403: invalid_token"}
```

The status is **502**, not 500: CertPilot worked and the destination did not, and
that distinction is the entire content of the answer.

### Webhook payload and signature

```json
{
  "severity": "CRITICAL",
  "topic": "ca.expiry_alert",
  "title": "CA expiring: Corporate Issuing CA",
  "summary": "Corporate Issuing CA expires in 9 days. Every certificate it has issued stops validating when it does.",
  "entity_id": "…",
  "fields": [{"label": "Days remaining", "value": "9 days"}],
  "timestamp": "2026-08-17T07:33:24Z",
  "source": "certpilot"
}
```

| Header | |
|:---|:---|
| `X-CertPilot-Event` | The topic, so a receiver can route without parsing |
| `X-CertPilot-Timestamp` | Unix seconds |
| `X-CertPilot-Signature` | Hex HMAC-SHA256, present only when a signing secret is configured |

The signed string is exactly `<X-CertPilot-Timestamp> "." <raw request body>`.
Verify it in constant time and reject anything outside a few minutes' tolerance.
The timestamp is inside the signature rather than merely alongside it: signing
the body alone yields a signature that stays valid forever, so a captured
delivery could be replayed indefinitely and the receiver could not tell.

```python
import hashlib, hmac
want = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(want, signature)
```

### Delivery behaviour

The dispatcher subscribes to the event broker rather than being called inline, so
a wedged destination loses its own place in the queue and can never apply
backpressure to the CA health sweep. Deliveries retry three times with jittered
exponential backoff, then stop — an endpoint that has refused three times inside
a minute is down, and retrying past that turns one outage into a queue that
outlives it.

Both outcomes are audited as `notification.sent` and `notification.failed`, and
are queryable through `/dashboard/activity?action=notification.failed`.

## Policies

```
GET    /api/v1/policies      List
GET    /api/v1/policies/:id  Detail
POST   /api/v1/policies      Create   (operator)
PUT    /api/v1/policies/:id  Update   (operator)
DELETE /api/v1/policies/:id  Delete   (admin)
```

Rule types, all of which are evaluated:

| `rule_type` | `rule_config` |
|:---|:---|
| `key_size` | `{"rsa_min_bits": 3072, "ecdsa_min_bits": 256}` |
| `key_type` | `{"allowed_key_types": ["ECDSA", "Ed25519"]}` or `{"forbidden_key_types": ["RSA"]}` |
| `max_lifetime` | `{"max_days": 90, "min_days": 30}` |
| `ca_restriction` | `{"allowed_providers": ["acme", "vault"]}` |
| `naming` | `{"allowed_suffixes": ["example.com"], "forbidden_patterns": ["*.internal"], "allow_wildcards": false, "max_sans": 50}` |

`severity` is `INFO`, `WARNING`, or `BLOCK`. Only `BLOCK` refuses the request;
the rest are returned in the issuance response.

`domain_pattern` scopes a policy — `*` matches everything, `*.example.com`
matches any subdomain. A policy applies when **any** requested domain matches.

### Key sizes are per algorithm

`rsa_min_bits` and `ecdsa_min_bits` are separate because the numbers are not
comparable: 256 is a strong ECDSA key and a broken RSA one. A single floor
cannot express both, and the rule's previous answer — check RSA, ignore
everything else — left elliptic keys with no floor at all.

`min_key_size` is still accepted and still means RSA bits, so policies written
against the original shape keep working.

**Ed25519 has one size.** A floor cannot be violated, so `key_size` does not
judge it. Use `key_type` to permit or forbid the algorithm itself.

### Naming

`allowed_suffixes` matches on a label boundary: `example.com` admits
`example.com`, `shop.example.com` and `*.example.com`, and refuses
`evil-example.com`. Every offending name in a request is reported, not just the
first.

`allow_wildcards` is only applied when present. A naming policy that does not
mention it permits wildcards, so a rule written to cap `max_sans` does not ban
them as a side effect.

### A policy never silently does nothing

A rule type this build cannot evaluate, a `rule_config` that will not parse, and
a configuration that sets no constraint each produce a violation at the policy's
own severity. Failing open is the one behaviour a security control must not
have: an operator who wrote "ECDSA only, BLOCK" and got a row in a table with no
effect had no way to tell it apart from compliance.

`approval_required` is no longer accepted on create. There is no approval
workflow in this build — no approvals table, no endpoint to approve or reject —
so a policy claiming to gate on approval was promising a control that did not
exist. The column still permits the value, because rows may already exist; the
engine now reports them rather than passing them.

> Policy is evaluated on issuance only, not on renewal.

## Display tokens

```
GET    /api/v1/display-tokens      List           (admin)
POST   /api/v1/display-tokens      Create         (admin, audited)
DELETE /api/v1/display-tokens/:id  Revoke         (admin, audited)
```

Create:

```json
{ "name": "fourth-floor-corridor", "expires_in_days": 90 }
```

`name` is required and unique — it is what makes "revoke the screen by the lifts"
an answerable request. `expires_in_days` defaults to 90 and is capped at 365;
there is no unlimited option.

```json
{
  "token": "cpd_...",
  "display": { "id": "...", "name": "...", "status": "ACTIVE", "expires_at": "..." },
  "warning": "This token is shown once and cannot be retrieved again. ..."
}
```

**`token` appears in this response and nowhere else.** Only its SHA-256 is
stored, so a database dump yields no working credentials — and neither does the
list endpoint, which returns everything except the hash.

`status` is `ACTIVE`, `EXPIRED`, or `REVOKED`. Revocation outranks expiry, and
is a soft delete: the row survives with `revoked_at` and `revoked_by` set,
because when a credential had to be pulled is exactly what someone will ask
later.

See [Authenticating an unattended screen](#authenticating-an-unattended-screen)
for what the credential can and cannot do.

## Response headers

Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
`Cache-Control: no-store`.

CORS reflects the request origin only when it appears in
`server.allowed_origins`. A wildcard is never sent — it is invalid alongside
credentials and browsers reject the combination.
