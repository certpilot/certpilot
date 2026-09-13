# Troubleshooting

Symptom, cause, fix. Grouped by where the symptom shows up.

- [Starting up](#starting-up)
- [Gateways and CAs](#gateways-and-cas)
- [Issuance and renewal](#issuance-and-renewal)
- [Deployment](#deployment)
- [The agent](#the-agent)
- [The dashboard](#the-dashboard)
- [Database](#database)

---

## Starting up

**`CERTPILOT_KEK is not set`**

The core will not start against a database without one. `make generate-kek`,
then put it somewhere durable — see [operations.md](operations.md#first-run).

**`config: auth.allow_anonymous no longer exists and must be removed`**

Working as intended, and it is refused rather than ignored on purpose: an
instance you believe is open should not quietly become one that is not.

Remove the setting. Sign in with a local account — the first one is created and
its password printed at first start — or configure `auth.jwks_url` for an
identity provider.

**Nobody can sign in / the first-run password scrolled past**

The password is shown once and is not recoverable. `make dev` writes it to
`.certpilot/dev-admin`.

If it is genuinely lost, the bootstrap runs again whenever **no active account
has a password**, so clearing the one on the bootstrap address is enough:

```sql
update users set password_hash = null where email = 'you@example.com';
```

Restart the core and it will print a new one.

**`gateway TLS configuration is invalid`**

The core needs a client certificate, key and CA for the gateway channel.
`make dev-certs` for development; your own internal CA otherwise. `insecure:
true` works in development mode and is refused in production.

**`no database connection string configured; production mode requires a
database`**

The in-memory store would come up healthy and lose everything it issued. Set
`CERTPILOT_DB_URL`.

**The core starts, but the log says `using the in-memory store with sample
data`**

No connection string was found. Check `CERTPILOT_DB_URL`, `--db`, or
`DATABASE_URL`.

---

## Gateways and CAs

**`could not connect to configured gateway at startup`**

The core dials at startup and retries later; this is a warning, not fatal.
Check the gateway process is running, the port matches, and — if mTLS is on —
that `server_name` matches the name in the gateway's certificate. Dialing by IP
without setting `server_name` fails verification.

**`gateway for <CA> is not connected`**

A CA account references a gateway that has not registered. The core matches by
account **name** first, then by **provider type**. A gateway named `vault` in
the config serves any `vault` account that has no better match.

**`the gateway could not report its issuers`**

The gateway is connected but `GetCAInfo` failed. For Vault, usually a token
without `list` on `<mount>/issuers`. The account still issues fine; only the CA
inventory is affected.

**A CA account validated, and no issuers appeared**

The ACME gateway reports a placeholder — ACME publishes no endpoint listing
issuer certificates — so there is nothing with an expiry to track and the
importer skips it, with a reason in the `outcomes` array. Not an error.

**Vault: `Vault has no role "x" on mount "y"`**

Both are paths rather than names. A mount that does not exist fails the same
way as a role that does not.

**Vault: everything suddenly fails with a message about `notAfter`**

The issuing CA is inside one certificate lifetime of its own expiry, and Vault
refuses to sign past it. This affects every renewal through that mount at once.
Rotate the CA, or shorten requested validity below what the CA has left. See
[gateways/vault.md](gateways/vault.md#the-expiring-issuer).

**Vault: `permission denied` after weeks of working**

A cached token reached its TTL and the credential cannot log in again — which
is the case for `auth_method: token`. Move to `approle` or `kubernetes`.

---

## Issuance and renewal

**`Certificate request blocked by security policy`**

A policy with `BLOCK` severity matched. `GET /api/v1/policies` to see which.

**`could not evaluate security policy, refusing to issue`**

The policy engine could not be consulted — usually the database. Refusing is
deliberate: treating an evaluation failure as "no violations" would silently
disable every policy at once.

**`policy "X" uses rule type "Y", which this build cannot evaluate`**

The policy names a rule this build does not implement. It is reported rather
than skipped for the same reason as above: a policy that cannot be evaluated is
otherwise indistinguishable from one that passed. Either the value predates a
downgrade, or it was written directly into the database — the API only accepts
rule types the engine implements.

**`policy "X" has a rule_config that does not parse`**

The JSON in `rule_config` is malformed. This used to disable the policy in
silence, which meant a typo and compliance looked identical.

**`policy "X" is enabled but sets no …`**

The rule parsed and constrains nothing — `{"max_days": 0}`, an empty
`allowed_key_types`. Somebody believes that policy is protecting them.

**`policy "X" requires approval, but this build has no approval workflow`**

There is no approvals table and no endpoint that can approve or reject. Remove
the policy, or express the constraint as a rule that can be evaluated.

**`"lab" is not one of production, staging, development`**

`environment` is constrained by the schema. Refused at the API rather than
after the CA has signed, because by then a real certificate exists that nothing
has a record of.

**`the <type> gateway returned a private key for a request that carried its own
public key`**

The gateway ignored the CSR and generated its own keypair. Storing that would
give you a certificate on the host that does not match the key in the database,
and both would look fine. Fix the gateway.

**A renewal succeeded and the site still serves the old certificate**

Renewal put a certificate in the database; something has to install it.
Either no deployment binding exists, or the deployment failed, or the far side
was not reloaded. `POST /api/v1/certificates/:id/verify` and check
`GET /api/v1/deployments`.

**Renewals stopped happening entirely**

Check `renewal.scan_interval` is not zero, that jobs are being created
(`GET /api/v1/renewals`), and that they are not all `FAILED` with the same
cause — a CA account whose credential expired fails every renewal identically.

**Renewal jobs pile up in `PENDING`**

The queue is not running or cannot claim. Check the core's log for the queue
starting, and that no other process holds a long transaction on `renewal_jobs`.

---

## Deployment

**`1 target failed. 2 others are waiting behind it.`**

Deliberate. A failing target halts the rest of that certificate's rollout, so a
bad certificate does not march through the estate one node at a time. Fix the
failing target; the queue drains by itself.

**A deployment reports success and the server serves the old certificate**

Success means bytes were accepted, not that they are being served. The
difference is a reload. Check the target's reload command actually ran.

**ACM: a new certificate appeared instead of the one being replaced**

`certificate_arn` was missing from the binding. Importing without one creates a
new certificate no load balancer points at. This is refused at binding time —
if you see it, the binding predates that check.

**F5: the certificate installed and the virtual server did not change**

`name` must be the crypto-store name the client-SSL profile already references.
The deployer replaces what the profile points at; it does not touch the profile.

**A binding cannot be created: "this target needs the private key"**

The target deploys keys and the certificate has none — because the agent holds
it, or because it was imported. Refused at binding rather than failing on every
renewal forever.

---

## The agent

**`enrol` refuses**

An identity already exists in the state directory. Re-enrolling silently would
leave the old record on the core with a key nothing holds.

**Requests rejected with a signature error**

Clock skew beyond five minutes. Check NTP on the host.

**`agent.request_refused` in the activity feed**

The host asked for a name no grant covers. Check the grant's `names` and
`label_selector` — labels come from the enrolment token, not from the host.

**`agent.stale`**

The host stopped reporting. Its certificates will expire silently; this alert
is the only warning you get.

**An install writes the file and the service does not pick it up**

The check command may be failing, in which case the previous bytes are restored
and the reload never runs. `certpilot-agent install --force` and read the
output.

**`agent.key_exposed`**

A private key on that host is group- or world-readable. Usually somebody's `cp`
from years ago.

---

## The dashboard

**The dashboard stops updating but looks healthy**

The most important failure in this document. Almost always a proxy buffering
the SSE stream. `proxy_buffering off` on `/api/v1/events`, in a location block
that comes **before** the generic `/api/` one. See
[operations.md](operations.md#behind-a-reverse-proxy).

**The stream connects and drops after 30 seconds**

An HTTP write timeout on the proxy, or a `WriteTimeout` on any server in front
of the core. The stream is idle between events by design; the core heartbeats
every 15 seconds.

**A display token returns 401**

Check it has not been revoked or expired. Display tokens work on `GET` and the
SSE endpoint only — a 403 on anything else is the design, not a bug.

**Events appear on one browser and not another**

The event broker is in-process. With several core replicas behind a load
balancer, a browser sees events from the replica it is connected to. Configure
sticky sessions on `/api/v1/events`.

---

## Database

**`WARNING 002_crypto_agility.sql has changed since it was applied`**

Expected once on any database migrated before August 2026. Migration 002 was
fixed to be rerunnable, which changed its checksum. It is recorded as applied
and will not re-run.

**`prepared statement "stmtcache_..." already exists`**

A connection pooler in **transaction** mode. pgx caches prepared statements per
connection, and transaction-mode pooling hands the next query to a backend that
has never seen them. Use session mode. See [database.md](database.md).

**`relation "auth.users" does not exist` applying migration 001**

A database built by a CertPilot older than the PostgreSQL-only change, whose
migration 001 created foreign keys into an `auth.users` table. Migration 005
severs them; apply outstanding migrations with `certpilot-core --migrate`.

**`violates check constraint "..._check"`**

A Go constant the schema does not accept — the defect class the store
conformance suite exists to catch. `make test-store` against a real PostgreSQL
reproduces it, and the fix is a migration widening the constraint.

**A list endpoint 500s on one row**

Usually a `NULL` in a column that scans into a non-pointer Go field. pgx fails
the whole query rather than the row. The fix is a `coalesce` in the column
list; see `caColumns` and `certificateColumns` in
[`core/store/postgres.go`](../core/store/postgres.go).
