# Operations

Running CertPilot, and what to do when something goes wrong.

- [First run](#first-run)
- [Migrations](#migrations)
- [Deploying](#deploying)
- [Running more than one replica](#running-more-than-one-replica)
- [Rotating the KEK](#rotating-the-kek)
- [Backups and restore](#backups-and-restore)
- [Upgrading](#upgrading)
- [Health and observability](#health-and-observability)
- [Routine tasks](#routine-tasks)

---

## First run

Four things, in order.

### 1. Generate a KEK

```bash
make generate-kek
```

Store it somewhere durable **before** issuing anything. Every certificate
private key and CA credential is encrypted with it, and there is no recovery
path. An environment variable injected from a secret manager is the minimum;
a `.env` file on one laptop is not a plan.

```bash
export CERTPILOT_KEK='...'
```

### 2. Point at a database

```bash
export CERTPILOT_DB_URL='postgres://user:pass@host:5432/certpilot?sslmode=require'
```

Any PostgreSQL 13 or later — the schema uses `gen_random_uuid()`, which is built in from 13. Tested against 17. You run the server; CertPilot does not provision one — see
[database.md](database.md) for the pooler note, which matters.

Without a connection string the core runs on the in-memory store with sample
data, which is the right way to spend ten minutes on it and the wrong way to
run it.

### 3. Apply migrations

```bash
make migrate
```

### 4. Generate the gateway channel material

```bash
make dev-certs
```

This writes development mTLS material into `.certpilot/pki/`. **In production,
issue the core and each gateway a certificate from your own internal CA** and
point `--tls-ca` at that CA. The development material is a convenience for
getting the shape right, not something to deploy.

---

## Migrations

Numbered SQL files in [`migrations/`](../migrations), applied in order, each
recorded in `schema_migrations` with a checksum.

```bash
make migrate                                     # uses CERTPILOT_DB_URL
make migrate DB='postgres://...'                 # explicit
docker compose -f deploy/docker-compose.yml --profile migrate run --rm migrate
```

Three rules the migrator enforces or expects:

**They are append-only.** A file that has been applied is never edited. To
change something, add a migration.

**They are rerunnable.** Every statement is `IF NOT EXISTS`, or guarded on the
catalogue. PostgreSQL has no `ADD CONSTRAINT IF NOT EXISTS`, so constraints are
wrapped in a `do $$ … pg_constraint … $$` block. Migration 002 was not
rerunnable for twenty-three migrations and nothing noticed until a conformance
suite applied the whole schema twice.

**A changed checksum is reported, not re-run.** If a file changes after being
applied, the migrator warns and moves on:

```
WARNING  002_crypto_agility.sql has changed since it was applied to this database.
         It was not rerun. Reconcile the difference with a new migration.
```

> This warning is currently expected once on any database migrated before
> August 2026: migration 002 was fixed to be rerunnable, which changed its
> checksum. It is recorded as applied and will not re-run. See
> [database.md](database.md).

The server never applies migrations itself. A schema change is something an
operator runs, not a side effect of a replica restarting during a deploy.

---

## Deploying

### Docker Compose

```bash
cp deploy/compose.env.example deploy/.env               # edit it
cp deploy/config.production.example.yaml deploy/config.production.yaml
make dev-certs                                          # or your own CA material
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
```

Four containers: core, ACME gateway, Vault gateway, frontend. The database is
deliberately **not** in the compose file — CertPilot stores private keys, and
running its store as an ephemeral container beside the app is how an evaluation
becomes a deployment nobody meant to make.

> The compose stack and Dockerfiles were repaired in this pass — they pinned
> Go 1.24 against a workspace requiring 1.26.6, so no image had built since the
> version bump, and the core had no `CERTPILOT_KEK` so it could not have
> started against a database. **They have not been verified by an actual
> build**, because no container runtime was available on the machine where
> they were fixed. Treat the first `docker compose build` as the test.

### Systemd

The core is a single static binary with no runtime dependencies beyond CA
certificates.

```ini
[Unit]
Description=CertPilot Core
After=network-online.target

[Service]
Type=simple
User=certpilot
Environment=CERTPILOT_KEK=...
Environment=CERTPILOT_DB_URL=...
ExecStart=/usr/local/bin/certpilot-core --config=/etc/certpilot/config.yaml
Restart=always
RestartSec=5

# The core needs to read its config and mTLS material and nothing else.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadOnlyPaths=/etc/certpilot

[Install]
WantedBy=multi-user.target
```

Prefer `EnvironmentFile=` with `0600` permissions over inline `Environment=`
for the KEK — the latter is visible in `systemctl show`.

Each gateway is the same shape on its own port.

### Behind a reverse proxy

One thing matters and it is easy to get wrong: **the SSE endpoint must not be
buffered.**

```nginx
location /api/v1/events {
    proxy_pass http://core:8080/api/v1/events;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 24h;
    chunked_transfer_encoding off;
}
```

Without `proxy_buffering off`, nginx holds the stream until a buffer fills. A
dashboard that has stopped updating then looks merely quiet — which on a wall
display is the worst available failure, because it reports "no problems"
precisely when the tool has stopped being able to see problems. The shipped
[`deploy/docker/nginx.conf`](../deploy/docker/nginx.conf) has this block, and
it must come *before* the generic `/api/` one.

The core also sends `X-Accel-Buffering: no` on that route as a second line of
defence.

---

## Running more than one replica

Run as many as you like. There is no leader election and none is needed.

- Enqueues collide on a partial unique index with `ON CONFLICT DO NOTHING`, so
  two schedulers noticing the same due certificate produce one job.
- Claims use `SELECT … FOR UPDATE SKIP LOCKED`, so two workers claiming produce
  one execution.
- A worker that dies mid-job holds a lease that expires; another picks it up.

This is deliberate. A leader has a failover window during which nothing renews,
and for a system whose purpose is that certificates do not expire, that is the
wrong failure mode.

What is *not* shared between replicas: the SSE event broker is in-process, so a
browser sees events from the replica it is connected to. Events are published
on the replica doing the work, so an alert is raised once, by whichever replica
ran the job — but a dashboard pinned to a different replica will not see that
event until it refreshes its snapshot. Sticky sessions on `/api/v1/events` are
worth configuring if you run several.

---

## Rotating the KEK

The KEK can be rotated without downtime, because each envelope records which
key sealed it.

**1. Generate the new key and keep the old one as retired.**

```bash
export CERTPILOT_KEK='<new key>'
export CERTPILOT_KEK_RETIRED='<old key>'
```

Restart the core. From this point new writes are sealed under the new key, and
reads still work for everything sealed under the old one.

**2. Re-seal existing records.** Anything read and written back is re-sealed
automatically — `NeedsRotation` reports whether a ciphertext came from a
retired key. Records that are never written are never re-sealed, so a
deliberate pass is needed for full coverage. There is no bulk re-seal command
yet; the practical approach is to touch each CA account and deployment target
through the API.

**3. Drop the retired key** once nothing reports needing rotation.

`CERTPILOT_KEK_RETIRED` accepts a comma-separated list, so more than one
generation can be in flight.

> Removing a retired key while ciphertext still depends on it makes that
> ciphertext unreadable. There is no warning at startup, because the core
> cannot know what it will be asked to decrypt.

---

## Backups and restore

Back up the database. That is the whole of the state.

```bash
pg_dump "$CERTPILOT_DB_URL" --format=custom --file=certpilot-$(date +%F).dump
```

**A backup without the KEK is not a backup.** The dump contains ciphertext for
every private key and CA credential. Store the KEK separately — a backup and
the key to it in the same place is one compromise, not two.

Restore:

```bash
pg_restore --dbname="$CERTPILOT_DB_URL" --clean --if-exists certpilot-2026-08-22.dump
export CERTPILOT_KEK='<the key that sealed it>'
```

Then check the estate reconciles: the CA health sweep and the renewal scheduler
both run on startup, so a restored database converges without intervention.

What is *not* in the database and needs its own handling:

| | |
|:---|:---|
| The KEK | Secret manager |
| ACME account keys | The ACME gateway's `--state-dir`. Losing them means re-registering with the CA |
| Agent identities | Each agent's `--state-dir` on its own host. Losing one means re-enrolling that host |
| mTLS material | Reissuable from your internal CA |

---

## Upgrading

```bash
git pull
make build
make migrate          # if the release adds migrations
# restart the core, then the gateways
```

Order matters in one direction only: **migrate before starting the new core.**
The core assumes its schema exists. Gateways are independent and can be
restarted whenever — the core reconnects and re-negotiates capabilities.

Rolling back a schema change is not supported. Migrations are append-only and
there are no down-migrations, because a down-migration that drops a column
drops the data in it, and the moment somebody wants one is the moment that data
matters. Roll forward.

---

## Health and observability

### Endpoints

```
GET /healthz                      the core is up. Says nothing about internals
GET /api/v1/gateways              per-gateway connection state and capabilities
POST /api/v1/ca-accounts/:id/health   ask one CA account's gateway to check its CA
GET /api/v1/dashboard/stats       counts, by status
GET /api/v1/events                the live stream (SSE)
```

`/healthz` is deliberately uninformative — it is a liveness probe, and a
liveness probe that reports internals is an unauthenticated information leak.

### What to watch

| Signal | Where | Means |
|:---|:---|:---|
| CAs in `CRITICAL` | `GET /pki/authorities?status=CRITICAL` | A CA is inside 30 days. Everything it signed dies with it |
| Renewal jobs `FAILED` | `GET /api/v1/renewals` | A CA is refusing, or a challenge is failing |
| Deployment jobs `FAILED` | `GET /api/v1/deployments` | A certificate renewed and did not reach the server |
| `verification_attempts` climbing | certificate detail | The new certificate is not being served. The renewal is not done |
| Agents not reporting | `GET /api/v1/agents` | A host has stopped; its certificates will expire silently |
| `notification.failed` in the audit log | `GET /dashboard/activity?actions=notification.failed` | Alerts are not reaching anyone |

The last one deserves attention. A monitoring system whose alerting is broken
is worse than none, because it is trusted.

### Logs

Structured via `log/slog`. `logging.format: json` for ingestion.

The request logger **never writes the query string**, because display tokens
travel in it. If you add your own access logging at the proxy, do the same.

---

## Routine tasks

### Connect a CA

```bash
curl -X POST localhost:8080/api/v1/ca-accounts -H 'Content-Type: application/json' -d '{
  "name": "vault-issuing", "provider_type": "vault",
  "gateway_addr": "gateway-vault:9093",
  "config": {"address": "https://vault.internal:8200", "mount": "pki-int",
             "role": "web", "auth_method": "approle",
             "role_id": "...", "secret_id": "..."}}'
```

The configuration is validated against the CA before it is stored, and the
response carries warnings worth reading — see [gateways/vault.md](gateways/vault.md).
The CAs behind the account are imported at the same time.

### Import the CAs behind an account

```bash
curl -X POST localhost:8080/api/v1/pki/authorities/import
curl -X POST 'localhost:8080/api/v1/pki/authorities/import?account=vault-issuing'
```

Runs automatically every 12 hours and on account creation. This is for the
moment after somebody has rotated an issuer.

### Force a renewal

```bash
curl -X POST localhost:8080/api/v1/certificates/$ID/renew
```

Enqueues a job; the queue runs it. The response is the job, not the
certificate.

### Check what is actually being served

```bash
curl -X POST localhost:8080/api/v1/certificates/$ID/verify
```

Opens a TLS connection to the endpoint and compares the fingerprint being
served against the one stored. This is the difference between "renewed" and
"renewed and in use".

### Revoke

```bash
curl -X POST localhost:8080/api/v1/certificates/$ID/revoke \
  -H 'Content-Type: application/json' \
  -d '{"reason": 1}'
```

Admin only. **The CA is told first, and the record changes only if the CA
agreed.** Every failure on this path — an unreachable gateway, a CA that
declines, a certificate CertPilot holds no copy of — leaves the record exactly
as it was and says so, because a row reading `REVOKED` beside a certificate
that still answers handshakes is the one outcome worse than not revoking at
all.

`reason` is required rather than defaulted. "Unspecified" is a legitimate
answer, but it should be one somebody chose: the reason is what tells the next
reader whether a key was compromised or a service was simply retired.

| Code | Reason |
|:---|:---|
| `0` | `unspecified` |
| `1` | `keyCompromise` |
| `3` | `affiliationChanged` |
| `4` | `superseded` |
| `5` | `cessationOfOperation` |
| `9` | `privilegeWithdrawn` |

Anything else is a 400 that lists these. RFC 5280 defines more codes; CertPilot
accepts the subset a CA will act on.

**What can refuse it:**

| Response | Meaning |
|:---|:---|
| `400` | No reason, or one not in the table |
| `400` | CertPilot holds no copy of the certificate, so it cannot be shown to a CA — usually a discovered certificate. Revoke it at the issuing CA |
| `400` | Not bound to a CA account, so there is nowhere to send the revocation |
| `404` | No such certificate |
| `409` | Already revoked. The CA is not asked a second time |
| `502` | The gateway is not connected, or the CA declined. **Nothing has been changed** |

The one dangerous outcome is a `500` reading "the CA has revoked this
certificate, but CertPilot could not record it". The certificate is genuinely
dead; the record is wrong until the write succeeds. It is stated plainly rather
than reported as a generic failure because the usual problem is the opposite
way round.

Revocation is audited (`certificate.revoked`, naming the actor, reason and
fingerprint) and published on the event stream as `cert.revoked`, so a wall
display reflects it without waiting for a sweep.

### Delete — not a substitute for revoking

`DELETE /api/v1/certificates/:id` deletes the *record*. It does not revoke.

It refuses with a `409` on a certificate that is still live, and names the
revoke endpoint in the error. Expired and already-revoked certificates delete
without argument: the first authenticates nothing, and for the second the CA
has already been told.

`?forget=true` is the deliberate override, for a certificate you want CertPilot
to stop tracking while it remains valid — an estate you no longer own, say. It
is recorded in the audit log as the choice it is.

### Take a CA out of the inventory

```bash
curl -X DELETE localhost:8080/api/v1/pki/authorities/$ID
```

Admin only. Note that a gateway-imported CA will come back on the next import
sweep if it is still offered by its mount — which is usually what you want. To
stop tracking it, remove the CA account.
