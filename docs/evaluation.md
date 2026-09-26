# Evaluate CertPilot

One container stack, a certificate you issued yourself, and a way to put it all
back. No clone, no Go toolchain, no database to provision, no account with any
certificate authority.

This is the route to take first. [Getting started](getting-started.md) is the
same product built from source, which is what you want when you are changing
it rather than deciding about it.

> **This stack is for evaluating and nothing else.** The database is a
> container, the key encryption key is committed to the CertPilot repository,
> and the CA is a self-signed gateway that nothing trusts. Every one of those
> is stated in `deploy/docker-compose.quickstart.yml` rather than hidden, and
> each is a thing you must not do in a pilot. What is *not* given up is mutual
> TLS on the core-to-gateway channel — a product that switches that off to make
> its own demo easier is making an argument it does not believe.

## What it costs

Measured on the versions in the table below — Apple Silicon, 4 CPUs, 6 GB to
the Docker VM, a home connection, nothing cached:

| | |
|:--|:--|
| Fetch two files | ~1s |
| `up -d`, cold, pulling every image | ~19s |
| Core answering `/healthz`, console serving | under 1s after that |
| **Cold start to a usable console** | **~20s** |
| Sign in, connect the CA, issue one certificate | under 1s of API time |

Your first run will be slower if your connection is: about 160 MB of images are
pulled. Nothing here claims how long *you* will take, because that is reading
time and this has not been measured with a stopwatch on anybody.

## Prerequisites

Docker with Compose v2. That is the whole list.

```bash
docker compose version    # v2.x
```

Ports `3000` and `8080` need to be free on the host.

## 1. Start it

```bash
mkdir certpilot-eval && cd certpilot-eval
base=https://raw.githubusercontent.com/certpilot/certpilot/v0.2.0/deploy
curl -O $base/docker-compose.quickstart.yml -O $base/config.quickstart.yaml
CERTPILOT_VERSION=0.2.0 GATEWAY_VERSION=0.4.0 \
  docker compose -f docker-compose.quickstart.yml up -d
```

**Set both versions.** The compose file defaults the gateway independently of
the core, and a release pins only what it shipped with — so setting
`CERTPILOT_VERSION` alone leaves you on whichever gateway that file was written
against, which is not necessarily the current one.

Expect, in order: `postgres` healthy, `certs` exited 0, `migrate` exited 0,
`gateway-selfsigned` healthy, `core` healthy, `frontend` started. Migrations run
as their own step rather than on startup; that rule does not bend for a demo.

These are the versions this page was written and measured against:

| Component | Version |
|:--|:--|
| `ghcr.io/certpilot/core` | 0.2.0 |
| `ghcr.io/certpilot/frontend` | 0.2.0 |
| `ghcr.io/certpilot/gateway-selfsigned` | 0.4.0 |
| `postgres` | 17-alpine |

## 2. Sign in

The core creates an administrator on first start and prints the password once.
There is no anonymous mode and no default password.

```bash
docker compose -f docker-compose.quickstart.yml logs core | grep -A4 'first run'
```

```
┌─ CertPilot: first run ─────────────────────────────────────────────
│ An administrator account has been created.
│
│   email:    you@example.com
│   password: <generated, shown once>
```

Open `http://localhost:3000` and sign in, or keep a session for the commands
below:

```bash
JAR=$(mktemp)
curl -sS -c "$JAR" -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email": "you@example.com", "password": "<the one above>"}'
```

Every command from here carries `-b "$JAR"`. Without it the answer is 401.

## 3. Connect a certificate authority

The stack starts the self-signed gateway and registers it, which you can see:

```bash
curl -sS -b "$JAR" localhost:8080/api/v1/gateways
```

A gateway is a process CertPilot can talk to. A **CA account** is permission to
issue through one, and the quickstart does not create it for you — so this is
the step between a console that looks finished and one that can do anything.

```bash
curl -sS -b "$JAR" -X POST localhost:8080/api/v1/ca-accounts \
  -H 'Content-Type: application/json' -d '{
    "name": "selfsigned-eval",
    "provider_type": "selfsigned",
    "gateway_addr": "gateway-selfsigned:9091",
    "server_name": "localhost",
    "config": {"validity_days": 90}
  }'
```

`gateway_addr` is the compose service name, because the core dials it on the
compose network. `server_name` is **`localhost`** and not the service name: the
mTLS material is generated on first run with `localhost` in its SAN, so the
name the certificate is checked against and the name dialled are different
here. Getting this wrong fails hostname verification after a 15-second dial
timeout, which reads like the gateway being down.

The response is wrapped: the account id is at `.data.id`.

## 4. Issue a certificate

```bash
curl -sS -b "$JAR" -X POST localhost:8080/api/v1/certificates \
  -H 'Content-Type: application/json' -d '{
    "common_name": "eval.example.local",
    "sans": ["www.eval.example.local"],
    "ca_account_id": "<id-from-step-3>",
    "key_type": "ECDSA",
    "key_size": 256,
    "auto_renew": true
  }'
```

```
status            ISSUED
common_name       eval.example.local
days_remaining    89
key_type/size     ECDSA 256
```

89 rather than 90 because the gateway backdates `not_before` slightly, which
real CAs also do. The certificate is in the response; **the private key is
not** — that is a separate, admin-only call which writes an audit record:

```bash
curl -sS -b "$JAR" localhost:8080/api/v1/certificates/<id>/private-key
```

## 5. Renew it

```bash
curl -sS -b "$JAR" -X POST localhost:8080/api/v1/certificates/<id>/renew
```

`202` with a job id, because renewal is a durable queued job rather than a
blocking call — which is what lets it survive a replica dying mid-renewal.

```bash
curl -sS -b "$JAR" localhost:8080/api/v1/renewals/<job-id>
```

It reaches `SUCCEEDED` in a few seconds here. The certificate then shows
`renewal_count: 1` and a new serial.

The renewed certificate keeps the 90 days the account asked for, so
`days_remaining` is 89 again. Before core v0.2.0 and gateway v0.4.0 a renewal
asked for no lifetime, came back with the gateway's 365-day default, and raised
no finding ([#102](https://github.com/certpilot/certpilot/issues/102)).

## 6. Check the audit chain

Every action above was recorded, and the record can be checked rather than
trusted:

```bash
curl -sS -b "$JAR" localhost:8080/api/v1/audit/verify
```

```json
{"intact": true, "verified": 4, "unchained": 0, "first_seq": 1, "last_seq": 4}
```

The chain is HMAC-linked with a subkey of the key encryption key, so somebody
holding only the database can alter a row and cannot forge a tag that agrees
with it.

## 7. Put it back

```bash
docker compose -f docker-compose.quickstart.yml down -v
```

About a second. `-v` removes the database volume and the generated mTLS
material with it, so the next `up -d` is a first run again, with a new
administrator password.

## What this evaluation does not show

Stated rather than implied, because each one is a real part of the product that
this route cannot reach:

- **Installing a certificate on a server.** That is the host agent's job, and
  the agent is not in this stack — it runs on the machine serving the
  certificate, not beside the control plane. See [the host agent](agent.md).
- **Verifying what is actually being served.** `POST /certificates/:id/verify`
  opens a TLS connection to an endpoint and compares fingerprints, and nothing
  here is serving anything.
- **A real CA.** The self-signed gateway needs no account anywhere, which is
  exactly why a first run can use it and exactly why nothing trusts what it
  signs. For ACME against Let's Encrypt staging or a Vault PKI mount, see
  [Getting started](getting-started.md#_5-issue-from-a-real-ca).
- **Anything about durability or scale.** One container each, one replica, a
  database whose volume is as durable as your laptop.

## From evaluation to a pilot

The gap is deliberate and it is not small. Every item below is something this
stack does the wrong way on purpose:

| Evaluation | A pilot needs |
|:--|:--|
| KEK committed to a public repository | A generated key, held outside the image — see [operations](operations.md#rotating-the-kek) |
| PostgreSQL as a container beside the app | A database you back up and can restore |
| Generated administrator password, `development` mode | An identity provider via `auth.jwks_url`, and `mode: production` |
| Self-signed gateway | ACME or Vault, with a CA account that has credentials |
| mTLS material generated on first run, CA key beside the certificates | Material you issued and keep |

`deploy/docker-compose.yml` and `deploy/config.production.example.yaml` are the
files to start from for that, and [operations](operations.md) is the page.

## Whether it is the right tool at all

[How CertPilot compares](comparison.md) puts it beside Keyfactor Command, Palo
Alto Networks' Next-Generation Trust Security and DigiCert Trust Lifecycle
Manager. It uses only what each vendor documents, dates every source, and says
when one of them fits better than this does.
