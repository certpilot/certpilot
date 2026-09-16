<p align="center">
  <img src="brand/logo.svg" alt="" width="76" height="76" />
</p>

<h1 align="center">CertPilot</h1>

<p align="center">
  <strong>Open-source PKI and certificate lifecycle management.</strong><br />
  Watches the CA hierarchy your organisation runs on, and every certificate under it, on one clock.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" /></a>
  <img alt="Go 1.26" src="https://img.shields.io/badge/go-1.26-00ADD8.svg" />
  <img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-orange.svg" />
  <a href="https://certpilot.github.io/certpilot-docs/"><img alt="API reference" src="https://img.shields.io/badge/docs-API%20reference-informational.svg" /></a>
</p>

---

<p align="center">
  <img src="docs/images/dashboard.png" alt="The CertPilot dashboard: a logarithmic expiry horizon with authorities above the axis and certificates below, a critical issuing CA seven days out, and the estate summarised beneath it." width="100%" />
</p>

<p align="center">
  <em>The expiry horizon. One logarithmic axis from now to ten years, authorities
  above and certificates below &mdash; because on a linear axis everything
  expiring inside a quarter collapses into the first two percent of the width.</em>
</p>

---

CertPilot is built for the **central PKI team** — the group that owns the CA
hierarchy and answers for every certificate the organisation serves. One place
to watch every CA and certificate across any authority, public or private, with
automated renewal, CA health monitoring, deployment to the servers that serve
them, policy enforcement, and cryptographic posture reporting.

An expiring issuing CA is the failure that takes down everything it ever
signed, and no amount of certificate automation helps once that has happened.
So CertPilot watches authorities first and certificates second.

> [!WARNING]
> **Early development.** Everything in the
> [implementation status](docs/status.md) has been run end to end against real
> certificate authorities, a real database and real servers. Anything not listed
> there does not exist. Do not run this in production yet.

## Why

Maximum certificate lifetimes are being reduced on a published schedule. Under
the CA/Browser Forum's [ballot SC-081v3][sc081], the maximum validity of a
public TLS certificate fell to **200 days in March 2026**, and falls to **100
days in March 2027** and **47 days in March 2029**. Domain validation reuse
periods are reduced on the same schedule, to 10 days.

At a 47-day maximum, each certificate is renewed approximately eight times a
year. An estate of ten thousand certificates therefore requires around 200
renewals per day. Manual renewal processes that are adequate for 398-day
certificates do not scale to this, and the dates are already set.

[sc081]: https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/

The open-source ecosystem is good at *getting* a certificate — certbot, lego,
cert-manager and step-ca all do it well. What is missing is everything around
it: knowing what you already have, where it is installed, whether it complies
with your policy, and getting the renewed certificate onto the machine that
serves it. That gap is where the commercial tools live, and it is what CertPilot
is aimed at.

## Quick start

Requires Docker. No clone, no toolchain, no database, no cloud account.

```bash
mkdir certpilot-demo && cd certpilot-demo
base=https://raw.githubusercontent.com/certpilot/certpilot/v0.1.1/deploy
curl -O $base/docker-compose.quickstart.yml -O $base/config.quickstart.yaml
CERTPILOT_VERSION=0.1.1 docker compose -f docker-compose.quickstart.yml up -d
```

The frontend is on `:3000` and the API on `:8080`. The first start creates an
administrator and prints its password once:

```bash
docker compose -f docker-compose.quickstart.yml logs core | grep -i password
```

This stack is for evaluating, not deploying, and it says so in its own
comments: the database is a container, the key encryption key is committed to
this repository, and the CA is the self-signed gateway. Mutual TLS on the
core-to-gateway channel is **not** switched off to make the demo easier —
`deploy/docker-compose.yml` is the one to start from for anything real.

### From source instead

Requires Go 1.26+, Node 20+, and PostgreSQL 13+.

```bash
make dev
```

That starts PostgreSQL, creates and migrates a `certpilot_dev` database,
generates a key encryption key once and keeps it, then runs the self-signed
gateway, the API and the frontend in one terminal — and registers the gateway as
a CA account so there is something to issue from. Ctrl-C stops all of it.

The API is on `:8080`, the frontend on `:3000`. Three pages are worth opening
first:

| | |
|:---|:---|
| `/` | The dashboard, with the expiry horizon |
| `/ca-health` | Every CA sorted by urgency |
| `/display` | Fullscreen wall view, for a screen nobody is sitting at |

On first start the core creates an administrator account and prints the password
once; `make dev` also writes it to `.certpilot/dev-admin`. There is no anonymous
mode, including locally.

Export `CERTPILOT_DB_URL` first to point at a database of your own. Without
PostgreSQL the core still starts, on an in-memory store discarded at exit.

[docs/getting-started.md](docs/getting-started.md) goes further: issuing a
certificate, pointing at a real CA, and putting it on a wall.

## What it does

| | |
|:---|:---|
| **Issue** | ACME (RFC 8555) with `dns-01` and `http-01`, wildcards, External Account Binding, and ARI (RFC 9773). HashiCorp Vault PKI. A self-signed gateway for development |
| **Renew** | A durable queue with leases, an attempt log, and backoff that tightens as expiry approaches. Safe on N replicas with no leader election. A renewal deploys itself |
| **Watch** | Scheduled CA health sweeps with expiry thresholds, CRL freshness, and a real OCSP request whose signature and delegation are verified. Live updates over SSE |
| **Find** | Network and CIDR scans, Certificate Transparency logs, and cloud inventory across ACM, Azure Key Vault, Google Cloud and Kubernetes secrets |
| **Deploy** | Signed webhook, host agent, AWS ACM, Azure Key Vault, F5 BIG-IP — in declared waves, so a canary is one target rather than one per worker |
| **Install** | The host agent installs to ten tested platforms by name: nginx, Apache, HAProxy, Caddy, Tomcat, PostgreSQL, MariaDB and MySQL, Postfix, Dovecot, and IIS through the Windows certificate store. Each writes the files or imports to the store, validates the configuration, reloads the service, and rolls back if the reload fails. See **[supported platforms](https://github.com/certpilot/certpilot-agent/blob/main/docs/platforms/README.md)** |
| **Prove** | A hash-chained audit log, CNSA 2.0 conformance per certificate, and CycloneDX 1.6 CBOM export |

Full detail, including what is partial and what does not exist:
**[docs/status.md](docs/status.md)**.

## Architecture

Every CA provider runs as its own process — a *gateway* — speaking gRPC to the
core. You run only the gateways you need, and adding support for a new CA means
writing one, in any language, without touching the core.

```text
                    ┌──────────────────────────┐
                    │     CertPilot Core       │
                    │  REST API · PKI engine   │
                    │  Renewal · Policy        │
                    │  Plugin manager          │
                    └────────────┬─────────────┘
                                 │ mutual TLS
        ┌────────────────────────┼────────────────────────┐
┌───────▼────────┐      ┌────────▼───────┐      ┌─────────▼──────┐
│ ACME gateway   │      │ Vault gateway  │      │ Self-signed    │
│ RFC 8555       │      │ PKI engine     │      │ gateway (dev)  │
└────────────────┘      └────────────────┘      └────────────────┘
```

Each gateway is its own repository, its own release and its own image, and the
core depends on none of them at build time — only on the published contract:

| | |
|:---|:---|
| [`certpilot-gateway-acme`](https://github.com/certpilot/certpilot-gateway-acme) | any RFC 8555 CA |
| [`certpilot-gateway-vault`](https://github.com/certpilot/certpilot-gateway-vault) | HashiCorp Vault PKI |
| [`certpilot-gateway-selfsigned`](https://github.com/certpilot/certpilot-gateway-selfsigned) | a local CA, for evaluating and for internal names |
| [`certpilot-gateway-sdk`](https://github.com/certpilot/certpilot-gateway-sdk) | the contract, plus a conformance probe that checks yours against it |

Separately, a **host agent** runs on the machines where certificates are served,
from [`certpilot-agent`](https://github.com/certpilot/certpilot-agent). It generates its own private keys and never sends
them anywhere — CertPilot cannot produce them and does not claim to. It runs on
Linux and on Windows, where it also installs into the certificate store IIS
reads from; see [where it runs](https://github.com/certpilot/certpilot-agent/blob/main/docs/agent.md#where-it-runs). Its
contract is published too, in
[`certpilot-agent-sdk`](https://github.com/certpilot/certpilot-agent-sdk), so an
agent can be a Kubernetes operator or a Python daemon rather than this binary.

[docs/architecture.md](docs/architecture.md) explains the three decisions the
whole design follows from.

## Documentation

The **[API reference](https://certpilot.github.io/certpilot-docs/)** is
published as its own site, generated from the router so it cannot fall behind
the implementation.

| | |
|:---|:---|
| [Getting started](docs/getting-started.md) | The first fifteen minutes |
| [Architecture](docs/architecture.md) | How the pieces fit and why |
| [Configuration](docs/configuration.md) | Every setting for every process |
| [Operations](docs/operations.md) | Deploying, migrating, KEK rotation, backups |
| [Security](docs/security.md) | Threat model, key custody, known gaps |
| [Monitoring](docs/monitoring.md) | CA health, alerting, wall displays |
| [Deployment](docs/deployment.md) | Getting a renewed certificate to what serves it |
| [The agent](https://github.com/certpilot/certpilot-agent/blob/main/docs/agent.md) | Host agent, and the keys CertPilot never sees |
| [Supported platforms](https://github.com/certpilot/certpilot-agent/blob/main/docs/platforms/README.md) | Configuration, commands and limitations for each platform |
| [Discovery](docs/discovery.md) | Network scans, CT logs, cloud inventory |
| [Posture](docs/posture.md) | CNSA 2.0 scoring and CBOM export |
| [Vault gateway](docs/gateways/vault.md) | HashiCorp Vault PKI in depth |
| [Writing a gateway](docs/writing-a-gateway.md) | Adding a CA, in any language |
| [Database](docs/database.md) | Schema, migrations, PostgreSQL, the conformance suite |
| [Troubleshooting](docs/troubleshooting.md) | Symptom, cause, fix |
| [Implementation status](docs/status.md) | What is built, what is partial, what is not |
| [Roadmap](ROADMAP.md) | Now, Next and Later: adoption, documentation and security |
| [Implementation history](ROADMAP-HISTORY.md) | Earlier phases and the reasoning behind them |

[docs/README.md](docs/README.md) is the index.

## Security

Certificate private keys and CA credentials are encrypted before they reach the
database, using AES-256-GCM envelope encryption with a context string bound in
as additional authenticated data — so a ciphertext lifted from one column and
pasted into another fails to decrypt rather than quietly succeeding.

The core-to-gateway channel is mutually authenticated TLS 1.3. Agents sign every
request with Ed25519, and a replayed request is refused. Roles are held in
CertPilot's own table keyed on `(issuer, subject)`, so an identity provider says
who you are and CertPilot says what you may do; a claim in a token cannot
promote anyone.

Production mode refuses anonymous access, an insecure gateway channel, a
wildcard CORS origin, a missing auth method, and a missing database — by
refusing to start, not by warning.

[docs/security.md](docs/security.md) has the threat model and an honest list of
what is not covered. Report vulnerabilities per [SECURITY.md](SECURITY.md) —
please do not open a public issue.

## Development

```bash
make build        # every binary
make test         # every module
make test-race    # under the race detector
make test-store   # the store conformance suite, against a real PostgreSQL
make lint         # gofmt, go vet, staticcheck
make routes       # regenerate the API route table after changing the router
```

This is a Go workspace with two modules — `core` and `pkg` — so `go build ./...`
from the root does not work. Build from inside a module, or use the `make`
targets.

Neither the gateways nor the agent are built here. `make dev` and the compose
files fetch the gateways from their own releases, and `make agent-lifecycle`
fetches a released agent and runs the whole lifecycle against this core — which
is the same thing a gateway or an agent somebody else wrote would do.

**Go** 1.26 · Gin · pgx · gRPC · PostgreSQL · **Vue 3** · TypeScript ·
Tailwind 4 · Chart.js

## Contributing

Bug reports from running this against a real certificate authority are the most
useful thing right now, followed by gateways for CAs that do not have one yet —
Google Cloud CAS, AWS Private CA, DigiCert and Sectigo are all unwritten.

See [CONTRIBUTING.md](CONTRIBUTING.md). Open an issue before writing anything
substantial; small fixes can go straight to a pull request.

## License

[Apache 2.0](LICENSE).
