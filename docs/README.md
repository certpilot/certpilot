# CertPilot documentation

An open-source PKI and certificate lifecycle manager, built for the central PKI
team inside an organisation.

Public TLS certificate lifetimes are capped at 200 days as of March 2026, 100
days from March 2027 and 47 days from March 2029, under the schedule adopted by
the CA/Browser Forum in [ballot SC-081v3][sc081]. At a 47-day maximum, each
certificate requires renewal approximately eight times per year. These pages
document how to automate that.

[sc081]: https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/

## Start here

| | |
|:---|:---|
| [getting-started.md](getting-started.md) | The first fifteen minutes. No database or cloud account needed |
| [platforms/](https://github.com/certpilot/certpilot-agent/blob/main/docs/platforms/README.md) | Supported platforms: configuration, commands and limitations for each. In `certpilot-agent`, with the agent |
| [architecture.md](architecture.md) | How the pieces fit, and the three decisions that shape everything else |

## Running it

| | |
|:---|:---|
| [configuration.md](configuration.md) | Every setting for every process, and what happens when it is wrong |
| [operations.md](operations.md) | Deploying, migrating, rotating the KEK, backups, upgrades, what to watch |
| [security.md](security.md) | Threat model, secrets at rest, key custody, authentication, and the known gaps |
| [database.md](database.md) | Schema, migrations, PostgreSQL, the conformance suite |
| [troubleshooting.md](troubleshooting.md) | Symptom, cause, fix |

## What it does

| | |
|:---|:---|
| [templates.md](templates.md) | What a kind of certificate looks like, who may ask for one, and the six rungs that decide |
| [monitoring.md](monitoring.md) | CA health, expiry thresholds, alerting, acknowledgement, wall displays |
| [deployment.md](deployment.md) | Getting a renewed certificate to the thing that serves it |
| [agent.md](https://github.com/certpilot/certpilot-agent/blob/main/docs/agent.md) | The host agent, and the private keys CertPilot never sees. In `certpilot-agent`, with the agent |
| [discovery.md](discovery.md) | Network scans, Certificate Transparency, cloud inventory |
| [posture.md](posture.md) | Cryptographic posture, CNSA 2.0, CBOM export |

## Talking to certificate authorities

| | |
|:---|:---|
| [gateways/vault.md](gateways/vault.md) | HashiCorp Vault PKI |
| [writing-a-gateway.md](writing-a-gateway.md) | Adding support for a CA, in any language |
| [compatibility.md](compatibility.md) | Which released gateways this core works with, measured weekly |
| [api-reference.md](api-reference.md) | Every endpoint |

## Elsewhere

| | |
|:---|:---|
| [repositories.md](repositories.md) | What each repository is called, and what holds them together |
| [../README.md](../README.md) | What CertPilot is and why |
| [../ROADMAP.md](../ROADMAP.md) | Current adoption, documentation and security priorities |
| [Implementation history](../ROADMAP-HISTORY.md) | Earlier phases and their reasoning |
| [../SECURITY.md](../SECURITY.md) | Reporting a vulnerability |

---

## Three things worth knowing before you read anything else

**A dashboard that stops updating must look broken, not healthy.** A frozen
screen showing green manufactures false confidence, which is worse than no
screen. Connection state is a first-class element of the UI, the stream
heartbeats, and a dead feed visibly degrades the page.

**Renewal is not done when the certificate is stored.** It is done when the
thing in front of your users is serving it. That is why there is a verifier,
why deployment is a durable job, and why "deployed" and "being served" are
different words here.

**The strongest private key is the one CertPilot never sees.** The agent
generates keys on the host that will serve them and sends only a CSR. There is
no field the key could travel in.
