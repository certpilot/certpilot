# Walkthroughs

The reference pages each answer one question. A
[platform page](../platforms/README.md)
says how nginx reads a certificate; [gateways/vault.md](../gateways/vault.md) says what
the Vault gateway can and cannot do; [deployment.md](../deployment.md) says what a
target is. None of them gets you from an empty CertPilot to a web server serving a
certificate it renewed by itself, because that crosses five of those pages and the
connecting steps live in none of them.

These do. Each one starts from nothing, names every prerequisite before it is needed,
and ends at a check you can run to see whether it worked.

| | What it gets you |
|:--|:--|
| [Vault to nginx](vault-nginx.md) | An internal CA in HashiCorp Vault, issuing to a host that installs and reloads nginx by itself |
| [ACME to nginx](acme-nginx.md) | The same, from a public CA over ACME, with the domain-control challenge solved for you |
| [Windows and IIS](windows-iis.md) | A binding re-pointed by thumbprint, on a platform that reads no certificate files |
| [A CA is expiring](ca-expiry.md) | Finding out before issuance starts failing, and what the failure looks like if you do not |
| [A renewal or deployment failed](failed-renewal.md) | Reading the refusal, finding what is still being served, and recovering |

The first two are alternatives, not a sequence. Read the one whose CA you have.

## What was actually run

Every command on these pages was run, and the output quoted is what came back.
Where something could not be run here, the page says so in place — there are no
silent gaps, and a step nobody exercised is worth less than one that says why.

| | Version |
|:--|:--|
| CertPilot core | `da9423f`, development mode, in-memory store |
| Agent | `certpilot-agent@v0.2.0`, linux/arm64 |
| Vault gateway | `certpilot-gateway-vault@v0.3.0` |
| ACME gateway | `ghcr.io/certpilot/gateway-acme:0.3.0` |
| HashiCorp Vault | 2.0.3, `vault server -dev` |
| ACME CA | Pebble (`ghcr.io/letsencrypt/pebble:latest`), http-01 |
| nginx | 1.29.8 (`nginx:1.29-alpine`), OpenSSL 3.5.8 |
| Host | macOS on aarch64, Docker 29.5.2 under colima |

### What was not run, and why

- **Let's Encrypt staging.** Proving control of a domain means a name that resolves on
  the public internet and a listener the CA can reach. Neither exists here. The ACME
  protocol path — directory, account, order, http-01 challenge, finalize, download — was
  exercised in full against Pebble, which is the ACME server Let's Encrypt builds for
  exactly this purpose. What Pebble cannot tell you is anything about Let's Encrypt's
  rate limits, its account policy or its CAA handling. [ACME to nginx](acme-nginx.md)
  marks those steps where they occur.
- **Windows and IIS.** There is no Windows host here. What can be checked off Windows was
  checked, and it is a short list: the profile's contents, and the agent's refusal to
  install a Windows destination on a machine that is not Windows. The store import, the
  binding and the post-binding handshake were **not** run.
  [Windows and IIS](windows-iis.md) says so at the top rather than at the bottom.
- **dns-01 challenges**, which need a real DNS provider and a token for it.
- **Deployment targets other than the agent** — webhook, AWS ACM, Azure Key Vault, F5.
  Those are [deployment.md](../deployment.md)'s subject and none of them was exercised
  here.

## Three defects these turned up

Walking the paths end to end found things that reading the pages did not. Each one is
linked from the step that hits it:

- [#107](https://github.com/certpilot/certpilot/issues/107), fixed — manually renewing an
  agent-held certificate made CertPilot hold its private key. The core now refuses it.
- [#108](https://github.com/certpilot/certpilot/issues/108), fixed — a SAN-only
  certificate could not be found by name. The name filter now matches the SANs.
- [#109](https://github.com/certpilot/certpilot/issues/109), fixed — a certificate
  shorter than the renewal lead time renewed on every agent cycle. The lead time is now
  bounded by the certificate's own lifetime.

## Before any of them

Two things every walkthrough assumes, and neither is part of the walkthrough itself:

**A running CertPilot.** [evaluation.md](../evaluation.md) is the shortest route to one —
a container stack and a password, in about twenty seconds.
[operations.md](../operations.md#first-run) is the route for something you intend to
keep.

**A credential.** Every route except `/healthz` and the three that sign-in itself needs
is a 401 without one. A password sign-in sets a cookie and returns no token, so the
examples here carry a cookie jar:

```bash
JAR=$(mktemp)
curl -sS -c "$JAR" -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email": "you@example.com", "password": "..."}'
```

`-H "Authorization: Bearer $TOKEN"` substitutes for `-b "$JAR"` anywhere below and is
what a script in a real deployment uses; it needs an identity provider, which an
evaluation does not have. See
[api-reference.md](../api-reference.md#from-the-command-line).

> **Do not run these against a database you care about.** They create CA accounts,
> templates, grants and certificates, and the failure walkthroughs break things on
> purpose.
