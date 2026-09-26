# The ACME gateway

Issuing from any CA that speaks [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)
— Let's Encrypt, ZeroSSL, Buypass, Google Trust Services, or an internal one.

Implemented by
[`certpilot-gateway-acme`](https://github.com/certpilot/certpilot-gateway-acme),
against the `provider.v1` contract in
[`certpilot-gateway-sdk`](https://github.com/certpilot/certpilot-gateway-sdk).

Two things shape how this gateway is used, and both are properties of ACME
rather than of CertPilot.

**The CA has to be convinced you control the name.** Every issuance is preceded
by a challenge, and which challenge you can satisfy decides what you can ask
for — wildcards are `dns-01` and nothing else.

**The CA may tell you when to renew.** A CA that publishes renewal information
([RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773), ARI) is saying when
*it* wants the certificate replaced, which is how a mass-revocation event gets
drained gradually instead of every client renewing at once. This gateway
reports the window; the core picks a random instant inside it.

- [What it supports](#what-it-supports)
- [Connecting an account](#connecting-an-account)
- [Challenges](#challenges)
- [Directories and rate limits](#directories-and-rate-limits)
- [External Account Binding](#external-account-binding)
- [Credentials and the security boundary](#credentials-and-the-security-boundary)
- [Limitations](#limitations)
- [Running and checking it](#running-and-checking-it)

---

## What it supports

| | |
|:--|:--|
| Challenges | `dns-01` (Cloudflare, or any webhook you write), `http-01` |
| Wildcards | Yes, over `dns-01` only — ACME permits no other |
| Key types | RSA, ECDSA |
| Revocation | Yes. Already-revoked is treated as success |
| ARI | RFC 9773 renewal windows, honoured and reported upward |
| `GetCAInfo` | Yes, but not issuers — see [limitations](#limitations). It reports who the CA says it is and which profiles the directory currently advertises, read live |
| `DescribeProfile` | No — answers `Unimplemented`, which is a supported answer under the v0.3.0 contract |

`DescribeProfile` answering `Unimplemented` is reported rather than stubbed, so
the core knows not to ask again.

---

## Connecting an account

Start the gateway on `:9092`:

```bash
make run-gateway-acme
```

Then register it. The walkthrough with a real domain is in
[Getting started](../getting-started.md#_5-issue-from-a-real-ca); this page is the
reference for what goes in `config`.

> These examples carry `-b "$JAR"`, a cookie jar from signing in. There is no
> anonymous mode, so a command without a credential is a 401. See
> [Authentication](../api-reference.md#from-the-command-line) for the one-liner
> that fills it, or substitute `-H "Authorization: Bearer $TOKEN"`.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/ca-accounts \
  -H 'Content-Type: application/json' -d '{
    "name": "letsencrypt-staging",
    "provider_type": "acme",
    "gateway_addr": "localhost:9092",
    "server_name": "localhost",
    "config": {
      "directory_url": "letsencrypt-staging",
      "email": "you@example.com",
      "challenge": "dns-01",
      "dns_provider": "cloudflare",
      "dns_config": {"api_token": "..."}
    }
  }'
```

The configuration is validated against the real directory before it is stored,
so an unreachable directory or a token the DNS provider rejects is reported now
rather than during a renewal months from now.

| Key | |
|:--|:--|
| `directory_url` | A shorthand (`letsencrypt-staging`, `letsencrypt`, `zerossl`, `buypass`, `google`) or a full directory URL |
| `email` | The ACME account contact. Where expiry warnings from the CA go |
| `challenge` | `dns-01` or `http-01` |
| `dns_provider` | `cloudflare` or `webhook`, for `dns-01` |
| `dns_config` | Provider-specific. `api_token` for Cloudflare; `url` plus `bearer_token` and/or `signing_secret` for the webhook |
| `http01_bind_addr` | Where the built-in listener binds, for `http-01` |
| `eab_kid` / `eab_hmac_key` | External Account Binding, where the CA requires it |

---

## Challenges

**`dns-01`** proves control by publishing a TXT record at
`_acme-challenge.<domain>`. It is the only challenge that can obtain a wildcard,
and the only one that works for a name whose host is not reachable from the
internet.

Cloudflare is built in and needs a token with `Zone:Read` and `DNS:Edit`. For
every other provider there is a webhook solver, so CertPilot does not have to
carry an implementation for every DNS provider that will ever matter — see
[dns-01 solvers](../getting-started.md#dns-01-solvers) for the request shape and
the HMAC signature.

**`http-01`** proves control by serving a token at
`http://<domain>/.well-known/acme-challenge/<token>` on port 80. Either let the
gateway bind 80, or run it on a high port and have your existing reverse proxy
forward that one path to it. It cannot obtain a wildcard, and it needs the name
to resolve to the machine running the gateway.

---

## Directories and rate limits

`-directory` defaults to **Let's Encrypt staging**, deliberately. The production
endpoint has rate limits that punish a misconfiguration for a week, and staging
is where you find that out for free. A CA account names its own directory and
overrides the flag.

Move to production by changing `directory_url` to `letsencrypt`, and do it only
once staging has issued you a certificate.

Staging certificates chain to a root nothing trusts. That is the point — they
prove the pipeline without consuming a production quota.

---

## External Account Binding

ZeroSSL, Google Trust Services and SSL.com require the ACME account to be bound
to an account you already hold with them. Put the key id and HMAC key the CA
gave you in `eab_kid` and `eab_hmac_key`.

> **This path is marked 🧪 in [implementation status](../status.md).** It is
> built and unit-tested, and nothing in CertPilot's CI has ever contacted
> ZeroSSL, Google Trust Services or SSL.com — no test here would tell you if it
> stopped working. Try it against one account before you depend on it for an
> estate.

---

## Credentials and the security boundary

**The gateway process holds no credential of its own.** The ACME account key
and the DNS provider token live on the CA account, are sealed with the key
encryption key before they reach the database, and arrive in `provider_config`
on each call. A gateway that could issue on its own would be a gateway worth
stealing.

`provider_config` is never logged, by the core or by any gateway. That is a
requirement of the contract, not a convention.

The core-to-gateway channel is mutually authenticated TLS 1.3 by default,
because it carries CSRs, private keys and CA credentials. `-insecure` exists for
loopback work and warns loudly.

---

## Limitations

- **No issuer inventory.** ACME publishes no endpoint listing a CA's issuer
  certificates — they arrive with each issuance instead. So `GetCAInfo` answers
  with the CA's identity and its advertised profiles but no issuers, and
  ACME-signed certificates do not populate the CA hierarchy view the way
  Vault-signed ones do. The certificates themselves are inventoried normally.
- **No profile description.** `DescribeProfile` answers `Unimplemented`. An
  unadvertised ACME profile is still refused at template-save time, checked
  against the directory's live metadata rather than a list compiled into the
  gateway — Let's Encrypt withdrew its `shortlived` profile in July 2026, which
  is what a compiled-in list gets wrong the moment it ships.
- **Wildcards need `dns-01`.** Not a CertPilot restriction; ACME does not permit
  a wildcard over `http-01`.
- **Issuance is not exercised in CI.** The conformance job runs the contract
  checks, and its issuance checks are reported *skipped* rather than passed,
  because a CA has to validate a domain CI does not control. See
  [compatibility](../compatibility.md).

---

## Running and checking it

```bash
make run-gateway-acme        # :9092, staging by default
```

```
-port         9092
-directory    letsencrypt-staging | letsencrypt | zerossl | buypass | google | <url>
-insecure     serve without TLS. Loopback only
-tls-cert / -tls-key / -tls-ca
```

Released as `ghcr.io/certpilot/gateway-acme` on `linux/amd64` and
`linux/arm64`. Images publish on a tag and never on a merge, and the Go module
is tagged in step, so
`go run github.com/certpilot/certpilot-gateway-acme/cmd@v0.3.0` runs the code
the image contains. Pin it anyway.

To check a build against the contract — including one you wrote yourself:

```bash
go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@v0.4.0 \
    -addr localhost:9092 -insecure
```

[Writing a gateway](../writing-a-gateway.md) is the guide for implementing the
contract for a CA that has no gateway yet.
