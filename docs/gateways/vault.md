# The Vault gateway

Issuing from a HashiCorp Vault PKI secrets engine — the private CA most
organisations running their own PKI already have.

Two things make this gateway different from an ACME one, and both shape how it
is used.

**Vault answers questions about itself.** It will name its issuers, hand over
their certificates and say when they expire. So `GetCAInfo` is real here, and
the CA that signs your estate ends up in the same inventory as the estate.

**Vault refuses to sign past its issuer's expiry.** Not truncates — refuses.
The day an issuing CA comes within one certificate lifetime of expiring, every
renewal through it fails at once.

- [Connecting an account](#connecting-an-account)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [What the warnings mean](#what-the-warnings-mean)
- [Issuance](#issuance)
- [Revocation and status](#revocation-and-status)
- [Issuers in the inventory](#issuers-in-the-inventory)
- [A lab to try it against](#a-lab-to-try-it-against)

---

## Connecting an account

```bash
make run-gateway-vault      # or the container; port 9093
```

> This example carries `-b "$JAR"`, a cookie jar from signing in. There is no
> anonymous mode, so a command without a credential is a 401. See
> [Authentication](../api-reference.md#from-the-command-line) for the one-liner
> that fills it, or substitute `-H "Authorization: Bearer $TOKEN"`.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/ca-accounts -H 'Content-Type: application/json' -d '{
  "name": "vault-issuing",
  "provider_type": "vault",
  "gateway_addr": "localhost:9093",
  "server_name": "localhost",
  "config": {
    "address": "https://vault.internal:8200",
    "mount": "pki-int",
    "role": "web",
    "issuer_ref": "issuing-2026",
    "auth_method": "approle",
    "role_id": "...",
    "secret_id": "..."
  }
}'
```

The configuration is validated against the real Vault before it is stored, and
the response carries warnings and the CAs it imported.

**The gateway process holds no credential of its own.** Each CA account carries
the identity it issues under, so the process is authorised to sign nothing
until an account gives it one. It also deliberately ignores `VAULT_TOKEN` in
its environment: a gateway that picked one up would issue under an ambient
credential no account names, and nothing would record which identity signed.

---

## Configuration

| Key | Default | |
|:---|:---|:---|
| `address` | `--address` flag | Vault API endpoint. Plain `http://` is refused except on loopback |
| `namespace` | `--namespace` flag | Vault Enterprise namespace |
| `mount` | `pki` | Where the PKI engine is mounted |
| `role` | — | **Required.** The role that constrains what may be issued |
| `issuer_ref` | mount default | Pin issuance to one issuer by name or ID |
| `auth_method` | inferred | `token`, `approle`, `kubernetes` |
| `token` | — | A Vault token, for `auth_method: token` |
| `role_id`, `secret_id` | — | AppRole credentials |
| `approle_mount` | `approle` | Where the AppRole method is mounted |
| `kubernetes_role` | — | The Vault role bound to this gateway's service account |
| `kubernetes_mount` | `kubernetes` | Where the Kubernetes method is mounted |
| `kubernetes_jwt_path` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | The projected token |
| `ca_cert_pem` | — | CA that verifies Vault's TLS certificate |
| `tls_skip_verify` | `false` | Disables that verification. Warned about loudly |
| `ttl` | role default | Requested validity, as `720h` |
| `request_timeout_seconds` | 30 | Bounds one call |

`role` is required because issuing without a role means issuing without
constraints. Vault performs **no domain control validation** — the role's
`allowed_domains` is the only thing between a request and a certificate.

Setting both `ca_cert_pem` and `tls_skip_verify` is an error, not a preference:
one supplies the CA that verifies Vault and the other says not to verify it.

---

## Authentication

| Method | Suitable for | |
|:---|:---|:---|
| `kubernetes` | The gateway running in a cluster | Best. The credential is the projected service-account token, so there is no secret in the configuration at all |
| `approle` | Everything else | Good. The gateway logs in and keeps the token alive |
| `token` | Trying it out | Weakest for unattended work |

A static token cannot outlive its maximum TTL. When it expires, **every renewal
through that account fails at once**, unattended — so the gateway warns about
it at configuration time and reports the token's remaining life.

### Token handling

Tokens are cached per credential and renewed before expiry, not fetched per
request. A login per issuance means a token per certificate, each with its own
lease, and a fleet renewal of two thousand certificates would grow Vault's
token store until somebody noticed the storage.

A cached token that Vault refuses is discarded and the call is retried once
with a fresh login. Without that, the gateway works perfectly until the token
reaches its TTL — typically weeks later, unattended, at renewal time.

The Kubernetes JWT is re-read at every login, because the kubelet rotates a
projected token roughly hourly and a copy taken at startup stops working while
the file beside it is perfectly valid.

---

## What the warnings mean

`ValidateConfig` reaches the real Vault, and this is the cheapest possible
moment to find any of it.

```json
"warnings": [
  "role \"web\" issues EC keys of 256 bits regardless of what a request asks for",
  "role \"web\" caps validity at 90 days; a longer request is shortened to it",
  "issuer_ref is not set, so this account signs with whichever issuer is
   currently the mount's default",
  "the issuing CA \"Corp Issuing CA G2\" expires on 2026-09-12, in 20 days…"
]
```

| Warning | Why it is worth reading |
|:---|:---|
| Role overrides key type / size | Vault's `/issue` endpoint has no key-type parameter. The role decides, whatever the request asks for |
| Role caps validity | Ask 90 days from a role whose `max_ttl` is 30 and you get 30. Vault mentions it as a warning; your renewal schedule assumed 90 |
| `issuer_ref` not set | The account signs with whichever issuer is the mount's default. Rotating the default silently changes which CA signs |
| `no_store` on the role | Vault keeps no copy, so status lookups return unknown |
| Static token expiry | The date on which everything stops |
| **The issuing CA's own expiry** | See below |

### The expiring issuer

This is the warning the gateway was built to be able to produce.

```
the issuing CA "Corp Issuing CA G2" expires on 2026-09-12, in 20 days. Vault
refuses to sign a certificate that would outlive its issuer, so issuance
through this account starts failing before that date — as soon as a requested
validity reaches past it — and every certificate it has already signed expires
with it
```

There is no gradual degradation. On the first day an issuing CA comes within
one certificate lifetime of its own expiry, **every renewal through that mount
fails together**, and Vault's message talks about a `notAfter` date:

```
cannot satisfy request, as TTL would result in notAfter 2026-10-21T20:37:58Z
that is beyond the expiration of the CA certificate at 2026-09-12T20:33:01Z
```

Read cold, that looks like a bad request, and teams go and look at the role.
The gateway translates it — `FailedPrecondition`, naming the CA and the date —
and says it at account creation so it does not have to.

---

## Issuance

**With a CSR, the gateway signs it.** The key was generated by whoever made the
CSR — on the host that will serve the certificate, when the request came from
an agent — and neither Vault nor CertPilot ever holds it. No private key comes
back, because there was never one to return.

**Without a CSR, Vault generates the key** and it travels back over the
mutually-authenticated gRPC channel. Convenient, and still the weaker pattern.

The role signs, not `sign-verbatim`. `sign-verbatim` honours the extensions in
the CSR, which means the CSR decides its own key usage and, on some mounts, its
own basic constraints. The role exists to constrain; going around it is going
around the reason it is there.

### Names in the CSR

A Vault role uses the names in the CSR by default — `use_csr_common_name` and
`use_csr_sans` are both on. So a request asking for a name the CSR does not
carry would be **silently issued short**, while CertPilot recorded it as
covering that name.

The gateway refuses that combination rather than issuing it, and the error says
which role setting causes it.

---

## Revocation and status

Revocation is real: the serial reaches the mount's CRL, and its OCSP responder
where the mount is configured for one.

A role with `no_store` can still be revoked, because CertPilot sends the
**certificate** rather than its serial and Vault will verify and revoke a
certificate it never stored. What cannot work is revocation by serial alone —
there is no copy to look it up by — and the error says exactly that.

Before revocation, a `no_store` certificate's status reads `UNKNOWN`, because
Vault has no record. Absence is not evidence, and reporting it as anything else
would mark live certificates dead.

`POST /api/v1/certificates/:id/revoke` is what reaches this — admin only, and it
tells Vault first, recording the result only if Vault agreed. `DELETE` on a
certificate is not a substitute: it removes the record and revokes nothing, and
refuses a live certificate with a `409` naming the revoke route. See
[operations.md](../operations.md#revoke).

---

## Issuers in the inventory

Connecting the account records the CAs behind it:

```json
"issuers": {
  "outcomes": [
    {"name": "pki-int/Corp Root CA",    "action": "added", "days_remaining": 3649},
    {"name": "pki-int/Corp Issuing CA", "action": "added", "days_remaining": 1824}
  ]
}
```

From that moment they are monitored, thresholded and alerted on like everything
else. See [monitoring.md](../monitoring.md#ca-health).

---

## A lab to try it against

```bash
vault server -dev -dev-root-token-id=certpilot-dev-root &
git clone https://github.com/certpilot/certpilot-gateway-vault
cd certpilot-gateway-vault
./scripts/lab-vault.sh
eval "$(./scripts/lab-vault.sh --env)"
go test ./... -run Live -v
```

The script builds a root, two issuing CAs — one healthy, one three weeks from
expiry — a role that keeps no copy of what it signs, and an AppRole identity
scoped to those mounts.

The expiring CA is the point. It is what makes the refusal reproducible, and
that refusal is the one thing about this gateway that could not be verified
against a stub. The dev server keeps everything in memory, so stopping it is
the cleanup.
