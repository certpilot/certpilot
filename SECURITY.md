# Security

CertPilot manages certificate private keys and certificate authority
credentials. A weakness here is a weakness in whatever it protects, so this
document states the security model plainly, including what is not yet done.

**CertPilot is in early development and has not been audited. Do not run it in
production.**

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/certpilot/certpilot/security/advisories/new)**,
or the *Report a vulnerability* button under this repository's Security tab.

Include a description, reproduction steps, and the affected version. Expect
acknowledgement within three working days.

Reporting through GitHub rather than to an email address is deliberate. A
published security contact that nobody reads is worse than none: a researcher
who gets no reply concludes the project is unmaintained and discloses
publicly, which is the outcome this section exists to avoid. GitHub's
advisory flow delivers to the maintainers directly, needs no infrastructure to
keep working, and cannot quietly stop resolving.

We will not pursue legal action against good-faith research that respects user
privacy, avoids service disruption, and gives us reasonable time to fix the
issue before disclosure.

## Model

### Private keys

The best outcome is that CertPilot never holds one.

Supply a CSR with a certificate request and the key stays wherever it was
generated. When no CSR is supplied the gateway generates a key, and that key is
sealed with AES-256-GCM before it reaches the database. This is the intended
architecture for the host agent (roadmap phase 5): keys generated on the machine
that will serve them, never traversing the network.

Stored keys are excluded from every list and detail response. Exporting one is a
separate admin-only endpoint that writes an audit record with the actor and
client IP.

### Encryption at rest

Set `CERTPILOT_KEK` to a base64-encoded 32-byte key (`make generate-kek`). The
core refuses to start against a database without one.

Each value is sealed under a freshly generated 256-bit data encryption key,
which is itself wrapped by the KEK. Only the KEK needs external custody. Rotation
is incremental — set the new key as `CERTPILOT_KEK`, list the old one in
`CERTPILOT_KEK_RETIRED`, and re-seal at leisure. No flag-day migration.

Ciphertexts are bound to the field they belong to via AES-GCM additional
authenticated data, so a blob sealed as `ca_account:config` will not decrypt as
`certificate:private_key`. A database-level mixup or a deliberate field swap
fails closed.

**Losing the KEK makes every stored private key and CA credential
unrecoverable.** Put it in a secret manager, not a shell profile or a config
file.

### Transport

Core-to-gateway is mutual TLS 1.3. Both ends present a certificate and verify
the peer against a shared CA; the gateway requires a client certificate. That
channel carries certificate signing requests, private keys, and CA credentials,
so an unauthenticated peer must never reach it.

gRPC reflection is off by default — it makes a gateway trivially enumerable.

TLS can be disabled for local development, but it must be asked for explicitly,
it warns on every start, and production mode refuses it.

### Authentication

Prefer `auth.jwks_url`. The core then verifies asymmetrically signed tokens
against the provider's published public keys and holds nothing capable of
minting one. The legacy `auth.jwt_secret` path requires the core to hold a
symmetric key that can forge admin tokens.

- Accepted signing algorithms are pinned, which blocks `alg: none` and
  algorithm-confusion attacks
- Expiry is required; a token without one is rejected
- Issuer and audience are validated when configured
- An invalid token is **always** rejected. There is no mode in which a bad token
  falls back to a privileged identity

There is **no anonymous mode**. `auth.allow_anonymous` was removed, and setting
it now fails configuration validation rather than being ignored — an operator
with it set believes their instance is open and would otherwise not learn
otherwise until somebody was refused.

It was gated to development mode on a loopback address, and the gate held. It
was still wrong: every local session ran as an unnamed superuser, so the
authorisation paths were the least exercised code in the system and the audit
log attributed everything to a subject nobody could be asked about.

### Local accounts

CertPilot holds its own accounts. Passwords are Argon2id (64 MiB, t=3, p=4),
with the parameters encoded in each hash so the cost can be raised later
without invalidating existing passwords.

Sessions are **rows, not signed tokens**: an opaque random value, stored only as
a SHA-256 hash and compared in constant time, carried in an `HttpOnly`,
`SameSite=Strict` cookie. The core therefore holds no key capable of forging a
session, and a session can be ended the instant an account is suspended.

Sign-in is throttled per account — 8 failures, then a 15-minute lock — in the
database rather than in process memory, because the core runs as several
replicas and an attacker spreading attempts across them would reset an
in-memory counter with every request. CertPilot has no rate limiting, so this
is the only thing standing between the password endpoint and an unlimited
guessing oracle.

Every failure returns the same message. Distinguishing "no such account" from
"wrong password" is an address oracle, and an unknown address is verified
against a decoy hash so that the two take the same time.

### Display tokens

A dashboard on a wall has nobody to sign in at it. The obvious workaround —
leaving an operator session logged in on that machine — gives an unattended
screen in a corridor the authority to issue certificates, revoke them, and
export private keys. A display token is a separate credential that carries none
of that.

The constraints are enforced in one middleware rather than per route, because a
rule that has to be remembered at every call site is one that will eventually be
forgotten at one:

- **The role is the constant `viewer`.** Not configurable, not derived from any
  input, and not raisable by anything the request contains
- **`GET` only.** Any other method is refused on every route, before the route's
  own gate is consulted
- **Refused by path** regardless of role: `/certificates/:id/private-key`,
  `/display-tokens` (so one leaked screen cannot enumerate the others), and
  `/dashboard/activity` (audit entries name who did what, which does not belong
  on a screen in a corridor)
- **An invalid token aborts**, and never falls through to the next
  authenticator. With `allow_anonymous` enabled for local evaluation, falling
  through would hand a rejected token an admin identity
- **A real session always wins.** A request carrying an `Authorization` header is
  never resolved as a display token, so one left in a bookmark cannot mask an
  operator's identity in the audit log

256 bits of CSPRNG output behind a `cpd_` prefix, so secret scanners can match
it. Only a SHA-256 is stored: the raw value exists in the creation response and
nowhere else, and is compared in constant time. Tokens carry an expiry, are
revocable, and record `last_seen_at` and `last_seen_ip` so a leaked one is
visible in use. Creation and revocation are admin-only and audited.

Presented as an `X-Display-Token` header, or a `display_token` query parameter
for clients that cannot set headers. The header is preferred and is what the
CertPilot frontend uses; `RequestLogger` redacts the query parameter, but a
query string still reaches proxy logs and browser history in ways a header does
not.

### Authorization

Roles come from `app_metadata.certpilot_role` in the token, and only from there.
`user_metadata` is writable by the user it belongs to, so trusting it would let
any account promote itself to admin.

| Role | Scope |
|:---|:---|
| `admin` | Everything, including deletion and private key export |
| `operator` | Issue, renew, revoke; manage CAs and policies |
| `auditor` | Read-only, including audit logs |
| `viewer` | Read-only |

Unrecognised roles fall back to `viewer`.

### Fail closed

Where a security control cannot be evaluated, the operation is refused:

- A policy engine that cannot be reached blocks issuance, rather than treating a
  database blip as "no violations"
- A gateway returning data that is not a valid X.509 certificate produces an
  error rather than a record marked `ISSUED`
- A private key that cannot be encrypted is not stored in the clear
- A failed database connection is fatal when a database was configured, rather
  than silently falling back to an in-memory store

### Production mode

`server.mode: production` refuses configurations that are convenient locally and
dangerous deployed — anonymous access, an insecure gateway channel, and wildcard
CORS origins. These are the settings that look harmless in a development config
and travel unnoticed.

### HTTP

`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on every response.

CORS reflects the request origin only when it appears in
`server.allowed_origins`. A wildcard is never sent: it is invalid alongside
credentials and browsers reject the combination.

## Known gaps

Stated here rather than discovered later.

| Gap | Impact |
|:---|:---|
| Audit log is not tamper-evident | An ordinary table; anything with database write access can rewrite history. Hash-chaining is roadmap phase 3 |
| No distributed locking on renewal | Two core replicas will renew the same certificate concurrently |
| No retry or backoff on renewal | A transient CA failure means the renewal is missed until the next scan |
| OCSP check is not a real OCSP request | A plain GET, so a responder returning 400 is scored healthy. RFC 6960 requires a POST with a DER-encoded request |
| Policy evaluated on issuance only | Renewals bypass policy entirely |
| Several policy rule types unimplemented | `key_type`, `naming`, and `approval_required` are accepted by the schema and silently do nothing |
| No rate limiting on the HTTP API | No protection against brute force or resource exhaustion. Display tokens are not throttled either — guessing 256 bits is not the concern, but a stolen token being used heavily is, and only revocation stops it |
| Client IPs are not verified | Trusted proxies are unconfigured, so `X-Forwarded-For` is taken from whoever sends it. Audit entries and display-token `last_seen_ip` are hints, not evidence |
| ACME account keys stored unencrypted on disk | Mode 0600 in the gateway state directory, not sealed with the KEK |
| No secret zeroization guarantees | Go's garbage collector may retain copies of plaintext keys in memory |

## Hardening a deployment

1. Set `server.mode: production` — it enforces much of the below
2. Store `CERTPILOT_KEK` in a secret manager; never in the config file
3. Use `auth.jwks_url`, not `auth.jwt_secret`
4. Issue real mTLS certificates for the gateway channel; `make dev-certs` is for
   development, and it writes the CA key beside the certificates it signs
5. Restrict `server.allowed_origins` to the frontend origin
6. Run gateways on a network segment reachable only by the core
7. Supply your own CSRs so private keys never reach CertPilot
8. Grant `admin` sparingly — it is the only role that can export private keys
9. Ship audit logs to external storage, since the table is not yet tamper-evident
10. Run the core behind a reverse proxy that terminates TLS and rate-limits
11. Give each wall display its own display token with a real expiry, and revoke
    it when the screen is decommissioned. One token shared across screens cannot
    be revoked without going dark everywhere, and `last_seen_ip` stops telling
    you which screen is calling

## Cryptography

| Purpose | Algorithm |
|:---|:---|
| Secrets at rest | AES-256-GCM, envelope encryption with per-record data keys |
| Control plane transport | TLS 1.3, mutual authentication |
| Development PKI | ECDSA P-256 |
| ACME account keys | ECDSA P-256 |
| Certificate keys | ECDSA P-256 (default) or RSA ≥ 2048 |
| Webhook signing | HMAC-SHA256 |
| Fingerprints | SHA-256 |

Post-quantum algorithms are not yet used. See the
[roadmap](ROADMAP.md#existing-work) for what is planned and
why it is not simply "issue ML-DSA certificates".
