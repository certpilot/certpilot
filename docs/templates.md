# Certificate templates

A template is what a kind of certificate looks like. A grant is who may ask for
one. Policies are the floor the whole estate has to clear, whatever anybody
asks for.

Those are three different questions and they used to have two answers between
them, which is how an agent came to be able to obtain a certificate the policy
engine would have refused a person.

---

## Why not just more policies

`policies` is one flat list evaluated against every request. That is the right
shape for a floor and the wrong shape for everything above it: an internal mTLS
certificate for a service mesh and a public TLS certificate for a marketing site
have almost nothing in common, and a single list of rules that has to be true of
both can only contain what they share.

There is also something a policy structurally cannot do. A policy **constrains**
— "RSA must be at least 3072". A template can also **supply** a value the
requester may not touch, and **pass through** one the requester decides.

| | What it means |
|:---|:---|
| **Supplied** | The template provides it. The request cannot change it |
| **Constrained** | The request provides it and is validated against the template |
| **Passed through** | The request decides |

That third axis is the whole reason this object exists.

---

## Creating one

> These examples carry `-b "$JAR"`, a cookie jar from signing in. There is no
> anonymous mode, so a command without a credential is a 401. See
> [Authentication](api-reference.md#from-the-command-line) for the one-liner
> that fills it, or substitute `-H "Authorization: Bearer $TOKEN"`.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/certificate-templates \
  -H 'Content-Type: application/json' -d '{
  "slug": "internal-mtls",
  "name": "Internal mTLS",
  "ca_account_id": "<id>",

  "common_name_rule": {"required": true, "suffixes": ["internal.example.com"]},
  "san_rules": {"types": ["DNS"], "allow_wildcards": false, "max_names": 8},

  "allowed_key_types": ["ECDSA"],
  "ecdsa_curves": ["P-256", "P-384"],
  "csr_required": true,
  "key_custody_required": "AGENT",

  "validity_days": 30,
  "renew_before_days": 7,
  "require_metadata": ["change_ticket"]
}'
```

Admin only. A policy can only ever refuse more than it did; a template also
supplies values and decides whether the requester may set the subject, and that
last one is the difference between a template and a way to get a certificate for
somebody else's name.

### The fields

| | |
|:---|:---|
| `slug` | The stable machine name. What a pipeline or an agent refers to; survives a rename |
| `ca_account_id` | **Pinned.** A requester who could pick its own issuer could pick the cheapest, the least logged, or the one with the widest trust |
| `subject_mode` | `SUPPLIED` (default) or `CONSTRAINED`. See below — this is the one to get right |
| `subject_defaults` | `O`, `OU`, `C`, `L`, `ST` the template asserts |
| `common_name_rule` | `required`, `suffixes`, `forbidden_patterns` |
| `san_rules` | `types` (DNS, IP, email, URI), `suffixes`, `allow_wildcards`, `max_names` |
| `allowed_key_types` | Any of RSA, ECDSA, Ed25519 |
| `rsa_min_bits`, `rsa_max_bits` | RSA only. Zero means unconstrained |
| `ecdsa_curves` | By name, not bit count — an RSA modulus and a curve order are not comparable numbers |
| `csr_required` | The requester must bring its own key |
| `key_custody_required` | `ANY`, `CERTPILOT`, `AGENT`, `EXTERNAL` |
| `validity_days` | Supplied. The requester does not choose |
| `max_validity_days` | The ceiling, for when they may |
| `renew_before_days` | How long before expiry to renew. Bounded by the certificate's own lifetime: a lead longer than two thirds of it renews when a third remains instead, so a six-day certificate under the default 30 renews at day four rather than the moment it is issued. A lead that fits is kept exactly |
| `require_metadata` | Which `metadata_fields` a request must answer. Per-template, unlike the estate-wide `is_required` |
| `ca_profile` | The CA's own template — a Vault role, an ACME profile (draft-ietf-acme-profiles), an AWS Private CA template ARN. Empty means the account's default |
| `key_usage`, `extended_key_usage` | Declared key usage, in RFC 5280's own field names (`digitalSignature`, `serverAuth`, ...). Enforced where a gateway builds the certificate itself; elsewhere refused at save time if this deployment cannot make the CA produce it — see [below](#ca-profiles-key-usage-and-what-actually-enforces-them) |
| `basic_constraints_ca` | Whether this template issues a CA certificate. Enforced only where a gateway builds the certificate itself |
| `extension_passthrough` | `NONE` (default), `LISTED`, or `ALL` — whether a CSR's own extensions reach the certificate. `NONE` everywhere that matters: an extension copied out of a CSR is an attacker-controlled field in a signed certificate |
| `conformance` | `ENFORCE` or `REPORT` — what happens when an issued certificate does not match what was asked for. See [below](#issue-then-check) |
| `version` | Bumped when a rule changes, never by a rename |

**Zero means unconstrained**, everywhere a number appears. A column defaulting
to 2048 would look like a safe default and would be a rule nobody wrote, applied
to requests nobody expected it to touch. The floor belongs in policies, where
somebody put it on purpose.

---

## Precedence

Six rungs, in one place, obeyed by every path that issues:

```
1. Global policy (BLOCK)     the estate floor — nothing below may exceed it
2. Template supplied values  win over everything under them
3. Template constraints      the request must satisfy these
4. Grant narrowing           may only narrow, never widen
5. The request               fills whatever is left
6. The CSR                   names and public key only
```

The CSR outranks the request for two things, and not because of precedence: the
names and the public key are facts about a document that has already been
signed. Honouring a conflicting `key_type` from the JSON body would issue a
certificate whose key nobody holds.

---

## `subject_mode`, and why it refuses

`SUPPLIED` means the requester does not choose the subject. A CSR carries one,
and CertPilot cannot strip it — the request is signed and is passed to the CA as
it stands, so rewriting it is not available without the private key.

So it refuses:

```
403 · the signing request asks for O="Somebody Else Entirely" and template
"corp-identity" supplies O="Example Ltd". A signed request cannot be rewritten,
so this one has to be regenerated or issued under a template whose subject the
requester may set
```

An override that silently did nothing would be a control reporting success while
the CA issued whatever was asked for. `CONSTRAINED` is the setting that lets the
requester supply a subject, and it is one to choose deliberately: in AD CS the
equivalent is "Supply in the request", and combining it with broad enrolment
rights is the misconfiguration usually called ESC1.

---

## Refused when saved, not when needed

A template that could never issue anything is refused at write time:

```
400 · this template could never issue a certificate: every key it permits is
refused by a BLOCK policy — ECDSA curve P-256 is below the minimum of P-384
required by policy "P-384 or better". Widen the template or change the policy
```

The check builds the most permissive request the template allows and asks the
policy engine. One probe getting through is enough — the floor still judges
every real request on its merits.

---

## Grants

A grant binds a subject to a template, and narrows the names.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/agent-grants \
  -H 'Content-Type: application/json' -d '{
  "name": "web tier",
  "template_id": "internal-mtls",
  "label_selector": {"tier": "web"},
  "names": ["*.web.internal.example.com"]
}'
```

`subject_kind` is `AGENT` by default; `ROLE`, `TEAM` and `USER` bound a person's
request the same way. A grant narrows and never widens — its names are a subset
of what the template permits, not an exception to it.

Deleting a template that a grant still names is refused. A **revoked** grant
still refers to the template it was written against, and that record is part of
why a certificate exists.

---

## Compatibility

Every CA account has a generated default template that constrains nothing, so a
request naming no template behaves exactly as it did before templates existed —
RSA/2048 for 90 days. Connecting a new CA account generates one too.

Requiring a template on every request is a decision for an operator, not a
migration.

---

## Renewal

The renewal sweep is the only component that touches every managed certificate
on a timer, so it is the only place a rule change can reach an estate that
already exists. It reloads the template and asks what the rules require *today*.

Renewal generates the key — the request carries no CSR — so a raised floor is
something it can act on rather than only report:

```
renewing into conformance · RSA 2048 → 4096 bits,
  the minimum template "drift-demo" now requires
```

Two rules govern that, and both are easy to get wrong in the direction that
looks like progress:

- **It never downgrades.** Asking a template for a key with the fields empty
  yields its *minimum*, so an RSA-4096 certificate under a 2048 floor would be
  rekeyed weaker. The rule is the larger of what it has and what is required
- **It changes nothing it does not have to.** A certificate that already
  satisfies its rules keeps exactly the key it has. Rotating RSA to ECDSA on a
  renewal that did not need it is a change nobody asked for

**A certificate with no template is still judged**, against the estate-wide
floor. Most of an inventory predates templates, and exempting all of it would
mean a policy change governed only certificates that did not exist yet.

**What renewal cannot fix is reported, never refused.** A name outside a
narrowed suffix rule cannot be dropped — the endpoints serving it expect it. So
the certificate is renewed and `cert.renewed_nonconforming` is raised:

```
renewing a certificate that no longer satisfies its rules ·
  carries "drift2.example.com", which is outside the suffixes
  template "drift-demo" now allows (internal.example.com)
```

Refusing would be the alternative and it is worse: an expired certificate is a
worse outcome than a non-conforming one, and a sweep that turned a policy
tightening into an outage is how people learn to switch automation off.

A renewal is an issuance, so `template_version` moves to the version that
governed it. Leaving the version the original was issued under would make an
auditor read a conforming certificate as a stale one.

Agent and externally held certificates are excluded from the sweep entirely —
the key is somewhere else and only its holder can rotate it.

---

## CA profiles, key usage, and what actually enforces them

Most real CAs have their own template concept — a Vault role, an ACME profile,
an AWS Private CA template ARN — and until Phase 13, `ca_profile` existed on
this object and nothing read it. `key_usage` and `extended_key_usage` did not
exist at all, because CertPilot cannot enforce either on a CA whose own profile
decides them, and adding a field nothing enforces is the exact failure this
whole line of work exists to remove.

**`ca_profile` selects the CA's own template**, carried through on every issuance
and renewal. One CA account now serves as many Vault roles or ACME profiles as
an operator wants to name, instead of one account — and one copy of its
credentials — per role.

An unadvertised profile is refused when the template is saved, checked against
the CA's *live* directory rather than a list compiled into this codebase:
Let's Encrypt withdrew its `shortlived` profile on 8 July 2026, which is exactly
the case a compiled-in list gets wrong the day after it ships.

**Whether `key_usage`/`extended_key_usage` are enforced, verified, or refused
outright depends entirely on which CA the template points at:**

| Provider | What happens |
|:---|:---|
| selfsigned | Enforced directly — the gateway builds the certificate, so what the template says is exactly what the certificate carries |
| Vault | Refused at save time unless the selected role's own flags can produce it. Read from the role (`server_flag`, `client_flag`, `key_usage`, ...), not sent to Vault and hoped for — **Vault ignores key usage passed in an issue/sign request body entirely**, confirmed against a running server before this was built |
| ACME | Refused at save time, unconditionally. The profile decides in a way no gateway here can predict, and the message names which profiles the directory advertises instead |

See [status.md](status.md#what-is-checked-before-issuance-what-is-only-checked-after)
for the equivalent table covering every enforcement boundary, not only this one.

## Issue, then check

CertPilot cannot enforce key usage, extended key usage, validity, or even the
requested names on a CA whose own template decides them. Sending a request and
storing whatever came back, unchecked, would be a control that passes while
enforcing nothing — reintroduced at the very last step. The honest answer:
parse what actually came back and compare it against what was asked for, after
every issuance and every renewal.

**What is compared, and what happens on a mismatch — not one answer for all of
them:**

| Divergence | Class | On a mismatch |
|:---|:---|:---|
| Key type, key size | BLOCK | Refused. Recording it would launder an unauthorised key into something that looks authorised |
| SANs | BLOCK | Refused. A certificate covering names other than what was authorised is not the certificate that was authorised, whichever direction it differs |
| Validity, shorter than asked | REPORT | Recorded. Every public CA caps lifetime; a 47-day certificate where 90 were requested is the CA being correct |
| Validity, longer than asked | BLOCK | Refused. A CA issuing beyond the requested lifetime is misconfigured or is not the CA that was expected |
| A subject field the CA added | REPORT | Recorded, with the addition named. Refusing would make CertPilot unusable against any CA that adds an OU by policy; hiding it would make the template's subject a fiction |

**`conformance: ENFORCE | REPORT`** is the switch, on the template, deciding
whether a BLOCK-class finding actually refuses. `REPORT`-class findings are
always recorded and never refuse, whatever the template says — neither was ever
the class that setting exists to catch.

The right strictness differs by CA, so the default differs too: **`ENFORCE`**
for a new template against a CA this deployment runs (Vault, selfsigned) — a
mismatch there is a misconfiguration worth refusing. **`REPORT`** for a new
template against a public CA (ACME), and for every template saved before this
existed — a default that would fail every renewal against Let's Encrypt on
upgrade is not a default. An explicit choice on either side is never overridden.

A refused certificate is revoked where the gateway supports it, best-effort —
a gateway that cannot revoke must not turn "this certificate was wrong" into
"and now nobody can be told about it".

Findings are stored on the certificate whether or not they blocked anything,
because `conformance: REPORT` means recording them, not discarding them.
