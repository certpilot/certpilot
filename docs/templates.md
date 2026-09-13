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

```bash
curl -X POST localhost:8080/api/v1/certificate-templates \
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
| `require_metadata` | Which `metadata_fields` a request must answer. Per-template, unlike the estate-wide `is_required` |
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
curl -X POST localhost:8080/api/v1/agent-grants \
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

## What does not consult a template yet

**Key usage and EKU.** The fields are not on the template yet, and for ACME and
Vault CertPilot could only select a profile and verify the result afterwards
rather than enforce it — the CA decides. Phase 13.
