# Implementation status

What is built, what is partial, and what does not exist. The table is accurate:
anything not in it has not been written.

Everything marked ✅ has been run end to end against a real certificate
authority, a real database, and real servers. ⚠️ means the capability exists but
is narrower than the name suggests, and the note says how. ❌ means not started.

This is early development software. Do not run it in production yet.

| Capability | State | Notes |
|:---|:---|:---|
| ACME issuance (RFC 8555) | ✅ | Full order flow: authorize, solve, finalize, download chain |
| ACME challenges | ✅ | `dns-01` via Cloudflare or a generic webhook; `http-01` via a built-in listener |
| Wildcard certificates | ✅ | Over `dns-01` |
| External Account Binding | ✅ | Required by ZeroSSL, Google Trust Services, SSL.com |
| ACME revocation | ✅ | Real revocation; already-revoked is treated as success |
| Renewal information (RFC 9773) | ✅ | Renews inside the CA's suggested window, at a random instant within it. A window pulled forward — what a CA does during a mass revocation — is a CRITICAL alert carrying the CA's own explanation |
| Vault PKI issuance | ✅ | Issue, renew, revoke and status against a Vault PKI mount, with token, AppRole or Kubernetes auth. Signs CSRs by preference, so a key generated on the host stays there. Verified against a real Vault, not only a stub |
| Vault issuer visibility | ✅ | The only gateway that answers `GetCAInfo`: the mount's issuers, their expiry and their CRL. Vault **refuses** to sign a certificate that would outlive its issuer, so the day an issuing CA comes within one certificate lifetime of expiry, every renewal through it fails at once — this is said at configuration time instead |
| Self-signed gateway | ✅ | Development and testing |
| Secrets encrypted at rest | ✅ | AES-256-GCM envelope encryption, context-bound, rotatable |
| Mutual TLS, core ↔ gateway | ✅ | Required by default; `make dev-certs` to get started |
| OIDC authentication | ✅ | Any provider, via JWKS; legacy shared-secret path also supported |
| RBAC | ✅ | admin / operator / auditor / viewer, enforced per route |
| Audit log | ✅ | Hash-chained. Every entry carries a gapless sequence number, its predecessor's tag, and an HMAC over both, keyed from a subkey of the master key, so a database-only attacker can alter a row and cannot forge a tag that agrees with it. `GET /audit/verify` walks the chain and counts the pre-chain entries rather than pretending they are covered |
| Ownership and acknowledgement | ✅ | Who owns a CA, who acknowledged an alert and why. Silencing suppresses delivery only — an acknowledged CA never leaves the dashboard |
| Automated renewal | ✅ | Durable queue, leases, deadline-aware backoff, ARI, and post-renewal verification. Safe on N replicas with no leader |
| CA health monitoring | ✅ | Scheduled sweep, expiry thresholds, CRL freshness, and a real OCSP request whose response signature, delegation and subject are all verified. For an intermediate the question asked is "has my parent revoked me", since the responder in a certificate's AIA is the parent's |
| CA expiry alerting | ✅ | Threshold crossings are delivered to Slack, a signed webhook, or email over SMTP, with per-channel severity and topic filters |
| Live dashboard updates | ✅ | Server-Sent Events end to end. The client tracks data age independently, so a dead feed degrades the surface instead of freezing it on green |
| CA health view | ✅ | Every CA by urgency: expiry countdown, chain position, CRL freshness, issuance volume, owner, and acknowledgement state |
| Wall display mode | ✅ | `/display` — fullscreen, no chrome, readable across a room, authenticated by a kiosk token in the launch URL |
| Kiosk display tokens | ✅ | Read-only, viewer-scoped, expiring, revocable credentials for a wall display |
| CA hierarchy tree | ⚠️ | Position and lineage are shown per CA and a malformed hierarchy is flagged; the tree is not drawn as a tree |
| Policy engine | ⚠️ | `key_size`, `key_type`, `max_lifetime`, `ca_restriction`, `naming`; a rule type it cannot evaluate is a violation, not a pass. **It runs on all three issuance paths.** A person's request and a host's go through the issuance resolver; renewal re-evaluates against the template and the floor and renews *into* conformance where it can, reporting what it cannot fix rather than refusing |
| Certificate templates | ⚠️ | What a kind of certificate looks like, with the three dispositions a policy cannot express — supply a value, constrain it, or pass it through. Key type and size, curve, naming, wildcards, SAN kinds, lifetime, custody, required metadata, and a supplied subject a CSR may not contradict. Enforced on **a person's request and a host's**, through one resolver. A grant says who may use which template and for which names; it no longer describes the certificate. A template that could never issue anything is refused when it is saved. Renewal reloads the template and raises a key to what the rules now require — never downgrading, and never changing what it does not have to. The console shows every template, which CA signs it, what it would refuse, and who may use it |
| CA profiles | ✅ | A Vault role, an ACME profile, an AWS template — selected per template, carried through on every issuance and renewal. An unadvertised ACME profile is refused at save time, checked against the CA's live directory rather than a compiled-in list |
| Key usage and extended key usage | ⚠️ | Enforced where a gateway builds the certificate (selfsigned). Refused at save time on Vault unless the selected role's own flags can produce it, and on ACME unconditionally — see the table below for why. Verified after every issuance regardless, so a wrong value cannot pass silently |
| Post-issuance conformance checking | ✅ | Every issuance and renewal parses what the CA actually returned and compares it against what was asked: key type, key size, names, validity, and added subject fields. `conformance: ENFORCE | REPORT` on the template decides whether a mismatch refuses (and revokes, where the gateway supports it) or is only recorded. See [templates.md](templates.md#issue-then-check) |
| Discovery | ✅ | Scans hosts, CIDR networks, and address ranges on a schedule; records the full handshake, says which certificates nobody manages, and reports what changed since last time |
| Certificate Transparency | ✅ | Watches CT for certificates issued in your name — including ones never deployed anywhere you could scan. A check that could not run is never reported as a check that found nothing |
| Cloud inventory | ✅ | Reads ACM, Azure Key Vault, Google Cloud, and Kubernetes TLS secrets. Reports which certificates the provider itself will not renew — the ones everybody assumes are automatic |
| Renewal queue | ✅ | Durable jobs with leases, an attempt log, and backoff that tightens as expiry approaches. Safe on N replicas with no leader. Per-CA rate limits defer rather than fail |
| Post-renewal verification | ✅ | Re-probes the endpoints discovery has seen serving a certificate and reports when a renewal never reached them — the green-dashboard-over-an-expiring-estate failure, caught |
| Notifications | ✅ | Slack (Block Kit), signed generic webhook, SMTP email. Deliberately not Teams or PagerDuty |
| Store conformance testing | ✅ | One suite run against both the in-memory store and a real PostgreSQL, covering the four classes of defect that had only ever been found by running the thing. Plain PostgreSQL is a supported target and proven by the suite |
| Cryptographic posture | ✅ | Which endpoints negotiate a post-quantum key exchange and which do not, from real handshakes; CNSA 2.0 conformance per certificate; CycloneDX 1.6 CBOM export validated against the published schema. Post-quantum *issuance* waits for `crypto/x509` |
| Deployment to servers | ✅ | Durable, retried, audited deployment to a signed webhook, a host running the agent, AWS ACM, Azure Key Vault and F5 BIG-IP. **A renewal deploys itself**, and a failing target halts the rest of the rollout rather than letting a bad certificate march through the estate. Key Vault and F5 are written to their published APIs and unit-tested; neither has been run against a real vault or appliance |
| Deployment profiles | ✅ | Nine platforms the agent installs to by name: nginx, Apache, HAProxy, Caddy, Tomcat, PostgreSQL, MariaDB/MySQL, Postfix, Dovecot. Each is tested by `make verify-profiles`, which runs the service in a container, installs a certificate through the agent, and confirms over TLS that the service returns it after reloading. A profile supplies defaults; any field set on the destination takes precedence. See [platforms](platforms/README.md) |
| Host agent | ✅ | One binary that enrols, inventories, **requests certificates with keys it generates locally and never sends** — CertPilot cannot produce them and does not claim to — then installs them where the server actually reads them and reloads it — as PEM, or as a PKCS#12 keystore for anything on the JVM. Bounded by grants an operator writes in advance — which now say *which template* a host may use, so the same rules and the same estate-wide floor apply to a host as to a person. **Linux only** — see [where it runs](agent.md#where-it-runs) |
| Vault issuers in the CA inventory | ✅ | Connecting a CA account records the CAs behind it, and from that moment they are monitored, thresholded and alerted on like everything else. The importer refreshes what the certificate says and never touches what an operator decided — the name, the thresholds, the owning team |
| Certificate revocation | ✅ | `POST /certificates/:id/revoke`, admin only. The CA is told first and only what it accepted is recorded, so a row can never read `REVOKED` while the certificate still answers handshakes. `DELETE` now refuses a live certificate and points at revoke; `?forget=true` is the deliberate override for one you want to stop tracking while it stays live |
| GCP CAS, AWS PCA, DigiCert, Sectigo gateways | ❌ | Not started |

## What is checked before issuance, what is only checked after

The table above says templates are enforced. This is the honest version of
that claim, per provider, because "enforced" means three different things
depending on which CA a template points at.

| | Before issuance | After issuance |
|:---|:---|:---|
| Key type, key size | selfsigned: enforced (the gateway builds the certificate). Vault: enforced by the role, which a template selects but cannot override. ACME: not controllable — the CA's own CSR handling decides | All three: verified against the returned certificate. A mismatch is BLOCK-class |
| Key usage, extended key usage | selfsigned: enforced. Vault: refused at template-save time unless the selected role's own flags can produce it — checked by reading the role, not by sending a value and hoping, because **Vault ignores key usage in an issue/sign request body entirely**. ACME: refused at template-save time, unconditionally — the profile decides in a way nothing here can predict | All three: not independently re-verified as a distinct check — a wrong value would already have failed to save, and selfsigned's output is definitionally correct since it built the certificate itself |
| Names (SANs) | All three: validated against the template's rules and the caller's grant before the request is sent | All three: verified against the returned certificate. Added or dropped names are BLOCK-class |
| Validity | Requested per the template's `validity_days`; no gateway is asked to promise it will honour that exactly | All three: verified. Shorter is REPORT-class (a public CA capping lifetime is correct); longer is BLOCK-class |
| Subject | `SUPPLIED` templates send a fixed subject; `CONSTRAINED` ones validate the requester's | All three: an added field (an OU a CA inserts by policy) is REPORT-class. A requester-supplied subject under `CONSTRAINED` is not compared, because there is no template default to compare it against |
| CA profile (Vault role, ACME profile) | Checked against the CA's live directory at template-save time, for ACME. Vault has no equivalent list to check against — an unknown role is caught at issuance, where Vault itself refuses it | Not applicable — the profile either issued or the request already failed |
| `basic_constraints_ca` | selfsigned only. Not communicated to Vault or ACME at all; there is no field on the wire contract for it yet | Not checked |
| `extension_passthrough` | selfsigned only, where "the gateway builds the certificate" already means a CSR's extensions are never copied unless this says so | Not checked |

The row that matters most to read literally: **a declared key usage on an ACME
or Vault template is a promise about what CertPilot will refuse to save, not a
promise about what the CA will do differently.** The CA was never going to do
anything differently — Vault's role and ACME's profile already decided before
the request existed. What changed is that a template asking for something its
CA account cannot produce now fails at the moment somebody makes that mistake,
in a sentence naming why, instead of at the moment somebody discovers a
certificate that does not do what its name implies.

## Known gaps

These are documented rather than secretly broken, and they are listed in full
with their reasoning in [security.md](security.md#known-gaps).

- The audit chain has no external anchor. An attacker holding both the database
  and the key encryption key can rewrite it wholesale, or truncate the newest
  entries.
- The Azure Key Vault and F5 BIG-IP deployers are written to their published
  APIs and unit-tested. Neither has been run against a real vault or appliance.
- The key encryption key is held in the core's memory. It can be loaded from a
  file or from Vault, but delegated unwrapping through a transit or KMS backend
  needs an envelope format that does not exist yet.
- Deployment waves are per certificate. Two rollouts do not coordinate.
- The host agent runs on Linux only. It does not compile for Windows, which is
  a port rather than a build flag: file modes, the certificate store and
  rollback all need Windows equivalents. Windows hosts can be deployed to
  through a signed webhook, or by an agent written against
  [`certpilot-agent-sdk`](https://github.com/certpilot/certpilot-agent-sdk).
