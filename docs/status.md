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
| Policy engine | ⚠️ | `key_size`, `key_type`, `max_lifetime`, `ca_restriction`, `naming`; a rule type it cannot evaluate is a violation, not a pass. **It runs on two of the three issuance paths.** A person's request and a host's both go through the issuance resolver, which applies the floor after the template has had its say. A renewal is still judged by nothing at all |
| Certificate templates | ⚠️ | What a kind of certificate looks like, with the three dispositions a policy cannot express — supply a value, constrain it, or pass it through. Key type and size, curve, naming, wildcards, SAN kinds, lifetime, custody, required metadata, and a supplied subject a CSR may not contradict. Enforced on **a person's request and a host's**, through one resolver. A grant says who may use which template and for which names; it no longer describes the certificate. A template that could never issue anything is refused when it is saved. **The renewal sweep does not consult one yet** |
| Discovery | ✅ | Scans hosts, CIDR networks, and address ranges on a schedule; records the full handshake, says which certificates nobody manages, and reports what changed since last time |
| Certificate Transparency | ✅ | Watches CT for certificates issued in your name — including ones never deployed anywhere you could scan. A check that could not run is never reported as a check that found nothing |
| Cloud inventory | ✅ | Reads ACM, Azure Key Vault, Google Cloud, and Kubernetes TLS secrets. Reports which certificates the provider itself will not renew — the ones everybody assumes are automatic |
| Renewal queue | ✅ | Durable jobs with leases, an attempt log, and backoff that tightens as expiry approaches. Safe on N replicas with no leader. Per-CA rate limits defer rather than fail |
| Post-renewal verification | ✅ | Re-probes the endpoints discovery has seen serving a certificate and reports when a renewal never reached them — the green-dashboard-over-an-expiring-estate failure, caught |
| Notifications | ✅ | Slack (Block Kit), signed generic webhook, SMTP email. Deliberately not Teams or PagerDuty |
| Store conformance testing | ✅ | One suite run against both the in-memory store and a real PostgreSQL, covering the four classes of defect that had only ever been found by running the thing. Plain PostgreSQL is a supported target and proven by the suite |
| Cryptographic posture | ✅ | Which endpoints negotiate a post-quantum key exchange and which do not, from real handshakes; CNSA 2.0 conformance per certificate; CycloneDX 1.6 CBOM export validated against the published schema. Post-quantum *issuance* waits for `crypto/x509` |
| Deployment to servers | ✅ | Durable, retried, audited deployment to a signed webhook, a host running the agent, AWS ACM, Azure Key Vault and F5 BIG-IP. **A renewal deploys itself**, and a failing target halts the rest of the rollout rather than letting a bad certificate march through the estate. Key Vault and F5 are written to their published APIs and unit-tested; neither has been run against a real vault or appliance |
| Host agent | ✅ | One binary that enrols, inventories, **requests certificates with keys it generates locally and never sends** — CertPilot cannot produce them and does not claim to — then installs them where the server actually reads them and reloads it. Bounded by grants an operator writes in advance — which now say *which template* a host may use, so the same rules and the same estate-wide floor apply to a host as to a person |
| Vault issuers in the CA inventory | ✅ | Connecting a CA account records the CAs behind it, and from that moment they are monitored, thresholded and alerted on like everything else. The importer refreshes what the certificate says and never touches what an operator decided — the name, the thresholds, the owning team |
| Certificate revocation | ✅ | `POST /certificates/:id/revoke`, admin only. The CA is told first and only what it accepted is recorded, so a row can never read `REVOKED` while the certificate still answers handshakes. `DELETE` now refuses a live certificate and points at revoke; `?forget=true` is the deliberate override for one you want to stop tracking while it stays live |
| GCP CAS, AWS PCA, DigiCert, Sectigo gateways | ❌ | Not started |

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
