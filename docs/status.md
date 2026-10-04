# Implementation status

What is built, what is partial, and what does not exist. The table is accurate:
anything not in it has not been written.

| | Means |
|:--|:--|
| ✅ | Supported. Exercised end to end against the real thing |
| ⚠️ | Constrained. It works, but it is narrower than the name suggests, and the note says how |
| 🧪 | Unverified. Built and unit-tested, but nothing in this repository or its CI ever contacts the real service — only a fake stands in for it |
| ❌ | Planned. Not started |

🧪 is not a claim that something is broken, and it is not a claim that nobody
has ever run it. It is a narrower and checkable statement: **there is no test
you can run that would tell you if it stopped working.** Every one of those
rows depends on a service CI cannot start for itself and holds no credential
for, such as a Slack workspace or a cloud account.

What CI does exercise, on every pull request:

- PostgreSQL 17 as a real service, and the full store conformance suite against it
- the self-signed gateway issuing real certificates
- the agent enrolling and installing end to end
- every released gateway against the current contract
- alerts delivered to [Mailpit](https://mailpit.axllent.org), a real SMTP
  server, over STARTTLS, implicit TLS and a plain relay; and signed webhook
  alerts checked by a receiver that uses the verification snippet in the
  [API reference](api-reference.md) — `make live-notifications`
- sign-in and bearer tokens against Keycloak, a real OpenID provider, through a
  rotation of its signing key — `make live-oidc`
- the Kubernetes inventory against a kind cluster running cert-manager —
  `make live-kubernetes`
- External Account Binding, through the released ACME gateway, against Pebble
  requiring one — `make live-eab`

Daily, and on demand: Certificate Transparency against crt.sh, for a public
site's real certificates — `make live-ct`. It is kept off pull requests because
it depends on crt.sh being up, and a red run there should read as "look at
this", not "your change broke it".

Everything it runs against is started inside the job. There are no third-party
secrets in any workflow.

That distinction is the point of this table. An evaluator carrying a capability
into production needs to know which half of it they are trusting.

This is early development software. Do not run it in production yet.

| Capability | State | Notes |
|:---|:---|:---|
| ACME issuance (RFC 8555) | ✅ | Full order flow: authorize, solve, finalize, download chain. Run against Let's Encrypt staging, which `make run-gateway-acme` and the compose file both point at — but by hand: no CI job issues over ACME, because that needs a domain CI does not control. The conformance run reports ACME's issuance checks as skipped rather than passed, for the same reason |
| ACME challenges | ✅ | `dns-01` via Cloudflare or a generic webhook; `http-01` via a built-in listener |
| Wildcard certificates | ✅ | Over `dns-01` |
| External Account Binding | ✅ | Required by ZeroSSL, Google Trust Services, SSL.com. CI runs the published ACME gateway image against Pebble with a binding required; Pebble is set to treat every authorization as valid. With a correct binding, the account issues a certificate and then renews it. No binding, a wrong HMAC key and a key id the CA never issued are each refused with the CA's own reason. No account at ZeroSSL, Google Trust Services or SSL.com has been used, so their own rules — such as a key id that opens one account only — are untested |
| ACME revocation | ✅ | Real revocation; already-revoked is treated as success |
| Renewal information (RFC 9773) | ✅ | Renews inside the CA's suggested window, at a random instant within it. A window pulled forward — what a CA does during a mass revocation — is a CRITICAL alert carrying the CA's own explanation |
| Vault PKI issuance | ✅ | Issue, renew, revoke and status against a Vault PKI mount, with token, AppRole or Kubernetes auth. Signs CSRs by preference, so a key generated on the host stays there. Verified against a real Vault, not only a stub |
| Vault issuer visibility | ✅ | The only gateway that returns **issuers** from `GetCAInfo` (ACME answers it too, with the CA's identity and advertised profiles, because ACME publishes no issuer listing): the mount's issuers, their expiry and their CRL. Vault **refuses** to sign a certificate that would outlive its issuer, so the day an issuing CA comes within one certificate lifetime of expiry, every renewal through it fails at once — this is said at configuration time instead |
| Self-signed gateway | ✅ | Development and testing |
| Secrets encrypted at rest | ✅ | AES-256-GCM envelope encryption, context-bound, rotatable |
| Mutual TLS, core ↔ gateway | ✅ | Required by default; `make dev-certs` to get started |
| OIDC authentication | ✅ | Any provider, via JWKS; legacy shared-secret path also supported. CI signs in through Keycloak by the steps the console takes — authorization code with PKCE and a nonce, redeemed by the core — with a script standing in for the browser, and presents access tokens Keycloak issued as bearer credentials. A replayed code, a wrong nonce, a wrong PKCE verifier, an altered signature and a token from a realm the core does not trust are each refused. A token signed with a key Keycloak has just rotated to makes the core fetch the key set again, at most once every ten seconds, rather than be refused until the cache expires; the check measured eleven seconds in the worst order, with an invented key id sent just before the rotation. Okta, Entra ID and Auth0 have not been tested by this project |
| RBAC | ✅ | admin / operator / auditor / viewer, enforced per route |
| Audit log | ✅ | Hash-chained. Every entry carries a gapless sequence number, its predecessor's tag, and an HMAC over both, keyed from a subkey of the master key, so a database-only attacker can alter a row and cannot forge a tag that agrees with it. `GET /audit/verify` walks the chain and counts the pre-chain entries rather than pretending they are covered |
| Ownership and acknowledgement | ✅ | Who owns a CA, who acknowledged an alert and why. Silencing suppresses delivery only — an acknowledged CA never leaves the dashboard |
| Automated renewal | ✅ | Durable queue, leases, deadline-aware backoff, ARI, and post-renewal verification. Safe on N replicas with no leader |
| CA health monitoring | ✅ | Scheduled sweep, expiry thresholds, CRL freshness, and a real OCSP request whose response signature, delegation and subject are all verified. For an intermediate the question asked is "has my parent revoked me", since the responder in a certificate's AIA is the parent's |
| CA expiry alerting | ✅ | Threshold crossings are delivered to Slack, a signed webhook, or email over SMTP, with per-channel severity and topic filters. CI registers a CA with twenty days left and checks that its 30-day alert arrives, with nobody prompting it, at a real SMTP server and at a webhook receiver, and that a channel filtered to other topics stays quiet. Delivery to Slack is 🧪, as below |
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
| Certificate Transparency | ✅ | Watches CT for certificates issued in your name — including ones never deployed anywhere you could scan. A check that could not run is never reported as a check that found nothing. A CI job scheduled daily runs against crt.sh. It checks that the certificate a public site serves, imported through discovery, is found in the index and matched to the inventory, although Python, crt.sh and the core each spell its serial differently. Its precertificate is recorded without counting the certificate twice, and a crt.sh outage reads as a check that did not run. Not run on pull requests, because it depends on crt.sh being up |
| Cloud inventory: Kubernetes | ✅ | Reads TLS secrets and the Ingresses that use them. Reports which certificates nothing renews — the ones everybody assumes are automatic. CI runs it against a kind cluster with a token scoped as documented: get and list on secrets and ingresses, TLS verified against the cluster's CA. A certificate cert-manager issued reads as renewed by cert-manager, and hand-made secrets read as not renewed. An Ingress's secret reads as attached, an expired secret as expired, and a deleted one as removed. The inventory pages past 500 secrets. A token with no rights fails the sync with the API server's reason, and one that cannot read Ingresses reports attachment as unknown rather than "unattached" |
| Cloud inventory: ACM, Azure Key Vault, Google Cloud | 🧪 | The same findings for certificates held by a cloud provider. Written to each provider's published API and tested against fakes; no cloud account is reached by CI |
| Renewal queue | ✅ | Durable jobs with leases, an attempt log, and backoff that tightens as expiry approaches. Safe on N replicas with no leader. Per-CA rate limits defer rather than fail |
| Post-renewal verification | ✅ | Re-probes the endpoints discovery has seen serving a certificate and reports when a renewal never reached them — the green-dashboard-over-an-expiring-estate failure, caught |
| Notifications: email and webhook | ✅ | SMTP email — STARTTLS, implicit TLS, or a plain relay — and a signed generic webhook. Deliberately not Teams or PagerDuty. CI delivers email to Mailpit, an SMTP server nobody here wrote. A wrong password, a certificate from an unknown CA, and a relay that does not offer STARTTLS are each refused, and the answer names the cause. Webhook signatures are checked by a receiver using the snippet in the [API reference](api-reference.md), not by CertPilot's own code |
| Notifications: Slack | 🧪 | Block Kit messages to an incoming webhook. Tested against a fake receiver; no Slack workspace is contacted by CI |
| Store conformance testing | ✅ | One suite run against both the in-memory store and a real PostgreSQL, covering the four classes of defect that had only ever been found by running the thing. Plain PostgreSQL is a supported target and proven by the suite |
| Cryptographic posture | ✅ | Which endpoints negotiate a post-quantum key exchange and which do not, from real handshakes; CNSA 2.0 conformance per certificate; CycloneDX 1.6 CBOM export validated against the published schema. Post-quantum *issuance* waits for `crypto/x509` |
| Deployment to servers | ⚠️ | Durable, retried, audited deployment to a signed webhook, a host running the agent, AWS ACM, Azure Key Vault and F5 BIG-IP. **Three of those five are 🧪.** **A renewal deploys itself**, and a failing target halts the rest of the rollout rather than letting a bad certificate march through the estate. The webhook and agent targets are exercised end to end by CI; AWS ACM, Key Vault and F5 are written to their published APIs and tested against fakes, and none has ever been run against a real AWS account, vault or appliance |
| Deployment profiles | ✅ | Ten platforms the agent installs to by name: nginx, Apache, HAProxy, Caddy, Tomcat, PostgreSQL, MariaDB/MySQL, Postfix, Dovecot, IIS. The nine Linux ones are tested by `make verify-profiles` in [certpilot-agent](https://github.com/certpilot/certpilot-agent), which runs the service in a container, installs a certificate through the agent, and confirms over TLS that the service returns it after reloading; IIS cannot run in a container and is held to the same bar on a Windows runner instead. A profile supplies defaults; any field set on the destination takes precedence. See [platforms](platforms/README.md) |
| Host agent | ✅ | One binary that enrols, inventories, **requests certificates with keys it generates locally and never sends** — CertPilot cannot produce them and does not claim to — then installs them where the server actually reads them and reloads it — as PEM, as a PKCS#12 keystore for anything on the JVM, or into the Windows certificate store for [IIS](platforms/iis.md), which reads no file at all. Bounded by grants an operator writes in advance — which now say *which template* a host may use, so the same rules and the same estate-wide floor apply to a host as to a person. Linux and Windows — see [where it runs](agent.md#where-it-runs) |
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
| Validity | Requested per the template's `validity_days`, and on renewal the certificate's own lifetime when no template declares one; no gateway is asked to promise it will honour that exactly | All three: verified. Shorter is REPORT-class (a public CA capping lifetime is correct); longer is BLOCK-class, except on a renewal whose lifetime was read off the certificate, where it is REPORT-class. The selfsigned and Vault gateways honour a renewal's lifetime from `certpilot-gateway-sdk` v0.4.0 ([#102](https://github.com/certpilot/certpilot/issues/102)); ACME is decided by the CA's profile |
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
- The AWS ACM, Azure Key Vault and F5 BIG-IP deployers are written to their
  published APIs and tested against fakes. None has been run against a real
  AWS account, vault or appliance, so ACM's hand-signed requests have never been
  checked by AWS itself.
- **Each capability still marked 🧪 above** depends on a service CI cannot
  start for itself and holds no credential for, so it is tested against a fake.
  It may well work; nothing here would tell you if it stopped.
- The key encryption key is held in the core's memory. It can be loaded from a
  file or from Vault, but delegated unwrapping through a transit or KMS backend
  needs an envelope format that does not exist yet.
- Deployment waves are per certificate. Two rollouts do not coordinate.
- The host agent installs into the Windows certificate store, and the only
  consumer of it that has been run is IIS. Exchange, ADFS, Network Policy Server
  and Remote Desktop Services read from the same store and differ only in the
  command that binds a thumbprint; each is the IIS profile with a different
  `bind`, and none has been tested by this project.
- A store destination has no pre-flight check. Nothing on Windows reports in
  advance whether a binding that has not been made yet will work, so the check
  offered is `verify`, which reconnects after the binding and rolls it back on a
  mismatch. A destination that does not set one has no check at all.
