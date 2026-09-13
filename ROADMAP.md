# Roadmap

## Who this is for

A **central PKI team inside an organisation** — the group that owns the private
CA hierarchy, answers for every certificate the company serves, and gets paged
when something expires.

That audience determines the design more than any other decision here:

- **The dashboard is the product surface, not a convenience.** A central PKI
  team runs a wall display. They need CA health, expiry countdowns, and chain
  state visible without asking for it. An answer that requires someone to run a
  command is an answer nobody sees at 2am on a Sunday.
- **CA expiry is the catastrophic failure, not certificate expiry.** An expired
  leaf certificate breaks one service. An expired issuing CA breaks everything
  it ever signed, all at once, and no amount of certificate automation helps
  once it has happened. CA monitoring is therefore load-bearing.
- **Any CA, public and private.** These teams run internal PKI *and* buy public
  certificates. A tool that handles only one half doubles their tooling instead
  of halving it.
- **The API and CLI serve automation, not humans.** They matter, but they are
  not how the team perceives the state of their estate.

## Forcing function

CA/Browser Forum [ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)
takes maximum TLS validity to **200 days in March 2026, 100 days in March 2027,
and 47 days in March 2029**, with domain validation reuse dropping to 10 days.

At 47 days, ten thousand certificates means roughly 670 renewals a day. Anything
that requires a human in the loop stops working well before then.

---

## Done

**Phase 0 — Honest foundations**
Accurate README, algorithm constraints removed from the schema, secrets kept out
of version control.

**Phase 1 — Security floor**
- `pkg/secrets`: AES-256-GCM envelope encryption, per-record data keys,
  context-bound ciphertexts, incremental key rotation
- Mutual TLS on the core-to-gateway channel, with one-command dev setup
- OIDC via JWKS, pinned algorithms, no development auth fallback
- Private keys sealed at rest, never serialized, admin-only audited export
- RBAC enforced per route

**Phase 2 — An ACME gateway that issues certificates**
- Full RFC 8555 order flow
- `dns-01` via Cloudflare and a generic signed webhook; `http-01` via a built-in
  listener
- Persistent ACME account keys, External Account Binding
- Real revocation
- RFC 9773 renewal information

**Phase 2.5 — CA monitoring actually runs**
The health sweep is now scheduled rather than manual, and threshold crossings
are recorded to the audit log so they reach the dashboard instead of stdout.

---

## In progress

### Phase 3 — A monitoring surface a team can leave on a screen ✅

The largest gap between what exists and what a central PKI team needs. The data
is already being collected; almost none of it reaches a human unprompted.

| Step | | |
|:---|:---|:---|
| 0 | Truth pass over the existing dashboard | ✅ |
| 1 | In-process event broker | ✅ |
| 2 | `GET /api/v1/events` — Server-Sent Events | ✅ |
| 3 | Kiosk display tokens | ✅ |
| 4 | Store filtering: audit log by action, CA filters, an index | ✅ |
| 5 | Frontend event stream and connection indicator | ✅ |
| 6 | CA health view, then fullscreen wall mode | ✅ |
| 7 | Alert delivery: Slack, webhook, SMTP | ✅ |
| 8 | Acknowledgement and ownership | ✅ |

**Step 0** was a prerequisite rather than cleanup: the dashboard computed CA
distribution with `Math.random()` inside a `computed`, fell back to invented
numbers when the API returned nothing, and bound field names the backend never
emitted. Two forms had never once worked. Live updates over that would have
produced a dashboard that flickered *and* lied.

**Steps 1–2** put changes on a stream. The broker drops the oldest event for a
slow consumer rather than applying backpressure, so a wall display on a flaky
link can never stall the CA health sweep; a client that falls behind is told to
resynchronise rather than fed deltas onto a stale base.

**Step 3** made the stream reachable from a screen nobody is sitting at, without
that screen holding credentials worth stealing.

**Step 4** made the collected data answerable. Audit logs can now be queried by
action, so `ca.expiry_alert` is reachable instead of buried under a day's
issuance; CAs can be filtered by status and expiry window and sorted by urgency,
which is what the health view is built on. Looking for the gaps turned up three
defects worth naming, all of the same kind — a store layer that quietly dropped
what it was handed:

- `UpdateCertificate` never wrote `private_key_encrypted`, so a renewal that
  rotated the key stored the new certificate against the old one.
- `GetCertificate` never read the column either, so private key export answered
  "no private key is stored" for every certificate on PostgreSQL.
- The in-memory store returned live pointers into its own maps, making the
  health sweep and the event stream race over the same records.

**Step 5** connected the UI to the stream. It is built on `fetch` rather than
`EventSource`, which cannot set headers and so cannot carry a bearer token, and
whose reconnect cannot be controlled beyond the server's `retry:` directive. The
load-bearing part is not the transport but the watchdog: a half-open TCP
connection raises no error and a browser will sit on a dead socket for minutes,
so staleness is judged on **data age**, not socket state. Thirty-five seconds
without a byte and the surface degrades — a chip for whoever is at the keyboard,
a banner naming the last confirmed time, and the colour draining out of the
content for whoever is across the room.

**Step 6** turned that into the two views a PKI team actually watches: a CA
health list sorted by urgency with days-remaining as the largest thing on each
row, and `/display`, a fullscreen wall mode that authenticates from a kiosk
token in its launch URL. Nothing needing attention is ever below the fold —
rows that do not fit are counted in the footer rather than silently truncated —
and an empty estate says it is empty rather than showing a calm green screen.

Building chain position first required fixing `ChainResolver`, which had two
defects of the kind that never announce themselves. It assigned depth while
ranging over its input, so a grandchild seen before its parent reported the
wrong depth, and since the input came from a map, identical data gave different
answers on different requests. Worse, a loop in `parent_ca_id` produced a
structure `json.Marshal` refuses to encode *after* Gin had sent the 200, so one
bad row turned the hierarchy endpoint into a successful empty response for the
whole estate — with the CAs in the loop absent from it entirely. A CA that
quietly fails to render is the one nobody notices expiring.

**Step 7** made alerts leave the building. Slack, a signed generic webhook, and
email over SMTP, with the dispatcher subscribing to the broker rather than being
called inline — so a wedged Slack webhook loses its own place in the queue and
can never apply backpressure to the CA health sweep. Two rules shape it: a
channel is validated when it is saved and can be tested on demand, because a
channel that looks configured and silently drops everything is worse than none;
and both outcomes are audited, because "we tried and Slack refused" and "we never
tried" look identical from outside and only one means the configuration is wrong.

**Step 8** answered the two questions the dashboard could not: who owns this CA,
and has anyone already looked at it. Without the second, an alerting dashboard
becomes wallpaper within a month — the same red row every morning, no way to tell
whether it is being handled, and the team stops reading it.

One rule governs it, and it is the one most likely to be "simplified" later:
**silencing suppresses delivery, never display.** An acknowledged CA stays
exactly where it was in the urgency order, marked with who acknowledged it and
why. Silencing buys quiet in Slack, not a clean screen. Two consequences follow.
An acknowledgement is bound to the threshold it was granted at, so someone who
silenced a CA at 30 days has not silenced the 7-day page — that is a materially
different situation and the earlier "yes, we know" answered a different question.
And the acknowledgement lookup fails *open*: a database blip must not turn into
an alert nobody received, because the cost of a duplicate notification is an
annoyed engineer and the cost of a suppressed one is an expired CA.

With that, phase 3 is complete.

The rest:

- **Chain visualisation.** Each CA now states its position and lineage, and a
  malformed hierarchy is flagged rather than hidden. The tree itself — root →
  intermediate → issuing drawn as a tree, with health carried up it, because a
  healthy issuing CA under an expiring root is not healthy — is not drawn yet.
- **Expiry timeline.** What breaks in the next 7 / 30 / 90 days, grouped by team
  and environment.

### Phase 5 — Discovery that finds what nobody told you about

| Step | | |
|:---|:---|:---|
| 1 | Scans that persist, and the verdict that matters | ✅ |
| 2 | CIDR expansion, worker pool, cancellation, progress on the stream | ✅ |
| 3 | Scheduled scans and re-scan reconciliation | ✅ |
| 4 | CT log monitoring | ✅ |
| 5 | Cloud inventory: ACM, Azure Key Vault, GCP, Kubernetes secrets | ✅ |

One sentence governs the phase:

> **Discovery's output is not a list of certificates. It is the list of
> certificates nobody told you about.**

A scan of a real estate returns mostly certificates the team issued itself and
already watches. Those rows are noise. So every result carries a verdict —
`MANAGED`, `UNMANAGED`, `UNREACHABLE` — decided on the certificate's fingerprint
rather than its hostname, because two certificates for the same host are two
different certificates and the one being served is the one that expires. An
inventory lookup that fails reports `UNMANAGED` and says so: calling something
managed that could not be checked is how a lookup error becomes an outage.

**Step 1** replaced a scanner that could reach one host and store nothing.
`discovery_scans` and `discovery_results` had existed since migration 001 with
no Go surface at all, and the columns 001 chose describe a certificate — which
is what a scanner *finds*, not what it needs to say.

A second verdict runs alongside the first: what the served chain terminates in.
`PUBLIC`, `INTERNAL` — a CA registered in CertPilot, so its own expiry is
already being watched — `SELF_SIGNED`, or `UNTRUSTED`, meaning someone is
issuing certificates from an authority nobody has registered. Internal trust is
decided on **signatures rather than by path building**, and that distinction is
load-bearing: an expired certificate fails every verification for one reason,
and letting that reason decide the trust answer reports every expired internal
certificate as issued by an unknown CA, sending whoever reads it hunting a rogue
issuer that does not exist.

Findings name the consequence rather than the observation. A missing
intermediate is not "chain incomplete" but "clients that already hold the
intermediate will connect and clients that do not will fail, which is why this
breaks intermittently and only for some users". It is also detected without
relying on verification succeeding, because a platform verifier caches
intermediates it has seen — so the endpoint verifies on the machine that has
visited it and fails on a fresh one, which is the defect itself.

Two deliberate omissions. `auto_renew` is always false on import whatever was
asked for, because CertPilot holds no private key for something it merely
observed and a record claiming it will renew itself is a promise the system
cannot keep. And a classical key exchange is **not** a finding: it is true of
nearly every endpoint alive, and a finding that appears on every row is the
noise that stops people reading the list. The negotiated group is recorded
verbatim instead — which is the whole point of capturing the handshake, since it
is unrecoverable once the connection is gone.

Verified against live endpoints, not only in tests: expired, self-signed,
wrong-host, incomplete-chain, TLS 1.0, 3DES, and a SHA-1 intermediate each
produced exactly one correct finding, an unmanaged run reached a signed webhook
through the existing dispatcher, and importing a result flipped the same
endpoint to `MANAGED` on re-scan.

**Step 2** made it a scanner rather than a lookup. Targets expand from CIDR
networks and address ranges, run through a worker pool, and can be stopped.

Expansion is where a typo becomes an incident: one misplaced digit turns
`10.0.0.0/24` into `10.0.0.0/8`, which is sixteen million outbound connections
carrying CertPilot's return address across somebody else's network. So the size
is counted from the prefix before a single address is materialised, and the
refusal names the number rather than merely saying no.

Three things follow from a scan now taking minutes rather than seconds.

Results are **written as they are found**, so a run that is cancelled, crashes,
or is restarted through keeps everything it reached — the alternative is having
nothing to show for the one endpoint it found something on. Progress goes to the
event stream, but **never** to a notification channel: a range scan would put a
message in Slack every few seconds for minutes, and a team that mutes that
channel has also muted the CA expiry alerts sharing it. That distinction now
exists in the broker as a property of the topic rather than of the severity,
because an INFO event can still be news.

And **cancelled is not failed.** A scan somebody stopped on purpose reached what
it reached; recording it as a failure would make the scan history lie about
which runs went wrong, and that history is the only thing that says whether
discovery is running at all. Endpoints abandoned mid-probe are not recorded as
unreachable either — they were never really asked, and a row saying otherwise is
a finding about the estate invented by stopping the scan.

The scan record keeps the targets as they were **typed**, with a separate count
of what they expanded to. A scan is repeated by re-running what was asked for
and found again by the range someone remembers typing; 254 addresses in an audit
entry answer neither question.

**Step 3** made it monitoring rather than a snapshot, which is the difference
between finding what was there the morning somebody ran a scan and finding what
is there now. Schedules run scans on an interval — not a cron expression, since
a cron field is a small language whose mistakes are silent and a schedule meant
to run nightly that instead runs yearly looks identical on screen to one that
works.

The important half is not the timer, it is what a *second* run is for. The
second scan of a range is not worth much as a list; it is worth what it says has
changed. Three findings exist only on a re-scan, and one of them is the reason
to bother:

> A certificate that changed on an endpoint CertPilot does not manage means
> something out there renewed it without going through any of this. **Somebody
> knows how to replace that certificate** — find out who.

The same rotation on a managed endpoint is a renewal CertPilot performed, and is
reported at INFO. Alerting on its own renewals is how a system teaches people to
ignore the alert that matters. An endpoint that used to answer and no longer
does is the third: either it moved and the scan no longer covers it, or it is
down, and both are invisible to a first scan. A first scan reports none of them,
because every endpoint is new the first time and a run whose findings are all
"this is new" is one nobody reads twice.

This also closed the gap step 1 left open. The results list now returns the
latest observation per endpoint, so a nightly schedule stops turning one
unmanaged certificate into thirty findings. The collapse happens *before* the
filters — the other order answers "the most recent time this endpoint was
unmanaged" and keeps asking for work already done — and the full history is
still one query parameter away.

Two smaller rules, both learned by reading what the system actually said. A
schedule advances even when its run fails, because one that only advanced on
success would retry a permanently broken target every tick, turning a single bad
entry into a scan running continuously against somebody else's network; the
error is recorded on the schedule rather than only logged, since a schedule that
fails every night and is never read is the appearance of coverage. And the
change alert is composed from the parts that happened: the first version said
"0 endpoints are serving a different certificate … so something is renewing
certificates outside this system", which asserts a claim about zero things and
then draws a conclusion from it.

**Step 4** added the half of discovery that a network scan cannot reach. A scan
answers "what is being served on the addresses I told you about". Certificate
Transparency answers a larger question — **what has been issued in your name at
all**, by any CA, to anyone, whether or not it was ever deployed and whether or
not the machine is reachable from here. A developer who obtained a certificate
for `api.corp.example.com` with a personal ACME account appears in no scan of
any range, and appears in CT within minutes, because every publicly-trusted CA
is required to log there.

One rule governs it, and it is the same rule as the dashboard's:

> **A check that could not run must not look like a check that found nothing.**

So a monitor carries two timestamps, not one: when a check was last *attempted*,
and when one last *answered*. Collapsed into a single "last checked", a monitor
unable to reach the log for a week reads exactly like one that has found nothing
for a week — and only one of those means nobody is being told about certificates
issued in their name. The list surfaces stale domains, and an on-demand check
answers 502 with the index's own words rather than an empty list.

That rule was exercised immediately: crt.sh returned 502s through most of the
live verification. The failure path is therefore the better-tested one, which is
not the worst outcome for a feature whose dependency is a free community service.

Two defects came out of running it against real data rather than fixtures.

A precertificate and its final certificate are logged separately and share a
serial, and the index publishes no field saying which is which — so a live check
of `badssl.com` reported **18** certificates where there are **9**. A headline
number wrong by a factor of two is one people act on. Entries are now labelled
by the one reliable signal (the precertificate is logged first, so it carries
the lower entry id), both rows are kept because "pre-logged, then issued" is
real information, and every count is per certificate.

And the synchronous check outlived the HTTP server's 30-second write timeout, so
the response was cut off mid-write and the caller got an empty body — which
reads as "nothing happened", the one conclusion that must never be reachable by
accident. The on-demand path is now bounded under it; the background poller
keeps its longer budget, because nobody is waiting on it.

Findings are matched to inventory on serial number, since the log index does not
publish a fingerprint. Both sides normalise first: CertPilot stores unpadded
lowercase hex and indexes pad and upper-case them, and a mismatch there would
report this system's own certificates as ones nobody manages.

**Step 5** covered the third place certificates hide: stored rather than served.
ACM, Azure Key Vault, Google Cloud load balancing, and Kubernetes TLS secrets.

The reason this belongs in a certificate lifecycle tool, rather than "because
cloud is popular", is one sentence: **cloud certificate stores do not renew
everything in them, and everybody believes they do.** AWS never renews an
imported certificate and says so in `RenewalEligibility`, a field beside a green
`ISSUED` on the console. A Key Vault certificate whose policy issuer is
`Unknown` was uploaded as a PFX and has no issuer to go back to — its lifetime
action can only send an email. A GCP `SELF_MANAGED` certificate sits in the same
list as its `MANAGED` neighbour and is renewed by nobody. A Kubernetes secret
without a cert-manager annotation was made by hand by somebody who may have
left. On each provider's own console, all four are indistinguishable from the
ones that renew themselves.

Severity therefore tracks **time rather than category**. The same self-managed
certificate is a note with a year left and an emergency with three weeks left,
and ranking them alike buries the one that matters among two hundred that do
not — the noise rule from step 1, in a new place. The inverse finding is the
sharpest of all: a provider that claims to renew a certificate and has not, days
from expiry, means automatic renewal has failed and nothing else would have said
so.

Two things are recorded that a naive inventory would omit. **Scopes** — what
each sync actually enumerated, in the provider's own words, including what it
cannot see: ACM is regional, and GCP Certificate Manager is not covered at all.
A tool that quietly covers one corner of a provider while presenting itself as
covering the provider produces a short list that reads as a small estate when it
is really a narrow search. And **attachment is three-valued**: attached, not
attached, or not knowable. A Key Vault has no idea what is serving its
certificates, and reporting "nothing is using this" there would be inventing a
finding.

No cloud SDK is vendored. The four providers are their REST APIs plus SigV4,
OAuth2 client credentials, JWT-bearer signing, and the instance metadata
services, written out — roughly two hundred transitive modules avoided inside a
process that holds every private key this system has issued. The signer is
checked against AWS's published test vector, because the failure mode of getting
it subtly wrong is a 403 that reads on a dashboard as the account refusing us.

Two defects came out of running it rather than testing it. An expired
certificate that nothing renews looked exactly like an expired certificate
cert-manager was about to replace on its own, because the two findings were
competing in one switch; they are separate facts now and both are raised. And
the import was rejected outright by a check constraint from migration 001 that
had never heard of `CLOUD` — invisible to every test, because the in-memory
store enforces no constraints. Writing `IMPORT` instead would have passed and
thrown away the answer to the only question that column exists for.

**Still open in this phase:** two replicas both run every schedule, every CT
monitor, and every cloud sync. Leader election over Postgres advisory locks
arrives with the renewal engine in phase 4, which has the same gap.

### Phase 4 — A renewal engine that survives 47-day certificates

Deferred deliberately: it is the last phase before deployment, and every earlier
phase widened what it has to renew.

| Step | | |
|:---|:---|:---|
| 1 | Renewal as a durable job, not a function call | ✅ |
| 2 | Backoff that tightens towards the deadline, and per-CA rate limiting | ✅ |
| 3 | ARI: let the CA say when, and when it changes its mind | ✅ |
| 4 | Post-renewal verification — confirm the new certificate is actually served | ✅ |

One sentence governs the phase:

> **Renewal is the only part of this system that changes the world.
> Everything else observes.**

Every other engine can be wrong, retried, or restarted with no consequence
beyond a stale screen. This one issues certificates, rotates private keys, and
replaces working material with new material. A discovery scan that runs twice
wastes a few seconds; a renewal that runs twice on two replicas issues two
certificates against a rate limit that is counted per week.

Which is why renewal stops being a call the scheduler makes and becomes a row
somebody owns. A process that dies mid-renewal must leave behind something that
can be picked up, not a certificate whose fate nobody recorded.

**Step 1** made that literal. A renewal is a row in `renewal_jobs` with a lease,
an attempt log, and a deadline it is racing.

The thing worth arguing about is what is *not* there: **there is no leader
election.** The roadmap said Postgres advisory locks, and building it that way
would have been a mistake. A leader is a single point of failure with a window
after it dies during which nothing renews at all, which is a strange thing to
put inside the one component whose entire job is that nothing lapses. Instead
the correctness comes from the schema: a partial unique index allows at most one
outstanding job per certificate, so two replicas sweeping in the same second
produce one job, and `FOR UPDATE SKIP LOCKED` means two workers never claim the
same row. Every replica is an equal worker and none of them is special.

The lease is the other half. A worker that is OOM-killed mid-renewal does not
need reaping — its claim expires and somebody else takes the job. Long renewals
heartbeat to extend it, because an ACME order waiting on DNS propagation can
outlive a five-minute lease and a job stolen mid-flight is one renewal becoming
two certificates.

Three decisions that look small and are not:

**A failed job stays outstanding.** There is no attempt count at which a
certificate stops needing to be renewed, so nothing is ever abandoned. It
escalates instead — after three failures, or after one when there is less than a
week of runway — and the alert fires once at that moment. A renewal retrying
every few minutes for a fortnight would otherwise put thousands of CRITICAL
messages into the channel that also carries CA expiry alerts, and a muted
channel takes those with it.

**Every attempt is kept, not just the last error.** "This has failed eleven
times in six days with the same DNS error" is a sentence somebody can act on;
`last_error: timeout` cannot distinguish a blip from a fortnight of silence.
Each entry names the replica that made it, because one replica failing and every
replica failing are different problems.

**The crash guard checks the outcome rather than trusting a key.** A worker that
finalised an order and died before writing the result would otherwise issue a
second certificate on retry. So the next attempt compares the certificate's
fingerprint against what it was at enqueue: if it moved on its own, the renewal
already happened. Verifying what actually changed beats an idempotency token,
because it is true however the world changed.

`POST /certificates/:id/renew` now answers 202 with a job. It used to call the
gateway inline and return the renewed certificate, which read well and was wrong
three ways: an ACME order with a DNS challenge outlives the 30-second write
timeout, so the caller got a truncated response for a renewal still running; a
failure meant one attempt and no record of it; and a restart mid-request left
nothing behind. Pressing it twice now returns the same job rather than spending
a weekly rate limit twice.

Two defects came out of reading the live output rather than the tests. A warning
that read *"8759 hours left"* — technically correct, and a number nobody parses
at a glance, which in a list of things needing attention means it does not get
read at all. And the same warning named certificates by UUID, so it could tell
somebody a renewal was broken without telling them which certificate it was.

Verified against the live database across a deliberate outage: four failed
attempts, a core restart in the middle, then success when the gateway came back
— all one job, `['fail','fail','fail','fail','ok']`, with the escalation raised
once on the third.

**Step 2** fixed the pacing, which step 1 had left deliberately wrong.

Ordinary exponential backoff rests on three assumptions: failures are transient,
retrying costs something, and there is no deadline. A certificate violates the
third outright. As expiry approaches, the cost of *not* retrying grows without
bound while the cost of retrying stays flat — so backing off further, which is
exactly what every backoff library does, is exactly wrong.

The delay is now the **smaller** of what the exponential curve says and what the
runway allows, where the runway is divided into a budget of twenty-four more
attempts. With a month left it behaves like ordinary backoff and sits at the
six-hour ceiling. With a day left it retries roughly hourly. With an hour left,
every few minutes. A certificate that has already expired retries at the floor,
because it is an outage now and getting it back matters more than politeness —
but never below a minute, since a CA answering the same error once a second will
not answer differently on the two hundredth try.

The other half is rate limiting, and the thing worth getting right is not the
counting. It is that **a renewal held back is not a renewal that failed.** A
public CA counts certificates per registered domain per week, and exhausting
that suspends issuance for the whole organisation — at exactly the moment
somebody is trying to fix an outage by reissuing. So the queue declines to
spend a slot it does not have, and records that as a deferral: `attempts` is
un-counted, `last_error` is left holding whatever real failure came before, and
nothing escalates. A job that waited nine times has not failed nine times, and a
system that reported it that way would teach people that escalation means
nothing.

Counted in the database rather than in a per-process token bucket, for the same
reason step 1 has no leader: N replicas each holding their own bucket would
allow N times the limit. And a limit that cannot be *read* never blocks a
renewal — turning a database hiccup into an expiry is a much worse trade than
being one certificate over a quota.

Unlimited is the default, deliberately. Inventing a conservative limit for a CA
whose real limits nobody has entered would delay renewals for a constraint that
does not exist, and a certificate that expired because this tool was being
careful is the worst outcome available.

Out of that falls the sharpest thing this engine can say — that the quota does
not free up until *after* the certificate has expired:

> step7-filter-probe.example.com cannot be renewed because the CA account's
> renewal rate limit is full until 29 November 2028, and it expires on 18 August
> 2027. Retrying will not fix this: the limit has to be raised, or this
> certificate moved to another CA account.

That is a loss with a date on it, months before the day, and it is deliberately
worded away from "renewal failed, retrying" — nothing is broken and retrying
will not help, so an alert that sent somebody hunting for a fault would waste
the warning.

One defect, found live rather than in the tests: the blocked-by-quota alert
published correctly and never persisted its escalation mark, so a certificate
deferred every hour would have sent the same CRITICAL message every hour until
it expired — the precise noise failure the rest of the engine is built to avoid,
reintroduced in the one path that had not been through it.

**Step 3** let the CA decide, and — the part that matters — let it change its
mind.

The ACME gateway has read RFC 9773 renewal information since phase 2. Nothing in
the core ever asked, so the advice was fetched during a status call, logged, and
thrown away. That is a strange thing to find in a tool whose entire subject is
knowing when certificates need replacing.

Routinely, honouring the window lets the CA spread load in a way a lead time
cannot: thirty days means every certificate issued in one week renews in one
week, forever. The client is meant to pick a **random instant inside** the
window rather than renewing at its start, and that randomness is the point of
the window rather than an implementation detail — renewing at the start would
move the thundering herd instead of dispersing it.

In an incident it is something else entirely. A CA facing mass revocation — a
CAA rechecking bug, a mis-issued intermediate, a broken validation path — pulls
the affected windows into the past. Clients that read ARI replace their
certificates within hours. Clients that do not find out by email, if the address
on the account still belongs to somebody, and otherwise find out when the
certificate stops working. **It is the only automated warning there is**, which
is why a window brought materially forward is a CRITICAL alert carrying the CA's
own explanation link, worded as what it means rather than what changed.

Three decisions worth naming.

**The CA's advice beats the lead time in both directions — but never off a
cliff.** It can bring a renewal forward and it can hold one back, because the CA
knows things about the certificate that the certificate does not say. Inside a
seven-day safety floor it stops being able to defer anything at all: a CA
publishing a bad window, or a poller that stopped running and left a stale one
behind, must not be able to talk this system out of renewing something that is
about to stop working.

**Support is three-valued.** Never asked, asked and unsupported, and asked with
an answer are three different states. Collapsing the first two would make a CA
nobody has reached look identical to one that has nothing to say — the same
mistake as a monitor with a single timestamp, in a new place. A gateway that is
down is likewise not recorded as "this CA publishes nothing", and it never
clears advice already given: a window does not stop being true because the next
call failed.

**The alert has a threshold.** The selected instant is a fresh random draw each
check, so two consecutive polls of an unchanged window differ by hours for no
reason at all. Alerting on that would mute the one message that matters during
an incident before the incident.

Verified live against the real database, driving the real gateway over the real
proto with a stand-in ACME directory: the RFC 9773 certificate identifier was
built correctly from the AKI and serial, the window was recorded with a random
instant inside it, Retry-After was honoured, a window pulled forward produced one
CRITICAL naming the CA and linking its explanation, moving it *further* into an
already-open window produced no second alert, and a certificate with sixty days
left — which the thirty-day lead time would never have queued — was renewed
because the CA asked.

One defect found by reading the delivered alert: it rendered the renewal moment
as a date, so something happening in fifty-five minutes read as "18 August
2026". During a revocation that is the difference between acting now and acting
tomorrow.

**Step 4** closed the phase with the question everything before it had assumed
the answer to: **is the thing in front of the users actually serving the new
certificate?**

Until now a successful renewal wrote a new certificate, incremented the count,
set the status to ISSUED, and published "certificate renewed". Every one of
those can be true while the server is still presenting the certificate it
replaced — and still expiring on that certificate's schedule. It is the sharpest
possible version of the failure this product exists to prevent, produced by this
product: a green dashboard over an expiring estate, where the inventory says
ninety days and the endpoint says twenty.

CertPilot deploys nothing yet, so "renewed but not deployed" is not an edge case
here. It is the normal state, and reporting it is the difference between a
renewal engine and a renewal engine somebody can trust.

The endpoints checked are the ones **discovery has actually observed serving
this certificate** — the two halves of the product finally holding each other
up. Not the SANs: probing hostnames read out of certificate data would have
CertPilot opening connections nobody asked for, to names that may not resolve to
anything it should be touching. A certificate discovery has never seen is
reported as `NO_ENDPOINTS`, with the sentence that makes it actionable — *"run a
discovery scan that covers wherever it is deployed and this will start being
verified"* — rather than guessed at. "We cannot verify this" is useful; a
fabricated verification is not.

Silence is never success. An endpoint that does not answer is `UNREACHABLE`, and
a certificate where some endpoints serve the new one and others do not answer is
*not* verified — the ones that did not answer are exactly the ones that might
still be on the old certificate.

Two defects, both from running it rather than testing it.

The renewal set the verification fields on the certificate and saved it with
`UpdateCertificate`, whose explicit column list did not include them, so they
were **dropped in silence** against PostgreSQL. Every test passed: the in-memory
store keeps whole structs and cannot express a dropped column. Found by renewing
a real certificate and watching `previous_fingerprint` come back empty. It is
now written through the narrow verification writer, which is where it belonged
anyway.

And after renewing twice without deploying, the endpoint — still on the
original certificate, two renewals back — was reported as *"something else is
terminating TLS there"*. Technically true and badly wrong: it sends somebody
hunting a rogue service when the answer is that renewals have been landing
nowhere. An older certificate for the same name now has its own words.

Verified live end to end: issue, deploy, scan so discovery links the endpoint,
renew, and the check answered **409 STALE** naming the endpoint; deploy the
renewed certificate and it answered **200 VERIFIED** and stopped asking; renew
once more and one CRITICAL arrived — *"Renewed, but not deployed:
verify-lab.local … CertPilot's record looks healthy; what users get expires on
the old schedule."*

The 47-day horizon is what forces the rest. When the CA/Browser Forum's maximum
lifetime lands, a certificate is renewed roughly every fortnight rather than
twice a year — renewal stops being an event and becomes a heartbeat, failures
become routine rather than exceptional, and anything that quietly stops working
has weeks rather than months before it is noticed.

### Phase 6 — Deployment, then the agent

Renewal that does not reach the server is only half the job, and this is where
the commercial tools earn their price. Phase 4 ended by being able to say,
honestly, that a renewal had not reached the server. This is the phase that can
do something about it.

| Step | | |
|:---|:---|:---|
| 1 | Deployment as a durable job, and the first target | ✅ |
| 4a | The agent: enrolment, and an identity the core cannot impersonate | ✅ |
| 4b | The agent inventories the certificate stores on its own host | ✅ |
| 4c | Local key generation and CSR submission | ✅ |
| 4d | Install and reload, as a deployment target | ✅ |
| 3 | Deploy on renewal, and the loop that proves it landed | ✅ |
| 2 | The deployers that need no agent: ACM, Azure Key Vault, F5 | ✅ |

**Steps 2 and 3 were deliberately taken out of order.** Kubernetes was going to be the
first agentless deployer and it should not be: clusters that manage certificates
already run cert-manager, and this roadmap's own out-of-scope list says
integrate with it rather than replace it. Writing a second thing that fights
cert-manager for ownership of a `kubernetes.io/tls` secret would have been worse
than writing nothing.

That leaves ACM, Key Vault and F5 — all real, none of them the reason anybody
adopts an agent-based CLM, and all of them reachable from the core in the same
shape as the webhook deployer that already works. The agent is the part that is
architecturally different, so it goes first.

Step 3 waits because it should: automatic deployment on renewal is the feature
that turns a mistake into a fleet-wide one, and it is worth having behind more
than one working deployer before it is switched on.

One sentence governs the phase, and it is not the same sentence that governed
phase 4:

> **Renewal creates new material. Deployment replaces material that is
> currently carrying traffic.**

A renewal that goes wrong leaves a certificate nobody installed — bad, and
recoverable by trying again. A deployment that goes wrong replaces a working
certificate on a live listener. Everything in step 1 is shaped by that
difference: nothing is deployed that has not been parsed, nothing is deployed
without the key that matches it when a target needs one, every attempt is
recorded against the *place* it was made, and success is reported as what it
actually is.

**Step 1** makes a deployment a row somebody owns, exactly as renewal is. The
same durable queue, the same lease, the same attempt log, the same
deadline-aware backoff — a certificate that has been renewed and not installed
runs down precisely the same clock as one that was never renewed at all, so the
retry curve tightens towards expiry for the same reason.

The one place the renewal queue's shape would have been actively wrong is the
partial unique index. Renewal allows one outstanding job per certificate,
because a second renewal issues a second certificate. Deployment is the opposite
case: **the index is on the binding, not the certificate.** A wildcard on six
load balancers needs six jobs outstanding at once, and copying renewal's
constraint would have deployed to the first target and dropped five without a
word.

That is also why `certificates.deployment_target_id` — one certificate, one
place, since migration 001 — is superseded by a binding table. One certificate
in six places has six outcomes, six fingerprints, and six ways to be
half-finished. A single `deployed_at` on the certificate averages them into a
number that is true of nowhere.

**What is deployed is the certificate as it stands now, not the fingerprint the
job recorded at enqueue.** If a second renewal happened while the job waited,
installing what the job was created for would push an older certificate onto a
live listener — and that renewal's own enqueue may well have been a no-op,
because the binding already had a job outstanding. The captured fingerprint stays
as provenance; it never selects the bytes.

The first deployer is the generic signed webhook, which is the escape hatch: any
receiver anybody can write fifteen lines of HTTP handler for becomes a
deployment target. Two of its rules are stricter than the notification
webhook's, and both follow from what the endpoint can *do* rather than what it
carries:

- **A signing secret is mandatory.** An unsigned alert webhook means a receiver
  might act on a fabricated alert. An unsigned *deployment* webhook means anyone
  who can reach the receiver can install a certificate on whatever it feeds —
  their certificate, their key, your hostname.
- **Private keys do not cross plaintext HTTP off the machine.** The exception is
  a loopback address, where there is no wire; that is the local-agent case, and
  refusing it would rule out the one topology where plaintext is harmless. A
  hostname that merely resolves to loopback today does not count.

`deployment_targets.deploys_private_key` is a plain column rather than something
derived from the sealed config at read time, because **"which places does this
organisation ship private keys to" has to be answerable with a SELECT** — by
somebody who does not hold the KEK and cannot decrypt a single deployment
credential.

Verified live end to end against a receiver written independently in Python,
which verified the documented HMAC itself: issue, bind, deploy, and the receiver
installed it and brought up a TLS listener; scan so discovery links the
endpoint; renew without deploying, and **both halves agreed from different
evidence** — the binding said *"1 holding an older certificate"* from its
recorded fingerprint with no network at all, and the verifier said **409 STALE**
from an actual handshake. Deploy, and it went to `200 VERIFIED`. Then the
receiver was made to refuse: three failures, the job stayed `PENDING`, one
CRITICAL arrived, and the binding kept the fingerprint it was really holding
rather than the one that failed to arrive. Signing the delivery with the wrong
secret produced `401: bad signature` from the receiver and that exact sentence
in the attempt log.

Running it caught a defect the tests did not. The binding summary reported only
what each place was holding, so a target that held the current certificate *and*
had failed its last three deployments read as **"All 1 target hold the current
certificate"** — true, reassuring, and precisely the half-told story this
product exists to stop other tools telling. What a place holds and whether the
last attempt to change it worked are two facts, and both belong in the sentence.

**Step 4a** gives the agent an identity, and the shape of that identity is the
whole argument for the agent existing at all.

The agent generates an Ed25519 keypair on the host during enrolment and sends
only the public half. Every request afterwards is signed with the private one,
which never leaves the machine. **The core stores nothing that can impersonate
an agent** — a database that leaks yields public keys. That is the same property
local key generation gives the certificates in 4c, arriving one step early, on
the agent's own credential.

It is not mTLS, and that is a decision rather than an omission. The core is
routinely deployed behind a reverse proxy — the shipped compose stack puts nginx
in front of it — and client-certificate authentication terminates *at the proxy*.
What reaches the application is a header, and a header is forged by anything that
can reach the core directly. An application-layer signature is checked by the
process that acts on the request, so it survives every proxy, ingress and mesh
in between.

What the scheme covers is stated exactly: method, path, timestamp, and a hash of
the body. So a heartbeat's signature cannot be lifted onto a route that does
something, and nothing in the body can be altered in flight. What it does **not**
prevent is an identical request replayed inside the five-minute window — and
there is no nonce, deliberately. A nonce would have to be checked against
something every replica shares, and one checked in a single replica's memory is
decoration: it implies a property that does not hold across a deployment of two.
**Decoration in a security mechanism is worse than its absence, because people
rely on it.**

Three smaller decisions that matter more than they look:

**Enrolment is a different credential from operation.** A one-use, one-hour
token bootstraps a host that has never spoken to CertPilot, and is exchanged for
the agent's own key. A long-lived shared enrolment token pasted into a
configuration-management template is a credential in a git repository, and it is
how this kind of system is usually broken. The token is spent by a conditional
`UPDATE`, not by a read followed by a write, because two hosts from the same
image enrol in the same second.

**The signature is checked before the agent's status.** Checking status first
would make a revoked agent distinguishable from an unknown one to anybody who
can guess an id — a fleet-enumeration oracle. Checking it second means the only
caller ever told *"you have been revoked"* is the one holding the private key,
which is exactly who needs to hear it: the agent reads that 403 and stops,
instead of knocking every few minutes for as long as the host stays up.

**An agent that goes quiet is a problem, not an absence.** This is where this
system's own principle is easiest to violate, because the absence of a heartbeat
is literally nothing happening. A host whose agent died three weeks ago still
has certificates on it, still has them expiring, and now has nothing maintaining
them — and it looks exactly like a healthy host on any screen that counts
enrolled agents. So the fleet monitor reports it, once, measured against what
that agent itself promised rather than one global number.

Verified live: enrolled a host, watched the key stay on disk at `0600` in a
`0700` directory while only the public half crossed the wire; the spent token
was refused; a hostile client holding the key had a swapped body, a signature
minted for another route, and timestamps an hour either side all refused with
one uniform sentence while the log named which check failed; revoking a
*running* agent made it stop by itself; and a host that went quiet produced one
WARNING naming the consequence rather than the observation.

Running it caught three things the tests did not. The fleet list said *"1 agent,
all reporting"* about an agent that had never reported once — a sentence built
from the stale count claiming something the stale count cannot know. The
revocation path returned a flat 401 from the middleware, so the agent could not
tell a withdrawn credential from a misconfiguration and would have retried
forever; fixing it is what produced the check-signature-then-status ordering
above. And the staleness query worked with a literal `now()` and failed against
PostgreSQL with a bound parameter, because an untyped `$1` in `$1 - <interval>`
is inferred as an *interval* — the fourth defect in this project that the
in-memory store cannot express and only a real database run has ever found.

**Step 4b** is the fourth place certificates hide.

Migration 011 called cloud stores the third, after what is served and what was
issued. This is the one none of the other three can reach: **a file on a disk**,
on a host behind two firewalls, issued by an internal CA, on a port nobody
scanned. That is where a great deal of an enterprise's TLS actually lives.

But finding files is not the reason this step matters. A process running *on*
the host can see two things no remote observer ever will, and both outrank most
of what the rest of this system reports:

**The private key's permissions.** `server.key` at mode 0644 means every account
on that machine holds the key to that certificate. No scanner, no transparency
log, and no cloud API can report that — it takes one `stat` from a process on
the host. And the message has to say what the fix is, because the instinct on
reading "key exposure" is to renew, and **renewing leaves the exposure exactly
where it was**: the certificate has to be reissued.

**Whether the key matches the certificate.** A mismatched pair is a service that
will not come back after its next restart, sitting quietly until something
unrelated restarts it — a deploy, a kernel update, an outage at three in the
morning. It gets its own topic rather than sharing the one above, because they
are different problems with different owners.

The agent sends certificates as **PEM, unparsed**. Parsing centrally is a
deliberate split: this binary runs on machines nobody upgrades for years, and
parsing logic living on five hundred of them is parsing logic that cannot be
fixed. What the agent does compute is the part that needs the host — file modes,
ownership, whether a key is beside the certificate and whether it belongs to it.
It parses a key only far enough to derive its public half and compare, and
**there is no field in the report a private key could travel in.**

Two pieces of noise control decide whether any of this gets read. A host's
`ca-certificates` bundle holds well over a hundred roots the distribution
manages and nobody here is responsible for; it is recorded as one row that says
so. And "no configuration names this file" is only claimed on hosts where the
reference heuristic matched something — otherwise it is a finding about the
heuristic rather than about the host.

The connective finding is `superseded`: this file holds the certificate a
renewal already replaced. That is post-renewal verification's conclusion
arriving from a third direction — and unlike the verifier, it needs no scan to
have ever reached the host.

Verified live against a host built to look like a real one: seven certificate
files including an exposed key, a combined HAProxy cert-and-key at 0644, a
mismatched pair, an expiring certificate nginx is configured to serve, a
certificate with no key at all, and a thirty-root trust bundle collapsed to one
row. Then a managed certificate was issued onto that host and renewed without
touching it, and the next scan said: *"This file holds the certificate that
shop.example.com was renewed away from … It is named in nginx.conf, so whatever
reads that configuration is serving the certificate this replaced."*

Running it caught four things. Every self-signed certificate came back
classified as a CA, because OpenSSL's `req -x509` sets `basicConstraints
CA:TRUE` by default — so on an internal estate, which is mostly self-signed,
almost everything would have skipped the findings that only apply to leaves. The
fix is to stop trusting what a certificate claims about itself and ask whether
it identifies a host: a genuine root has no DNS names. `--once` heartbeated
without inventorying, which quietly ruled out running the agent from a systemd
timer rather than as a daemon. The fleet summary said *"2 certificate files
has"*. And the key alert lumped exposure and mismatch into one message saying
"one of these two things", which makes the reader go and look — the work an
alert exists to save.

**Step 4c** is the claim this product is built on, made true.

Everything issued before this was issued by asking a gateway for a certificate
*and a key*. That key was generated where it did not need to exist, travelled
over gRPC, was sealed into the database, and — if the certificate was ever
deployed — travelled again to the host serving it. Three places and two
journeys, for a secret whose whole security model is that it stays in one.

Now the agent generates the key on the host, signs a CSR with it, and sends only
the request. **CertPilot never sees the key and cannot produce it.** `GET
/certificates/:id/private-key` answers 404, truthfully.

`certificates.key_custody` makes that legible. "No key stored" used to mean one
thing — discovered or imported, somebody else holds it. It now also means the
best possible outcome, and the two must not look alike: `CERTPILOT` (sealed
here, and therefore losable, copyable, subpoenable), `AGENT` (on a host, never
anywhere else), `EXTERNAL` (somebody has it and it is not us). *"Which of our
certificates have keys we could not export even if we wanted to"* is a question
a security team should be able to answer.

**Authorisation is the whole security surface**, and getting it wrong is worse
than not having an agent. A credential that can request any name is a way to
obtain a certificate for the payroll system from a compromised web server,
signed by the organisation's own CA, sitting in the audit log next to every
legitimate issuance. So nothing is signed that an operator did not grant in
advance, and the checks are these:

- **A grant targets one agent or a set of labels**, and the labels come from the
  enrolment token, not from the agent — so a host cannot label itself into a
  grant written for another tier. Four hundred web servers are one grant; the
  alternative is a grant per host created by a script, which is how a fleet ends
  up with four hundred wildcards nobody reviewed.
- **One grant must cover the whole request.** Assembling permission from several
  would let a host combine one tier's names with another tier's CA account, and
  the certificate would be something nobody authorised as a whole.
- **The common name is authorised too**, not just the SANs — otherwise a request
  with permitted SANs and an unpermitted CN produces a certificate for a name
  nobody granted.
- **`*` is refused as a grant.** A grant permitting every name makes the agent
  credential equivalent to the CA behind it, and there is no way to write "I
  meant it" that is better than listing the domains.
- **A request asking to be an authority is refused, not stripped.** A correct CA
  ignores CSR extensions and builds its own template — which is what the
  gateways here do — but "the code downstream is careful" is a hope about code
  that may be a third-party gateway next year, not a control. A CSR carrying
  `basicConstraints CA:TRUE` or `keyCertSign` gets an error.
- **The CSR signature is checked.** Without it, anyone reaching the endpoint
  could obtain a certificate for somebody else's public key — which is a
  certificate issued to that somebody else, by an authority this organisation
  runs.
- **A gateway that returns a private key for a CSR-based request is refused.**
  It means the gateway ignored the request and generated its own pair, and
  storing that would leave the host's certificate and the database's key
  mismatched with both looking fine.

The agent renews its own, because it is the only thing that can: rotating means
generating a key. The core's renewal sweep excludes `key_custody = 'AGENT'` for
exactly that reason — without it the queue would claim those jobs and fail
forever, which is a loud way of being wrong about something that works. *When*
to renew is the core's decision, carried back in `renew_after`: a host that
picked its own moment could decide to renew hourly, and four hundred of them
would be a denial of service against the CA.

One gap had to be closed first: the selfsigned gateway ignored `csr_pem`
entirely and always generated its own key, so no gateway in the tree could do
CSR-based issuance except ACME. It signs requests now — which meant giving it a
CA, because a self-signed certificate is one whose *subject key* signed it, and
that is precisely what a CSR makes impossible. In memory, per process, so a
development CA cannot quietly become load-bearing.

Verified live end to end: enrolled a host, watched a request with no grant get
refused by name; created a label-matched grant and had `*` refused as one;
obtained a certificate whose key never left the host — confirmed by comparing
the public key in the file against the one in the certificate, with `GET
private-key` answering 404. Then a hostile client holding a valid credential and
a valid grant tried a CSR with a permitted CN and an extra SAN (**refused**), and
a CSR asking for `CA:TRUE` (**refused**), each producing a WARNING that says the
two things it could mean and refuses to pick one. Finally the agent rotated its
own key on a certificate that was due, and the new one had never been anywhere
either.

Running it caught five things. The agent treated the issuance refusal's 403 as a
revocation and **shut itself down over a missing grant** — 403 is the right
status for both, so the body now carries a code and the client reads it. The
provenance check constraint refused `'AGENT'`, which is migration 012's lesson
for the third time and the second widening of the same constraint. The response
envelope was not decoded, producing a certificate on disk with an expiry in year
one. `--once` did not renew, which quietly ruled out running the agent from a
systemd timer — the case where renewal matters most. And the key-size floor
compared one number across algorithms, so a grant written for RSA-2048 refused a
P-256 key for being "smaller" when it is considerably stronger.

The scanner from 4b also produced a CRITICAL about a chain file whose "key" was
the leaf's, found by a conventional filename in a directory holding both. A
guess that turns out wrong is evidence the key is elsewhere, not evidence the
pair is broken — so a stem-named key that mismatches is still a finding, and a
conventionally-named one is only accepted if it matches.

**Step 4d** is where the agent stops holding certificates and starts installing
them.

Everything up to here lands in the agent's own state directory, which is not
where nginx reads. Closing that gap is the first time this binary writes to a
file another process depends on, so it is the second thing in the system
governed by the sentence at the top of this phase — and the first one where the
process doing the replacing is on the far side of every firewall, with nobody
watching.

**Where a certificate goes, and above all what to run afterwards, is declared on
the host.** There is no wire format for a destination in `certpilot-agent-sdk/agentapi`, and
that absence is the security argument of the step rather than an oversight: a
core that could hand a host a command to run would be a fleet-wide remote
execution channel with a certificate manager on the front of it, authenticated
by whoever can write one row. The core may say *install certificate X*; it may
never say *and here is what to run*. `agent_installations.reload_command` exists
so a central team can see that installing a certificate on that machine runs
`nginx -s reload` without having shell on it — and seeing it is the opposite of
being able to set it.

The install is three steps, not one, and the middle one carries the weight:

> Write the files. Ask the server whether it can live with them. Only then tell
> the running process to pick them up.

A `check` that fails costs a rollback of files nothing has read yet. The same
failure without a check costs a listener. So a failed check restores the files
and never reloads, and a failed *reload* restores them **and reloads again** —
because at that point the process is running on material that is no longer on
disk, and putting the files back is not enough on its own. What was there is
kept in memory rather than in a `.bak`, because a private key copied to
`server.key.bak` is a private key nobody is tracking.

Three smaller decisions:

**Nothing is written or reloaded when the bytes already match.** An agent that
reloaded nginx every five minutes because it could would be a worse problem than
the stale certificate it was fixing. But the declared mode and ownership are
enforced on every pass, without a write and without a reload — so a key somebody
chmodded to 0644 during an incident three weeks ago is quietly put back. That is
step 4b's CRITICAL finding, fixed by the only process in the system that can.

**The agent refuses a world-readable `key_mode`, at load, naming the mode.** It
must not create the finding it exists to report — and the fix for that finding
is reissuance, not a later `chmod`, so writing one on request would be a tool
manufacturing its own alerts.

**A destination declared for a certificate the host does not hold is a finding,
not silence.** `UNFULFILLED` is the status nothing else in this system can
produce: there is no binding, no certificate and no failed attempt, just a
machine configured for a name nobody granted it that will do nothing at all when
the renewal it is waiting for never arrives. It is almost always one character.

Then the agent becomes a deployment target like any other — with one inversion.
Every other target is deployed to by a core worker opening a connection; a host
behind two firewalls **claims the job itself**, off the same queue, with the same
lease, the same retry curve and the same attempt log. Only the worker moves. The
core's own claim query excludes agent targets for the reason the renewal sweep
excludes agent-custody keys: a worker that took one would fail it until the
attempt budget ran out, being loudly wrong about something that works.

The target appears on its own when a host first reports a destination, because
four hundred hosts are four hundred targets and a product that asks somebody to
create them by hand gets a script that creates them by hand. It carries
`deploys_private_key: false` as a fact rather than a default: the key was
generated on that host and is already there, so agent hosts are correctly absent
from the answer to "where does this organisation ship private keys" — which is
the property step 4c existed to create, showing up in a column somebody else
reads.

Verified live against a host built to behave like a real one: a TLS listener
holding its material in memory and reloading on SIGHUP, a `check` that verifies
the certificate and key match with `openssl`, and a `reload` that signals the
process. Install, and **an actual TLS handshake returned the certificate the
host had generated the key for** — not a status column agreeing with itself.
Then a new certificate arrived with the check failing: the destination kept the
old bytes, the listener kept serving them, and the message said so. Then the
check passed and the *reload* failed: same outcome, arrived at differently.
Then recovery, and the handshake returned the new certificate. A second host
holding a valid credential tried to report the first host's deployment as done
and got `403 not_permitted`. And the core queue, given four poll cycles at a job
for an agent target, left it at `attempts=0`.

Running it caught four things the tests did not, and one the tests caught first.

The one the tests caught is the worst: **the rollback deleted a file that had
been working.** `for _, f := range files` hands out a copy of each element, so
capturing the previous contents wrote them to a value that was then discarded,
and the restore — finding no previous contents — concluded the file had not
existed and removed it. Nothing would have surfaced that until a reload failed
in production.

Of the four found by running: **an agent that renewed left two bindings on one
destination**, both saying that place was holding the current certificate. An
agent obtains a new certificate rather than replacing one in place, so the old
binding stayed beside the new one — two confident sentences about one file,
where only one of them is true, which is precisely the failure mode this
product exists not to have. Bindings are reconciled to the report now, exactly
as the installations are.

**The ordinary HAProxy destination was refused.** `cert_path` and `key_path`
being the same file is the layout HAProxy wants, and the file correctly takes
the key's mode — but the guard against a world-readable certificate mode fired
on the *default* rather than on anything anybody had written, rejecting the
destination this project keeps finding at 0644 and wants people to write.

**The attempt log recorded a negative duration.** The start time was worked back
from the queue's own three-minute lease, and a host claims for ten — because it
has files to write, a configuration to check and a service to reload before it
can say anything — so the arithmetic put the start of the attempt seven minutes
in the future.

And the binding summary said **"All 1 target hold the current certificate"** —
the plural form producing a sentence that reads as a machine talking, in the one
place a person goes to find out whether their certificate arrived.

**Step 3** is where the button presses itself, and it is the most dangerous
change in the phase. The sentence at the top of it stops being about one
deployment and becomes about all of them at once:

> Automatic deployment on renewal is the feature that turns one mistake into a
> fleet-wide one.

So the whole step is brakes rather than accelerator, and the two that matter are
a default and a predicate.

**The default: new bindings deploy automatically, and every binding that existed
before this did not.** Those look contradictory and are not. A binding created
from now on is created by somebody who knows the feature exists, and "install
this certificate there" plainly includes "when it changes". A binding that
already existed was made under a regime where nothing deployed by itself, and an
upgrade that silently began writing to production servers would be exactly the
fleet-wide mistake above, delivered by a package manager. The cost of that
choice is real — a switch nobody turns on is a feature nobody has — and it is
paid in words rather than in defaults, on the page an operator is already
looking at: *"1 target will not be updated when it renews, and will hold an
older certificate until deployed by hand."*

**The predicate: a job that has not itself failed waits while another job for
the same certificate has.** That is a canary that needs no configuration to
exist, on every certificate, with nobody having declared anything. The first
target attempted proves the certificate is installable; if it does not, the rest
of the estate is never touched. When the failure clears, they resume on their
own.

Explicit deployment waves were designed and dropped in favour of it. Ordering is
a real feature and a later one, and shipping the two together would have been
two half-built controls instead of one working one.

The bound it gives is worth stating exactly rather than generously. **A bad
rollout reaches at most as many targets as there are workers**, not one and not
all of them — two per replica, because both workers claim before either has
failed. Measured, not assumed: with three targets and all three receivers
refusing, two were contacted twice each over several retry cycles and the third
was never contacted at all.

The other half of the step is the loop closing. Deployment's success is a claim
that bytes were accepted; the verifier's is evidence from a handshake. Until
now, a renewal scheduled that check half an hour out because deployment was a
person doing something later — so once every place a certificate belongs is
holding it, the check comes forward to three minutes. Not zero: a verification
that ran the instant a deployer returned would report the reload it did not wait
for, and a false STALE costs the same afternoon as a real one. And not at all
until the rollout is complete, because a partial one verified early is a STALE
nobody needed to see.

One deliberate non-choice: deployments are enqueued by a direct call from the
renewal executor, not by subscribing to the `cert.renewed` event it publishes
two lines later. The broker drops the oldest event on a slow consumer, which is
the right policy for a wall display and precisely the wrong one here. A dropped
event would be a certificate that renewed and silently never deployed — the
failure this phase exists to prevent, produced by the machinery meant to prevent
it.

Verified live against three independent receivers. A renewal nobody asked for
queued three deployments, all three installed, and each receiver recorded the
new fingerprint from its own side; the binding summary and the receivers agreed
from different evidence. Then the estate was broken: two targets refused, the
third was never contacted, and after three attempts the alert said *"1 other
target is waiting behind it and will not be attempted until this one succeeds"*
— because a rollout halted on purpose looks exactly like a queue that has
stopped working, and the message has to say which it is. The estate was then
fixed, nothing was pressed, and the rollout drained by itself with the untouched
third target getting the certificate.

Running it caught three things, and one of them was the feature not working at
all.

**The halt leaked once per retry cycle.** The predicate looked for a job that
had failed and was *waiting*, and a failing job spends part of every cycle
RUNNING — so during those seconds nothing looked failed and the rollout marched
on one target at a time. Having failed is a property of the job; being idle is a
property of the moment, and the first version keyed on the wrong one.

**The in-memory store dropped the new column on update.** `deploy_on_renewal`
was added to the model and not to the writer that copies fields onto an existing
binding, so switching it off silently did nothing. That is migration 016's
lesson for the second time, in the store that is supposed to be the simple one.

**And a cleanup script deleted six certificates it had not asked for.** It
requested `?search=<name>`; the certificates endpoint has never read a `search`
parameter, so the filter was dropped, the list came back as the whole estate,
and the loop deleting what it matched deleted everything. The fix is not to add
the parameter: **a filter an endpoint does not understand is now a 400 that
names it.** A narrowing parameter that silently does not narrow is harmless on a
page a person reads and destructive the moment anything acts on the result.

**Step 2** is three deployers that share one mistake.

ACM, Key Vault and a BIG-IP have nothing in common architecturally — an AWS API,
an Azure vault, an appliance on a management address reachable from nowhere. But
all three offer the same failure, in three vocabularies, and in every case the
API returns 200:

| | The one-field mistake | What is actually being served |
|:---|:---|:---|
| ACM | `ImportCertificate` with no `CertificateArn` | Every listener still points at the old ARN |
| Key Vault | Import under a new name | Whatever reads the old name is on the old certificate |
| F5 | Install under a new crypto-store name | The client-SSL profile references the previous one |

> **Installing the certificate is the easy half. Installing it as the thing that
> is already being served is the job.**

Get it wrong and the deployment succeeds, the attempt log says so, the
provider's console shows a fresh green certificate beside the old one, and the
thing in front of the users expires on schedule. That is this product's own
founding complaint, available as an omitted field. So the identifier of the
thing being replaced is required **per binding and refused at binding time** —
a 400 somebody reads, rather than a success nobody questions. ACM goes further
and refuses the *result*: an import that comes back with a different ARN means
it created rather than replaced, and reporting that as a deployment would be
reporting one that nothing is serving.

The F5 deployer stops after installing over the existing name, and does not
touch the client-SSL profile. Pointing an existing profile at a *different*
certificate is a change to what a virtual server serves, and that belongs to
whoever owns the virtual server. Replacing the material behind the name they
already chose does not.

**A cloud target borrows a connection's credentials rather than storing its
own.** Two copies of one AWS key — one in `cloud_connections` for discovery, one
in `deployment_targets` for deployment — is one rotation away from a system that
can read an account it can no longer write to, and that surfaces at the worst
possible moment. Proven rather than asserted: the target's sealed config was
decrypted straight out of the database and holds `{"connection_id": …}` and
nothing else.

It also closes a loop this project opened. Phase 5's headline finding is that an
*imported* ACM certificate is never renewed by AWS and that almost everybody
believes otherwise. The account that finding comes from is now the account this
deploys to, and the certificate it names is the one being replaced.

None of this needed an AWS SDK. `cloudsync` has spoken these APIs over plain
HTTP since phase 5 — hand-rolled SigV4, checked against AWS's published test
vectors — so the write side is a method beside the read side rather than two
hundred modules of dependency inside a process that holds every private key this
system has issued.

**What was verified, and what was not.** ACM was exercised end to end against a
stub that verifies the SigV4 signature independently, recomputing it from the
connection's secret: a renewal nobody asked for reached it, the ARN was
preserved, and the read-back reported what was using the certificate. Docker was
unavailable on this machine, so LocalStack was not used and no real AWS account
was touched. **Key Vault and F5 were written to their published APIs and are
covered by unit tests only** — neither has been run against a real vault or a
real appliance, and a misreading of either API would pass every test here. That
is recorded as a gap rather than smoothed over.

Running it caught two things. The endpoint override key was guessed rather than
looked up, so the first test run **signed requests with test credentials and
sent them to the real `acm.eu-west-1.amazonaws.com`** — rejected, harmless, and
exactly the accident a test suite should be incapable of having. And a
pre-existing test used `"f5"` as its example of a target type nothing can deploy
to, which stopped being true the moment this shipped; the negative case is now a
name nothing will ever implement.

### Phase 7 — More CAs

**HashiCorp Vault PKI ✅** — issue, renew, revoke and status against a PKI
mount, with token, AppRole or Kubernetes auth; CSRs signed by preference so a
key generated on a host stays there; tokens cached and renewed rather than one
login per issuance. Verified against a real Vault, not only against a stub — a
distinction that earned its keep, because the first live run found that
`sys/health` is not wrapped in Vault's data envelope and every real Vault was
therefore being reported as uninitialized.

Vault is also the first CA that will describe itself, and that turns out to
matter more than the issuance:

> Vault does not shorten a certificate that would outlive its issuer. It
> **refuses to sign it**.

So the day an issuing CA comes within one certificate lifetime of its own
expiry, every renewal through it fails at once, with a message about a
`notAfter` date that says nothing about the cause. The gateway reports the
mount's issuers and their expiry through `GetCAInfo`, says it at account
creation, and translates the refusal if it arrives anyway.

**The core now records what `GetCAInfo` returns ✅.** Connecting a CA account
imports the CAs behind it, and from that moment they are in the same inventory
as the certificates they signed — monitored, thresholded, alerted on, and
sorted by urgency on the wall display. One rule governs the importer: *the
certificate is the truth.* A gateway's account of a CA is hearsay about a
document CertPilot has been handed, so everything derivable is derived from the
certificate, and the gateway is believed only about the two things it does not
contain — what the CA is called where it lives, and where the mount publishes
its CRL. What an operator decided — the name, the thresholds, the owning team,
the notes — is never touched by a sweep.

This is also where the ACME gateway's `GetCAInfo` turns out to be a placeholder:
ACME publishes no endpoint listing issuer certificates, so it returns the
directory URL and nothing to track. The importer skips it and says so rather
than creating a row that looks monitored and has no expiry. The real answer for
public CAs is the chain already stored against every certificate, which is a
different piece of work.

Then Microsoft AD CS, AWS Private CA, Google Cloud CAS, EJBCA, DigiCert,
Sectigo.

One gateway that genuinely works beats five stubs.

### Phase 8 — Cryptographic posture ✅ (issuance deferred)

Deliberately **not** "issue ML-DSA certificates". For public TLS that is not yet
possible: the CA/Browser Forum has not updated the Baseline Requirements, and in
February 2026 Google stated Chrome has no near-term plan to accept post-quantum
algorithms in traditional X.509 certificates in its root store, pursuing
[Merkle Tree Certificates](https://datatracker.ietf.org/wg/plants/about/)
instead. The urgent quantum risk — harvest-now-decrypt-later — is already
addressed by hybrid key exchange that browsers ship today.

The useful work is knowing where your cryptography lives and what breaks when it
changes:

- **CBOM export** (CycloneDX 1.6) from the existing inventory
- **Quantum-readiness scoring** per certificate and endpoint, mapped to CNSA 2.0
- **Hybrid key exchange visibility** — "142 of your endpoints do not negotiate
  X25519MLKEM768" is a sentence no open-source tool can produce today
- **ML-DSA and composite issuance in the private-CA gateways**, where it is
  legal and usable now

[Migration 002](migrations/002_crypto_agility.sql) laid this schema in the first
week of the project. Nothing wrote to it for twenty-three migrations. Migration
025 is the one that fills it.

**One distinction governs the whole phase, and most reporting on this subject
has it backwards:**

> A classical **signature** is a problem in the 2030s. A classical **key
> exchange** is a problem this afternoon.

Nobody forges a handshake that already happened. An RSA-signed certificate
expiring in ninety days is not a quantum risk — it will be replaced many times
before a relevant quantum computer exists. But traffic protected by a classical
key exchange can be recorded today and decrypted whenever that machine arrives,
and the fix is already shipping in every current browser.

So a report that leads with "your certificates use RSA" has ordered the work by
which fact was easier to collect. This one leads with the handshake:

```
3 of 6 scanned endpoints do not negotiate a post-quantum key exchange. Traffic
to them can be recorded today and decrypted whenever a quantum computer arrives
— and unlike certificate algorithms, that is a cost being paid now rather than a
deadline in the 2030s.
```

That sentence needs a real connection to a real server, which is why this lives
in the scanner rather than in the inventory. An inventory knows what a
certificate is signed with; only a handshake knows what a server chooses.

**`offered_hybrid` is the load-bearing column and looks like the least important
one.** "This endpoint did not negotiate a post-quantum group" is a finding about
the server only if CertPilot offered one — otherwise the identical row is a
finding about CertPilot. Go enables X25519MLKEM768 by default and that default
could change in a release, so the scanner now states its curve preferences
explicitly and records what it offered against every observation. A finding
whose meaning depends on the observer is not a finding until the observer is on
the record.

Three more distinctions the assessment refuses to collapse:

- **TLS 1.2 cannot be fixed by enabling a group.** There is no hybrid key
  exchange below TLS 1.3, so those endpoints need a protocol upgrade — a much
  bigger job that reads identically to the smaller one unless the message says
  so.
- **SHA-256 is a shortfall, not a break.** Grover halves the effective preimage
  resistance, so it offers 128 bits where CNSA 2.0 asks for 192. Lumping it in
  with SHA-1 would be false and would teach the reader to ignore the category.
- **Something broken today outranks something broken in 2035.** A certificate
  signed with SHA-1 is forgeable now by anyone with a modest budget, and burying
  that under a paragraph about quantum computing would be this product's
  founding complaint committed by this product. Those get their own verdict and
  their own line in the summary.

The score is stated as what it is: **the percentage of applicable CNSA 2.0
requirements met, not a risk score.** A certificate scoring zero is the normal
and correct state of nearly every certificate in production today, and
presenting that as an alarm is how a report gets muted. What it is for is
measuring movement — the same estate, six months later. The suite is written out
in the code so a reader can check it against the NSA's publication rather than
trusting this project's memory of it; the transition *dates* are deliberately
absent, because they have been revised, differ by category, and a compliance
tool that invents a deadline is worse than one that reports none.

**CBOM export is CycloneDX 1.6, validated against the published JSON schema in
the test suite** rather than against a reading of it. Algorithms are emitted
once and referenced by every certificate that uses them, so "what does moving
off SHA-256 touch" is a graph query rather than a search — which is the only
reason the document is worth producing over a list. The serial number is derived
from the contents, so two exports of an unchanged estate are byte-identical and
a diff means something.

Verified live against real infrastructure: Google, Cloudflare and Amazon all
negotiated X25519MLKEM768; three TLS 1.2 endpoints could not, and were reported
as needing a protocol upgrade rather than a setting. The resulting CBOM
validated against the real schema.

Running it caught one defect the tests did not. The classical security level was
looked up by algorithm *family* — and "ECDSA" is the same word for P-256 and
P-521 — so the strongest and weakest elliptic keys both reported no classical
strength at all. A CBOM with a hole in exactly the common case.

**Issuance is not done, and is blocked rather than skipped.** `crypto/mldsa`
does not exist in Go 1.26 and `crypto/x509` cannot build or parse an ML-DSA
certificate, so issuing one would mean hand-rolling ASN.1 in a certificate
management product plus a third-party signature implementation — for a
certificate almost nothing can verify. That is a demo, not a feature, and it
waits for the standard library.

---

---

## Next

Ordered by what unblocks the most people, not by what is most interesting to
build.

### Phase 9 — Containers, and proof that they run

`deploy/docker-compose.yml` exists and has never been built. That is recorded
as a known gap rather than presented as working, and it is now the single
biggest obstacle to anybody trying this: the quick start needs Go 1.26, Node 20
and a local PostgreSQL, which is a thirty-minute detour for somebody who wanted
to spend ten minutes deciding whether the product is interesting.

It is first for that reason and no other. Nothing in this phase makes CertPilot
better at managing certificates. It makes the difference between a reader who
evaluates it and a reader who closes the tab.

- **Build every image and run the stack from them.** Six modules produce five
  binaries — core, three gateways, the agent — plus the frontend. Every
  Dockerfile in the tree is unverified, and the honest expectation is that
  several do not build at all
- **One `docker compose up` to a working instance**, with PostgreSQL, the
  self-signed gateway, the core and the frontend, seeded. The migration step
  stays explicit: the server never migrates itself, and a compose file that
  quietly did would contradict the one rule this project is least willing to
  bend
- **Publish to a registry, tagged.** `ghcr.io` alongside the repository, built
  by CI on a tag so the image and the source cannot drift
- **A CI job that builds the images on every pull request.** Without it they rot
  back to unbuildable within a month, which is how they got here
- **Verify the mTLS story survives containers.** The core-to-gateway channel is
  mutually authenticated and `make dev-certs` writes development material for
  loopback. Names change inside a compose network, and this is exactly where a
  certificate management product looks silly if it gets it wrong

Blocked on this machine — there is no container runtime here — so this is work
for somebody who has one, or for CI.

### Phase 10 — Post-quantum, the half that is possible

Phase 8 built posture scoring and deferred issuance, correctly. The deferral is
still correct and the reasoning has not changed: `crypto/mldsa` does not exist
in Go 1.26, `crypto/x509` cannot build or parse an ML-DSA certificate, and
issuing one would mean hand-rolling ASN.1 plus a third-party signature
implementation for a certificate almost nothing can verify.

What has changed is the other half. `crypto/tls` in Go 1.26 carries
`X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024`. Post-quantum
*key exchange* is in the standard library today, and CertPilot can both measure
it and use it.

- **Report which endpoints negotiate a post-quantum key exchange.** The
  discovery scanner already completes a handshake to read the certificate; the
  negotiated group is one field away. "Three of six scanned endpoints do not
  negotiate a post-quantum group" is a finding about the estate that needs no
  new standard, no new certificate, and nothing from a CA
- **Offer hybrid groups on CertPilot's own channels** — the API, and the
  core-to-gateway mTLS. A product that reports on other people's key exchange
  and does not use one itself is making an argument it does not believe
- **Keep issuance blocked and say why.** It moves when the standard library
  moves. Watching `crypto/mldsa` is the whole plan, and a CBOM that reports
  honestly about a classical estate is worth more than an ML-DSA certificate
  nothing will accept

The distinction matters more than the feature: harvest-now-decrypt-later is a
threat to *key exchange*, which is available to fix. Signature agility is a
threat to certificates issued today with a long life, which is a planning
problem rather than a shipping one.

### Phase 11 — The rest, in the order it hurts

- **Delegated unwrapping for the key encryption key.** `secrets.kek_provider`
  can read a key from an environment variable, a file or Vault, and all three
  end with the key in this process's memory — which rules out every HSM, because
  refusing to hand over the key is what an HSM is for. Needs a `CPS2` envelope
  that stores a reference the backend unwraps, with `CPS1` still readable
- **A gateway for a CA that does not have one.** Google Cloud CAS, AWS Private
  CA, DigiCert, Sectigo. The best-isolated work in the project: one gRPC
  contract, three existing implementations to read, no need to understand
  anything else
- **Run the Azure Key Vault and F5 deployers against real hardware.** Both are
  written to published APIs and unit-tested against fakes, which is precisely
  the arrangement that let `sys/health` and `GetCAChain` ship broken
- **An approval queue for agent enrolment.** A leaked token currently yields a
  live agent rather than one waiting for somebody to say yes

---

### Phase 12 — Certificate templates

Issuance policy moves from the estate to the certificate. `policies` stays as
the floor; a template says what one *kind* of certificate looks like, with the
two dispositions a policy structurally cannot express — supply a value the
requester may not touch, and pass one through that the requester decides.

Built: the object and its store, and one resolver applying six precedence rungs
in front of a person's request and a host's. Grants stopped carrying
certificate shape and went back to being permission, which closed the bypass
that let an agent obtain what a `BLOCK` policy would have refused a person.

Renewal re-evaluates too, which is what makes a rule change reach an estate
that already exists rather than only governing certificates that do not exist
yet.

The console shows every template: which CA signs it, what it would refuse —
computed from its own rules rather than written by hand, so it cannot drift from
them — and which grants name it. `agent_grants` had been API-only since
migration 020, and a control nobody can see is a control nobody reviews;
templates were not going to repeat that.

### Phase 13 — X.509 shape and CA profiles

What CertPilot can enforce about the shape of a certificate, and what it can
only verify afterwards. Key usage, extended key usage and extension
passthrough; and carrying a native CA profile — a Vault role, an ACME profile,
an AWS Private CA template ARN — through the gateway contract, which today has
no field for one.

The honest part is the limit. For a CA whose issuance CertPilot does not
control, a template can select a profile and compare the certificate that comes
back; it cannot dictate. Claiming otherwise would be a control that reports
success while the CA does as it likes.

### Phase 14 — Deploying to what people actually run

The agent writes a certificate, validates the configuration and reloads the
service. It cannot say which platforms that covers, and it writes only PEM.

**Java keystores, PKCS#12 and the Windows certificate store.** A JVM estate is
invisible today, in inventory and in deployment both. PKCS#12 first — Java 9
made it the default keystore type, so it covers the modern JVM *and* the `.pfx`
tooling; JKS is for the estate still on Java 8. The Windows store is filed
separately because it is a port, not a format: there is no Windows build and
`install.go` is POSIX throughout.

**Named deployment profiles.** A profile is a path, a format, a validate
command and a reload command — four fields over machinery that already exists.
What is missing is the catalogue, and the documentation axis to go with it:
every page in `docs/` is shaped like the software rather than like the reader,
and none answers "I have forty nginx boxes and an F5".

---

## Known gaps

Tracked honestly rather than quietly:

- ~~Audit log is an ordinary table — not hash-chained~~ — **closed.** Migration
  031 gave each entry a gapless `seq`, its predecessor's tag, and a keyed MAC
  over both, from a subkey of `CERTPILOT_KEK`. A database-only attacker can
  alter a row and cannot forge a tag that agrees with it. Entries written before
  the chain existed are left unchained and counted as such rather than presented
  as covered
- Post-renewal verification only covers endpoints discovery has already
  observed. A certificate deployed somewhere nothing has scanned is reported as
  unverifiable rather than checked
- `certificates.deployment_target_id` survives from migration 001 and is no
  longer the answer to where a certificate is deployed. It is unread by anything
  in the deployment path and should be dropped once nothing else references it
- Post-quantum *issuance* is not implemented. `crypto/mldsa` is not in Go 1.26
  and `crypto/x509` cannot build an ML-DSA certificate, so this waits for the
  standard library rather than being hand-rolled
- TLS posture is recorded only for endpoints a discovery scan has reached. A
  certificate deployed somewhere nothing has scanned has no handshake on record,
  and the posture summary counts only what was observed rather than what exists
- The CBOM covers certificates and observed TLS. Keys at rest, the algorithms
  inside applications, and anything CertPilot has never seen are outside it —
  which is most of an estate's cryptography, and the document should not be read
  as though it were complete
- Azure Key Vault and F5 deployment are written to their published APIs and
  verified by unit tests only. Neither has been run against a real vault or a
  real BIG-IP, so a misreading of either API would pass everything here. ACM was
  exercised end to end, but against a stub rather than LocalStack or a real
  account
- The F5 deployer installs over the existing crypto-store name and does not
  touch the client-SSL profile, so a certificate bound to a name no profile
  references installs successfully and serves nothing. That is deliberate —
  repointing a virtual server is its owner's decision — but nothing here detects
  it, the way ACM's read-back detects an unattached ARN
- ~~Deployment ordering is not expressible~~ — **closed.** Migration 034 put
  `deploy_order` on the target, copied onto the job at enqueue so reordering a
  target cannot disturb a rollout already under way. A canary is one target in
  the lowest wave: exactly one attempt, declared rather than inferred
- ~~Agent request signatures are bounded against replay by a five-minute window
  and nothing else~~ — **closed.** Migration 032. Ed25519 is deterministic, so an
  identical request carries an identical signature: the core stores the ones it
  has accepted and refuses a repeat, which is the nonce the earlier note said
  would need a protocol change. Exempted on heartbeat, inventory, installations
  and deployment results, because a one-second timestamp makes an agent's own
  retry byte-identical to a replay
- An enrolled agent is trusted from the moment it presents a valid token. There
  is no approval queue, so a leaked enrolment token yields a live agent rather
  than one waiting for somebody to say yes
- Agents have no rotation story. An identity key lives as long as the agent
  does; replacing it means revoking and re-enrolling the host
- Host inventory covers PEM and DER files only. Java keystores, the Windows
  certificate store, and PKCS#12 bundles are not read, so a JVM estate's
  certificates are invisible to it
- A grant cannot require a specific curve. `min_key_size` means RSA bits, and
  elliptic keys are floored at P-256 — because the numbers are not comparable
  across algorithms and one field that meant two things would be worse
- Certificates issued to an agent are never revoked when that agent is revoked.
  The credential stops working; the certificates keep working until they expire
- An agent renewing obtains a *new* certificate row rather than superseding the
  one it replaces, so the old row stays `ISSUED` and will eventually alert about
  a certificate nothing is serving. The install reconciliation removes its
  binding, which is the half that matters for deployment; the certificate record
  itself is not yet linked to its replacement the way a core-side renewal is
- An agent installation is not staged either. A host with six destinations for
  one certificate writes and reloads all six in the order the spec lists them,
  and a `check` that passes on the first and fails on the sixth leaves five
  reloaded and one rolled back
- The host's install spec is trusted as written. A path traversal is not
  possible — every path is absolute and the agent runs as whoever runs it — but
  an agent running as root will happily write a certificate over anything the
  spec names, because the file is owned by whoever administers the host
- Which configurations name a certificate file is found by text search, not by
  parsing. nginx `include`, Apache variables, and generated configuration will
  be missed — deliberately erring towards reporting a file as unreferenced,
  which invites a look, rather than silently marking it in use
- ~~The OCSP responder check is an HTTP GET, not an RFC 6960 request~~ —
  **closed.** Migration 033. `pkg/revocation` builds a real request and
  `ocsp.ParseResponseForCert` verifies the signature, the delegation, and that
  the answer is about the right certificate. A revoked CA is forced critical
  from the *recorded* status rather than the check's own result, so a blip at
  the responder cannot return it to healthy
- `migrations/001_initial_schema.sql` references `auth.users` and `auth.jwt()`
  and is now gone. The Go store layer is plain `pgx`, and as of the
  PostgreSQL-only change the schema carries no external-platform coupling
  either: all 38 migrations apply to a stock PostgreSQL 17 server with no
  prelude, and `TestNoMigrationDependsOnSupabase` keeps it that way
- ~~Policy is evaluated on issuance, not renewal~~ — **closed.** The sweep
  reloads the template and the floor, and renews *into* conformance where it can:
  a certificate issued at RSA-2048 under a floor since raised to 4096 comes back
  at 4096. What renewal cannot fix — a name outside a narrowed suffix rule
  cannot be dropped — is reported rather than refused, because an expired
  certificate is a worse outcome than a non-conforming one
- The conformance suite covers the store's constraint, round-trip and queue
  behaviour against both implementations, and the two classes only PostgreSQL
  can exhibit. It does not yet cover discovery, CT, cloud sync or the
  acknowledgement tables to the same depth — those still rely on the in-memory
  store, and are where the next defect of this kind will come from
- After a long outage the stream's backoff is capped at 30 seconds, so a display
  can take that long to notice the core is back. Deliberate — the alternative is
  a floor of wall displays stampeding a core the instant it restarts

## Deliberately out of scope

- **Being a CA.** EJBCA, step-ca, and Vault do that well. CertPilot manages CAs;
  it does not become one.
- **Replacing cert-manager inside Kubernetes.** Integrate with it instead.
