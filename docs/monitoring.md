# Monitoring and alerting

CertPilot's audience is the central PKI team — the group that owns the CA
hierarchy and gets paged when something expires. For them the dashboard is not
a convenience, it is the product surface.

One principle drives the whole design:

> **A dashboard that stops updating must look broken, not healthy.**

A frozen screen showing green is worse than no screen, because it manufactures
false confidence.

![Every certificate authority sorted by urgency, with a critical intermediate five days from expiry at the top, a warning at seventy-four, and the acknowledgement control on each.](images/ca-health.png)

*CA health, sorted by urgency. An acknowledged authority keeps its place in the
order and is marked rather than hidden — filtering it out is how CAs expire in
organisations that believed they were monitoring them.*

- [CA health](#ca-health)
- [Expiry thresholds](#expiry-thresholds)
- [The live event stream](#the-live-event-stream)
- [Notification channels](#notification-channels)
- [Acknowledgement and ownership](#acknowledgement-and-ownership)
- [Wall displays](#wall-displays)
- [Event topics](#event-topics)

---

## CA health

The CA monitor sweeps every registered CA every six hours by default
(`pki.ca_health_check_interval`), and on startup so a freshly started core
reports real state rather than what was last persisted.

Per CA it re-parses the certificate, recomputes days remaining, fetches the CRL
and checks its freshness, asks the OCSP responder whether the CA itself has
been revoked, and evaluates expiry
thresholds.

```bash
GET /api/v1/pki/authorities?sort=urgency
```

Urgency sort, worst first, is what the CA health view is built on. For a team
watching a screen the useful question is *which CA fails first*, and an
alphabetical list answers a different one.

Status is derived from days remaining:

| | |
|:---|:---|
| `CRITICAL` | ≤ 30 days |
| `WARNING` | ≤ 180 days |
| `HEALTHY` | more |
| `EXPIRED` | past |
| `UNKNOWN` | the certificate could not be parsed |

### Where CAs come from

Two ways, and the row records which in `source`:

**Registered by a person** (`MANUAL`) — paste a certificate at
`POST /api/v1/pki/authorities`.

**Imported from a gateway** (`GATEWAY`) — connecting a CA account asks its
gateway for the issuers behind it and records them. See
[gateways/vault.md](gateways/vault.md). This is how the CA that actually signs
your estate ends up in the same list as the estate.

![The authorities view: six CAs under management with their type, key algorithm, days remaining, issued count and state, above a breakdown of roots and intermediates.](images/authorities.png)

*Every CA is on one clock, roots and intermediates together, most urgent first.
The issued counts read zero because nothing in this estate was signed through
CertPilot — which is not the same as the CA being unused, and is exactly the gap
[discovery](discovery.md) exists to close.*

An imported CA is refreshed on a 12-hour sweep, and the sweep never overwrites
what an operator decided: the name, the alert thresholds, the owning team, the
tags, the notes. A CA rotated out of its mount is not deleted — it signed
certificates that are still being served — so `last_seen_at` goes stale
instead.

---

## Expiry thresholds

Each CA carries `alert_thresholds`, defaulting to:

```json
[365, 180, 90, 30, 14, 7]
```

Crossing one raises `ca.expiry_alert` **once**, recorded in
`last_alert_threshold` so it does not fire again every sweep. Severity is
`CRITICAL` at 30 days and below, `WARNING` above.

Tune them per CA. A root with ten years left does not need a 365-day alert; an
issuing CA that signs 90-day certificates needs one well before 90.

Certificates have their own lead days rather than thresholds — see
[configuration.md](configuration.md#renewal).

---

## The live event stream

```
GET /api/v1/events
Accept: text/event-stream
```

Server-Sent Events, not WebSockets: one-way traffic, survives proxies, and
browsers reconnect on their own.

On connect the server sends a **snapshot**, so a client never renders from an
empty store, then deltas. A comment heartbeat every 15 seconds keeps the
connection alive and lets a client judge freshness by data age rather than by
whether a socket has errored.

`Last-Event-ID` is honoured on reconnect.

### Slow consumers

The broker's policy is **bounded buffer, drop oldest, mark the subscription
lossy**. A wall display on a flaky link must never apply backpressure to the CA
health sweep. A lossy subscription is told to re-fetch a snapshot rather than
being fed a gap it cannot detect.

### Proxies

`proxy_buffering off` is mandatory. See
[operations.md](operations.md#behind-a-reverse-proxy) — this is the single
most common way to end up with a dashboard that looks fine and has stopped
updating.

---

## Notification channels

Three types, deliberately not more:

| Type | |
|:---|:---|
| `slack` | Incoming webhook, Block Kit formatting |
| `webhook` | Generic receiver, HMAC-SHA256 signed |
| `email` | SMTP with STARTTLS |

> These examples carry `-b "$JAR"`, a cookie jar from signing in. There is no
> anonymous mode, so a command without a credential is a 401. See
> [Authentication](api-reference.md#from-the-command-line) for the one-liner
> that fills it, or substitute `-H "Authorization: Bearer $TOKEN"`.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/notification-channels -H 'Content-Type: application/json' -d '{
  "name": "pki-oncall", "channel_type": "slack",
  "severity_threshold": "CRITICAL",
  "topics": ["ca.expiry_alert", "ca.discovered", "cert.not_deployed"],
  "config": {"webhook_url": "https://hooks.slack.com/services/..."}}'
```

| Field | |
|:---|:---|
| `severity_threshold` | `INFO`, `WARNING`, `CRITICAL`. Below this, nothing is sent |
| `topics` | Empty means every topic. Otherwise an allow-list |

Configuration is sealed with the KEK. The dispatcher **subscribes to the
broker** rather than being called inline, so a wedged Slack webhook cannot
stall the CA health sweep. Failures retry with backoff and are written to the
audit log as `notification.failed`.

> Watch for `notification.failed`. A monitoring system whose alerting is
> broken is worse than none, because it is trusted.

---

## Acknowledgement and ownership

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/pki/authorities/$ID/acknowledge \
  -H 'Content-Type: application/json' \
  -d '{"note": "rotation scheduled for the 3rd", "silence_until": "2026-09-03T00:00:00Z"}'
```

```bash
curl -b "$JAR" -X PUT localhost:8080/api/v1/pki/authorities/$ID/owner \
  -H 'Content-Type: application/json' \
  -d '{"owner_team": "platform-security", "owner_email": "pki@example.com"}'
```

One rule, and it is not negotiable:

> **Silencing suppresses delivery, never display.**

An acknowledged CA still appears on the dashboard, marked as acknowledged and
by whom. Hiding a problem because somebody clicked a button is how CAs expire
in organisations that believed they were monitoring them.

Owner is free text. Team names and distribution lists do not live in CertPilot,
and a foreign key to something it does not own would mean either an import step
or a wrong answer on a row somebody is reading at 2am.

---

## Wall displays

A screen in a corridor that nobody logs into needs a credential that cannot do
damage if the screen is stolen.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/display-tokens -H 'Content-Type: application/json' -d '{
  "name": "corridor-screen", "expires_at": "2027-01-01T00:00:00Z"}'
```

The raw token is returned **once**. Only a SHA-256 hash is stored.

Then point the display at:

```
https://certpilot.example.com/display?display_token=<token>
```

What the token can do:

| | |
|:---|:---|
| Role | `viewer`, hardcoded — not configurable, not derivable from input |
| Methods | `GET` only, plus the SSE endpoint |
| Never | `/certificates/:id/private-key`, or any write route |
| Presented as | `?display_token=` or `X-Display-Token` |
| Recorded | `last_seen_at`, `last_seen_ip` — so a leaked token is visible |
| Revocable | `DELETE /api/v1/display-tokens/:id`, admin only, audited |

The query-string form is necessary because `EventSource` cannot set headers.
That is also why the request logger never writes query strings.

---

## Event topics

| Topic | Raised when |
|:---|:---|
| `ca.health` | A CA's status changes |
| `ca.expiry_alert` | A CA crosses an expiry threshold |
| `ca.discovered` | A gateway reported a CA that was not in the inventory |
| `cert.issued` | A certificate was issued |
| `cert.renewed` | A certificate was renewed |
| `cert.renewal_failed` | A renewal attempt failed |
| `cert.renewal_window_moved` | A CA changed its RFC 9773 renewal window — materially forward means it is facing a mass revocation |
| `cert.not_deployed` | A renewed certificate is not being served |
| `cert.deployed` | A deployment succeeded |
| `cert.deploy_failed` | A deployment failed |
| `agent.enrolled` | A host joined |
| `agent.stale` | A host stopped reporting |
| `agent.key_exposed` | A private key on a host is group- or world-readable |
| `agent.key_mismatch` | A certificate and the key beside it do not match |
| `agent.unmanaged` | A host holds a certificate CertPilot does not know |
| `agent.request_refused` | A host asked for a name no grant covers |
| `agent.install_failed` | An install on a host failed |
| `agent.install_unfulfilled` | A destination asked for a certificate the host does not hold |
| `discovery.unmanaged` | A scan found a certificate nothing renews |
| `discovery.changed` | An endpoint is serving a different certificate |
| `discovery.progress` | Scan progress, for the UI |
| `ct.unmanaged` | A Certificate Transparency log shows a certificate for your domain that you did not issue |
| `cloud.unmanaged` | A cloud provider holds a certificate CertPilot does not know |
| `cloud.will_not_renew` | A cloud provider will not renew a certificate everyone assumes is automatic |

Severity is `INFO`, `WARNING` or `CRITICAL`, matching the vocabulary the CA
monitor and the frontend both use.
