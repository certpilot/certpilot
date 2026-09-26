# A renewal or deployment failed

Something is red. This page is about finding out which of three different things went
wrong, because they look similar from the dashboard and none of the fixes is the same:

1. **The CA would not issue** — the renewal never produced a certificate.
2. **The certificate exists and did not reach the host** — deployment or installation
   failed.
3. **Everything succeeded and the host is serving something else** — the worst one,
   because nothing is red.

Work through them in that order.

## Prerequisites

A running CertPilot with something that failed. **Viewer** is enough for every read on
this page; **operator** to retry, and to run `verify`.

To produce a failure on purpose, the two in this page were made by stopping a gateway
the core was configured to use, and by breaking `nginx.conf` on a host before the agent
installed into it.

## Step 1: did the CA issue?

A renewal is a queued job, not an API call, so the answer is in the queue:

```bash
curl -b "$JAR" 'localhost:8080/api/v1/renewals?limit=10'
```

```json
{
  "id": "72ab85ef-…",
  "status": "PENDING",
  "reason": "SCHEDULED",
  "attempts": 1,
  "last_error": "gateway for CA account selfsigned-dev is not connected: gateway
                 selfsigned not found or disconnected",
  "run_after": "2026-09-22T23:43:44Z"
}
```

```json
"attempt_log": [
  { "number": 1, "started_at": "2026-09-22T23:41:57Z", "duration_ms": 0,
    "worker": "Mervins-MacBook/64613-ab55ae",
    "error": "gateway for CA account selfsigned-dev is not connected: …" }
]
```

Four fields are doing the work here:

| | |
|:--|:--|
| `status` | `PENDING` with a non-empty `last_error` means **failing and retrying**, not waiting to start |
| `attempts` | How many times. A number that keeps climbing is a problem that is not going to fix itself |
| `run_after` | When the next attempt is due. It backs off, so the gap grows |
| `attempt_log` | Every attempt with its own error. A job whose error *changed* is a different problem from one repeating |

`worker` matters if you run more than one core replica: it says which one took the job.

### Read the error, not the status

The errors are written to be diagnostic on their own. Three that mean quite different
things:

```
gateway for CA account selfsigned-dev is not connected:
gateway selfsigned not found or disconnected
```
The gateway is not there. Either it is not running, or it is not in the core's
configuration — a CA account's `gateway_addr` selects among gateways the core already
knows, and cannot introduce one. Fix the config, start the gateway **first**, then
restart the core.

```
Vault refused to sign because the certificate would outlive the CA signing it …
the issuing CA is inside one certificate lifetime of its own expiry
```
Not a renewal problem. Go to [a CA is expiring](ca-expiry.md).

```
certificate … is renewed by whoever holds its private key, not by CertPilot:
key_custody is EXTERNAL
```
Working as intended. The key is in an HSM, a load balancer or somewhere else that will
never send it here, and renewing from CertPilot would issue against a key this
certificate does not use. Submit a new signing request from wherever the key is.

### Retrying

Fix the cause first — a retry against an unchanged cause just adds a row to
`attempt_log`. Then:

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/certificates/$CERT_ID/renew
```

```json
{ "message": "A renewal for this certificate is already queued; this did not start
              a second one." }
```

You cannot stack duplicate renewals for one certificate, which is deliberate: the
failure mode it prevents is somebody clicking retry six times and six certificates being
ordered from the CA.

> **A certificate whose `key_custody` is `AGENT` is refused here, with `400`.** Its key
> is on a host, and a renewal from the core would make CertPilot hold a new key the host
> never installs. The refusal names the agent. Renew it from that host instead:
> `certpilot-agent request` with the same name. This used to be accepted
> ([#107](https://github.com/certpilot/certpilot/issues/107)).

## Step 2: did it reach the host?

The certificate exists and the endpoint is still serving the old one. Two different
mechanisms, depending on who holds the key.

### Hosts running the agent

```bash
curl -b "$JAR" localhost:8080/api/v1/agent-installations
```

```json
{ "certificate_name": "app.example.com", "status": "FAILED",
  "last_error": "/usr/sbin/nginx -t refused the new certificate, so it was not
    loaded: it exited with an error: exit status 1 — 2026/09/22 21:21:00 [emerg]
    no \"ssl_certificate_key\" is defined for certificate
    \"/etc/nginx/does-not-exist.pem\" nginx: configuration file
    /etc/nginx/nginx.conf test failed" }
```

The host's own tool's error text, carried up verbatim. In this case `nginx -t` was
already failing for an unrelated reason — somebody had edited the config — and the
renewal is what found it.

What the agent did about it, from its own output:

```
app  FAILED  /usr/sbin/nginx -t refused the new certificate, so it was not loaded …
             — the previous certificate was put back and app was never reloaded,
             so it is still serving what it was before
web  INSTALLED  /etc/certpilot/live/www.example.com/cert.pem already holds this
                certificate; nothing was written and nothing was reloaded
```

**The service did not go down.** The check runs before the reload, the previous files
are restored, and nothing is reloaded. The other destination on the same host was
untouched — a failure is per destination, not per host.

> **The agent's own status stays `ACTIVE` through all of this.**
>
> ```
> name        web01
> status      ACTIVE
> last_seen   2026-09-22T23:21:00Z
> ```
>
> Which is correct — the agent is healthy, it reported on time, and it did exactly the
> right thing. But it means **watching agent status will not show you a failed
> install.** Watch `agent-installations`.

After a *first* install that failed, the destination directory exists and is empty.
There were no previous files to put back, and the message still says there were.

**Recovering** is the ordinary case and needs nothing from CertPilot. Fix what the check
was complaining about, and let the next cycle run:

```bash
nginx -t                      # until it passes
certpilot-agent run --once --state-dir /etc/certpilot/state \
  --installs /etc/certpilot/installs.json
```

```
app  INSTALLED  wrote /etc/certpilot/live/app.example.com/cert.pem, … and ran
                /usr/sbin/nginx -s reload
```

`last_error` clears on the next report. Nothing needs to be retried from the CertPilot
side, and re-issuing the certificate would not have helped — the certificate was never
the problem.

On Windows the equivalent failure is a binding, and the rollback order is different
enough to matter — see
[Windows and IIS](windows-iis.md#when-it-fails).

### Deployment targets

For a certificate CertPilot holds the key for, delivery is a deployment target rather
than an agent:

```bash
curl -b "$JAR" localhost:8080/api/v1/certificates/$CERT_ID/targets
curl -b "$JAR" -X POST localhost:8080/api/v1/certificates/$CERT_ID/deploy
```

A rollout across waves halts rather than continuing past a failed wave, and what it does
next is [deployment.md](../deployment.md#when-a-rollout-halts)'s subject. None of the
non-agent target types was exercised for these walkthroughs.

## Step 3: everything is green and the wrong certificate is being served

This is the one no status field reports, because every status field is correct. The core
holds one certificate; the endpoint serves another.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/certificates/$CERT_ID/verify
```

It opens a TLS connection to the endpoint and compares the fingerprint being served with
the one stored. **This is the difference between "renewed" and "renewed and in use".**

By hand, which also tells you what the endpoint thinks it is doing:

```bash
echo | openssl s_client -connect www.example.com:443 -servername www.example.com 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 -dates
```

Compare against `fingerprint_sha256` on the record, or on the installation row. The
handshake prints it upper-cased with colons and the API stores it lower-cased without;
they are the same value.

Three ways to arrive here:

- **A renewal that never reached the host.** Section 2 — and the installation row will
  say so.
- **A reload that never happened.** nginx reads its certificate files at start and at
  reload and never again, so a renewed file with no reload changes nothing. The agent
  reloads; a hand-copied certificate does not.
- **A manual renewal of an agent-held certificate, on a core older than the fix for
  [#107](https://github.com/certpilot/certpilot/issues/107).** CertPilot's record moves
  and the host does not, and the agent's next cycle says `already holds this
  certificate; nothing was written and nothing was reloaded`, which is true and looks
  like success. A current core refuses the renewal instead.

## A short checklist

```bash
# 1. did the CA issue?
curl -b "$JAR" 'localhost:8080/api/v1/renewals?limit=10'

# 2. did it reach the host?
curl -b "$JAR" localhost:8080/api/v1/agent-installations

# 3. is it the one being served?
curl -b "$JAR" -X POST localhost:8080/api/v1/certificates/$CERT_ID/verify

# and if the answer to 1 was "the CA refused":
curl -b "$JAR" 'localhost:8080/api/v1/pki/authorities?sort=urgency'
```

## Limitations

- **Only the agent path was exercised** for section 2. Webhook, AWS ACM, Azure Key Vault
  and F5 targets were not.
- **`verify` needs to reach the endpoint.** A host CertPilot cannot connect to cannot be
  checked this way; the agent's own installation report is what you have instead.
- **The renewal queue holds jobs, not history.** A job that eventually succeeded carries
  its failed attempts in `attempt_log`, but a certificate's whole renewal history is not
  assembled anywhere.
- **`GET /api/v1/events` is a live stream, not a list.** It does not return past events,
  so a failure nobody was watching for is not retrievable from it. Notification channels
  are the durable path — [monitoring.md](../monitoring.md#notification-channels).

## What this was run against

Core `da9423f` with the Vault gateway at `v0.3.0` and
[the lab PKI](vault-nginx.md#if-you-have-no-vault-to-try-this-against),
`certpilot-agent@v0.2.0` on nginx 1.29.8. The renewal failure is a real job from a CA
account whose gateway was not running; the installation failure is a real `nginx -t`
refusal, with the rollback and the recovery run afterwards.
