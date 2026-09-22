# A CA is expiring

An issuing CA does not fail on the day it expires. It fails one certificate lifetime
earlier, when the first request arrives asking for a certificate that would outlive it —
and it fails for *every* issuance after that, because every one of them asks for the
same thing.

This walkthrough is for two moments: the one where somebody asks "is anything about to
go" and you need a real answer, and the one where issuance has already started failing
and nobody knows why.

## The short version

```bash
curl -b "$JAR" 'localhost:8080/api/v1/pki/authorities?sort=urgency'
```

Worst first. If the top row is `CRITICAL`, read on.

## Prerequisites

A running CertPilot with at least one CA account connected — [Vault](vault-nginx.md) or
[ACME](acme-nginx.md). **Viewer** is enough to look; **operator** to re-check or
acknowledge.

To reproduce the failure rather than wait for one, the Vault gateway's lab script builds
an issuing CA three weeks from expiry alongside a healthy one:

```bash
vault server -dev -dev-root-token-id=certpilot-dev-root &
./scripts/lab-vault.sh        # in a certpilot-gateway-vault checkout
```

Then connect `pki-expiry` as a CA account the same way you connected `pki-int` —
[Vault walkthrough, step 2](vault-nginx.md#step-2-connect-the-ca).

## Step 1: the warning arrives before the failure does

Connecting the account is the first place this shows up. The configuration is validated
against Vault before it is stored, and the warnings come back with the account:

```
the issuing CA "CertPilot Lab Expiring Issuing" expires on 2026-10-13, in 20 days.
Vault refuses to sign a certificate that would outlive its issuer, so issuance
through this account starts failing before that date — as soon as a requested
validity reaches past it — and every certificate it has already signed expires
with it
```

The account is still `CONNECTED`. Nothing is broken yet. This is the cheapest moment to
find out, and it is a moment most people scroll past.

## Step 2: where the answer is, and where it is not

> **`POST /ca-accounts/:id/health` will tell you this account is healthy.** It is not
> lying; it is answering a different question:
>
> ```bash
> curl -b "$JAR" -X POST localhost:8080/api/v1/ca-accounts/$ID/health
> ```
>
> ```json
> { "status": "HEALTH_STATUS_HEALTHY", "latency_ms": 1,
>   "message": "Vault 2.0.3 at http://127.0.0.1:8200 is unsealed and active" }
> ```
>
> That is the health of the *CA service* — is Vault up, unsealed, reachable, fast. The
> CA inside it can be three weeks from expiry and refusing every request while this
> reads `HEALTHY`. Do not use it to answer "is my CA all right".

The CA itself is in the authority inventory:

```bash
curl -b "$JAR" 'localhost:8080/api/v1/pki/authorities?sort=urgency'
```

```
    20d  CRITICAL   GATEWAY  pki-expiry/CertPilot Lab Expiring Issuing
   729d  HEALTHY    MANUAL   CertPilot Production Intermediate CA G1
  1824d  HEALTHY    GATEWAY  pki-int/CertPilot Lab Issuing CA
  3649d  HEALTHY    GATEWAY  pki-int/CertPilot Lab Root CA
  3649d  HEALTHY    MANUAL   CertPilot Global Root CA 2026
```

Urgency sort is worst-first because the useful question is *which CA fails next*, not
which one comes first alphabetically. `source` says where the row came from: `GATEWAY`
for one imported from a CA account, `MANUAL` for a certificate somebody pasted in.

Status is derived from days remaining — `CRITICAL` at 30 or fewer, `WARNING` at 180 or
fewer. See [monitoring.md](../monitoring.md#ca-health).

## Step 3: get a current reading

The sweep runs every six hours, and on startup. To ask now:

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/pki/authorities/$AUTHORITY_ID/check
```

```
status                       CRITICAL
days_remaining               20
not_after                    2026-10-13T21:14:36Z
last_alert_threshold         30
last_alert_sent_at           2026-09-22T23:37:43Z
is_crl_fresh                 False
is_ocsp_responsive           False
certificates_issued_count    0
```

`last_alert_threshold: 30` is the alert having already fired. Thresholds default to
`[365, 180, 90, 30, 14, 7]` and each one raises `ca.expiry_alert` **once**, recorded
here so the next sweep does not raise it again. If that field is set and nobody heard
about it, the gap is in [notification channels](../monitoring.md#notification-channels),
not in the detection.

`certificates_issued_count: 0` means nothing was signed *through CertPilot* on this CA.
It is not the same as the CA being unused — see [discovery.md](../discovery.md).

## Step 4: what the failure looks like, if you got here late

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/certificates \
  -H 'Content-Type: application/json' \
  -d '{"common_name": "shop.example.com", "ca_account_id": "…", "validity_days": 90}'
```

```
gateway issuance failed: rpc error: code = FailedPrecondition desc = Vault refused to
sign because the certificate would outlive the CA signing it (cannot satisfy request,
as TTL would result in notAfter of 2026-12-21T21:21:45Z that is beyond the expiration
of the CA certificate at 2026-10-13T21:14:36Z). This is not a problem with the
request: the issuing CA is inside one certificate lifetime of its own expiry, so every
renewal through mount pki-expiry is now failing, and will keep failing until that CA
is rotated or the requested validity is shortened below what it has left. The issuer
is "CertPilot Lab Expiring Issuing", which expires on 2026-10-13 — 20 days from now
```

Worth reading twice, because it contains the whole diagnosis: **the request is fine**,
the CA is the problem, it affects everything not just this one, and it will not recover
on its own.

The shape of the failure is the giveaway. A credential problem fails the same way every
time from the start. This one starts working and then stops — the first certificate to
fail is the first one whose requested validity reached past the issuer's expiry, so a
fleet with mixed validities fails in stages, longest-lived first.

## Step 5: decide, and record the decision

Two ways out, and they are not equivalent:

**Rotate the issuing CA.** The real fix. In Vault that is a new intermediate signed by
the root, and then `issuer_ref` on the CA account pointing at it — or the mount's
default, if you let it float. Afterwards:

```bash
curl -b "$JAR" -X POST 'localhost:8080/api/v1/pki/authorities/import?account=vault-issuing'
```

which re-reads the issuers behind the account. The old CA is **not** deleted: it signed
certificates that are still being served, so its row stays and `last_seen_at` goes
stale instead.

**Shorten the requested validity.** Buys time and is not a fix. Every certificate you
issue still expires when the CA does, all at once. Useful only as a bridge with a
rotation date already set.

Either way, record it where the next person looks:

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/pki/authorities/$AUTHORITY_ID/acknowledge \
  -H 'Content-Type: application/json' \
  -d '{"note": "rotation scheduled 2026-10-01", "until": "2026-10-05T00:00:00Z"}'
```

```
This certificate authority still appears on the dashboard and the wall display, now
marked as acknowledged. Alerts continue to be delivered — acknowledging does not
silence.
```

**Acknowledging does not silence.** It says somebody has seen this and what they are
doing about it. A mechanism that made the row go away would be a mechanism for making
the row go away.

`PUT /pki/authorities/:id/owner` names who is responsible, and survives the 12-hour
import sweep — the sweep never overwrites what an operator decided.

## What this cannot tell you

> **A CA reached over ACME never appears in this inventory at all.**
>
> An ACME directory names its CA and does not hand over the certificate, so there is
> nothing to record and no expiry to monitor. Connecting an ACME account says so
> explicitly:
>
> ```
> the gateway named this CA and did not send its certificate, so there is no expiry
> to monitor and nothing to identify it by
> ```
>
> This is not a gap in CertPilot; it is what the protocol provides. Public CAs manage
> their own issuer rotation and the ACME client is not told about it. The inventory
> covers CAs you are responsible for, which is the set that can surprise you.

Other limits:

- **A CA nothing has imported is not watched.** Only CAs behind a connected account
  (`GATEWAY`) or pasted in by hand (`MANUAL`) are in the list.
- **CRL freshness and OCSP responsiveness read `False` above** because the lab CA
  publishes neither at a reachable URL. On a real CA they are two more independent
  signals; a stale CRL is its own incident.
- **Nothing here rotates a CA.** That is a Vault operation, or your CA vendor's.

## Related

- [monitoring.md](../monitoring.md#ca-health) — the sweep, thresholds and event topics
- [gateways/vault.md](../gateways/vault.md) — what the Vault gateway reports and why
- [a renewal or deployment failed](failed-renewal.md) — when the failure is not the CA

## What this was run against

Vault 2.0.3 with the gateway's lab PKI, `certpilot-gateway-vault@v0.3.0`, core
`da9423f`. Every output above is real: the connect-time warning, the urgency listing,
the forced re-check with its fired alert, the issuance refusal, and the
acknowledgement.
