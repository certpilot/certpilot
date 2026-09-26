# ACME to nginx

The same destination as [Vault to nginx](vault-nginx.md) — a host serving a certificate
it renews by itself — from a public CA over ACME instead of an internal one.

Most of the path is identical, because it is the same host, the same agent and the same
nginx. What is different is everything before the certificate exists: a public CA will
not sign for a name until you have proved you control it, and that proof is the part
worth walking through.

**Read first:** [gateways/acme.md](../gateways/acme.md) for challenges, wildcards and
ARI.

## What this page was run against, and what it was not

> **Let's Encrypt staging was not exercised.** Proving domain control means a name that
> resolves on the public internet and a listener the CA can reach, and neither exists in
> the environment this was written in.
>
> The ACME protocol path *was* exercised in full — directory, account registration,
> order, http-01 challenge, validation, finalize, download — against
> [Pebble](https://github.com/letsencrypt/pebble), the ACME server Let's Encrypt builds
> for this purpose. Every output quoted below is real.
>
> What Pebble cannot tell you: anything about Let's Encrypt's rate limits, its account
> policy, its CAA checking, or how long a real validation takes. Those steps are marked
> **not verified here** where they occur.

## Prerequisites

| | |
|:--|:--|
| A running CertPilot | [evaluation.md](../evaluation.md) |
| A domain you control | And the ability to prove it — see below |
| A host running nginx | With root, and the agent installed |
| **For http-01** | Port 80 on that name reachable from the CA |
| **For dns-01** | A Cloudflare token, or a webhook that writes TXT records |

Admin on your CertPilot account, for the same two steps as the Vault walkthrough: the
template and the enrolment token.

### Choosing the challenge

| | http-01 | dns-01 |
|:--|:--|:--|
| Proves control by | Serving a file at a well-known path | Publishing a TXT record |
| Needs inbound | Yes, port 80, from the CA | No |
| Wildcards | No — ACME permits none | Yes, the only way |
| Credentials | None | Your DNS provider's |

http-01 is the default when no DNS provider is configured, and is what this page uses.
A host behind a firewall, or a name you want a wildcard for, needs dns-01.

> **The gateway answers the challenge, not the host.** The http-01 listener belongs to
> the ACME gateway, so port 80 for that name has to reach *the gateway*, not nginx. On a
> single host serving its own name that is a proxy rule; on a gateway serving many hosts
> it is a decision about where challenges terminate. This is the step people get wrong,
> and it fails as an unexplained validation timeout.

## Step 1: start the gateway

```bash
docker run -d --name gateway-acme -p 9092:9092 \
  -v /var/lib/certpilot-acme:/state \
  ghcr.io/certpilot/gateway-acme:0.3.0 \
  --port=9092 --directory=letsencrypt-staging --state-dir=/state \
  --tls-cert=/pki/gateway.pem --tls-key=/pki/gateway-key.pem --tls-ca=/pki/ca.pem
```

> **`--state-dir` is not optional in practice.** Without it the gateway warns, and means
> it:
>
> ```
> no --state-dir configured; ACME account keys will not survive a restart, which
> will register a new account with the CA each time and can hit account rate limits
> ```
>
> A container restarted a few times registers a few ACME accounts. The alternative is an
> `account_key_pem` on the CA account, which pins the identity to the account rather
> than to the gateway's disk.

`--directory` defaults to Let's Encrypt **staging**, deliberately: the production
endpoint's rate limits punish a misconfiguration for a week. Move to
`--directory=letsencrypt` once a staging certificate has come out the other end.

Register it in the core's configuration and restart the core, exactly as in
[step 1 of the Vault walkthrough](vault-nginx.md#step-1-start-the-gateway-and-tell-the-core-about-it):

```yaml
plugins:
  gateways:
    - name: acme
      addr: gateway-acme:9092
      type: acme
```

## Step 2: connect the CA

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/ca-accounts \
  -H 'Content-Type: application/json' -d '{
  "name": "letsencrypt-staging", "provider_type": "acme",
  "gateway_addr": "gateway-acme:9092",
  "config": {"directory_url": "letsencrypt-staging",
             "email": "pki@example.com",
             "challenge": "http-01"}}'
```

> **The contact field is `email`.** Not `contact_email`, which is what most people type.
> The wrong name is not an error — the field is simply absent, and the refusal that
> comes back is `email is empty; most CAs require a contact address and will reject
> registration`, which reads like the CA's complaint rather than a typo in your JSON.

A refusal carries its reason in `validation_error`, which is a different field from
`error`:

```json
{
  "error": "the gateway rejected this configuration",
  "validation_error": [
    "ACME directory https://… is unreachable: Get \"https://…\": tls: failed to
     verify certificate: x509: certificate is valid for localhost, pebble, not …"
  ],
  "warnings": ["no account_key_pem and no gateway state directory: …"]
}
```

A client that prints only `error` reports `the gateway rejected this configuration` and
nothing else, which is how a five-second fix turns into an afternoon.

On success:

```json
{ "data": { "id": "05e99dea-…", "name": "acme", "status": "CONNECTED" },
  "issuers": { "outcomes": [ { "action": "skipped",
    "reason": "the gateway named this CA and did not send its certificate, so there
               is no expiry to monitor and nothing to identify it by" } ] } }
```

**No issuers were imported, and that is correct.** An ACME directory names the CA and
does not hand over its certificate, so there is nothing to record and nothing to watch
expire. The Vault gateway is the one that returns issuers. Nothing about a public CA's
own expiry appears in [the authority inventory](ca-expiry.md), because ACME gives
CertPilot no way to learn it.

## Steps 3 to 5: template, enrolment, grant

Identical to the Vault walkthrough — [step 3](vault-nginx.md#step-3-a-template-to-issue-against),
[step 4](vault-nginx.md#step-4-enrol-the-host) and
[step 5](vault-nginx.md#step-5-grant-it-a-name) — with the ACME account's id in place of the
Vault one:

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/certificate-templates \
  -H 'Content-Type: application/json' \
  -d '{"slug": "acme-web", "name": "ACME web", "ca_account_id": "05e99dea-…"}'
```

The enrolment token is still at the top level of the response rather than inside `data`,
and still shown once.

## Step 6: ask for the certificate

```bash
certpilot-agent request --name shop.example.com --state-dir /etc/certpilot/state
```

The gateway's log is where the challenge is visible:

```
starting ACME order  directory=… domains=[shop.example.com] challenge=http-01
http-01 challenge presented  domain=shop.example.com path=/.well-known/acme-challenge/U1pHPQj0…
authorization validated  domain=shop.example.com
ACME order completed  domains=[shop.example.com] chain_length=2
```

**This is where a real CA differs.** Against Pebble the validation took three seconds.
Against Let's Encrypt it takes longer, is retried, and fails outright if the CAA records
on the name forbid the CA — none of which is exercised here.

### Two things that surprise people about what comes back

**The certificate may have no common name.**

```
subject=
X509v3 Subject Alternative Name: critical
    DNS:shop.example.com
```

That is a correct, modern certificate: the Baseline Requirements mark
`subject:commonName` as NOT RECOMMENDED, and Pebble issues without one by default.
Let's Encrypt still populates it today.

CertPilot records it accurately — `common_name` empty, `sans` holding the name — and
then cannot find it:

```bash
curl -b "$JAR" 'localhost:8080/api/v1/certificates?common_name=shop.example.com'
```

```
hits: 0
```

It lists as a blank row, too. [#108](https://github.com/certpilot/certpilot/issues/108),
open. Until it is fixed, list without the filter and match on `sans`.

**The certificate may be much shorter than you expect.** ACME CAs increasingly offer
short-lived profiles; Pebble issued six days here without being asked. The renewal lead
time, 30 days by default, is bounded by the certificate's own lifetime, so a six-day
certificate renews once, at day four. Before that bound, a certificate shorter than its
lead time renewed on *every* cycle, ordering a new certificate from the CA every five
minutes ([#109](https://github.com/certpilot/certpilot/issues/109)).

## Steps 7 and 8: install, and point nginx at it

Unchanged from the Vault walkthrough:
[step 7](vault-nginx.md#step-7-install-it-where-nginx-reads) and
[step 8](vault-nginx.md#step-8-point-nginx-at-it). The `nginx` profile does not care which
CA signed the certificate.

```json
{ "destinations": [
    { "name": "shop", "certificate": "shop.example.com", "profile": "nginx" } ] }
```

```
shop  INSTALLED  wrote /etc/certpilot/live/shop.example.com/cert.pem, … and ran
                 /usr/sbin/nginx -s reload
```

## Step 9: check it

A public CA makes one check stronger than the Vault walkthrough's: the certificate
should verify against the trust store a browser uses, with no `-CAfile`.

```bash
echo | openssl s_client -connect shop.example.com:443 -servername shop.example.com 2>/dev/null \
  | grep -E 'Verification|Verify return code'
```

```
Verification: OK
Verify return code: 0 (ok)
```

Against **staging** that will fail, and should: staging roots are not trusted anywhere,
which is the point of them. Pass `-CAfile` with the staging root to check the chain
while you are still there.

Then the same two checks as before — that the chain is complete, and that the
fingerprint CertPilot recorded is the one being served:

```bash
curl -b "$JAR" localhost:8080/api/v1/agent-installations
```

## Renewal

As with Vault, **the host renews this**, and `POST /certificates/:id/renew` refuses it
with `400` ([#107](https://github.com/certpilot/certpilot/issues/107)).

One thing is specific to ACME. A CA that publishes **renewal information** (RFC 9773) is
telling you when *it* wants the certificate replaced, and the gateway reports that
window upward so the core can pick a moment inside it rather than everybody renewing at
the same instant. That is what lets a CA drain a mass-revocation event gradually. See
[gateways/acme.md](../gateways/acme.md).

## Limitations

- **Wildcards need dns-01.** ACME permits no other challenge for them. Not exercised
  here.
- **Rate limits are the CA's, and CertPilot does not model them.** There is a
  per-account renewal rate limit (`PUT /ca-accounts/:id/rate-limit`) which is your own
  brake, not a reflection of the CA's.
- **External Account Binding** — required by ZeroSSL, Google Trust Services and most
  commercial CAs — is configured with `eab_key_id` and `eab_hmac_key` and was not
  exercised here. It is marked unverified in [status.md](../status.md).
- **Everything in the [Vault walkthrough's limitations](vault-nginx.md#limitations)**
  applies unchanged: one destination per path, the agent does not edit `nginx.conf`, and
  development mode forgets enrolments on restart.

## What this was run against

Pebble (`ghcr.io/letsencrypt/pebble:latest`) as the ACME CA, with real http-01
challenges solved and validated; `ghcr.io/certpilot/gateway-acme:0.3.0`; core `da9423f`;
`certpilot-agent@v0.2.0`; nginx 1.29.8. The served certificate verified against Pebble's
root with return code 0.
