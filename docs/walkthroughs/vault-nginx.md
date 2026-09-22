# Vault to nginx

An internal CA in HashiCorp Vault, a host running nginx, and a certificate that gets
from one to the other and stays current without anybody logging in.

At the end of this the host holds a private key CertPilot has never seen, nginx is
serving a certificate signed by your Vault issuing CA, and the fingerprint CertPilot
recorded is the one on the wire.

**Read first:** [gateways/vault.md](../gateways/vault.md) for what the gateway does with
your credentials, and
[platforms/nginx.md](../platforms/nginx.md)
for what it writes on the host. Neither is required to follow this page; both explain
things this page only uses.

## Prerequisites

| | |
|:--|:--|
| A running CertPilot | [evaluation.md](../evaluation.md) is the quickest |
| A Vault with a PKI secrets engine | A mount, a role, and an issuer that is not about to expire |
| An AppRole on that Vault | Scoped to the mount. The `role_id` and `secret_id` |
| A host running nginx | With somewhere to put `/etc/certpilot`, and root |
| The agent on that host | [agent.md](../agent.md#where-it-runs) |

Your CertPilot account needs **admin**, not operator. Two of the steps below require it
— creating a template and issuing an enrolment token — and the rest need operator. If
you are working with somebody else's credentials, that is the line you will hit.

### If you have no Vault to try this against

The Vault gateway ships a script that builds one, and it is what this page was written
against:

```bash
vault server -dev -dev-root-token-id=certpilot-dev-root &
git clone https://github.com/certpilot/certpilot-gateway-vault
cd certpilot-gateway-vault && ./scripts/lab-vault.sh
eval "$(./scripts/lab-vault.sh --env)"   # exports the AppRole credentials
```

It creates a root, an issuing CA, a role that allows `*.example.com`, and an AppRole
scoped to both. It also creates a second issuing CA three weeks from expiry, which is
what [a CA is expiring](ca-expiry.md) uses. The dev server keeps everything in memory,
so stopping it is the cleanup.

## Step 1: start the gateway and tell the core about it

The Vault gateway holds no credential of its own. It needs to know where Vault is; the
authority to sign arrives per request, from the CA account you create in step 2.

```bash
docker run -d --name gateway-vault -p 9093:9093 \
  ghcr.io/certpilot/gateway-vault:0.3.0 \
  --port=9093 --address=https://vault.internal:8200 \
  --tls-cert=/pki/gateway.pem --tls-key=/pki/gateway-key.pem --tls-ca=/pki/ca.pem
```

> **The core dials the gateway, and only gateways in its configuration file.** There is
> no API for adding one. A CA account's `gateway_addr` selects among the gateways the
> core already knows; it does not introduce a new one.
>
> ```yaml
> plugins:
>   gateways:
>     - name: vault
>       addr: gateway-vault:9093
>       type: vault
> ```
>
> **Restart the core after editing this.** Gateway registration happens at startup, and
> a core started before its gateway registers nothing — every issuance then fails with
> `gateway vault not found or disconnected` while the gateway sits there listening
> perfectly. Start the gateway first, then the core.

## Step 2: connect the CA

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/ca-accounts \
  -H 'Content-Type: application/json' -d '{
  "name": "vault-issuing", "provider_type": "vault",
  "gateway_addr": "gateway-vault:9093",
  "config": {"address": "https://vault.internal:8200", "mount": "pki-int",
             "role": "web", "auth_method": "approle",
             "role_id": "...", "secret_id": "..."}}'
```

The configuration is validated against Vault before it is stored, so a wrong mount or a
revoked AppRole is a refusal now rather than a failed issuance later. What came back:

```json
{ "id": "3e1fa7e9-…", "name": "vault-issuing", "status": "CONNECTED" }
```

**Read the warnings.** They are not decoration — each one is a fact about your Vault
that will surprise somebody later:

```
issuer_ref is not set, so this account signs with whichever issuer is currently the
mount's default. Rotating the default silently changes which CA signs your certificates
the Vault token expires in 59 minutes; it is renewable, and this gateway renews it
while it is running
role "web" issues EC keys of 256 bits regardless of what a request asks for
role "web" caps validity at 90 days; a longer request is shortened to it, and Vault
reports that as a warning rather than an error
```

The third and fourth are the ones that catch people: the role decides the key type and
the validity, and a template asking for something else does not get it.

Creating the account also imports the CAs behind it, so they land in the same inventory
as everything else:

```bash
curl -b "$JAR" localhost:8080/api/v1/pki/authorities
```

```
INTERMEDIATE   1824d  HEALTHY    pki-int/CertPilot Lab Issuing CA
ROOT           3649d  HEALTHY    pki-int/CertPilot Lab Root CA
```

`source` on those rows reads `GATEWAY`, which is how you tell them from a certificate
somebody pasted in. See [monitoring.md](../monitoring.md#where-cas-come-from).

## Step 3: a template to issue against

A template is what a grant points at. It carries the CA account, and the policy the
issuance is judged by.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/certificate-templates \
  -H 'Content-Type: application/json' \
  -d '{"slug": "web-server", "name": "Web server", "ca_account_id": "3e1fa7e9-…"}'
```

**Admin only.** A template decides what a whole class of certificate is allowed to be,
so operator is not enough.

Leaving `validity_days` unset means the CA's default applies. Against the Vault role
above that is 90 days, because the role caps it there — see
[templates.md](../templates.md) for what else a template can assert.

## Step 4: enrol the host

An enrolment token is single-use and short-lived. It is how a host that has never spoken
to CertPilot proves it was invited.

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/agent-enrol-tokens \
  -H 'Content-Type: application/json' -d '{"name": "web01 enrolment"}'
```

> **The token is at the top level of the response, not inside `data`.**
>
> ```json
> { "data": { "id": "b81941a7-…", "expires_at": "…", "max_uses": 1 },
>   "message": "This token is shown once and cannot be recovered…",
>   "token": "cpe_…" }
> ```
>
> `.data.token` is where everything else on this API would put it, and it is empty. A
> script reading it from there gets an empty string and the agent then reports
> `--token is required`, which sends you looking at the agent.

**Admin only**, and shown once. Then, on the host:

```bash
certpilot-agent enrol --server https://certpilot.internal \
  --token "$TOKEN" --name web01 --state-dir /etc/certpilot/state
```

```
Enrolled as "web01"
  agent id : 491f170a-fb35-43e0-a3b9-85d788131e00
  key id   : 70ef69dfb1422660
  identity : /etc/certpilot/state (private key never leaves this host)
```

Keep the agent id. A grant targets a host by it, and nothing else identifies the host
until it has enrolled — which is why this step comes before the next one rather than
after.

## Step 5: grant it a name

```bash
curl -b "$JAR" -X POST localhost:8080/api/v1/agent-grants \
  -H 'Content-Type: application/json' -d '{
  "name": "web01 public names", "template_id": "6ede253b-…",
  "names": ["*.example.com"], "agent_id": "491f170a-…"}'
```

```
One agent may now obtain certificates for *.example.com, with keys generated on the
host. CertPilot will never hold those private keys.
```

A grant is the whole of the host's authority. It may ask for names inside it and nothing
else, and it cannot widen its own grant. See
[agent.md](../agent.md#grants).

## Step 6: ask for the certificate

```bash
certpilot-agent request --name www.example.com --state-dir /etc/certpilot/state
```

```
Issued for www.example.com
  expires    : 2026-12-21T21:17:15Z
  renew after: 2026-11-21T21:17:15Z (the core decides this, not this host)
  files      : /etc/certpilot/state/certificates/www.example.com

The private key was generated on this host and was never sent anywhere.
CertPilot cannot produce it, and does not claim to.
```

The key was generated here. CertPilot received a signing request and returned a
certificate; it has no copy of the key and the record says so — `key_custody` reads
`AGENT`.

## Step 7: install it where nginx reads

The state directory is not where nginx looks. A destination says where the certificate
goes and what to run afterwards, and the `nginx` profile fills in both:

```json
{
  "destinations": [
    { "name": "web", "certificate": "www.example.com", "profile": "nginx" }
  ]
}
```

Write that to `/etc/certpilot/installs.json`. `certpilot-agent profiles nginx` prints
what it expands to — the paths, mode `0640` on the key, `nginx -t` as the check and
`nginx -s reload` as the reload.

```bash
certpilot-agent run --once --state-dir /etc/certpilot/state \
  --installs /etc/certpilot/installs.json
```

```
web  INSTALLED  wrote /etc/certpilot/live/www.example.com/cert.pem,
                /etc/certpilot/live/www.example.com/privkey.pem,
                /etc/certpilot/live/www.example.com/fullchain.pem
                and ran /usr/sbin/nginx -s reload
```

```
-rw-r--r--  root root   919 cert.pem
-rw-r--r--  root root  2983 fullchain.pem
-rw-r-----  root root   241 privkey.pem
```

`--once` runs one cycle and exits, which is what you want while setting this up. In
service, `certpilot-agent run` stays up and repeats every five minutes.

## Step 8: point nginx at it

> **Do this after step 7, not before.** nginx will not start with an
> `ssl_certificate` that does not exist yet, so a server block written first leaves you
> with a web server that is down until the agent has run. Install, then configure, then
> reload. Every renewal after this is the agent's job.

```nginx
server {
    listen 443 ssl;
    server_name www.example.com;

    ssl_certificate     /etc/certpilot/live/www.example.com/fullchain.pem;
    ssl_certificate_key /etc/certpilot/live/www.example.com/privkey.pem;
}
```

`fullchain.pem`, not `cert.pem`. `ssl_certificate` is the only place nginx reads
intermediates from, and a server block naming `cert.pem` serves the leaf alone — which
clients that have already cached the intermediate accept and fresh ones reject.

```bash
nginx -t && nginx -s reload
```

## Step 9: check it, rather than assuming

Three checks, each of which can pass while the others fail.

**What is on the wire:**

```bash
echo | openssl s_client -connect 127.0.0.1:443 -servername www.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
```

```
subject=CN=www.example.com
issuer=CN=CertPilot Lab Issuing CA
notBefore=Sep 22 21:16:45 2026 GMT
notAfter=Dec 21 21:17:15 2026 GMT
sha256 Fingerprint=1D:A0:4F:A0:19:CC:DF:1E:…:46:83
```

**That the chain is complete**, against the root your Vault holds:

```bash
openssl verify -CAfile labroot.pem \
  -untrusted /etc/certpilot/live/www.example.com/fullchain.pem \
  /etc/certpilot/live/www.example.com/cert.pem
```

```
/etc/certpilot/live/www.example.com/cert.pem: OK
```

**That CertPilot and the host hold the same certificate:**

```bash
curl -b "$JAR" localhost:8080/api/v1/agent-installations
```

```
www.example.com  1da04fa019ccdf1e302afdf24453f79c59c122c84199c523a41ddd2cebb84683
```

That is the fingerprint from the handshake above, lower-cased and without the colons.
Everything else can be green while these two differ — the core holding one certificate
and the host serving another is a state in which every status field still reads
correctly.

## Renewal

**The host renews this, and CertPilot does not.** Rotating the certificate means
generating a new key, and the key is here. The core's renewal sweep skips certificates
whose `key_custody` is `AGENT` for exactly that reason; the agent checks `renew_after`
on each cycle and asks for a replacement when it has passed.

So there is nothing to schedule. Leave `certpilot-agent run` up.

> **Do not use `POST /certificates/:id/renew` on one of these.** It is accepted, it
> succeeds, and it is wrong in three ways at once: CertPilot ends up holding a private
> key for a certificate whose `key_custody` still says `AGENT`, the record stops
> describing what the host is serving, and the replacement can be *shorter* than the
> original. [#107](https://github.com/certpilot/certpilot/issues/107), open.

To force a renewal before `renew_after`, do it from the host — `certpilot-agent request`
with the same name replaces what it holds.

## Limitations

- **One destination installs one certificate to one path.** A host serving several names
  from separate certificates needs one destination each, or one certificate with several
  SANs.
- **The agent does not edit `nginx.conf`.** Step 8 is done once, by a person. The agent
  writes files and reloads.
- **`fullchain.pem` contains the root as well as the intermediate** when Vault's
  `ca_chain` does — three certificates were served here. Harmless, and a few hundred
  wasted bytes per handshake.
- **Confirming the right server block is using the certificate** is outside the agent's
  scope. `POST /certificates/:id/verify` reconnects to an endpoint and compares what is
  served; see [operations.md](../operations.md#check-what-is-actually-being-served).
- **Development mode keeps everything in memory.** Restarting the core forgets every
  enrolment, and the host's next cycle is refused with
  `the core did not accept this agent's signature (401)`. Point the core at a database
  before you enrol anything you intend to keep — [database.md](../database.md).

## What this was run against

Vault 2.0.3 in dev mode with the lab PKI above, `certpilot-gateway-vault@v0.3.0`, core
`da9423f`, `certpilot-agent@v0.2.0`, nginx 1.29.8 with OpenSSL 3.5.8. The gateway's own
live tests — issuance, revocation, no-store revocation, CA information, configuration
validation — were run against the same Vault and all passed.

The gateway ran with `--insecure` on loopback here. A real deployment does not: the
core-to-gateway channel carries CSRs and CA credentials, and it is mutually
authenticated by default. See [security.md](../security.md).
