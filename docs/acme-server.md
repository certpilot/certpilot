# The ACME server

Most hosts that need a certificate already run an ACME client: certbot,
acme.sh, lego, win-acme, Caddy. The core can serve ACME (RFC 8555) itself, so
those clients get certificates from CertPilot with no agent installed. The
client generates and keeps its key. CertPilot issues through the template you
choose, records the certificate as held by the client, and alerts on it like
any other.

This is the other direction from the [ACME gateway](gateways/acme.md), where
CertPilot is the client of a public CA.

## Turning it on

Off by default, because it opens unauthenticated endpoints on the core's
listener.

```yaml
acme:
  enabled: true
  external_url: "https://certpilot.example.com"
```

`external_url` is the address clients use. Every URL the server hands out is
built from it, and a request is refused unless it was signed for one of them.
It is required, and must be `https`, in production mode.
[configuration.md](configuration.md#acme) has every setting.

There is one directory per template, at
`https://certpilot.example.com/acme/<template-slug>/directory`. A template
already pins its CA, the names it allows, its key types and its lifetime, so
the template is what you hand a client access to.

## Giving a client access

Registration is closed. Each client needs a credential, an External Account
Binding: a key ID and an HMAC key. Make one in **Settings → ACME clients**:
choose a name that says who it is for, and the template. The HMAC key is shown
once, with the directory URL and a certbot command filled in. CertPilot keeps
the key sealed and cannot show it again; if it is lost, revoke the credential
and make another.

The same through the API, as an administrator:

```bash
curl -s -X POST "$CERTPILOT/api/v1/acme/credentials" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "web team", "template": "internal-web"}'
```

One credential makes one account. Then, on the host:

```bash
# certbot
certbot register --server "$DIRECTORY_URL" \
  --eab-kid "$KID" --eab-hmac-key "$HMAC_KEY" --email ops@example.com
certbot certonly --server "$DIRECTORY_URL" --webroot -w /var/www/html \
  -d web.example.com -d api.example.com

# acme.sh
acme.sh --register-account --server "$DIRECTORY_URL" \
  --eab-kid "$KID" --eab-hmac-key "$HMAC_KEY" -m ops@example.com
acme.sh --issue --server "$DIRECTORY_URL" -d web.example.com -w /var/www/html

# lego
lego --server "$DIRECTORY_URL" --email ops@example.com --accept-tos \
  --eab --kid "$KID" --hmac "$HMAC_KEY" \
  --domains web.example.com --http --http.webroot /var/www/html run
```

lego and acme.sh refuse a directory that is not `https`. All three are run
against the server in CI, as released (`make live-acme`).

## What the template decides

The CSR goes through the same rules as a request made in the console: the
template's names, key types, key usages and lifetime, and the estate-wide
policy above it. A name the template does not allow is refused when the order
is finalised, with the template's reason. The lifetime is the template's, so an
order that names `notBefore` or `notAfter` is refused. The CSR must ask for
exactly the names ordered.

The certificate is recorded with `discovered_via: ACME` and
`key_custody: EXTERNAL`, and with automatic renewal off: the client renews it,
and CertPilot holds no key to renew it with.

## Proof of control

By default the credential is the authorisation. The template's name rules
bound what it covers, and the client is not asked to prove anything further.

A credential made with **Require proof of control** (`"require_challenge":
true`) also makes the client prove each name before anything is issued, by any
one of:

- **HTTP-01**: a file at `http://<name>/.well-known/acme-challenge/<token>`,
  fetched on port 80. Up to ten redirects are followed, only to the same name,
  over http on port 80 or https on 443 (whose certificate is not checked, as
  RFC 8555 says): a redirect is a web server telling the core where to
  connect, and it cannot send it anywhere a challenge could not go. A redirect
  to another name, such as a CDN's, is refused, where Let's Encrypt would
  follow it.
- **DNS-01**: a TXT record at `_acme-challenge.<name>`. The only one a wildcard
  can use.
- **TLS-ALPN-01** (RFC 8737): a self-signed certificate for the name, carrying
  the key authorization, served on port 443 to a connection asking for
  `acme-tls/1`.

The core looks the name up with `acme.challenges.dns_resolver`, or the system's
resolver when that is not set, so point it at the resolver that sees your
internal zones. A failed proof ends the order, and the client orders again.
Proving a name does not let a template issue what it does not allow: the
template's rules still apply when the order is finalised.

## Renewal

A client renews by ordering again. An order from the same account for the same
names and key type as a live certificate is a renewal: it is written over that
certificate's record, as the core's own renewals are. The renewal count goes
up, the old fingerprint is kept, and the check that the new certificate reached
its servers is scheduled. Different names, another key type or another account
make a second certificate.

The server also offers ACME Renewal Information (RFC 9773). A client that asks
`renewalInfo` is given the window in which the core would renew the
certificate itself: the template's renewal lead before expiry. A revoked
certificate gets a window that has already passed, which tells the client to
replace it now. certbot and lego both ask. lego also sends `replaces`, which
renews the record it names even when the names change.

## Revocation

```bash
certbot revoke --server "$DIRECTORY_URL" --cert-name web.example.com --reason keycompromise
```

The account that ordered a certificate may revoke it, and so may anyone signing
with the certificate's own private key. Other accounts on the same template may
not. The CA is told first and the inventory changes only if it agrees, as with
a revocation made in the console, and it is audited under the same
`certificate.revoked` action. The certificate a renewal replaced can still be
revoked: the CA is sent it, and the record, which now describes its successor,
is left as it is.

## Cutting a client off

Revoke its credential in Settings → ACME clients. The account it made is
deactivated in the same step, so the client can no longer order, renew or
revoke, and no new account can be made with the credential. Certificates it was
already issued stay valid; revoke them as well if the client's keys are no
longer trusted.

An account can also roll its key over (RFC 8555 key change): the request has to
be signed by both the old key and the new one.

## Limitations

- No open registration. Every client needs a credential.
- Names only: a `dns` identifier has to be a host name, and IP address
  identifiers (RFC 8738) are not accepted.
- Caddy and win-acme speak the same protocol and should work; neither has been
  run against it.
- A client renews its own certificates. CertPilot cannot renew one early for
  it, except by revoking it, which renewalInfo then tells the client to
  replace.
