# Apache httpd

Apache reads its certificate at startup and again on a graceful restart, and at
no other time. A renewed certificate on disk changes nothing until somebody
tells the server, on every host, and nobody finds out it did not happen until a
browser says so.

Apache also has a deprecated setting that is still in a great many
configurations: `SSLCertificateChainFile`. Since 2.4.8 the intermediates go in
the same file as the leaf, and a configuration still splitting them is one
upgrade away from serving an incomplete chain.

## What CertPilot does

The agent writes the certificate, runs `apachectl configtest` before anything
picks it up, performs a graceful restart, and rolls back from a captured copy
if that fails.

```bash
certpilot-agent profiles apache
```

```json
{ "name": "web", "certificate": "www.example.com", "profile": "apache" }
```

```apache
SSLCertificateFile    /etc/certpilot/live/www.example.com/fullchain.pem
SSLCertificateKeyFile /etc/certpilot/live/www.example.com/privkey.pem
```

One file for the certificate and its issuers. No `SSLCertificateChainFile`.

The reload is `apachectl graceful` rather than `systemctl`, and that is
deliberate: the unit is `apache2` on Debian and `httpd` on Red Hat, so a
profile naming one would be wrong on half the hosts that used it. This is what
Debian's unit runs verbatim — `ExecReload=/usr/sbin/apachectl graceful` — and
it is the same command on Red Hat, where the unit name is not. Graceful means
in-flight requests finish on the old workers while new ones start.

## What it does not do

- **It does not edit your configuration**, or know which `VirtualHost` should
  use which certificate.
- **`configtest` opens the certificate, but does not pair it with the key.** A
  missing or empty certificate file fails the check, which is better than most
  of the platforms here manage. A certificate and key that are not a pair pass
  it and fail the handshake — which is why the agent's rollback exists and why
  post-renewal verification probes from outside. Both checked against 2.4.68
  rather than assumed.
- **It does not cover mod_md.** If Apache is getting its own certificates over
  ACME, it is doing this job itself and the two should not both be doing it.

Verified against Apache 2.4.68 from the Debian package. See
[agent.md](../agent.md).
