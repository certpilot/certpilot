# Apache httpd

Apache reads its certificate files at startup and on a graceful restart. A
renewed certificate on disk has no effect until Apache is reloaded.

## Configuration

```json
{ "name": "web", "certificate": "www.example.com", "profile": "apache" }
```

```apache
SSLCertificateFile    /etc/certpilot/live/www.example.com/fullchain.pem
SSLCertificateKeyFile /etc/certpilot/live/www.example.com/privkey.pem
```

`SSLCertificateFile` should reference `fullchain.pem`. Apache 2.4.8 and later
read intermediate certificates from the same file as the leaf certificate.
`SSLCertificateChainFile` is deprecated and should not be used; configurations
that still set it should be migrated, as it is scheduled for removal.

## What the agent does

The agent writes the certificate and key, runs `apachectl configtest`,
performs a graceful restart, and restores the previous files if the restart
fails.

The reload command is `apachectl graceful` rather than `systemctl`. The service
unit is named `apache2` on Debian and Ubuntu and `httpd` on Red Hat
derivatives, so a profile referencing either would be incorrect on the other.
`apachectl graceful` is the command Debian's unit file runs, and is valid on
Red Hat systems as well. A graceful restart allows in-flight requests to
complete on existing worker processes.

## Limitations

- **The agent does not modify Apache's configuration**, and does not determine
  which `VirtualHost` uses which certificate.
- **`configtest` does not detect a mismatched certificate and key.** It does
  detect a missing or empty certificate file. A certificate and key that are
  not a matching pair will pass the check and fail at the TLS handshake, which
  is why the agent restores the previous files on reload failure and why
  post-renewal verification is recommended.
- **Not compatible with `mod_md`.** If Apache is obtaining its own certificates
  over ACME, it is already performing this function and the two should not both
  be configured.

Last tested against Apache 2.4.68 (Debian package). See
[agent.md](../agent.md).
