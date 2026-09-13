# PostgreSQL

Nobody thinks of the database as having a certificate. It is not on port 443,
no browser ever shows a padlock for it, and the application connecting to it
very often has `sslmode=require` — which encrypts and **does not check the
certificate at all**. So the certificate expires, nothing breaks, and nobody
knows.

Then somebody moves that application to `sslmode=verify-full`, which is the
correct setting, and discovers the certificate expired eleven months ago.

The other half is specific to PostgreSQL and worth knowing before it happens to
you: on reload, a postmaster handed an unreadable or malformed certificate
**logs the failure and carries on with the one it already had**:

```
LOG:  could not load server certificate file "...": bad base64 decode
LOG:  SSL configuration was not reloaded
```

The service does not fall over, no connection is dropped, and the rotation
silently does not happen. Those two lines are the only evidence.

## What CertPilot does

The certificate is inventoried, monitored and alerted on like every other
certificate in the estate, and the agent installs it where PostgreSQL reads it.

```bash
certpilot-agent profiles postgresql
```

```json
{ "name": "db", "certificate": "db-01.example.com", "profile": "postgresql" }
```

```
ssl = on
ssl_cert_file = '/etc/certpilot/live/db-01.example.com/fullchain.pem'
ssl_key_file  = '/etc/certpilot/live/db-01.example.com/privkey.pem'
```

The profile sets `owner`, `group` and mode `0600`, because PostgreSQL is one of
the very few services that checks: it refuses to start if its key is readable
by anyone but the account it runs as. If your PostgreSQL runs as something
other than `postgres`, say so on the destination.

Reload is a SIGHUP. No restart, no dropped connections.

## What it does not do

- **There is no check command**, because PostgreSQL has no configuration
  validator to run. That is a real downgrade in safety compared with the web
  servers on these pages — combined with the carry-on-regardless behaviour
  above, the failure mode is a rotation that reports success and did not
  happen. **Watch the log after a rotation**, or let post-renewal verification
  probe the port from outside.
- **`systemctl reload postgresql` is Debian's unit name.** Red Hat's carries
  the major version — `postgresql-16` — so change it there.
- **It does not touch `pg_hba.conf`.** Requiring TLS, and requiring clients to
  verify it, are your decisions.

Verified against PostgreSQL 16.15. See [agent.md](../agent.md).
