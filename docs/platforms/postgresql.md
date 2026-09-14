# PostgreSQL

PostgreSQL server certificates are frequently overlooked. Clients connecting
with `sslmode=require` encrypt the connection but do not validate the
certificate, so an expired certificate causes no visible failure. The
expiry becomes apparent only when a client is moved to `sslmode=verify-full`,
which is the setting that provides actual protection.

PostgreSQL also handles a failed certificate reload in a way worth
understanding in advance. If the certificate cannot be read or parsed during a
reload, the server logs the failure and continues using the previously loaded
certificate:

```
LOG:  could not load server certificate file "...": bad base64 decode
LOG:  SSL configuration was not reloaded
```

The service remains available and no connections are dropped. The rotation
simply does not take effect, and these log entries are the only indication.

## Configuration

```json
{ "name": "db", "certificate": "db-01.example.com", "profile": "postgresql" }
```

```
ssl = on
ssl_cert_file = '/etc/certpilot/live/db-01.example.com/fullchain.pem'
ssl_key_file  = '/etc/certpilot/live/db-01.example.com/privkey.pem'
```

The profile sets the key's owner and group to `postgres` and its mode to
`0600`. PostgreSQL refuses to start if the private key is readable by any
account other than the one the server runs as. If PostgreSQL runs as a
different user on this host, set `owner` and `group` on the destination
accordingly.

## What the agent does

The agent writes the certificate and key with the required ownership and
permissions, then reloads PostgreSQL. The reload is a `SIGHUP`: no restart is
performed and no connections are dropped.

## Limitations

- **No configuration check is available.** PostgreSQL provides no equivalent of
  `nginx -t`. Combined with the reload behaviour described above, a failed
  rotation reports success. Review the server log after a renewal, or rely on
  [post-renewal verification](../deployment.md) to confirm the certificate in
  use.
- **Verify the service unit name.** `systemctl reload postgresql` is correct on
  Debian and Ubuntu. Red Hat packages include the major version in the unit
  name, for example `postgresql-16`.
- **The agent does not modify `pg_hba.conf`.** Requiring TLS, and requiring
  clients to verify certificates, remain configuration decisions for the
  administrator.

Last tested against PostgreSQL 16.15. See [agent.md](../agent.md).
