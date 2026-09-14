# MariaDB and MySQL

Two characteristics make database certificates more likely to be left
unrotated than web server certificates.

**Older procedures require a restart.** Before MariaDB 10.4 and MySQL 8.0.16
there was no way to load a new certificate without restarting the server.
Documentation and internal procedures written before those releases still
specify a restart, which is rarely scheduled for a production database.

**An unreadable key prevents startup.** If the private key cannot be read by
the account the server runs as, the server does not start:

```
SSL error: Unable to get private key from '...'
[ERROR] Failed to setup SSL
[ERROR] Aborting
```

This is the correct behaviour, but the failure is delayed. Nothing restarts a
database on the day its certificate is rotated, so an incorrectly permissioned
key may not cause a failure until the next restart, potentially weeks later and
for an unrelated reason.

## Configuration

```json
{ "name": "db", "certificate": "db-01.example.com", "profile": "mariadb" }
```

```ini
[mariadbd]
ssl_cert = /etc/certpilot/live/db-01.example.com/fullchain.pem
ssl_key  = /etc/certpilot/live/db-01.example.com/privkey.pem
```

The profile sets the key's owner and group to `mysql` and its mode to `0600`,
which prevents the startup failure described above.

## What the agent does

The agent writes the certificate and key with the required ownership, then runs
`FLUSH SSL`, which loads the new certificate without a restart and without
dropping connections.

**On MySQL the equivalent statement is `ALTER INSTANCE RELOAD TLS`.** Update
the reload command in the destination accordingly.

## Limitations

- **The reload command connects as root over the local socket.** This works on
  Debian and Ubuntu packages, where the root account authenticates using the
  `unix_socket` plugin. On a host where the root account has a password, supply
  credentials in a `my.cnf` file readable by root. Do not place credentials on
  the command line, where they are visible to all accounts via `ps`.
- **No configuration check is available.** Neither server provides a
  configuration validator that can be run before the reload.
- **The agent does not enable `require_secure_transport`** or modify any
  account's TLS requirements. Installing a certificate and requiring its use
  are separate decisions.

Last tested against MariaDB 10.11.18 (Debian package). See
[agent.md](../agent.md).
