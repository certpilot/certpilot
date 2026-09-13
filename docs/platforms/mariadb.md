# MariaDB and MySQL

Two things make database certificates the ones that get left to expire.

**The runbook says restart.** Before MariaDB 10.4 and MySQL 8.0.16 there was no
way to present a new certificate without restarting the server, and a great
many internal wiki pages still say exactly that. A restart of the primary
database is not something anybody schedules casually, so it does not get
scheduled, so the certificate does not get rotated.

**The permissions failure is delayed.** Hand MariaDB a key it cannot read and
it refuses to start — `Failed to setup SSL … Aborting`. That is the right
behaviour, and it is still the worse outcome here, because nothing tries to
start a database on the day you rotate its certificate. The rotation looks
fine. Weeks later something restarts the server for an unrelated reason and it
does not come back, and the change that caused it is a month behind you.

## What CertPilot does

`FLUSH SSL` — the statement that makes the restart unnecessary — as the reload
command, so the rotation is a non-event.

```bash
certpilot-agent profiles mariadb
```

```json
{ "name": "db", "certificate": "db-01.example.com", "profile": "mariadb" }
```

```ini
[mariadbd]
ssl_cert = /etc/certpilot/live/db-01.example.com/fullchain.pem
ssl_key  = /etc/certpilot/live/db-01.example.com/privkey.pem
```

The profile sets `owner` and `group` to `mysql` and the key to `0600`, which is
what stops the delayed failure above — the key is readable by the account that
has to read it, from the moment it is written rather than from the moment
somebody notices.

**On MySQL the statement is `ALTER INSTANCE RELOAD TLS`.** Same idea, different
spelling; change the reload line.

## What it does not do

- **The reload runs as root over the unix socket**, which works on a Debian or
  Ubuntu package because root authenticates with `unix_socket`. On a host where
  root has a password this needs credentials — put them in a `my.cnf` that the
  root account reads, **never on the command line**, where `ps` would show them
  to every account on the machine.
- **There is no check command.** Neither server has a configuration validator
  to run before the reload.
- **It does not set `require_secure_transport`**, or change any user's TLS
  requirements. Installing a certificate is not the same as requiring it be
  used, and the second one breaks clients.

Verified against MariaDB 10.11.18 from the Debian package. See
[agent.md](../agent.md).
