# By platform

The rest of `docs/` is organised the way the software is: a page for the
posture subsystem, a page for the renewal queue, a page for the agent. That is
the right shape for somebody who has already chosen CertPilot and needs to
operate it.

It is the wrong shape for somebody deciding, because nobody arrives with a
question about the posture subsystem. They arrive with *"I have forty nginx
boxes and an F5, does this help me."*

These pages answer that, one platform at a time. Each one names the failure
first, says what CertPilot does about it, gives the commands, and says what it
does not handle.

| | | |
|:---|:---|:---|
| [nginx](nginx.md) | Web | Reloads without dropping a connection |
| [Apache httpd](apache.md) | Web | Graceful restart finishes in-flight requests |
| [HAProxy](haproxy.md) | Web | Wants one file, certificate and key together |
| [Caddy](caddy.md) | Web | Manages its own certificates unless told not to |
| [Apache Tomcat](tomcat.md) | Java | Reads a keystore, not PEM |
| [PostgreSQL](postgresql.md) | Database | Reloads the certificate without a restart |
| [MariaDB and MySQL](mariadb.md) | Database | `FLUSH SSL`, since 10.4 and 8.0.16 |
| [Postfix](postfix.md) | Mail | The certificate every other mail server sees |
| [Dovecot](dovecot.md) | Mail | The certificate every mail client checks |

## What "supported" means on these pages

Every platform listed has been **installed to**. Not unit-tested: run.
`make verify-profiles` starts that service in a container, hands it one
certificate to boot with, installs a *different* one through the agent's own
installer, runs the platform's own check and reload commands, and then
completes a TLS handshake from outside to confirm the service is serving the
installed certificate and sending its chain.

A platform that has not done that does not get a page here. That rule is the
whole reason these pages are worth reading: an unverified asset is how a
quickstart comes to describe a container image nobody ever built.

## What a check command actually catches

Every profile that has a check command runs it before anything is told to pick
the new material up, and the rollback is real. But they do not all catch the
same things, and the differences were measured rather than assumed:

| | Missing certificate file | Certificate and key not a pair | Syntax error |
|:---|:---|:---|:---|
| nginx `-t` | caught | caught | caught |
| Apache `configtest` | caught | **not caught** | caught |
| HAProxy `-c` | caught | caught | caught |
| Caddy `validate` | caught | caught | caught |
| Dovecot `doveconf -n` | **not caught** | **not caught** | caught |
| Postfix `check` | **not caught** | **not caught** | caught |
| PostgreSQL | *no check command exists* | | |
| MariaDB | *no check command exists* | | |
| Tomcat | *no check command exists* | | |

Measured, not inferred: each check was run against a real instance with a
certificate path that does not exist, with a certificate and key that are not a
pair, and with a deliberate syntax error, and the table is the exit codes.

A gap in that table is not a reason to avoid the platform. It is the reason
[post-renewal verification](../deployment.md) exists: it re-probes the endpoint
from outside and answers the only question that matters, which is what the
service is actually serving.

## What is not here

**Anything with no verified profile.** Jetty, Kafka, Elasticsearch, Traefik,
Redis, Prometheus, LiteSpeed and the rest are absent because nobody has run
them, not because they cannot work — the agent installs to a path and runs a
command, and that is all most of them need. Write the four fields by hand;
[agent.md](../agent.md) has the shape.

**Windows.** The agent is Linux-only and nothing about it pretends otherwise.

**Appliances that have no filesystem you can write to.** An F5 BIG-IP or an
Azure Key Vault is reached over its API by the core's own deployers, not by
this agent — [deployment.md](../deployment.md) covers those.
