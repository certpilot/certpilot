# Supported platforms

CertPilot's host agent installs certificates on the platforms listed below.
Each page covers the configuration required, the commands the agent runs, and
the limitations that apply.

| Platform | Type | Notes |
|:---|:---|:---|
| [nginx](nginx.md) | Web server | Reloads without dropping connections |
| [Apache httpd](apache.md) | Web server | Graceful restart completes in-flight requests |
| [HAProxy](haproxy.md) | Load balancer | Requires certificate and key in a single file |
| [Caddy](caddy.md) | Web server | Requires `auto_https off` |
| [Apache Tomcat](tomcat.md) | Java application server | Requires a PKCS#12 keystore |
| [PostgreSQL](postgresql.md) | Database | Reloads without a restart |
| [MariaDB and MySQL](mariadb.md) | Database | Reloads via `FLUSH SSL` |
| [Postfix](postfix.md) | Mail transfer agent | Certificate presented on port 25 |
| [Dovecot](dovecot.md) | IMAP and POP3 server | Certificate presented to mail clients |

A platform is listed here only after it has been tested. Platforms that have
not been tested are not listed, which does not mean they cannot be used — see
[Unlisted platforms](#unlisted-platforms) below.

## How platforms are tested

Each platform is tested automatically by `make verify-profiles`. For each one,
the test:

1. Starts the service in a container with an initial certificate.
2. Installs a second, different certificate using the agent.
3. Runs the platform's configuration check and reload commands.
4. Opens a TLS connection from outside the container and confirms the service
   returns the newly installed certificate and its chain.

The versions each platform was last tested against are recorded in the agent
and shown by `certpilot-agent profiles <name>`.

## Configuration check coverage

Before reloading a service, the agent runs that platform's configuration check
command. If the check fails, the previous certificate is restored and the
service is not reloaded.

Check commands differ in what they detect. The table below records results
measured by running each check against a live instance in three states.

| Check command | Missing certificate file | Certificate and key mismatch | Syntax error |
|:---|:---|:---|:---|
| nginx `-t` | Detected | Detected | Detected |
| Apache `configtest` | Detected | **Not detected** | Detected |
| HAProxy `-c` | Detected | Detected | Detected |
| Caddy `validate` | Detected | Detected | Detected |
| Dovecot `doveconf -n` | **Not detected** | **Not detected** | Detected |
| Postfix `check` | **Not detected** | **Not detected** | Detected |
| PostgreSQL | No check command available | | |
| MariaDB and MySQL | No check command available | | |
| Apache Tomcat | No check command available | | |

Where a check command does not detect a fault, or does not exist,
[post-renewal verification](../deployment.md) provides the backstop: it
reconnects to the endpoint after deployment and reports the certificate the
service is actually serving.

## Unlisted platforms

**Platforms without a tested profile.** Jetty, Kafka, Elasticsearch, Traefik,
Redis, Prometheus and LiteSpeed are not listed because they have not been
tested, not because they are unsupported. The agent requires only a file path,
a format, a check command and a reload command, which can be specified
manually. See [agent.md](../agent.md) for the configuration format.

**Windows.** The agent runs on Linux only.

**Appliances without a writable filesystem.** F5 BIG-IP and Azure Key Vault are
updated through their APIs by CertPilot Core rather than by the host agent. See
[deployment.md](../deployment.md).
