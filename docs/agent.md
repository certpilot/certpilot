# The host agent

One binary that runs on the machines where certificates are actually served.

Its reason for existing is one sentence:

> **The agent generates its own private keys and never sends them anywhere.**
> CertPilot cannot produce them and does not claim to.

Everything else here follows from that.

- [Where it runs](#where-it-runs)
- [What it does](#what-it-does)
- [Enrolment](#enrolment)
- [Grants](#grants)
- [Requesting a certificate](#requesting-a-certificate)
- [Installing where the server reads](#installing-where-the-server-reads)
- [Inventory](#inventory)
- [Running it](#running-it)
- [What can go wrong](#what-can-go-wrong)

---

## Where it runs

The agent's home is **Linux, under systemd**: that is what it is released as,
what every deployment profile describes, and what the platform pages cover.
It also builds and runs on Windows, with the limits set out below.

| Target | State |
|:---|:---|
| Linux | Supported. Every deployment profile is tested against it |
| Windows | Builds and runs for file destinations. No deployment profiles, and the certificate store is not written to — see [Windows](#windows) |
| macOS, FreeBSD | Compiles, and is usable for development. Not tested, and the deployment profiles assume systemd |

The published container image is built on Alpine, every deployment profile
reloads its service with `systemctl`, and the configuration paths the profiles
write to are the Linux ones: `/etc/nginx`, `/etc/apache2`, `/etc/haproxy`.

### Windows

The agent runs on Windows and writes certificates to files there. What it does
not do is write to the Windows certificate store, which is what IIS, Exchange,
ADFS, NPS and RDS read from.

**The private key guarantee is an ACL, not a mode.** Windows has no file modes.
Go accepts a `0600` and ignores it, and the file inherits whatever its directory
grants — under `ProgramData`, usually read access for every authenticated user
on the machine. So the agent sets an explicit access control list on every key
it writes: the account it runs as, `SYSTEM`, and the local administrators, with
inheritance switched off. A certificate written at a world-readable mode is left
alone, because the service reading it often runs as a different account.

SYSTEM and Administrators are on that list deliberately. A key no administrator
can read is not safer — an administrator can take ownership of it in one
command — but it is unbackuppable and invisible to the endpoint tooling every
Windows estate runs. What the ACL removes is *other ordinary accounts*.

**No deployment profiles.** Every profile in the catalogue describes a Linux
service: `systemctl` to reload, `/etc/nginx` and `/etc/haproxy` to write to.
Naming one on Windows is refused, with a message saying to set `cert_path`,
`key_path`, `check` and `reload` on the destination instead.

**No `owner` or `group`.** Both are Unix file ownership. They are refused when
the spec is read rather than accepted and ignored, because an operator who sets
them believes a service account can read a key it cannot.

**The certificate store is not written to.** IIS binds a certificate by
thumbprint from `LocalMachine\My` rather than reading a file, and Exchange,
ADFS, NPS and RDS each have their own binding step. Importing also has no
equivalent of the installer's rollback — capture the previous file, put it back
if the reload fails — so it is a separate piece of work rather than a flag.
Tracked in [issue #38](https://github.com/certpilot/certpilot/issues/38).

So the Windows hosts this helps today are the ones whose software reads
certificates from disk: nginx, Java applications, PostgreSQL, Node services.

**Without the agent at all.** The core does not need it in order to deploy. A
signed webhook target delivers the certificate to an endpoint you control, which
can be a script on the Windows host. The agent's contract is also published, in
[`certpilot-agent-sdk`](https://github.com/certpilot/certpilot-agent-sdk), so an
agent written in another language is a first-class one — the core does not
distinguish it from this binary.

---

## What it does

Four things, on a cycle:

| | |
|:---|:---|
| **Heartbeat** | Reports that this host is alive, and what it holds |
| **Renew** | Replaces certificates it holds that are due, generating a new key each time |
| **Install** | Writes certificates where the local server reads them, and reloads it |
| **Inventory** | Reports the certificate files it finds on disk, including ones nobody told CertPilot about |

It is not a gateway. It speaks HTTPS to `/api/v1/agent/*`, not gRPC, and it is
authenticated by an Ed25519 signature rather than by a client certificate.

---

## Enrolment

```bash
certpilot-agent enrol \
  --server https://certpilot.internal:8080 \
  --token <enrolment token> \
  --name web-01
```

An operator issues the token first:

```bash
curl -X POST localhost:8080/api/v1/agent-enrol-tokens \
  -H 'Content-Type: application/json' \
  -d '{"name": "web tier", "labels": {"tier": "web", "env": "production"}, "max_uses": 20}'
```

What happens, in order:

1. The agent **generates an Ed25519 keypair on the host**, before anything is
   sent.
2. It sends the public half, its hostname and its platform. There is no field
   in the request for the private half — not as a precaution but as the shape
   of the thing.
3. The core records the agent, attaches the token's **labels**, and returns an
   agent ID.
4. The agent writes its identity to `--state-dir` at `0600`.

Every subsequent request is signed:

```
certpilot-agent-v1
<METHOD>
<PATH>
<unix-seconds>
<hex sha256 of body>
```

Five-minute tolerance. Headers `X-CertPilot-Agent`, `X-CertPilot-Timestamp`,
`X-CertPilot-Signature`.

**Labels come from the token, not from the agent.** A host cannot label itself
into somebody else's grant — which is the whole point of putting the labels on
the token an operator issued.

**Re-enrolling is refused** when an identity already exists. Doing it silently
would leave the old agent's record on the core with a key nothing holds any
more, and nobody would notice until that host stopped renewing.

### State directory

| Running as | Default |
|:---|:---|
| root | `/var/lib/certpilot-agent` |
| anyone else | `$HOME/.certpilot-agent` |

Override with `--state-dir` or `CERTPILOT_AGENT_STATE`. Under `/var/lib` for a
system service because that is where a service's state belongs, and because it
does not then get backed up to somebody's home directory by accident.

---

## Grants

An agent cannot ask for whatever it likes. An operator writes a grant first,
and the grant is checked on every request.

A grant says **who may ask, and for which names**. What the certificate looks
like — the issuer, the key rules, the lifetime — lives on the
[certificate template](templates.md) the grant names.

```bash
curl -X POST localhost:8080/api/v1/agent-grants -H 'Content-Type: application/json' -d '{
  "name": "web tier certificates",
  "template_id": "host-workloads",
  "label_selector": {"tier": "web"},
  "names": ["*.web.example.com", "api.example.com"]
}'
```

| Field | |
|:---|:---|
| `template_id` | The template this grant is permission for, by slug or uuid. **Required** |
| `subject_kind` | `AGENT` (the default), or `ROLE`, `TEAM`, `USER` for a person's request |
| `agent_id` | Targets one host |
| `label_selector` | Targets every agent carrying these labels. Either this or `agent_id` |
| `names` | Exact hostnames, or single-level wildcards. A **narrowing** of what the template permits, never an exception to it |

### Why the shape is not on the grant

It used to be. `ca_account_id`, `allowed_key_types`, `min_key_size`,
`validity_days` and `renew_before_days` were columns here, and that made them a
second rulebook — narrower than `policies`, reachable only by agents, and
maintained separately. The result was that a `BLOCK` policy an operator wrote
stopped somebody in the console and did not stop a host.

Now both paths go through one resolver, so the same template rules and the same
estate-wide floor apply to a host as to a person. Migration 038 converted every
existing grant into a template carrying its exact rules, so nothing an agent
could request before is refused now.

`renew_before_days` moved to the template and still does the same job: it
becomes `renew_after` in the response, and **the core decides when**, not the
host. A fleet that picked its own renewal moment is a fleet that can decide to
renew hourly, and four hundred hosts doing that is a denial of service against
your CA.

A refused request is recorded and raises `agent.request_refused`. An agent
asking for a name it has no grant for is a signal, not a nuisance.

---

## Requesting a certificate

```bash
certpilot-agent request --name web-01.example.com --key-type ECDSA
```

```
1. generate a key                       on this host
2. build a CSR                          names only — no extensions
3. POST /api/v1/agent/certificates      the CSR, and the install path
4. core checks the grant                names, key type, size, CA account
5. core asks the gateway to sign        the CSR travels; the key does not
6. write key (0600), cert, chain, meta  together, after the core answers
```

Step 6's ordering is deliberate: the key is written first at `0600`. If
anything fails after that, the host has a key it cannot use, which is inert.
The other order leaves a certificate whose key never landed — which looks like
a working deployment until something restarts.

The CSR carries **names only**. No basic constraints, no key usage, no
requested extensions: a CSR is a request, the CA builds its own template, and
anything else would at best be ignored and at worst honoured by a CA that
should not have.

### Renewal

The agent renews its own certificates, because it is the only thing that can —
rotating means generating a new key, and the core does not have one and must
not. The core's renewal sweep skips agent-held certificates for exactly that
reason.

When to renew comes from `renew_after` in the grant's response.

---

## Installing where the server reads

Obtaining a certificate is only the first step. It must then be written to the
location the service reads, with the correct ownership and permissions, and the
service must be reloaded.

### Platform profiles

Installing a certificate for a given platform requires four values: a file
path, a file format, a command that validates the configuration, and a command
that reloads the service. A profile supplies all four, so a destination can
name the platform instead of specifying them individually:

```json
{
  "destinations": [
    { "name": "web", "certificate": "web-01.example.com", "profile": "nginx" }
  ]
}
```

That supplies the file paths, the file modes, and the `nginx -t` and
`nginx -s reload` commands. Run `certpilot-agent profiles` to list the
platforms, or `certpilot-agent profiles nginx` to see exactly what one profile
supplies and what it does not cover. [platforms/](platforms/README.md)
documents each platform's configuration requirements and limitations.

**A profile provides defaults, which can be overridden.** Any field written in
the destination takes precedence over the profile's value. This includes an
explicitly empty list: `"reload": []` indicates that the destination is
reloaded by some other means, and the profile's reload command is not
substituted. Deployments that keep certificates in non-standard locations are
therefore still able to use a profile for the remaining fields.

`{{ .Certificate }}` in any path is replaced with the certificate's name. It is
the only placeholder supported, and any other text in double braces is rejected
when the file is read, rather than written to disk as a literal filename.

| Profile | Platform | Verified against |
|:---|:---|:---|
| `nginx` | nginx | nginx 1.27.5 |
| `apache` | Apache httpd | Apache 2.4.68, Debian package |
| `haproxy` | HAProxy | HAProxy 2.6.12, Debian package |
| `caddy` | Caddy | Caddy 2.11.4 |
| `tomcat` | Apache Tomcat | Tomcat 10.1.59 on JDK 21 |
| `postgresql` | PostgreSQL | PostgreSQL 16.15 |
| `mariadb` | MariaDB and MySQL | MariaDB 10.11.18, Debian package |
| `postfix` | Postfix | Postfix 3.7.11, Debian package |
| `dovecot` | Dovecot | Dovecot 2.3.19.1, Debian package |

Each profile is tested by `make verify-profiles`, which starts the service in a
container with one certificate, installs a different one using the agent, runs
the profile's check and reload commands, and then opens a TLS connection from
outside the container to confirm the service returns the newly installed
certificate and its chain. Profiles that have not passed this test are not
included.

### Detection

```bash
certpilot-agent profiles --detect
```

Reports which of these platforms appear to be installed on the host. The result
indicates that a configuration file exists in the location that platform
normally uses. It does not confirm that the profile's paths match the ones the
running service reads, which is determined by that service's own configuration.
The agent does not act on detection; the output is intended for review by an
administrator.

### Or write it out in full

`/etc/certpilot/installs.json`:

```json
{
  "destinations": [
    {
      "name": "nginx",
      "certificate": "web-01.example.com",
      "cert_path": "/etc/nginx/tls/web-01.pem",
      "key_path": "/etc/nginx/tls/web-01-key.pem",
      "chain_path": "/etc/nginx/tls/chain.pem",
      "cert_mode": "0644",
      "key_mode": "0600",
      "owner": "root",
      "group": "root",
      "check": ["/usr/sbin/nginx", "-t"],
      "reload": ["/bin/systemctl", "reload", "nginx"]
    }
  ]
}
```

### Keystores, for anything on the JVM

A JVM reads a keystore, not a pair of PEM files, so a Tomcat, Jetty, Kafka or
Elasticsearch estate was invisible to this agent until it could write one.

```json
{
  "name": "tomcat",
  "certificate": "app.example.com",
  "format": "PKCS12",
  "cert_path": "/opt/tomcat/conf/keystore.p12",
  "keystore_password_file": "/opt/tomcat/conf/keystore.pass",
  "keystore_alias": "tomcat",
  "key_mode": "0600",
  "check": ["/opt/tomcat/bin/configtest.sh"],
  "reload": ["/bin/systemctl", "reload", "tomcat"]
}
```

**`check` and `reload` run with `PATH` and nothing else.** The agent clears the
environment before running either, so that a command named in this file cannot
read whatever put the agent's own environment together — an enrolment token, a
server address. It costs one thing worth knowing: a command that needs a
variable must set it itself, which is why `catalina.sh` called directly needs
`JAVA_HOME` and the same command through `systemctl` does not.

`cert_path` is the keystore, and `key_path` must be omitted — the key is inside
it, and naming a second path would write it to disk in the clear as well.
`chain_path` does not apply either: the chain is stored as CA certificates,
which is what a consumer asking the keystore for a chain expects. Everything
else works exactly as it does for PEM — the mode, the ownership, the check
before the reload, and the rollback from a captured copy if the reload fails.

**PKCS#12 and not JKS.** Java 9 made PKCS#12 the default keystore type and every
JDK since reads it natively, so this covers the modern JVM and the `.pfx` that
Windows tooling and several appliances want. JKS is for an estate still on
Java 8 and is not written by this build.

#### Naming the entry

A keystore is a map, and Java looks entries up by name. `keystore_alias` is that
name.

Leave it out and the entry is written unnamed, which the JDK reports as `1`
because it falls back to a counter. That is correct for a configuration that
does not name an alias, and wrong for one that does: a Tomcat connector with
`certificateKeyAlias="tomcat"` — the conventional value, and what
`keytool -genkeypair -alias tomcat` produces — cannot find the key, while Tomcat
still reports a successful startup. Tomcat has no configuration check, so
nothing catches that until post-renewal verification reports the endpoint
serving the old certificate.

There is no default and no profile supplies one. The value has to match a
configuration file this agent cannot read, so anything chosen here would be a
guess, and a wrong guess is a host looking at the right file and finding nothing
in it. Setting it on a PEM destination is refused when the spec is read, rather
than accepted and ignored.

#### About that password

It is **not protecting the key from anyone**. The private key is already on this
host — this agent generated it there — and whoever can read the keystore can
read whatever else is in that directory.

What it is, is a coordination value. Tomcat has it in `server.xml`, and the
keystore will not open unless the two match. Which is why there is no default:
`changeit` is what every Java tutorial uses, and defaulting to it would look
like protection while being none.

Give it as `keystore_password` inline, or `keystore_password_file` pointing at a
file — the second exists so an operator who already keeps it in one for their
application does not have to copy it into a second place. Exactly one, and
omitting both is refused when the spec is read rather than when the install
runs.

---

```bash
certpilot-agent install            # writes what has changed, checks, reloads
certpilot-agent install --force    # rewrite and reload even when unchanged
certpilot-agent install --offline  # do the local work, report nothing
```

The sequence per destination:

```
capture what is there  →  write atomically  →  run check  →  run reload
                                   │
                                   └── check fails → restore the previous bytes
```

**Atomic writes.** A temp file in the same directory, `chmod` before `rename`,
`Sync()` before `rename`. A server reading a half-written certificate is a
server that has stopped serving TLS.

**The check runs before the reload.** If `nginx -t` fails, the previous
contents come back and the reload never happens. A bad certificate that fails a
config check leaves the server exactly as it was.

**No shell.** `check` and `reload` are argv arrays executed directly, with a
bare `PATH=/usr/sbin:/usr/bin:/sbin:/bin`. There is no string to inject into.

**A combined file** — one path holding certificate and key, which HAProxy wants
— is refused if `cert_mode` would make it world-readable. The key is in that
file.

### Why `--offline` exists

Putting a certificate this machine already holds where its own server reads it
needs permission from nobody. `--offline` works with a revoked credential or an
unreachable core, because the alternative — a host that cannot fix its own TLS
because the control plane is down — is the wrong dependency to create.

---

## Inventory

```bash
certpilot-agent scan --json
```

Walks the default paths (or `--path`, repeatable), parses every certificate it
finds, and reports fingerprint, subject, expiry and **whether a private key sits
beside it and how readable that key is**.

The last part is the interesting one. `agent.key_exposed` fires when a private
key on a host is group- or world-readable. That is a finding no amount of
certificate management produces, and it is usually somebody's `cp` from three
years ago.

Reported certificates the core does not recognise raise `agent.unmanaged` —
the same verdict as a network scan, from the inside.

---

## Running it

```bash
certpilot-agent run                # the loop: heartbeat, renew, install, inventory
certpilot-agent run --once         # one cycle, then exit — for cron or a unit timer
certpilot-agent status             # what this host holds and when it last reported
```

As a systemd unit — see [Where it runs](#where-it-runs) for the platforms
this is supported on:

```ini
[Unit]
Description=CertPilot agent
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/certpilot-agent run
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

It runs as root when it has to write into `/etc/nginx` and reload a service.
Where it does not, run it as a user that owns the certificate directory.

---

## What can go wrong

| Symptom | Cause |
|:---|:---|
| `enrol` refuses | An identity already exists in the state directory. Remove it deliberately, or use another `--state-dir` |
| Requests rejected with a signature error | Clock skew beyond five minutes. Check NTP |
| `agent.request_refused` in the activity feed | The host asked for a name no grant covers. Check `label_selector` and `names` |
| A certificate renews but the server serves the old one | The install destination is not where the server actually reads. `certpilot-agent install --force` and read the check output |
| `agent.stale` | The host stopped reporting. Its certificates will expire silently — this alert is the only warning |
| `agent.key_exposed` | A private key on that host is group- or world-readable |

See [troubleshooting.md](troubleshooting.md) for the rest.
