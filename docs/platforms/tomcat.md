# Apache Tomcat

A JVM does not read PEM. It reads a keystore — one file holding the
certificate, its chain and the private key together, opened with a password
that also appears in `server.xml`.

That single difference is why Java estates renew by hand years after everything
else stopped. The certificate arrives as PEM, somebody runs `openssl pkcs12
-export` and `keytool` from memory or from a wiki page, gets the alias or the
password or the chain order wrong, and restarts Tomcat to find out. It is a
task nobody automates because it never felt like the same task as copying two
files.

It is the same task. Only the encoding is different.

## What CertPilot does

The agent writes the keystore itself, from the key it generated on this host
and the certificate it was issued. The mode, the ownership, the check before
the reload and the rollback from a captured copy all work exactly as they do
for PEM, because a keystore is a different encoding and not a different kind of
operation.

```bash
certpilot-agent profiles tomcat
```

```json
{
  "name": "tomcat",
  "certificate": "app.example.com",
  "profile": "tomcat",
  "keystore_password_file": "/etc/certpilot/keystore-password"
}
```

```xml
<Certificate certificateKeystoreFile="/etc/certpilot/live/app.example.com/keystore.p12"
             certificateKeystorePassword="..."
             certificateKeystoreType="PKCS12" />
```

`key_path` is omitted, deliberately — the key is inside the keystore, and
naming a second path would also write it to disk in the clear.

**The password has no default and will not get one.** It is not protecting the
key from anybody: the key is already on this host, written by this same agent,
and whoever can read the keystore can read the directory it is in. It is a
coordination value — Tomcat has it in `server.xml` and the keystore will not
open unless the two match. `changeit` is what every Java tutorial uses, and
defaulting to it would be theatre with the added harm of looking like
protection.

## What it does not do

- **This one restarts.** Tomcat re-reads a keystore when the connector is
  rebuilt and there is no supported way to make it do that in place, so it is
  the only platform here whose rotation drops connections. Schedule it.
- **It does not write JKS.** PKCS#12 has been the JVM default since Java 9 and
  every JDK since reads it natively. A Java 8 estate, or an application with a
  hard-coded `storetype=JKS`, is not covered — `keytool -importkeystore`
  converts in one command in the meantime.
- **The unit name is a guess.** The profile says `tomcat10`, which is Debian
  12. Change it for `tomcat9`, for Red Hat, or for a Tomcat installed from the
  tarball — which is most of them.
- **`check` and `reload` run with `PATH` and nothing else**, so that a command
  in that file cannot read whatever put the agent's own environment together. A
  reload calling `catalina.sh` directly must export `JAVA_HOME` itself; going
  through `systemctl` does not, because the unit sets it.

Verified against Tomcat 10.1.59 on JDK 21 — a keystore written by this agent,
read by a real Tomcat, serving the certificate with its chain. See
[agent.md](../agent.md).
