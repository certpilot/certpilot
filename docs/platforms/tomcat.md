# Apache Tomcat

Java applications read certificates from a keystore — a single file containing
the certificate, its chain and the private key, protected by a password that
also appears in the server configuration. They do not read PEM files.

This difference is why Java deployments are often excluded from certificate
automation: the certificate arrives as PEM and must be converted with
`openssl pkcs12 -export` or `keytool` before use, with the correct alias, chain
order and password. The agent performs this conversion, writing the keystore
directly from the private key generated on the host. Its one gap is the entry
alias, described under [Limitations](#limitations).

## Configuration

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

`key_path` is omitted. The private key is contained in the keystore, and
specifying a second path would write it to disk unencrypted as well.

**A keystore password is required and has no default.** The value must match
the one configured in `server.xml`. Supply it with `keystore_password`, or with
`keystore_password_file` pointing at a file that already contains it. The
password does not protect the key from anyone with access to the host — the key
was generated there — but the keystore cannot be opened unless the two values
match.

## What the agent does

The agent writes the keystore, restarts Tomcat, and restores the previous
keystore if the restart fails. File mode, ownership and rollback behave
identically to PEM destinations.

## Limitations

- **Tomcat is restarted, not reloaded.** Tomcat re-reads a keystore only when
  the connector is rebuilt, and there is no supported command to trigger this
  in place. This is the only platform in this section whose certificate
  rotation interrupts connections. Schedule renewals accordingly.
- **No configuration check is available.** Tomcat provides no equivalent of
  `nginx -t`.
- **The keystore entry has no alias.** The agent writes the entry without a
  `friendlyName` attribute, so Java names it `1`. Omit `certificateKeyAlias`
  from the `<Certificate>` element, as the example above does, and Tomcat uses
  the first entry. Setting it to anything else — `tomcat` is the conventional
  value, and is what `keytool -genkeypair -alias tomcat` produces — leaves the
  connector unable to find the key, and **Tomcat still reports a successful
  startup**. With no configuration check for this platform, nothing catches it
  until post-renewal verification reports the endpoint is not serving the new
  certificate. Tracked in
  [issue #65](https://github.com/certpilot/certpilot/issues/65).
- **Verify the service unit name.** The profile specifies `tomcat10`, which is
  correct for Debian 12. Installations using `tomcat9`, a Red Hat package, or a
  Tomcat installed from the upstream archive require a different command.
- **Check and reload commands run with a minimal environment.** The agent sets
  `PATH` and nothing else, so that commands defined in the destination file
  cannot read the agent's own environment variables. `catalina.sh` requires
  `JAVA_HOME` and will not infer it, so a reload command invoking it directly
  must set `JAVA_HOME` itself. Invoking `systemctl` avoids this, as the unit
  file supplies it.
- **JKS keystores are not written.** PKCS#12 has been the default JVM keystore
  format since Java 9 and is read natively by all later versions. Deployments
  that still require JKS can convert the file after the agent writes it — see
  [Converting to JKS](#converting-to-jks) below.

## Converting to JKS

The agent does not write JKS, and the JDK reports the format as deprecated on
every read and write:

> The JKS keystore uses a proprietary format. It is recommended to migrate to
> PKCS12 which is an industry standard format.

An application that still requires JKS — one on Java 8, or with a keystore type
fixed in configuration nobody can change — can convert the file by making the
conversion the destination's check command:

```json
{
  "name": "tomcat",
  "certificate": "app.example.com",
  "profile": "tomcat",
  "keystore_password_file": "/etc/certpilot/keystore-password",
  "check": [
    "/usr/bin/keytool", "-importkeystore", "-noprompt",
    "-srckeystore", "/etc/certpilot/live/app.example.com/keystore.p12",
    "-srcstoretype", "PKCS12",
    "-srcstorepass:file", "/etc/certpilot/keystore-password",
    "-srcalias", "1",
    "-destalias", "tomcat",
    "-destkeystore", "/etc/certpilot/live/app.example.com/keystore.jks",
    "-deststoretype", "JKS",
    "-deststorepass:file", "/etc/certpilot/keystore-password"
  ]
}
```

Four details make this work:

- **The check runs after the keystore is written and before the service is
  reloaded**, so the JKS file is always converted from the certificate that is
  about to be loaded. A failed conversion stops the reload and restores the
  previous keystore, which is the same protection every other destination has.
- **`-srcalias 1`** is required. The agent's PKCS#12 entry carries no alias, so
  Java names it `1`. `-destalias` then sets the name the configuration expects.
- **`-noprompt` overwrites the existing entry** on every renewal. Without it
  `keytool` asks whether to replace the alias and the conversion stalls.
- **`-storepass:file` keeps the password out of the process table** and accepts
  the same file `keystore_password_file` points at. Both the agent and `keytool`
  ignore a trailing newline, so one file serves both.

The configuration then names the JKS file and the alias:

```xml
<Certificate certificateKeystoreFile="/etc/certpilot/live/app.example.com/keystore.jks"
             certificateKeystorePassword="..."
             certificateKeystoreType="JKS"
             certificateKeyAlias="tomcat" />
```

Last tested against Apache Tomcat 10.1.59 on JDK 21. See
[agent.md](../agent.md).
