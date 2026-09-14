# Apache Tomcat

Java applications read certificates from a keystore — a single file containing
the certificate, its chain and the private key, protected by a password that
also appears in the server configuration. They do not read PEM files.

This difference is why Java deployments are often excluded from certificate
automation: the certificate arrives as PEM and must be converted with
`openssl pkcs12 -export` or `keytool` before use, with the correct alias, chain
order and password. The agent performs this conversion, writing the keystore
directly from the private key generated on the host.

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
  requiring JKS can convert with
  `keytool -importkeystore -srckeystore keystore.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS`.

Last tested against Apache Tomcat 10.1.59 on JDK 21. See
[agent.md](../agent.md).
