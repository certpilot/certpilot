# Dovecot

Dovecot presents its certificate to every mail client in the organisation, and
mail clients validate it strictly. Unlike a web browser, most mail clients
provide no straightforward way to proceed past a certificate error. An expired
IMAP certificate therefore affects all users simultaneously and is usually
reported as a general mail outage.

Dovecot's configuration syntax for certificate paths differs from other
services and is a common source of error. The value is a file reference, not a
path:

```
ssl_cert = </etc/certpilot/live/mail.example.com/fullchain.pem
```

The `<` character instructs Dovecot to read the file. Without it, Dovecot
treats the path itself as the certificate data and reports an error that
resembles a corrupt certificate.

## Configuration

```json
{ "name": "imap", "certificate": "mail.example.com", "profile": "dovecot" }
```

```
ssl = yes
ssl_cert = </etc/certpilot/live/mail.example.com/fullchain.pem
ssl_key  = </etc/certpilot/live/mail.example.com/privkey.pem
```

## What the agent does

The agent writes the certificate and key, validates the configuration with
`doveconf -n`, and reloads with `doveadm reload`. Existing connections are not
dropped.

## Limitations

- **`doveconf -n` does not open the certificate.** It parses the configuration
  and reports syntax errors, which is what makes it usable as a check. A path
  that does not exist, or a certificate and key that do not match, will pass.
- **Clients continue to use the previous certificate until they reconnect.** A
  client holding an IMAP IDLE connection retains it across a reload, so the new
  certificate is not presented to the entire estate immediately. Confirming a
  rotation therefore requires a new connection rather than an existing one.
- **Postfix and Dovecot are separate destinations**, even where both serve the
  same hostname from the same certificate. Each service is configured and
  reloaded independently.

Last tested against Dovecot 2.3.19.1 (Debian package), on port 993. See
[agent.md](../agent.md).
