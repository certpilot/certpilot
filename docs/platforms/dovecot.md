# Dovecot

This is the certificate that produces support tickets. Every phone, laptop and
desktop mail client in the organisation checks it on every connection, and they
all check it properly — unlike a browser, a mail client has no "proceed anyway"
that most people will find. An expired IMAP certificate is not a degraded
experience; it is several hundred people whose mail stopped working at the same
minute, and none of them know why.

There is also a syntax trap here that costs an afternoon the first time.
Dovecot's setting is not a path — it is a redirection:

```
ssl_cert = </etc/certpilot/live/mail.example.com/fullchain.pem
```

The `<` means "read the file". Without it, Dovecot treats the path as the
certificate itself and fails in a way that reads like a corrupt certificate,
which sends you looking at the certificate.

## What CertPilot does

```bash
certpilot-agent profiles dovecot
```

```json
{ "name": "imap", "certificate": "mail.example.com", "profile": "dovecot" }
```

```
ssl = yes
ssl_cert = </etc/certpilot/live/mail.example.com/fullchain.pem
ssl_key  = </etc/certpilot/live/mail.example.com/privkey.pem
```

`doveconf -n` parses the whole configuration before anything reloads, then
`doveadm reload` picks the new material up without dropping connections.

## What it does not do

- **`doveconf -n` does not open the certificate.** It catches syntax errors,
  which is what makes it usable as a check, and a path that does not exist
  passes it.
- **Clients keep the old certificate until they reconnect.** A mail client
  holding an IMAP IDLE connection keeps it across a reload, so a rotation is
  not visible to the estate immediately. This is normally what you want; it
  does mean "did it work" cannot be answered by asking a client that was
  already connected.
- **Postfix and Dovecot are separate destinations**, even on a host where they
  serve the same name from the same file. Two services, two reloads.

Verified against Dovecot 2.3.19.1 from the Debian package, on port 993. See
[agent.md](../agent.md).
