# Postfix

Postfix presents its certificate on port 25 to every other mail server it
exchanges mail with. Expiry of this certificate does not produce an obvious
failure: SMTP between servers uses opportunistic TLS by default, so a sending
server that cannot validate the certificate delivers the message unencrypted
rather than rejecting it. No bounce is generated and no error is recorded at
the receiving end.

The consequence changes if MTA-STS or DANE is in use, or if a partner
organisation enforces TLS. In those cases the same expired certificate causes
delivery failures, typically reported by the sender rather than detected
locally.

## Configuration

```json
{ "name": "mta", "certificate": "mail.example.com", "profile": "postfix" }
```

```
smtpd_tls_cert_file = /etc/certpilot/live/mail.example.com/fullchain.pem
smtpd_tls_key_file  = /etc/certpilot/live/mail.example.com/privkey.pem
```

Postfix has no separate setting for intermediate certificates; they belong in
the same file as the leaf certificate.

The private key is written with mode `0600` and owned by root. The Postfix
master process reads the certificate before `smtpd` drops privileges and enters
its chroot, so the `postfix` user does not require access to the key.

## What the agent does

The agent writes the certificate and key, runs `postfix check`, and runs
`postfix reload`. The reload restarts the `smtpd` processes without stopping
the queue: mail in transit is not lost and the listener remains available.

## Limitations

- **`postfix check` does not validate the certificate.** It verifies file
  ownership, permissions and configuration consistency. A certificate and key
  that are not a matching pair will pass the check and fail at the TLS
  handshake.
- **The agent does not configure submission or SMTPS.** Ports 587 and 465
  normally inherit these settings from `main.cf`, but if `master.cf` overrides
  them for those services, they must be updated separately.
- **The agent does not publish MTA-STS policies or TLSA records.** If DANE is
  in use, the TLSA record must be rolled before the certificate is replaced, or
  delivery will fail.

Last tested against Postfix 3.7.11 (Debian package), over STARTTLS on port 25.
See [agent.md](../agent.md).
