# Postfix

Port 25 is where your mail server presents a certificate to every other mail
server on the internet, and it is the certificate nobody is tracking. The
reason is that SMTP between servers is *opportunistic* by default: if the
certificate has expired, or the chain is incomplete, the sending server shrugs
and delivers the mail anyway, in the clear. Nothing bounces. Nothing is logged
anywhere you are looking. The only signal is that your mail quietly stopped
being encrypted in transit.

That changes the moment anybody publishes MTA-STS or DANE, or a partner
enforces TLS on their side — then the same expired certificate is a delivery
failure, and it arrives as "we stopped receiving your email" rather than as an
alert.

## What CertPilot does

Treats it like any other certificate: inventoried, monitored, renewed, and
installed where Postfix reads it.

```bash
certpilot-agent profiles postfix
```

```json
{ "name": "mta", "certificate": "mail.example.com", "profile": "postfix" }
```

```
smtpd_tls_cert_file = /etc/certpilot/live/mail.example.com/fullchain.pem
smtpd_tls_key_file  = /etc/certpilot/live/mail.example.com/privkey.pem
```

`postfix check` runs first, then `postfix reload`, which restarts the smtpd
processes without stopping the queue — mail in flight is not lost and the
listener does not drop.

The key stays `0600` and root-owned. Postfix runs smtpd chrooted and
unprivileged, but the master reads the certificate before dropping privileges,
so it does not need to be readable by the `postfix` user.

## What it does not do

- **`postfix check` does not check the certificate.** It validates file
  ownership, permissions and configuration consistency. A certificate and key
  that are not a pair pass it and fail the handshake.
- **It does not configure submission or smtps.** Ports 587 and 465 in
  `master.cf` usually inherit these settings, but if yours override them, they
  are separate lines.
- **It does not publish MTA-STS or TLSA records.** Those are DNS, and a
  certificate rotation that ignores a pinned TLSA record is an outage — if you
  use DANE, roll the record first.

Verified against Postfix 3.7.11 from the Debian package, over STARTTLS on port
25. See [agent.md](../agent.md).
