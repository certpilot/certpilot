# Caddy

Caddy is the one platform here that normally does this job itself, and does it
well. It gets its own certificates over ACME, renews them, and needs nothing
from anybody. The reason this page exists is the estate where it must not:
where the CA is internal, or the name is not publicly resolvable, or policy
says certificates come from one place and that place is not Let's Encrypt.

In that estate Caddy fails in two ways that both look like success.

**It will go and get its own anyway.** Unless `auto_https off` is set, the
certificate you installed is on disk, correct, and never served — Caddy has its
own and prefers it. Nothing logs an error, because nothing is wrong from
Caddy's point of view.

**`caddy reload` does nothing after a rotation.** Caddy compares the
configuration it is handed against the one it is running, and a rotated
certificate does not change the Caddyfile. So it logs `"config is unchanged"`,
does no work, and **exits 0** — the install reports success, the file on disk is
new, and the certificate on the wire is the old one until something restarts
the process.

## What CertPilot does

The profile ships `--force` on the reload, which is the entire fix for the
second problem, and this page is the fix for the first.

```bash
certpilot-agent profiles caddy
```

```json
{ "name": "web", "certificate": "www.example.com", "profile": "caddy" }
```

```caddyfile
{
    auto_https off
}

https://www.example.com {
    tls /etc/certpilot/live/www.example.com/fullchain.pem /etc/certpilot/live/www.example.com/privkey.pem
}
```

`caddy validate` runs before the reload; the previous files go back if it
fails.

## What it does not do

- **It cannot reload through a disabled admin API.** `caddy reload` talks to
  `localhost:2019`. With `admin off`, nothing can reload Caddy in place and a
  restart is the only option.
- **It does not turn off `auto_https` for you.** That is a line in your
  Caddyfile, and a tool that edited it would be a tool that could silently stop
  a working ACME setup.
- **If Caddy is managing its own certificates, do not install to it.** Two
  systems renewing the same thing is worse than either alone.

Verified against Caddy 2.11.4. See [agent.md](../agent.md).
