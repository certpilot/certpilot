# Caddy

Caddy obtains and renews its own certificates over ACME by default, and in most
deployments requires no external certificate management. This page applies to
deployments where that is not appropriate: an internal certificate authority, a
name that is not publicly resolvable, or a policy requiring all certificates to
be issued from one source.

Two behaviours require attention in that configuration.

**Caddy will obtain its own certificate unless told not to.** With
`auto_https` at its default setting, the installed certificate is present on
disk but never served, because Caddy prefers the one it obtained itself. No
error is logged, as this is normal operation from Caddy's perspective.

**`caddy reload` does not reload certificates when the configuration is
unchanged.** Caddy compares the submitted configuration against the running
one. A renewed certificate does not alter the Caddyfile, so Caddy logs
`config is unchanged`, takes no action, and exits with status 0. The
installation is reported as successful while the previously loaded certificate
remains in use.

## Configuration

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

The `tls` directive takes a certificate file and a key file. The certificate
file must contain the intermediates, so reference `fullchain.pem` rather than
`cert.pem`.

## What the agent does

The agent writes the certificate and key, runs `caddy validate`, reloads with
`caddy reload --force`, and restores the previous files if the reload fails.

The `--force` flag addresses the second behaviour described above. Without it,
certificate rotation has no effect.

## Limitations

- **The reload requires the admin API.** `caddy reload` connects to
  `localhost:2019`. If the admin endpoint is disabled, Caddy cannot be reloaded
  in place and a restart is required.
- **The agent does not modify the Caddyfile.** `auto_https off` must be set by
  an administrator.
- **Do not install to Caddy if it is managing its own certificates.** Two
  systems renewing the same certificate is less reliable than either alone.

Last tested against Caddy 2.11.4. See [agent.md](../agent.md).
