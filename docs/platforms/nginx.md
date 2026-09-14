# nginx

nginx reads its certificate files when it starts and when it is reloaded. It
does not monitor those files, so a renewed certificate on disk has no effect
until nginx is told to reload. Without automation, this step is performed
manually on each host, and a missed reload is not visible until a client
reports a certificate error.

## Configuration

Declare the destination in `/etc/certpilot/installs.json`:

```json
{ "name": "web", "certificate": "www.example.com", "profile": "nginx" }
```

Point nginx at the installed files:

```nginx
ssl_certificate     /etc/certpilot/live/www.example.com/fullchain.pem;
ssl_certificate_key /etc/certpilot/live/www.example.com/privkey.pem;
```

Use `fullchain.pem`, not `cert.pem`. `ssl_certificate` is the only location
nginx reads intermediate certificates from, so a configuration pointing at
`cert.pem` will serve the leaf certificate alone. Clients that have already
cached the intermediate will connect successfully; clients that have not will
fail to verify the chain.

Run `certpilot-agent profiles nginx` to see the full set of values the profile
supplies.

## What the agent does

On each renewal the agent writes the certificate and key, runs `nginx -t` to
validate the configuration, reloads nginx, and restores the previous files if
the reload fails.

The reload command is `nginx -s reload` rather than `systemctl reload nginx`.
Both perform the same operation — the Debian unit file's `ExecReload` invokes
`nginx -s reload` — but the direct command is identical across distributions,
whereas unit names are not. nginx starts new worker processes and allows
existing ones to finish, so no connection is dropped.

The private key is written with mode `0640` and owned by root. nginx's master
process reads the key before worker processes drop privileges, so the worker
user does not require access to it.

## Limitations

- **The agent does not modify `nginx.conf`.** The directives above are set once
  by an administrator. The agent writes certificate files only.
- **One destination installs one certificate to one path.** A host serving
  multiple names from separate certificates requires one destination for each,
  or a single certificate with multiple SANs.
- **`nginx -t` detects more faults than most equivalent checks**, including a
  missing certificate file and a certificate and key that do not match. See
  [Configuration check coverage](README.md#configuration-check-coverage).
- **Confirming that the correct server block is using the certificate** is
  outside the agent's scope. [Post-renewal
  verification](../deployment.md) reconnects to the endpoint and reports the
  certificate being served.

Last tested against nginx 1.27.5. See [agent.md](../agent.md) for the full
destination format.
