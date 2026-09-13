# nginx

nginx serves whatever certificate is on disk when it last started. When a
certificate renews, nothing happens — nginx does not watch the file and has no
opinion about the date inside it. Somebody has to write the new files and
reload the service, on every host, and the way that fails is silent: the
renewal succeeded, the file on disk is current, and the process is still
serving what it read in March.

The other half is the chain. `ssl_certificate` is the only place nginx looks
for intermediates, so a server block naming a leaf-only file serves a leaf
alone. That works perfectly on the machine you are testing from, because its
cache already has the intermediate, and fails for a client that has never seen
your CA before.

## What CertPilot does

The agent holds the certificate, writes it where nginx reads it, runs
`nginx -t` **before** anything is told to pick it up, reloads, and puts the old
files back if the reload fails. A renewal deploys itself; nobody is in the
loop.

```bash
certpilot-agent profiles nginx    # what it will write, and where
```

```json
{ "name": "web", "certificate": "www.example.com", "profile": "nginx" }
```

```nginx
ssl_certificate     /etc/certpilot/live/www.example.com/fullchain.pem;
ssl_certificate_key /etc/certpilot/live/www.example.com/privkey.pem;
```

`fullchain.pem`, not `cert.pem`. That is the whole of the chain problem above,
and it is why the profile writes both files under names you may already
recognise from certbot.

Reload is `nginx -s reload`, not `systemctl reload nginx` — the same operation
the unit performs (Debian's `ExecReload` is `nginx … -s reload`) and portable
to a host whose init is something else. nginx starts new workers and lets the old ones finish, so no
connection is dropped and no request sees a half-written file.

## What it does not do

- **It does not edit nginx.conf.** The paths above are yours to write once. The
  agent writes certificates, not configuration.
- **It does not know which server blocks exist.** One destination is one
  certificate at one path. A host serving forty names from forty certificates
  needs forty destinations, or one certificate with forty SANs.
- **`nginx -t` is the best check of the nine.** It catches a missing
  certificate file *and* a certificate and key that are not a pair, which
  Apache's own check does not. That is a reason to be less nervous about this
  platform than about the ones with no check at all.
- **It cannot tell you the reload worked in the sense you mean.** It can tell
  you `nginx -t` passed and the reload command exited 0. Whether the right
  server block picked it up is a question about your configuration —
  [post-renewal verification](../deployment.md) re-probes the endpoint and
  answers it from outside.

Verified against nginx 1.27.5. The whole story is in [agent.md](../agent.md).
