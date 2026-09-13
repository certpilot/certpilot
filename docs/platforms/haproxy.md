# HAProxy

HAProxy wants something nothing else wants: the certificate, its chain and the
private key concatenated into **one file**, in that order. That single
requirement is why HAProxy hosts are where this project keeps finding private
keys at mode 0644 — somebody assembled the file by hand with `cat`, and the
mode came from whichever fragment was copied last.

And like every other server here, it reads that file when it starts. A renewal
on disk is not a renewal in the process.

## What CertPilot does

The agent recognises that layout as a first-class thing rather than an
accident. Setting `cert_path` and `key_path` to the same file makes the
installer write certificate, chain and key in that order, **at the key's mode**
— so the combined file is 0640, not 0644, without anybody having to remember.

```bash
certpilot-agent profiles haproxy
```

```json
{ "name": "edge", "certificate": "www.example.com", "profile": "haproxy" }
```

```
bind :443 ssl crt /etc/certpilot/live/www.example.com/haproxy.pem
```

`haproxy -c -f /etc/haproxy/haproxy.cfg` runs before anything reloads, and the
previous file goes back if the reload fails.

## What it does not do

- **The reload is `systemctl reload haproxy`**, and this is the one profile
  where that is not a shortcut. HAProxy has no in-process reload: the seamless
  one hands the listening sockets to a new process, and on a packaged host
  systemd is what holds them. On a host without systemd, replace that line with
  whatever starts HAProxy. What systemd actually sends is `USR2` to the master
  process.
- **Check the `-f` path.** The profile names `/etc/haproxy/haproxy.cfg`. If
  this host reads a different file, validating the wrong one is worse than not
  validating at all — change it.
- **It does not manage `crt-list`.** A frontend selecting among many
  certificates by SNI needs a destination per certificate; the list itself is
  yours.

Verified against HAProxy 2.6.12 from the Debian package. See
[agent.md](../agent.md).
