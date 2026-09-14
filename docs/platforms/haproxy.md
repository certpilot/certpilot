# HAProxy

HAProxy requires the certificate, its chain and the private key to be
concatenated into a single file, in that order. This differs from every other
platform in this section and is a common source of error: files assembled
manually with `cat` frequently inherit the permissions of the last file copied,
which results in a private key readable by any account on the host.

Like other services here, HAProxy reads this file at startup. A renewed
certificate on disk has no effect until HAProxy is reloaded.

## Configuration

```json
{ "name": "edge", "certificate": "www.example.com", "profile": "haproxy" }
```

```
bind :443 ssl crt /etc/certpilot/live/www.example.com/haproxy.pem
```

The profile sets `cert_path` and `key_path` to the same file. The agent
recognises this as the combined layout, writes the certificate, chain and key
in the required order, and applies the private key's file mode (`0640`) to the
combined file rather than the certificate's.

## What the agent does

The agent writes the combined file, validates the configuration with
`haproxy -c -f /etc/haproxy/haproxy.cfg`, reloads the service, and restores the
previous file if the reload fails.

## Limitations

- **The reload command is `systemctl reload haproxy`.** HAProxy has no
  in-process reload: a seamless reload transfers the listening sockets to a new
  process, and on a packaged host systemd holds those sockets. Debian's unit
  file implements this by sending `SIGUSR2` to the master process. On a host
  that does not use systemd, replace this command with the equivalent for that
  service manager.
- **Verify the configuration path in the check command.** The profile specifies
  `/etc/haproxy/haproxy.cfg`. If this host reads a different file, update the
  destination accordingly — validating a file the service does not use provides
  no protection.
- **The agent does not manage `crt-list` files.** A frontend selecting among
  multiple certificates by SNI requires one destination per certificate; the
  list itself is maintained separately.

Last tested against HAProxy 2.6.12 (Debian package). See
[agent.md](../agent.md).
