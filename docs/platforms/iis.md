# Microsoft IIS

IIS does not read a certificate from a file path. It binds one by thumbprint
from the Windows certificate store, and so do Exchange, ADFS, Network Policy
Server and Remote Desktop Services. An agent that writes PEM to a destination on
one of those hosts installs nothing.

The agent therefore imports into the store rather than writing files. A
destination names a `store` instead of `cert_path` and `key_path`, and the two
are mutually exclusive: a destination that names both is refused when the spec
is read.

## Requirements

- Windows, with the agent running elevated. Writing to `LocalMachine\My`
  requires it; running as a service satisfies it.
- The WebAdministration PowerShell module, which is the
  `Web-Scripting-Tools` feature. The binding command imports it.
- **An existing https binding on the site.** The agent re-points a binding; it
  does not create sites or bindings. Creating one means choosing a port, an
  address, a host header and whether SNI is enabled, which are decisions about
  how the machine serves traffic. Add the binding once in IIS Manager with any
  certificate; every renewal after that is handled here.

## Configuration

```json
{
  "name": "iis",
  "certificate": "www.example.com",
  "profile": "iis",
  "verify": "{{ .Certificate }}:443"
}
```

Which fills in:

| Field | Value |
|:---|:---|
| `store` | `LocalMachine\My` |
| `bind` | PowerShell that re-points every https binding on `Default Web Site` |
| `verify` | Not supplied by the profile — see [The check runs afterwards](#the-check-runs-afterwards) |

`certpilot-agent profiles iis` prints the binding command in full.

### The site is `Default Web Site`

That is the name IIS ships with and not the name most estates use. It appears
once, in the binding command, which is overridden by writing a `bind` on the
destination:

```json
{
  "name": "iis",
  "certificate": "www.example.com",
  "store": "LocalMachine\\My",
  "verify": "www.example.com:443",
  "bind": [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "-NoProfile", "-NonInteractive", "-Command",
    "$ErrorActionPreference = 'Stop'; Import-Module WebAdministration; $b = @(Get-WebBinding -Name 'Intranet' -Protocol https); if ($b.Count -eq 0) { throw 'no https binding' }; foreach ($x in $b) { $x.AddSslCertificate('{{ .Thumbprint }}', 'My') }"
  ]
}
```

`{{ .Thumbprint }}` is substituted with the thumbprint of the certificate just
imported. A `bind` that does not contain it is refused: it would run, exit
successfully, and re-point nothing, leaving the host serving the previous
certificate until it expired.

**Keep `$ErrorActionPreference = 'Stop'`.** Without it PowerShell writes an
error, continues, and exits 0. The agent would record a binding that never
happened.

### The check runs afterwards

Every other platform runs a configuration check before the reload. Windows has
no equivalent: nothing will report in advance whether a binding that has not
been made yet will work.

`verify` is what is offered instead. After binding, the agent completes a TLS
handshake against the endpoint and compares the thumbprint of the certificate
served with the one just installed. A mismatch, or a connection that cannot be
made, rolls the binding back.

The handshake does not check whether the certificate is trusted. The question
being asked is whether this specific certificate is the one on the wire; a
private CA would fail a trust check while everything was correct.

The profile does not supply a `verify`, deliberately. The port is a property of
the site, and a default that guessed wrong would roll back a working
certificate on every renewal. A destination without `verify` has no check at
all.

## What the agent does

1. Reads `LocalMachine\My` for a certificate named `CertPilot: <destination>`,
   which is the one it installed last time. If the store cannot be read, it
   stops before importing anything: without that value there is nothing to roll
   back to.
2. Imports the certificate, its chain and the private key, as PKCS#12 built in
   memory. Nothing is written to disk.
3. Runs `bind` with the new thumbprint.
4. Runs `reload`, if the destination declares one. IIS does not need one.
5. Connects to `verify`, if set, and confirms the certificate being served.
6. Names the new certificate `CertPilot: <destination>` and removes the one it
   replaced.

If any step after the import fails, the binding is returned to the previous
thumbprint and the imported certificate is removed — in that order. See
[Rollback](#rollback).

### Where each certificate goes

| | Store |
|:---|:---|
| The issued certificate | The store the destination names, normally `LocalMachine\My` |
| Intermediates | `LocalMachine\CA` |
| A self-signed root | Not imported |

Intermediates go to `CA` because schannel builds the chain it presents from
that store rather than from whatever was imported alongside the leaf. An
intermediate left in `My` is an intermediate never sent, which most browsers
accept from a cache and no fresh client does.

A self-signed root in the chain is imported nowhere. The store that would make
it work is `Root`, and writing there makes a certificate authority trusted by
every program on the machine. That is a decision for whoever administers the
host, not a side effect of a renewal. The agent logs which certificates it
skipped and why.

### The friendly name

Every certificate the agent imports is given the friendly name
`CertPilot: <destination>` — the Friendly Name column in `certlm.msc`. It is
how a renewal finds the certificate it is replacing, and therefore the only
thing a rollback has to return to.

Renaming one there means the agent no longer recognises it. It will leave it in
the store rather than remove something it is no longer sure about, and the
renewal that follows will behave as a first install.

### The private key

Imported non-exportable, through CNG. The key was generated on this host and
CertPilot cannot produce it; marking it exportable would make that a
convention rather than a property.

An Exchange DAG or an ADFS farm that requires the same key on several nodes
cannot use this. Enrol each node and give each its own certificate.

Removing a certificate from a store does not remove its private key. The agent
deletes the key with the certificate, because otherwise each renewal would
leave an unreferenced private key in the storage provider for the life of the
machine.

## Rollback

A file destination rolls back by writing back the bytes it captured. Importing
into a store displaces nothing, so there is nothing to capture; what changes is
which thumbprint the binding names.

When a bind, a reload or a verify fails:

1. **The binding is returned to the previous thumbprint first.** Until that
   succeeds the running service is using the certificate that just failed.
2. **The imported certificate is removed second.** Removing a certificate that
   a binding still names turns a service serving the wrong certificate into one
   serving nothing, which is not recoverable by trying again.
3. **If the binding cannot be returned, the imported certificate is left in
   place** and the failure says so. This is the case that needs a person.

Two cases have no rollback and are reported rather than guessed at:

- **A failure before the binding was changed.** Nothing was re-pointed, so the
  imported certificate is removed and the host is serving what it was before.
- **The first install on a host.** There is no earlier certificate of the
  agent's to return to. The certificate stays where it is, because a binding
  naming a certificate that is not there serves nothing at all.

## Other consumers of the store

Exchange, ADFS, Network Policy Server and Remote Desktop Services import from
the same store and differ only in the binding step. Each is this profile with a
different `bind`. Exchange, for example:

```json
"bind": [
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "-NoProfile", "-NonInteractive", "-Command",
  "$ErrorActionPreference = 'Stop'; Enable-ExchangeCertificate -Thumbprint '{{ .Thumbprint }}' -Services IIS,SMTP -Force"
]
```

**None of these four has been run by this project.** They are documented as a
shape to copy, not as supported platforms, and are listed the same way in
[status.md](../status.md).

## Limitations

- **No configuration check.** See [The check runs
  afterwards](#the-check-runs-afterwards).
- **`owner`, `group`, `cert_mode` and `key_mode` do not apply.** A store
  destination writes no file. They are refused when the spec is read rather
  than accepted and ignored.
- **`format`, `keystore_password` and `keystore_alias` do not apply.** The
  material is handed to Windows as PKCS#12 in memory, protected by a password
  the agent generates and discards. A certificate in the store is found by
  thumbprint.
- **The site name is a default.** `Default Web Site` is correct for a fresh
  installation and for very little else.
- **Bindings are re-pointed, not created.** See
  [Requirements](#requirements).
- **`CurrentUser\My` is accepted and is almost never what is wanted.** A
  certificate imported there is invisible to every service on the machine.

## How this platform is tested

The Linux platforms are tested by `make verify-profiles`, which runs the
service in a container. IIS cannot run in one, so it is tested in CI on a
Windows runner instead, to the same standard:

1. IIS is installed and `Default Web Site` is given an https binding with **no**
   certificate on it.
2. A certificate is installed through the agent's own installer, using the
   profile as shipped. A TLS handshake from outside confirms IIS is serving it.
3. A second certificate is installed. The handshake confirms the binding moved,
   and the store confirms the first certificate was removed.
4. A third is installed with a `verify` that cannot succeed. The handshake
   confirms IIS is serving the second certificate again, and the store confirms
   the third was removed.

The job also checks the version recorded in the profile against the version of
IIS on the runner, so the claim cannot become one about a machine nobody used.

Last tested against IIS 10.0 on Windows Server 2022. See
[agent.md](../agent.md).
