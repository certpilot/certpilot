# Windows and IIS

A certificate that reaches an IIS site and re-points its binding on every renewal,
without anybody opening IIS Manager.

IIS does not read certificate files. It binds a certificate by thumbprint out of the
Windows certificate store, and so do Exchange, ADFS, Network Policy Server and Remote
Desktop Services. An agent that writes PEM to one of those hosts installs nothing. So
this walkthrough differs from [Vault to nginx](vault-nginx.md) at the last step and only
there: same CA, same enrolment, same grant, entirely different destination.

**Read first:**
[platforms/iis.md](../platforms/iis.md).
It is the reference for what follows, and it is detailed — the store layout, the
friendly name, the rollback order. This page is the sequence; that page is the
behaviour.

## What was verified here, and what was not

> **There is no Windows host in the environment this was written in, so the Windows half
> of this walkthrough was not run.**
>
> Verified off Windows:
> - the `iis` profile's contents, including the binding command it supplies
> - the agent's refusal to install a Windows destination on a machine that is not
>   Windows
>
> **Not verified:** the PKCS#12 import, the certificate store layout, the binding, the
> `verify` handshake, the rollback, and the friendly-name bookkeeping. Every one of
> those is described from
> [platforms/iis.md](../platforms/iis.md)
> and the agent's source, not from having watched it happen.
>
> Treat this page as a plan to check against your own host, not as a transcript. The
> two pages either side of it are transcripts.

What the guard looks like, which is the part that was run:

```
error: /tmp/iis.json: destination "iis": profile "iis" describes a Windows service and
installs into the Windows certificate store, and this host is linux. There is no
certificate store here for it to install into
```

A destination naming a `store` rather than a profile is refused the same way. So a
Linux host cannot be misconfigured into pretending to be Windows, which is the one
Windows-specific failure reachable from anywhere else.

## Prerequisites

Beyond a running CertPilot and a CA account — [Vault](vault-nginx.md#step-2-connect-the-ca)
or [ACME](acme-nginx.md#step-2-connect-the-ca), either works:

| | |
|:--|:--|
| Windows, agent running **elevated** | Writing to `LocalMachine\My` requires it; running as a service satisfies it |
| The WebAdministration module | The `Web-Scripting-Tools` feature. The binding command imports it |
| **An existing https binding on the site** | The agent re-points a binding. It does not create sites or bindings |
| The site's name | `Default Web Site` unless you say otherwise |
| The port the site serves on | Needed for `verify`, and not supplied by the profile |

Admin on your CertPilot account for the template and the enrolment token; operator for
the rest.

> **The https binding is the prerequisite people miss.** Creating one means choosing a
> port, an address, a host header and whether SNI is on — decisions about how the
> machine serves traffic, not about certificates. Add it once in IIS Manager with any
> certificate, self-signed included. Every renewal after that is handled here. Without
> it the binding command throws `Default Web Site has no https binding to re-point` and
> the install fails, having changed nothing.

## Steps 1 to 5: everything before the destination

Unchanged from the Vault walkthrough. The CA does not know or care that the host is
Windows:

- [Start the gateway and register it](vault-nginx.md#step-1-start-the-gateway-and-tell-the-core-about-it)
- [Connect the CA](vault-nginx.md#step-2-connect-the-ca)
- [Create a template](vault-nginx.md#step-3-a-template-to-issue-against)
- [Enrol the host](vault-nginx.md#step-4-enrol-the-host) — `certpilot-agent.exe enrol`, in an
  elevated shell
- [Grant it a name](vault-nginx.md#step-5-grant-it-a-name)

The state directory defaults differ on Windows; see
[agent.md](../agent.md#windows).

## Step 6: ask for the certificate

```powershell
certpilot-agent.exe request --name www.example.com --state-dir C:\ProgramData\CertPilot
```

The key is generated on the host, through CNG, and imported **non-exportable** at the
next step. CertPilot never has it.

> An Exchange DAG or an ADFS farm needing the same key on several nodes **cannot use
> this**. Enrol each node and give each its own certificate.

## Step 7: declare the destination

```json
{
  "destinations": [
    {
      "name": "iis",
      "certificate": "www.example.com",
      "profile": "iis",
      "verify": "{{ .Certificate }}:443"
    }
  ]
}
```

`certpilot-agent profiles iis` prints what that expands to:

```
store   LocalMachine\My
bind    powershell.exe -NoProfile -NonInteractive -Command
        $ErrorActionPreference = 'Stop'; Import-Module WebAdministration;
        $site = 'Default Web Site';
        $bindings = @(Get-WebBinding -Name $site -Protocol https);
        if ($bindings.Count -eq 0) { throw "$site has no https binding to re-point" };
        foreach ($b in $bindings) {
          if (([int]$b.sslFlags -band 1) -eq 1) {
            $b.AddSslCertificateByHostHeader('{{ .Thumbprint }}', 'My')
          } else { $b.AddSslCertificate('{{ .Thumbprint }}', 'My') } }
verify  — none unless you set one
```

### Set `verify` yourself

**The profile supplies no `verify`, and a destination without one has no check at all.**

Every other platform runs a configuration check *before* the reload — `nginx -t` and its
equivalents. Windows has no such thing: nothing will tell you in advance whether a
binding that has not been made yet will work. `verify` is what is offered instead. After
binding, the agent completes a TLS handshake against the endpoint and compares the
thumbprint served with the one just installed. A mismatch, or a connection it cannot
make, rolls the binding back.

The profile does not guess the port, deliberately: a default that guessed wrong would
roll back a working certificate on every renewal.

The handshake does not check trust. The question is whether *this* certificate is the
one on the wire — a private CA would fail a trust check while everything was correct.

### If your site is not `Default Web Site`

Override `bind` in full. Two rules it must obey:

```json
"bind": [
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "-NoProfile", "-NonInteractive", "-Command",
  "$ErrorActionPreference = 'Stop'; Import-Module WebAdministration; $b = @(Get-WebBinding -Name 'Intranet' -Protocol https); if ($b.Count -eq 0) { throw 'no https binding' }; foreach ($x in $b) { $x.AddSslCertificate('{{ .Thumbprint }}', 'My') }"
]
```

1. **It must contain `{{ .Thumbprint }}`.** A `bind` without it is refused before it
   runs — it would exit successfully, re-point nothing, and leave the host serving the
   previous certificate until it expired.
2. **Keep `$ErrorActionPreference = 'Stop'`.** Without it PowerShell writes an error,
   carries on, and exits 0. The agent would record a binding that never happened.

## Step 8: install

```powershell
certpilot-agent.exe run --once --state-dir C:\ProgramData\CertPilot `
  --installs C:\ProgramData\CertPilot\installs.json
```

What the agent does, in order — the detail is in
[platforms/iis.md](../platforms/iis.md#what-the-agent-does):

1. Reads `LocalMachine\My` for the certificate named `CertPilot: iis` — the one it
   installed last time, and the only thing a rollback has to return to. If the store
   cannot be read it stops before importing anything.
2. Imports the certificate, chain and key as PKCS#12 built in memory. Nothing touches
   disk.
3. Runs `bind` with the new thumbprint.
4. Connects to `verify` and confirms what is being served.
5. Names the new certificate `CertPilot: iis` and removes the one it replaced.

**There is no step 8 equivalent of "point nginx at it".** The binding already exists;
the agent changed which certificate it names. Nothing else has to be edited.

## Step 9: check it

```powershell
Get-ChildItem Cert:\LocalMachine\My |
  Where-Object FriendlyName -like 'CertPilot:*' |
  Format-List Subject, Thumbprint, FriendlyName, NotAfter
```

```powershell
Get-WebBinding -Name 'Default Web Site' -Protocol https |
  ForEach-Object { $_.certificateHash }
```

The thumbprint in the second must be the one in the first. Then, from CertPilot:

```bash
curl -b "$JAR" localhost:8080/api/v1/agent-installations
```

The `fingerprint_sha256` there is the same value the thumbprint is, lower-cased. A
mismatch means CertPilot and the host disagree about which certificate this host is
serving, which every other status field will happily report as fine.

## When it fails

The rollback order is the thing worth knowing before it happens:

1. **The binding is returned to the previous thumbprint first.** Until that succeeds the
   service is using the certificate that just failed.
2. **The imported certificate is removed second.** Doing it the other way turns a
   service serving the wrong certificate into one serving nothing, which trying again
   does not fix.
3. **If the binding cannot be returned, the imported certificate is left in place**, and
   the failure says so. This is the case that needs a person — most often because the
   previous certificate was removed from the store by hand.

Renaming a `CertPilot: <destination>` certificate in `certlm.msc` means the agent no
longer recognises it. It will leave it alone rather than delete something it is unsure
about, and the next renewal behaves as a first install.

See [a renewal or deployment failed](failed-renewal.md) for reading the refusal from the
CertPilot side.

## Limitations

- **Nothing on this page was run against Windows.** See the top.
- **The agent does not create sites or bindings.** One https binding, added once, by a
  person.
- **A self-signed root in the chain is imported nowhere.** Trusting a CA machine-wide is
  an administrator's decision, not a side effect of a renewal. The agent logs what it
  skipped.
- **Intermediates go to `LocalMachine\CA`**, because schannel builds the chain it
  presents from there. An intermediate left in `My` is an intermediate never sent.
- **Keys are imported non-exportable**, so shared-key deployments are out.
- **`verify` does not check trust**, only identity.
