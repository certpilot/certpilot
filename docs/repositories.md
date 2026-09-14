# Repositories

CertPilot is several repositories rather than one. This page says what they are
called, why, and what keeps them working together now that a single build no
longer does.

## The standard

| Repository | Holds |
|:---|:---|
| `certpilot` | The core, the migrations, and the frontend |
| `certpilot-docs` | The documentation site |
| `certpilot-gateway-sdk` | The provider contract, published, plus the conformance probe |
| `certpilot-agent-sdk` | The agent contract, published |
| `certpilot-gateway-<ca>` | One per certificate authority — `-acme`, `-vault`, `-selfsigned` |
| `cert-pilot-landing` | The public site. Spelled differently on purpose — see below |

Two rules, and the first is the one that matters.

**`certpilot-gateway-` is a load-bearing prefix.** It is what makes a gateway
recognisable as one in a GitHub search, and what lets this project point at
gateways it did not write without appearing to vouch for them. A gateway named
anything else is a gateway nobody finds.

**No hyphen inside the word.** It is `certpilot`, not `cert-pilot`. The Go module
paths, the container images and the organisation all spell it one way, and a
second spelling is a thing every future reader has to check rather than know.

### The one exception, and why it stays

`cert-pilot-landing` breaks the second rule and is not going to be renamed.

It is the repository Vercel builds the public site from, and the connection is
to that repository under that owner. Renaming it, or moving it into the
organisation, means reconnecting the project and reattaching the production
domain — a live marketing site taken down to make a name tidier.

The rule it breaks is a readability rule. Nothing resolves this name: no Go
module path imports it, no container image is built from it, and no gateway
search depends on it. The prefix rule above is the one with consequences, and
this repository is not a gateway.

So it is recorded here rather than left as an inconsistency somebody
rediscovers, files, and has to reason about again from the start. If the site
ever moves off Vercel, rename it then, when the cost is a redirect rather than
an outage.

## Checkouts are siblings, not nested

```
~/src/
  certpilot/
  certpilot-docs/
  certpilot-gateway-acme/
  certpilot-gateway-sdk/
```

Not a matter of taste: `go.work` and every `replace` directive in this tree
resolve by relative path, so `../pkg` has to be a sibling. Nesting one checkout
inside another produces module resolution errors that read as though the code is
wrong.

## What holds it together

Splitting a repository trades one place where breakage is caught for several
where it is discovered. Three things are in place so that trade is not simply
lost.

**The core builds against released SDKs.** `core/go.mod` requires
`certpilot-gateway-sdk` and `certpilot-agent-sdk` by version, with no `replace`
pointing at a local path. A contract change that breaks a consumer is therefore
visible in the pull request that makes it, rather than working locally for
whoever made it and failing for everyone else.

The same holds in the other direction: the three gateways CertPilot maintains
build against the published module from their own repositories with no
`replace`, which is the only real test of whether a contract is published or
merely copied.

**Compatibility is measured, not remembered.** A hand-maintained table of which
versions work together is a claim nobody re-checks. `make compatibility` starts
each released gateway and talks to it — the conformance probe from the gateway
SDK, then a core built from this repository dialling it over mutual TLS — and
writes [compatibility.md](compatibility.md) from what happened.

It runs weekly rather than only on pull requests, because the other half moves
independently: a gateway can release on a Tuesday and break a core that has not
changed at all, and no pull request here would ever run.

**A third-party gateway has the same probe.** There is no plugin registry and no
compatibility testing for gateways this project does not build, and saying so is
better than implying otherwise. What a third party gets instead is the probe the
in-house gateways are held to. See
[writing a gateway](writing-a-gateway.md#check-it-before-you-trust-it).
