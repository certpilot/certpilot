# Repositories

CertPilot is several repositories rather than one. This page says what they are
called, why, and what keeps them working together now that a single build no
longer does.

## The standard

| Repository | Holds |
|:---|:---|
| `certpilot` | The core, the migrations, and the frontend |
| `certpilot-agent` | The host agent, its deployment profiles, and its documentation |
| `certpilot-docs` | The documentation site |
| `certpilot-gateway-sdk` | The provider contract, published, plus the conformance probe |
| `certpilot-agent-sdk` | The agent contract, published |
| `certpilot-gateway-<ca>` | One per certificate authority — `-acme`, `-vault`, `-selfsigned` |

Two rules, and the first is the one that matters.

**`certpilot-gateway-` is a load-bearing prefix.** It is what makes a gateway
recognisable as one in a GitHub search, and what lets this project point at
gateways it did not write without appearing to vouch for them. A gateway named
anything else is a gateway nobody finds.

**No hyphen inside the word.** It is `certpilot`, not `cert-pilot`. The Go module
paths, the container images and the organisation all spell it one way, and a
second spelling is a thing every future reader has to check rather than know.

## An agent is not a gateway

Both are separate processes, both have an SDK, and both are named in the same
sentence often enough that the difference is worth stating once. They do not
even talk to the core the same way.

| | A gateway | The agent |
|:--|:--|:--|
| Answers the question | "How do I talk to *this CA*?" | "What is on *this host*, and how do I install a certificate here?" |
| Runs | Wherever the core can reach it — usually beside it | On the machine that serves the certificate |
| How many | One process per CA vendor | One per host |
| Speaks | gRPC, and the core dials *it* | REST, and it calls the core — so it needs no inbound port |
| Contract | The `provider.v1` protobuf in `certpilot-gateway-sdk` | Go types in `certpilot-agent-sdk/agentapi`, with the signing scheme in `agentauth`. There is no `.proto` |
| Authenticates as | A client certificate on a mutually authenticated channel | An Ed25519 signature over method, path, timestamp and body hash, enrolled in advance. A replayed request is refused |
| Holds credentials | None of its own. The CA credential arrives per call, on the CA account | Its own identity key, generated on the host and never sent |
| Sees private keys | Whatever the CA issuance produces, in transit | Generates them locally; CertPilot never receives them |

The division is what lets a key stay on the host it belongs to. The agent
generates a key and sends a signing request; the gateway carries that request to
a CA. Neither is trusted with the other's job, and a compromise of one does not
hand over the other's material.

**You need a gateway** when CertPilot has no support for a CA you use — see
[writing a gateway](writing-a-gateway.md). **You need the agent** when a
certificate has to end up in a file, a keystore, or the Windows certificate
store on a machine, rather than only in the inventory — see
[the host agent](agent.md).

## Depending on an SDK: released, not local

Both SDKs are published Go modules — one carrying a protobuf contract, one
carrying Go types and a signing scheme — and both are meant to be depended on
the way any other module is:

```
require github.com/certpilot/certpilot-gateway-sdk v0.4.0
```

A `replace` directive pointing at a sibling checkout is for editing the contract
itself, not for building against it. The difference matters because a gateway
built against a local SDK can pass every test on the machine that wrote it and
fail against the contract the core actually ships — which is precisely what the
conformance probe exists to catch, and it cannot catch it if the SDK under test
is the one in your working tree.

The contract and the probe are released together, so pinning one pins the other:

```bash
go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@v0.4.0 \
    -addr localhost:9094 -insecure -domain test.example.com
```

That is the same command an external implementation runs — there is nothing
privileged about the gateways in this organisation, and each of them runs
exactly this in its own CI. `-domain` is what turns the issuance checks from
skipped into run; without it a gateway can pass while proving nothing about
issuance. [Compatibility](compatibility.md) records what each released gateway
currently passes, measured rather than asserted.

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
SDK, then a core built from this repository dialling it over mutual TLS.
`make agent-compatibility` runs the whole agent lifecycle against each released
agent — enrol, grant, request, install, report — and compares the fingerprint
the core recorded with the file actually on the host, which is the one check two
systems that are merely both working cannot satisfy. Both write
[compatibility.md](compatibility.md) from what happened.

They run weekly rather than only on pull requests, because the other halves move
independently: a gateway or an agent can release on a Tuesday and break a core
that has not changed at all, and no pull request here would ever run.

**Both sides of the agent contract ask the question.** This repository runs the
released agent against the core in every pull request; `certpilot-agent` runs
the same harness — `scripts/agent-lifecycle.sh`, checked out from here — against
an agent built from the commit under review. A contract between two
repositories can be broken from either end, so it is checked from both.

**Documentation follows the code.** The agent's guide and the ten platform
pages live in `certpilot-agent`, not here, because prose about the system is
updated by the person changing the system — and that stops being true the moment
the prose is one repository away from the code it describes. The documentation
site publishes from both repositories into one set of pages, so a link from a
platform page to [the security model](security.md) still resolves; a page's
source path is its identity there, not the repository it came from.

**A third-party gateway has the same probe.** There is no plugin registry and no
compatibility testing for gateways this project does not build, and saying so is
better than implying otherwise. What a third party gets instead is the probe the
in-house gateways are held to. See
[writing a gateway](writing-a-gateway.md#check-it-before-you-trust-it).
