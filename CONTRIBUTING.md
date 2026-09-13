# Contributing to CertPilot

Thanks for looking. This is early software with a small surface, so the most
useful contributions right now are bug reports from running it against a real
certificate authority, and gateways for CAs that do not have one yet.

## Before you start

Open an issue before writing anything substantial. A gateway or an engine is a
few hundred lines and a design decision; it is worth agreeing the second part
before you spend time on the first.

For small fixes — a typo, a wrong error message, a missing nil check — just open
a pull request.

## Getting set up

You need Go 1.26+, Node 20+, and PostgreSQL 13+. No cloud account.

```bash
git clone https://github.com/certpilot/certpilot.git
cd certpilot
make dev
```

`make dev` starts PostgreSQL, creates and migrates `certpilot_dev`, generates a
key encryption key once and reuses it, then runs the self-signed gateway on
`:9091`, the API on `:8080` and the frontend on `:3000`. Ctrl-C stops all of it.

`make seed` fills a running instance with a realistic estate. It is idempotent
and deletes nothing, so re-run it rather than starting from empty.

## Before you open a pull request

```bash
make test         # every module
make test-race    # under the race detector
make lint         # gofmt, go vet, staticcheck
```

If you touched `core/api/router.go`, also run `make routes`. The endpoint tables
on the documentation site are generated from `docs/routes.json`, and CI fails if
it has drifted.

If you touched a ```mermaid diagram in `docs/`, two limits are worth knowing,
because both produce a diagram that looks right on GitHub and wrong once the
documentation site publishes it. **A node label is at most two lines**, since
mermaid sizes the box from the label it measured and then draws it with
different metrics, so a third line lands across the bottom edge of its own box.
**A cluster title is one line**, since the second is drawn where the first row
of nodes goes and ends up behind them.

## What we look for

**Run it against the real thing.** This project has a history of green test
suites over broken behaviour: `sys/health` was decoded through the wrong
envelope so every real Vault reported "not initialized", and the fake wrapped it
the same way so the tests agreed. `GetCAChain` had been broken against any real
database since migration 006, and the in-memory store had no such column and
never noticed. A passing suite is necessary and it is not evidence.

For store work specifically, every test runs against both the in-memory and the
PostgreSQL implementation, and a preflight test enforces it. There is a short
allow-list and it is not accepting new entries.

**Comments say why, not what.** The codebase is full of comments explaining the
failure a piece of code prevents, often naming the bug that motivated it. That
is the most valuable thing in the repository. A comment restating the line below
it is worse than no comment.

**Errors are written for whoever reads them at 2am.** Name the cause, not the
symptom.

**British spelling** in prose and comments. Proper nouns keep their capitals in
error strings, which is why `ST1005` is off in `staticcheck.conf`.

## Commit messages

Long, and explaining the reasoning, the failure mode, and what was verified.
Look at recent history before writing one. A one-line summary of the diff is not
what we are after; the diff already says that.

## Adding a gateway

A gateway is its own process speaking one gRPC contract, in any language, and
adding one does not touch this repository at all — **including not needing a
pull request here.** The contract is published:

```bash
go get github.com/certpilot/certpilot-gateway-sdk
```

[docs/writing-a-gateway.md](docs/writing-a-gateway.md) walks through it, and
names the four things that have been got wrong at least once each.

Check it against the contract rather than hoping:

```bash
go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@latest \
    -addr localhost:9443 -insecure -domain test.example.com
```

The three gateways this project maintains run that same probe in their own CI.
The check worth reading first is `IssueCertificate (honours csr_pem)`: it asks
you to sign a CSR it generated and compares the public key in what you return
against the key it asked you to sign. A gateway that generates its own key
instead passes every test its author is likely to write, and fails much later as
a certificate that does not match its private key.

Name it `certpilot-gateway-<ca>`. That prefix is what makes one findable on a
GitHub search, and what lets this project point at community gateways without
vouching for them.

The ones that do not exist yet and would be welcome: Google Cloud CAS, AWS
Private CA, DigiCert, Sectigo.

## Reporting a vulnerability

Do not open a public issue. See [SECURITY.md](SECURITY.md).
