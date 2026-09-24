# Documentation checks

The checks on this page catch documentation that cannot run, links that do not
land and versions that do not exist. **None of them can tell whether a sentence
is true.** That part is a person's job, and the second half of this page says
which sentences need one.

A faithful copy of a wrong sentence is still a wrong sentence, just published.
The documentation site syncs these pages byte for byte, and that proves only
that the site shows what this repository says.

## What is checked, and what each check cannot tell you

| Check | What it asks | What it cannot tell you | Runs |
|:--|:--|:--|:--|
| `make test-docs` | Every `curl` in `docs/` names a route that exists, and carries a credential if that route needs one | Whether the route does what the prose around it says | Docs pull requests, weekly |
| `make test-docs-live` | The documented GETs that have nothing for the reader to fill in are sent to a core built from the commit, signed in, and each must answer 2xx | Anything about writes, and whether a response says what the page claims it says | Docs pull requests, weekly |
| `make test-doc-links` | Every relative link and anchor in `docs/` resolves, in the spelling the published site uses, including links into `certpilot-agent`'s pages | Links to other sites | Docs pull requests, weekly |
| `npm run check:links` in certpilot-docs | Every link, anchor, image and stylesheet on the **built** site lands | Links to other sites | Every certpilot-docs pull request, after the build |
| `make test-doc-versions` | Every pinned image tag, module version and release ref is published. Each page names one version per component, and a pinned gateway or agent is one [compatibility.md](compatibility.md) measured | Whether a pinned *combination* works. Only the evaluation run shows that, and only for its own pair | Docs pull requests, weekly |
| `make test-evaluation` | [evaluation.md](evaluation.md), run as written against the release it pins, does what sixteen of its sentences say | Every sentence it does not assert | Docs pull requests, weekly |
| `make test-comparison-sources` | Every vendor sentence [comparison.md](comparison.md) quotes is still on the vendor's page, and every claim there cites a source the page lists | Whether the vendor's documentation is right, or anything it does not say | Weekly, and on pull requests that change the comparison |
| `sync:pages --check` and `sync:guides --check` in certpilot-docs | The site shows exactly what this repository says, and records which commit it came from | Whether this repository is right | Every certpilot-docs pull request |
| `make test-doc-checks` and `npm run test:checks` | Each check above fails on the breakage it exists to catch, and passes once that is corrected | Nothing beyond that. This one checks the checks | Docs pull requests, weekly |

The checks in this repository also run weekly. The version check and the
evaluation run depend on things outside this repository: an image can be
deleted, a tag moved, or a released quickstart can stop starting, all on a day
when nobody opens a pull request here.

### What "does not skip" means

A check that cannot run fails. It does not pass. The link check fails when the
`certpilot-agent` checkout beside it is missing. The version check fails when a
registry cannot be reached. The built-site check fails when there is no build to
read. Each has an explicit flag for skipping, and that flag says in the output
what went unchecked.

This rule exists because the opposite shipped. The docs site's first anchor
check printed "skipping" and exited 0 whenever its build output was absent, and
it only ever read one directory. Five dead links were live on the published
site when it was replaced.

## What none of them can tell you

Here are the false claims found in September 2026. Each one passed every check
that existed, because every check reads syntax, and these were about behaviour.

| The sentence | Where | What was true | How long |
|:--|:--|:--|:--|
| "`GET /healthz` is the only unauthenticated route" | `api-reference.md` | Four routes are unauthenticated. Sign-in added two of them on 23 August and the third on 29 August | Four weeks |
| "CertPilot's own API currently exposes no route that triggers revocation" | `gateways/vault.md` | True when written on 22 August. `POST /certificates/:id/revoke` arrived on 24 August | A month |
| The agent and the gateways "both speak gRPC" | A draft, caught in review | The agent speaks REST and has no `.proto` | Never published |
| Vault is "the only gateway that answers GetCAInfo" | A draft, caught in review | ACME answers it as well. Vault is the only one that returns *issuers* | Never published |
| `config.example.yaml` "defaults to a wildcard CORS origin" | A draft, caught in review | It sets `http://localhost:3000` | Never published |
| Deploying to servers: "Two of those five are 🧪" | `status.md` | Three are. The AWS ACM deployer has only ever answered a stub, and no CI job holds an AWS credential. Found while writing the comparison on 24 September | Two days as that sentence. The ✅ it replaced had said all five |

The two that were published follow the same pattern, and it is the one most
worth knowing. **A sentence saying that something does not exist was true when
it was written. The next feature made it false, and nothing pointed from that
feature back to the sentence.** The code review for revocation had no reason to
open `gateways/vault.md`.

## Which sentences need a person

These sentences go stale when CertPilot changes:

1. **Absence and exclusivity.** "There is no …", "the only …", "cannot",
   "never", "is not supported". These are the most fragile, because adding the
   thing makes them false and they sit on pages the new code has no reason to
   touch. Both published false claims above were this kind.
2. **Shape.** Where a field is in a response, what wraps what, which protocol a
   component speaks, what a command prints. These change with a handler or a
   contract.
3. **Numbers the code decides.** Durations, counts, ports, lifetimes and limits:
   "tolerance is five minutes", "eight failures, fifteen minutes", "a 90-day
   certificate".
4. **Known-defect callouts.** "Known defect, #102 …". These must go when the
   defect is fixed. One is enforced: the evaluation run asserts the #102 callout,
   so fixing #102 fails it until the page is updated. The rest are not enforced.

These go stale when *someone else's* software changes: how Vault, nginx, IIS or
a browser behaves, and CA/Browser Forum dates. Re-read them when a tested
version moves, not when CertPilot changes.

These do not go stale with the code: rationale, instructions to the reader, and
descriptions of the documentation itself.

### The rule

**A pull request that changes behaviour re-reads the pages that describe that
behaviour, and says in its description that it did.** To find those pages,
search `docs/` for what the change touches: the route, the configuration key,
the file path, the error message, the issue number it closes. Search for the
*absence* too, because that is the sentence that goes stale. If you add
revocation, search for `revoc`, not for the new handler's name.

```bash
grep -rn -i 'revoc' docs/            # everything that talks about it, including "there is no"
grep -rn '#102' docs/                # every callout that must go when #102 closes
grep -rn 'certificates/:id/renew' docs/
```

### Why not a list of sentences

We tried making one. In September 2026 a per-sentence classifier asked "could a
change to CertPilot make this sentence false?". On a labelled sample it flagged
all five claims above. On `security.md` it flagged 118 of 175 sentences, and it
was right to: a security model is mostly claims about behaviour. A list that
long is the page itself. So the unit of review is the page that describes what
you changed, and finding that page is a search, as above.

## Links that survive both renderers

These pages are read on the published site and on GitHub, and the two slug a
heading differently:

| Heading | The site | GitHub |
|:--|:--|:--|
| `## 5. Issue from a real CA` | `#_5-issue-from-a-real-ca` | `#5-issue-from-a-real-ca` |
| `### Delete — not a substitute for revoking` | `#delete-—-not-a-substitute-for-revoking` | `#delete--not-a-substitute-for-revoking` |

- **Link with the site's spelling.** The site is where these pages are read. When
  a link uses GitHub's spelling, `make test-doc-links` says so and prints the
  site's.
- **For a heading you expect people to link to**, do not start it with a number
  and do not use an em-dash. The two spellings then agree.
- `scripts/check-doc-links.py` uses the site's slugifier, ported exactly. An
  approximation shipped first and passed a link that was dead in both renderers.
  The built-site check in certpilot-docs caught it, and that check is the
  authority, because it reads what the reader gets.

## Where a published page came from

Every page on the documentation site records, in its frontmatter
(`source.commit`) and in a comment at its top, the commit that last changed its
source here. Its "Last updated" date is that commit's date. Before this it was
the date the site happened to copy the page, which was hours or days later.

The recorded commit is the last one to change *that file*, not the one the site
synced at. So a page that has not changed stays byte-for-byte the same however
many unrelated commits land.

**Do not commit a sync made from a local checkout.** Its commits may exist only
on your machine. Sync from a pushed ref with `CERTPILOT_REF=<sha>`. `--check`
compares against the remote and fails a local sync.

## Running them

```bash
make test-docs test-doc-links test-doc-versions test-doc-checks
make test-docs-live     # builds a core from this tree; about a second once the build is cached
make test-evaluation    # Docker, and ports 3000 and 8080 free
```

The first line takes seconds. It needs the network and a `certpilot-agent`
checkout beside this one. Under colima, `make test-evaluation` needs a directory
the VM shares: `make test-evaluation EVAL_DIR=/path/it/shares`.
