#!/usr/bin/env python3
"""Every link in docs/ points at something that exists — including the anchor.

The documentation site fails its build on a dead *page* link and says nothing
about a dead *anchor*. VitePress does not check them, so a link to
`operations.md#revoke--not-available-through-the-api` builds green, publishes,
and drops the reader at the top of a page that no longer has that heading.
That exact link shipped: the heading it named had been renamed, and the prose
beside it had gone stale in the same way — it claimed there was no revocation
route, which there is.

So this checks three things a reader depends on and nothing else does:

  1. A relative link resolves to a file that exists.
  2. An anchor on it matches a heading on that file.
  3. A bare `#anchor` matches a heading on the page it is written on.

Two repositories, deliberately. `docs/platforms/nginx.md` and `docs/agent.md`
live in certpilot-agent and are published to the same site from the same source
paths, so a core page linking to `../platforms/nginx.md` is correct and resolves
for a reader — and would be a missing file to anything looking only here. The
agent checkout is found next to this one, and skipped with a warning if it is
not there rather than failing a run that cannot see it.

  python3 scripts/check-doc-links.py
  python3 scripts/check-doc-links.py docs/walkthroughs/vault-nginx.md

Exit status is the verdict.
"""

import argparse
import pathlib
import re
import sys

# Matches VitePress's slugifier closely enough for the headings this project
# writes: lower-cased, punctuation dropped, runs of whitespace to hyphens.
# `_` becomes `-` too, which is what both VitePress and GitHub do.
#
# The one case they disagree on is a heading whose slug would start with a
# digit: VitePress prefixes `_`, GitHub does not. The published site is where
# these pages are read, so the `_` spelling is the correct one and the bare one
# is reported — three of those were already live and dead when this was written.
# The *link* is reported rather than the heading: numbered headings are useful,
# most are never linked to, and flagging all of them would print twenty problems
# on a tree with nothing wrong with it. A check that cries wolf is a check
# people learn to skip.
INLINE_CODE = re.compile(r"`([^`]*)`")
MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
HTML_ANCHOR = re.compile(r'<a\s+id="([^"]+)"')
LINK = re.compile(r"\]\(([^)\s]+?)(?:\s+\"[^\"]*\")?\)")


def slug(heading: str) -> str:
    s = INLINE_CODE.sub(r"\1", heading.strip().lower())
    s = MD_LINK.sub(r"\1", s)
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    return re.sub(r"[\s_]+", "-", s.strip())


def anchors_of(path: pathlib.Path) -> dict[str, bool]:
    """Every id a link can land on, and whether it is spelled the same by both
    renderers. Maps anchor -> True when VitePress and GitHub agree."""
    found: dict[str, bool] = {}
    in_fence = False
    for line in path.read_text().splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = HEADING.match(line)
        if m:
            s = slug(m.group(2))
            if s[:1].isdigit():
                # VitePress renders this as `_1-foo` and that is what the site
                # serves. The bare form is recorded so the message can name the
                # spelling to use instead of just saying the anchor is missing.
                found[s] = False
                found["_" + s] = True
            else:
                found[s] = True
        for a in HTML_ANCHOR.findall(line):
            found[a] = True
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="*", help="markdown files; default is all of docs/")
    args = ap.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    docs = root / "docs"
    agent_docs = root.parent / "certpilot-agent" / "docs"
    if not agent_docs.is_dir():
        print(
            f"note: no agent checkout at {agent_docs}; links into it are not checked",
            file=sys.stderr,
        )
        agent_docs = None

    files = [pathlib.Path(f).resolve() for f in args.files] or sorted(docs.rglob("*.md"))

    # Cached, because a set of pages that all link into operations.md would
    # otherwise re-read and re-slug it once per link.
    cache: dict[pathlib.Path, dict[str, bool]] = {}

    def anchors(p: pathlib.Path) -> dict[str, bool]:
        if p not in cache:
            cache[p] = anchors_of(p)
        return cache[p]

    problems: list[str] = []
    checked = 0

    for path in files:
        text = path.read_text()
        for m in LINK.finditer(text):
            target = m.group(1)
            if re.match(r"^(https?:|mailto:|tel:|data:)", target):
                continue
            rel, _, anchor = target.partition("#")
            line = text[: m.start()].count("\n") + 1
            here = f"{path.relative_to(root)}:{line}"

            if rel == "":
                checked += 1
                if anchor:
                    found = anchors(path)
                    if anchor not in found:
                        problems.append(
                            f"{here}: no heading on this page matches #{anchor}")
                    elif not found[anchor]:
                        problems.append(
                            f"{here}: #{anchor} is dead on the published site — the "
                            f"heading starts with a number, so VitePress renders it "
                            f"as #_{anchor}")
                continue

            resolved = (path.parent / rel).resolve()
            if not resolved.exists() and agent_docs is not None:
                # Published from the agent's repository at the same source path.
                try:
                    resolved = agent_docs / resolved.relative_to(docs.resolve())
                except ValueError:
                    pass

            checked += 1
            if not resolved.exists():
                problems.append(f"{here}: {rel} does not exist")
                continue
            if anchor and resolved.suffix == ".md":
                found = anchors(resolved)
                if anchor not in found:
                    problems.append(f"{here}: {rel} has no heading matching #{anchor}")
                elif not found[anchor]:
                    problems.append(
                        f"{here}: {rel}#{anchor} is dead on the published site — the "
                        f"heading starts with a number, so VitePress renders it as "
                        f"#_{anchor}")

    for p in problems:
        print(p)
    print(f"{checked} link(s) checked, {len(problems)} problem(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
