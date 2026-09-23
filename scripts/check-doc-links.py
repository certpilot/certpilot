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
import unicodedata

# The published site's slugifier, ported exactly rather than approximated.
#
# An approximation shipped first and was wrong in a way worth remembering: it
# collapsed "Delete — not a substitute for revoking" to
# `delete-not-a-substitute-for-revoking` and accepted a link spelled that way.
# VitePress keeps the em-dash — `delete-—-not-a-substitute-for-revoking` — and
# GitHub drops it but keeps both hyphens — `delete--not-a-substitute-for-revoking`.
# So the checker passed a link that was dead in *both* renderers, and the built
# site, read by certpilot-docs' check-built-links.mjs, is what found it.
#
# This is VitePress 1.6's `slugify`, regex for regex. The site is where these
# pages are read, so its spelling is the correct one; GitHub's is computed only
# so a link written the GitHub way can be told which spelling to use instead of
# just "not found". The two disagree on a heading that starts with a digit
# (VitePress prefixes `_`) and on any punctuation outside the list below, of
# which the em-dash is the one this project uses.
#
# The *link* is reported rather than the heading: numbered headings are useful,
# most are never linked to, and flagging all of them would print twenty problems
# on a tree with nothing wrong with it. A check that cries wolf is a check people
# learn to skip.
R_CONTROL = re.compile(r"[\u0000-\u001f]")
R_SPECIAL = re.compile(r"[\s~`!@#$%^&*()\-_+=\[\]{}|\\;:\"'\u201c\u201d\u2018\u2019<>,.?/]+")
R_COMBINING = re.compile(r"[\u0300-\u036f]")
INLINE_CODE = re.compile(r"`([^`]*)`")
MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
HTML_TAG = re.compile(r"<[^>]+>")
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
HTML_ANCHOR = re.compile(r'<a\s+id="([^"]+)"')
LINK = re.compile(r"\]\(([^)\s]+?)(?:\s+\"[^\"]*\")?\)")


def heading_text(raw: str) -> str:
    """What the heading renders as: the slug is taken from the text a reader
    sees, so a link's URL and a code span's backticks are not part of it."""
    s = MD_LINK.sub(r"\1", raw)
    s = INLINE_CODE.sub(r"\1", s)
    return HTML_TAG.sub("", s).strip()


def site_slug(text: str) -> str:
    s = unicodedata.normalize("NFKD", text)
    s = R_COMBINING.sub("", s)
    s = R_CONTROL.sub("", s)
    s = R_SPECIAL.sub("-", s)
    s = re.sub(r"-{2,}", "-", s)
    s = re.sub(r"^-+|-+$", "", s)
    s = re.sub(r"^(\d)", r"_\1", s)
    return s.lower()


def github_slug(text: str) -> str:
    return re.sub(r"[^\w\- ]", "", text.lower()).replace(" ", "-")


def anchors_of(path: pathlib.Path) -> tuple[set[str], dict[str, str]]:
    """The ids a link can land on in the built site, and — for a heading the two
    renderers slug differently — the GitHub spelling mapped to the site's.

    A repeated heading gets `-1`, `-2` on the site, as markdown-it-anchor does,
    so a link to the second "Limitations" on a page has to say so."""
    ids: set[str] = set()
    github: dict[str, str] = {}
    in_fence = False
    for line in path.read_text().splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = HEADING.match(line)
        if m:
            text = heading_text(m.group(2))
            s = site_slug(text)
            unique, n = s, 1
            while unique in ids:
                unique, n = f"{s}-{n}", n + 1
            ids.add(unique)
            g = github_slug(text)
            if g != unique:
                github.setdefault(g, unique)
        ids.update(HTML_ANCHOR.findall(line))
    return ids, github


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="*", help="markdown files; default is all of docs/")
    ap.add_argument("--allow-missing-agent-docs", action="store_true",
                    help="check what can be checked without a certpilot-agent checkout, and "
                         "say which links went unchecked")
    args = ap.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    docs = root / "docs"
    agent_docs = root.parent / "certpilot-agent" / "docs"
    if not agent_docs.is_dir():
        # A failure by default, not a note. This used to print a line to stderr
        # and carry on, so a CI job whose agent checkout step had been removed
        # would report "0 problems" over a check that no longer read the
        # platform pages at all — green, and indistinguishable from green that
        # meant something. Skipping has to be asked for.
        if not args.allow_missing_agent_docs:
            print(f"no certpilot-agent checkout at {agent_docs}. docs/platforms/ and "
                  f"docs/agent.md are published from it, so links into them cannot be "
                  f"checked without it. Clone it beside this repository, or pass "
                  f"--allow-missing-agent-docs to skip those links and say so.")
            return 2
        agent_docs = None

    files = [pathlib.Path(f).resolve() for f in args.files] or sorted(docs.rglob("*.md"))

    # Cached, because a set of pages that all link into operations.md would
    # otherwise re-read and re-slug it once per link.
    cache: dict[pathlib.Path, tuple[set[str], dict[str, str]]] = {}

    def anchors(p: pathlib.Path) -> tuple[set[str], dict[str, str]]:
        if p not in cache:
            cache[p] = anchors_of(p)
        return cache[p]

    problems: list[str] = []
    checked = 0
    skipped = 0

    def shown(p: pathlib.Path) -> pathlib.Path:
        # A page outside the repository — the self-test's fixtures live in a
        # temporary directory — is shown by the path it was given. relative_to
        # raises instead, which exits 1 with a traceback: a "this must fail"
        # test reading only the exit status would count that as the check
        # working. test-doc-checks.sh reads the message too, which is how this
        # was found.
        try:
            return p.relative_to(root)
        except ValueError:
            return p

    for path in files:
        text = path.read_text()
        for m in LINK.finditer(text):
            target = m.group(1)
            if re.match(r"^(https?:|mailto:|tel:|data:)", target):
                continue
            rel, _, anchor = target.partition("#")
            line = text[: m.start()].count("\n") + 1
            here = f"{shown(path)}:{line}"

            if rel == "":
                checked += 1
                if anchor:
                    ids, github = anchors(path)
                    if anchor in github and anchor not in ids:
                        problems.append(
                            f"{here}: #{anchor} is GitHub's spelling and is dead on the "
                            f"published site, which renders that heading as "
                            f"#{github[anchor]}")
                    elif anchor not in ids:
                        problems.append(
                            f"{here}: no heading on this page matches #{anchor}")
                continue

            resolved = (path.parent / rel).resolve()
            if not resolved.exists() and agent_docs is None and args.allow_missing_agent_docs:
                try:
                    under = resolved.relative_to(docs.resolve()).parts[0]
                except ValueError:
                    under = ""
                if under in ("platforms", "agent.md"):
                    skipped += 1
                    continue
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
                ids, github = anchors(resolved)
                if anchor in github and anchor not in ids:
                    problems.append(
                        f"{here}: {rel}#{anchor} is GitHub's spelling and is dead on "
                        f"the published site, which renders that heading as "
                        f"#{github[anchor]}")
                elif anchor not in ids:
                    problems.append(f"{here}: {rel} has no heading matching #{anchor}")

    for p in problems:
        print(p)
    note = (f" {skipped} link(s) into the agent's pages NOT checked: "
            f"--allow-missing-agent-docs." if skipped else "")
    print(f"{checked} link(s) checked, {len(problems)} problem(s).{note}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
