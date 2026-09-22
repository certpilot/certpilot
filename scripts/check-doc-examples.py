#!/usr/bin/env python3
"""Check that every curl example in the documentation could actually run.

Two things go wrong with an API example in a Markdown file, and neither shows
up in a build:

  1. It names a route that no longer exists, or never did.
  2. It carries no credential, against a route that requires one.

The second is how this check came to be written. CertPilot used to accept
anonymous requests on a loopback address in development mode. That was removed
— `auth.allow_anonymous` is now refused by configuration validation — and the
prose in api-reference.md, security.md and configuration.md was updated to say
so. Every runnable example was left behind. Twenty-seven of them, across eight
files, every one a 401 for anybody who copied it. The getting-started guide's
entire hands-on path did not work.

Prose and examples drifted apart because only the prose was being read. This
reads the examples, against docs/routes.json, which `make routes` generates
from the router itself. A route renamed in router.go fails this check on the
next `make test-docs`.

Usage:  python3 scripts/check-doc-examples.py [--routes docs/routes.json] [FILE...]
Exit:   0 if every example checks out, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
import sys

# A credential, in any of the forms the API accepts. `-b`/`--cookie` is the
# session cookie a password sign-in returns; the header forms are the bearer
# token from an identity provider and the display token for an unattended
# screen. An example may legitimately use any of them.
CREDENTIAL = re.compile(
    r"(^|\s)(-b|--cookie)(\s|=)|authorization:\s*bearer|x-certpilot-agent|x-display-token",
    re.IGNORECASE,
)

# The host forms an example may use for CertPilot's own API. Anything else is
# somebody else's service — a CA's ACME directory, a release download — and is
# not ours to check.
API_HOST = re.compile(
    r"^(https?://)?(localhost|127\.0\.0\.1|\$\{?[A-Z_]+\}?)(:\d+)?(?=/|$)", re.IGNORECASE
)

# A path segment that stands for a value the reader supplies: a shell variable,
# an angle-bracket placeholder, or a literal uuid. Any of these matches a
# `:param` segment in the route table.
PLACEHOLDER = re.compile(
    r"^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|<[^>]+>|\{[^}]+\}"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)


SHELL_LANGS = {"bash", "sh", "shell", "console", "zsh"}


def fenced_shell_blocks(text: str):
    """Yield (start_line, block_text) for every shell-tagged fenced block.

    Every fence has to be recognised, not only the shell ones. A block opened
    with an info string this function does not care about — ```text, ```sql,
    ```yaml — still has a closing fence, and skipping the opener means reading
    that closer as the next opener. Everything after it then pairs up wrongly,
    which silently hid two examples the first version of this script was
    written to catch.
    """
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(`{3,}|~{3,})\s*([^\s`]*)", lines[i])
        if not m:
            i += 1
            continue
        indent, marker, lang = m.group(1), m.group(2), m.group(3).lower()
        fence = re.compile(r"^\s*" + re.escape(marker[0]) + r"{%d,}\s*$" % len(marker))
        start = i + 1
        j = start
        while j < len(lines) and not fence.match(lines[j]):
            j += 1
        if lang in SHELL_LANGS:
            yield start + 1, "\n".join(lines[start:j])
        i = j + 1


def curl_commands(block: str):
    """Yield (line_offset, command_text) for each curl in a shell block.

    Line continuations are joined, because almost every real example wraps.
    """
    joined, starts = [], []
    buf, buf_start = "", None
    for n, raw in enumerate(block.splitlines()):
        line = raw.rstrip()
        if buf_start is None:
            buf_start = n
        buf += line[:-1] + " " if line.endswith("\\") else line
        if not line.endswith("\\"):
            joined.append(buf)
            starts.append(buf_start)
            buf, buf_start = "", None
    if buf:
        joined.append(buf)
        starts.append(buf_start if buf_start is not None else 0)

    for off, cmd in zip(starts, joined):
        if re.search(r"(^|\s|\|)curl(\s|$)", cmd):
            yield off, cmd


def parse_curl(cmd: str):
    """Return (method, url) for a curl command, or None if there is no URL."""
    try:
        argv = shlex.split(cmd, comments=True)
    except ValueError:
        argv = cmd.split()

    method, url = None, None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-X", "--request") and i + 1 < len(argv):
            method = argv[i + 1].upper()
            i += 2
            continue
        if a.startswith("-X") and len(a) > 2:
            method = a[2:].upper()
            i += 1
            continue
        # Flags that consume the next argument, so it is never mistaken for a URL.
        if a in ("-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
                 "-o", "--output", "-b", "--cookie", "-c", "--cookie-jar",
                 "-u", "--user", "-A", "--user-agent", "-e", "--referer",
                 "-F", "--form", "-T", "--upload-file", "--cacert", "--cert",
                 "--key", "-m", "--max-time", "-w", "--write-out"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        if a != "curl" and url is None:
            url = a
        i += 1

    if url is None:
        return None
    if method is None:
        method = "PUT" if re.search(r"(^|\s)(-T|--upload-file)(\s|=)", cmd) else (
            "POST" if re.search(r"(^|\s)(-d|--data|-F|--form)", cmd) else "GET")
    return method, url


def api_path(url: str):
    """The API path an example targets, or None if it is not our API."""
    url = url.strip("'\"")
    if not API_HOST.match(url):
        return None
    path = API_HOST.sub("", url, count=1)
    path = path.split("?", 1)[0].split("#", 1)[0]
    return path or "/"


def normalise(path: str) -> str:
    """Rewrite reader-supplied segments to `:param`, so it can match a route."""
    out = []
    for seg in path.split("/"):
        out.append(":param" if PLACEHOLDER.match(seg) else seg)
    return "/".join(out)


def route_key(path: str) -> str:
    return "/".join(":param" if s.startswith(":") or s.startswith("*") else s
                    for s in path.split("/"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--routes", default="docs/routes.json")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()

    table = json.loads(pathlib.Path(args.routes).read_text())
    routes = {}
    for r in table["routes"]:
        routes.setdefault((r["method"].upper(), route_key(r["path"])), r)

    # rglob, not glob. The first version of this checked docs/*.md only, so
    # docs/gateways/ and the eleven docs/platforms/ pages were never read —
    # and docs/gateways/vault.md had carried an uncredentialled example the
    # whole time. A checker with a silent blind spot is worse than none,
    # because it reports zero problems over the part it looked at.
    files = [pathlib.Path(f) for f in args.files] or (
        sorted(pathlib.Path("docs").rglob("*.md")) + [pathlib.Path("README.md")])

    problems, checked = [], 0
    for f in files:
        if not f.exists():
            continue
        text = f.read_text()
        for block_line, block in fenced_shell_blocks(text):
            for off, cmd in curl_commands(block):
                parsed = parse_curl(cmd)
                if not parsed:
                    continue
                method, url = parsed
                path = api_path(url)
                if path is None or not path.startswith("/api/"):
                    continue  # not CertPilot's API
                checked += 1
                line = block_line + off
                key = (method, normalise(path))
                route = routes.get(key)
                if route is None:
                    problems.append(
                        (f, line, f"{method} {path} is not a route: "
                                  f"nothing in {args.routes} serves it"))
                    continue
                if route["auth"] != "none" and not CREDENTIAL.search(cmd):
                    problems.append(
                        (f, line, f"{method} {path} requires {route['auth']} "
                                  f"({route['min_role']}), but this example "
                                  f"carries no credential — it is a 401"))

    for f, line, msg in problems:
        print(f"{f}:{line}: {msg}")

    print(f"\n{checked} API examples checked, {len(problems)} problem(s).",
          file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
