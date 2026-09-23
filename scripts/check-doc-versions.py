#!/usr/bin/env python3
"""Every version the documentation tells a reader to run exists, and agrees with itself.

A published instruction that pins a version makes two promises: that the version
can be fetched, and that it works with the rest of what the page tells you to run.
Neither is checked by anything else here. A tag that was never pushed, an image
that was never published, a table that says 0.3.0 above a command that says
0.2.0 — each of those builds, lints and syncs cleanly, and fails the first
reader who pastes it.

The second promise has already been broken once, quietly: the released v0.1.1
quickstart defaults its gateway to 0.2.0, so a reader who set only
CERTPILOT_VERSION ran a gateway older than the one the page was measured on.

Three checks, in order of how certain the answer is:

  exists       Every pinned image tag, git tag and module version is published.
               Asked of the registry and the repository, not inferred.
  consistent   Within one page, every mention of a component names one version.
  measured     A gateway or agent version pinned for use with this core is one
               docs/compatibility.md measured as working. One it measured as
               *failing* is an error; one it never measured is reported, not
               failed — otherwise every pull request would go red on the day
               somebody else's repository released.

Network access is required, and its absence is a failure rather than a pass.
`--offline` skips the first check explicitly, and says so in its output, for a
laptop on a train; nothing in CI passes it.

  python3 scripts/check-doc-versions.py
  python3 scripts/check-doc-versions.py --offline

Exit status is the verdict.
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Components by the name each kind of pin uses for them. An image called
# gateway-vault, a module called certpilot-gateway-vault and a compatibility row
# for certpilot-gateway-vault are the same thing, and the consistency check has
# to know that or it compares nothing.
def component(name: str) -> str:
    name = name.removeprefix("ghcr.io/certpilot/").removeprefix("certpilot-")
    return {"core": "core", "frontend": "core"}.get(name, name)

IMAGE = re.compile(r"\b(ghcr\.io/certpilot/[a-z0-9-]+|ghcr\.io/letsencrypt/pebble|nginx|postgres|hashicorp/vault):([0-9][0-9A-Za-z._-]*)")
ENV = re.compile(r"\b(CERTPILOT_VERSION|GATEWAY_VERSION)=([0-9][0-9A-Za-z._-]*)")
MODULE = re.compile(r"\b(?:github\.com/certpilot/)?(certpilot-[a-z0-9-]+)(?:/cmd)?@(v\d+\.\d+\.\d+[0-9A-Za-z.-]*)")
RAW = re.compile(r"raw\.githubusercontent\.com/certpilot/([a-z0-9-]+)/(v\d+\.\d+\.\d+[0-9A-Za-z.-]*)/")
TABLE = re.compile(r"^\|\s*`(ghcr\.io/certpilot/[a-z0-9-]+|postgres)`\s*\|\s*v?([0-9][0-9A-Za-z._-]*)\s*\|", re.M)

# The quickstart's two variables, and the images each one selects. From the
# compose file, where CERTPILOT_VERSION tags the core, the migration job and the
# frontend, and GATEWAY_VERSION tags the self-signed gateway alone.
ENV_IMAGES = {
    "CERTPILOT_VERSION": ["ghcr.io/certpilot/core", "ghcr.io/certpilot/frontend"],
    "GATEWAY_VERSION": ["ghcr.io/certpilot/gateway-selfsigned"],
}


def pins(files):
    """(file, line, kind, name, version) for every version a page pins."""
    for f in files:
        text = f.read_text()
        line = lambda m: text[: m.start()].count("\n") + 1
        for m in IMAGE.finditer(text):
            yield f, line(m), "image", m.group(1), m.group(2)
        for m in ENV.finditer(text):
            for image in ENV_IMAGES[m.group(1)]:
                yield f, line(m), "image", image, m.group(2)
        for m in MODULE.finditer(text):
            yield f, line(m), "tag", m.group(1), m.group(2)
        for m in RAW.finditer(text):
            yield f, line(m), "tag", f"certpilot-{m.group(1)}" if m.group(1) != "certpilot" else "certpilot", m.group(2)
        for m in TABLE.finditer(text):
            yield f, line(m), "image", m.group(1), m.group(2)


# ── exists ────────────────────────────────────────────────────────────────────

MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def _get(url, headers=None, method="GET"):
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, r.read() if method == "GET" else b""


def image_exists(name: str, tag: str) -> bool:
    """Ask the registry, anonymously. HEAD rather than GET, which Docker Hub does
    not count against its anonymous pull limit."""
    if name.startswith("ghcr.io/"):
        repo = name.removeprefix("ghcr.io/")
        token_url = f"https://ghcr.io/token?scope=repository:{repo}:pull&service=ghcr.io"
        manifest = f"https://ghcr.io/v2/{repo}/manifests/{tag}"
    else:
        repo = name if "/" in name else f"library/{name}"
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
        manifest = f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}"
    _, body = _get(token_url)
    token = json.loads(body).get("token") or json.loads(body).get("access_token")
    try:
        status, _ = _get(manifest, {"Authorization": f"Bearer {token}", "Accept": MANIFEST_TYPES}, "HEAD")
        return status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def tag_exists(repo: str, tag: str) -> bool:
    url = f"https://github.com/certpilot/{repo}.git"
    out = subprocess.run(["git", "ls-remote", "--tags", url, f"refs/tags/{tag}"],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"git ls-remote {url} failed: {out.stderr.strip()}")
    return bool(out.stdout.strip())


# ── measured ──────────────────────────────────────────────────────────────────

def compatibility():
    """{(component, version): passed} from the generated compatibility page."""
    rows = {}
    text = (ROOT / "docs/compatibility.md").read_text()
    for m in re.finditer(r"^\|\s*`(certpilot-[a-z0-9-]+)`\s*\|\s*(\S+)\s*\|(.*)$", text, re.M):
        name, version, rest = m.group(1), m.group(2), m.group(3)
        cells = [c.strip() for c in rest.split("|")]
        if name.startswith("certpilot-gateway-"):
            # Contract and Core. Issuance is "not exercised" for two gateways by
            # design, which is recorded as such rather than as a failure.
            passed = cells[0] == "pass" and cells[2] == "pass"
        else:
            passed = cells[0] == "pass"
        rows[(component(name), version)] = passed
    return rows


def agent_latest():
    _, body = _get("https://proxy.golang.org/github.com/certpilot/certpilot-agent/@latest")
    return json.loads(body)["Version"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--offline", action="store_true",
                    help="skip asking registries whether versions exist, and say so")
    args = ap.parse_args()

    files = [pathlib.Path(f) for f in args.files] or (
        sorted((ROOT / "docs").rglob("*.md")) + [ROOT / "README.md"])
    found = list(pins(files))
    problems, notices = [], []
    def rel(f: pathlib.Path) -> pathlib.Path:
        # A file outside the repository — the self-test's fixtures live in a
        # temporary directory — is reported by the path it was given. Crashing
        # here would exit 1 with a traceback, which a "this must fail" test
        # cannot tell apart from the check working.
        try:
            return f.resolve().relative_to(ROOT)
        except ValueError:
            return f

    # exists
    if args.offline:
        notices.append("existence NOT checked: --offline was given, so no registry "
                       "or repository was asked whether any pinned version is published")
    else:
        asked = {}
        for f, n, kind, name, version in found:
            key = (kind, name, version)
            if key not in asked:
                try:
                    asked[key] = (image_exists(name, version) if kind == "image"
                                  else tag_exists(name, version))
                except Exception as e:  # noqa: BLE001 — every failure mode is the same verdict
                    problems.append(
                        f"could not ask whether {name}:{version} exists ({e}). This check "
                        f"does not pass when it cannot run; use --offline to skip it explicitly")
                    asked[key] = None
            if asked[key] is False:
                what = "image tag" if kind == "image" else "tag"
                problems.append(f"{rel(f)}:{n}: {name} {version} — no such {what} is published")

    # consistent
    by_page = {}
    for f, n, kind, name, version in found:
        if name in ("nginx", "postgres", "hashicorp/vault", "ghcr.io/letsencrypt/pebble"):
            continue
        by_page.setdefault((f, component(name)), {}).setdefault(version.lstrip("v"), []).append(n)
    for (f, comp), versions in sorted(by_page.items()):
        if len(versions) > 1:
            where = "; ".join(f"{v} on line{'s' if len(ls) > 1 else ''} {', '.join(map(str, sorted(set(ls))))}"
                              for v, ls in sorted(versions.items()))
            problems.append(f"{rel(f)}: {comp} is pinned to more than one version — {where}")

    # measured
    compat = compatibility()
    latest = None
    for f, n, kind, name, version in found:
        comp = component(name)
        if comp.startswith("gateway-"):
            v = "v" + version.lstrip("v")
            if (comp, v) not in compat:
                notices.append(f"{rel(f)}:{n}: {comp} {v} is not a version compatibility.md measured")
            elif not compat[(comp, v)]:
                problems.append(f"{rel(f)}:{n}: {comp} {v} is measured as NOT working with this core "
                                f"in docs/compatibility.md")
        elif comp == "agent":
            if latest is None and not args.offline:
                try:
                    latest = agent_latest()
                except Exception as e:  # noqa: BLE001
                    problems.append(f"could not resolve the agent's latest version ({e})")
                    latest = ""
            measured = compat.get(("agent", "latest"))
            if measured is False:
                problems.append(f"{rel(f)}:{n}: the latest agent is measured as NOT working with this core")
            elif latest and version != latest:
                notices.append(f"{rel(f)}:{n}: agent {version} is pinned, and compatibility.md measures "
                               f"the latest release, which is {latest}")

    for p in problems:
        print(p)
    for note in sorted(set(notices)):
        print(f"note: {note}")
    distinct = len({(k, nm, v) for _, _, k, nm, v in found})
    print(f"{len(found)} pin(s), {distinct} distinct, across {len(files)} file(s): "
          f"{len(problems)} problem(s), {len(set(notices))} note(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
