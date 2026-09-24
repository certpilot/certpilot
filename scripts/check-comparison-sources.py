#!/usr/bin/env python3
"""Every vendor sentence docs/comparison.md quotes is still on the vendor's page.

The comparison page makes claims about other companies' products, and each one
rests on a sentence copied from that company's documentation. Those pages change
without telling anybody. By the time the page was first reviewed, Keyfactor's
v26.2 documentation suite had already moved one of the pages it quotes, and the
Venafi product line had changed owners twice. A comparison nobody re-reads turns
into claims about products as they were, published under this project's name
about somebody else's work.

So this re-reads it. For every row of the page's Sources table it fetches the
page and looks for the quoted text. It also checks the page's citations: every
[K1](#sources) in the text must name a row that exists, and every row must be
cited by something, because a claim that has lost its citation and a source
nothing depends on look identical from outside.

  python3 scripts/check-comparison-sources.py            # fetch every page
  python3 scripts/check-comparison-sources.py --offline  # the table and citations only
  python3 scripts/check-comparison-sources.py --page PATH

--offline says what it did not check. It exists so a pull request that does not
touch the comparison can check its structure without asking fifteen vendor
sites for anything; the weekly run fetches them all.

Exit status: 0 clean, 1 a quote or citation is wrong, 2 nothing to check.
"""

from __future__ import annotations

import argparse
import datetime
import html
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CITE = re.compile(r"\[([A-Z]\d+)\]\(#sources\)")
LINK = re.compile(r"\]\((https?://[^)\s]+)\)")
# A review older than this is reported, not failed: the page still says what
# was true on its review date, but a reader deserves to know it is getting old.
STALE_AFTER = datetime.timedelta(days=180)


def visible_text(raw: str) -> str:
    """The text a reader sees, normalised so a quote matches it however the
    vendor's HTML happens to spell a space, an apostrophe or a trademark."""
    t = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", raw)
    t = html.unescape(re.sub(r"<[^>]+>", " ", t))
    return normalise(t)


def normalise(t: str) -> str:
    t = re.sub(r"[​‌‍⁠﻿]", "", t)  # DigiCert​​® has two of these
    t = t.translate(str.maketrans({"’": "'", "‘": "'", "“": '"',
                                   "”": '"', " ": " "}))
    return re.sub(r"\s+", " ", t).strip().casefold()


def fetch(url: str) -> tuple[str, str]:
    """(title, visible text), retried twice: a vendor site having a bad minute
    is not a claim that has gone stale."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; certpilot documentation check)"})
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read().decode("utf-8", "replace")
            title = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw)
            return (html.unescape(title.group(1)).strip() if title else "", visible_text(raw))
        except urllib.error.HTTPError as e:
            if e.code < 500:
                raise
            last = e
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
        time.sleep(3 * (attempt + 1))
    raise last  # type: ignore[misc]


def sources_table(text: str) -> list[dict[str, str]]:
    start = text.find("\n## Sources")
    if start < 0:
        return []
    end = text.find("\n## ", start + 1)
    rows = []
    for line in text[start: end if end > 0 else None].splitlines():
        if not line.startswith("|") or line.startswith("|:") or line.startswith("| ID "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) != 6:
            rows.append({"id": cells[0] if cells else "?", "error": f"{len(cells)} columns, not 6"})
            continue
        link = LINK.search(cells[2])
        rows.append({"id": cells[0], "vendor": cells[1], "url": link.group(1) if link else "",
                     "version": cells[3], "reviewed": cells[4], "quote": cells[5]})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--page", default=str(ROOT / "docs" / "comparison.md"))
    ap.add_argument("--offline", action="store_true",
                    help="check the table and the citations, and fetch nothing")
    args = ap.parse_args()

    page = pathlib.Path(args.page)
    text = page.read_text()
    rows = sources_table(text)
    if not rows:
        print(f"{page}: no Sources table to check. The comparison's claims about other "
              f"products rest on it, so its absence is a failure, not a pass.")
        return 2

    problems: list[str] = []
    notes: list[str] = []
    today = datetime.date.today()

    body = text[: text.find("\n## Sources")]
    cited = set(CITE.findall(body))
    listed = {r["id"] for r in rows}
    for missing in sorted(cited - listed):
        problems.append(f"the page cites {missing}, which is not in Sources")
    for r in rows:
        if "error" in r:
            problems.append(f"{r['id']}: the Sources row has {r['error']}")
            continue
        if r["id"] not in cited:
            problems.append(f"{r['id']} is in Sources but nothing on the page cites it")
        if not r["url"]:
            problems.append(f"{r['id']}: no link in the Page column")
        if not r["quote"]:
            problems.append(f"{r['id']}: nothing quoted, so nothing can be checked")
        try:
            reviewed = datetime.date.fromisoformat(r["reviewed"])
            if reviewed > today:
                problems.append(f"{r['id']}: reviewed {r['reviewed']}, which has not happened yet")
            elif today - reviewed > STALE_AFTER:
                notes.append(f"{r['id']}: last reviewed {r['reviewed']}, over "
                             f"{STALE_AFTER.days} days ago")
        except ValueError:
            problems.append(f"{r['id']}: review date {r['reviewed']!r} is not YYYY-MM-DD")

    fetched = 0
    if not args.offline:
        pages: dict[str, tuple[str, str] | Exception] = {}
        for r in rows:
            if "error" in r or not r["url"] or not r["quote"]:
                continue
            if r["url"] not in pages:
                try:
                    pages[r["url"]] = fetch(r["url"])
                    fetched += 1
                except Exception as e:  # noqa: BLE001 — reported against the row
                    pages[r["url"]] = e
            got = pages[r["url"]]
            if isinstance(got, Exception):
                problems.append(f"{r['id']} ({r['vendor']}): {r['url']} could not be read: {got}")
                continue
            title, visible = got
            if re.search(r"(?i)page not found|\b404\b", title):
                # Keyfactor's documentation answers a moved page with 200 and a
                # page titled "Oops! Page Not Found". A status code check would
                # have called that page present.
                problems.append(f"{r['id']} ({r['vendor']}): {r['url']} now serves a "
                                f"not-found page ({title!r}). The page has moved or gone")
            elif normalise(r["quote"]) not in visible:
                problems.append(f"{r['id']} ({r['vendor']}): the quoted text is no longer on "
                                f"{r['url']}: \"{r['quote']}\"")

    for p in problems:
        print(p)
    for n in notes:
        print(f"note: {n}")
    how = ("fetched nothing: --offline checked the table and the citations only"
           if args.offline else f"{fetched} page(s) fetched")
    print(f"{len(rows)} source(s), {len(cited)} cited, {how}: {len(problems)} problem(s), "
          f"{len(notes)} note(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
