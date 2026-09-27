#!/usr/bin/env python3
"""Run docs/evaluation.md the way a reader does, and check it says what happens.

The evaluation guide is the first thing an evaluator runs, and every command in
it was checked by hand when it was written. Nothing re-checks it. It depends on
things outside this repository — a tagged compose file on GitHub, three images on
ghcr.io, whatever the released core does on first start — and any of them can
change without a pull request here.

So this executes the page's own shell blocks, in order, in one shell, as if
pasted into a terminal: `cd` and variables carry over between blocks exactly as
they would for a reader. The commands are read from the page, never copied into
this file, so a command edited on the page is the command that runs.

The page's placeholders are bound from the responses they name — the password
from the core's log, `<id-from-step-3>` from step 3's response, and so on. A
placeholder this script has not been taught is a failure, not a guess: the page
has started asking the reader for something new, and this is where that shows.

Each assertion names the sentence on the page that it verifies, and fails if
that sentence is no longer there. Otherwise the page could be reworded to say
something different and this would go on checking the old claim, passing,
forever. That included the page's known-defect callout for #102, which this
asserted until the day the fix made it fail; it now asserts the fix.

Not indiscriminate execution: one page, allow-listed, in a throwaway directory,
against containers it starts and removes. It needs Docker, Compose v2, and ports
3000 and 8080 free — the page's own prerequisites.

  python3 scripts/run-evaluation-doc.py
  python3 scripts/run-evaluation-doc.py --workdir /somewhere/docker/can/mount

Exit status is the verdict.
"""

import argparse
import json
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "evaluation.md"
COMPOSE = "docker compose -f docker-compose.quickstart.yml"

STEP = re.compile(r"^##\s+(\d+)\.\s+(.+)$", re.M)
FENCE = re.compile(r"^```(\w*)\s*\n(.*?)^```\s*$", re.M | re.S)
UNBOUND = re.compile(r"<[a-z][a-z0-9 -]*>")
DONE = "__DOC_BLOCK_EXIT__"
FAILED = "__DOC_COMMAND_FAILED__"


class Failure(Exception):
    pass


def steps(page_text: str) -> dict[int, list[str]]:
    """{step number: [bash blocks]}, from the page's numbered headings."""
    heads = list(STEP.finditer(page_text))
    out = {}
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(page_text)
        body = page_text[h.end():end]
        # Stop at the next heading of any level, so a "What this does not show"
        # section after the last step is not read as part of it.
        body = re.split(r"^#{1,2}\s", body, flags=re.M)[0]
        out[int(h.group(1))] = [m.group(2) for m in FENCE.finditer(body)
                                if m.group(1) in ("bash", "sh", "shell")]
    return out


class Shell:
    """One bash, fed block by block, so state carries over as in a terminal."""

    def __init__(self, cwd: pathlib.Path):
        self.p = subprocess.Popen(
            ["bash", "--noprofile", "--norc"], cwd=cwd, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
        # A reader's terminal does not stop at the first failing command, and
        # neither does this — but it has to know which one failed, which the
        # exit status of the block's last command alone would not say.
        self.send(f"trap 'printf \"\\n{FAILED} %s\\n\" \"$BASH_COMMAND\"' ERR")

    def send(self, block: str, timeout: float = 120) -> str:
        self.p.stdin.write(block.rstrip("\n") + f"\nprintf '\\n{DONE} %s\\n' \"$?\"\n")
        self.p.stdin.flush()
        lines, deadline = [], time.monotonic() + timeout
        while True:
            if time.monotonic() > deadline:
                raise Failure(f"a block did not finish within {timeout:.0f}s:\n{block}")
            line = self.p.stdout.readline()
            if line == "":
                raise Failure("the shell exited while running:\n" + block)
            if line.startswith(DONE):
                return "".join(lines)
            lines.append(line)

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:  # noqa: BLE001 — best effort on the way out
            self.p.kill()


def json_after(text: str):
    """The last JSON object in a block's output — the response to its curl."""
    for start in [m.start() for m in re.finditer(r"^\{", text, re.M)][::-1]:
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            continue
    raise Failure(f"expected a JSON response, got:\n{text[-800:]}")


def the_id(response: dict) -> str:
    """Some responses wrap their record in `data` and some do not, which the page
    says out loud for step 3. Either way this is the record's id."""
    return (response.get("data") or {}).get("id") or response.get("id") or ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", type=pathlib.Path,
                    help="where the page's `mkdir certpilot-eval` runs; must be somewhere Docker "
                         "can bind-mount (under colima, only paths it shares)")
    ap.add_argument("--keep", action="store_true", help="leave the stack running afterwards")
    ap.add_argument("--page", type=pathlib.Path, default=PAGE,
                    help="a copy of the page to run instead; what the self-test uses to show "
                         "that a page asking for something new fails before running anything")
    args = ap.parse_args()

    page = args.page.read_text()
    by_step = steps(page)
    # What a sentence reads as, for matching: a blockquote's `>` on each wrapped
    # line is markup, not text, and would otherwise make a callout unmatchable.
    prose = " ".join(re.sub(r"^\s*>\s?", "", page, flags=re.M).split())
    results: list[tuple[str, bool, str]] = []

    def claim(sentence: str, ok: bool, detail: str = ""):
        """Record one assertion against the sentence on the page it verifies."""
        on_page = " ".join(sentence.split()) in prose
        if not on_page:
            results.append((sentence, False, "this sentence is no longer on the page — the "
                            "assertion checking it has to be updated with it"))
        else:
            results.append((sentence, ok, detail))
        if not (on_page and ok):
            raise Failure(f"{sentence!r}: {results[-1][2]}")

    for port in (3000, 8080):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                print(f"port {port} is in use. The page needs it free, and so does this.")
                return 2
    missing = [n for n in range(1, 8) if not by_step.get(n)]
    if missing:
        print(f"docs/evaluation.md has no shell block under step(s) {missing}; "
              f"the page and this script disagree about its shape")
        return 1

    work = args.workdir or pathlib.Path(tempfile.mkdtemp(prefix="cp-evaluation-"))
    work.mkdir(parents=True, exist_ok=True)
    sh = Shell(work)
    bound: dict[str, str] = {}
    started = time.monotonic()
    up = False

    def run(n: int, i: int = 0, timeout: float = 120) -> str:
        block = by_step[n][i]
        for placeholder, value in bound.items():
            block = block.replace(placeholder, value)
        left = UNBOUND.findall(block)
        if left:
            raise Failure(f"step {n} asks the reader for {left}, which this script has not been "
                          f"taught to fill in. The page has changed; teach it what that is.")
        out = sh.send(block, timeout)
        if FAILED in out:
            failed = out.split(FAILED, 1)[1].strip().splitlines()[0]
            raise Failure(f"step {n}: a command failed — {failed}\n{out[-1200:]}")
        return out

    try:
        # ── 1. Start it ──────────────────────────────────────────────────────
        t0 = time.monotonic()
        run(1, timeout=900)
        up = True
        # Healthchecks settle after `up -d` returns, so this waits the way a
        # reader waiting for the console would, and times out rather than hangs.
        want = {"postgres": "healthy", "certs": "exited 0", "migrate": "exited 0",
                "gateway-selfsigned": "healthy", "core": "healthy", "frontend": "running"}
        deadline, states = time.monotonic() + 240, {}
        while time.monotonic() < deadline:
            raw = sh.send(f"{COMPOSE} ps -a --format json")
            rows = [json.loads(l) for l in raw.splitlines() if l.startswith("{")]
            states = {r["Service"]: (f"exited {r.get('ExitCode')}" if r["State"] == "exited"
                                     else r.get("Health") or r["State"]) for r in rows}
            if all(states.get(k) == v for k, v in want.items()):
                break
            time.sleep(2)
        cold = time.monotonic() - t0
        claim("Expect, in order: `postgres` healthy, `certs` exited 0, `migrate` exited 0, "
              "`gateway-selfsigned` healthy, `core` healthy, `frontend` started.",
              all(states.get(k) == v for k, v in want.items()), f"got {states}")

        # ── 2. Sign in ───────────────────────────────────────────────────────
        logs = run(2, 0)
        m = re.search(r"password:\s+(\S+)", logs)
        claim("The core creates an administrator on first start and prints the password once.",
              bool(m), f"no password in the core's log:\n{logs[-600:]}")
        bound["<the one above>"] = m.group(1)
        run(2, 1)
        jar = sh.send('printf "%s" "$JAR"').strip()
        signed_in = pathlib.Path(jar).exists() and "certpilot_session" in pathlib.Path(jar).read_text()
        claim("Every command from here carries `-b \"$JAR\"`. Without it the answer is 401.",
              signed_in, "the sign-in command set no session cookie")

        # ── 3. Connect a certificate authority ───────────────────────────────
        gateways = run(3, 0)
        claim("The stack starts the self-signed gateway and registers it, which you can see:",
              "selfsigned" in gateways, f"no self-signed gateway listed:\n{gateways[-400:]}")
        account = json_after(run(3, 1, timeout=60))
        claim("The response is wrapped: the account id is at `.data.id`.",
              bool((account.get("data") or {}).get("id")), f"got {json.dumps(account)[:300]}")
        bound["<id-from-step-3>"] = account["data"]["id"]

        # ── 4. Issue a certificate ───────────────────────────────────────────
        cert = json_after(run(4, 0, timeout=60))
        record = cert.get("data") or cert
        bound["<id>"] = the_id(cert)
        claim("status            ISSUED", record.get("status") == "ISSUED", f"status {record.get('status')}")
        claim("days_remaining    89", record.get("days_remaining") == 89,
              f"days_remaining {record.get('days_remaining')}")
        claim("key_type/size     ECDSA 256",
              (record.get("key_type"), record.get("key_size")) == ("ECDSA", 256),
              f"{record.get('key_type')} {record.get('key_size')}")
        claim("The certificate is in the response; **the private key is\nnot**",
              "PRIVATE KEY" not in json.dumps(cert), "the issuance response carried a private key")
        key = run(4, 1)
        claim("that is a separate, admin-only call which writes an audit record:",
              "PRIVATE KEY" in key, f"no key came back:\n{key[-300:]}")
        serial_before = record.get("serial_number")

        # ── 5. Renew it ──────────────────────────────────────────────────────
        job = json_after(run(5, 0))
        bound["<job-id>"] = the_id(job)
        claim("`202` with a job id, because renewal is a durable queued job rather than a\nblocking call",
              bool(bound["<job-id>"]), f"no job id in {json.dumps(job)[:300]}")
        deadline, status = time.monotonic() + 180, None
        while time.monotonic() < deadline:
            status = (json_after(run(5, 1)).get("data") or {}).get("status")
            if status in ("SUCCEEDED", "FAILED"):
                break
            time.sleep(3)
        claim("It reaches `SUCCEEDED` in a few seconds here.", status == "SUCCEEDED", f"ended {status}")
        renewed = json_after(sh.send(
            f'curl -sS -b "$JAR" localhost:8080/api/v1/certificates/{bound["<id>"]}'))
        renewed = renewed.get("data") or renewed
        claim("The certificate then shows\n`renewal_count: 1` and a new serial.",
              renewed.get("renewal_count") == 1 and renewed.get("serial_number") != serial_before,
              f"renewal_count {renewed.get('renewal_count')}, serial unchanged: "
              f"{renewed.get('serial_number') == serial_before}")
        # #102, fixed in core v0.2.0 and gateway v0.4.0: a renewal asks for the
        # lifetime the account did, and this is the claim that says so. It used
        # to assert the defect, 364 days, so that the fix would fail it.
        days = renewed.get("days_remaining") or 0
        claim("`days_remaining` is 89 again", 88 <= days <= 90,
              f"days_remaining after renewal is {days}; the account asked for 90")

        # ── 6. Check the audit chain ─────────────────────────────────────────
        audit = json_after(run(6, 0))
        claim('{"intact": true, "verified": 4, "unchained": 0, "first_seq": 1, "last_seq": 4}',
              audit.get("intact") is True and audit.get("unchained") == 0,
              f"got {json.dumps(audit)}")

        # The rest of docs/ is not sent here. Those pages describe the core on
        # main, and this stack runs the release the page pins; a route added
        # since would 404 here and look like a documentation fault. They go to a
        # core built from the tree instead — scripts/doc-examples-live.sh.

        # ── 7. Put it back ───────────────────────────────────────────────────
        run(7, 0, timeout=120)
        up = False
        project = work / "certpilot-eval"
        left = subprocess.run(["docker", "volume", "ls", "-q", "--filter",
                               f"label=com.docker.compose.project={project.name}"],
                              capture_output=True, text=True).stdout.split()
        claim("`-v` removes the database volume and the generated mTLS\nmaterial with it",
              not left, f"volumes left behind: {left}")
    except Failure as e:
        print(f"\nFAIL: {e}\n")
    finally:
        if up and not args.keep:
            sh.send(f"cd {work}/certpilot-eval 2>/dev/null; {COMPOSE} down -v >/dev/null 2>&1", 120)
        sh.close()
        if not args.workdir and not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    for sentence, ok, detail in results:
        first = " ".join(sentence.split())[:88]
        print(f"{'ok  ' if ok else 'FAIL'} {first}" + (f"\n     {detail}" if detail and not ok else ""))
    # Every claim above must have been reached: a run that stopped early and
    # recorded no failure would otherwise report a clean pass on half the page.
    passed = all(ok for _, ok, _ in results) and len(results) == 16
    total = time.monotonic() - started
    if "cold" in locals():
        print(f"\ncold start to a healthy stack: {cold:.0f}s (the page says ~20s); whole run {total:.0f}s")
    print(f"{sum(ok for _, ok, _ in results)} of {len(results)} claims hold." if results else "nothing ran.")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
