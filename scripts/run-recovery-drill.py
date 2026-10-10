#!/usr/bin/env python3
"""Run the upgrade, backup, restore and key-recovery procedures for real.

docs/operations.md says how to upgrade, back up, restore and recover from a
lost key. This script does each of those things against real containers and
PostgreSQL, and checks that what the page says happens is what happens.

It starts the quickstart at a released core (v0.1.1 by default, which has
migrations still to apply), puts real state in it, and upgrades it to a core
built from this tree. On the way it:

  - starts the new core before migrating, which must refuse;
  - interrupts the migration, leaving one file applied but unrecorded, and
    finishes it by running the migrations again;
  - starts the new core, and checks that what was there still reads, decrypts,
    renews and issues, including through a CA account created before v0.2.0;
  - rolls the binary back onto the migrated schema, then forward again;
  - restores a pg_dump into an empty database, timed, and checks it again;
  - starts with the wrong key, which must refuse and write nothing;
  - gives up a lost key with CERTPILOT_KEK_ABANDON, then reissues.

Each assertion names the sentence on the page it verifies, and fails if that
sentence is no longer there, so the page cannot be reworded to say something
this no longer checks. Everything runs in a throwaway compose project that is
removed afterwards.

  python3 scripts/run-recovery-drill.py
  python3 scripts/run-recovery-drill.py --from 0.2.1 --from-gateway 0.4.0
  python3 scripts/run-recovery-drill.py --to 0.2.1   # a released core instead of this tree

It needs Docker, Compose v2, and port 8080 free. Under Docker Desktop on macOS
the work directory must be somewhere Docker can bind-mount: pass --workdir.

Exit status is the verdict.
"""

import argparse
import base64
import http.cookiejar
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGES = {
    "operations": ROOT / "docs" / "operations.md",
    "troubleshooting": ROOT / "docs" / "troubleshooting.md",
}
PROJECT = "cp-recovery-drill"
TREE_IMAGE = "certpilot-core:recovery-drill"
QUICKSTART_KEK = "Q2VydFBpbG90UXVpY2tzdGFydERlbW9LZXlfMDAwMDA="
API = "http://127.0.0.1:8080/api/v1"
ABSENT = "6f9d0f6e-0000-4000-8000-000000000000"


class Failure(Exception):
    pass


def prose(path: pathlib.Path) -> str:
    """The page as a reader sees it: no emphasis or code markup, one space."""
    text = re.sub(r"^\s*>\s?", "", path.read_text(), flags=re.M)
    text = text.replace("**", "").replace("`", "")
    return " ".join(text.split())


class Drill:
    def __init__(self, args):
        self.args = args
        self.pages = {name: prose(p) for name, p in PAGES.items()}
        self.results: list[tuple[str, str, bool, str]] = []
        self.measured: list[str] = []
        self.work = args.workdir or pathlib.Path(tempfile.mkdtemp(prefix="cp-recovery-"))
        self.work.mkdir(parents=True, exist_ok=True)
        self.jar = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.password = ""

    # ── assertions ───────────────────────────────────────────────────────────

    def claim(self, page: str, sentence: str, ok: bool, detail: str = ""):
        """Record one assertion against the sentence on the page it verifies."""
        if " ".join(sentence.split()) not in self.pages[page]:
            self.results.append((page, sentence, False,
                                 "this sentence is no longer on the page; the assertion "
                                 "checking it has to be updated with it"))
        else:
            self.results.append((page, sentence, ok, detail))
        if not self.results[-1][2]:
            raise Failure(f"docs/{page}.md: {sentence!r}: {self.results[-1][3]}")

    # ── shell and compose ────────────────────────────────────────────────────

    def sh(self, cmd: list[str], *, check=True, stdin=None, env=None, timeout=600) -> subprocess.CompletedProcess:
        p = subprocess.run(cmd, cwd=self.work, input=stdin, capture_output=True,
                           env={**os.environ, **(env or {})}, timeout=timeout)
        if check and p.returncode != 0:
            raise Failure(f"{' '.join(cmd)} exited {p.returncode}:\n"
                          f"{p.stderr.decode(errors='replace')[-1500:]}")
        return p

    def compose(self, *args: str, core: str, gateway: str, core_env: dict | None = None, check=True,
                stdin=None, timeout=600) -> subprocess.CompletedProcess:
        """docker compose with the core and gateway versions this step runs, and
        any environment the core is to be given on top of the quickstart's."""
        files = ["-f", "docker-compose.quickstart.yml"]
        services: dict[str, list[str]] = {}
        if core == "tree":
            services["core"] = [f"    image: {TREE_IMAGE}"]
            services["migrate"] = [f"    image: {TREE_IMAGE}"]
        if core_env:
            services.setdefault("core", []).append("    environment:")
            services["core"] += [f"      {k}: {json.dumps(v)}" for k, v in core_env.items()]
        if services:
            body = "".join(f"  {name}:\n" + "\n".join(lines) + "\n" for name, lines in services.items())
            (self.work / "override.yml").write_text("services:\n" + body)
            files += ["-f", "override.yml"]
        env = {"CERTPILOT_VERSION": core if core != "tree" else "unused",
               "GATEWAY_VERSION": gateway}
        return self.sh(["docker", "compose", "-p", PROJECT, *files, *args],
                       check=check, stdin=stdin, env=env, timeout=timeout)

    def psql(self, sql: str, db="certpilot") -> str:
        p = self.compose("exec", "-T", "postgres", "psql", "-U", "certpilot", "-d", db, "-Atq",
                         "-v", "ON_ERROR_STOP=1", "-c", sql, core=self.args.to, gateway=self.args.gateway)
        return p.stdout.decode().strip()

    def container(self, service: str) -> dict:
        p = self.sh(["docker", "inspect", f"{PROJECT}-{service}-1"])
        return json.loads(p.stdout)[0]["State"]

    def wait_core(self, timeout=180) -> str:
        """'healthy', or 'exited N' if the core stopped, whichever comes first."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = self.container("core")
            if st["Status"] == "exited":
                return f"exited {st['ExitCode']}"
            if st.get("Health", {}).get("Status") == "healthy":
                return "healthy"
            time.sleep(1)
        raise Failure(f"the core neither became healthy nor exited within {timeout}s")

    def start_core(self, core: str, env: dict | None = None) -> str:
        self.compose("up", "-d", "--force-recreate", "--no-deps", "core",
                     core=core, gateway=self.args.gateway, core_env=env)
        return self.wait_core()

    def core_log(self, core: str, env: dict | None = None) -> str:
        p = self.compose("logs", "--no-log-prefix", "core", core=core, gateway=self.args.gateway,
                         core_env=env, check=False)
        return p.stdout.decode(errors="replace")

    def stop_core(self):
        self.compose("stop", "core", core=self.args.to, gateway=self.args.gateway)

    def restore(self, dump: pathlib.Path):
        self.stop_core()
        self.psql("DROP DATABASE certpilot WITH (FORCE)", db="postgres")
        self.psql("CREATE DATABASE certpilot OWNER certpilot", db="postgres")
        self.compose("exec", "-T", "postgres", "pg_restore", "-U", "certpilot", "-d", "certpilot",
                     "--no-owner", core=self.args.to, gateway=self.args.gateway, stdin=dump.read_bytes())

    def dump(self, name: str) -> pathlib.Path:
        p = self.compose("exec", "-T", "postgres", "pg_dump", "-U", "certpilot", "-d", "certpilot",
                         "--format=custom", core=self.args.to, gateway=self.args.gateway)
        path = self.work / name
        path.write_bytes(p.stdout)
        return path

    # ── the API ──────────────────────────────────────────────────────────────

    def call(self, method: str, path: str, body=None, timeout=60) -> tuple[int, object]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(API + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with self.http.open(req, timeout=timeout) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode(errors="replace")

    @staticmethod
    def data(body):
        return body.get("data", body) if isinstance(body, dict) else body

    def sign_in(self, core: str):
        if not self.password:
            m = re.search(r"password:\s*(\S+)", self.core_log(core))
            if not m:
                raise Failure("the first-run password is not in the core's log")
            self.password = m.group(1)
        self.jar.clear()
        code, body = self.call("POST", "/auth/login", {"email": "you@example.com", "password": self.password})
        if code != 200:
            raise Failure(f"sign-in answered {code}: {body}")

    def issue(self, account: str, name: str) -> tuple[int, object]:
        return self.call("POST", "/certificates", {
            "common_name": name, "ca_account_id": account,
            "key_type": "ECDSA", "key_size": 256, "auto_renew": True})

    def key_matches(self, cert_id: str) -> tuple[int, bool]:
        """Whether the exported private key is the one the certificate certifies."""
        code, cert = self.call("GET", f"/certificates/{cert_id}")
        kcode, key = self.call("GET", f"/certificates/{cert_id}/private-key")
        if code != 200 or kcode != 200:
            return kcode, False
        key = self.data(key)
        pem = key.get("private_key_pem") if isinstance(key, dict) else key
        a = self.spki(["openssl", "x509", "-noout", "-pubkey"], self.data(cert)["certificate_pem"])
        b = self.spki(["openssl", "pkey", "-pubout"], pem)
        return kcode, bool(a) and a == b

    @staticmethod
    def spki(cmd: list[str], pem: str) -> str:
        p = subprocess.run(cmd, input=pem.encode(), capture_output=True)
        return p.stdout.decode().strip()

    def renew(self, cert_id: str, timeout=60) -> str:
        code, body = self.call("POST", f"/certificates/{cert_id}/renew")
        if code != 202:
            return f"renew answered {code}: {body}"
        job = self.data(body)["id"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, b = self.call("GET", f"/renewals/{job}")
            status = self.data(b)["status"]
            if status in ("SUCCEEDED", "FAILED", "CANCELLED"):
                return status
            time.sleep(2)
        return "still pending"

    def audit(self) -> dict:
        _, body = self.call("GET", "/audit/verify")
        return body

    # ── the drill ────────────────────────────────────────────────────────────

    def run(self):
        a = self.args
        for f in ("docker-compose.quickstart.yml", "config.quickstart.yaml"):
            shutil.copy(ROOT / "deploy" / f, self.work / f)

        if a.to == "tree":
            t = time.monotonic()
            self.sh(["docker", "build", "-q", "-f", str(ROOT / "deploy" / "docker" / "core.Dockerfile"), "-t", TREE_IMAGE,
                     "--build-arg", "VERSION=0.0.0-recovery-drill", str(ROOT)], timeout=1800)
            self.measured.append(f"core image built from this tree in {time.monotonic() - t:.0f}s")

        # ── 1. The release being upgraded from, with real state in it ───────
        print(f"── 1. core {a.from_} with gateway {a.from_gateway}")
        self.compose("up", "-d", "--wait", "core", core=a.from_, gateway=a.from_gateway, timeout=900)
        self.sign_in(a.from_)
        code, body = self.call("POST", "/ca-accounts", {
            "name": "selfsigned-eval", "provider_type": "selfsigned",
            "gateway_addr": "gateway-selfsigned:9091", "server_name": "localhost",
            "config": {"validity_days": 90}})
        if code not in (200, 201):
            raise Failure(f"creating the CA account answered {code}: {body}")
        account = self.data(body)["id"]
        code, body = self.issue(account, "before-upgrade.drill.test")
        if code not in (200, 201):
            raise Failure(f"issuing on {a.from_} answered {code}: {body}")
        cert = self.data(body)["id"]
        serial = self.data(body).get("serial_number")
        _, matched = self.key_matches(cert)
        if not matched:
            raise Failure(f"on {a.from_}, the exported key did not match its certificate")
        before = self.psql("SELECT max(version) FROM schema_migrations")
        print(f"   state: CA account, one certificate, schema at {before}")

        # ── 2. The new core before migrating ────────────────────────────────
        print("── 2. the new core, before migrating")
        self.stop_core()
        outcome = self.start_core(a.to)
        log = self.core_log(a.to)
        self.claim("operations", "A core started on an older schema refuses, naming both versions:",
                   outcome.startswith("exited") and f"schema is at migration {before}" in log,
                   f"the core {outcome}; its log does not name migration {before}")

        # ── 3. An interrupted migration, finished by running it again ───────
        print("── 3. an interrupted migration")
        files = sorted(p.name for p in (ROOT / "migrations").glob("*.sql"))
        pending = [f for f in files if f.split("_", 1)[0] > before]
        if pending:
            # Applied, never recorded: what a migrator killed between the two
            # steps leaves behind.
            self.compose("exec", "-T", "postgres", "psql", "-U", "certpilot", "-d", "certpilot", "-q",
                         "-v", "ON_ERROR_STOP=1", core=a.to, gateway=a.gateway,
                         stdin=(ROOT / "migrations" / pending[0]).read_bytes())
        t = time.monotonic()
        mig = self.compose("run", "--rm", "migrate", core=a.to, gateway=a.gateway)
        self.measured.append(f"{len(pending)} migration(s) applied in {time.monotonic() - t:.1f}s")
        again = self.compose("run", "--rm", "migrate", core=a.to, gateway=a.gateway)
        after = self.psql("SELECT max(version) FROM schema_migrations")
        out = (mig.stdout + mig.stderr + again.stdout + again.stderr).decode(errors="replace")
        self.claim("operations",
                   "A migration run that stops part-way is finished by running it again: each file "
                   "applies whole or not at all, and a file that applied but was never recorded "
                   "applies again harmlessly.",
                   after == files[-1].split("_", 1)[0] and "up to date" in out,
                   f"after two runs the schema is at {after}, want {files[-1]}")

        # ── 4. The upgraded core ────────────────────────────────────────────
        print(f"── 4. the upgraded core, with gateway {a.gateway}")
        self.compose("up", "-d", "--no-deps", "--force-recreate", "--wait", "gateway-selfsigned",
                     core=a.to, gateway=a.gateway)
        outcome = self.start_core(a.to)
        if outcome != "healthy":
            raise Failure(f"the upgraded core {outcome} on a migrated schema")
        self.sign_in(a.to)
        self.check_estate(account, cert, serial, "after the upgrade")
        # A CA account from before v0.2.0 has no server_name: v0.1.x never
        # stored it. Issuing through it is what #132 fixed.
        if a.from_.startswith("0.1."):
            code, body = self.issue(account, "after-upgrade.drill.test")
            self.claim("troubleshooting",
                       "If the account's address is a gateway in the config file, the connection "
                       "made for that gateway serves it.",
                       code in (200, 201) and self.data(body).get("status") == "ISSUED",
                       f"issuing through the v{a.from_} account answered {code}: {body}")

        # ── 5. Rolling the binary back, then forward ────────────────────────
        print(f"── 5. rolling back to core {a.from_}")
        outcome = self.start_core(a.from_)
        self.sign_in(a.from_)
        code, _ = self.call("GET", f"/certificates/{cert}")
        self.claim("operations",
                   "A newer schema than the core needs is accepted, so rolling the binary back "
                   "after a migration still starts.",
                   outcome == "healthy" and code == 200 and self.audit().get("intact") is True,
                   f"core {a.from_} on the migrated schema: {outcome}, reading a certificate "
                   f"answered {code}")
        if self.start_core(a.to) != "healthy":
            raise Failure("the core did not come back after rolling forward again")
        self.sign_in(a.to)

        # ── 6. Back up, lose the database, restore ──────────────────────────
        print("── 6. a backup restored into an empty database")
        backup = self.dump("after-upgrade.dump")
        t = time.monotonic()
        self.restore(backup)
        outcome = self.start_core(a.to)
        self.measured.append(f"restore of a {backup.stat().st_size // 1024} KiB dump to a healthy "
                             f"core: {time.monotonic() - t:.1f}s")
        if outcome != "healthy":
            raise Failure(f"the core {outcome} on the restored database")
        self.sign_in(a.to)
        self.check_estate(account, cert, serial, "after the restore", claim=True)

        # ── 7. The wrong key ────────────────────────────────────────────────
        print("── 7. the restored database, started with the wrong key")
        self.restore(backup)
        rows = self.psql("SELECT count(*) FROM audit_logs")
        wrong = base64.b64encode(secrets.token_bytes(32)).decode()
        wrong_key = {"CERTPILOT_KEK": wrong}
        outcome = self.start_core(a.to, env=wrong_key)
        log = self.core_log(a.to, env=wrong_key)
        sealed_by = re.search(r"sealed with key encryption key ([0-9a-f]{16})", log)
        self.claim("operations", "Given the wrong key, the core refuses to start.",
                   outcome.startswith("exited") and sealed_by is not None
                   and self.psql("SELECT count(*) FROM audit_logs") == rows,
                   f"the core {outcome}; audit rows {rows} before and "
                   f"{self.psql('SELECT count(*) FROM audit_logs')} after")

        # ── 8. Giving up a lost key ─────────────────────────────────────────
        print("── 8. giving the lost key up, and reissuing")
        abandon = {**wrong_key, "CERTPILOT_KEK_ABANDON": sealed_by.group(1)}
        outcome = self.start_core(a.to, env=abandon)
        if outcome != "healthy":
            raise Failure(f"with CERTPILOT_KEK_ABANDON naming the sealing key the core {outcome}")
        last = self.psql("SELECT action FROM audit_logs ORDER BY seq DESC LIMIT 1")
        self.claim("operations",
                   "The core starts, and writes a secrets.kek_abandoned audit entry, signed with the "
                   "new key, naming the one given up.",
                   last == "secrets.kek_abandoned", f"the newest audit entry is {last!r}")
        self.sign_in(a.to)
        kcode, _ = self.key_matches(cert)
        code, body = self.call("POST", "/ca-accounts", {
            "name": "selfsigned-after-loss", "provider_type": "selfsigned",
            "gateway_addr": "gateway-selfsigned:9091", "server_name": "localhost",
            "config": {"validity_days": 90}})
        icode, ibody = self.issue(self.data(body)["id"], "reissued.drill.test") if code in (200, 201) else (code, body)
        self.claim("operations",
                   "Then recreate those accounts, targets, channels and connections, and reissue the "
                   "certificates whose keys CertPilot held.",
                   kcode >= 500 and icode in (200, 201),
                   f"the lost key's export answered {kcode} (want a failure), a new account's "
                   f"issuance answered {icode}: {ibody}")
        outcome = self.start_core(a.to, env=wrong_key)
        self.claim("operations", "Remove the variable afterwards: the next start no longer needs it.",
                   outcome == "healthy", f"without the override the core {outcome}")

    def check_estate(self, account: str, cert: str, serial: str, when: str, claim=False):
        code, body = self.call("GET", f"/certificates/{cert}")
        if code != 200:
            raise Failure(f"{when}, the certificate from before answered {code}: {body}")
        _, matched = self.key_matches(cert)
        intact = self.audit().get("intact") is True
        renewed = self.renew(cert)
        code, body = self.issue(account, f"{when.replace(' ', '-')}.drill.test")
        issued = code in (200, 201) and self.data(body).get("status") == "ISSUED"
        detail = (f"{when}: key matches {matched}, audit intact {intact}, renewal {renewed}, "
                  f"issuance {code}")
        if claim:
            self.claim("operations",
                       "Restored with the key that sealed it, the database reads as it did: the audit "
                       "chain checks, the private keys CertPilot holds still match their certificates, "
                       "and renewal and issuance work.",
                       matched and intact and renewed == "SUCCEEDED" and issued, detail)
        elif not (matched and intact and renewed == "SUCCEEDED" and issued):
            raise Failure(detail)
        print(f"   {detail}")

    def teardown(self):
        if not self.args.keep:
            self.compose("down", "-v", "--remove-orphans", core=self.args.to, gateway=self.args.gateway,
                         check=False)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="from_", default="0.1.1", help="the released core to upgrade from")
    ap.add_argument("--from-gateway", default="0.3.0", help="the self-signed gateway that release ran with")
    ap.add_argument("--to", default="tree", help='"tree" builds this checkout; or a released version')
    ap.add_argument("--gateway", default="0.4.0", help="the self-signed gateway to upgrade to")
    ap.add_argument("--workdir", type=pathlib.Path, help="somewhere Docker can bind-mount")
    ap.add_argument("--keep", action="store_true", help="leave the stack running afterwards")
    args = ap.parse_args()

    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", 8080)) == 0:
            print("port 8080 is in use. The quickstart needs it free, and so does this.")
            return 2

    drill = Drill(args)
    started = time.monotonic()
    failed = None
    try:
        drill.run()
    except (Failure, subprocess.TimeoutExpired) as e:
        failed = e
    finally:
        drill.teardown()

    print()
    for page, sentence, ok, detail in drill.results:
        print(f"{'ok  ' if ok else 'FAIL'} docs/{page}.md: {' '.join(sentence.split())[:110]}")
        if not ok or detail and os.environ.get("VERBOSE"):
            print(f"     {detail}")
    for m in drill.measured:
        print(f"measured: {m}")
    print(f"whole run {time.monotonic() - started:.0f}s")
    if failed:
        print(f"\n{failed}")
        return 1
    print(f"{len(drill.results)} of {len(drill.results)} claims hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
