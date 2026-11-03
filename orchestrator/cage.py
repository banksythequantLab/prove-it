"""
The cage: per-job Docker container with a deny-by-default posture.

Faraday runs untrusted documents through TWO cage profiles, because the two
stages have different threat models:

  PARSE  (network_mode="none")
      The untrusted file is parsed and rasterised here. The adversary is a
      malformed document attacking the parser. Nothing in this stage has any
      legitimate need for a socket, so it gets none at all.

  AGENT  (network_mode=<internal bridge>)
      The agent reasons over extracted artefacts and may act. The adversary is
      a prompt injection steering the agent. This stage DOES get a network --
      an internal bridge whose only resident is the sinkhole -- precisely so
      that an exfiltration attempt is RECORDED rather than silently failing.
      A dead network makes containment invisible; a sinkholed one makes it
      demonstrable.

Everything about the posture lives in build_run_kwargs(), which is a pure
function. That is deliberate: the security properties can be asserted in a
unit test with no Docker daemon present.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

PARSE = "parse"
AGENT = "agent"
Profile = Literal["parse", "agent"]

# Dropped unconditionally. Note docker's default set is already reduced, but
# cap_drop=ALL removes CHOWN/SETUID/NET_RAW etc. that a payload could lean on.
CAP_DROP_ALL = ["ALL"]


@dataclass
class CageLimits:
    memory: str = "512m"
    cpus: float = 1.0
    pids: int = 128
    timeout_s: int = 60
    tmpfs_size: str = "64m"


@dataclass
class CageJob:
    job_id: str
    profile: Profile
    image: str
    command: list[str]
    input_path: Path | None = None       # bind-mounted READ ONLY at /input
    output_dir: Path | None = None       # bind-mounted rw at /output
    network: str | None = None           # internal bridge name, AGENT only
    limits: CageLimits = field(default_factory=CageLimits)
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class CageResult:
    job_id: str
    exit_code: int | None
    duration_s: float
    timed_out: bool
    stdout: str
    stderr: str
    verdict: dict[str, Any] | None
    egress_attempts: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and self.verdict is not None


def build_run_kwargs(job: CageJob) -> dict[str, Any]:
    """
    Pure function: CageJob -> docker-py containers.run(**kwargs).

    Unit-tested directly. If a security flag regresses, the test fails without
    needing a daemon, which matters because the cage is the whole product.
    """
    lim = job.limits

    if job.profile == PARSE:
        network_mode = "none"
    elif job.profile == AGENT:
        if not job.network:
            raise ValueError("AGENT profile requires an internal bridge name")
        network_mode = job.network
    else:
        raise ValueError(f"unknown cage profile: {job.profile!r}")

    mounts: dict[str, dict[str, str]] = {}
    if job.input_path is not None:
        mounts[str(Path(job.input_path).resolve())] = {
            "bind": "/input/" + Path(job.input_path).name,
            "mode": "ro",
        }
    if job.output_dir is not None:
        mounts[str(Path(job.output_dir).resolve())] = {
            "bind": "/output",
            "mode": "rw",
        }

    kwargs: dict[str, Any] = {
        "image": job.image,
        "command": job.command,
        "name": f"faraday-{job.profile}-{job.job_id}",

        # --- isolation -------------------------------------------------
        "network_mode": network_mode,
        "cap_drop": CAP_DROP_ALL,
        "cap_add": [],
        "privileged": False,
        "security_opt": [
            "no-new-privileges:true",
            "seccomp=/etc/faraday/seccomp.json",
            "apparmor=docker-default",
        ],
        "read_only": True,                       # immutable rootfs
        "tmpfs": {"/work": f"rw,noexec,nosuid,nodev,size={lim.tmpfs_size}"},
        "volumes": mounts,
        "user": "65534:65534",                   # nobody; never root in the cage
        "working_dir": "/work",

        # --- resource ceilings (a fork bomb must not take the host) ----
        "mem_limit": lim.memory,
        "memswap_limit": lim.memory,             # == mem_limit disables swap
        "nano_cpos": None,                       # placeholder, removed below
        "pids_limit": lim.pids,
        "ulimits": [],

        # --- lifecycle --------------------------------------------------
        "detach": True,
        "auto_remove": False,                    # we read logs after exit
        "stdout": True,
        "stderr": True,
        "environment": {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "HOME": "/work",
            **job.env,
        },
    }
    kwargs.pop("nano_cpos")
    kwargs["nano_cpus"] = int(lim.cpus * 1_000_000_000)
    return kwargs


class CageRunner:
    """Thin wrapper over docker-py. Import-safe without a daemon."""

    def __init__(self, client=None):
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import docker
            self._client = docker.from_env()
        return self._client

    def ensure_network(self, name: str) -> None:
        """
        Create the cage bridge as INTERNAL. An internal network has no route to
        the outside world -- containers on it can reach each other and nothing
        else. The sinkhole lives here so attempts are logged, not just dropped.
        """
        import docker.errors
        try:
            net = self.client.networks.get(name)
            if not net.attrs.get("Internal", False):
                raise RuntimeError(
                    f"network {name!r} exists but is NOT internal -- refusing to "
                    f"run a cage on a network with external routing. "
                    f"Remove it and let Faraday recreate it."
                )
        except docker.errors.NotFound:
            self.client.networks.create(name, driver="bridge", internal=True)

    def run(self, job: CageJob) -> CageResult:
        kwargs = build_run_kwargs(job)
        if job.profile == AGENT:
            self.ensure_network(job.network)  # type: ignore[arg-type]

        started = time.monotonic()
        container = self.client.containers.run(**kwargs)
        timed_out = False
        exit_code: int | None = None
        try:
            try:
                res = container.wait(timeout=job.limits.timeout_s)
                exit_code = res.get("StatusCode")
            except Exception:
                timed_out = True
                container.kill()
            duration = time.monotonic() - started
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", "replace")
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

        return CageResult(
            job_id=job.job_id,
            exit_code=exit_code,
            duration_s=round(duration, 3),
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            verdict=_last_json_line(stdout),
        )


def _last_json_line(stdout: str) -> dict[str, Any] | None:
    """
    The cage speaks exactly one language back to the orchestrator: a single
    JSON object on the final line of stdout. No files, no sockets, no HTTP.
    Anything else the cage printed is diagnostic noise and is ignored.
    """
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None
