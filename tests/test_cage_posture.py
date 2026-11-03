"""
Security-posture assertions for the cage.

These run with NO Docker daemon: build_run_kwargs is a pure function, so the
flags that constitute the containment claim are unit-testable. If someone
loosens the cage, this fails.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator"))
import cage  # noqa: E402


def _job(profile=cage.PARSE, **kw):
    return cage.CageJob(
        job_id="t1", profile=profile, image="faraday-cage:latest",
        command=["python3", "/opt/faraday/entrypoint.py"], **kw)


def test_parse_profile_has_no_network():
    k = cage.build_run_kwargs(_job())
    assert k["network_mode"] == "none", "parse cage must have NO network at all"


def test_agent_profile_requires_explicit_bridge():
    try:
        cage.build_run_kwargs(_job(profile=cage.AGENT))
    except ValueError:
        pass
    else:
        raise AssertionError("AGENT profile must refuse to run without a bridge")


def test_agent_profile_uses_named_bridge_not_default():
    k = cage.build_run_kwargs(_job(profile=cage.AGENT, network="faraday-internal"))
    assert k["network_mode"] == "faraday-internal"
    assert k["network_mode"] not in ("bridge", "host", "", None), \
        "agent cage must never land on the default or host network"


def test_all_capabilities_dropped():
    k = cage.build_run_kwargs(_job())
    assert k["cap_drop"] == ["ALL"]
    assert k["cap_add"] == []
    assert k["privileged"] is False


def test_no_new_privileges_and_seccomp():
    """
    We rely on Docker's DEFAULT seccomp profile and must never disable it.

    A hand-written allowlist used to be pinned here. Against a real daemon it
    broke container init (missing setgroups) and ordinary fork(), while its
    one namespace rule was inverted and permitted exactly what it was meant
    to block. The default profile is the safer choice, so the requirement is
    "not unconfined" rather than "pinned".
    """
    k = cage.build_run_kwargs(_job())
    opts = k["security_opt"]
    assert "no-new-privileges:true" in opts
    assert not any("seccomp=unconfined" in o for o in opts), \
        "seccomp must never be disabled"
    assert not any("apparmor=unconfined" in o for o in opts)
    assert not any(o.startswith("seccomp=") for o in opts), \
        "do not pin a custom profile without validating it on a live daemon"


def test_rootfs_readonly_and_workdir_is_noexec_tmpfs():
    k = cage.build_run_kwargs(_job())
    assert k["read_only"] is True, "cage rootfs must be immutable"
    tm = k["tmpfs"]["/work"]
    for flag in ("noexec", "nosuid", "nodev"):
        assert flag in tm, f"/work tmpfs missing {flag}"


def test_never_runs_as_root():
    k = cage.build_run_kwargs(_job())
    assert k["user"].startswith("65534"), "cage must run as nobody, never uid 0"


def test_resource_ceilings_present():
    k = cage.build_run_kwargs(_job())
    assert k["mem_limit"] == k["memswap_limit"], "swap must be disabled"
    assert k["pids_limit"] == 128
    assert k["nano_cpus"] == 1_000_000_000


def test_input_is_mounted_read_only():
    p = Path("corpus/generated/DOC_0018.pdf").resolve()
    k = cage.build_run_kwargs(_job(input_path=p))
    b = next(b for b in k["_binds"] if b["target"].startswith("/input/"))
    assert b["read_only"] is True, "evidence file must be unmodifiable by the cage"
    assert b["source"] == str(p)


def test_docker_socket_is_never_mounted():
    p = Path("corpus/generated/DOC_0018.pdf").resolve()
    k = cage.build_run_kwargs(_job(input_path=p, output_dir=Path("/tmp/claude-0").resolve()))
    for b in k["_binds"]:
        assert "docker.sock" not in b["source"], "mounting the docker socket defeats the cage"


def test_unknown_profile_refused():
    try:
        cage.build_run_kwargs(_job(profile="yolo"))
    except ValueError:
        pass
    else:
        raise AssertionError("unknown profile must be refused, not defaulted")


def test_verdict_parser_takes_last_json_line_only():
    out = 'noise\n{"ok": false, "stale": 1}\nmore noise\n{"ok": true, "n": 2}\n'
    assert cage._last_json_line(out) == {"ok": True, "n": 2}
    assert cage._last_json_line("no json here") is None
    assert cage._last_json_line('{"broken": ') is None
