"""Tamper-evidence of the audit chain."""
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator"))
import audit  # noqa: E402


def _log():
    tmp = Path(tempfile.mkdtemp()) / "audit.db"
    return audit.AuditLog(tmp)


def test_chain_verifies_when_untouched():
    log = _log()
    for i in range(6):
        log.append("classified", {"doc": f"DOC_{i:04d}", "label": "privileged"})
    r = log.verify()
    assert r["valid"] and r["checked"] == 6


def test_retroactive_edit_breaks_the_chain():
    """The whole point: you cannot quietly rewrite a privilege call after the fact."""
    log = _log()
    for i in range(5):
        log.append("classified", {"doc": f"DOC_{i:04d}", "label": "privileged"})
    assert log.verify()["valid"]

    conn = sqlite3.connect(str(log.path))
    conn.execute("UPDATE audit SET payload=? WHERE seq=3",
                 ('{"doc":"DOC_0002","label":"responsive"}',))
    conn.commit(); conn.close()

    r = log.verify()
    assert not r["valid"], "edited entry must invalidate the chain"
    assert r["broken_at"] == 3


def test_deleting_an_entry_breaks_the_chain():
    log = _log()
    for i in range(5):
        log.append("egress_blocked", {"host": "exfil-example.invalid"})
    conn = sqlite3.connect(str(log.path))
    conn.execute("DELETE FROM audit WHERE seq=2"); conn.commit(); conn.close()
    assert not log.verify()["valid"]


def test_genesis_links_to_zero():
    log = _log()
    e = log.append("ingest", {"n": 1})
    assert e.prev_hash == audit.GENESIS_PREV
    assert log.head() == e.hash
