"""
Hash-chained, append-only audit log.

Every state transition in a review -- ingest, sandbox spawn, a file flagged
for manual handling, ranking, human coding, custody re-hash -- becomes a
chained entry. Each entry commits to its predecessor, so any retroactive edit
to an earlier entry invalidates every hash after it.

This is chain of custody in the sense the legal market already means it: not
"we promise we logged it" but "here is a tamper-evident sequence you can
verify independently." verify() recomputes the whole chain and names the first
broken link.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

GENESIS_PREV = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq       INTEGER PRIMARY KEY,
    ts        REAL    NOT NULL,
    event     TEXT    NOT NULL,
    job_id    TEXT,
    payload   TEXT    NOT NULL,
    prev_hash TEXT    NOT NULL,
    hash      TEXT    NOT NULL
);
"""


def _canonical(obj: Any) -> str:
    """Stable serialisation -- sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(seq: int, ts: float, event: str, job_id: str | None,
               payload: dict, prev_hash: str) -> str:
    material = _canonical({
        "seq": seq, "ts": ts, "event": event,
        "job_id": job_id, "payload": payload, "prev_hash": prev_hash,
    })
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    seq: int
    ts: float
    event: str
    job_id: str | None
    payload: dict
    prev_hash: str
    hash: str


class AuditLog:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # --- write ----------------------------------------------------------
    def append(self, event: str, payload: dict, job_id: str | None = None) -> AuditEntry:
        cur = self._conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        seq = (row[0] + 1) if row else 1
        prev = row[1] if row else GENESIS_PREV
        ts = time.time()
        h = entry_hash(seq, ts, event, job_id, payload, prev)
        self._conn.execute(
            "INSERT INTO audit (seq, ts, event, job_id, payload, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?)",
            (seq, ts, event, job_id, _canonical(payload), prev, h),
        )
        self._conn.commit()
        return AuditEntry(seq, ts, event, job_id, payload, prev, h)

    # --- read -----------------------------------------------------------
    def __iter__(self) -> Iterator[AuditEntry]:
        for r in self._conn.execute(
            "SELECT seq, ts, event, job_id, payload, prev_hash, hash FROM audit ORDER BY seq"
        ):
            yield AuditEntry(r[0], r[1], r[2], r[3], json.loads(r[4]), r[5], r[6])

    def head(self) -> str:
        row = self._conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_PREV

    # --- verify ---------------------------------------------------------
    def verify(self) -> dict:
        prev = GENESIS_PREV
        count = 0
        for e in self:
            count += 1
            if e.prev_hash != prev:
                return {"valid": False, "broken_at": e.seq,
                        "reason": "prev_hash does not match predecessor", "checked": count}
            recomputed = entry_hash(e.seq, e.ts, e.event, e.job_id, e.payload, e.prev_hash)
            if recomputed != e.hash:
                return {"valid": False, "broken_at": e.seq,
                        "reason": "entry hash does not match its contents", "checked": count}
            prev = e.hash
        return {"valid": True, "broken_at": None, "reason": None,
                "checked": count, "head": prev}
