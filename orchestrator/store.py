"""
Run store for the review workflow. SQLite, one file per run.

Holds the ingest result for every document (hash, type, parse status, kill
reason, extracted text), the model's ranking, and the human's coding. The
audit chain (audit.py) is separate and records custody events.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS docs (
  docid TEXT PRIMARY KEY,
  file TEXT, type TEXT, bytes INTEGER,
  sha256_ingest TEXT,
  status TEXT,                -- parsed | needs_manual
  kill_kind TEXT, kill_reason TEXT,
  parse_s REAL, text_chars INTEGER,
  headers TEXT,               -- json
  text TEXT,
  ranking TEXT,               -- json (RankResult.to_dict)
  overall INTEGER DEFAULT -1,
  privilege_signal INTEGER DEFAULT 0,
  coded_responsive INTEGER,   -- null=uncoded, 0/1
  coded_hot INTEGER,
  coded_privileged INTEGER,
  coded_by TEXT, coded_at REAL
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.c = sqlite3.connect(str(self.path), check_same_thread=False)
        self.c.row_factory = sqlite3.Row
        self.c.executescript(SCHEMA)
        self.c.commit()

    # meta -------------------------------------------------------------
    def set_meta(self, k: str, v) -> None:
        self.c.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, json.dumps(v)))
        self.c.commit()

    def get_meta(self, k: str, default=None):
        r = self.c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return json.loads(r["v"]) if r else default

    # docs -------------------------------------------------------------
    def upsert_ingest(self, docid: str, **f) -> None:
        f["docid"] = docid
        if "headers" in f and not isinstance(f["headers"], str):
            f["headers"] = json.dumps(f["headers"])
        cols = ",".join(f)
        ph = ",".join("?" for _ in f)
        upd = ",".join(f"{k}=excluded.{k}" for k in f if k != "docid")
        self.c.execute(
            f"INSERT INTO docs ({cols}) VALUES ({ph}) "
            f"ON CONFLICT(docid) DO UPDATE SET {upd}", list(f.values()))
        self.c.commit()

    def set_ranking(self, docid: str, ranking: dict) -> None:
        self.c.execute(
            "UPDATE docs SET ranking=?, overall=?, privilege_signal=? WHERE docid=?",
            (json.dumps(ranking), ranking.get("overall", 0),
             1 if ranking.get("privilege_signal") else 0, docid))
        self.c.commit()

    def code(self, docid: str, responsive: int | None, hot: int | None,
             privileged: int | None, by: str) -> None:
        self.c.execute(
            "UPDATE docs SET coded_responsive=?, coded_hot=?, coded_privileged=?,"
            " coded_by=?, coded_at=? WHERE docid=?",
            (responsive, hot, privileged, by, time.time(), docid))
        self.c.commit()

    def get(self, docid: str) -> dict | None:
        r = self.c.execute("SELECT * FROM docs WHERE docid=?", (docid,)).fetchone()
        return dict(r) if r else None

    def all(self) -> list[dict]:
        return [dict(r) for r in self.c.execute("SELECT * FROM docs")]

    def parsed(self) -> list[dict]:
        return [dict(r) for r in self.c.execute(
            "SELECT * FROM docs WHERE status='parsed'")]

    def needs_manual(self) -> list[dict]:
        return [dict(r) for r in self.c.execute(
            "SELECT * FROM docs WHERE status='needs_manual' ORDER BY file")]

    def queue(self) -> list[dict]:
        return [dict(r) for r in self.c.execute(
            "SELECT docid,file,type,overall,privilege_signal,ranking,"
            "coded_responsive,coded_hot,coded_privileged FROM docs "
            "WHERE status='parsed' ORDER BY overall DESC, docid")]

    def type_counts(self) -> dict:
        out = {}
        for r in self.c.execute("SELECT type,COUNT(*) n FROM docs GROUP BY type"):
            out[r["type"]] = r["n"]
        return out

    def coded(self) -> list[dict]:
        return [dict(r) for r in self.c.execute(
            "SELECT * FROM docs WHERE coded_at IS NOT NULL")]
