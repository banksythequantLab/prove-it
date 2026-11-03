"""
Prove-It eDiscovery -- sandboxed first-pass review. Control plane.

Every file is opened in its own throwaway sandbox (no network, read-only
evidence, 512 MB, 20 s). The model ranks, with every quote verified against
the document. The human decides. Nothing here makes a final call.

Runs with a real Docker daemon (each file in its own cage) or, when none is
present, in a DEGRADED in-process mode that it labels loudly -- the limits
still apply but there is no kernel-enforced isolation.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "collection"))

import cage as cage_mod            # noqa: E402
import parse_entry                 # noqa: E402
import rank as rankmod             # noqa: E402
from audit import AuditLog         # noqa: E402
from inference import VultrInference, InferenceError  # noqa: E402
from store import Store            # noqa: E402

RUN = Path(os.environ.get("PROVEIT_RUN", "/var/lib/proveit"))
COLLECTION = Path(os.environ.get("PROVEIT_COLLECTION", "collection/demo"))
CAGE_IMAGE = os.environ.get("PROVEIT_CAGE_IMAGE", "faraday-cage:latest")
UI = HERE.parent / "ui" / "proveit.html"

DEFAULT_ISSUES = {
    "ca_trading": "California power trading strategies (congestion relief, "
                  "Ricochet, export/import gaming, scheduling)",
    "raptor_ljm_spe": "Raptor / LJM special-purpose entities and related-party "
                      "hedges or transfers",
    "doc_retention": "document retention, preservation, or destruction "
                     "instructions (incl. Arthur Andersen)",
}
PRIVILEGE_SIGNALS = ["attorney / outside counsel named", "\"privileged\" or "
                     "\"work product\" on the face", "legal advice sought or given"]

app = FastAPI(title="Prove-It eDiscovery")
store = Store(RUN / "run.db")
audit = AuditLog(RUN / "audit.db")
inference = VultrInference()

_state = {"ingest": {"running": False, "done": 0, "total": 0, "contained": False},
          "rank": {"running": False, "done": 0, "total": 0}}


def docker_ok() -> bool:
    try:
        import docker
        docker.from_env().ping()
        return True
    except Exception:
        return False


# ---- ingest ---------------------------------------------------------------
def _parse_one(f: Path, contained: bool) -> dict:
    if contained:
        runner = cage_mod.CageRunner()
        job = cage_mod.CageJob(
            job_id=f.stem[:12], profile=cage_mod.PARSE, image=CAGE_IMAGE,
            command=["python3", "/opt/faraday/parse_entry.py"],
            input_path=f)
        res = runner.run(job)
        if res.verdict:
            return res.verdict
        return {"ok": False, "file": f.name, "ext": f.suffix.lower(),
                "status": "needs_manual", "kill_kind": "cage_error",
                "kill_reason": f"cage returned no verdict "
                               f"(exit={res.exit_code} timeout={res.timed_out})",
                "sha256": "", "bytes": f.stat().st_size, "parse_s": res.duration_s}
    return parse_entry.parse_path(f)


def _ingest_worker(contained: bool) -> None:
    files = sorted([p for p in COLLECTION.iterdir()
                    if p.is_file() and p.name not in ("manifest.json",)])
    _state["ingest"].update(running=True, done=0, total=len(files),
                            contained=contained)
    audit.append("ingest_start", {"files": len(files), "contained": contained})
    for f in files:
        v = _parse_one(f, contained)
        store.upsert_ingest(
            v.get("file", f.name),
            file=v.get("file", f.name), type=v.get("ext", f.suffix).lstrip("."),
            bytes=v.get("bytes", 0), sha256_ingest=v.get("sha256", ""),
            status=v.get("status", "needs_manual"),
            kill_kind=v.get("kill_kind"), kill_reason=v.get("kill_reason"),
            parse_s=v.get("parse_s", 0), text_chars=v.get("text_chars", 0),
            headers=v.get("headers", {}), text=v.get("text", ""))
        if v.get("status") == "needs_manual":
            audit.append("contained", {"file": v.get("file", f.name),
                                       "kill": v.get("kill_reason")})
        _state["ingest"]["done"] += 1
    store.set_meta("ingested", True)
    store.set_meta("contained", contained)
    audit.append("ingest_done", {"parsed": len(store.parsed()),
                                 "needs_manual": len(store.needs_manual())})
    _state["ingest"]["running"] = False


# ---- rank -----------------------------------------------------------------
def _rank_worker(issues: dict) -> None:
    docs = store.parsed()
    _state["rank"].update(running=True, done=0, total=len(docs))
    for d in docs:
        try:
            r = rankmod.rank_document(inference, d["docid"], d["text"] or "", issues)
            store.set_ranking(d["docid"], r.to_dict())
        except Exception as exc:
            store.set_ranking(d["docid"],
                              {"overall": 0, "error": str(exc)[:120], "issues": {}})
        _state["rank"]["done"] += 1
    store.set_meta("ranked", True)
    audit.append("rank_done", {"docs": len(docs), "model": inference.text_model})
    _state["rank"]["running"] = False


# ---- routes ---------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    return UI.read_text() if UI.exists() else "<h1>Prove-It</h1>"


@app.get("/api/health")
def health():
    d = docker_ok()
    return {"ok": True, "docker": d, "contained": d,
            "model": inference.text_model or None,
            "collection_dir": str(COLLECTION),
            "collection_present": COLLECTION.is_dir(),
            "ingested": bool(store.get_meta("ingested")),
            "ranked": bool(store.get_meta("ranked")),
            "warning": None if d else "No Docker: ingest runs DEGRADED "
                       "(in-process, limits apply but no kernel isolation)."}


@app.post("/api/ingest")
def ingest():
    if _state["ingest"]["running"]:
        return {"ok": True, "already": True}
    if not COLLECTION.is_dir():
        raise HTTPException(400, f"collection not found at {COLLECTION}")
    contained = docker_ok()
    threading.Thread(target=_ingest_worker, args=(contained,), daemon=True).start()
    return {"ok": True, "contained": contained}


@app.get("/api/ingest/status")
def ingest_status():
    st = dict(_state["ingest"])
    st["type_counts"] = store.type_counts()
    st["needs_manual"] = store.needs_manual()
    st["parsed"] = len(store.parsed())
    return st


@app.get("/api/protocol")
def get_protocol():
    return {"issues": store.get_meta("issues", DEFAULT_ISSUES),
            "privilege_signals": PRIVILEGE_SIGNALS}


@app.post("/api/protocol")
def set_protocol(issues_json: str = Form(...)):
    store.set_meta("issues", json.loads(issues_json))
    return {"ok": True}


@app.post("/api/rank")
def do_rank():
    if _state["rank"]["running"]:
        return {"ok": True, "already": True}
    if not inference.text_model:
        try:
            inference.text_model = os.environ.get("FARADAY_TEXT_MODEL") or \
                inference.resolve_models()[0]
        except InferenceError as e:
            raise HTTPException(400, str(e))
    issues = store.get_meta("issues", DEFAULT_ISSUES)
    threading.Thread(target=_rank_worker, args=(issues,), daemon=True).start()
    return {"ok": True, "model": inference.text_model}


@app.get("/api/rank/status")
def rank_status():
    return dict(_state["rank"])


@app.get("/api/queue")
def queue():
    rows = store.queue()
    out = []
    for r in rows:
        rk = json.loads(r["ranking"]) if r["ranking"] else {}
        out.append({
            "docid": r["docid"], "file": r["file"], "type": r["type"],
            "overall": r["overall"], "privilege_signal": bool(r["privilege_signal"]),
            "issues": {k: v["score"] for k, v in (rk.get("issues") or {}).items()},
            "coded_responsive": r["coded_responsive"],
            "coded_hot": r["coded_hot"], "coded_privileged": r["coded_privileged"],
        })
    return {"ok": True, "queue": out}


@app.get("/api/doc/{docid}")
def doc(docid: str):
    d = store.get(docid)
    if not d:
        raise HTTPException(404, "unknown doc")
    return {"ok": True, "docid": docid, "file": d["file"], "type": d["type"],
            "headers": json.loads(d["headers"] or "{}"),
            "text": d["text"] or "", "sha256_ingest": d["sha256_ingest"],
            "ranking": json.loads(d["ranking"]) if d["ranking"] else None,
            "coded_responsive": d["coded_responsive"], "coded_hot": d["coded_hot"],
            "coded_privileged": d["coded_privileged"]}


@app.post("/api/code/{docid}")
def code(docid: str, responsive: int = Form(...), hot: int = Form(0),
         privileged: int = Form(0), by: str = Form("reviewer")):
    if not store.get(docid):
        raise HTTPException(404, "unknown doc")
    store.code(docid, responsive, hot, privileged, by)
    audit.append("coded", {"docid": docid, "responsive": responsive,
                           "hot": hot, "privileged": privileged, "by": by})
    return {"ok": True}


@app.get("/api/qc")
def qc():
    """Model-vs-human agreement on coded docs, and an elusion sample: a random
    sample of LOW-scored docs, where the model expects few responsives, so a
    reviewer can check what it may have missed."""
    import random
    coded = store.coded()
    agree = disagree = 0
    rows = []
    for d in coded:
        model_resp = 1 if d["overall"] >= 50 else 0
        human_resp = d["coded_responsive"]
        if human_resp is None:
            continue
        ok = model_resp == human_resp
        agree += ok
        disagree += not ok
        rows.append({"docid": d["docid"], "overall": d["overall"],
                     "model_responsive": model_resp, "human_responsive": human_resp,
                     "agree": ok})
    low = [d for d in store.parsed() if 0 <= d["overall"] < 50]
    rng = random.Random(7)
    sample = rng.sample(low, min(15, len(low))) if low else []
    return {"ok": True,
            "coded": len(rows), "agree": agree, "disagree": disagree,
            "agreement_pct": round(100 * agree / len(rows), 1) if rows else None,
            "rows": rows[:50],
            "elusion": {"low_pool": len(low), "sampled": len(sample),
                        "docids": [d["docid"] for d in sample],
                        "note": "sample of low-scored documents; code these to "
                                "estimate what first-pass ranking missed"}}


@app.get("/api/custody")
def custody():
    """Re-hash every file on disk and compare to the hash taken at ingest."""
    match = mismatch = missing = 0
    rows = []
    for d in store.all():
        f = COLLECTION / d["file"]
        if not f.exists():
            missing += 1
            rows.append({"file": d["file"], "status": "MISSING"})
            continue
        import hashlib
        h = hashlib.sha256(f.read_bytes()).hexdigest()
        ok = (h == d["sha256_ingest"]) if d["sha256_ingest"] else None
        if ok is True:
            match += 1
        elif ok is False:
            mismatch += 1
            rows.append({"file": d["file"], "status": "ALTERED",
                         "ingest": d["sha256_ingest"][:16], "now": h[:16]})
    total = len(store.all())
    audit.append("custody_rehash", {"match": match, "mismatch": mismatch,
                                     "missing": missing, "total": total})
    return {"ok": True, "total": total, "match": match, "mismatch": mismatch,
            "missing": missing,
            "verdict": f"{match}/{total} match" if mismatch == 0 and missing == 0
                       else f"{mismatch} ALTERED, {missing} missing",
            "rows": rows[:50], "chain_valid": audit.verify()["valid"]}


@app.get("/api/audit")
def audit_log():
    return {"ok": True, "verification": audit.verify(),
            "entries": [{"seq": e.seq, "event": e.event, "payload": e.payload,
                         "hash": e.hash[:12]} for e in audit][-100:]}


@app.get("/api/export/{kind}")
def export(kind: str):
    if kind == "coding":
        lines = ["docid,file,overall,model_responsive,human_responsive,hot,privileged,coded_by"]
        for d in store.all():
            mr = 1 if d["overall"] >= 50 else 0
            lines.append(",".join(str(x) for x in [
                d["docid"], d["file"], d["overall"], mr,
                d["coded_responsive"] if d["coded_responsive"] is not None else "",
                d["coded_hot"] or "", d["coded_privileged"] or "", d["coded_by"] or ""]))
        return PlainTextResponse("\n".join(lines), media_type="text/csv")
    if kind == "privilege":
        lines = ["docid,file,privilege_signal,privilege_rationale,human_privileged"]
        for d in store.all():
            rk = json.loads(d["ranking"]) if d["ranking"] else {}
            lines.append(",".join('"%s"' % str(x).replace('"', "'") for x in [
                d["docid"], d["file"], bool(d["privilege_signal"]),
                rk.get("privilege_rationale", ""),
                d["coded_privileged"] if d["coded_privileged"] is not None else ""]))
        return PlainTextResponse("\n".join(lines), media_type="text/csv")
    if kind == "audit":
        out = [json.dumps({"seq": e.seq, "event": e.event, "payload": e.payload,
                           "hash": e.hash, "prev": e.prev_hash}) for e in audit]
        return PlainTextResponse("\n".join(out), media_type="application/x-ndjson")
    raise HTTPException(404, "unknown export")
