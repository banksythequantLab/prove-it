"""
Faraday control plane. Runs on the Vultr Cloud Compute instance.

This process is the central control layer: it owns the review queue, spawns and
reaps every cage, holds the human approval gate, talks to Vultr Serverless
Inference, and serves the operator UI. It is not static hosting -- nothing in
the system runs without it.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit import AuditLog          # noqa: E402
from inference import VultrInference, InferenceError  # noqa: E402
from pipeline import Pipeline       # noqa: E402

DB = os.environ.get("FARADAY_DB", "/var/lib/faraday/faraday.db")
CORPUS = Path(os.environ.get("FARADAY_CORPUS_DIR", "corpus/generated"))
SINK_LOG = Path(os.environ.get("FARADAY_SINK_LOG", "/var/log/faraday/egress.jsonl"))
UI = Path(__file__).resolve().parents[1] / "ui" / "index.html"

app = FastAPI(title="Faraday", version="0.1.0")
audit = AuditLog(DB)
inference = VultrInference()
pipeline = Pipeline(
    audit, inference,
    cage_image=os.environ.get("FARADAY_CAGE_IMAGE", "faraday-cage:latest"),
    cage_net=os.environ.get("FARADAY_CAGE_NET", "faraday-internal"),
    sinkhole_log=SINK_LOG,
)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return UI.read_text() if UI.exists() else "<h1>Faraday</h1><p>ui/index.html missing</p>"


@app.get("/api/health")
def health() -> dict:
    import docker
    daemon = False
    detail = ""
    try:
        docker.from_env().ping()
        daemon = True
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"[:160]
    return {
        "ok": True,
        "docker_daemon": daemon,
        "docker_detail": detail,
        "contained": daemon,
        "warning": None if daemon else
                   "No Docker daemon: reviews will run UNCONTAINED in degraded mode.",
        "text_model": inference.text_model or None,
        "vision_model": inference.vision_model or None,
        "audit_head": audit.head()[:16],
    }


@app.get("/api/models")
def models() -> JSONResponse:
    """Live Vultr Serverless Inference catalogue. Never assume a model ID."""
    try:
        return JSONResponse({"ok": True, "models": inference.resolve_models()})
    except InferenceError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"{type(exc).__name__}: {exc}"},
                            status_code=502)


@app.get("/api/corpus")
def corpus() -> dict:
    import json
    man = CORPUS / "manifest.json"
    if not man.exists():
        return {"ok": False, "error": f"no corpus at {CORPUS}; run corpus/generate.py"}
    return {"ok": True, "documents": json.loads(man.read_text())}


@app.post("/api/review")
def review(doc_id: str = Form(...)) -> JSONResponse:
    src = CORPUS / f"{doc_id}.pdf"
    if not src.exists():
        raise HTTPException(404, f"{doc_id} not in corpus")
    return JSONResponse(pipeline.review(src).to_dict())


@app.post("/api/review/upload")
async def review_upload(file: UploadFile = File(...)) -> JSONResponse:
    tmp = Path(tempfile.mkdtemp()) / (file.filename or "upload.pdf")
    with tmp.open("wb") as fh:
        shutil.copyfileobj(file.file, fh)
    try:
        return JSONResponse(pipeline.review(tmp).to_dict())
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)


@app.get("/api/reviews")
def reviews() -> dict:
    return {"ok": True, "reviews": pipeline.results()}


@app.post("/api/review/{job_id}/approve")
def approve(job_id: str, approver: str = Form(...)) -> JSONResponse:
    if pipeline.get(job_id) is None:
        raise HTTPException(404, "unknown job")
    return JSONResponse(pipeline.approve(job_id, approver).to_dict())


@app.get("/api/containment")
def containment() -> dict:
    """The Containment Log: every egress attempt the sinkhole absorbed."""
    attempts = pipeline.read_egress()
    return {"ok": True, "count": len(attempts), "attempts": attempts}


@app.get("/api/audit")
def audit_chain(limit: int = 200) -> dict:
    entries = [{
        "seq": e.seq, "ts": e.ts, "event": e.event, "job_id": e.job_id,
        "payload": e.payload, "hash": e.hash, "prev_hash": e.prev_hash,
    } for e in audit][-limit:]
    return {"ok": True, "verification": audit.verify(), "entries": entries}
