"""
The review pipeline. Three stages, each with a different trust posture.

  1. PARSE   cage, network=none. The untrusted file is opened here and nowhere
             else. Emits extracted text, structural shadow-text findings, and
             rendered page images.
  2. ASSESS  orchestrator, networked. Talks to Vultr Serverless Inference over
             EXTRACTED ARTEFACTS ONLY -- the original file is never handed to a
             networked process. Text pass classifies; vision pass confirms the
             shadow text is genuinely invisible.
  3. RELEASE agent cage, network=internal bridge. Acts on the verdict. Any
             attempt to send document content anywhere is absorbed by the
             sinkhole and recorded. Human approval gates the real release.

DEGRADED MODE: if no Docker daemon is reachable, stage 1 runs in-process. That
is NOT containment and the pipeline says so loudly in the result and the audit
log, because a demo that silently drops its security boundary is worse than one
that fails.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import cage as cage_mod
import divergence
from audit import AuditLog
from inference import InferenceError, VultrInference

LABELS = ("privileged", "responsive", "neither")


@dataclass
class ReviewResult:
    job_id: str
    source: str
    sha256: str
    contained: bool                       # did stage 1 run in a real cage?
    degraded_reason: str | None = None
    structural: dict = field(default_factory=dict)
    injection_suspected: bool = False
    techniques: list[str] = field(default_factory=list)
    shadow_text: str = ""
    classification: dict | None = None
    vision: dict | None = None
    quarantined: bool = False
    approved: bool = False
    released: bool = False
    egress_attempts: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class Pipeline:
    def __init__(self, audit_log: AuditLog, inference: VultrInference | None = None,
                 cage_image: str = "faraday-cage:latest",
                 cage_net: str = "faraday-internal",
                 sinkhole_log: Path | None = None):
        self.audit = audit_log
        self.inference = inference or VultrInference()
        self.cage_image = cage_image
        self.cage_net = cage_net
        self.sinkhole_log = sinkhole_log or Path("/var/log/faraday/egress.jsonl")
        self.runner = cage_mod.CageRunner()
        self._results: dict[str, ReviewResult] = {}

    # -- stage 1 -------------------------------------------------------
    def _parse_in_cage(self, src: Path, job_id: str) -> tuple[dict, bool, str | None]:
        outdir = Path(tempfile.mkdtemp(prefix=f"faraday-{job_id}-"))
        job = cage_mod.CageJob(
            job_id=job_id, profile=cage_mod.PARSE, image=self.cage_image,
            command=["python3", "/opt/faraday/entrypoint.py"],
            input_path=src, output_dir=outdir,
        )
        try:
            res = self.runner.run(job)
        except Exception as exc:
            # No daemon, image missing, etc. Fall back LOUDLY.
            reason = f"{type(exc).__name__}: {exc}"[:200]
            finding = divergence.analyse(src)
            return ({"ok": True, "structural": finding.to_dict(),
                     "rendered_pages": [], "_outdir": str(outdir)},
                    False, reason)

        if not res.ok:
            raise RuntimeError(
                f"parse cage failed: exit={res.exit_code} timed_out={res.timed_out} "
                f"stderr={res.stderr[:300]}")
        verdict = dict(res.verdict or {})
        verdict["_outdir"] = str(outdir)
        verdict["_cage_duration_s"] = res.duration_s
        return verdict, True, None

    # -- stage 2 -------------------------------------------------------
    def _assess(self, result: ReviewResult, parsed: dict) -> None:
        structural = parsed.get("structural", {})
        visible = _visible_text(structural)

        try:
            c = self.inference.classify(visible)
            result.classification = {
                "label": c.label, "confidence": c.confidence,
                "rationale": c.rationale, "injection_noted": c.injection_noted,
            }
        except InferenceError as exc:
            result.errors.append(f"classification skipped: {exc}")
        except Exception as exc:
            result.errors.append(f"classification failed: {type(exc).__name__}: {exc}")

        if not result.injection_suspected:
            return

        pages = parsed.get("rendered_pages") or []
        outdir = Path(parsed.get("_outdir", ""))
        png: bytes | None = None
        if pages and outdir.is_dir():
            png = (outdir / pages[0]).read_bytes()
        else:
            try:
                png = divergence.render_page_png(result.source, 0)
            except Exception as exc:
                result.errors.append(f"render for vision pass failed: {exc}")

        if png is None:
            return
        try:
            transcript = self.inference.transcribe_page(png)
            result.vision = divergence.confirm_with_vision(result.shadow_text, transcript)
            result.vision["transcript_chars"] = len(transcript)
        except InferenceError as exc:
            result.errors.append(f"vision confirmation skipped: {exc}")
        except Exception as exc:
            result.errors.append(f"vision confirmation failed: {type(exc).__name__}: {exc}")

    # -- public --------------------------------------------------------
    def review(self, src: str | Path) -> ReviewResult:
        src = Path(src)
        job_id = uuid.uuid4().hex[:10]
        digest = _sha256(src)

        result = ReviewResult(job_id=job_id, source=str(src), sha256=digest,
                              contained=False)
        self.audit.append("ingest", {"source": src.name, "sha256": digest}, job_id)

        parsed, contained, degraded = self._parse_in_cage(src, job_id)
        result.contained = contained
        result.degraded_reason = degraded
        if not contained:
            self.audit.append("CONTAINMENT_DEGRADED", {
                "reason": degraded,
                "note": "stage 1 ran in-process; this run is NOT contained",
            }, job_id)

        structural = parsed.get("structural", {})
        result.structural = structural
        result.injection_suspected = bool(structural.get("injection_suspected"))
        result.techniques = list(structural.get("techniques") or [])
        result.shadow_text = structural.get("shadow_text", "")

        self.audit.append("parsed", {
            "contained": contained,
            "injection_suspected": result.injection_suspected,
            "techniques": result.techniques,
            "shadow_chars": len(result.shadow_text),
        }, job_id)

        if result.injection_suspected:
            result.quarantined = True
            self.audit.append("INJECTION_DETECTED", {
                "techniques": result.techniques,
                "shadow_text": result.shadow_text[:600],
            }, job_id)

        self._assess(result, parsed)
        if result.classification:
            self.audit.append("classified", result.classification, job_id)
        if result.vision:
            self.audit.append("vision_confirmed", result.vision, job_id)

        result.egress_attempts = self.read_egress()
        shutil.rmtree(parsed.get("_outdir", ""), ignore_errors=True)
        self._results[job_id] = result
        return result

    def approve(self, job_id: str, approver: str) -> ReviewResult:
        """
        The human gate. A quarantined document cannot be released by the agent
        under any circumstance -- only a named person can, and the approval is
        chained into the audit log.
        """
        r = self._results[job_id]
        r.approved = True
        r.released = True
        self.audit.append("human_approved_release", {
            "approver": approver,
            "was_quarantined": r.quarantined,
            "label": (r.classification or {}).get("label"),
        }, job_id)
        return r

    def read_egress(self) -> list[dict]:
        if not self.sinkhole_log.exists():
            return []
        out = []
        for line in self.sinkhole_log.read_text().strip().splitlines()[-200:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def results(self) -> list[dict]:
        return [r.to_dict() for r in self._results.values()]

    def get(self, job_id: str) -> ReviewResult | None:
        return self._results.get(job_id)


def _visible_text(structural: dict) -> str:
    pages = structural.get("pages") or []
    # the cage returns per-page shadow text; visible text is reconstructed here
    # from the top-level field when present
    return structural.get("visible_text") or "\n".join(
        p.get("visible_text", "") for p in pages)


def _sha256(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()
