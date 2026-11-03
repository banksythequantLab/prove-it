#!/usr/bin/env python3
"""
Sandboxed parser entrypoint. Runs INSIDE the cage, once per file.

The cage gives us the containment that does not depend on recognizing an
attack: no network, read-only evidence mount, unprivileged user, 512 MB,
and a wall-clock kill from outside. THIS process adds the two limits a
memory ceiling alone does not express cleanly:

  * a decompression cap -- refuse to expand more than MAX_EXPAND bytes out
    of any archive (zip, docx, xlsx: all zip containers). A zip bomb is a
    few KB on disk that expands to gigabytes; the cap stops it before the
    512 MB ceiling kills the whole container, so we get a clean reason
    string instead of an OOM.
  * a page cap -- stop a PDF after MAX_PAGES. A 4,000-page PDF is a wall-
    clock attack; the outer 20 s kill is the real backstop, but the page
    cap lets a well-behaved run say why it stopped.

Nothing here tries to detect a "malicious" file. It sets limits and reports
what happened when a file hit one. A zip bomb and a genuinely large archive
trip the same cap and get the same treatment: killed in the sandbox, flagged
for a human. That is the point -- we do not have to tell them apart.

Contract: exactly one JSON object on the last line of stdout.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import time
import zipfile
from pathlib import Path

MAX_EXPAND = 256 * 1024 * 1024      # 256 MB of decompressed output, total
MAX_PAGES = 500                      # PDF page ceiling
MAX_TEXT = 2 * 1024 * 1024           # keep at most 2 MB of extracted text
MAX_MEMBERS = 10000                  # archive member-count ceiling


class LimitHit(Exception):
    """A resource limit stopped the parse. Carries a human-readable reason."""
    def __init__(self, kind: str, detail: str):
        self.kind = kind
        self.detail = detail
        super().__init__(f"{kind}: {detail}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- per-format extractors ---------------------------------------------------

def _guard_zip(zf: zipfile.ZipFile) -> None:
    """Refuse an archive whose declared expansion exceeds the cap."""
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        raise LimitHit("decompression_cap",
                       f"{len(infos)} members exceeds {MAX_MEMBERS}")
    total = sum(i.file_size for i in infos)       # declared uncompressed size
    if total > MAX_EXPAND:
        raise LimitHit("decompression_cap",
                       f"declared {total/1e6:.0f} MB expansion exceeds "
                       f"{MAX_EXPAND/1e6:.0f} MB cap")
    # Guard against a lying header: decompress with a running ceiling.
    seen = 0
    for i in infos:
        with zf.open(i) as m:
            while True:
                buf = m.read(1 << 20)
                if not buf:
                    break
                seen += len(buf)
                if seen > MAX_EXPAND:
                    raise LimitHit("decompression_cap",
                                   f"actual expansion passed "
                                   f"{MAX_EXPAND/1e6:.0f} MB (header understated it)")


def extract_eml(data: bytes) -> tuple[str, dict]:
    import email
    from email import policy
    msg = email.message_from_bytes(data, policy=policy.default)
    headers = {k: str(v) for k, v in msg.items()
               if k.lower() in ("from", "to", "cc", "subject", "date")}
    parts = []
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is not None:
        parts.append(body.get_content())
    else:
        for p in msg.walk():
            if p.get_content_type() == "text/plain":
                try:
                    parts.append(p.get_content())
                except Exception:
                    pass
    return "\n".join(parts)[:MAX_TEXT], headers


def extract_mbox(data: bytes) -> tuple[str, dict]:
    # count messages; concatenate their plain bodies up to the text cap
    chunks = data.split(b"\nFrom ")
    text = []
    for i, c in enumerate(chunks):
        raw = c if i == 0 else b"From " + c
        try:
            t, _ = extract_eml(raw)
            text.append(t)
        except Exception:
            continue
        if sum(len(x) for x in text) > MAX_TEXT:
            break
    return "\n\n".join(text)[:MAX_TEXT], {"messages": str(len(chunks))}


def extract_pdf(path: Path) -> tuple[str, dict]:
    import pypdfium2 as pdfium
    pdf = pdfium.PdfDocument(str(path))
    try:
        n = len(pdf)
        if n > MAX_PAGES:
            raise LimitHit("page_cap", f"{n} pages exceeds {MAX_PAGES}")
        out = []
        for i in range(n):
            tp = pdf[i].get_textpage()
            out.append(tp.get_text_range())
            if sum(len(x) for x in out) > MAX_TEXT:
                break
        return "\n".join(out)[:MAX_TEXT], {"pages": str(n)}
    finally:
        pdf.close()


def extract_docx(path: Path) -> tuple[str, dict]:
    # docx is a zip; guard it, then pull paragraph text out of document.xml
    import re
    with zipfile.ZipFile(path) as zf:
        _guard_zip(zf)
        try:
            xml = zf.read("word/document.xml").decode("utf-8", "replace")
        except KeyError:
            raise LimitHit("parse_error", "no word/document.xml in archive")
    text = re.sub(r"<[^>]+>", " ", xml)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_TEXT], {}


def extract_csv(data: bytes) -> tuple[str, dict]:
    text = data.decode("utf-8", "replace")
    rows = text.count("\n")
    return text[:MAX_TEXT], {"rows": str(rows)}


def extract_zip(path: Path) -> tuple[str, dict]:
    with zipfile.ZipFile(path) as zf:
        _guard_zip(zf)
        names = zf.namelist()
        text = []
        for nm in names:
            if nm.lower().endswith((".txt", ".eml", ".csv")):
                try:
                    text.append(zf.read(nm).decode("utf-8", "replace"))
                except Exception:
                    pass
            if sum(len(x) for x in text) > MAX_TEXT:
                break
    return "\n".join(text)[:MAX_TEXT], {"members": str(len(names))}


EXTRACTORS = {
    ".eml": lambda p: extract_eml(p.read_bytes()),
    ".mbox": lambda p: extract_mbox(p.read_bytes()),
    ".pdf": lambda p: extract_pdf(p),
    ".docx": lambda p: extract_docx(p),
    ".csv": lambda p: extract_csv(p.read_bytes()),
    ".zip": lambda p: extract_zip(p),
}


def main() -> int:
    inp = Path("/input")
    files = [p for p in inp.iterdir() if p.is_file()] if inp.is_dir() else []
    if not files:
        print(json.dumps({"ok": False, "error": "no input file mounted"}))
        return 2
    target = files[0]
    ext = target.suffix.lower()
    started = time.monotonic()

    result: dict = {
        "ok": True,
        "file": target.name,
        "ext": ext,
        "sha256": sha256(target),
        "bytes": target.stat().st_size,
        "status": "parsed",
        "kill_reason": None,
        "text_chars": 0,
        "headers": {},
        "limits": {
            "max_expand_mb": MAX_EXPAND // (1024 * 1024),
            "max_pages": MAX_PAGES,
            "wall_clock_s": 20,
            "memory_mb": 512,
        },
    }

    extractor = EXTRACTORS.get(ext)
    if extractor is None:
        result["status"] = "needs_manual"
        result["kill_reason"] = f"unsupported type {ext}"
    else:
        try:
            text, headers = extractor(target)
            result["text_chars"] = len(text)
            result["headers"] = headers
            result["text"] = text
        except LimitHit as lh:
            # The file hit a resource limit. Destroyed in its sandbox, flagged.
            result["status"] = "needs_manual"
            result["kill_reason"] = str(lh)
            result["kill_kind"] = lh.kind
        except MemoryError:
            result["status"] = "needs_manual"
            result["kill_reason"] = "memory_cap: exhausted 512 MB during parse"
            result["kill_kind"] = "memory_cap"
        except Exception as exc:
            result["status"] = "needs_manual"
            result["kill_reason"] = f"parse_error: {type(exc).__name__}: {exc}"[:160]
            result["kill_kind"] = "parse_error"

    result["parse_s"] = round(time.monotonic() - started, 3)
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
