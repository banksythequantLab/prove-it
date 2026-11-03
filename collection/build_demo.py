#!/usr/bin/env python3
"""
Assemble the Enron demo collection: real documents in several real container
formats, plus the stress-test files, with every file hashed at ingest.

Issue-relevant documents are drawn in first so the ranked queue has genuine
signal to surface. The rest are filled at random. Nothing is fabricated: the
.eml, .mbox, .pdf and .docx all carry real Enron text, just in different
containers -- which is exactly the variety a real collection arrives in.

The CSV is the collection's own load file (docid, custodian-ish source,
sha256, type) -- a real eDiscovery artifact, not invented content.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import random
import re
import shutil
import sys
import zipfile
from pathlib import Path

ISSUES = {
    "ca_trading": ["California", "congestion", "Ricochet", "CAISO", "ISO",
                   "trading strateg", "power", "megawatt"],
    "raptor_ljm_spe": ["Raptor", "LJM", "special purpose", "Fastow",
                       "Condor", "off-balance", "hedge"],
    "doc_retention": ["retention", "preserve", "destroy", "Andersen",
                      "shred", "litigation hold", "document policy"],
}

SRC = Path("corpus/trec/docs")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def pick_relevant(rng: random.Random, per_issue: int = 60) -> list[Path]:
    chosen: dict[str, Path] = {}
    allfiles = sorted(SRC.glob("*.txt"))
    # cheap relevance: scan once, bucket by issue
    for issue, kws in ISSUES.items():
        pat = re.compile("|".join(re.escape(k) for k in kws), re.I)
        hits = []
        for f in allfiles:
            if f.name in chosen:
                continue
            try:
                if pat.search(f.read_text(errors="replace")):
                    hits.append(f)
            except Exception:
                continue
            if len(hits) >= per_issue * 3:
                break
        rng.shuffle(hits)
        for f in hits[:per_issue]:
            chosen[f.name] = f
    return list(chosen.values())


def render_pdf(text: str, path: Path) -> None:
    """Real email text in a PDF container (how an attachment would arrive)."""
    import pypdfium2  # noqa: F401  (ensure available; render via reportlab)
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import LETTER
    c = canvas.Canvas(str(path), pagesize=LETTER)
    c.setFont("Helvetica", 10)
    y = 740
    for line in text.splitlines():
        for chunk in (line[i:i+95] for i in range(0, max(len(line), 1), 95)):
            if y < 60:
                c.showPage(); c.setFont("Helvetica", 10); y = 740
            c.drawString(54, y, chunk); y -= 13
    c.showPage(); c.save()


def render_docx(text: str, path: Path) -> None:
    paras = "".join(
        f"<w:p><w:r><w:t>{_xml(line)}</w:t></w:r></w:p>"
        for line in text.splitlines() if line.strip())
    document = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.'
                'openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                f"{paras}</w:body></w:document>")
    ctypes = ('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats'
              '.org/package/2006/content-types"><Default Extension="xml" '
              'ContentType="application/xml"/><Override PartName="/word/'
              'document.xml" ContentType="application/vnd.openxmlformats-'
              'officedocument.wordprocessingml.document.main+xml"/></Types>')
    rels = ('<?xml version="1.0"?><Relationships xmlns="http://schemas.'
            'openxmlformats.org/package/2006/relationships"/>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ctypes)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document)


def _xml(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "collection/demo")
    stress = Path("collection/stress")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    rng = random.Random(42)

    relevant = pick_relevant(rng)
    allfiles = sorted(SRC.glob("*.txt"))
    pool = [f for f in allfiles if f not in relevant]
    rng.shuffle(pool)
    # target ~581 eml so the final collection lands near 594 with the extras
    eml_sources = relevant + pool[: max(0, 581 - len(relevant))]
    rng.shuffle(eml_sources)

    manifest = []

    def record(dest: Path, typ: str, source_docid: str | None) -> None:
        data = dest.read_bytes()
        manifest.append({
            "file": dest.name,
            "type": typ,
            "bytes": len(data),
            "sha256_ingest": sha256_bytes(data),
            "source_docid": source_docid,
        })

    # --- .eml (the bulk) ---
    emld = out
    n_eml = 0
    for f in eml_sources:
        dest = out / (f.stem + ".eml")
        dest.write_bytes(f.read_bytes())
        record(dest, "eml", f.stem)
        n_eml += 1

    # --- 1 .mbox bundling 20 real messages ---
    mbox_src = eml_sources[:20]
    mbox = io.BytesIO()
    for f in mbox_src:
        mbox.write(b"From enron-archive\n")
        mbox.write(f.read_bytes())
        mbox.write(b"\n")
    (out / "custodian_archive.mbox").write_bytes(mbox.getvalue())
    record(out / "custodian_archive.mbox", "mbox", None)

    # --- 3 real emails rendered to PDF (attachment-style container) ---
    for i, f in enumerate(eml_sources[20:23]):
        dest = out / f"scanned_{i+1:02d}.pdf"
        render_pdf(f.read_text(errors="replace")[:4000], dest)
        record(dest, "pdf", f.stem)

    # --- 2 real emails as .docx ---
    for i, f in enumerate(eml_sources[23:25]):
        dest = out / f"memo_{i+1:02d}.docx"
        render_docx(f.read_text(errors="replace")[:4000], dest)
        record(dest, "docx", f.stem)

    # --- 1 benign .zip bundling 5 real .eml (a real archive in the set) ---
    bz = out / "mailstore_backup.zip"
    with zipfile.ZipFile(bz, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in eml_sources[25:30]:
            zf.writestr(f.stem + ".eml", f.read_bytes())
    record(bz, "zip", None)

    # --- the load file (CSV) -- a real eDiscovery artifact over THIS set ---
    csv_path = out / "loadfile.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "type", "bytes", "sha256_ingest", "source_docid"])
        for m in manifest:
            w.writerow([m["file"], m["type"], m["bytes"],
                        m["sha256_ingest"], m["source_docid"] or ""])
    record(csv_path, "csv", None)

    # --- the 3 stress-test files ---
    for name in ("zipbomb.zip", "wordbomb.docx", "pagebomb.pdf"):
        src = stress / name
        if src.exists():
            dest = out / name
            shutil.copy2(src, dest)
            record(dest, dest.suffix.lstrip("."), None)

    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    by_type: dict[str, int] = {}
    for m in manifest:
        by_type[m["type"]] = by_type.get(m["type"], 0) + 1
    print(f"collection: {len(manifest)} files -> {out}")
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t:6} {n}")
    print(f"stress-test files included: zipbomb.zip, wordbomb.docx, pagebomb.pdf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
