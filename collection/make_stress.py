#!/usr/bin/env python3
"""
Generate stress-test files for the demo collection.

These are REAL files that break naive parsers -- the kind every large
collection actually contains (a backup zip that unpacks to gigabytes, an
export with tens of thousands of pages). They are added to the demo set so
the containment moment shows the sandbox killing them at its limits, with
the real reason, and flagging them for a human.

They are called "stress-test files" on screen. Nothing here is weaponised:
each is zeros or repeated boilerplate compressed well. The point is resource
exhaustion, which does not care whether the bytes are hostile.
"""
from __future__ import annotations

import struct
import sys
import zipfile
import zlib
from pathlib import Path


def zip_bomb(path: Path) -> None:
    """~1 GB of zeros in one member. Tiny on disk, trips the decompression cap."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        # one 1 GB member of zeros; DEFLATE squashes it to ~1 MB
        chunk = b"\0" * (1024 * 1024)
        import io
        buf = io.BytesIO()
        for _ in range(1024):          # 1024 MB
            buf.write(chunk)
        zf.writestr("backup/dump.bin", buf.getvalue())


def docx_bomb(path: Path) -> None:
    """A .docx whose document.xml expands to ~400 MB of repeated paragraphs."""
    para = "<w:p><w:r><w:t>boilerplate retention notice paragraph</w:t></w:r></w:p>"
    body = para * 6_000_000           # ~400 MB of XML
    document = (
        '<?xml version="1.0"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body></w:document>"
    )
    rels = ('<?xml version="1.0"?><Relationships '
            'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
    ctypes = ('<?xml version="1.0"?><Types '
              'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
              '<Default Extension="xml" ContentType="application/xml"/>'
              '<Override PartName="/word/document.xml" ContentType="application/'
              'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
              '</Types>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("[Content_Types].xml", ctypes)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document)


def _pdf(path: Path, n_pages: int) -> None:
    """Minimal multi-page PDF written by hand -- no library, exact page count."""
    objs: list[bytes] = []

    def add(b: bytes) -> int:
        objs.append(b)
        return len(objs)

    # placeholder for pages root (obj 1), filled after we know kid ids
    add(b"")  # obj 1 reserved
    font_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    kids = []
    for i in range(n_pages):
        content = f"BT /F1 12 Tf 72 720 Td (Page {i+1} of {n_pages}) Tj ET".encode()
        stream = b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content)
        content_id = add(stream)
        page = (b"<< /Type /Page /Parent 1 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>"
                % (font_id, content_id))
        kids.append(add(page))

    kids_ref = b" ".join(b"%d 0 R" % k for k in kids)
    objs[0] = (b"<< /Type /Pages /Count %d /Kids [%s] >>"
               % (n_pages, kids_ref))
    catalog_id = add(b"<< /Type /Catalog /Pages 1 0 R >>")

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i)
        out.write(body)
        out.write(b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n" % (len(objs) + 1))
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF"
              % (len(objs) + 1, catalog_id, xref))
    path.write_bytes(out.getvalue())


def page_bomb(path: Path) -> None:
    """4,000-page PDF. Trips the page cap; the 20 s wall-clock is the backstop."""
    _pdf(path, 4000)


import io  # noqa: E402  (used by _pdf / zip_bomb)

GENERATORS = {
    "zipbomb.zip": zip_bomb,
    "wordbomb.docx": docx_bomb,
    "pagebomb.pdf": page_bomb,
}


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "collection/stress")
    out.mkdir(parents=True, exist_ok=True)
    for name, gen in GENERATORS.items():
        dest = out / name
        gen(dest)
        print(f"  {name:16} {dest.stat().st_size/1024:9.1f} KB on disk")
    print(f"wrote {len(GENERATORS)} stress-test files -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
