#!/usr/bin/env python3
"""
Runs INSIDE the parse cage. Network: none. Rootfs: read-only. User: nobody.

Contract with the orchestrator: exactly one JSON object on the last line of
stdout. No sockets, no files handed back except rendered page images written to
/output. The untrusted document never leaves this container and no networked
process ever opens it.
"""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

sys.path.insert(0, "/opt/faraday")
import divergence  # noqa: E402


def main() -> int:
    inp = Path("/input")
    files = [p for p in inp.iterdir() if p.is_file()] if inp.is_dir() else []
    if not files:
        print(json.dumps({"ok": False, "error": "no input file mounted at /input"}))
        return 2
    target = files[0]
    out = Path("/output")

    try:
        finding = divergence.analyse(target)
        pages = []
        if out.is_dir():
            for pno in range(len(finding.pages)):
                png = divergence.render_page_png(target, page=pno, scale=2.0)
                dest = out / f"page_{pno + 1:03d}.png"
                dest.write_bytes(png)
                pages.append(dest.name)

        print(json.dumps({
            "ok": True,
            "source": target.name,
            "structural": finding.to_dict(),
            "rendered_pages": pages,
        }, default=str))
        return 0
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "trace": traceback.format_exc()[-1200:],
        }))
        return 1


if __name__ == "__main__":
    sys.exit(main())
