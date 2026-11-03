"""
Text/vision divergence detection -- Faraday's technical centerpiece.

A prompt injection hidden in a document only works if it is present in the
text an LLM consumes while being ABSENT from what a human reviewer sees. That
gap is the signature, and it is measurable.

Two layers, cheap first:

  Layer 1 (structural, deterministic, no model, no network)
      Walk every glyph in the PDF and flag it as non-visible if ANY of:
        - fill colour matches the page background (white-on-white)
        - alpha is zero (fully transparent)
        - font size is below the legibility floor (micro-type)
        - the glyph box falls outside the page's crop box (drawn off-page)
        - text render mode is 3 / INVISIBLE (the OCR-layer trick)
      Concatenating the flagged glyphs yields SHADOW TEXT: text that an
      extractor hands to a model but a reader never sees.

  Layer 2 (vision, confirmatory)
      Render the page and ask a vision model to transcribe it. Shadow text
      should not appear in that transcription. Catches what structure cannot:
      text baked into an image, or glyphs occluded by a drawn shape.

Layer 1 alone catches all three poison techniques in the Faraday corpus, which
means the containment claim does not depend on a model call succeeding.
"""
from __future__ import annotations

import ctypes
import math
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

import pypdfium2 as pdfium
import pypdfium2.raw as raw

# --- thresholds --------------------------------------------------------------
LEGIBLE_PT_FLOOR = 3.0      # below this, nothing is readable at any sane zoom
BG_COLOR_DELTA = 24         # 0-255 per-channel distance to call it "background"
ALPHA_FLOOR = 8             # <= this alpha is effectively transparent
RENDERMODE_INVISIBLE = 3

# A "weak" signal marks text that is not rendered but whose absence has an
# innocent explanation. It is counted and surfaced, never used alone to
# quarantine a document, and never folded into shadow text.
WEAK_RIGHT_OVERFLOW = "offpage_right_overflow"
WEAK_REASONS = frozenset({WEAK_RIGHT_OVERFLOW})
MIN_SHADOW_CHARS = 24       # ignore stray artefacts; an injection needs words

_WORD = re.compile(r"[a-z0-9@:/._-]{3,}", re.I)


@dataclass
class GlyphFlag:
    index: int
    char: str
    reason: str
    detail: str


@dataclass
class PageFinding:
    page: int
    visible_text: str = ""
    shadow_text: str = ""
    glyph_flags: list[GlyphFlag] = field(default_factory=list)
    reasons: dict[str, int] = field(default_factory=dict)
    weak_reasons: dict[str, int] = field(default_factory=dict)
    weak_text: str = ""

    @property
    def has_shadow(self) -> bool:
        return len(self.shadow_text.strip()) >= MIN_SHADOW_CHARS


@dataclass
class DocFinding:
    path: str
    pages: list[PageFinding] = field(default_factory=list)

    @property
    def shadow_text(self) -> str:
        return "\n".join(p.shadow_text for p in self.pages if p.has_shadow).strip()

    @property
    def visible_text(self) -> str:
        return "\n".join(p.visible_text for p in self.pages).strip()

    @property
    def injection_suspected(self) -> bool:
        """Strong signals only. Weak signals never quarantine on their own."""
        return bool(self.shadow_text)

    @property
    def weak_signals(self) -> dict[str, int]:
        agg: dict[str, int] = {}
        for p in self.pages:
            for r, n in p.weak_reasons.items():
                agg[r] = agg.get(r, 0) + n
        return agg

    @property
    def techniques(self) -> list[str]:
        seen: dict[str, None] = {}
        for p in self.pages:
            for r in p.reasons:
                seen[r] = None
        return list(seen)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "injection_suspected": self.injection_suspected,
            "techniques": self.techniques,
            "weak_signals": self.weak_signals,
            "shadow_text": self.shadow_text,
            "shadow_chars": len(self.shadow_text),
            # the text a HUMAN would read -- this, and only this, is what the
            # classifier is allowed to see. Omitting it silently starved the
            # classifier of input, so it is part of the contract now.
            "visible_text": self.visible_text,
            "visible_chars": len(self.visible_text),
            "pages": [
                {
                    "page": p.page,
                    "reasons": p.reasons,
                    "weak_reasons": p.weak_reasons,
                    "visible_text": p.visible_text,
                    "shadow_text": p.shadow_text,
                    "flags": [asdict(f) for f in p.glyph_flags[:40]],
                }
                for p in self.pages
            ],
        }


# --- raw pdfium helpers ------------------------------------------------------

def _fill_color(tp, i: int) -> tuple[int, int, int, int] | None:
    r = ctypes.c_uint(); g = ctypes.c_uint(); b = ctypes.c_uint(); a = ctypes.c_uint()
    ok = raw.FPDFText_GetFillColor(
        tp, i, ctypes.byref(r), ctypes.byref(g), ctypes.byref(b), ctypes.byref(a)
    )
    if not ok:
        return None
    return (r.value, g.value, b.value, a.value)


def _char_box(tp, i: int) -> tuple[float, float, float, float] | None:
    l = ctypes.c_double(); rr = ctypes.c_double()
    bo = ctypes.c_double(); t = ctypes.c_double()
    ok = raw.FPDFText_GetCharBox(
        tp, i, ctypes.byref(l), ctypes.byref(rr), ctypes.byref(bo), ctypes.byref(t)
    )
    if not ok:
        return None
    return (l.value, rr.value, bo.value, t.value)


def _font_size(tp, i: int) -> float:
    try:
        return float(raw.FPDFText_GetFontSize(tp, i))
    except Exception:
        return math.nan


def _render_mode(tp, i: int) -> int:
    """
    Text render mode is a property of the PDF text OBJECT, not of the text page
    (there is no FPDFText_GetTextRenderMode in pdfium -- only the *TextObj*
    variant). Resolve the owning object for this char index, then read its mode.
    Returns -1 only when the object cannot be resolved.
    """
    try:
        obj = raw.FPDFText_GetTextObject(tp, i)
        if not obj:
            return -1
        return int(raw.FPDFTextObj_GetTextRenderMode(obj))
    except Exception:
        return -1


def _is_background(rgba: tuple[int, int, int, int]) -> bool:
    r, g, b, a = rgba
    if a <= ALPHA_FLOOR:
        return True
    # page background is white in every document Faraday ingests; generalise
    # by comparing against pure white within a tolerance.
    return all(abs(c - 255) <= BG_COLOR_DELTA for c in (r, g, b))


# --- layer 1 -----------------------------------------------------------------

def analyse(pdf_path: str | Path) -> DocFinding:
    """Structural pass. Pure function of the file: no network, no model."""
    path = Path(pdf_path)
    finding = DocFinding(path=str(path))
    pdf = pdfium.PdfDocument(str(path))
    try:
        for pno in range(len(pdf)):
            page = pdf[pno]
            box = page.get_cropbox() or page.get_mediabox()
            bx0, by0, bx1, by1 = box
            tp = page.get_textpage()
            raw_tp = tp.raw

            pf = PageFinding(page=pno + 1)
            n = raw.FPDFText_CountChars(raw_tp)

            # --- pass 1: classify real glyphs -----------------------------
            # pdfium synthesises layout characters (\r, \n) that belong to no
            # text object: they report size 1.0 and no fill colour, and testing
            # them directly made every document look micro-typed. Whitespace
            # carries no visual identity of its own, so it is resolved in pass 2
            # by inheriting from its neighbour instead.
            records: list[tuple[int, str, str | None, str]] = []  # (i, ch, reason|INHERIT, detail)
            INHERIT = "\x00inherit"

            for i in range(n):
                ch = tp.get_text_range(i, 1)
                if not ch:
                    continue

                rgba = _fill_color(raw_tp, i)
                if ch.isspace() or rgba is None:
                    records.append((i, ch, INHERIT, ""))
                    continue

                size = _font_size(raw_tp, i)
                mode = _render_mode(raw_tp, i)
                cb = _char_box(raw_tp, i)
                reason = None
                detail = ""

                if mode == RENDERMODE_INVISIBLE:
                    reason, detail = "render_mode_invisible", "Tr 3"
                elif _is_background(rgba):
                    reason, detail = "background_colour", f"rgba{rgba}"
                elif not math.isnan(size) and 0 < size < LEGIBLE_PT_FLOOR:
                    reason, detail = "microtype", f"{size:.2f}pt"
                elif cb is not None:
                    l, r_, b_, t_ = cb
                    geo = (f"box=({l:.0f},{b_:.0f},{r_:.0f},{t_:.0f}) "
                           f"crop=({bx0:.0f},{by0:.0f},{bx1:.0f},{by1:.0f})")
                    # Direction matters, and conflating the two directions cost
                    # us a 6-document false-positive rate on real correspondence.
                    #
                    # STRONG: parked above, below, or left of the page. No
                    # layout engine does this by accident -- it is deliberate.
                    #
                    # WEAK: running off the RIGHT edge. This is what an
                    # unwrapped long line does in countless real documents, so
                    # on its own it is bad layout, not an injection. Recorded
                    # and reported, but it does not by itself quarantine a
                    # document.
                    if t_ < by0 or b_ > by1 or r_ < bx0:
                        reason, detail = "offpage", geo
                    elif l > bx1:
                        reason, detail = WEAK_RIGHT_OVERFLOW, geo
                records.append((i, ch, reason, detail))

            # --- pass 2: resolve inherited whitespace ---------------------
            # Backward first (whitespace trails the run it belongs to), then
            # forward for leading whitespace. Unresolvable => visible.
            resolved: list[str | None] = [r[2] for r in records]
            last: str | None = None
            for idx, reason in enumerate(resolved):
                if reason == INHERIT:
                    resolved[idx] = last
                else:
                    last = reason
            nxt: str | None = None
            for idx in range(len(resolved) - 1, -1, -1):
                if resolved[idx] is INHERIT or resolved[idx] == INHERIT:
                    resolved[idx] = nxt
                else:
                    nxt = resolved[idx]

            vis, shadow, weak = [], [], []
            for (i, ch, _orig, detail), reason in zip(records, resolved):
                if reason in WEAK_REASONS:
                    weak.append(ch)
                    pf.weak_reasons[reason] = pf.weak_reasons.get(reason, 0) + 1
                elif reason:
                    shadow.append(ch)
                    pf.reasons[reason] = pf.reasons.get(reason, 0) + 1
                    if len(pf.glyph_flags) < 400 and not ch.isspace():
                        pf.glyph_flags.append(GlyphFlag(i, ch, reason, detail))
                else:
                    vis.append(ch)
            pf.weak_text = "".join(weak).strip()

            pf.visible_text = "".join(vis)
            pf.shadow_text = "".join(shadow).strip()
            finding.pages.append(pf)
    finally:
        pdf.close()
    return finding


# --- layer 2 -----------------------------------------------------------------

def render_page_png(pdf_path: str | Path, page: int = 0, scale: float = 2.0) -> bytes:
    """Rasterise a page for the vision pass. Runs on extracted artefacts only."""
    pdf = pdfium.PdfDocument(str(pdf_path))
    try:
        bitmap = pdf[page].render(scale=scale)
        import io
        buf = io.BytesIO()
        bitmap.to_pil().save(buf, format="PNG")
        return buf.getvalue()
    finally:
        pdf.close()


def confirm_with_vision(shadow_text: str, transcription: str) -> dict:
    """
    Compare structural shadow text against a vision model's transcription of
    the rendered page. Words in the shadow but not the transcription are
    confirmed invisible -- present for the model, absent for the human.
    """
    shadow_words = {w.lower() for w in _WORD.findall(shadow_text)}
    seen_words = {w.lower() for w in _WORD.findall(transcription)}
    if not shadow_words:
        return {"confirmed": False, "ratio": 0.0, "unseen": [], "checked": 0}
    unseen = sorted(shadow_words - seen_words)
    ratio = len(unseen) / len(shadow_words)
    return {
        "confirmed": ratio >= 0.6,
        "ratio": round(ratio, 3),
        "unseen": unseen[:40],
        "checked": len(shadow_words),
    }
