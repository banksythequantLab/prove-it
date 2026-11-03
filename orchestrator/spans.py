"""
Verified exact-span quoting.

A ranking model is allowed to cite quotes to justify its score. On its own,
a cited quote is worth nothing -- models paraphrase, compress, and invent
while believing they are quoting. So every quote the model returns is checked
against the extracted document text and thrown out if it is not actually
there, verbatim.

This is the real, checkable counterpart to the thing we dropped: instead of
trusting the model to resist a hidden instruction, we trust it for nothing and
verify the one thing it can be held to -- that a quote it attributes to the
document really appears in the document.

Matching is whitespace-insensitive (PDF and email extraction mangle runs of
spaces and line breaks) but otherwise exact: the sequence of non-space
characters must appear in order. A match returns the span's offsets in the
ORIGINAL text so the UI can highlight the real words. No match -> rejected,
and a rejected quote never reaches the reviewer as support.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

_WS = re.compile(r"\s+")
MIN_QUOTE_CHARS = 12          # too-short quotes match by accident; reject them


@dataclass
class SpanCheck:
    quote: str
    verified: bool
    reason: str
    start: int | None = None
    end: int | None = None
    matched_text: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _normalize_with_map(text: str) -> tuple[str, list[int]]:
    """
    Collapse whitespace runs to a single space, and record for each character
    in the normalized string its index in the ORIGINAL text, so a match can be
    reported against the real document.
    """
    out_chars: list[str] = []
    out_map: list[int] = []
    prev_ws = False
    for i, ch in enumerate(text):
        if ch.isspace():
            if prev_ws:
                continue
            out_chars.append(" ")
            out_map.append(i)
            prev_ws = True
        else:
            out_chars.append(ch)
            out_map.append(i)
            prev_ws = False
    return "".join(out_chars), out_map


def verify_quote(doc_text: str, quote: str,
                 norm_doc: str | None = None,
                 idx_map: list[int] | None = None) -> SpanCheck:
    q = quote.strip()
    if len(q) < MIN_QUOTE_CHARS:
        return SpanCheck(quote, False, f"too short (<{MIN_QUOTE_CHARS} chars)")
    if norm_doc is None or idx_map is None:
        norm_doc, idx_map = _normalize_with_map(doc_text)
    norm_q = _WS.sub(" ", q).strip()
    pos = norm_doc.find(norm_q)
    if pos == -1:
        return SpanCheck(quote, False, "not found in document text verbatim")
    start = idx_map[pos]
    end = idx_map[pos + len(norm_q) - 1] + 1
    return SpanCheck(quote, True, "verified exact span",
                     start=start, end=end, matched_text=doc_text[start:end])


def verify_all(doc_text: str, quotes: list[str]) -> list[SpanCheck]:
    norm_doc, idx_map = _normalize_with_map(doc_text)
    return [verify_quote(doc_text, q, norm_doc, idx_map) for q in quotes]


def summary(checks: list[SpanCheck]) -> dict:
    v = [c for c in checks if c.verified]
    return {
        "quotes": len(checks),
        "verified": len(v),
        "rejected": len(checks) - len(v),
        "verified_quotes": [c.to_dict() for c in v],
        "rejected_quotes": [c.to_dict() for c in checks if not c.verified],
    }
