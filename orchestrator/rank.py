"""
Issue-based ranking. Advisory only; the human decides.

The model reads EXTRACTED TEXT ONLY -- never the original file, which was
destroyed with the parse cage. For each reviewer-defined issue it returns a
0-100 relevance score, a one-line rationale, and supporting quotes. Every
quote is then checked by spans.verify_all against the document text. Quotes
that do not verify are dropped, and a score that rests on zero verified quotes
is marked unsupported so a reviewer treats it with suspicion.

Nothing here makes a privilege determination final. A privilege SIGNAL is a
flag for a human, explicitly not a call.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from inference import VultrInference, InferenceError
import spans

RANK_SYSTEM = """You are a first-pass eDiscovery review assistant. You are
ADVISORY: a human reviewer makes every final call. You read only the extracted
text you are given.

Return TWO sections, in this order and nothing else.

SECTION 1 -- a single line of JSON with scores and rationale only (no quotes):
{"issues":{"<id>":{"score":<0-100>,"rationale":"<one sentence>"}},"privilege_signal":true|false,"privilege_rationale":"<one sentence>"}

SECTION 2 -- supporting quotes, one per line, each line formatted as:
QUOTE<TAB><issue_id><TAB><a SHORT span copied EXACTLY from the document>
Copy quotes verbatim; do not paraphrase. Put at most 3 lines per issue. If you
have no exact quote for an issue, write no QUOTE line for it. Never invent text.

Quotes go ONLY in Section 2 lines, so they can contain any punctuation without
breaking Section 1. Flag privilege SIGNALS (attorney names, "privileged",
"work product", legal advice) as a hint for a human -- never a determination."""


@dataclass
class IssueResult:
    issue_id: str
    score: int
    rationale: str
    verified_quotes: list[dict] = field(default_factory=list)
    rejected_quotes: list[dict] = field(default_factory=list)

    @property
    def supported(self) -> bool:
        return bool(self.verified_quotes)


@dataclass
class RankResult:
    docid: str
    issues: dict
    privilege_signal: bool
    privilege_rationale: str
    overall: int
    raw: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "docid": self.docid,
            "overall": self.overall,
            "privilege_signal": self.privilege_signal,
            "privilege_rationale": self.privilege_rationale,
            "issues": {k: {
                "score": v.score, "rationale": v.rationale,
                "supported": v.supported,
                "verified_quotes": v.verified_quotes,
                "rejected_quotes": v.rejected_quotes,
            } for k, v in self.issues.items()},
            "error": self.error,
        }


def _parse_scores(raw: str) -> dict:
    """Section 1: the first {...} on its own. Control chars stripped so a stray
    newline inside the line cannot break it."""
    a = raw.find("{")
    if a == -1:
        raise InferenceError(f"no JSON in model output: {raw[:160]!r}")
    depth = 0
    for i in range(a, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                blob = raw[a:i + 1]
                blob = "".join(c if c >= " " or c == "\t" else " " for c in blob)
                try:
                    return json.loads(blob)
                except json.JSONDecodeError:
                    break
    raise InferenceError("Section 1 JSON did not parse")


def _parse_quote_lines(raw: str, issues: dict) -> dict[str, list[str]]:
    """Section 2: QUOTE<TAB>issue<TAB>text lines. Delimited, so inner quotes,
    commas and apostrophes in the quoted span are harmless."""
    out: dict[str, list[str]] = {i: [] for i in issues}
    for line in raw.splitlines():
        if not line.startswith("QUOTE"):
            continue
        parts = line.split("\t", 2)
        if len(parts) < 3:
            # tolerate a model that used spaces: QUOTE <issue> <text>
            m = line[len("QUOTE"):].strip()
            for iid in issues:
                if m.startswith(iid):
                    out[iid].append(m[len(iid):].strip())
                    break
            continue
        _, iid, quote = parts
        iid = iid.strip()
        if iid in out:
            out[iid].append(quote.strip())
    return out


def rank_document(inf: VultrInference, docid: str, text: str,
                  issues: dict[str, str]) -> RankResult:
    """issues: {issue_id: human-readable description}."""
    issue_block = "\n".join(f"  {i}: {desc}" for i, desc in issues.items())
    prompt = (f"ISSUES:\n{issue_block}\n\n<document>\n{text[:12000]}\n</document>")
    try:
        resp = inf.client.chat.completions.create(
            model=inf.text_model, temperature=0, max_tokens=1600,
            messages=[{"role": "system", "content": RANK_SYSTEM},
                      {"role": "user", "content": prompt}])
        raw = (resp.choices[0].message.content or "").strip()
        d = _parse_scores(raw)
        quote_map = _parse_quote_lines(raw, issues)
    except Exception as exc:
        return RankResult(docid, {}, False, "", 0, error=f"{type(exc).__name__}: {exc}"[:160])

    # verify quotes once against the doc
    norm, idx = spans._normalize_with_map(text)
    out_issues: dict[str, IssueResult] = {}
    for iid in issues:
        blk = (d.get("issues") or {}).get(iid, {}) or {}
        quotes = quote_map.get(iid, [])
        checks = [spans.verify_quote(text, q, norm, idx) for q in quotes]
        verified = [c.to_dict() for c in checks if c.verified]
        rejected = [c.to_dict() for c in checks if not c.verified]
        score = int(blk.get("score", 0) or 0)
        # a score with no verified support is capped as unsupported signal
        out_issues[iid] = IssueResult(
            iid, score, str(blk.get("rationale", "")), verified, rejected)

    overall = max((r.score for r in out_issues.values()), default=0)
    return RankResult(
        docid=docid, issues=out_issues,
        privilege_signal=bool(d.get("privilege_signal")),
        privilege_rationale=str(d.get("privilege_rationale", "")),
        overall=overall, raw=raw)
