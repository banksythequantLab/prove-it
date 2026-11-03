"""
TREC 2010 Legal Track Topic 304 -- real attorney-adjudicated privilege labels.

Why this matters. Faraday's synthetic corpus proves the *detector* works, but
its labels are ones we wrote. Topic 304 is different: it is a privilege call
("documents withheld on the basis of a claim of privilege, attorney
work-product, or any other applicable protection") made over real Enron
documents by a commercial review firm, appealed, and adjudicated by a named
Topic Authority. 175 labels changed on appeal, which is what real privilege
review looks like.

That gives Faraday something a synthetic corpus cannot: an accuracy number
nobody has to take on trust.

  message level : 6,766 judged   941 privileged
  document level: 11,509 judged  1,220 privileged  (includes attachments)

Labels: 1 = privileged, 0 = not privileged, -1 = grey / unadjudicated.

Provenance
    qrels   https://trec.nist.gov/data/legal10.html
            qrel_leg_int_2010_{msg,doc}_{pre,post}.txt  -- open, no login
    corpus  https://trec-legal.umiacs.umd.edu/corpora/trec/legal10/
            edrmv2txt-v2.tar.bz2 (~625MB) -- open mirror of EDRM Enron v2
    overview https://trec.nist.gov/pubs/trec19/papers/LEGAL10.OVERVIEW.pdf

PRIVACY. This is real correspondence from real people, including genuinely
personal mail that was swept into a public regulatory release. Aggregate
benchmarking is ordinary research practice; putting an identifiable person's
personal message on screen in a demo video is not. redact() masks addresses,
phone numbers and long digit strings, and it is ON by default for anything
that could be rendered. Use the real text for the number; use the synthetic
corpus on camera.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PRIVILEGED, NOT_PRIVILEGED, GREY = 1, 0, -1

QREL_FILES = {
    ("msg", "post"): "qrel_leg_int_2010_msg_post.txt",
    ("msg", "pre"): "qrel_leg_int_2010_msg_pre.txt",
    ("doc", "post"): "qrel_leg_int_2010_doc_post.txt",
    ("doc", "pre"): "qrel_leg_int_2010_doc_pre.txt",
}
QREL_BASE = "https://trec.nist.gov/data/legal/10/"
TOPIC_PRIVILEGE = "304"

# Header keys the EDRM text export emits before the blank line.
_HEADER = re.compile(r"^(Date|Subject|From|To|Cc|Bcc|X-SDOC|X-ZLID):", re.I)

# Any RFC822-ish header line, anywhere. Needed because forwarded mail drags
# Received:/Message-ID:/MIME-Version: blocks down into the body, and those are
# transport metadata, not prose.
_ANY_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,30}:\s")

# Confidentiality / privilege footers.
#
# These MUST be stripped from carrier prose, and not merely for tidiness: a
# footer saying "privileged and confidential" appears on a large share of the
# privileged documents, so leaving it in would let a classifier score well by
# pattern-matching the boilerplate instead of reading the correspondence. That
# would inflate our own benchmark, which is the one number here meant to be
# trustworthy.
_FOOTER = re.compile(
    r"(intended recipient|intended only for|privileged and confidential"
    r"|confidential and privileged|is the property of|subject to the attorney"
    r"|attorney[- ]client privilege|unauthorized (?:review|use|disclosure)"
    r"|if you (?:are not|have received) this|please (?:delete|notify)"
    r"|this (?:e-?mail|message|transmission) (?:and any|is|may)"
    r"|contained in this e-?mail)", re.I)

# --- redaction ---------------------------------------------------------------
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE = re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b")
_LONGNUM = re.compile(r"\b\d{7,}\b")

# Quoted-reply, forward and boilerplate markers -- stripped when harvesting
# carrier prose so injected test text sits in clean body copy.
_NOISE = (
    "-----Original Message-----", "---------------------- Forwarded",
    "**********", "This e-mail is the property of Enron",
    "____________", "========",
)


def _looks_like_prose(line: str) -> bool:
    """
    Reject table rows, ASCII art, URL dumps and encoded blobs. A carrier line
    has to read as a sentence a human wrote, because it is the copy a reviewer
    is nominally reading on the page.
    """
    words = line.split()
    if len(words) < 5:
        return False
    alpha = sum(c.isalpha() or c.isspace() for c in line)
    if alpha / len(line) < 0.72:                    # punctuation/digit soup
        return False
    if any(len(w) > 24 for w in words):            # tokens, not words
        return False
    # box-drawing, bullets and control glyphs mean a table or a form, not prose
    if any(ord(ch) > 0x2000 and not ch.isalpha() for ch in line):
        return False
    letters = [c for c in line if c.isalpha()]
    if letters and sum(c.isupper() for c in letters) / len(letters) > 0.6:
        return False                                 # SHOUTING HEADLINE
    return True


def redact(text: str) -> str:
    """Mask direct identifiers. Not anonymisation -- names survive."""
    text = _EMAIL.sub("[EMAIL]", text)
    text = _PHONE.sub("[PHONE]", text)
    text = _LONGNUM.sub("[NUMBER]", text)
    return text


@dataclass
class TrecDoc:
    docid: str
    label: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    @property
    def subject(self) -> str:
        return self.headers.get("subject", "")

    @property
    def is_privileged(self) -> bool:
        return self.label == PRIVILEGED

    def carrier_lines(self, max_lines: int = 5, redacted: bool = True) -> list[str]:
        """
        Clean body prose suitable as the carrier text of a generated PDF.

        Quoted replies, forwards and the Enron confidentiality footer are
        dropped: an injection buried under 40 lines of '>' quoting is not a
        fair test of the detector, and the footer would contaminate every
        privilege signal in the corpus.
        """
        out: list[str] = []
        for raw in self.body.splitlines():
            line = raw.rstrip()
            if not line or line.startswith(">") or line.startswith("\t"):
                continue
            if any(mark in line for mark in _NOISE):
                break
            # a footer ends the usable prose -- everything after it is boilerplate
            if _FOOTER.search(line):
                break
            if _HEADER.match(line) or _ANY_HEADER.match(line):
                continue
            if len(line) < 25:
                continue
            if not _looks_like_prose(line):
                continue
            out.append(redact(line) if redacted else line)
            if len(out) >= max_lines:
                break
        return out


def load_qrels(qrel_dir: str | Path, level: str = "doc",
               stage: str = "post", topic: str = TOPIC_PRIVILEGE) -> dict[str, int]:
    """
    Parse one qrel file into {docid: label} for a single topic.

    Format is whitespace-separated: topic iteration docid assessment score.
    The trailing score is the stratum sampling probability, not a confidence,
    and is ignored.
    """
    path = Path(qrel_dir) / QREL_FILES[(level, stage)]
    if not path.exists():
        raise FileNotFoundError(
            f"{path} missing. Fetch it (open, no login):\n"
            f"  curl -O {QREL_BASE}{QREL_FILES[(level, stage)]}")
    out: dict[str, int] = {}
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != topic:
            continue
        try:
            out[parts[2]] = int(parts[3])
        except ValueError:
            continue
    return out


def parse_doc(raw: str) -> tuple[dict[str, str], str]:
    """Split an EDRM text export into headers and body at the first blank line."""
    lines = raw.splitlines()
    headers: dict[str, str] = {}
    i, last_key = 0, None
    for i, line in enumerate(lines):
        if not line.strip():
            i += 1
            break
        m = _HEADER.match(line)
        if m:
            key, _, val = line.partition(":")
            last_key = key.strip().lower()
            headers[last_key] = val.strip()
        elif last_key and (line.startswith((" ", "\t"))):
            headers[last_key] += " " + line.strip()      # folded continuation
    return headers, "\n".join(lines[i:])


def iter_docs(docs_dir: str | Path, qrels: dict[str, int],
              include_grey: bool = False) -> list[TrecDoc]:
    """Load every judged document present on disk. Missing files are skipped."""
    d = Path(docs_dir)
    if not d.is_dir():
        raise FileNotFoundError(
            f"{d} missing. See scripts/fetch_trec.sh -- it streams the EDRM "
            f"tarball and keeps only the judged documents.")
    docs: list[TrecDoc] = []
    for docid, label in qrels.items():
        if label == GREY and not include_grey:
            continue
        p = d / f"{docid}.txt"
        if not p.exists():
            continue
        headers, body = parse_doc(p.read_text(errors="replace"))
        docs.append(TrecDoc(docid=docid, label=label, headers=headers, body=body))
    return docs


def coverage(docs_dir: str | Path, qrels: dict[str, int]) -> dict:
    """How much of the judged set is actually on disk, and its class balance."""
    d = Path(docs_dir)
    have = {f.stem for f in d.glob("*.txt")} if d.is_dir() else set()
    judged = set(qrels)
    present = judged & have
    labels = [qrels[k] for k in present]
    return {
        "judged": len(judged),
        "on_disk": len(present),
        "coverage_pct": round(100 * len(present) / max(len(judged), 1), 1),
        "privileged": sum(1 for l in labels if l == PRIVILEGED),
        "not_privileged": sum(1 for l in labels if l == NOT_PRIVILEGED),
        "grey": sum(1 for l in labels if l == GREY),
    }


# --- scoring -----------------------------------------------------------------

def score(predictions: dict[str, str], truth: dict[str, int]) -> dict:
    """
    Binary privilege scoring. predictions maps docid -> label string from the
    classifier; anything equal to "privileged" counts as a positive call.

    Recall is the number that matters here and precision is the one that costs
    money: a missed privileged document is a waiver, a false positive is just
    a lawyer's time. Reported separately for that reason.
    """
    tp = fp = tn = fn = 0
    scored = 0
    for docid, pred in predictions.items():
        if docid not in truth:
            continue
        t = truth[docid]
        if t == GREY:
            continue
        scored += 1
        p = (pred or "").strip().lower() == "privileged"
        if p and t == PRIVILEGED:
            tp += 1
        elif p and t == NOT_PRIVILEGED:
            fp += 1
        elif not p and t == PRIVILEGED:
            fn += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "scored": scored,
        "true_positives": tp, "false_positives": fp,
        "true_negatives": tn, "false_negatives": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "accuracy": round((tp + tn) / scored, 4) if scored else 0.0,
        "note": "a false negative is a privilege waiver; a false positive is "
                "a lawyer's time. They are not symmetric costs.",
    }
