"""Sandboxed parser: real parser-breaking files hit their caps; normal mail parses."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collection"))
sys.path.insert(0, str(ROOT / "orchestrator"))
import parse_entry as pe  # noqa: E402
import spans              # noqa: E402


def _stress(name):
    d = ROOT / "collection" / "stress"
    if not (d / name).exists():
        import subprocess
        subprocess.run([sys.executable, str(ROOT / "collection" / "make_stress.py"),
                        str(d)], check=True)
    return d / name


def test_zip_bomb_hits_decompression_cap():
    r = pe.parse_path(_stress("zipbomb.zip"))
    assert r["status"] == "needs_manual" and r["kill_kind"] == "decompression_cap"


def test_docx_bomb_hits_decompression_cap():
    r = pe.parse_path(_stress("wordbomb.docx"))
    assert r["status"] == "needs_manual" and r["kill_kind"] == "decompression_cap"


def test_page_bomb_hits_page_cap():
    r = pe.parse_path(_stress("pagebomb.pdf"))
    assert r["status"] == "needs_manual" and r["kill_kind"] == "page_cap"


def test_normal_mail_parses():
    import tempfile
    p = Path(tempfile.mkdtemp()) / "n.eml"
    p.write_bytes(b"From: a@enron.com\r\nSubject: lunch\r\n\r\nSee you at noon.\r\n")
    r = pe.parse_path(p)
    assert r["status"] == "parsed" and r["kill_reason"] is None
    assert "noon" in r["text"]


def test_verified_quote_survives_whitespace_mangling():
    doc = "the first set of comments from one of our lawyers about the matter"
    c = spans.verify_quote(doc, "first   set\n  of  comments from one")
    assert c.verified and c.start is not None


def test_fabricated_quote_is_rejected():
    doc = "the first set of comments from one of our lawyers about the matter"
    c = spans.verify_quote(doc, "we shredded everything per instructions")
    assert not c.verified
