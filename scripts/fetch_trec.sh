#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Fetch TREC 2010 Legal Track Topic 304 -- real adjudicated privilege labels.
#
# Both sources are open: no login, no signed agreement.
#   qrels  trec.nist.gov                  (~9MB, four files)
#   corpus trec-legal.umiacs.umd.edu      (625MB tarball, streamed)
#
# The tarball is NOT fully extracted. It is streamed once and only the 11,509
# documents carrying a Topic 304 judgment are written to disk (~90MB), which
# keeps this inside a hackathon-sized disk budget. The script is resumable:
# re-run it and it picks up whatever is missing.
# ---------------------------------------------------------------------------
set -uo pipefail
cd "$(dirname "$0")/.."
TREC="${FARADAY_TREC_DIR:-corpus/trec}"
DOCS="$TREC/docs"
QBASE="https://trec.nist.gov/data/legal/10"
CORPUS="https://trec-legal.umiacs.umd.edu/corpora/trec/legal10/edrmv2txt-v2.tar.bz2"
mkdir -p "$DOCS"

echo "== 1. privilege judgments =="
for f in qrel_leg_int_2010_msg_post qrel_leg_int_2010_msg_pre \
         qrel_leg_int_2010_doc_post qrel_leg_int_2010_doc_pre; do
  if [ -s "$TREC/$f.txt" ]; then
    echo "  have $f.txt"
  else
    curl -sS --fail -o "$TREC/$f.txt" "$QBASE/$f.txt" \
      && echo "  got  $f.txt ($(wc -l < "$TREC/$f.txt") rows)" \
      || { echo "  FAILED $f.txt"; exit 1; }
  fi
done

python3 - "$TREC" <<'PY'
import sys, pathlib
d = pathlib.Path(sys.argv[1])
rows = [l.split() for l in (d/"qrel_leg_int_2010_doc_post.txt").read_text().splitlines()]
t = [r for r in rows if r and r[0] == "304"]
print(f"  Topic 304: {len(t)} judged documents, "
      f"{sum(1 for r in t if r[3]=='1')} privileged, "
      f"{sum(1 for r in t if r[3]=='-1')} grey")
(d/"want_docids.txt").write_text("\n".join(sorted({r[2] for r in t})) + "\n")
PY

echo "== 2. judged documents (streamed, resumable) =="
HAVE=$(find "$DOCS" -name '*.txt' | wc -l)
WANT=$(wc -l < "$TREC/want_docids.txt")
echo "  on disk: $HAVE / $WANT"
if [ "$HAVE" -ge "$WANT" ]; then
  echo "  complete, nothing to do"
else
  echo "  streaming $CORPUS (625MB; keeps only judged docs)"
  curl -sS --max-time 2400 "$CORPUS" | python3 -I - "$TREC/want_docids.txt" "$DOCS" <<'PY'
import os, sys, tarfile
want = {l.strip() for l in open(sys.argv[1]) if l.strip()}
out = sys.argv[2]
os.makedirs(out, exist_ok=True)
todo = want - {f[:-4] for f in os.listdir(out) if f.endswith(".txt")}
print(f"  need {len(todo)} more", flush=True)
kept = 0
tf = tarfile.open(fileobj=sys.stdin.buffer, mode="r|bz2")
for m in tf:
    if not m.isfile() or not m.name.endswith(".txt"):
        continue
    docid = os.path.basename(m.name)[:-4]
    if docid in todo:
        f = tf.extractfile(m)
        if f is None:
            continue
        with open(os.path.join(out, docid + ".txt"), "wb") as fh:
            fh.write(f.read())
        todo.discard(docid); kept += 1
        if kept % 1000 == 0:
            print(f"    +{kept}, {len(todo)} to go", flush=True)
    if not todo:
        break
print(f"  added {kept}", flush=True)
PY
fi

echo "== 3. verify =="
python3 - <<'PY'
import sys, pathlib
sys.path.insert(0, "corpus")
import trec_privilege as tp
d = pathlib.Path("corpus/trec")
q = tp.load_qrels(d, level="doc", stage="post")
print(" ", tp.coverage(d/"docs", q))
PY
echo
echo "Next:"
echo "  python3 corpus/generate.py --out corpus/generated-trec --carrier trec"
echo "  python3 scripts/benchmark_privilege.py --mode structural --n 60"
