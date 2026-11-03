# Prove-It eDiscovery

**Sandboxed first-pass review on Vultr. Every file is opened in its own throwaway sandbox. The AI ranks. A human decides.**

Built for the [Vultr: Agent Rush Hackathon](https://lablab.ai/ai-hackathons/vultr-hackathon) — Challenge 1, *Blast Radius Zero*.

---

## The problem

Opposing counsel produces 40,000 files. Before anyone reads them, something has to open each one — and a real collection is full of files that break parsers: a backup `.zip` that unpacks to gigabytes, a document export with tens of thousands of pages, a `.docx` whose XML expands past memory. One bad file shouldn't take down the review, and no untrusted file should have a network socket while it's being opened on a law firm's machine.

Prove-It opens every file in its own throwaway container — no network, read-only evidence, 512 MB, 20 seconds — ranks what parsed against the reviewer's issues, and shows a human a queue to decide. The model is advisory. Every quote it cites is checked against the document or discarded.

## What's real here, and what isn't

Two things are provable and don't depend on the model being clever:

- **The sandbox.** A file that breaks the parser is killed in its container and flagged for a human; the rest keep going. The kernel enforces the limits, not our code. `tcp_connect_external → Network is unreachable` is the kernel refusing, not a check we wrote.
- **Verified-span quoting.** The ranking model cites quotes; each one is string-matched against the extracted document text and thrown out if it is not there verbatim. A fabricated or paraphrased quote never reaches the reviewer as support.

One thing is explicitly *not* claimed: the ranking model is **advisory and not a strong classifier on its own**. It surfaces candidates and must support every call with a verified quote; the human makes every determination, and no privilege call is final. The value is the sandbox + verified quotes + human-in-the-loop, not model accuracy.

---

## How it works

```
┌─ INGEST ────────────────────────────────┐   one sandbox PER FILE
│  hash the file, then parse it in its own │   network: none
│  container. eml / mbox / pdf / docx /    │   evidence: read-only mount
│  csv / zip. A file that hits a limit is  │   512 MB · 20 s · unprivileged
│  killed and flagged "needs manual".      │   read-only rootfs, noexec scratch
└──────────────────────────────────────────┘
                  │ extracted text (never the original file)
                  ▼
┌─ RANK ──────────────────────────────────┐   Vultr Serverless Inference
│  score each doc against the reviewer's   │   glm-5.3-flash, advisory
│  issues; cite quotes. EVERY quote is     │   reads extracted text only
│  verified against the document or        │
│  discarded. Privilege = a SIGNAL only.   │
└──────────────────────────────────────────┘
                  │
                  ▼
┌─ REVIEW ────────────────────────────────┐   human codes Responsive / Hot /
│  ranked queue + viewer with verified     │   Privileged. QC: model-vs-human
│  spans highlighted. The human decides.   │   agreement + elusion sample.
│  Chain of custody: re-hash all evidence. │   Hash-chained audit log.
└──────────────────────────────────────────┘
```

### In-code caps on top of the cage

The container gives no-network / read-only / 512 MB / 20 s. The parser adds two limits that a memory ceiling alone does not express cleanly, so a kill gets a clean reason instead of an OOM:

| limit | catches |
|---|---|
| 256 MB decompression cap | zip / docx expansion bombs |
| 500-page cap | page-count exhaustion in PDFs |

It does not try to tell a hostile file from a merely large one — it sets limits and reports what a file hit. A zip bomb and a genuine multi-gigabyte archive trip the same cap and get the same treatment. That is the point: we don't have to recognise the attack.

---

## Required Vultr services

| Service | Role |
|---|---|
| **Vultr Cloud Compute** | the control plane: owns the queue, spawns and reaps every sandbox, holds the human approval gate, serves the UI. Not static hosting. |
| **Vultr Serverless Inference** | ranking, via the OpenAI-compatible surface at `https://api.vultrinference.com/v1` (`glm-5.3-flash`). Model IDs are resolved live, never hardcoded. |
| Docker | one sandbox per file (parse profile: no network, read-only, 512 MB, 20 s). |

No Vultr GPUs are used (unavailable for this event).

---

## Results, measured

Full demo collection — 592 real Enron documents in a realistic format mix (581 eml, 4 pdf, 3 docx, 2 zip, 1 mbox, 1 csv load file) with 3 stress-test files added — **ingested through real containers on a live Docker daemon**:

```
592/592 parsed in their own sandbox · 589 parsed · 3 flagged
  zipbomb.zip    decompression cap · declared 1074 MB expansion exceeds 268 MB
  wordbomb.docx  decompression cap · declared  426 MB expansion exceeds 268 MB
  pagebomb.pdf   page cap          · 4000 pages exceeds 500
chain of custody: 592/592 re-hash match · audit chain verified
```

Top-ranked document in the collection: a genuine Enron litigation-hold email, scored 99, privilege signal flagged, with the verified verbatim span *"our normal document destruction policies are suspended immediately."*

### The sealing proof

`scripts/verify_cage.sh` (needs a live Docker daemon) proves the sandbox on real hardware: the bridge is internal, the parse cage cannot open a socket, a canary of forbidden operations is refused or sinkholed (not merely dropped — the attempt is recorded), and a stress file is killed inside the cage. Run it before trusting anything built on top.

---

## Quick start

```bash
# 1. build the demo collection (needs the Enron source corpus; see scripts/fetch_trec.sh)
python3 collection/make_stress.py collection/stress
python3 collection/build_demo.py collection/demo

# 2. the sandbox sealing proof (needs Docker)
bash scripts/verify_cage.sh

# 3. run it
docker build -t faraday-cage:latest -f cage/Dockerfile .
pip install -r requirements.txt
export VULTR_INFERENCE_API_KEY=...        # from the hackathon gift code
export FARADAY_TEXT_MODEL=glm-5.3-flash   # confirm against /api/models
export PROVEIT_COLLECTION=collection/demo
uvicorn review_app:app --app-dir orchestrator --host 0.0.0.0 --port 8120
```

Tests (no Docker, no key needed): `python3 -m pytest tests/ -q`.

---

## Layout

```
orchestrator/  control plane: review_app (FastAPI), cage runner, parser rank,
               span verifier, run store, hash-chained audit, inference client
collection/    parse_entry (the sandboxed parser), make_stress, build_demo
cage/          the sandbox image (Dockerfile) — its job is to run the parser
sinkhole/      egress sink for the sealing proof (records attempts, never drops silently)
canary/        the cage-sealing canary (forbidden ops, counted)
scripts/       verify_cage.sh (sealing proof), provision.sh, fetch_trec.sh
ui/            proveit.html — the six-tab review interface
tests/         parser caps + span verification + cage posture + audit tamper-evidence
```

## License

MIT. See [LICENSE](LICENSE).
