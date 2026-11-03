#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Faraday sealing proof. REQUIRES A LIVE DOCKER DAEMON.
#
# This is the script that turns the containment claim into evidence. Run it
# before building anything else on top -- if it does not pass, nothing above
# it matters. Record it for the demo video.
#
# Portability notes, learned the hard way on Windows:
#   * "python3" on Windows resolves to the Microsoft Store shim, not an
#     interpreter. PYTHON=python overrides it.
#   * Under Git bash, paths look like /d/project/... but the Docker daemon and
#     python.exe are native Windows programs that cannot resolve them. Every
#     path handed to either one goes through hostpath().
# ---------------------------------------------------------------------------
set -uo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
NET="${FARADAY_CAGE_NET:-faraday-internal}"
IMG="${FARADAY_CAGE_IMAGE:-faraday-cage:latest}"
SINK_IMG="faraday-sinkhole:latest"
LOGDIR="$(mktemp -d)"
pass=0; fail=0
ok(){ echo "  PASS  $1"; pass=$((pass+1)); }
no(){ echo "  FAIL  $1"; fail=$((fail+1)); }

# Translate a POSIX path to one the host daemon / native python understands.
# cygpath -m yields D:/path/with/forward/slashes, which Docker accepts.
hostpath() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Git bash rewrites any argument that looks like a Unix absolute path into a
# Windows one, so "/opt/faraday/canary.py" -- a path INSIDE the container --
# arrived as "C:/Program Files/Git/opt/faraday/canary.py" and the cage could
# not find its own entrypoint. Every host path here already goes through
# hostpath(), so blanket-disabling the rewrite is both safe and necessary.
# ...and exporting MSYS_NO_PATHCONV is not enough: the MSYS runtime rewrites
# arguments as it execs docker.exe, before the variable is consulted. Container
# paths are therefore passed inside a quoted `sh -c` string, which MSYS leaves
# alone because it is not a bare path-shaped argument.

HERE="$(hostpath "$(pwd)")"
HLOG="$(hostpath "$LOGDIR")"

echo "== 0. daemon =="
docker info >/dev/null 2>&1 && ok "docker daemon reachable" || { no "no docker daemon"; exit 1; }
echo "     host paths: $HERE"

echo "== 1. build images =="
docker build -q -t "$IMG" -f cage/Dockerfile . >/dev/null 2>&1 \
  && ok "cage image built" || no "cage build failed"
docker build -q -t "$SINK_IMG" sinkhole/ >/dev/null 2>&1 \
  && ok "sinkhole image built" || no "sinkhole build failed"

echo "== 2. internal bridge =="
docker rm -f faraday-sinkhole >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --driver bridge --internal "$NET" >/dev/null
if [ "$(docker network inspect "$NET" -f '{{.Internal}}')" = "true" ]; then
  ok "bridge $NET is INTERNAL (no route off the host)"
else
  no "bridge $NET is NOT internal -- cage would have egress"
fi

echo "== 3. start sinkhole =="
docker run -d --name faraday-sinkhole --network "$NET" \
  --network-alias intake.exfil-example.invalid \
  --network-alias archive-intake.opposing-counsel-example.invalid \
  -v "$HLOG:/var/log/faraday" "$SINK_IMG" >/dev/null
sleep 3
if docker ps --filter name=faraday-sinkhole --filter status=running -q | grep -q .; then
  ok "sinkhole running on $NET"
else
  no "sinkhole did not start"; docker logs faraday-sinkhole 2>&1 | tail -5
fi

# The cage's resolver must BE the sinkhole. Without --dns, lookups go to
# Docker's embedded resolver (127.0.0.11), which answers NXDOMAIN for an
# invented exfil host; the agent then fails at name resolution and the
# sinkhole never sees a thing. The attempt is blocked, but INVISIBLY -- which
# is the single failure mode this whole design exists to avoid.
SINK_ADDR="$(docker inspect faraday-sinkhole \
  -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" 2>/dev/null)"
if [ -n "$SINK_ADDR" ]; then
  ok "sinkhole reachable at $SINK_ADDR (cage will resolve through it)"
else
  no "could not determine the sinkhole address -- cage DNS cannot be pointed at it"
fi

echo "== 4. PARSE cage has no network at all =="
if docker run --rm --network none --cap-drop ALL \
     --security-opt no-new-privileges:true \
     --read-only --tmpfs /work:rw,noexec,nosuid,nodev --user 65534:65534 \
     --entrypoint python3 "$IMG" -c \
     "import socket;socket.create_connection(('1.1.1.1',53),timeout=3)" 2>/dev/null; then
  no "parse cage reached the internet"
else
  ok "parse cage cannot open an external socket"
fi

echo "== 5. canary in the AGENT cage (every attempt must be refused) =="
[ -f corpus/generated/DOC_0018.pdf ] || "$PY" corpus/generate.py --out corpus/generated >/dev/null
# An evidence file IS mounted, read-only, so the tamper probe actually runs.
# Previously /input was empty, the probe raised StopIteration, and that got
# scored as "contained" -- a pass for a test that never happened.
docker run --rm --network "$NET" --dns "$SINK_ADDR" \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --read-only --tmpfs /work:rw,noexec,nosuid,nodev,size=64m \
  --user 65534:65534 --memory 512m --memory-swap 512m --pids-limit 128 \
  -v "$HERE/corpus/generated/DOC_0018.pdf:/input/DOC_0018.pdf:ro" \
  --entrypoint sh "$IMG" -c 'python3 /opt/faraday/canary.py' > "$LOGDIR/canary.json" 2>&1
# piped on stdin, never opened by path: python may be a native binary that
# cannot resolve this shell's idea of /tmp
if cat "$LOGDIR/canary.json" | "$PY" -c "
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw)
except Exception:
    print('       cage did not return JSON:'); print('       '+raw.strip()[:400]); sys.exit(2)
print('       contained %d (refused %d, sinkholed %d)  allowed %d  skipped %d  of %d'%(
    d['contained'],d.get('refused',0),d.get('sinkholed',0),
    d['allowed'],d['skipped'],d['total']))
for a in d['attempts']:
    print('       %-26s %-8s %s'%(a['attempt'],a['outcome'],a['detail'][:58]))
sys.exit(0 if d['sealed'] else 1)"; then
  ok "all canary attempts refused -- cage is sealed"
else
  no "an attempt SUCCEEDED or a probe was SKIPPED -- not sealed (see above)"
fi

echo "== 6. PARSE cage detects a poisoned document =="
[ -f corpus/generated/DOC_0018.pdf ] || "$PY" corpus/generate.py --out corpus/generated >/dev/null
OUT="$(mktemp -d)"
docker run --rm --network none --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only --tmpfs /work:rw,noexec,nosuid,nodev --user 65534:65534 \
  -v "$HERE/corpus/generated/DOC_0018.pdf:/input/DOC_0018.pdf:ro" \
  -v "$(hostpath "$OUT"):/output" "$IMG" > "$LOGDIR/parse.json" 2>&1
if cat "$LOGDIR/parse.json" | "$PY" -c "
import json,sys
raw=sys.stdin.read()
lines=[l for l in raw.splitlines() if l.strip().startswith('{')]
if not lines:
    print('       cage returned no JSON:'); print('       '+raw.strip()[:400]); sys.exit(2)
s=json.loads(lines[-1])['structural']
print('       injection_suspected =',s['injection_suspected'],' techniques =',s['techniques'])
print('       shadow text:',repr(s['shadow_text'][:90]))
sys.exit(0 if s['injection_suspected'] else 1)"; then
  ok "injection detected inside the cage"
else
  no "injection NOT detected"
fi

echo "== 7. egress attempts were recorded, not merely dropped =="
if [ -s "$LOGDIR/egress.jsonl" ]; then
  ok "sinkhole recorded $(wc -l < "$LOGDIR/egress.jsonl") attempt(s)"
  echo "       --- containment log ---"
  cat "$LOGDIR/egress.jsonl" | "$PY" -c "
import json,sys
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    e=json.loads(l)
    print('       BLOCKED %-5s %-44s %s'%(e['kind'],e.get('host','?'),
          (e.get('path') or e.get('preview','') or '')[:30]))"
else
  no "sinkhole log empty -- escape attempts were invisible"
  docker logs faraday-sinkhole 2>&1 | tail -8
fi

docker rm -f faraday-sinkhole >/dev/null 2>&1 || true
echo
echo "================  $pass passed, $fail failed  ================"
echo "artifacts: $LOGDIR"
[ "$fail" -eq 0 ] || exit 1
