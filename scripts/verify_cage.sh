#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Faraday sealing proof. REQUIRES A LIVE DOCKER DAEMON.
#
# This is the script that turns the containment claim into evidence. Run it on
# the Vultr VM before building anything else on top -- if it does not pass,
# nothing above it matters. Record it for the demo video.
# ---------------------------------------------------------------------------
set -uo pipefail
# Python interpreter is overridable: on Windows (Git bash) "python3" resolves to
# the Microsoft Store shim, which is not Python. PYTHON=python works there.
PY="${PYTHON:-python3}"
cd "$(dirname "$0")/.."

NET="${FARADAY_CAGE_NET:-faraday-internal}"
IMG="${FARADAY_CAGE_IMAGE:-faraday-cage:latest}"
SINK_IMG="faraday-sinkhole:latest"
LOGDIR="$(mktemp -d)"
pass=0; fail=0
ok(){ echo "  PASS  $1"; pass=$((pass+1)); }
no(){ echo "  FAIL  $1"; fail=$((fail+1)); }

echo "== 0. daemon =="
docker info >/dev/null 2>&1 && ok "docker daemon reachable" || { no "no docker daemon"; exit 1; }

echo "== 1. build images =="
docker build -q -t "$IMG" -f cage/Dockerfile . >/dev/null && ok "cage image built" || no "cage build failed"
docker build -q -t "$SINK_IMG" sinkhole/ >/dev/null && ok "sinkhole image built" || no "sinkhole build failed"

echo "== 2. internal bridge =="
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --driver bridge --internal "$NET" >/dev/null
if [ "$(docker network inspect "$NET" -f '{{.Internal}}')" = "true" ]; then
  ok "bridge $NET is INTERNAL (no route off the host)"
else
  no "bridge $NET is NOT internal -- cage would have egress"
fi

echo "== 3. start sinkhole =="
docker rm -f faraday-sinkhole >/dev/null 2>&1 || true
docker run -d --name faraday-sinkhole --network "$NET" \
  --network-alias intake.exfil-example.invalid \
  -v "$LOGDIR:/var/log/faraday" "$SINK_IMG" >/dev/null
sleep 2
docker ps --filter name=faraday-sinkhole --filter status=running -q | grep -q . \
  && ok "sinkhole running on $NET" || no "sinkhole did not start"

echo "== 4. PARSE cage has no network at all =="
if docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
     --read-only --tmpfs /work:rw,noexec,nosuid,nodev --user 65534:65534 \
     --entrypoint python3 "$IMG" -c \
     "import socket;socket.create_connection(('1.1.1.1',53),timeout=3)" 2>/dev/null; then
  no "parse cage reached the internet"
else
  ok "parse cage cannot open an external socket"
fi

echo "== 5. canary in the AGENT cage (every attempt must be refused) =="
docker run --rm --network "$NET" --dns 127.0.0.11 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --security-opt "seccomp=$(pwd)/cage/seccomp.json" \
  --read-only --tmpfs /work:rw,noexec,nosuid,nodev,size=64m \
  --user 65534:65534 --memory 512m --memory-swap 512m --pids-limit 128 \
  --entrypoint python3 "$IMG" /opt/faraday/canary.py > "$LOGDIR/canary.json" 2>&1
if "$PY" -c "
import json,sys
d=json.load(open('$LOGDIR/canary.json'))
print('       contained %d/%d'%(d['contained'],d['total']))
for a in d['attempts']:
    print('       %-26s %s  %s'%(a['attempt'],a['outcome'],a['detail'][:60]))
sys.exit(0 if d['sealed'] else 1)"; then
  ok "all canary attempts refused -- cage is sealed"
else
  no "at least one canary attempt SUCCEEDED -- cage is NOT sealed (see above)"
fi

echo "== 6. PARSE cage detects a poisoned document =="
[ -f corpus/generated/DOC_0018.pdf ] || "$PY" corpus/generate.py --out corpus/generated >/dev/null
OUT="$(mktemp -d)"
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
  --read-only --tmpfs /work:rw,noexec,nosuid,nodev --user 65534:65534 \
  -v "$(pwd)/corpus/generated/DOC_0018.pdf:/input/DOC_0018.pdf:ro" \
  -v "$OUT:/output" "$IMG" > "$LOGDIR/parse.json" 2>/dev/null
"$PY" -c "
import json,sys
raw=open('$LOGDIR/parse.json').read().strip().splitlines()
d=json.loads([l for l in raw if l.startswith('{')][-1])
s=d['structural']
print('       injection_suspected =',s['injection_suspected'],'techniques =',s['techniques'])
sys.exit(0 if s['injection_suspected'] else 1)" \
  && ok "injection detected inside the cage" || no "injection NOT detected"

echo "== 7. egress attempts were recorded, not merely dropped =="
if [ -s "$LOGDIR/egress.jsonl" ]; then
  ok "sinkhole recorded $(wc -l < "$LOGDIR/egress.jsonl") attempt(s)"
  echo "       --- containment log ---"
  "$PY" -c "
import json
for l in open('$LOGDIR/egress.jsonl'):
    e=json.loads(l)
    print('       BLOCKED %-5s %-40s %s'%(e['kind'],e.get('host','?'),e.get('path') or e.get('preview','')[:28]))"
else
  no "sinkhole log empty -- escape attempts were invisible"
fi

docker rm -f faraday-sinkhole >/dev/null 2>&1 || true
echo
echo "================  $pass passed, $fail failed  ================"
echo "artifacts: $LOGDIR"
[ "$fail" -eq 0 ] || exit 1
