#!/usr/bin/env bash
# Bootstrap a fresh Vultr Cloud Compute instance (Ubuntu 24.04) for Faraday.
set -euo pipefail

echo "== docker =="
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

echo "== system deps =="
apt-get update -qq
apt-get install -y -qq python3-pip python3-venv git

echo "== faraday =="
install -d /var/lib/faraday /var/log/faraday
python3 -m venv /opt/faraday-venv
/opt/faraday-venv/bin/pip install -q -r requirements.txt

echo "== images =="
docker build -q -t faraday-cage:latest -f cage/Dockerfile .
docker build -q -t faraday-sinkhole:latest sinkhole/

echo "== internal bridge =="
docker network inspect faraday-internal >/dev/null 2>&1 || \
  docker network create --driver bridge --internal faraday-internal

echo "== sinkhole =="
docker rm -f faraday-sinkhole 2>/dev/null || true
docker run -d --name faraday-sinkhole --restart unless-stopped \
  --network faraday-internal \
  --network-alias intake.exfil-example.invalid \
  -v /var/log/faraday:/var/log/faraday \
  faraday-sinkhole:latest

echo "== corpus =="
/opt/faraday-venv/bin/python corpus/generate.py --out /var/lib/faraday/corpus

cat >/etc/systemd/system/faraday.service <<UNIT
[Unit]
Description=Faraday control plane
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=$(pwd)
EnvironmentFile=$(pwd)/.env
Environment=FARADAY_CORPUS_DIR=/var/lib/faraday/corpus
Environment=FARADAY_SINK_LOG=/var/log/faraday/egress.jsonl
ExecStart=/opt/faraday-venv/bin/uvicorn orchestrator.main:app --host 0.0.0.0 --port 8080
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable faraday
echo
echo "Next:"
echo "  1. cp .env.example .env && put your Vultr Inference key in it"
echo "  2. curl -H \"Authorization: Bearer \$VULTR_INFERENCE_API_KEY\" \\"
echo "       https://api.vultrinference.com/v1/models   # pick real model IDs"
echo "  3. bash scripts/verify_cage.sh                  # MUST pass before anything else"
echo "  4. systemctl start faraday                      # UI on :8080"
