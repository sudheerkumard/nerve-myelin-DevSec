#!/usr/bin/env bash
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
#
# RAT Flea DevSec — start the customer live demo on http://localhost:8080
#   ./demo/start-demo.sh            # Python (default)
#   ./demo/start-demo.sh --docker   # Docker Compose
set -euo pipefail
cd "$(dirname "$0")/.."
export MYELIN_ENV_FILE="${MYELIN_ENV_FILE:-config/backend/myelin.env.demo}"
URL="http://localhost:8080"

if [[ "${1:-}" == "--docker" ]]; then
  docker compose up --build -d
else
  export MYELIN_CONSOLE_PATH="$(pwd)/demo/offline/RAT-Flea-DevSec-Demo-Console.html"
  command -v python3 >/dev/null || { echo "Python 3.10+ is required (or use --docker)"; exit 1; }
  [[ -d .venv ]] || python3 -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
  pip install -q -r backend/requirements.txt
  pip install -q -e . >/dev/null
  python scripts/build_console.py
  cd backend
  nohup uvicorn app.main:app --host 127.0.0.1 --port 8080 > ../demo/.demo.log 2>&1 < /dev/null &
  echo $! > ../demo/.demo.pid
  cd ..
fi

for _ in $(seq 1 30); do curl -fsS "$URL/api/health" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$URL/api/health" >/dev/null || { echo "API did not start — see demo/.demo.log"; exit 1; }
echo "RAT Flea DevSec demo running at $URL  (stop: ./demo/stop-demo.sh)"
(command -v open >/dev/null && open "$URL") || (command -v xdg-open >/dev/null && xdg-open "$URL") || true
