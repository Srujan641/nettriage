#!/usr/bin/env bash
# Start the API and the dashboard together; Ctrl-C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -x backend/.venv/bin/nettriage ] || { echo "Run 'make setup' first." >&2; exit 1; }
[ -d frontend/node_modules ] || { echo "Run 'make setup' first." >&2; exit 1; }

backend/.venv/bin/nettriage serve &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT
echo "API:       http://127.0.0.1:8000  (docs at /docs)"
echo "Dashboard: http://localhost:5173"
cd frontend && npm run dev
