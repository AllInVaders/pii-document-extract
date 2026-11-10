#!/usr/bin/env bash
# Local run. Generates a per-session vault key if none is set.
set -euo pipefail
cd "$(dirname "$0")"
PORT="${PORT:-8796}"

if [[ ! -f .env.local ]]; then
  echo "Missing .env.local. Run ./scripts/bootstrap_gcp.sh first." >&2
  exit 1
fi
if [[ -z "${VAULT_API_KEY:-}" ]]; then
  VAULT_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  export VAULT_API_KEY
fi

PY=python3
if [[ -x .venv/bin/python ]]; then PY=.venv/bin/python; fi

echo "Secure ID Extract on http://localhost:${PORT}"
echo "Vault key for this session: ${VAULT_API_KEY}"
exec "$PY" -m uvicorn app.server:app --host "${HOST:-127.0.0.1}" --port "${PORT}" --no-server-header
