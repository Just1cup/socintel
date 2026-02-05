#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  echo "Virtualenv not found at ${ROOT_DIR}/.venv. Create it first (e.g. python -m venv .venv)."
  exit 1
fi

exec "${ROOT_DIR}/.venv/bin/python" "${ROOT_DIR}/backend/socintel.py"
