#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pip3 install -r "${ROOT_DIR}/requirements.txt"
npm install --prefix "${ROOT_DIR}"
python3 "${ROOT_DIR}/backend/socintel.py" --ip 8.8.8.8
