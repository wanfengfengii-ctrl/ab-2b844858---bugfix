#!/usr/bin/env bash
# One-shot verification pipeline. Runs inside the `verify` image and exits
# non-zero as soon as any stage fails.
set -euo pipefail

echo "==> [1/3] Backend test suite (pytest)"
cd /app/backend
python -m pytest -q tests/

echo "==> [2/3] Frontend production build (tsc + vite)"
cd /app/frontend
npm run build

echo "==> [3/3] HTTP smoke tests against ${BASE_URL}"
python /app/verify/smoke.py

echo "==> ALL VERIFICATION STAGES PASSED"
