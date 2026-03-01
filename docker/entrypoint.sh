#!/usr/bin/env bash
set -euo pipefail
cd /workspace

# Ensure editable install if using pyproject
if [ -f pyproject.toml ]; then
  pip install -e . >/dev/null 2>&1 || true
fi

exec "$@"
