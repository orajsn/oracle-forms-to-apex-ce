#!/usr/bin/env bash
# Development launcher for the real setup wizard, not a full customer release.
set -euo pipefail
unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH PYTHONPATH PYTHONHOME
fox_product_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if ! command -v python3 >/dev/null 2>&1; then
  echo 'FOX bootstrap needs the supported Linux OS Python3 (3.6 or newer).' >&2
  exit 2
fi
exec python3 -I -B "${fox_product_root}/deployment/bootstrap_runtime.py" "$@"
