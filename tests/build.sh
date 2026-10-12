#!/usr/bin/env bash
set -euo pipefail
: "${OWNERSHIP_LEDGER:?Set OWNERSHIP_LEDGER to a new private path outside the repository}"
exec python3 tests/owned_run.py build "$OWNERSHIP_LEDGER"
