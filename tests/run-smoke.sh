#!/usr/bin/env bash
set -euo pipefail
: "${OWNERSHIP_LEDGER:?Set OWNERSHIP_LEDGER to the build run ledger}"
exec python3 tests/owned_run.py smoke "$OWNERSHIP_LEDGER"
