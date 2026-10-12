#!/usr/bin/env bash
set -euo pipefail
: "${OWNERSHIP_LEDGER:?Set OWNERSHIP_LEDGER to the build run ledger}"
# No suppressed failures. The ledger is retained if verification fails.
exec python3 tests/owned_run.py cleanup "$OWNERSHIP_LEDGER"
