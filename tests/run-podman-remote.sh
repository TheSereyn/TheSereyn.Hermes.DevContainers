#!/usr/bin/env bash
# Explicitly authorized isolated services only. Never discovers a host socket.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/owned_run.py" remote "$@"
