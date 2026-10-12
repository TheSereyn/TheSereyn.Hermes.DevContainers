#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CONTEXT="$ROOT/fedora44-dotnet10"
RUNTIME="${CONTAINER_RUNTIME:-podman}"
UPDATE_LATEST=1

usage() {
  printf 'Usage: %s [--version-only|--latest]\n' "$0"
  printf 'Build local localhost/hermes-dev-dotnet:<SDK major.minor>; --version-only leaves the latest alias unchanged.\n'
}

for arg in "$@"; do
  case "$arg" in
    --latest) UPDATE_LATEST=1 ;;
    --version-only) UPDATE_LATEST=0 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
  esac
done

mapfile -t metadata < <(
  PYTHONPATH="$ROOT/tests${PYTHONPATH:+:$PYTHONPATH}" python3 -c '
import json, pathlib, sys, owned_run
context = pathlib.Path(sys.argv[1])
version = json.loads((context / "versions.json").read_text())["tools"]["dotnet_sdk"]
print(".".join(version.split(".")[:2]))
print(owned_run.package_lock_sha256())
print(owned_run.recipe_sha256())
' "$CONTEXT"
)
if (( ${#metadata[@]} != 3 )); then
  printf 'Could not derive SDK version and recipe hashes.\n' >&2
  exit 1
fi

VERSION_TAG="${metadata[0]}"
PACKAGE_LOCK_SHA256="${metadata[1]}"
RECIPE_SHA256="${metadata[2]}"
IMAGE_REPOSITORY="localhost/hermes-dev-dotnet"

args=(build --pull=never --layers=false --force-rm
  --build-arg "PACKAGE_LOCK_SHA256=$PACKAGE_LOCK_SHA256"
  --build-arg "RECIPE_SHA256=$RECIPE_SHA256"
  -t "$IMAGE_REPOSITORY:$VERSION_TAG")
if (( UPDATE_LATEST )); then
  args+=(-t "$IMAGE_REPOSITORY:latest")
fi
args+=("$CONTEXT")

"$RUNTIME" "${args[@]}"
printf 'Built local image tag: %s:%s\n' "$IMAGE_REPOSITORY" "$VERSION_TAG"
if (( UPDATE_LATEST )); then
  printf 'Updated local image tag: %s:latest\n' "$IMAGE_REPOSITORY"
fi
