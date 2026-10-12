#!/usr/bin/env bash
# Requires curl, tar, sha256sum, Python 3, and Internet access.
# Vulnerabilities and known-benign matches are reported. Unreviewed findings and incomplete or failed scans fail verification.
set -euo pipefail
archive=$(realpath "$1")
out=$(realpath -m "$2")
# Existing evidence is immutable, including failed and interrupted runs.
if [[ -e "$out" || -L "$out" ]]; then
  printf 'Refusing existing evidence directory: %s\n' "$out" >&2
  exit 2
fi
umask 077
mkdir "$out"
mkdir -p "$out/tools"
fetch_tool() {
  local name=$1 version=$2 filename=$3 checksum=$4 repo=$5
  if [[ -n ${SCAN_TOOL_CACHE:-} ]]; then
    cp -- "$SCAN_TOOL_CACHE/$filename" "$out/tools/$filename"
  else
    curl -fsSL "https://github.com/$repo/releases/download/v$version/$filename" -o "$out/tools/$filename"
  fi
  printf '%s  %s\n' "$checksum" "$out/tools/$filename" | sha256sum -c -
  mkdir -p "$out/tools/$name"
  tar -xzf "$out/tools/$filename" -C "$out/tools/$name"
}
fetch_tool syft 1.54.1 syft_1.54.1_linux_amd64.tar.gz c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47 anchore/syft
fetch_tool grype 0.120.1 grype_0.120.1_linux_amd64.tar.gz 0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d anchore/grype
fetch_tool gitleaks 8.30.1 gitleaks_8.30.1_linux_x64.tar.gz 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb gitleaks/gitleaks
exec python3 "$(dirname "$(realpath "$0")")/scan_candidate.py" "$archive" "$out"
