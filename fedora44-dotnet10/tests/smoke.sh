#!/usr/bin/env bash
set -euo pipefail

for tool in bash sleep python3 node npm uv uvx git gh az rg curl ssh dotnet rpm podman podman-remote; do
  command -v "$tool" >/dev/null || { printf 'MISSING: %s\n' "$tool" >&2; exit 1; }
done
for forbidden in python codex copilot hermes; do
  if command -v "$forbidden" >/dev/null 2>&1; then
    printf 'UNEXPECTED TOOL: %s\n' "$forbidden" >&2
    exit 1
  fi
done

[[ $(dotnet --version) == 10.* ]]
dotnet --list-sdks | grep -F '10.0.112'
[[ $(node --version) == v24.* ]]
[[ $(npm --version) == 11.* ]]
[[ $(python3 --version) == 'Python 3.14.'* ]]
[[ $(uv --version) == 'uv 0.12.24 '* ]]
[[ $(git --version) == 'git version 2.56.0' ]]
[[ $(gh --version | head -1) == 'gh version 2.97.0 '* ]]
[[ $(az version --output json | python3 -c 'import json,sys; print(json.load(sys.stdin)["azure-cli"])') == 2.83.0 ]]
[[ $(rg --version | head -1) == 'ripgrep 15.2.0'* ]]

[[ $(readlink -f "$(command -v podman)") == /usr/bin/podman-remote ]]
[[ $(rpm -q --qf '%{NAME}' -f /usr/bin/podman-remote) == podman-remote ]]
[[ $(podman --version) == "podman version $(rpm -q --qf '%{VERSION}' podman-remote)" ]]
podman build --help >/dev/null
podman run --help >/dev/null
if rpm -q podman >/dev/null 2>&1; then
  printf 'UNEXPECTED LOCAL ENGINE: podman RPM\n' >&2
  exit 1
fi

test -r /usr/share/hermes-dev/rpm-packages.lock
rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort | python3 -c 'import pathlib,sys; expected=pathlib.Path("/usr/share/hermes-dev/rpm-packages.lock").read_text().splitlines(); actual=sys.stdin.read().splitlines(); sys.exit(actual != expected)'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
# This smoke test must not contact a configured host engine.
python3 - "$tmp" <<'PY'
import pathlib, subprocess, sys
endpoint = 'unix://' + str(pathlib.Path(sys.argv[1]) / 'missing.sock')
result = subprocess.run(['podman', '--url', endpoint, 'info'], capture_output=True, text=True, timeout=10)
assert result.returncode != 0, 'missing socket unexpectedly succeeded'
assert 'missing.sock' in result.stderr, result.stderr
assert any(message in result.stderr.lower() for message in ('no such file', 'cannot connect', 'unable to connect')), result.stderr
PY
printf 'fixture-ok\n' > fixture.txt
rg fixture-ok fixture.txt

git init -q git-fixture
git -C git-fixture config user.name Smoke
 git -C git-fixture config user.email smoke@example.invalid
git -C git-fixture -c commit.gpgsign=false commit --allow-empty -m smoke >/dev/null
git -C git-fixture status --short --branch

gh help >/dev/null
az monitor -h >/dev/null
npm view npm@11.16.0 version --json | python3 -c 'import json,sys; assert json.load(sys.stdin) == "11.16.0"'

python3 -m venv pyvenv
pyvenv/bin/python -m pip --version >/dev/null
pyvenv/bin/python -c 'import sys; assert sys.version_info[:2] == (3, 14)'
uv venv uvvenv >/dev/null
uvvenv/bin/python -c 'import json; assert json.loads("{\"ok\":true}")["ok"]'

# Exercise .NET restore, build, run, and test without credentials.
dotnet new console -n App -f net10.0 --no-restore >/dev/null
dotnet restore App --verbosity quiet
dotnet build App --no-restore --verbosity quiet
dotnet run --project App --no-build | grep -F 'Hello, World!'
dotnet new mstest -n Tests -f net10.0 --test-runner Microsoft.Testing.Platform --no-restore >/dev/null
rm -f Tests/Test1.cs Tests/UnitTest1.cs
printf '%s\n' 'using Microsoft.VisualStudio.TestTools.UnitTesting;' '[TestClass] public sealed class ArithmeticTests {' '[TestMethod] public void Addition() { Assert.AreEqual(4, 2 + 2); }' '}' > Tests/ArithmeticTests.cs
printf '{"test":{"runner":"Microsoft.Testing.Platform"}}\n' > global.json
dotnet test --project Tests --verbosity quiet

echo 'SMOKE PASSED'
