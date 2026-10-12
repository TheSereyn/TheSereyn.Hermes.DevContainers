# Build and test

Run commands from the repository root on Linux/AMD64. Building requires Podman, Bash, and Python 3. The local build script expects the digest-pinned Fedora base image to be present locally. Image scanning requires Python 3.14 with `compression.zstd`, curl, tar, sha256sum, and outbound Internet access for scanner downloads and database updates.

## Build a local image

Pull the base image and build the current SDK line:

```sh
podman pull quay.io/fedora/fedora-minimal@sha256:94938a50b2d2ca73dbaa2529e4f4697e3f734276139ebb5767866b064746532d
bash fedora44-dotnet10/build-local.sh
```

The script tags the image as `localhost/hermes-dev-dotnet:10.0` and updates `localhost/hermes-dev-dotnet:latest`. Use `--version-only` to rebuild an older SDK line without moving `latest`:

```sh
bash fedora44-dotnet10/build-local.sh --version-only
```

The build verifies that the installed RPM inventory matches the package lock. It records the package-lock and recipe hashes in image labels. It does not push an image to a registry.

## Package updates

The Fedora base image is pinned by digest. RPM installation uses the live Fedora repositories, then checks the installed packages against `fedora44-dotnet10/rpm-packages.lock`. If those repositories change, a build can fail the inventory check. The lock records a tested inventory; it does not keep old RPMs available.

A package update requires a new candidate inventory and matching tool versions in `fedora44-dotnet10/versions.json`. Review changes to the base image, package list, and tool versions together. Run source tests, rebuild with the updated lock, run smoke tests, and scan the new image. Update the vulnerability register with new findings and any resolutions confirmed by that scan.

## Run source tests

The test suite uses Python's standard `unittest` library and PyYAML. Install the declared test dependencies in a virtual environment, then run the suite and check shell syntax:

```sh
python3 -m venv /tmp/devcontainer-test-venv
/tmp/devcontainer-test-venv/bin/python -m pip install -r tests/requirements.txt
PATH="/tmp/devcontainer-test-venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests -v
for script in tests/*.sh fedora44-dotnet10/build-local.sh fedora44-dotnet10/tests/smoke.sh; do
  bash -n "$script" || exit
done
```

The image smoke test covers .NET restore/build/run and MSTest, Node/npm, Python virtual environments and `uv`, Git, GitHub CLI, Azure CLI, and ripgrep. It does not authenticate to GitHub or Azure and does not test browser software.

## Run image checks locally

Use a new directory outside the repository for each run. The ownership ledger tracks only resources created by that run.

```sh
(
  set -eu
  review=$(mktemp -d "${TMPDIR:-/tmp}/devcontainer-review.XXXXXX")
  export OWNERSHIP_LEDGER="$review/ownership.json"
  trap 'bash tests/cleanup.sh' EXIT
  bash tests/build.sh
  bash tests/run-smoke.sh
  image=$(python3 tests/owned_run.py image "$OWNERSHIP_LEDGER")
  podman save --format docker-archive -o "$review/candidate.tar" "$image"
  bash tests/scan.sh "$review/candidate.tar" "$review/evidence"
)
```

Pull the pinned base image before running these checks. The cleanup script removes the run's containers and image, not its reports or image archive. Retain the reports you need and remove the review directory when finished.

## Image scan

The manual image-verification workflow builds and smoke-tests the image, scans its layers, and removes its test resources. It does not publish an image. It retains publication copies of scan reports as GitHub Actions artifacts for 30 days. These include the image identity, package inventory, advisory IDs, severities, suggested fixed versions, and scan completion status. Raw scanner reports, image configuration, secret matches, image archives, and extracted scan contents are not uploaded.

Vulnerability matches at any severity are reported without failing verification. Known-benign corpus and layer findings remain in the reports but do not fail verification. Their image path, file SHA-256, rule, and count must match `tests/known-benign.json`. Changed content, additional matches, and unreviewed findings fail verification. Native archive secret matches, failed scans, and incomplete coverage also fail verification.

The workflow fails if it detects any of the following:

- Unreviewed secret matches
- Unreviewed layer-audit findings
- Incomplete nested-archive coverage
- Failed scan stages

See the [vulnerability register](vulnerabilities.md) for the findings from the 2026-10-12 scan.
