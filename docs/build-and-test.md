# Build and test

Run commands from the repository root on Linux/AMD64. Building requires Podman, Bash, and Python 3. The local build script expects the digest-pinned Fedora base image to be present locally. Image scanning requires Python 3.14 with `compression.zstd`, curl, tar, sha256sum, and outbound Internet access for scanner downloads and database updates.

## Build a local image

Pull the base image and build the current SDK line:

```sh
podman pull registry.fedoraproject.org/fedora-minimal@sha256:694cfd38a85e4c48bae777d37e4ca8d5f0ee0dd36ace04294f23b72bf9bd3475
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

The image smoke test covers .NET restore/build/run and MSTest, Node/npm, Python virtual environments and `uv`, Git, GitHub CLI, Azure CLI, ripgrep, and the Podman remote client. Client checks cover the RPM-owned binary and alias, version, command help and an explicit missing-socket failure. Both root and nonroot runs use fresh writable homes. No real engine socket is discovered or contacted by the normal smoke test. It does not authenticate to GitHub or Azure and does not test browser software.

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

## Opt-in remote service check

This check is separate from ordinary image smoke tests. It requires an explicitly authorised isolated rootless Podman service, permission to use its Unix socket, and an immutable base image already present in that service's storage. The service account must have only the host access intended for the test. Do not select a production engine or an arbitrary runner's default socket.

After a candidate build, supply all inputs explicitly:

```sh
bash tests/run-podman-remote.sh \
  --ledger "$OWNERSHIP_LEDGER" \
  --socket "$APPROVED_TEST_SOCKET" \
  --expect-storage "$APPROVED_TEST_STORAGE" \
  --base-image "$APPROVED_IMMUTABLE_TEST_BASE"
```

The socket and storage values are paths on the machine running the check. The base is an immutable image reference already available to the remote service. The wrapper launches the candidate from the local build ledger and keeps its local-engine resources separate from workload resources created in the remote engine.

The check verifies rootless mode and the exact expected graph root before creating resources. It exercises a streamed build context, image execution, named-volume persistence, a dedicated network and workload limits, then checks exact-resource cleanup and baseline preservation. Failure and interruption receipts are retained for recovery. A failed cleanup is a failed check, not a passing workload result.

For recovery, retain the candidate image, build ledger and recorded evidence directory. The build ledger's `remote_test.directory` identifies the directory containing `remote.json`, `workload.log` and any later `cleanup.log`. Retry cleanup with all the original target parameters:

```sh
bash tests/run-podman-remote.sh \
  --ledger "$OWNERSHIP_LEDGER" \
  --socket "$APPROVED_TEST_SOCKET" \
  --expect-storage "$APPROVED_TEST_STORAGE" \
  --base-image "$APPROVED_IMMUTABLE_TEST_BASE" \
  --cleanup-only
```

Recovery retries cleanup; it does not turn a previously failed workload into a passing workload result.

No service, endpoint, SELinux exception, permission change or base-image pull is provisioned automatically. Hosts whose policy prevents the socket mount need a separate integration decision. Fake-adapter source tests validate orchestration and recovery behavior; only an actual authorised service run establishes live compatibility. Default CI does not run this check. See [Podman remote client](podman-remote.md) for path semantics and socket authority.

## Image scan

The manual image-verification workflow builds and smoke-tests the image, scans its layers, then publishes the exact candidate to GHCR if every preceding step succeeds. It runs only when manually dispatched on `main`. It publishes `ghcr.io/thesereyn/hermes-dev-dotnet:<major.minor>` and `:latest`, deriving the version tag from the pinned .NET SDK in `fedora44-dotnet10/versions.json`. The build job has `contents: read` and `packages: write`; it uses the job's `GITHUB_TOKEN` and needs no personal access token. The workflow does not change package visibility.

It retains publication copies of scan reports as GitHub Actions artifacts for 30 days. These include the image identity, package inventory, advisory IDs, severities, suggested fixed versions, and scan completion status. Raw scanner reports, image configuration, secret matches, image archives, and extracted scan contents are not uploaded.

Vulnerability matches at any severity are reported without failing verification. Known-benign corpus and layer findings remain in the reports but do not fail verification. Their image path, file SHA-256, rule, and count must match `tests/known-benign.json`. Changed content, additional matches, and unreviewed findings fail verification. Native archive secret matches, failed scans, and incomplete coverage also fail verification.

The workflow fails if it detects any of the following:

- Unreviewed secret matches
- Unreviewed layer-audit findings
- Incomplete nested-archive coverage
- Failed scan stages

See the [vulnerability register](vulnerabilities.md) for the findings from the 2026-10-19 scan.
