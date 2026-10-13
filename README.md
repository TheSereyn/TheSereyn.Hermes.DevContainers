# Hermes Agent .NET development container

A container image for the Hermes Agent terminal backend, designed as a drop-in replacement for its default Docker container image. It provides a Fedora 44 Linux/AMD64 environment with the .NET 10 SDK and tools for Node.js, Python, Git, GitHub, Azure, and shell-based work.

The image can also be used as a standalone development container. This repository contains the image recipe and instructions for building and using it.

## Intended use

This image is a development environment for trusted internal networks. It is not a hardened hosting image and is not intended to receive inbound connections from the public Internet. Network access controls are managed by the host or deployment environment.

Vulnerability scans report known issues, including Critical and High findings. These findings do not block image release. The [vulnerability register](docs/vulnerabilities.md) records the scan results and update statuses so users can assess the image for their own use.

## Included software

- Fedora 44 minimal base, pinned by digest
- .NET SDK 10 and ASP.NET Core runtime 10
- Node.js 24 and npm
- Python 3, `venv`, and `uv`
- Git, GitHub CLI, Azure CLI, ripgrep, Bash, OpenSSH client, curl, and CA certificates

Exact package versions are recorded in [`fedora44-dotnet10/versions.json`](fedora44-dotnet10/versions.json) and [`fedora44-dotnet10/rpm-packages.lock`](fedora44-dotnet10/rpm-packages.lock). The build uses Fedora's `fedora` and `updates` repositories. It removes the optional OpenH264 repository and does not add Microsoft or GitHub package repositories.

The image provides `python3`, not a `python` alias. System pip is not installed. Create a virtual environment with `python3 -m venv` to use pip for project dependencies. The image does not include Playwright or a browser runtime.

## Build

The build script creates a local Podman image tagged `localhost/hermes-dev-dotnet:10.0` and updates `localhost/hermes-dev-dotnet:latest` by default. It does not publish an image to a registry.

```sh
podman pull quay.io/fedora/fedora-minimal@sha256:694cfd38a85e4c48bae777d37e4ca8d5f0ee0dd36ace04294f23b72bf9bd3475
bash fedora44-dotnet10/build-local.sh
```

Use `--version-only` when rebuilding an older SDK line without moving the `latest` tag:

```sh
bash fedora44-dotnet10/build-local.sh --version-only
```

See [build and test](docs/build-and-test.md) for source tests, smoke tests, and image scanning.

## Use with Hermes Agent

Hermes supports Docker Engine, Docker Desktop, and Podman through its `docker` terminal backend. Build or load the image into the selected runtime on the machine running Hermes. The examples below use the tag `localhost/hermes-dev-dotnet:10.0`.

### Docker

With Docker Engine or Docker Desktop running, select Docker and set the image tag:

```sh
hermes config set HERMES_DOCKER_BINARY docker
hermes config set terminal.backend docker
hermes config set terminal.docker_image localhost/hermes-dev-dotnet:10.0
```

### Podman

Build the image with the local build script, then select Podman and set the image tag:

```sh
hermes config set HERMES_DOCKER_BINARY podman
hermes config set terminal.backend docker
hermes config set terminal.docker_image localhost/hermes-dev-dotnet:10.0
```

Docker and Podman use separate local image stores. The image must be available in the runtime selected by `HERMES_DOCKER_BINARY`. Set `terminal.docker_image` to the tag used by that runtime.

Start a new Hermes process after changing the settings. See the [Hermes terminal configuration](https://hermes-agent.nousresearch.com/docs/user-guide/configuration#terminal) for backend options.

## Run as a standalone container

Mount a project directory at `/workspace` and start Bash:

```sh
podman run --rm -it \
  -v "$PWD:/workspace" \
  -w /workspace \
  localhost/hermes-dev-dotnet:10.0
```

On SELinux systems, add `:Z` to the volume option if the container cannot access the mounted project directory.

The image scan dated 2026-10-13 found vulnerability matches. See the [vulnerability register](docs/vulnerabilities.md) for findings and update statuses, and [third-party notices](docs/third-party-notices.md) for supplier information.
