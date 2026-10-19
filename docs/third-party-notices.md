# Third-party notices

This image combines a Fedora 44 base with packages from Fedora's `fedora` and `updates` repositories. The included toolchains and utilities are maintained by their respective upstream projects and packaged for Fedora.

The image includes the .NET SDK and ASP.NET Core runtime, Node.js and npm, Python and `uv`, Git, GitHub CLI, Azure CLI, ripgrep, and the Podman remote client. Project information and notices are available from the upstream suppliers:

- [Fedora Project](https://fedoraproject.org/)
- [.NET](https://dotnet.microsoft.com/)
- [Node.js](https://nodejs.org/)
- [Python](https://www.python.org/)
- [uv](https://github.com/astral-sh/uv)
- [Git](https://git-scm.com/)
- [GitHub CLI](https://cli.github.com/)
- [Azure CLI](https://github.com/Azure/azure-cli)
- [ripgrep](https://github.com/BurntSushi/ripgrep)
- [Podman](https://podman.io/), the remote client

The Fedora `podman-remote` 5.8.9 RPM declares `Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND ISC AND MIT AND MPL-2.0` for the client and bundled components. Its source package is `podman-5.8.9-1.fc44.src.rpm`. Fedora's package metadata describes this remote client as experimental; this image is a development environment, not a production-hosting runtime.

Supplier-provided notices are retained with their packages in the image.
