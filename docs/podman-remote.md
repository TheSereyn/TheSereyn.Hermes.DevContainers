# Podman remote client

The image includes Fedora's `podman-remote` package. Both `podman` and `podman-remote` invoke the remote client. A Podman API service performs builds and runs containers outside this development container. The image contains no nested engine or API service.

The shared image does not select an endpoint or mount a socket. Without an accessible service, engine operations fail. Client installation alone grants no host-engine access. Docker CLI and Compose are not included.

## Connect to a service

Provision the service and its access policy outside the image. Use an isolated rootless engine where the development agent should not control other users' workloads. A socket gives the client the service account's full Podman API authority, including access to host files that account can read. A read-only socket mount does not make the API read-only.

For a standalone container, this example mounts an explicitly selected socket directory. The service socket is named `podman.sock` in this example:

```sh
# Set PODMAN_SOCKET_DIRECTORY to the approved service's socket directory.
podman run --rm -it \
  --mount "type=bind,source=$PODMAN_SOCKET_DIRECTORY,target=/run/container-engine,readonly" \
  --env CONTAINER_HOST=unix:///run/container-engine/podman.sock \
  localhost/hermes-dev-dotnet:10.0
```

The example assumes the host's Unix permissions and SELinux policy already permit access. Do not relabel the socket or disable host SELinux to make the command work. Any container-specific SELinux exception needs a separate host security decision. Mounting the directory rather than one socket inode allows a restarted socket-activation service to replace its socket.

Inside the development container:

```sh
podman info
podman build -t localhost/component:dev .
```

Alternatively, select the endpoint for each command with `podman --url unix:///run/container-engine/podman.sock ...`. Keep test ports on loopback unless wider exposure is intended and authorised. Set suitable resource limits when starting workloads.

For Hermes, keep `terminal.backend: docker` and the host's engine selection separate from the remote client inside the sandbox. Do not set `CONTAINER_HOST` through `terminal.docker_env`: Hermes also passes that mapping into the host engine process, where it can redirect sandbox creation. Select the endpoint with an explicit URL or a command-local export inside the terminal. Keep host-specific endpoints out of the shared image.

## Paths and credentials

A build context streams from the client to the service. `COPY` therefore reads files from the client-side build context. Bind-mount source paths instead refer to the service host and are opened with that service account's permissions. A client path such as `/workspace` is not automatically shared with the service.

Use image `COPY` instructions, service-owned named volumes and `podman cp` when the service cannot read the client workspace. Do not grant broad host-home access as a path workaround. Client environment variables and credentials are not automatically passed to workload containers; pass only the values a particular workload requires. Never bake credentials into image layers or build arguments.

## Verification

The normal image smoke test checks the client binary, its RPM ownership and version, build/run help and bounded failure against an explicitly missing socket. These checks run as root and nonroot with fresh homes, without contacting a real engine.

The opt-in socket test requires an explicitly selected test service and records resources separately from the host engine that launches the development image. Its interface and safety requirements are documented in [build and test](build-and-test.md). Default CI does not connect to a host socket. Client version output and fake-adapter tests are not evidence of live service compatibility.

See the upstream [remote client reference](https://docs.podman.io/en/latest/markdown/podman-remote.1.html) and [API service security model](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html).
