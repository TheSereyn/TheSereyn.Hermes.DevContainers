# Image vulnerability register

This register reports scanner matches for the Fedora 44, Linux/AMD64, .NET 10 development image. Matches identify packages and advisories; they do not establish exploitability.

## Current snapshot

- Image config ID: `sha256:60fdb019b39eb7a39372a1257ec4f093ddaf322452fe11f11a49f3f69769a29c`.
- Image archive SHA-256: `2199a756e6f44239a878fbfa54e4974937c56d4dcec0d8a939cd2d9bf9aca6b6`.
- Scan date: 2026-10-19. Scanner: Grype 0.120.1.
- Vulnerability database: schema v6.1.10, built 2026-10-19T06:39:15Z; imported database digest `xxh64:2ce9c386b446f139`.
- Findings: 149 package/advisory matches across 103 unique advisory IDs: 5 Critical, 79 High, 56 Medium, 6 Low, and 3 Unknown.
- Matches by source: 40 .NET, 39 Podman remote, 15 GitHub CLI, 29 Node.js/npm, 20 Azure CLI Python dependencies, and 6 Fedora RPM matches.

## Scan verification

The scan completed against the exact image archive. It found 95 corpus secret-pattern matches and 20 layer-pattern matches. All matched the reviewed, exact-content registry. The scan found no native-archive secret matches, no unreviewed findings, and no nested-archive coverage gaps. The scanner reports remain available in the private candidate evidence; raw reports are not published here.

## Previous snapshot

The 2026-10-13 scan recorded 64 advisory matches on image config `sha256:659a29220dd17b5341893af0a3016739e640caa44d90d950ccd8b4a9f7cdf176`, with 3 Critical, 26 High, 28 Medium, 5 Low, and 2 Unknown matches. It used a different image and vulnerability database. The totals are not a controlled package-only comparison. The earlier detailed snapshot remains in repository history.

## Tracking policy

Vulnerability matches are reported at every severity and do not block image release. A scanner-listed fixed version does not establish that an update is available in the image source. Findings remain open until a scan of an updated image confirms resolution. The image is rebuilt and rescanned after applicable updates to the Fedora base, .NET SDK, or included tools.

Each row below is one Grype package/advisory match. Fix versions and direct advisory links come from the scan report. Statuses distinguish a scanner-listed candidate from confirmed package availability.

### .NET SDK and ASP.NET Core reference packs (40 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `Microsoft.AspNetCore.SignalR.Common` | [GHSA-334f-vvp4-7g6p](https://github.com/advisories/GHSA-334f-vvp4-7g6p) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-2fmv-rv2c-59x7](https://github.com/advisories/GHSA-2fmv-rv2c-59x7) | Medium | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Pkcs` | [GHSA-846f-f764-76mx](https://github.com/advisories/GHSA-846f-f764-76mx) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-7hqp-7c5m-4vq6](https://github.com/advisories/GHSA-7hqp-7c5m-4vq6) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-7hqp-7c5m-4vq6](https://github.com/advisories/GHSA-7hqp-7c5m-4vq6) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-7hqp-7c5m-4vq6](https://github.com/advisories/GHSA-7hqp-7c5m-4vq6) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-7hqp-7c5m-4vq6](https://github.com/advisories/GHSA-7hqp-7c5m-4vq6) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-7hqp-7c5m-4vq6](https://github.com/advisories/GHSA-7hqp-7c5m-4vq6) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-7hqp-7c5m-4vq6](https://github.com/advisories/GHSA-7hqp-7c5m-4vq6) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-7hqp-7c5m-4vq6](https://github.com/advisories/GHSA-7hqp-7c5m-4vq6) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-c399-9853-6jmj](https://github.com/advisories/GHSA-c399-9853-6jmj) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-c399-9853-6jmj](https://github.com/advisories/GHSA-c399-9853-6jmj) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-c399-9853-6jmj](https://github.com/advisories/GHSA-c399-9853-6jmj) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-c399-9853-6jmj](https://github.com/advisories/GHSA-c399-9853-6jmj) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-c399-9853-6jmj](https://github.com/advisories/GHSA-c399-9853-6jmj) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-c399-9853-6jmj](https://github.com/advisories/GHSA-c399-9853-6jmj) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-c399-9853-6jmj](https://github.com/advisories/GHSA-c399-9853-6jmj) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-r955-8q5j-3h83](https://github.com/advisories/GHSA-r955-8q5j-3h83) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-r955-8q5j-3h83](https://github.com/advisories/GHSA-r955-8q5j-3h83) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-r955-8q5j-3h83](https://github.com/advisories/GHSA-r955-8q5j-3h83) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-r955-8q5j-3h83](https://github.com/advisories/GHSA-r955-8q5j-3h83) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-r955-8q5j-3h83](https://github.com/advisories/GHSA-r955-8q5j-3h83) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-r955-8q5j-3h83](https://github.com/advisories/GHSA-r955-8q5j-3h83) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |
| `System.Security.Cryptography.Xml` | [GHSA-r955-8q5j-3h83](https://github.com/advisories/GHSA-r955-8q5j-3h83) | High | `10.0.12` | `10.0.13` | Pending Microsoft .NET update; candidate version listed |

### Podman remote client (39 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `github.com/containers/podman/v5` | [GHSA-4hq8-gpf5-8p68](https://github.com/advisories/GHSA-4hq8-gpf5-8p68) | High | `v5.0.0-20261012000000-9c608fd3e228+dirty` | `5.8.4` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/containers/podman/v5` | [GHSA-65gg-3w2w-hr4h](https://github.com/advisories/GHSA-65gg-3w2w-hr4h) | High | `v5.0.0-20261012000000-9c608fd3e228+dirty` | `5.5.2` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/containers/podman/v5` | [GHSA-874v-pj72-92f3](https://github.com/advisories/GHSA-874v-pj72-92f3) | Medium | `v5.0.0-20261012000000-9c608fd3e228+dirty` | `5.0.1` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/containers/podman/v5` | [GHSA-fhqq-8f65-5xfc](https://github.com/advisories/GHSA-fhqq-8f65-5xfc) | Medium | `v5.0.0-20261012000000-9c608fd3e228+dirty` | `5.2.4` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/containers/podman/v5` | [GHSA-hc8w-h2mf-hp59](https://github.com/advisories/GHSA-hc8w-h2mf-hp59) | Medium | `v5.0.0-20261012000000-9c608fd3e228+dirty` | `5.8.2` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/containers/podman/v5` | [GHSA-m68q-4hqr-mc6f](https://github.com/advisories/GHSA-m68q-4hqr-mc6f) | High | `v5.0.0-20261012000000-9c608fd3e228+dirty` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `github.com/containers/podman/v5` | [GHSA-q6r4-3wmg-fwcq](https://github.com/advisories/GHSA-q6r4-3wmg-fwcq) | Medium | `v5.0.0-20261012000000-9c608fd3e228+dirty` | `5.7.1` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/containers/podman/v5` | [GHSA-rpcc-p8xm-rc6p](https://github.com/advisories/GHSA-rpcc-p8xm-rc6p) | High | `v5.0.0-20261012000000-9c608fd3e228+dirty` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `github.com/containers/podman/v5` | [GHSA-wp3j-xq48-xpjw](https://github.com/advisories/GHSA-wp3j-xq48-xpjw) | High | `v5.0.0-20261012000000-9c608fd3e228+dirty` | `5.6.1` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/docker/distribution` | [GHSA-685w-q87j-wqw3](https://github.com/advisories/GHSA-685w-q87j-wqw3) | Medium | `v2.8.3+incompatible` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `github.com/docker/docker` | [GHSA-pxq6-2prw-chj9](https://github.com/advisories/GHSA-pxq6-2prw-chj9) | Medium | `v28.5.1+incompatible` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `github.com/docker/docker` | [GHSA-rg2x-37c3-w2rh](https://github.com/advisories/GHSA-rg2x-37c3-w2rh) | High | `v28.5.1+incompatible` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `github.com/docker/docker` | [GHSA-vp62-88p7-qqf5](https://github.com/advisories/GHSA-vp62-88p7-qqf5) | Medium | `v28.5.1+incompatible` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `github.com/docker/docker` | [GHSA-x86f-5xw2-fm2r](https://github.com/advisories/GHSA-x86f-5xw2-fm2r) | High | `v28.5.1+incompatible` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `github.com/docker/docker` | [GO-2026-4887](https://pkg.go.dev/vuln/GO-2026-4887) | High | `v28.5.1+incompatible` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `github.com/klauspost/compress` | [GO-2026-5841](https://pkg.go.dev/vuln/GO-2026-5841) | Unknown | `v1.18.0` | `1.18.7` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/moby/buildkit` | [GHSA-4c29-8rgm-jvjj](https://github.com/advisories/GHSA-4c29-8rgm-jvjj) | High | `v0.25.1` | `0.28.1` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/moby/buildkit` | [GHSA-4vrq-3vrq-g6gg](https://github.com/advisories/GHSA-4vrq-3vrq-g6gg) | High | `v0.25.1` | `0.28.1` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/moby/buildkit` | [GHSA-7236-3392-c5c6](https://github.com/advisories/GHSA-7236-3392-c5c6) | Medium | `v0.25.1` | `0.31.1` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/moby/buildkit` | [GHSA-72x6-4j93-7w86](https://github.com/advisories/GHSA-72x6-4j93-7w86) | Low | `v0.25.1` | `0.31.1` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/moby/go-archive` | [GHSA-hfg8-hc9c-6c3h](https://github.com/advisories/GHSA-hfg8-hc9c-6c3h) | High | `v0.1.0` | `0.3.0` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/moby/sys/user` | [GHSA-mjcv-p78q-w5fw](https://github.com/advisories/GHSA-mjcv-p78q-w5fw) | Medium | `v0.4.0` | `0.4.1` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/opencontainers/runc` | [GHSA-xjvp-4fhw-gc47](https://github.com/advisories/GHSA-xjvp-4fhw-gc47) | Medium | `v1.3.4` | `1.3.6` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/sigstore/fulcio` | [GHSA-59jp-pj84-45mr](https://github.com/advisories/GHSA-59jp-pj84-45mr) | Medium | `v1.7.1` | `1.8.5` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/sigstore/fulcio` | [GHSA-f5mr-q85p-6hh6](https://github.com/advisories/GHSA-f5mr-q85p-6hh6) | High | `v1.7.1` | `1.8.6` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/sigstore/fulcio` | [GHSA-f83f-xpx7-ffpw](https://github.com/advisories/GHSA-f83f-xpx7-ffpw) | High | `v1.7.1` | `1.8.3` | Pending Fedora podman-remote package update; candidate version listed |
| `github.com/sigstore/sigstore` | [GHSA-fcv2-xgw5-pqxf](https://github.com/advisories/GHSA-fcv2-xgw5-pqxf) | Medium | `v1.9.5` | `1.10.4` | Pending Fedora podman-remote package update; candidate version listed |
| `go.opentelemetry.io/otel` | [GHSA-mh2q-q3fh-2475](https://github.com/advisories/GHSA-mh2q-q3fh-2475) | High | `v1.36.0` | `1.41.0` | Pending Fedora podman-remote package update; candidate version listed |
| `golang.org/x/crypto` | [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) | Unknown | `v0.56.0` | — | Pending Fedora podman-remote package update; no fixed version listed |
| `golang.org/x/net` | [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603) | High | `v0.57.0` | `0.60.0` | Pending Fedora podman-remote package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610) | High | `v0.57.0` | `0.60.0` | Pending Fedora podman-remote package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611) | High | `v0.57.0` | `0.60.0` | Pending Fedora podman-remote package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6612](https://pkg.go.dev/vuln/GO-2026-6612) | Critical | `v0.57.0` | `0.60.0` | Pending Fedora podman-remote package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617) | High | `v0.57.0` | `0.60.0` | Pending Fedora podman-remote package update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-2v4p-qf9q-27wj](https://github.com/advisories/GHSA-2v4p-qf9q-27wj) | High | `v1.72.2` | `1.82.2` | Pending Fedora podman-remote package update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-hrxh-6v49-42gf](https://github.com/advisories/GHSA-hrxh-6v49-42gf) | High | `v1.72.2` | `1.82.1` | Pending Fedora podman-remote package update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-p77j-4mvh-x3m3](https://github.com/advisories/GHSA-p77j-4mvh-x3m3) | Critical | `v1.72.2` | `1.79.3` | Pending Fedora podman-remote package update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-qc2q-p7wx-3px3](https://github.com/advisories/GHSA-qc2q-p7wx-3px3) | Medium | `v1.72.2` | `1.83.1` | Pending Fedora podman-remote package update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-vp52-pcj8-j9qc](https://github.com/advisories/GHSA-vp52-pcj8-j9qc) | High | `v1.72.2` | `1.83.1` | Pending Fedora podman-remote package update; candidate version listed |

### GitHub CLI (`gh`) (15 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `golang.org/x/crypto` | [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) | Unknown | `v0.54.0` | — | Pending GitHub CLI package update; no fixed version listed |
| `golang.org/x/crypto` | [GO-2026-6303](https://pkg.go.dev/vuln/GO-2026-6303) | High | `v0.54.0` | `0.55.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/crypto` | [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) | High | `v0.54.0` | `0.56.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/crypto` | [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) | High | `v0.54.0` | `0.56.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/mod` | [GO-2026-6179](https://pkg.go.dev/vuln/GO-2026-6179) | High | `v0.37.0` | `0.40.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/mod` | [GO-2026-6180](https://pkg.go.dev/vuln/GO-2026-6180) | High | `v0.37.0` | `0.40.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603) | High | `v0.56.0` | `0.60.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610) | High | `v0.56.0` | `0.60.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611) | High | `v0.56.0` | `0.60.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6612](https://pkg.go.dev/vuln/GO-2026-6612) | Critical | `v0.56.0` | `0.60.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617) | High | `v0.56.0` | `0.60.0` | Pending GitHub CLI package update; candidate version listed |
| `golang.org/x/text` | [GO-2026-6629](https://pkg.go.dev/vuln/GO-2026-6629) | High | `v0.40.0` | `0.41.0` | Pending GitHub CLI package update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-2v4p-qf9q-27wj](https://github.com/advisories/GHSA-2v4p-qf9q-27wj) | High | `v1.82.1` | `1.82.2` | Pending GitHub CLI package update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-qc2q-p7wx-3px3](https://github.com/advisories/GHSA-qc2q-p7wx-3px3) | Medium | `v1.82.1` | `1.83.1` | Pending GitHub CLI package update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-vp52-pcj8-j9qc](https://github.com/advisories/GHSA-vp52-pcj8-j9qc) | High | `v1.82.1` | `1.83.1` | Pending GitHub CLI package update; candidate version listed |

### Node.js and npm (29 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `brace-expansion` | [GHSA-3jxr-9vmj-r5cp](https://github.com/advisories/GHSA-3jxr-9vmj-r5cp) | High | `5.0.6` | `5.0.7` | Pending Node.js/npm packages update; candidate version listed |
| `brace-expansion` | [GHSA-6j4f-fj2g-mc7p](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p) | High | `5.0.6` | `5.0.10` | Pending Node.js/npm packages update; candidate version listed |
| `brace-expansion` | [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg) | High | `5.0.6` | `5.0.8` | Pending Node.js/npm packages update; candidate version listed |
| `brace-expansion` | [GHSA-q2hr-2g5m-vwhr](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr) | Medium | `5.0.6` | `5.0.12` | Pending Node.js/npm packages update; candidate version listed |
| `brace-expansion` | [GHSA-qhr7-859c-m2p7](https://github.com/advisories/GHSA-qhr7-859c-m2p7) | High | `5.0.6` | `5.0.11` | Pending Node.js/npm packages update; candidate version listed |
| `brace-expansion` | [GHSA-rgw5-rvv9-x895](https://github.com/advisories/GHSA-rgw5-rvv9-x895) | High | `5.0.6` | `5.0.9` | Pending Node.js/npm packages update; candidate version listed |
| `http-cache-semantics` | [GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp) | High | `4.2.0` | — | Pending Node.js/npm packages update; no fixed version listed |
| `ip-address` | [GHSA-22jq-vg5j-6vgg](https://github.com/advisories/GHSA-22jq-vg5j-6vgg) | Medium | `10.2.0` | `10.2.1` | Pending Node.js/npm packages update; candidate version listed |
| `ip-address` | [GHSA-2vr4-cq9g-pvrc](https://github.com/advisories/GHSA-2vr4-cq9g-pvrc) | Medium | `10.2.0` | `10.5.1` | Pending Node.js/npm packages update; candidate version listed |
| `ip-address` | [GHSA-4xrf-jv44-h6hh](https://github.com/advisories/GHSA-4xrf-jv44-h6hh) | Medium | `10.2.0` | `10.2.2` | Pending Node.js/npm packages update; candidate version listed |
| `ip-address` | [GHSA-h3mg-xc3c-68pw](https://github.com/advisories/GHSA-h3mg-xc3c-68pw) | Medium | `10.2.0` | `10.7.1` | Pending Node.js/npm packages update; candidate version listed |
| `ip-address` | [GHSA-j6r3-76f7-8jcv](https://github.com/advisories/GHSA-j6r3-76f7-8jcv) | Medium | `10.2.0` | `10.7.1` | Pending Node.js/npm packages update; candidate version listed |
| `ip-address` | [GHSA-mwp4-54f8-5fhr](https://github.com/advisories/GHSA-mwp4-54f8-5fhr) | High | `10.2.0` | `10.3.1` | Pending Node.js/npm packages update; candidate version listed |
| `ip-address` | [GHSA-rpw4-54j3-4h4q](https://github.com/advisories/GHSA-rpw4-54j3-4h4q) | Medium | `10.2.0` | `10.5.1` | Pending Node.js/npm packages update; candidate version listed |
| `pacote` | [GHSA-w4pp-8pjf-rmxw](https://github.com/advisories/GHSA-w4pp-8pjf-rmxw) | High | `21.5.0` | `21.5.1` | Pending Node.js/npm packages update; candidate version listed |
| `postcss-selector-parser` | [GHSA-rj75-hqrm-r3gf](https://github.com/advisories/GHSA-rj75-hqrm-r3gf) | Medium | `7.1.1` | `7.1.6` | Pending Node.js/npm packages update; candidate version listed |
| `postcss-selector-parser` | [GHSA-w9m9-85wc-3x92](https://github.com/advisories/GHSA-w9m9-85wc-3x92) | Low | `7.1.1` | `7.1.3` | Pending Node.js/npm packages update; candidate version listed |
| `tar` | [GHSA-23hp-3jrh-7fpw](https://github.com/advisories/GHSA-23hp-3jrh-7fpw) | Critical | `7.5.15` | `7.5.19` | Pending Node.js/npm packages update; candidate version listed |
| `tar` | [GHSA-8x88-c5mf-7j5w](https://github.com/advisories/GHSA-8x88-c5mf-7j5w) | High | `7.5.15` | `7.5.18` | Pending Node.js/npm packages update; candidate version listed |
| `tar` | [GHSA-gvwx-54wh-qm9j](https://github.com/advisories/GHSA-gvwx-54wh-qm9j) | Medium | `7.5.15` | `7.5.17` | Pending Node.js/npm packages update; candidate version listed |
| `tar` | [GHSA-r292-9mhp-454m](https://github.com/advisories/GHSA-r292-9mhp-454m) | High | `7.5.15` | `7.5.21` | Pending Node.js/npm packages update; candidate version listed |
| `tar` | [GHSA-vmf3-w455-68vh](https://github.com/advisories/GHSA-vmf3-w455-68vh) | Medium | `7.5.15` | `7.5.16` | Pending Node.js/npm packages update; candidate version listed |
| `tar` | [GHSA-w8wr-v893-vjvp](https://github.com/advisories/GHSA-w8wr-v893-vjvp) | Medium | `7.5.15` | `7.5.18` | Pending Node.js/npm packages update; candidate version listed |
| `undici` | [GHSA-3wwx-pv8p-q78v](https://github.com/advisories/GHSA-3wwx-pv8p-q78v) | Medium | `6.26.0` | `6.28.1` | Pending Node.js/npm packages update; candidate version listed |
| `undici` | [GHSA-8xcm-r25x-g524](https://github.com/advisories/GHSA-8xcm-r25x-g524) | Medium | `6.26.0` | `6.28.0` | Pending Node.js/npm packages update; candidate version listed |
| `undici` | [GHSA-m8rv-5g2x-5cg5](https://github.com/advisories/GHSA-m8rv-5g2x-5cg5) | Medium | `6.26.0` | `6.28.0` | Pending Node.js/npm packages update; candidate version listed |
| `undici` | [GHSA-r53p-7pc4-xj5r](https://github.com/advisories/GHSA-r53p-7pc4-xj5r) | Low | `6.26.0` | `6.28.1` | Pending Node.js/npm packages update; candidate version listed |
| `undici` | [GHSA-rfgv-xxqx-mfg5](https://github.com/advisories/GHSA-rfgv-xxqx-mfg5) | High | `6.26.0` | `6.28.1` | Pending Node.js/npm packages update; candidate version listed |
| `undici` | [GHSA-v3r7-h72x-cjcm](https://github.com/advisories/GHSA-v3r7-h72x-cjcm) | Medium | `6.26.0` | `6.28.0` | Pending Node.js/npm packages update; candidate version listed |

### Azure CLI Python dependencies (20 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `oauthlib` | [GHSA-hj66-6f7g-4r5v](https://github.com/advisories/GHSA-hj66-6f7g-4r5v) | Medium | `3.3.1` | `4.0.0` | Pending Azure CLI package update; candidate version listed |
| `oauthlib` | [GHSA-xpv3-w29h-x7cv](https://github.com/advisories/GHSA-xpv3-w29h-x7cv) | Medium | `3.3.1` | `4.0.0` | Pending Azure CLI package update; candidate version listed |
| `paramiko` | [GHSA-r374-rxx8-8654](https://github.com/advisories/GHSA-r374-rxx8-8654) | Low | `3.5.1` | — | Pending Azure CLI package update; no fixed version listed |
| `pygments` | [GHSA-5239-wwwm-4pmq](https://github.com/advisories/GHSA-5239-wwwm-4pmq) | Low | `2.19.1` | `2.20.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-2gx3-rcp4-g85q](https://github.com/advisories/GHSA-2gx3-rcp4-g85q) | Medium | `2.10.1` | `2.14.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-42vr-xj54-vc7v](https://github.com/advisories/GHSA-42vr-xj54-vc7v) | Medium | `2.10.1` | `2.15.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-752w-5fwx-jx9f](https://github.com/advisories/GHSA-752w-5fwx-jx9f) | High | `2.10.1` | `2.12.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-993g-76c3-p5m4](https://github.com/advisories/GHSA-993g-76c3-p5m4) | Medium | `2.10.1` | `2.13.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-9v7f-9g4p-ffgj](https://github.com/advisories/GHSA-9v7f-9g4p-ffgj) | High | `2.10.1` | `2.14.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-ffc3-869f-jxw9](https://github.com/advisories/GHSA-ffc3-869f-jxw9) | Critical | `2.10.1` | `2.14.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-fhv5-28vv-h8m8](https://github.com/advisories/GHSA-fhv5-28vv-h8m8) | Low | `2.10.1` | `2.13.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-hxm8-2xgr-2p9m](https://github.com/advisories/GHSA-hxm8-2xgr-2p9m) | Medium | `2.10.1` | `2.14.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-jq35-7prp-9v3f](https://github.com/advisories/GHSA-jq35-7prp-9v3f) | Medium | `2.10.1` | `2.13.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-jwrc-g2q2-pq5p](https://github.com/advisories/GHSA-jwrc-g2q2-pq5p) | Medium | `2.10.1` | `2.14.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-p4g4-x82p-q773](https://github.com/advisories/GHSA-p4g4-x82p-q773) | High | `2.10.1` | `2.14.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-w6j9-cwv2-h6wq](https://github.com/advisories/GHSA-w6j9-cwv2-h6wq) | Medium | `2.10.1` | `2.14.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-w7vc-732c-9m39](https://github.com/advisories/GHSA-w7vc-732c-9m39) | Medium | `2.10.1` | `2.13.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-x33g-cr3x-6449](https://github.com/advisories/GHSA-x33g-cr3x-6449) | Medium | `2.10.1` | `2.15.0` | Pending Azure CLI package update; candidate version listed |
| `pyjwt` | [GHSA-xgmm-8j9v-c9wx](https://github.com/advisories/GHSA-xgmm-8j9v-c9wx) | High | `2.10.1` | `2.13.0` | Pending Azure CLI package update; candidate version listed |
| `setuptools` | [GHSA-h35f-9h28-mq5c](https://github.com/advisories/GHSA-h35f-9h28-mq5c) | Medium | `80.10.2` | `83.0.0` | Pending Azure CLI package update; candidate version listed |

### Fedora RPM packages (6 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `curl` | [CVE-2026-13608](https://nvd.nist.gov/vuln/detail/CVE-2026-13608) | Medium | `8.18.0-13.fc44` | `0:8.18.0-14.fc44` | Pending Fedora package update; candidate version listed |
| `curl` | [CVE-2026-80230](https://nvd.nist.gov/vuln/detail/CVE-2026-80230) | Medium | `8.18.0-13.fc44` | `0:8.18.0-14.fc44` | Pending Fedora package update; candidate version listed |
| `curl` | [CVE-2026-8932](https://nvd.nist.gov/vuln/detail/CVE-2026-8932) | Medium | `8.18.0-13.fc44` | `0:8.18.0-14.fc44` | Pending Fedora package update; candidate version listed |
| `libcurl` | [CVE-2026-13608](https://nvd.nist.gov/vuln/detail/CVE-2026-13608) | Medium | `8.18.0-13.fc44` | `0:8.18.0-14.fc44` | Pending Fedora package update; candidate version listed |
| `libcurl` | [CVE-2026-80230](https://nvd.nist.gov/vuln/detail/CVE-2026-80230) | Medium | `8.18.0-13.fc44` | `0:8.18.0-14.fc44` | Pending Fedora package update; candidate version listed |
| `libcurl` | [CVE-2026-8932](https://nvd.nist.gov/vuln/detail/CVE-2026-8932) | Medium | `8.18.0-13.fc44` | `0:8.18.0-14.fc44` | Pending Fedora package update; candidate version listed |

## Updates

New scans recheck existing matches and add newly reported findings. Update statuses only after the relevant supplier release and a confirming image scan. Keep the dated scan identity and findings together so a later report does not replace the history.
