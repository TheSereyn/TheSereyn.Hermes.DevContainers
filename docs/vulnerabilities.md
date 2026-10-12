# Image vulnerability register

This register lists vulnerability findings from the image scan dated 2026-10-12. Findings are grouped by the tool that introduced the affected component, including its dependencies.

## Snapshot and scope

- Image: Fedora 44, Linux/AMD64, .NET 10 development image.
- Image config ID: `sha256:0dff96899a4526c3054020e9b5e9e49652c325afdc7ec8766468d91c3235cf9c`.
- Scan date: 2026-10-12; scanner: Grype 0.120.1.
- Database build: 2026-10-12T06:45:22Z.
- Image archive SHA-256: `b49def75212ae006e34ad7979082e728f66b839d18892f35d0f9c0eddf977f4d`.
- Findings: 64 advisory matches, including 3 Critical, 26 High, 28 Medium, 5 Low, and 2 Unknown.
- The matches came from layers adding Node.js/npm and later command-line tools: 29 npm components, 15 Go modules bundled in GitHub CLI, and 20 Python components installed with Azure CLI. This scan found no matches in the Fedora base-image layers or the .NET SDK installation layer.

## Verification results

The fresh build and root/nonroot smoke tests passed. A fresh scan of the exact tested image passed verification after applying the known-benign registry. The reports retain 93 corpus matches and 21 layer-pattern matches, all classified as known benign, with no unreviewed findings or nested-archive coverage gaps. The earlier failed scan remains preserved separately.

The corpus secret scan reported 93 matches. The layer audit reported 21 pattern matches, including 18 private-key markers, 2 AWS access-key patterns, and 1 GitHub-token pattern. These findings are recorded in `tests/known-benign.json` with exact file hashes and rule-specific count limits. The five parseable GnuTLS keys match public cryptographic self-test fixtures. Other matches are documentation examples, parser markers, encoded program content, or approved binary string-table patterns. Known-benign findings remain visible in raw reports. Changed or additional matches require review.

## Changes from the previous scan

The previous image, `sha256:44a40a5b1e5dc8564e3807b5057c6d59ce36a4c4e45c3bb201177139dcd51a1d`, was scanned on 2026-10-11. The new image includes glib2 2.88.4 in place of 2.88.3 and was scanned with a newer vulnerability database.

All 64 advisory/package matches persist. No advisory/package matches were added or resolved. The 93 corpus secret matches have the same rules, source locations, and line ranges. The all-layer audit has one additional private-key marker in the updated glib2 library. This marker has no complete PEM key block.

The scan reports advisory matches. Exploitability and update availability have not been verified.

## Updates and status

The image is rebuilt and rescanned after an applicable update to the Fedora base image, .NET SDK, or an included tool. Findings remain open until a follow-up scan confirms they are resolved.

Scans check for new advisory matches and recheck existing findings. The register records new findings and marks resolved findings with the confirming image identity and scan date. The dated results remain available to users.

Vulnerability findings are reported at every severity and do not block image release. This development image does not guarantee zero vulnerabilities.

The tracking statuses used below are:

- `Pending <provider> update; candidate version listed`: The scanner lists a fixed component version. Availability in a tool update has not been confirmed.
- `Pending <provider> update; no fixed version listed`: The scanner does not list a fixed component version.

## Findings by tool

### Azure CLI and its Python dependencies (20 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `oauthlib` | [GHSA-hj66-6f7g-4r5v](https://github.com/advisories/GHSA-hj66-6f7g-4r5v) | Medium | `3.3.1` | `4.0.0` | Pending Azure CLI update; candidate version listed |
| `oauthlib` | [GHSA-xpv3-w29h-x7cv](https://github.com/advisories/GHSA-xpv3-w29h-x7cv) | Medium | `3.3.1` | `4.0.0` | Pending Azure CLI update; candidate version listed |
| `paramiko` | [GHSA-r374-rxx8-8654](https://github.com/advisories/GHSA-r374-rxx8-8654) | Low | `3.5.1` | `—` | Pending Azure CLI update; no fixed version listed |
| `pygments` | [GHSA-5239-wwwm-4pmq](https://github.com/advisories/GHSA-5239-wwwm-4pmq) | Low | `2.19.1` | `2.20.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-ffc3-869f-jxw9](https://github.com/advisories/GHSA-ffc3-869f-jxw9) | Critical | `2.10.1` | `2.14.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-752w-5fwx-jx9f](https://github.com/advisories/GHSA-752w-5fwx-jx9f) | High | `2.10.1` | `2.12.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-9v7f-9g4p-ffgj](https://github.com/advisories/GHSA-9v7f-9g4p-ffgj) | High | `2.10.1` | `2.14.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-p4g4-x82p-q773](https://github.com/advisories/GHSA-p4g4-x82p-q773) | High | `2.10.1` | `2.14.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-xgmm-8j9v-c9wx](https://github.com/advisories/GHSA-xgmm-8j9v-c9wx) | High | `2.10.1` | `2.13.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-fhv5-28vv-h8m8](https://github.com/advisories/GHSA-fhv5-28vv-h8m8) | Low | `2.10.1` | `2.13.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-2gx3-rcp4-g85q](https://github.com/advisories/GHSA-2gx3-rcp4-g85q) | Medium | `2.10.1` | `2.14.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-42vr-xj54-vc7v](https://github.com/advisories/GHSA-42vr-xj54-vc7v) | Medium | `2.10.1` | `2.15.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-993g-76c3-p5m4](https://github.com/advisories/GHSA-993g-76c3-p5m4) | Medium | `2.10.1` | `2.13.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-hxm8-2xgr-2p9m](https://github.com/advisories/GHSA-hxm8-2xgr-2p9m) | Medium | `2.10.1` | `2.14.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-jq35-7prp-9v3f](https://github.com/advisories/GHSA-jq35-7prp-9v3f) | Medium | `2.10.1` | `2.13.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-jwrc-g2q2-pq5p](https://github.com/advisories/GHSA-jwrc-g2q2-pq5p) | Medium | `2.10.1` | `2.14.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-w6j9-cwv2-h6wq](https://github.com/advisories/GHSA-w6j9-cwv2-h6wq) | Medium | `2.10.1` | `2.14.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-w7vc-732c-9m39](https://github.com/advisories/GHSA-w7vc-732c-9m39) | Medium | `2.10.1` | `2.13.0` | Pending Azure CLI update; candidate version listed |
| `pyjwt` | [GHSA-x33g-cr3x-6449](https://github.com/advisories/GHSA-x33g-cr3x-6449) | Medium | `2.10.1` | `2.15.0` | Pending Azure CLI update; candidate version listed |
| `setuptools` | [GHSA-h35f-9h28-mq5c](https://github.com/advisories/GHSA-h35f-9h28-mq5c) | Medium | `80.10.2` | `83.0.0` | Pending Azure CLI update; candidate version listed |

### GitHub CLI (`gh`) (15 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `golang.org/x/crypto` | [GO-2026-6303](https://pkg.go.dev/vuln/GO-2026-6303) | High | `v0.54.0` | `0.55.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/crypto` | [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) | High | `v0.54.0` | `0.56.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/crypto` | [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) | High | `v0.54.0` | `0.56.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/crypto` | [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) | Unknown | `v0.54.0` | `—` | Pending GitHub CLI update; no fixed version listed |
| `golang.org/x/mod` | [GO-2026-6179](https://pkg.go.dev/vuln/GO-2026-6179) | High | `v0.37.0` | `0.40.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/mod` | [GO-2026-6180](https://pkg.go.dev/vuln/GO-2026-6180) | High | `v0.37.0` | `0.40.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6612](https://pkg.go.dev/vuln/GO-2026-6612) | Critical | `v0.56.0` | `0.60.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603) | High | `v0.56.0` | `0.60.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610) | High | `v0.56.0` | `0.60.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611) | High | `v0.56.0` | `0.60.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/net` | [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617) | Unknown | `v0.56.0` | `0.60.0` | Pending GitHub CLI update; candidate version listed |
| `golang.org/x/text` | [GO-2026-6629](https://pkg.go.dev/vuln/GO-2026-6629) | High | `v0.40.0` | `0.41.0` | Pending GitHub CLI update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-2v4p-qf9q-27wj](https://github.com/advisories/GHSA-2v4p-qf9q-27wj) | High | `v1.82.1` | `1.82.2` | Pending GitHub CLI update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-vp52-pcj8-j9qc](https://github.com/advisories/GHSA-vp52-pcj8-j9qc) | High | `v1.82.1` | `1.83.1` | Pending GitHub CLI update; candidate version listed |
| `google.golang.org/grpc` | [GHSA-qc2q-p7wx-3px3](https://github.com/advisories/GHSA-qc2q-p7wx-3px3) | Medium | `v1.82.1` | `1.83.1` | Pending GitHub CLI update; candidate version listed |

### Node.js / npm (29 matches)

| Component | Advisory | Severity | Detected version | Scanner-listed fixed version | Tracking status |
|---|---|---|---|---|---|
| `brace-expansion` | [GHSA-3jxr-9vmj-r5cp](https://github.com/advisories/GHSA-3jxr-9vmj-r5cp) | High | `5.0.6` | `5.0.7` | Pending Node.js/npm update; candidate version listed |
| `brace-expansion` | [GHSA-6j4f-fj2g-mc7p](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p) | High | `5.0.6` | `5.0.10` | Pending Node.js/npm update; candidate version listed |
| `brace-expansion` | [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg) | High | `5.0.6` | `5.0.8` | Pending Node.js/npm update; candidate version listed |
| `brace-expansion` | [GHSA-qhr7-859c-m2p7](https://github.com/advisories/GHSA-qhr7-859c-m2p7) | High | `5.0.6` | `5.0.11` | Pending Node.js/npm update; candidate version listed |
| `brace-expansion` | [GHSA-rgw5-rvv9-x895](https://github.com/advisories/GHSA-rgw5-rvv9-x895) | High | `5.0.6` | `5.0.9` | Pending Node.js/npm update; candidate version listed |
| `brace-expansion` | [GHSA-q2hr-2g5m-vwhr](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr) | Medium | `5.0.6` | `5.0.12` | Pending Node.js/npm update; candidate version listed |
| `http-cache-semantics` | [GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp) | High | `4.2.0` | `—` | Pending Node.js/npm update; no fixed version listed |
| `ip-address` | [GHSA-mwp4-54f8-5fhr](https://github.com/advisories/GHSA-mwp4-54f8-5fhr) | High | `10.2.0` | `10.3.1` | Pending Node.js/npm update; candidate version listed |
| `ip-address` | [GHSA-22jq-vg5j-6vgg](https://github.com/advisories/GHSA-22jq-vg5j-6vgg) | Medium | `10.2.0` | `10.2.1` | Pending Node.js/npm update; candidate version listed |
| `ip-address` | [GHSA-2vr4-cq9g-pvrc](https://github.com/advisories/GHSA-2vr4-cq9g-pvrc) | Medium | `10.2.0` | `10.5.1` | Pending Node.js/npm update; candidate version listed |
| `ip-address` | [GHSA-4xrf-jv44-h6hh](https://github.com/advisories/GHSA-4xrf-jv44-h6hh) | Medium | `10.2.0` | `10.2.2` | Pending Node.js/npm update; candidate version listed |
| `ip-address` | [GHSA-h3mg-xc3c-68pw](https://github.com/advisories/GHSA-h3mg-xc3c-68pw) | Medium | `10.2.0` | `10.7.1` | Pending Node.js/npm update; candidate version listed |
| `ip-address` | [GHSA-j6r3-76f7-8jcv](https://github.com/advisories/GHSA-j6r3-76f7-8jcv) | Medium | `10.2.0` | `10.7.1` | Pending Node.js/npm update; candidate version listed |
| `ip-address` | [GHSA-rpw4-54j3-4h4q](https://github.com/advisories/GHSA-rpw4-54j3-4h4q) | Medium | `10.2.0` | `10.5.1` | Pending Node.js/npm update; candidate version listed |
| `pacote` | [GHSA-w4pp-8pjf-rmxw](https://github.com/advisories/GHSA-w4pp-8pjf-rmxw) | High | `21.5.0` | `21.5.1` | Pending Node.js/npm update; candidate version listed |
| `postcss-selector-parser` | [GHSA-w9m9-85wc-3x92](https://github.com/advisories/GHSA-w9m9-85wc-3x92) | Low | `7.1.1` | `7.1.3` | Pending Node.js/npm update; candidate version listed |
| `postcss-selector-parser` | [GHSA-rj75-hqrm-r3gf](https://github.com/advisories/GHSA-rj75-hqrm-r3gf) | Medium | `7.1.1` | `7.1.6` | Pending Node.js/npm update; candidate version listed |
| `tar` | [GHSA-23hp-3jrh-7fpw](https://github.com/advisories/GHSA-23hp-3jrh-7fpw) | Critical | `7.5.15` | `7.5.19` | Pending Node.js/npm update; candidate version listed |
| `tar` | [GHSA-8x88-c5mf-7j5w](https://github.com/advisories/GHSA-8x88-c5mf-7j5w) | High | `7.5.15` | `7.5.18` | Pending Node.js/npm update; candidate version listed |
| `tar` | [GHSA-r292-9mhp-454m](https://github.com/advisories/GHSA-r292-9mhp-454m) | High | `7.5.15` | `7.5.21` | Pending Node.js/npm update; candidate version listed |
| `tar` | [GHSA-gvwx-54wh-qm9j](https://github.com/advisories/GHSA-gvwx-54wh-qm9j) | Medium | `7.5.15` | `7.5.17` | Pending Node.js/npm update; candidate version listed |
| `tar` | [GHSA-vmf3-w455-68vh](https://github.com/advisories/GHSA-vmf3-w455-68vh) | Medium | `7.5.15` | `7.5.16` | Pending Node.js/npm update; candidate version listed |
| `tar` | [GHSA-w8wr-v893-vjvp](https://github.com/advisories/GHSA-w8wr-v893-vjvp) | Medium | `7.5.15` | `7.5.18` | Pending Node.js/npm update; candidate version listed |
| `undici` | [GHSA-rfgv-xxqx-mfg5](https://github.com/advisories/GHSA-rfgv-xxqx-mfg5) | High | `6.26.0` | `6.28.1` | Pending Node.js/npm update; candidate version listed |
| `undici` | [GHSA-r53p-7pc4-xj5r](https://github.com/advisories/GHSA-r53p-7pc4-xj5r) | Low | `6.26.0` | `6.28.1` | Pending Node.js/npm update; candidate version listed |
| `undici` | [GHSA-3wwx-pv8p-q78v](https://github.com/advisories/GHSA-3wwx-pv8p-q78v) | Medium | `6.26.0` | `6.28.1` | Pending Node.js/npm update; candidate version listed |
| `undici` | [GHSA-8xcm-r25x-g524](https://github.com/advisories/GHSA-8xcm-r25x-g524) | Medium | `6.26.0` | `6.28.0` | Pending Node.js/npm update; candidate version listed |
| `undici` | [GHSA-m8rv-5g2x-5cg5](https://github.com/advisories/GHSA-m8rv-5g2x-5cg5) | Medium | `6.26.0` | `6.28.0` | Pending Node.js/npm update; candidate version listed |
| `undici` | [GHSA-v3r7-h72x-cjcm](https://github.com/advisories/GHSA-v3r7-h72x-cjcm) | Medium | `6.26.0` | `6.28.0` | Pending Node.js/npm update; candidate version listed |
