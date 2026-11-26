<!-- SPDX-License-Identifier: Apache-2.0 -->

# PKI Manager image

PKI Manager runs this fork as a container image. The image is built from the source
tree with `downstream/pki-manager/image/Dockerfile`. No prebuilt binary is needed.

## Build and test locally

```
docker build -f downstream/pki-manager/image/Dockerfile \
  --build-arg OPENBAO_COMMIT="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  -t openbao-pki-manager:dev .
bash downstream/pki-manager/image/smoke-test.sh openbao-pki-manager:dev
```

The build uses the Go version of `.go-version` (the build stops on a mismatch),
`CGO_ENABLED=0`, `-trimpath`, no VCS stamp and no build id. Base images are pinned by
digest. The same commit and build arguments therefore give the same binary.
`bao version` prints `v<upstream>+pki-manager (<commit>)`.

The image:

- runs `bao server -config=/openbao/config` as user `openbao` (uid/gid 1000), with no
  dev-mode default;
- has no web UI (no `ui` build tag);
- has no file capabilities: set `disable_mlock = true` (Raft storage) or give the
  container `IPC_LOCK`;
- contains the MPL-2.0 and Apache-2.0 texts and `DOWNSTREAM-LICENSING.md` in
  `/licenses`. The label `org.opencontainers.image.revision` names the source commit.

The smoke test starts the image with TLS and Raft storage, initializes and unseals it,
recovers a PKCS#1 v1.5-wrapped session key through `session-key/pkcs1v15`, and checks that
a token with only the RA paths cannot export, back up or reconfigure the key.

It needs `docker`, `go` and `jq`, not the `openssl` CLI. The test TLS certificates and
the wrapped session key come from `image/smokefixtures`, a small Go standard-library
helper (`go test ./downstream/pki-manager/image/smokefixtures/` tests it). The container
runs with the caller's uid, so the server key stays mode 0600 and the CA key is never
written. The independent OpenSSL cross-check is the optional
`downstream/pki-manager/interop` test.

## Release

Workflow `.github/workflows/pki-manager-image.yml`:

| Trigger | Result |
|---|---|
| Pull request, push to `pki-manager*` | Downstream tests, amd64 build, smoke test. Nothing is pushed. |
| Tag `v<upstream>-pki-manager.<n>` | Also amd64 + arm64 push to `ghcr.io/oriolrius/openbao:<upstream>-pki-manager.<n>`, SBOM, provenance and a keyless cosign signature |

The job summary gives the digest. PKI Manager pins it as
`OPENBAO_PUBLISHED_IMAGE=ghcr.io/oriolrius/openbao:<tag>@sha256:<digest>` in its
`openbao/image.env`. Record the upstream tag, the downstream commit and the digest in
the release notes.
