<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenBao, PKI Manager build

This repository is a downstream build of [OpenBao](https://openbao.org). It is OpenBao
**v2.7.3** with a small set of additions, published as a signed container image:

```
ghcr.io/oriolrius/openbao:2.7.3-pki-manager.2
ghcr.io/oriolrius/openbao@sha256:4ea3dfec698abe0feb041444f87942d37c103f92f4011d9756df4fed1e6d96b2
```

It was made for [PKI Manager](https://pki-manager.oriolrius.cat), which keeps all its private
keys in it, but it is a complete OpenBao server: you can run it **without PKI Manager**, as a
drop-in replacement for OpenBao 2.7.3. Everything that works with OpenBao 2.7.3 works here.

It is maintained by one person ([Oriol Rius](https://oriolrius.cat)) for his own use. It is not
an official OpenBao release, it is not affiliated with the OpenBao project or the Linux
Foundation, and there is no support contract.

## Features

Each downstream feature has an id, a specification and tests. Its status is **downstream
only** (kept here) or **upstream candidate** (to propose to OpenBao, by hand).

| Id | Feature | Kind | Specification | Status |
|---|---|---|---|---|
| D1 | Transit `session-key/pkcs1v15`: RSA PKCS#1 v1.5 key transport for SCEP | Core patch (Transit) | [pkcs1v15-session-key.md](pki-manager/pkcs1v15-session-key.md) | Upstream candidate |
| D2 | Reproducible, signed, server-only image for amd64 and arm64 | Build | [image.md](pki-manager/image.md) | Downstream only |

A new feature goes in as an **external plugin** when it does not need OpenBao internals: its
own repository and version, put in the image at build time. It is a **core patch** only when it
must read internal state (D1 must read the Transit key material). Core patches add files where
possible and change few upstream lines, so that upstream merges stay easy.

## What it adds to OpenBao 2.7.3

| Area | Official OpenBao 2.7.3 | This build |
|---|---|---|
| Transit: RSA PKCS#1 v1.5 key transport (SCEP, CMS `KeyTransRecipientInfo`) | Not possible: Transit decrypts RSA with OAEP-SHA-256 only, and only its own `vault:v1:` ciphertext | **New operation** `POST /v1/transit/session-key/pkcs1v15/:name`: unwraps a raw RSAES-PKCS1-v1_5 ciphertext into a 16, 24 or 32-byte session key, in constant time, with no padding oracle. Opt-in per key (`allow_pkcs1v15_session_key`, `rsa-3072` only, set at create or import time and never changed later). Specification: [pkcs1v15-session-key.md](pki-manager/pkcs1v15-session-key.md) |
| Transit: all other operations | — | Unchanged. `decrypt/` stays OAEP-only; signing, export, import, backup and their rules are the upstream ones |
| Container image | Official images | **Reproducible build** from this source tree: pinned Go and base images, `-trimpath`, no VCS stamp; same commit and arguments give the same binary. Spec: [image.md](pki-manager/image.md) |
| Image architectures | — | `linux/amd64` and `linux/arm64` |
| Image supply chain | — | Keyless **cosign** signature, SBOM and build provenance, made by [the release workflow](../.github/workflows/pki-manager-image.yml) |
| Image contents | — | Server only: **no web UI** (no `ui` build tag), runs as uid/gid 1000, `bao server -config=/openbao/config`, no dev-mode default, licence texts in `/licenses` |
| Version string | `v2.7.3` | `v2.7.3+pki-manager (<commit>)` |

What it does **not** change: storage, seals, authentication methods, policies, audit devices,
the PKI, SSH and KV engines, the API of every existing endpoint.

## Run it without PKI Manager

1. Write `config/openbao.hcl`. This one is for a local test; in production enable TLS
   (`tls_cert_file`, `tls_key_file`) and keep `disable_mlock = true` for Raft.

   ```hcl
   ui            = false
   disable_mlock = true
   api_addr      = "http://127.0.0.1:8200"
   cluster_addr  = "http://127.0.0.1:8201"
   listener "tcp" {
     address     = "0.0.0.0:8200"
     tls_disable = true
   }
   storage "raft" {
     path    = "/openbao/data"
     node_id = "node-1"
   }
   ```

2. Start it. The data directory must be writable by uid 1000.

   ```sh
   docker run -d --name openbao -p 127.0.0.1:8200:8200 \
     -v "$PWD/config:/openbao/config:ro" -v "$PWD/data:/openbao/data" \
     ghcr.io/oriolrius/openbao:2.7.3-pki-manager.2
   docker exec openbao bao version   # OpenBao v2.7.3+pki-manager (fcf3d59…)
   ```

3. Initialize and unseal it like any OpenBao (`bao operator init`, `bao operator unseal`).

4. Use the new operation:

   ```sh
   bao secrets enable transit
   bao write transit/keys/scep-ra type=rsa-3072 allow_pkcs1v15_session_key=true
   bao write transit/session-key/pkcs1v15/scep-ra \
     ciphertext="$(base64 -w0 wrapped-key.bin)" key_version=1 session_key_length=32
   ```

These steps were run on 2026-11-27 with the image above: the server started, a 32-byte key
wrapped with `openssl pkeyutl -pkeyopt rsa_padding_mode:pkcs1` came back unchanged, and the
upstream `transit/decrypt` of the same ciphertext was refused, as expected.

## Verify the image

```sh
cosign verify ghcr.io/oriolrius/openbao:2.7.3-pki-manager.2 \
  --certificate-identity-regexp 'https://github.com/oriolrius/openbao/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The label `org.opencontainers.image.revision` names the source commit.

## Versions and branches

| | |
|---|---|
| Branch `pki-manager` | The source of this build (the GitHub default branch of this fork) |
| Branch `main` | Follows upstream `openbao/openbao` `main` (GitHub fork sync); not used for builds |
| Tags `v<upstream>-pki-manager.<n>` | One release, with notes on the [releases page](https://github.com/oriolrius/openbao/releases); `<n>` counts the downstream releases on one upstream version |

| Release | Upstream | Commit | Change |
|---|---|---|---|
| `v2.7.3-pki-manager.2` | v2.7.3 | `fcf3d59` | Test: the cross-version ciphertext check is bounded by both RSA moduli. No behaviour change |
| `v2.7.3-pki-manager.1` | v2.7.3 | `32c18cb` | First build: `session-key/pkcs1v15` and the reproducible image build. Source only: no image was published |

## How the build follows upstream

The repository is a GitHub fork of `openbao/openbao`. Our commits go only to `pki-manager`.

1. Every Monday the workflow [`pki-manager-upstream.yml`](../.github/workflows/pki-manager-upstream.yml)
   finds the highest stable upstream release. The build follows only the newest release: patch
   releases of older lines (for example 2.6.x) are not merged. When it is not in `pki-manager`, the workflow tries the
   merge (it pushes nothing) and opens an issue: a clean merge, or the conflicting files.
2. The maintainer runs `downstream/scripts/sync-upstream.sh <tag>`. It syncs `main`, merges
   the tag into a branch `sync/<tag>`, sets the OpenBao version in the image build, checks the
   Go image, pushes and opens a pull request to `pki-manager`. When a step needs a person (a
   conflict, a new Go image), it stops and says what to do; then `--continue`.
3. The pull request runs the upstream tests and the downstream tests. When they pass: merge,
   tag `v<tag>-pki-manager.1`, write the release notes. The tag publishes the image.

The script runs with the maintainer's GitHub account and not in CI: a workflow token cannot
push the upstream workflow files, and its pull requests do not start the checks.

A new downstream feature: branch `feat/<name>` from `pki-manager`, pull request to
`pki-manager` of **this** repository (`gh pr create --repo oriolrius/openbao --base pki-manager`;
`gh` proposes the upstream repository by default), then the next `-pki-manager.<n>` tag.

## Tests

The downstream tests run on every pull request and push to `pki-manager` (workflow
`pki-manager-image.yml`): the Transit and keysutil tests of the new operation, an OpenSSL
cross-check, an image build and a smoke test that initializes, unseals and uses the image with
TLS and Raft. The list of tests is in [pkcs1v15-session-key.md](pki-manager/pkcs1v15-session-key.md#tests).

## Upstream

The plan is to propose the session-key operation to the OpenBao project. OpenBao does not accept
contributions written with generative AI, so that proposal will be written by hand, following
its [contributing guide](../CONTRIBUTING.md). Until it is accepted there, PKI Manager needs this
build.

## Licence

OpenBao is MPL-2.0. Its files keep that licence here, also where this build changes them. The
files that this build adds are Apache-2.0. The rules are in
[DOWNSTREAM-LICENSING.md](../DOWNSTREAM-LICENSING.md).
