# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: Apache-2.0
#
# OpenBao server image for PKI Manager, built from this source tree.
#
#   docker build -f downstream/pki-manager/image/Dockerfile \
#     --build-arg OPENBAO_COMMIT="$(git rev-parse HEAD)" \
#     --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
#     -t openbao-pki-manager:dev .
#
# - The binary is compiled in the build (no prebuilt bin/ directory), with the
#   Go toolchain of .go-version, CGO off, -trimpath and no VCS stamp, so the same
#   commit and build arguments give the same binary.
# - The default command starts a server from /openbao/config. There is no dev
#   mode default: dev mode keeps everything in memory and prints a root token.
# - No web UI (the `ui` build tag is not set). PKI Manager uses the HTTP API only.

ARG GO_IMAGE=golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
ARG RUNTIME_IMAGE=alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

FROM ${GO_IMAGE} AS build
ARG OPENBAO_VERSION=2.7.3
ARG OPENBAO_VERSION_METADATA=pki-manager
ARG OPENBAO_COMMIT=unknown
ARG SOURCE_DATE_EPOCH=0
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
# Module download first, so source changes do not invalidate the module layer.
COPY go.mod go.sum ./
COPY api/ api/
COPY sdk/ sdk/
COPY internal/helper/stubbolt/ internal/helper/stubbolt/
RUN --mount=type=cache,target=/root/go/pkg/mod go mod download -x
COPY . .
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    test "$(cat .go-version)" = "$(go env GOVERSION | sed 's/^go//')" \
      || { echo ".go-version $(cat .go-version) != builder $(go env GOVERSION)" >&2; exit 1; }; \
    commit_date="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)"; \
    pkg=github.com/openbao/openbao/v2/internal/version; \
    go build -trimpath -buildvcs=false -tags openbao \
      -ldflags "-s -w -buildid= \
        -X ${pkg}.fullVersion=${OPENBAO_VERSION} \
        -X ${pkg}.VersionMetadata=${OPENBAO_VERSION_METADATA} \
        -X ${pkg}.GitCommit=${OPENBAO_COMMIT} \
        -X ${pkg}.CommitDate=${commit_date}" \
      -o /out/bao .; \
    /out/bao version

FROM ${RUNTIME_IMAGE}
ARG OPENBAO_VERSION=2.7.3
ARG OPENBAO_VERSION_METADATA=pki-manager
ARG OPENBAO_COMMIT=unknown
LABEL org.opencontainers.image.title="OpenBao for PKI Manager" \
      org.opencontainers.image.description="OpenBao ${OPENBAO_VERSION} with the PKI Manager downstream patches (SCEP session-key transport)" \
      org.opencontainers.image.source="https://github.com/oriolrius/openbao" \
      org.opencontainers.image.revision="${OPENBAO_COMMIT}" \
      org.opencontainers.image.version="${OPENBAO_VERSION}+${OPENBAO_VERSION_METADATA}" \
      org.opencontainers.image.licenses="MPL-2.0 AND Apache-2.0"
# dumb-init reaps children and forwards signals. No file capabilities on the
# binary: set `disable_mlock = true` (integrated storage) or run with IPC_LOCK.
RUN apk add --no-cache ca-certificates dumb-init tzdata \
 && addgroup -g 1000 openbao && adduser -S -D -H -u 1000 -G openbao openbao \
 && mkdir -p /openbao/config /openbao/data /openbao/logs /openbao/tls \
 && chown -R openbao:openbao /openbao/data /openbao/logs
COPY LICENSE /licenses/mozilla.txt
COPY LICENSES/Apache-2.0.txt /licenses/apache-2.0.txt
COPY DOWNSTREAM-LICENSING.md /licenses/DOWNSTREAM-LICENSING.md
COPY --from=build --chmod=555 /out/bao /usr/bin/bao
EXPOSE 8200 8201
USER openbao
ENTRYPOINT ["dumb-init", "--", "bao"]
CMD ["server", "-config=/openbao/config"]
