#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# smoke-test.sh IMAGE — check a built image before it is published.
#
# 1. `bao version` reports the expected commit (EXPECTED_COMMIT, optional).
# 2. A server starts from the image default command, with a TLS listener and Raft
#    storage from a test configuration, and initializes and unseals.
# 3. Transit: an rsa-3072 key with allow_pkcs1v15_session_key recovers a session key
#    that was wrapped with RSAES-PKCS1-v1_5 (the SCEP fork operation).
# 4. A token with only the RA operation paths cannot export, back up or configure
#    the key.
#
# Needs docker, go and jq; no openssl. The TLS fixtures and the wrapped session key
# come from smokefixtures (Go standard library, next to this script); set
# SMOKE_FIXTURES to a prebuilt binary of it to skip the build. The optional OpenSSL
# cross-check is downstream/pki-manager/interop. Test material only; nothing is kept.
# The container runs with the caller's uid, so private keys stay mode 0600.
set -euo pipefail

image="${1:?usage: smoke-test.sh IMAGE}"
work="$(mktemp -d)"; name="openbao-smoke-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "smoke-test: FAIL: $*" >&2; exit 1; }
ok() { echo "smoke-test: ok: $*"; }

version="$(docker run --rm --entrypoint bao "$image" version)"
echo "smoke-test: $version"
if [ -n "${EXPECTED_COMMIT:-}" ]; then
  grep -q "($EXPECTED_COMMIT)" <<<"$version" || fail "version does not name $EXPECTED_COMMIT"
fi
ok "version"

fixtures="${SMOKE_FIXTURES:-}"
if [ -z "$fixtures" ]; then
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
  fixtures="$work/smokefixtures"
  (cd "$root" && go build -o "$fixtures" ./downstream/pki-manager/image/smokefixtures)
fi

# Test TLS: CA + server certificate for 127.0.0.1 (the CA key is never written).
mkdir -p "$work/tls" "$work/config" "$work/data"
"$fixtures" tls "$work/tls"
cat > "$work/config/server.hcl" <<'HCL'
ui = false
disable_mlock = true
listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_cert_file = "/openbao/tls/server.pem"
  tls_key_file  = "/openbao/tls/server-key.pem"
}
storage "raft" {
  path    = "/openbao/data"
  node_id = "smoke"
}
api_addr     = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
HCL

docker run -d --name "$name" --user "$(id -u):$(id -g)" \
  -v "$work/config:/openbao/config:ro" -v "$work/tls:/openbao/tls:ro" -v "$work/data:/openbao/data" \
  -e BAO_ADDR=https://127.0.0.1:8200 -e BAO_CACERT=/openbao/tls/ca.pem "$image" >/dev/null
bao() { docker exec -e BAO_TOKEN="${BAO_TOKEN:-}" "$name" bao "$@"; }
for _ in $(seq 1 30); do
  set +e; bao status >/dev/null 2>&1; rc=$?; set -e
  [ "$rc" = 2 ] && break; sleep 1
done
[ "$rc" = 2 ] || { docker logs "$name" >&2; fail "server did not start"; }
init="$(bao operator init -key-shares=1 -key-threshold=1 -format=json)"
bao operator unseal "$(jq -r '.unseal_keys_b64[0]' <<<"$init")" >/dev/null
BAO_TOKEN="$(jq -r .root_token <<<"$init")"
ok "TLS server with Raft storage initialized and unsealed"

bao secrets enable -path=ra transit >/dev/null
bao write ra/keys/scep-ra type=rsa-3072 exportable=false allow_plaintext_backup=false \
  allow_pkcs1v15_session_key=true >/dev/null
bao read -format=json ra/keys/scep-ra | jq -r '.data.keys["1"].public_key' > "$work/ra.pub.pem"
[ "$(bao read -format=json ra/keys/scep-ra | jq -r .data.allow_pkcs1v15_session_key)" = true ] || fail "opt-in flag not reported"
wrapped="$("$fixtures" wrap "$work/ra.pub.pem" 32)"
ciphertext="$(jq -r .ciphertext <<<"$wrapped")"
got="$(bao write -format=json ra/session-key/pkcs1v15/scep-ra ciphertext="$ciphertext" \
  key_version=1 session_key_length=32 | jq -r .data.session_key)"
[ "$got" = "$(jq -r .session_key <<<"$wrapped")" ] || fail "recovered session key differs"
ok "PKCS#1 v1.5 session-key transport recovers the wrapped key"

printf '%s\n' 'path "ra/session-key/pkcs1v15/scep-ra" { capabilities = ["update"] }' \
  'path "ra/sign/scep-ra/*" { capabilities = ["update"] }' | docker exec -i -e BAO_TOKEN="$BAO_TOKEN" "$name" bao policy write ra-runtime - >/dev/null
rt="$(bao token create -policy=ra-runtime -no-default-policy -field=token)"
for path in "read ra/export/signing-key/scep-ra" "read ra/backup/scep-ra" "write ra/keys/scep-ra/config exportable=true"; do
  # shellcheck disable=SC2086
  if BAO_TOKEN="$rt" bao $path >/dev/null 2>&1; then fail "runtime token allowed: $path"; fi
done
BAO_TOKEN="$rt" bao write -format=json ra/session-key/pkcs1v15/scep-ra ciphertext="$ciphertext" \
  key_version=1 session_key_length=32 >/dev/null || fail "runtime token denied its operation"
ok "runtime token: operation allowed; export, backup and key config denied"
echo "smoke-test: PASS $image"
