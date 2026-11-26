#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# smoke-test.sh IMAGE — check a built image before it is published.
#
# 1. `bao version` reports the expected commit (EXPECTED_COMMIT, optional).
# 2. A server starts from the image default command, with a TLS listener and Raft
#    storage from a test configuration, and initializes and unseals.
# 3. Transit: an rsa-3072 key with allow_pkcs1v15_session_key recovers a session key
#    that OpenSSL wrapped with RSAES-PKCS1-v1_5 (the SCEP fork operation).
# 4. A token with only the RA operation paths cannot export, back up or configure
#    the key.
#
# Needs docker, openssl and jq. Test material only; nothing is kept.
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

# Test TLS: CA + server certificate for 127.0.0.1.
mkdir -p "$work/tls" "$work/config" "$work/data"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=smoke-ca \
  -addext basicConstraints=critical,CA:TRUE -keyout "$work/tls/ca-key.pem" -out "$work/tls/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=openbao \
  -keyout "$work/tls/server-key.pem" -out "$work/tls/server.csr" 2>/dev/null
openssl x509 -req -in "$work/tls/server.csr" -CA "$work/tls/ca.pem" -CAkey "$work/tls/ca-key.pem" \
  -CAcreateserial -days 1 -out "$work/tls/server.pem" \
  -extfile <(printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n') 2>/dev/null
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
chmod -R a+rX "$work"; chmod 777 "$work/data"

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
openssl rand 32 > "$work/session.key"
openssl pkeyutl -encrypt -pubin -inkey "$work/ra.pub.pem" -pkeyopt rsa_padding_mode:pkcs1 \
  -in "$work/session.key" -out "$work/wrapped.bin"
got="$(bao write -format=json ra/session-key/pkcs1v15/scep-ra ciphertext="$(base64 -w0 "$work/wrapped.bin")" \
  key_version=1 session_key_length=32 | jq -r .data.session_key)"
[ "$got" = "$(base64 -w0 "$work/session.key")" ] || fail "recovered session key differs"
ok "PKCS#1 v1.5 session-key transport recovers the OpenSSL-wrapped key"

printf '%s\n' 'path "ra/session-key/pkcs1v15/scep-ra" { capabilities = ["update"] }' \
  'path "ra/sign/scep-ra/*" { capabilities = ["update"] }' | docker exec -i -e BAO_TOKEN="$BAO_TOKEN" "$name" bao policy write ra-runtime - >/dev/null
rt="$(bao token create -policy=ra-runtime -no-default-policy -field=token)"
for path in "read ra/export/signing-key/scep-ra" "read ra/backup/scep-ra" "write ra/keys/scep-ra/config exportable=true"; do
  # shellcheck disable=SC2086
  if BAO_TOKEN="$rt" bao $path >/dev/null 2>&1; then fail "runtime token allowed: $path"; fi
done
BAO_TOKEN="$rt" bao write -format=json ra/session-key/pkcs1v15/scep-ra ciphertext="$(base64 -w0 "$work/wrapped.bin")" \
  key_version=1 session_key_length=32 >/dev/null || fail "runtime token denied its operation"
ok "runtime token: operation allowed; export, backup and key config denied"
echo "smoke-test: PASS $image"
