<!-- SPDX-License-Identifier: Apache-2.0 -->

# Transit: PKCS #1 v1.5 session-key transport (SCEP)

This downstream operation recovers the CMS content-encryption key that a
SCEP client wraps with RSAES-PKCS1-v1_5 for the RA key. Stock Transit
`decrypt/` supports RSA-OAEP only, and it stays unchanged.

## Opt-in

The key must opt in when it is created or imported. The flag is valid only
for `rsa-3072`. It cannot be set later: an upsert of an existing key and
`keys/:name/config` do not change it. Rotation, backup and restore keep it.

```
POST /v1/transit/keys/:name
{"type": "rsa-3072", "allow_pkcs1v15_session_key": true}

POST /v1/transit/keys/:name/import
{"type": "rsa-3072", "ciphertext": "<wrapped PKCS#8>", "allow_pkcs1v15_session_key": true}
```

An import with only `public_key` cannot opt in. `GET /v1/transit/keys/:name`
returns `allow_pkcs1v15_session_key` for `rsa-3072` keys.

## Operation

```
POST /v1/transit/session-key/pkcs1v15/:name
{
  "ciphertext": "<base64 of the raw 384-byte encrypted key>",
  "key_version": 1,
  "session_key_length": 32
}

200 {"data": {"session_key": "<base64, session_key_length bytes>", "key_version": 1}}
```

- `key_version` is required. The latest version is not implied.
  Lifecycle rules apply: `min_decryption_version`, trimmed versions and
  soft delete refuse the request.
- `session_key_length` is required: 16, 24 or 32 bytes.
- `ciphertext` must be exactly the modulus size (384 bytes) and below the
  modulus. `batch_input` is refused.
- Errors (HTTP 400) depend only on public request properties: key name,
  opt-in, type, version, lengths, encoding.

## No padding indicator

The response always holds a key of the requested length. When the padding
is invalid, or the encoded key has another length, the key is a fallback
value: HMAC-SHA-256 over the version, the length and the ciphertext, keyed by
SHA-256 of a label and the private exponent. Go `crypto/rsa`
`DecryptPKCS1v15SessionKey` selects between the decrypted key and the
fallback in constant time. The fallback is deterministic, so a repeated
request does not show whether a fallback was used. The CMS content
decryption that follows fails as with any wrong key. The caller must not
expose a different error for that failure.

## Deployment constraints

Create or import the RA key with both `exportable=false` and
`allow_plaintext_backup=false`. The transport opt-in does not enforce these
settings. Deny key configuration to the RA and application runtime identities.
Enabling either export setting later is irreversible.

Go FIPS-only mode disables this legacy RSA operation. Check SCEP readiness
with the real RA self-test before routing enrollments to a new instance.

## Authorization and audit

Grant the RA runtime identity only the operation path of its own key, plus
its signing path:

```hcl
path "transit/session-key/pkcs1v15/scep-ra-1" { capabilities = ["update"] }
path "transit/sign/scep-ra-1/*"               { capabilities = ["update"] }
```

Keep `keys/`, `keys/:name/config`, `export/`, `backup/` and `decrypt/`
outside that role. The audit device HMACs `ciphertext` and `session_key`
like other string fields.

## Tests

| Test | What it checks |
|---|---|
| `sdk/helper/keysutil` `TestPKCS1v15SessionKey_*` | Recovery of 16/24/32 bytes from an independent math/big encoder and from crypto/rsa; malformed blocks and wrong lengths give stable, distinct fallbacks; size, modulus, length and version checks; rotation, `min_decryption_version`, soft delete; opt-in and RSA-3072 requirement; public-only versions; OAEP unchanged |
| `internal/builtin/logical/transit` `TestTransit_PKCS1v15SessionKey_*` | Route fields and errors; opt-in on create and import only; generated and imported (migrated) RA; OAEP decrypt and signing unchanged; export and backup still refused; version lifecycle; HTTP cluster with an ACL token for one key, denied paths, audit HMAC of the session key |
| `downstream/pki-manager/interop` | Optional OpenSSL cross-check of the primitive; skips without `openssl`, mandatory with `PKI_MANAGER_REQUIRE_OPENSSL=1` (CI does not set it) |
| `downstream/pki-manager/image/smokefixtures` | The Go helper of the image smoke test: TLS fixtures (chain, names, key mode 0600, handshake) and RSAES-PKCS1-v1_5 wrapping |

```
(cd sdk && go test -count=1 -run PKCS1v15 ./helper/keysutil/)
go test -count=1 -run PKCS1v15 ./internal/builtin/logical/transit/
go test -count=1 -v ./downstream/pki-manager/image/smokefixtures/ ./downstream/pki-manager/interop/
```
