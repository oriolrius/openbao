// SPDX-License-Identifier: Apache-2.0

package keysutil

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/helper/errutil"
)

// PKCS#1 v1.5 session-key transport (PKI Manager downstream).
//
// SCEP wraps the CMS content-encryption key with RSAES-PKCS1-v1_5. The
// operation below recovers that key for one explicit key version and one
// explicit key length. It never reports whether the padding was valid:
//
//   - The output buffer is filled before decryption with a value derived
//     from the private key and the request (HMAC-SHA-256). When the padding
//     or the length is wrong, rsa.DecryptPKCS1v15SessionKey leaves the buffer
//     unchanged, in constant time. The caller then continues the protocol
//     with a key that fails later, in the same way as a wrong key.
//   - The derived value is deterministic. A repeated request with the same
//     invalid ciphertext returns the same bytes, so repetition does not show
//     whether a random fallback was used (see the crypto/rsa documentation).
//
// Errors depend only on public request properties (key state, version,
// ciphertext size, key length), never on the decrypted padding.

// PKCS1v15SessionKeyLengths lists the content-encryption key lengths the
// operation accepts: AES-128, 3DES / AES-192, AES-256.
var PKCS1v15SessionKeyLengths = []int{16, 24, 32}

const pkcs1v15RejectionLabel = "openbao-pki-manager/pkcs1v15-session-key/implicit-rejection/v1"

// ValidPKCS1v15SessionKeyLength reports whether n is an accepted session-key length.
func ValidPKCS1v15SessionKeyLength(n int) bool {
	for _, l := range PKCS1v15SessionKeyLengths {
		if n == l {
			return true
		}
	}
	return false
}

// DecryptPKCS1v15SessionKey recovers a session key of exactly keyLen bytes
// from an RSAES-PKCS1-v1_5 ciphertext with key version ver.
func (p *Policy) DecryptPKCS1v15SessionKey(ver int, ciphertext []byte, keyLen int) ([]byte, error) {
	if p.SoftDeleted {
		return nil, errutil.UserError{Err: ErrSoftDeleted}
	}
	if !p.AllowPKCS1v15SessionKey {
		return nil, errutil.UserError{Err: "key does not permit PKCS#1 v1.5 session-key transport"}
	}
	if p.Type != KeyType_RSA3072 {
		return nil, errutil.UserError{Err: fmt.Sprintf("PKCS#1 v1.5 session-key transport requires an rsa-3072 key, not %v", p.Type)}
	}
	if !ValidPKCS1v15SessionKeyLength(keyLen) {
		return nil, errutil.UserError{Err: fmt.Sprintf("session key length must be one of %v bytes", PKCS1v15SessionKeyLengths)}
	}
	switch {
	case ver <= 0:
		return nil, errutil.UserError{Err: "key version must be a positive integer"}
	case ver > p.LatestVersion:
		return nil, errutil.UserError{Err: "key version does not exist"}
	case p.MinDecryptionVersion > 0 && ver < p.MinDecryptionVersion:
		return nil, errutil.UserError{Err: ErrTooOld}
	case ver < p.MinAvailableVersion:
		return nil, errutil.UserError{Err: "key version is no longer available"}
	}

	keyEntry, err := p.safeGetKeyEntry(ver)
	if err != nil {
		return nil, err
	}
	key := keyEntry.RSAKey
	if key == nil {
		return nil, errutil.UserError{Err: "key version does not have a private counterpart"}
	}
	if len(ciphertext) != key.Size() {
		return nil, errutil.UserError{Err: fmt.Sprintf("ciphertext must be exactly %d bytes", key.Size())}
	}

	sessionKey := pkcs1v15RejectionValue(key, ver, ciphertext, keyLen)
	if err := rsa.DecryptPKCS1v15SessionKey(nil, key, ciphertext, sessionKey); err != nil {
		// Only the public checks above (size, value >= modulus) fail here.
		return nil, errutil.UserError{Err: "invalid ciphertext for this key"}
	}
	return sessionKey, nil
}

// pkcs1v15RejectionValue derives the fallback session key. Its HMAC key
// comes from the private exponent, so the value is unpredictable without
// the private key and identical for identical requests.
func pkcs1v15RejectionValue(key *rsa.PrivateKey, ver int, ciphertext []byte, keyLen int) []byte {
	seed := sha256.New()
	seed.Write([]byte(pkcs1v15RejectionLabel))
	seed.Write(key.D.Bytes())
	macKey := seed.Sum(nil)

	var header [8]byte
	binary.BigEndian.PutUint32(header[0:4], uint32(ver))
	binary.BigEndian.PutUint32(header[4:8], uint32(keyLen))

	mac := hmac.New(sha256.New, macKey)
	mac.Write(header[:])
	mac.Write(ciphertext)
	return mac.Sum(nil)[:keyLen]
}
