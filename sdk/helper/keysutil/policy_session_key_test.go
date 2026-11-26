// SPDX-License-Identifier: Apache-2.0

package keysutil

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The fixtures in this file come from an independent PKCS #1 v1.5 encoder:
// the test builds the encoded block EM by hand and computes EM^e mod n with
// math/big. It does not use crypto/rsa to encrypt, and it needs no
// external tool.

// rawRSAEncrypt returns em^e mod n as a modulus-sized big-endian value.
func rawRSAEncrypt(t *testing.T, pub *rsa.PublicKey, em []byte) []byte {
	t.Helper()
	k := pub.Size()
	if len(em) != k {
		t.Fatalf("encoded block is %d bytes, want %d", len(em), k)
	}
	m := new(big.Int).SetBytes(em)
	if m.Cmp(pub.N) >= 0 {
		t.Fatal("encoded block is not below the modulus")
	}
	c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	return c.FillBytes(make([]byte, k))
}

// nonZeroRandom returns n random bytes, none of them zero.
func nonZeroRandom(t *testing.T, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	for i := range out {
		for out[i] == 0 {
			if _, err := rand.Read(out[i : i+1]); err != nil {
				t.Fatal(err)
			}
		}
	}
	return out
}

// encodeBlock builds 00 || blockType || PS || 00 || msg for a k-byte modulus.
func encodeBlock(t *testing.T, k int, blockType byte, msg []byte) []byte {
	t.Helper()
	psLen := k - 3 - len(msg)
	if psLen < 0 {
		t.Fatal("message too long for the modulus")
	}
	em := make([]byte, 0, k)
	em = append(em, 0x00, blockType)
	em = append(em, nonZeroRandom(t, psLen)...)
	em = append(em, 0x00)
	return append(em, msg...)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func newSessionKeyPolicy(t *testing.T, keyType KeyType, optIn bool) (*Policy, logical.Storage) {
	t.Helper()
	lm, err := NewLockManager(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	storage := &logical.InmemStorage{}
	p, _, err := lm.GetPolicy(context.Background(), PolicyRequest{
		Upsert:                  true,
		Storage:                 storage,
		KeyType:                 keyType,
		Name:                    "scep-ra",
		AllowPKCS1v15SessionKey: optIn,
	}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("nil policy")
	}
	p.Unlock()
	if p.AllowPKCS1v15SessionKey != optIn {
		t.Fatalf("policy opt-in is %v, want %v", p.AllowPKCS1v15SessionKey, optIn)
	}
	return p, storage
}

func publicKeyOf(t *testing.T, p *Policy, ver int) *rsa.PublicKey {
	t.Helper()
	entry, err := p.safeGetKeyEntry(ver)
	if err != nil {
		t.Fatal(err)
	}
	return &entry.RSAKey.PublicKey
}

func requireUserError(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q", contains)
	}
	var userErr errutil.UserError
	if !errors.As(err, &userErr) {
		t.Fatalf("expected a user error, got %T: %v", err, err)
	}
	if contains != "" && !bytes.Contains([]byte(err.Error()), []byte(contains)) {
		t.Fatalf("error %q does not contain %q", err, contains)
	}
}

func TestPKCS1v15SessionKey_RecoversEachLength(t *testing.T) {
	p, _ := newSessionKeyPolicy(t, KeyType_RSA3072, true)
	pub := publicKeyOf(t, p, 1)
	if pub.Size() != 384 {
		t.Fatalf("modulus is %d bytes, want 384", pub.Size())
	}

	for _, keyLen := range PKCS1v15SessionKeyLengths {
		t.Run(fmt.Sprintf("%d_bytes", keyLen), func(t *testing.T) {
			want := randomBytes(t, keyLen)
			ciphertext := rawRSAEncrypt(t, pub, encodeBlock(t, pub.Size(), 0x02, want))
			got, err := p.DecryptPKCS1v15SessionKey(1, ciphertext, keyLen)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("recovered session key differs from the encoded key")
			}
		})
	}

	t.Run("crypto/rsa encoder", func(t *testing.T) {
		want := randomBytes(t, 32)
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.DecryptPKCS1v15SessionKey(1, ciphertext, 32)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("recovered session key differs from the crypto/rsa input")
		}
	})
}

// Invalid padding and a wrong expected length give no error and no
// distinguishable output: a key of the requested length that is stable for
// the same request and differs between requests.
func TestPKCS1v15SessionKey_ImplicitRejection(t *testing.T) {
	p, _ := newSessionKeyPolicy(t, KeyType_RSA3072, true)
	pub := publicKeyOf(t, p, 1)
	k := pub.Size()
	key32 := randomBytes(t, 32)

	cases := map[string]struct {
		em     []byte
		keyLen int
	}{
		"block type 1":           {encodeBlock(t, k, 0x01, key32), 32},
		"block type 0":           {append([]byte{0x00, 0x00}, make([]byte, k-2)...), 32},
		"nonzero leading octet":  {func() []byte { em := encodeBlock(t, k, 0x02, key32); em[0] = 0x01; return em }(), 32},
		"no separator":           {append([]byte{0x00, 0x02}, nonZeroRandom(t, k-2)...), 32},
		"short padding string":   {append(append([]byte{0x00, 0x02}, nonZeroRandom(t, 7)...), append([]byte{0x00}, randomBytes(t, k-10)...)...), 32},
		"16 bytes expected 32":   {encodeBlock(t, k, 0x02, key32[:16]), 32},
		"32 bytes expected 16":   {encodeBlock(t, k, 0x02, key32), 16},
		"24 bytes expected 32":   {encodeBlock(t, k, 0x02, key32[:24]), 32},
		"empty message":          {encodeBlock(t, k, 0x02, nil), 16},
		"oversized message (64)": {encodeBlock(t, k, 0x02, randomBytes(t, 64)), 32},
	}

	seen := map[string]string{}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ciphertext := rawRSAEncrypt(t, pub, tc.em)
			first, err := p.DecryptPKCS1v15SessionKey(1, ciphertext, tc.keyLen)
			if err != nil {
				t.Fatalf("invalid padding must not return an error, got %v", err)
			}
			if len(first) != tc.keyLen {
				t.Fatalf("got %d bytes, want %d", len(first), tc.keyLen)
			}
			if bytes.Equal(first, key32[:tc.keyLen]) {
				t.Fatal("invalid block returned the encoded key")
			}
			want := pkcs1v15RejectionValue(p.Keys["1"].RSAKey, 1, ciphertext, tc.keyLen)
			if !bytes.Equal(first, want) {
				t.Fatal("fallback is not the derived rejection value")
			}
			second, err := p.DecryptPKCS1v15SessionKey(1, ciphertext, tc.keyLen)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, second) {
				t.Fatal("repeated request returned a different fallback")
			}
			if other, ok := seen[string(first)]; ok {
				t.Fatalf("fallback repeats the one of %q", other)
			}
			seen[string(first)] = name
		})
	}

	t.Run("fallback depends on the private key", func(t *testing.T) {
		ciphertext := rawRSAEncrypt(t, pub, encodeBlock(t, k, 0x01, key32))
		other, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}
		a := pkcs1v15RejectionValue(p.Keys["1"].RSAKey, 1, ciphertext, 32)
		b := pkcs1v15RejectionValue(other, 1, ciphertext, 32)
		c := pkcs1v15RejectionValue(p.Keys["1"].RSAKey, 2, ciphertext, 32)
		if bytes.Equal(a, b) || bytes.Equal(a, c) {
			t.Fatal("fallback must depend on the private key and the key version")
		}
		// It is not a plain hash of public data.
		pubHash := sha256.Sum256(ciphertext)
		if bytes.Equal(a, pubHash[:]) {
			t.Fatal("fallback equals a hash of the ciphertext")
		}
	})
}

func TestPKCS1v15SessionKey_PublicChecks(t *testing.T) {
	p, storage := newSessionKeyPolicy(t, KeyType_RSA3072, true)
	pub := publicKeyOf(t, p, 1)
	valid := rawRSAEncrypt(t, pub, encodeBlock(t, pub.Size(), 0x02, randomBytes(t, 16)))

	_, err := p.DecryptPKCS1v15SessionKey(1, valid[1:], 16)
	requireUserError(t, err, "exactly 384 bytes")
	_, err = p.DecryptPKCS1v15SessionKey(1, append(valid, 0), 16)
	requireUserError(t, err, "exactly 384 bytes")

	// A value at or above the modulus is not an RSA ciphertext.
	_, err = p.DecryptPKCS1v15SessionKey(1, pub.N.FillBytes(make([]byte, pub.Size())), 16)
	requireUserError(t, err, "invalid ciphertext")
	allOnes := bytes.Repeat([]byte{0xff}, pub.Size())
	_, err = p.DecryptPKCS1v15SessionKey(1, allOnes, 16)
	requireUserError(t, err, "invalid ciphertext")

	for _, n := range []int{0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 48, 64, -16} {
		_, err = p.DecryptPKCS1v15SessionKey(1, valid, n)
		requireUserError(t, err, "session key length")
	}

	for _, v := range []int{0, -1, 2} {
		_, err = p.DecryptPKCS1v15SessionKey(v, valid, 16)
		requireUserError(t, err, "version")
	}

	// Version lifecycle: rotate, keep v1 usable, then raise min_decryption_version.
	ctx := context.Background()
	if err := p.Rotate(ctx, storage, rand.Reader); err != nil {
		t.Fatal(err)
	}
	pub2 := publicKeyOf(t, p, 2)
	want := randomBytes(t, 24)
	ciphertext2 := rawRSAEncrypt(t, pub2, encodeBlock(t, pub2.Size(), 0x02, want))
	got, err := p.DecryptPKCS1v15SessionKey(2, ciphertext2, 24)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("version 2 did not recover its session key: %v", err)
	}
	// The wrong version does not report padding: it yields the fallback.
	got, err = p.DecryptPKCS1v15SessionKey(1, ciphertext2, 24)
	if err != nil || bytes.Equal(got, want) {
		t.Fatalf("version 1 must return a fallback for a version 2 ciphertext: %v", err)
	}
	if _, err = p.DecryptPKCS1v15SessionKey(1, valid, 16); err != nil {
		t.Fatalf("version 1 stays usable after rotation: %v", err)
	}
	p.MinDecryptionVersion = 2
	_, err = p.DecryptPKCS1v15SessionKey(1, valid, 16)
	requireUserError(t, err, ErrTooOld)

	p.SoftDeleted = true
	_, err = p.DecryptPKCS1v15SessionKey(2, ciphertext2, 24)
	requireUserError(t, err, ErrSoftDeleted)
}

func TestPKCS1v15SessionKey_RequiresOptInAndRSA3072(t *testing.T) {
	plain, _ := newSessionKeyPolicy(t, KeyType_RSA3072, false)
	pub := publicKeyOf(t, plain, 1)
	ciphertext := rawRSAEncrypt(t, pub, encodeBlock(t, pub.Size(), 0x02, randomBytes(t, 16)))
	_, err := plain.DecryptPKCS1v15SessionKey(1, ciphertext, 16)
	requireUserError(t, err, "does not permit")

	// The opt-in is checked before the key type; force it on a 2048-bit key.
	rsa2048, _ := newSessionKeyPolicy(t, KeyType_RSA2048, false)
	rsa2048.AllowPKCS1v15SessionKey = true
	pub2048 := publicKeyOf(t, rsa2048, 1)
	c2048 := rawRSAEncrypt(t, pub2048, encodeBlock(t, pub2048.Size(), 0x02, randomBytes(t, 16)))
	_, err = rsa2048.DecryptPKCS1v15SessionKey(1, c2048, 16)
	requireUserError(t, err, "requires an rsa-3072 key")
}

func TestPKCS1v15SessionKey_PublicOnlyVersion(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{
		Name:                    "public-only",
		Type:                    KeyType_RSA3072,
		Imported:                true,
		AllowPKCS1v15SessionKey: true,
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	if err := p.ImportPublicOrPrivate(context.Background(), &logical.InmemStorage{}, publicPEM, false, rand.Reader); err != nil {
		t.Fatal(err)
	}
	ciphertext := rawRSAEncrypt(t, &priv.PublicKey, encodeBlock(t, priv.Size(), 0x02, randomBytes(t, 16)))
	_, err = p.DecryptPKCS1v15SessionKey(1, ciphertext, 16)
	requireUserError(t, err, "private counterpart")
}

// The opt-in leaves RSA-OAEP decryption unchanged.
func TestPKCS1v15SessionKey_OAEPUnchanged(t *testing.T) {
	p, _ := newSessionKeyPolicy(t, KeyType_RSA3072, true)
	ciphertext, err := p.Encrypt(1, nil, nil, "c2Vzc2lvbi1rZXktdHJhbnNwb3J0")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := p.Decrypt(nil, nil, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "c2Vzc2lvbi1rZXktdHJhbnNwb3J0" {
		t.Fatal("OAEP round trip changed")
	}
}
