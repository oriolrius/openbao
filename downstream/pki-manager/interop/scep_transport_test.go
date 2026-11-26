// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestOpenSSLRSAKeyTransport checks the RSA key transport used by SCEP
// against OpenSSL. It is an optional cross-check: without openssl on PATH it
// skips, unless PKI_MANAGER_REQUIRE_OPENSSL=1 makes OpenSSL mandatory.
// The mandatory tests use Go fixtures only (sdk/helper/keysutil and
// internal/builtin/logical/transit, *PKCS1v15SessionKey*).
// Only the public RSA key goes to disk.
func TestOpenSSLRSAKeyTransport(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("PKI_MANAGER_REQUIRE_OPENSSL") == "1" {
			t.Fatal("PKI_MANAGER_REQUIRE_OPENSSL=1 but openssl is not on PATH")
		}
		t.Skip("optional OpenSSL cross-check: openssl is not on PATH")
	}
	raKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&raKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(t.TempDir(), "ra-public.pem")
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	if err := os.WriteFile(publicPath, publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, keyBytes := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("%d_bytes", keyBytes), func(t *testing.T) {
			contentKey := make([]byte, keyBytes)
			if _, err := rand.Read(contentKey); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(openssl, "pkeyutl", "-encrypt", "-pubin",
				"-inkey", publicPath, "-pkeyopt", "rsa_padding_mode:pkcs1")
			cmd.Stdin = bytes.NewReader(contentKey)
			ciphertext, err := cmd.Output()
			if err != nil {
				t.Fatalf("OpenSSL encryption failed: %v", err)
			}
			if len(ciphertext) != raKey.Size() {
				t.Fatalf("got %d bytes of ciphertext, want %d", len(ciphertext), raKey.Size())
			}

			// The CMS layer must supply the expected key size before decryption.
			recovered := make([]byte, keyBytes)
			if _, err := rand.Read(recovered); err != nil {
				t.Fatal(err)
			}
			if err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, raKey, ciphertext, recovered); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(recovered, contentKey) {
				t.Fatal("recovered session key differs from OpenSSL input")
			}
		})
	}
}
