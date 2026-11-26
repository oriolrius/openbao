// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestTLSFixtures(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"tls", dir}, nil); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"ca.pem": 0o644, "server.pem": 0o644, "server-key.pem": 0o600} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		// The umask can only remove bits; the key must never be readable by others.
		if got := info.Mode().Perm(); got&^want != 0 {
			t.Errorf("%s: mode %o, want at most %o", name, got, want)
		}
	}

	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca.pem has no certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "localhost"} {
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName: host, Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Errorf("verify for %s: %v", host, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots}); err == nil {
		t.Error("certificate verified for a name it does not have")
	}

	// A real TLS handshake with the files, as the server and a client use them.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(),
		&tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestTLSFixturesDoNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"tls", dir}, nil); err == nil {
		t.Fatal("tls wrote into a directory that already has fixtures")
	}
}

func TestWrapSessionKey(t *testing.T) {
	raKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&raKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "ra.pub.pem")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, length := range []int{16, 24, 32} {
		var out bytes.Buffer
		if err := run([]string{"wrap", pubPath, strconv.Itoa(length)}, &out); err != nil {
			t.Fatal(err)
		}
		var got struct {
			SessionKey string `json:"session_key"`
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		sessionKey, err := base64.StdEncoding.DecodeString(got.SessionKey)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := base64.StdEncoding.DecodeString(got.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if len(sessionKey) != length {
			t.Fatalf("session key is %d bytes, want %d", len(sessionKey), length)
		}
		if len(ciphertext) != raKey.Size() {
			t.Fatalf("ciphertext is %d bytes, want %d", len(ciphertext), raKey.Size())
		}
		plain, err := rsa.DecryptPKCS1v15(nil, raKey, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, sessionKey) {
			t.Fatal("decrypted session key differs")
		}
	}
}

func TestWrapRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	notRSA := filepath.Join(dir, "x.pem")
	if err := os.WriteFile(notRSA, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"wrap", notRSA, "32"},
		{"wrap", notRSA, "0"},
		{"wrap", notRSA, "x"},
		{"wrap", filepath.Join(dir, "missing.pem"), "32"},
		{"nope"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
