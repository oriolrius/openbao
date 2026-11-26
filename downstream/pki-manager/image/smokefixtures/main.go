// SPDX-License-Identifier: Apache-2.0

// Command smokefixtures makes the test material of smoke-test.sh with the Go
// standard library, so the image smoke test does not need the openssl CLI.
//
//	smokefixtures tls DIR
//	    Writes DIR/ca.pem, DIR/server.pem and DIR/server-key.pem: a throwaway
//	    ECDSA P-256 CA and a server certificate for 127.0.0.1 and localhost,
//	    valid for one day. The CA private key stays in memory. The server key
//	    file is mode 0600.
//
//	smokefixtures wrap PUBLIC_KEY_PEM LENGTH
//	    Makes a random session key of LENGTH bytes, encrypts it to the RSA
//	    public key with RSAES-PKCS1-v1_5 (the SCEP key transport), and prints
//	    {"session_key": base64, "ciphertext": base64} on stdout.
//
// Test material only. Nothing here is for production keys.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "smokefixtures:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	switch {
	case len(args) == 2 && args[0] == "tls":
		return writeTLS(args[1], time.Now())
	case len(args) == 3 && args[0] == "wrap":
		length, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("LENGTH: %w", err)
		}
		return wrap(args[1], length, stdout)
	default:
		return errors.New("usage: smokefixtures tls DIR | smokefixtures wrap PUBLIC_KEY_PEM LENGTH")
	}
}

// writeTLS writes a CA certificate, a server certificate signed by it and the
// server private key into dir.
func writeTLS(dir string, now time.Time) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	notBefore, notAfter := now.Add(-5*time.Minute), now.Add(24*time.Hour)

	caTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "smoke-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "openbao"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return err
	}

	files := []struct {
		name, pemType string
		der           []byte
		mode          os.FileMode
	}{
		{"ca.pem", "CERTIFICATE", caDER, 0o644},
		{"server.pem", "CERTIFICATE", serverDER, 0o644},
		{"server-key.pem", "PRIVATE KEY", serverKeyDER, 0o600},
	}
	for _, f := range files {
		data := pem.EncodeToMemory(&pem.Block{Type: f.pemType, Bytes: f.der})
		if err := writeNew(filepath.Join(dir, f.name), data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// writeNew creates path with mode (it must not exist yet), so an existing
// file never keeps looser permissions.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// wrap encrypts a new random session key to the RSA public key in pubPath.
func wrap(pubPath string, length int, stdout io.Writer) error {
	if length < 1 || length > 64 {
		return fmt.Errorf("LENGTH %d: want 1..64 bytes", length)
	}
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("%s: no PEM PUBLIC KEY block", pubPath)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%s: not an RSA public key", pubPath)
	}
	sessionKey := make([]byte, length)
	if _, err := rand.Read(sessionKey); err != nil {
		return err
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, sessionKey)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{
		"session_key": base64.StdEncoding.EncodeToString(sessionKey),
		"ciphertext":  base64.StdEncoding.EncodeToString(ciphertext),
	})
}
