package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestAccountKeyRejectsCorruptionWithoutOverwriting(t *testing.T) {
	for _, data := range [][]byte{[]byte("broken backup"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("bad DER")})} {
		path := filepath.Join(t.TempDir(), "account.key")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ecdsaKey(path); err == nil {
			t.Fatal("corrupt account key silently regenerated")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("existing account key overwritten")
		}
	}
}

func TestAccountKeyRejectsUnsupportedCurve(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ecdsaKey(path); err == nil {
		t.Fatal("unsupported ES256 curve accepted")
	}
}

func TestAccountKeyCreatesOnceAndReusesIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")
	a, err := ecdsaKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdsaKey(path)
	if err != nil || a.D.Cmp(b.D) != 0 {
		t.Fatal("account identity not preserved")
	}
}
