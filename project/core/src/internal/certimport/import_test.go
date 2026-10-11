package certimport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testPair(t *testing.T, names []string, key *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestInspectPEMPairReturnsNormalizedSANs(t *testing.T) {
	cert, key := testPair(t, []string{"*.CHENOS.CN", "chenos.cn"}, nil)
	domains, exp, err := InspectPEM(cert, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0] != "*.chenos.cn" || domains[1] != "chenos.cn" {
		t.Fatalf("domains=%v", domains)
	}
	if !exp.After(time.Now()) {
		t.Fatalf("expires=%v", exp)
	}
}

func TestInspectPEMRejectsMismatchedKey(t *testing.T) {
	cert, _ := testPair(t, []string{"chenos.cn"}, nil)
	_, other := testPair(t, []string{"chenos.cn"}, nil)
	if _, _, err := InspectPEM(cert, other, time.Now()); err == nil {
		t.Fatal("expected key mismatch")
	}
}

func TestImportPublishesPair(t *testing.T) {
	cert, key := testPair(t, []string{"chenos.cn", "*.chenos.cn"}, nil)
	tmp := t.TempDir()
	certSrc := filepath.Join(tmp, "cert.pem")
	keySrc := filepath.Join(tmp, "key.pem")
	if err := os.WriteFile(certSrc, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keySrc, key, 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Import(filepath.Join(tmp, "homegate"), "0.5.0", "cert_local_test", certSrc, keySrc)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Domains) != 2 {
		t.Fatalf("report=%+v", report)
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		path := filepath.Join(tmp, "homegate", "certs", "cert_local_test", name)
		if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s stat=%v err=%v", name, st, err)
		}
	}
}
