package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"homegate.local/homegate/internal/config"
)

func TestMatchesPatternSingleLabelWildcard(t *testing.T) {
	if !MatchesPattern("a.example.com", "*.example.com") {
		t.Fatal("expected wildcard match")
	}
	if MatchesPattern("a.b.example.com", "*.example.com") {
		t.Fatal("wildcard matched multiple labels")
	}
	if MatchesPattern("example.com", "*.example.com") {
		t.Fatal("wildcard matched zone apex")
	}
}

func TestResolvePrefersExactOverWildcard(t *testing.T) {
	idx, err := New([]config.Certificate{
		{ID: "wild", Enabled: true, Domains: []string{"*.example.com"}},
		{ID: "exact", Enabled: true, Domains: []string{"a.example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := idx.Resolve("", "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "exact" {
		t.Fatalf("Resolve selected %q, want exact", got)
	}
}

func TestResolveValidatesExplicitReference(t *testing.T) {
	idx, err := New([]config.Certificate{
		{ID: "disabled", Enabled: false, Domains: []string{"a.example.com"}},
		{ID: "other", Enabled: true, Domains: []string{"b.example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ id, want string }{
		{"missing", "not found"},
		{"disabled", "disabled"},
		{"other", "does not cover"},
	}
	for _, tc := range cases {
		if _, err := idx.Resolve(tc.id, "a.example.com"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("Resolve(%q) error=%v, want substring %q", tc.id, err, tc.want)
		}
	}
}

func TestNewRejectsDuplicateEnabledPattern(t *testing.T) {
	_, err := New([]config.Certificate{
		{ID: "one", Enabled: true, Domains: []string{"*.example.com"}},
		{ID: "two", Enabled: true, Domains: []string{"*.EXAMPLE.com."}},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("New error=%v, want duplicate pattern error", err)
	}
}

func TestNewAllowsDisabledDuplicatePattern(t *testing.T) {
	if _, err := New([]config.Certificate{
		{ID: "one", Enabled: true, Domains: []string{"*.example.com"}},
		{ID: "two", Enabled: false, Domains: []string{"*.example.com"}},
	}); err != nil {
		t.Fatal(err)
	}
}

func testCertificatePEM(t *testing.T, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unused.example.com"},
		DNSNames:     append([]string{}, dnsNames...),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestValidatePEMIdentitiesExactWildcardAndSAN(t *testing.T) {
	chain := testCertificatePEM(t, []string{"Example.COM.", "*.chenos.cn", "home.chenos.cn"})
	if err := ValidatePEMIdentities(chain, []string{"example.com", "*.CHENOS.CN.", "home.chenos.cn"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePEMIdentitiesRejectsMissingIdentity(t *testing.T) {
	chain := testCertificatePEM(t, []string{"example.com"})
	err := ValidatePEMIdentities(chain, []string{"example.com", "*.chenos.cn"})
	if err == nil || !strings.Contains(err.Error(), "missing DNS identity *.chenos.cn") {
		t.Fatalf("error=%v, want missing wildcard identity", err)
	}
}

func TestValidatePEMIdentitiesRejectsUnexpectedIdentity(t *testing.T) {
	chain := testCertificatePEM(t, []string{"example.com", "extra.example.com"})
	err := ValidatePEMIdentities(chain, []string{"example.com"})
	if err == nil || !strings.Contains(err.Error(), "unexpected DNS identity extra.example.com") {
		t.Fatalf("error=%v, want unexpected identity", err)
	}
}

func TestValidatePEMIdentitiesRejectsCNOnlyCertificate(t *testing.T) {
	chain := testCertificatePEM(t, nil)
	err := ValidatePEMIdentities(chain, []string{"example.com"})
	if err == nil || !strings.Contains(err.Error(), "no DNS SAN identities") {
		t.Fatalf("error=%v, want no DNS SAN identities", err)
	}
}
