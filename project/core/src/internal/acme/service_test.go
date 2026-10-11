package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/dnsprovider"
)

type fakeProvider struct {
	mu      sync.Mutex
	upserts []string
	deletes []string
}

func (p *fakeProvider) Upsert(_ context.Context, zone, host, typ, value string, ttl int) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.upserts = append(p.upserts, fmt.Sprintf("%s|%s|%s|%s|%d", zone, host, typ, value, ttl))
	return "created", nil
}
func (p *fakeProvider) Delete(_ context.Context, zone, host, typ, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deletes = append(p.deletes, fmt.Sprintf("%s|%s|%s|%s", zone, host, typ, value))
	return nil
}

type fakeWaiter struct {
	fqdn, value string
	err         error
}

func (w *fakeWaiter) Wait(_ context.Context, fqdn, value string) error {
	w.fqdn, w.value = fqdn, value
	return w.err
}

type fakeLog struct{ errors []string }

func (l *fakeLog) Infof(string, ...any)         {}
func (l *fakeLog) Errorf(f string, args ...any) { l.errors = append(l.errors, fmt.Sprintf(f, args...)) }

func testConfig(dirURL string) config.Snapshot {
	return config.Snapshot{
		Configured:   true,
		Main:         config.Main{Enabled: true, ACMEDirectory: dirURL, ACMEEmail: "ops@example.com", RenewDays: 30, DDNSInterval: 300, LogLevel: "info", LogMaxLines: 1024},
		Accounts:     map[string]config.DNSAccount{"dns": {ID: "dns", Provider: "aliyun", KeyID: "id", Secret: "secret"}},
		Certificates: []config.Certificate{{ID: "cert_test", Enabled: true, Name: "test", Account: "dns", Zone: "example.com", Domains: []string{"test.example.com"}, RenewDays: 30, Environment: config.CertificateEnvProduction}},
	}
}

func certificatePEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.example.com"}, DNSNames: []string{"test.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newACMEMock(t *testing.T, certPEM []byte) (*httptest.Server, *bool) {
	t.Helper()
	challengeValid := false
	var srv *httptest.Server
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL
		w.Header().Set("Replay-Nonce", "nonce-next")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/dir":
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, base+"/nonce", base+"/account", base+"/order")
		case r.Method == http.MethodHead && r.URL.Path == "/nonce":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/account":
			w.Header().Set("Location", base+"/acct/1")
			fmt.Fprint(w, `{"status":"valid"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/order":
			w.Header().Set("Location", base+"/order/1")
			fmt.Fprintf(w, `{"status":"pending","authorizations":[%q],"finalize":%q}`, base+"/auth/1", base+"/finalize")
		case r.Method == http.MethodPost && r.URL.Path == "/auth/1":
			status := "pending"
			if challengeValid {
				status = "valid"
			}
			fmt.Fprintf(w, `{"status":%q,"identifier":{"type":"dns","value":"test.example.com"},"wildcard":false,"challenges":[{"type":"dns-01","url":%q,"status":%q,"token":"token-123"}]}`, status, base+"/challenge", status)
		case r.Method == http.MethodPost && r.URL.Path == "/challenge":
			challengeValid = true
			fmt.Fprint(w, `{}`)
		case r.Method == http.MethodPost && r.URL.Path == "/finalize":
			fmt.Fprintf(w, `{"status":"valid","certificate":%q}`, base+"/cert/1")
		case r.Method == http.MethodPost && r.URL.Path == "/order/1":
			fmt.Fprintf(w, `{"status":"valid","certificate":%q}`, base+"/cert/1")
		case r.Method == http.MethodPost && r.URL.Path == "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(certPEM)
		default:
			t.Fatalf("unexpected ACME request %s %s", r.Method, r.URL.Path)
		}
	})
	srv = httptest.NewServer(h)
	return srv, &challengeValid
}

func newCSRSigningACMEMock(t *testing.T, notAfter time.Time) (*httptest.Server, *bool) {
	t.Helper()
	challengeValid := false
	var issuedPEM []byte
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "HomeGate Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	var srv *httptest.Server
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL
		w.Header().Set("Replay-Nonce", "nonce-next")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/dir":
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, base+"/nonce", base+"/account", base+"/order")
		case r.Method == http.MethodHead && r.URL.Path == "/nonce":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/account":
			w.Header().Set("Location", base+"/acct/1")
			fmt.Fprint(w, `{"status":"valid"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/order":
			w.Header().Set("Location", base+"/order/1")
			fmt.Fprintf(w, `{"status":"pending","authorizations":[%q],"finalize":%q}`, base+"/auth/1", base+"/finalize")
		case r.Method == http.MethodPost && r.URL.Path == "/auth/1":
			status := "pending"
			if challengeValid {
				status = "valid"
			}
			fmt.Fprintf(w, `{"status":%q,"identifier":{"type":"dns","value":"test.example.com"},"wildcard":false,"challenges":[{"type":"dns-01","url":%q,"status":%q,"token":"token-123"}]}`, status, base+"/challenge", status)
		case r.Method == http.MethodPost && r.URL.Path == "/challenge":
			challengeValid = true
			fmt.Fprint(w, `{}`)
		case r.Method == http.MethodPost && r.URL.Path == "/finalize":
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Fatalf("read finalize request: %v", readErr)
			}
			var jws map[string]string
			if err := json.Unmarshal(body, &jws); err != nil {
				t.Fatalf("decode finalize JWS: %v", err)
			}
			payload, err := b64raw.DecodeString(jws["payload"])
			if err != nil {
				t.Fatalf("decode finalize payload: %v", err)
			}
			var req struct {
				CSR string `json:"csr"`
			}
			if err := json.Unmarshal(payload, &req); err != nil {
				t.Fatalf("decode finalize payload JSON: %v", err)
			}
			csrDER, err := b64raw.DecodeString(req.CSR)
			if err != nil {
				t.Fatalf("decode CSR: %v", err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatalf("parse CSR: %v", err)
			}
			leaf := x509.Certificate{
				SerialNumber: big.NewInt(101),
				Subject:      csr.Subject,
				DNSNames:     append([]string{}, csr.DNSNames...),
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     notAfter,
				KeyUsage:     x509.KeyUsageDigitalSignature,
			}
			der, err := x509.CreateCertificate(rand.Reader, &leaf, &caTpl, csr.PublicKey, caKey)
			if err != nil {
				t.Fatalf("issue test certificate: %v", err)
			}
			issuedPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			fmt.Fprintf(w, `{"status":"valid","certificate":%q}`, base+"/cert/1")
		case r.Method == http.MethodPost && r.URL.Path == "/order/1":
			fmt.Fprintf(w, `{"status":"valid","certificate":%q}`, base+"/cert/1")
		case r.Method == http.MethodPost && r.URL.Path == "/cert/1":
			if len(issuedPEM) == 0 {
				t.Fatal("certificate requested before finalize")
			}
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(issuedPEM)
		default:
			t.Fatalf("unexpected ACME request %s %s", r.Method, r.URL.Path)
		}
	})
	srv = httptest.NewServer(h)
	return srv, &challengeValid
}

func TestChallengeHost(t *testing.T) {
	cases := map[string]string{"example.com": "_acme-challenge", "*.example.com": "_acme-challenge", "test.example.com": "_acme-challenge.test"}
	for domain, want := range cases {
		got, err := challengeHost(domain, "example.com")
		if err != nil || got != want {
			t.Fatalf("domain=%s got=%s err=%v", domain, got, err)
		}
	}
	if _, err := challengeHost("other.net", "example.com"); err == nil {
		t.Fatal("expected zone error")
	}
}

func TestIssueDNS01AndExactCleanup(t *testing.T) {
	srv, valid := newCSRSigningACMEMock(t, time.Now().Add(90*24*time.Hour))
	defer srv.Close()
	provider := &fakeProvider{}
	waiter := &fakeWaiter{}
	home := t.TempDir()
	svc := NewService(home, nil)
	svc.HTTP = srv.Client()
	svc.Provider = func(config.DNSAccount) (dnsprovider.RecordProvider, error) { return provider, nil }
	svc.TXT = waiter
	svc.Sleep = func(context.Context, time.Duration) error { return nil }
	cfg := testConfig(srv.URL + "/dir")
	svc.DirectoryForEnvironment = func(string) string { return cfg.Main.ACMEDirectory }
	report, err := svc.Issue(context.Background(), "0.5.0", cfg, cfg.Certificates[0])
	if err != nil {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if !report.OK || report.Certificate != "cert_test" || report.Expires == "" || !*valid {
		t.Fatalf("report=%+v valid=%v", report, *valid)
	}
	if waiter.fqdn != "_acme-challenge.test.example.com" || waiter.value == "" {
		t.Fatalf("waiter=%+v", waiter)
	}
	if len(provider.upserts) != 1 || len(provider.deletes) != 1 {
		t.Fatalf("upserts=%v deletes=%v", provider.upserts, provider.deletes)
	}
	upParts := strings.Split(provider.upserts[0], "|")
	delParts := strings.Split(provider.deletes[0], "|")
	if upParts[1] != "_acme-challenge.test" || upParts[2] != "TXT" || upParts[3] != delParts[3] || delParts[1] != "_acme-challenge.test" {
		t.Fatalf("upsert=%v delete=%v", upParts, delParts)
	}
	certPath, keyPath := svc.certPaths("cert_test")
	for _, path := range []string{certPath, keyPath, svc.accountKeyPath()} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o", path, st.Mode().Perm())
		}
	}
	status := svc.Status("0.5.0", cfg)
	if len(status.Certificates) != 1 || !status.Certificates[0].Exists || status.Certificates[0].Renew {
		t.Fatalf("status=%+v", status)
	}
}

func TestIssueUsesCertificateEnvironment(t *testing.T) {
	srv, _ := newCSRSigningACMEMock(t, time.Now().Add(90*24*time.Hour))
	defer srv.Close()
	provider := &fakeProvider{}
	waiter := &fakeWaiter{}
	svc := NewService(t.TempDir(), nil)
	svc.HTTP = srv.Client()
	svc.Provider = func(config.DNSAccount) (dnsprovider.RecordProvider, error) { return provider, nil }
	svc.TXT = waiter
	svc.Sleep = func(context.Context, time.Duration) error { return nil }
	cfg := testConfig("unused")
	cfg.Certificates[0].Environment = config.CertificateEnvStaging
	seen := ""
	svc.DirectoryForEnvironment = func(environment string) string {
		seen = environment
		return srv.URL + "/dir"
	}
	report, err := svc.Issue(context.Background(), "0.5.0", cfg, cfg.Certificates[0])
	if err != nil || !report.OK {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if seen != config.CertificateEnvStaging {
		t.Fatalf("directory resolver environment=%q", seen)
	}
	status := svc.Status("0.5.0", cfg)
	if len(status.Certificates) != 1 || status.Certificates[0].Environment != config.CertificateEnvStaging {
		t.Fatalf("status=%+v", status)
	}
}

func TestTXTCleanupRunsWhenPropagationFails(t *testing.T) {
	srv, _ := newACMEMock(t, certificatePEM(t, time.Now().Add(90*24*time.Hour)))
	defer srv.Close()
	provider := &fakeProvider{}
	waiter := &fakeWaiter{err: errors.New("dns not propagated")}
	svc := NewService(t.TempDir(), nil)
	svc.HTTP = srv.Client()
	svc.Provider = func(config.DNSAccount) (dnsprovider.RecordProvider, error) { return provider, nil }
	svc.TXT = waiter
	svc.Sleep = func(context.Context, time.Duration) error { return nil }
	cfg := testConfig(srv.URL + "/dir")
	svc.DirectoryForEnvironment = func(string) string { return cfg.Main.ACMEDirectory }
	report, err := svc.Issue(context.Background(), "0.5.0", cfg, cfg.Certificates[0])
	if err == nil || report.OK || !strings.Contains(report.Error, "dns not propagated") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if len(provider.upserts) != 1 || len(provider.deletes) != 1 {
		t.Fatalf("upserts=%v deletes=%v", provider.upserts, provider.deletes)
	}
}

func TestStatusRecognizesExistingR6CertificatePath(t *testing.T) {
	home := t.TempDir()
	svc := NewService(home, nil)
	path, _ := svc.certPaths("cert_c00a05d1c203")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, certificatePEM(t, time.Now().Add(89*24*time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Snapshot{Certificates: []config.Certificate{{ID: "cert_c00a05d1c203", Enabled: true, Domains: []string{"test.chenos.cn"}, RenewDays: 30}}}
	st := svc.Status("0.5.0", cfg)
	if len(st.Certificates) != 1 || !st.Certificates[0].Exists || st.Certificates[0].Renew {
		t.Fatalf("status=%+v", st)
	}
}

func TestRenewDueSkipsFreshExistingCertificateWithoutProviderCall(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 9, 5, 15, 0, 0, 0, time.UTC)
	svc := NewService(home, nil)
	svc.Now = func() time.Time { return now }
	path, _ := svc.certPaths("cert_fresh")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, certificatePEM(t, now.Add(89*24*time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	svc.Provider = func(config.DNSAccount) (dnsprovider.RecordProvider, error) {
		called = true
		return nil, errors.New("should not be called")
	}
	cfg := config.Snapshot{Certificates: []config.Certificate{{ID: "cert_fresh", Enabled: true, Account: "dns", Zone: "example.com", Domains: []string{"test.example.com"}, RenewDays: 30}}}
	report := svc.RenewDue(context.Background(), "0.5.0", cfg)
	if !report.OK || len(report.Results) != 0 || called {
		t.Fatalf("report=%+v called=%v", report, called)
	}
}

func TestRenewalFailureStatePersistsUntilSuccessfulRenewal(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 9, 8, 8, 0, 0, 0, time.UTC)
	svc := NewService(home, nil)
	svc.Now = func() time.Time { return now }
	path, _ := svc.certPaths("cert_due")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, certificatePEM(t, now.Add(25*24*time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Snapshot{Certificates: []config.Certificate{{ID: "cert_due", Enabled: true, Domains: []string{"test.example.com"}, RenewDays: 30}}}

	if err := svc.writeRenewalAttempt("cert_due", false); err != nil {
		t.Fatal(err)
	}
	failed := svc.Status("0.5.0", cfg).Certificates[0]
	if !failed.Renew || failed.RenewState != "failed" || failed.LastRenewAt == "" || failed.Days != 25 {
		t.Fatalf("failed status=%+v", failed)
	}

	if err := svc.writeRenewalAttempt("cert_due", true); err != nil {
		t.Fatal(err)
	}
	cleared := svc.Status("0.5.0", cfg).Certificates[0]
	if cleared.RenewState != "" || cleared.LastRenewAt == "" {
		t.Fatalf("successful attempt did not clear failure: %+v", cleared)
	}
}

func TestOldRenewalFailureDoesNotMaskFreshCertificate(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 9, 8, 8, 0, 0, 0, time.UTC)
	svc := NewService(home, nil)
	svc.Now = func() time.Time { return now }
	path, _ := svc.certPaths("cert_fresh_after_failure")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, certificatePEM(t, now.Add(89*24*time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := svc.writeRenewalAttempt("cert_fresh_after_failure", false); err != nil {
		t.Fatal(err)
	}
	cfg := config.Snapshot{Certificates: []config.Certificate{{ID: "cert_fresh_after_failure", Enabled: true, Domains: []string{"test.example.com"}, RenewDays: 30}}}
	st := svc.Status("0.5.0", cfg).Certificates[0]
	if st.Renew || st.RenewState != "" || st.Days != 89 {
		t.Fatalf("fresh certificate incorrectly warned: %+v", st)
	}
}

func TestIssueDoesNotPublishGeneratedKeyForMismatchedCertificate(t *testing.T) {
	srv, _ := newACMEMock(t, certificatePEM(t, time.Now().Add(90*24*time.Hour)))
	defer srv.Close()
	svc := NewService(t.TempDir(), nil)
	svc.HTTP = srv.Client()
	svc.Provider = func(config.DNSAccount) (dnsprovider.RecordProvider, error) { return &fakeProvider{}, nil }
	svc.TXT = &fakeWaiter{}
	svc.Sleep = func(context.Context, time.Duration) error { return nil }
	cfg := testConfig(srv.URL + "/dir")
	svc.DirectoryForEnvironment = func(string) string { return cfg.Main.ACMEDirectory }

	report, err := svc.Issue(context.Background(), "0.5.0", cfg, cfg.Certificates[0])
	if err == nil || report.OK || !strings.Contains(report.Error, "private key mismatch") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	certPath, keyPath := svc.certPaths("cert_test")
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("mismatched certificate was published: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("generated private key was published before certificate validation: %v", err)
	}
}

func TestCertificateRenewalLockHonorsContext(t *testing.T) {
	svc := NewService(t.TempDir(), nil)
	release, err := svc.acquireCertificateLock(context.Background(), "cert_lock")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := svc.acquireCertificateLock(ctx, "cert_lock"); err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected lock wait deadline, got %v", err)
	}
}

func TestRenewDueUsesIndependentTimeoutPerCertificate(t *testing.T) {
	svc := NewService(t.TempDir(), nil)
	svc.IssueTimeout = 30 * time.Millisecond
	release, err := svc.acquireCertificateLock(context.Background(), "cert_one")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	cfg := config.Snapshot{Certificates: []config.Certificate{
		{ID: "cert_one", Enabled: true, Account: "missing", Zone: "example.com", Domains: []string{"one.example.com"}, RenewDays: 30},
		{ID: "cert_two", Enabled: true, Account: "missing", Zone: "example.com", Domains: []string{"two.example.com"}, RenewDays: 30},
	}}
	report := svc.RenewDue(context.Background(), "0.5.0", cfg)
	if report.OK || len(report.Results) != 2 {
		t.Fatalf("report=%+v", report)
	}
	if !strings.Contains(report.Results[0].Error, "context deadline exceeded") {
		t.Fatalf("first result=%+v", report.Results[0])
	}
	if !strings.Contains(report.Results[1].Error, "DNS account not found") {
		t.Fatalf("second certificate did not receive an independent timeout/context: %+v", report.Results[1])
	}
}

func TestRenewDueRechecksFreshnessAfterWaitingForLock(t *testing.T) {
	home := t.TempDir()
	svc := NewService(home, nil)
	svc.IssueTimeout = time.Second
	called := false
	svc.Provider = func(config.DNSAccount) (dnsprovider.RecordProvider, error) {
		called = true
		return nil, errors.New("provider should not be called")
	}
	cfg := config.Snapshot{Certificates: []config.Certificate{{ID: "cert_race", Enabled: true, Account: "dns", Zone: "example.com", Domains: []string{"test.example.com"}, RenewDays: 30}}}

	release, err := svc.acquireCertificateLock(context.Background(), "cert_race")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan RenewReport, 1)
	go func() { done <- svc.RenewDue(context.Background(), "0.5.0", cfg) }()
	time.Sleep(40 * time.Millisecond)
	certPath, _ := svc.certPaths("cert_race")
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certificatePEM(t, time.Now().Add(90*24*time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	release()

	report := <-done
	if !report.OK || len(report.Results) != 0 || called {
		t.Fatalf("report=%+v called=%v", report, called)
	}
}

func TestRenewalFailureStatusIncludesLastError(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 9, 9, 16, 0, 0, 0, time.UTC)
	svc := NewService(home, nil)
	svc.Now = func() time.Time { return now }
	path, _ := svc.certPaths("cert_due_error")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, certificatePEM(t, now.Add(10*24*time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := svc.writeRenewalAttemptDetail("cert_due_error", false, "DNS provider timeout\nretry later"); err != nil {
		t.Fatal(err)
	}
	cfg := config.Snapshot{Certificates: []config.Certificate{{ID: "cert_due_error", Enabled: true, Domains: []string{"test.example.com"}, RenewDays: 30}}}
	st := svc.Status("0.5.0", cfg).Certificates[0]
	if st.RenewState != "failed" || st.RenewError != "DNS provider timeout\nretry later" {
		t.Fatalf("status=%+v", st)
	}
}

func certificatePairPEM(t *testing.T, commonName string, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestIssuePreservesExistingPairWhenIssuedCertificateMismatches(t *testing.T) {
	home := t.TempDir()
	svc := NewService(home, nil)
	oldCert, oldKey := certificatePairPEM(t, "test.example.com", time.Now().Add(10*24*time.Hour))
	certPath, keyPath := svc.certPaths("cert_test")
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, oldCert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, oldKey, 0600); err != nil {
		t.Fatal(err)
	}

	srv, _ := newACMEMock(t, certificatePEM(t, time.Now().Add(90*24*time.Hour)))
	defer srv.Close()
	svc.HTTP = srv.Client()
	svc.Provider = func(config.DNSAccount) (dnsprovider.RecordProvider, error) { return &fakeProvider{}, nil }
	svc.TXT = &fakeWaiter{}
	svc.Sleep = func(context.Context, time.Duration) error { return nil }
	cfg := testConfig(srv.URL + "/dir")
	svc.DirectoryForEnvironment = func(string) string { return cfg.Main.ACMEDirectory }

	if report, err := svc.Issue(context.Background(), "0.5.0", cfg, cfg.Certificates[0]); err == nil || report.OK {
		t.Fatalf("expected mismatched renewal failure, report=%+v err=%v", report, err)
	}
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCert) != string(oldCert) || string(gotKey) != string(oldKey) {
		t.Fatal("failed renewal modified the previously working certificate pair")
	}
}

func TestPublishCertificatePairRollsBackGeneratedKeyWhenCertificatePublishFails(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := certificatePairPEM(t, "test.example.com", time.Now().Add(90*24*time.Hour))
	keyPath := filepath.Join(dir, "privkey.pem")
	oldKey := []byte("previous-invalid-key\n")
	if err := os.WriteFile(keyPath, oldKey, 0600); err != nil {
		t.Fatal(err)
	}
	// An existing directory cannot be atomically replaced by the temp certificate
	// file, forcing the cert publication step to fail after the new key is staged.
	certPath := filepath.Join(dir, "fullchain.pem")
	if err := os.Mkdir(certPath, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := publishCertificatePair(certPath, keyPath, certPEM, keyPEM, true, []string{"test.example.com"}); err == nil {
		t.Fatal("expected certificate publication failure")
	}
	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(oldKey) {
		t.Fatalf("private key rollback failed: got %q want %q", got, oldKey)
	}
}

func TestIssueFailurePopulatesRenewError(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 9, 9, 16, 30, 0, 0, time.UTC)
	svc := NewService(home, nil)
	svc.Now = func() time.Time { return now }
	cfg := config.Snapshot{Certificates: []config.Certificate{{
		ID: "cert_error", Enabled: true, Account: "dns", Domains: []string{"test.example.com"}, RenewDays: 30,
	}}}
	report, err := svc.Issue(context.Background(), "0.5.0", cfg, cfg.Certificates[0])
	if err == nil || report.OK || !strings.Contains(report.Error, "zone is empty") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	st := svc.Status("0.5.0", cfg).Certificates[0]
	if st.RenewState != "failed" || !strings.Contains(st.RenewError, "zone is empty") || st.LastRenewAt == "" {
		t.Fatalf("status=%+v", st)
	}
}

func TestCanceledLockWaitDoesNotWriteRenewFailure(t *testing.T) {
	home := t.TempDir()
	svc := NewService(home, nil)
	release, err := svc.acquireCertificateLock(context.Background(), "cert_cancel")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := config.Snapshot{Certificates: []config.Certificate{{
		ID: "cert_cancel", Enabled: true, Account: "dns", Zone: "example.com", Domains: []string{"test.example.com"}, RenewDays: 30,
	}}}
	if report, err := svc.Issue(ctx, "0.5.0", cfg, cfg.Certificates[0]); err == nil || report.OK {
		t.Fatalf("expected cancellation, report=%+v err=%v", report, err)
	}
	if _, ok := svc.readRenewalAttempt("cert_cancel"); ok {
		t.Fatal("generation/shutdown cancellation created a false renewal failure state")
	}
}

func TestStatusReportsCertificateIdentityValidity(t *testing.T) {
	home := t.TempDir()
	svc := NewService(home, nil)
	certPath, _ := svc.certPaths("cert_identity")
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := certificatePairPEM(t, "test.example.com", time.Now().Add(90*24*time.Hour))
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	validCfg := config.Snapshot{Certificates: []config.Certificate{{ID: "cert_identity", Enabled: true, Domains: []string{"test.example.com"}, RenewDays: 30}}}
	valid := svc.Status("0.5.0", validCfg).Certificates[0]
	if valid.IdentityValid == nil || !*valid.IdentityValid || valid.IdentityError != "" {
		t.Fatalf("valid identity status=%+v", valid)
	}

	invalidCfg := config.Snapshot{Certificates: []config.Certificate{{ID: "cert_identity", Enabled: true, Domains: []string{"other.example.com"}, RenewDays: 30}}}
	invalid := svc.Status("0.5.0", invalidCfg).Certificates[0]
	if invalid.IdentityValid == nil || *invalid.IdentityValid || !strings.Contains(invalid.IdentityError, "missing DNS identity other.example.com") {
		t.Fatalf("invalid identity status=%+v", invalid)
	}
}

func TestPublishCertificatePairRejectsIdentityMismatchBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	oldCert, oldKey := certificatePairPEM(t, "test.example.com", time.Now().Add(10*24*time.Hour))
	if err := os.WriteFile(certPath, oldCert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, oldKey, 0600); err != nil {
		t.Fatal(err)
	}

	newCert, newKey := certificatePairPEM(t, "wrong.example.com", time.Now().Add(90*24*time.Hour))
	if _, err := publishCertificatePair(certPath, keyPath, newCert, newKey, true, []string{"test.example.com"}); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("error=%v, want identity mismatch", err)
	}
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCert) != string(oldCert) || string(gotKey) != string(oldKey) {
		t.Fatal("identity mismatch modified previous certificate pair")
	}
}

func TestLocalCertificateIsNeverACMERenewed(t *testing.T) {
	svc := NewService(t.TempDir(), nil)
	local := config.Certificate{ID: "cert_local", Enabled: true, Source: "local", Domains: []string{"local.example.com"}, RenewDays: 30}
	if svc.NeedsRenew(local) {
		t.Fatal("local certificate must never enter ACME renewal")
	}
	cfg := config.Snapshot{Certificates: []config.Certificate{local}}
	status := svc.Status("0.5.0", cfg)
	if len(status.Certificates) != 1 || status.Certificates[0].Source != "local" || status.Certificates[0].Renew {
		t.Fatalf("status=%+v", status.Certificates)
	}
	report := svc.RenewDue(context.Background(), "0.5.0", cfg)
	if !report.OK || len(report.Results) != 0 {
		t.Fatalf("renew report=%+v", report)
	}
	if _, err := svc.Issue(context.Background(), "0.5.0", cfg, local); err == nil || !strings.Contains(err.Error(), "not ACME-managed") {
		t.Fatalf("issue err=%v", err)
	}
}

func TestPublicTXTWaiterTimeoutIsPropagationPending(t *testing.T) {
	w := PublicTXTWaiter{Timeout: time.Nanosecond, Poll: time.Nanosecond}
	err := w.Wait(context.Background(), "_acme-challenge.example.invalid", "value")
	if err == nil {
		t.Fatal("expected propagation error")
	}
	kind, retryable, _ := dnsprovider.ErrorDetails(err)
	if kind != dnsprovider.ErrorPropagationPending || !retryable {
		t.Fatalf("kind=%s retryable=%v err=%v", kind, retryable, err)
	}
}

func TestIssueErrorCarriesProviderTaxonomy(t *testing.T) {
	err := fmt.Errorf("create ACME TXT: %w", dnsprovider.NewError("aliyun", "records.create", dnsprovider.ErrorAuthentication, "SignatureDoesNotMatch", "bad signature", false, nil))
	r := issueError("0.5.0", "cert_test", []string{"example.com"}, err)
	if r.ErrorKind != "authentication" || r.Retryable || r.ProviderCode != "SignatureDoesNotMatch" {
		t.Fatalf("report=%+v", r)
	}
}

func TestIssueStaleGenerationDoesNotPublishCertificate(t *testing.T) {
	srv, _ := newCSRSigningACMEMock(t, time.Now().Add(90*24*time.Hour))
	defer srv.Close()
	provider := &fakeProvider{}
	waiter := &fakeWaiter{}
	home := t.TempDir()
	svc := NewService(home, nil)
	svc.HTTP = srv.Client()
	svc.Provider = func(config.DNSAccount) (dnsprovider.RecordProvider, error) { return provider, nil }
	svc.TXT = waiter
	svc.Sleep = func(context.Context, time.Duration) error { return nil }
	svc.Commit = func(fn func() error) (bool, error) {
		return false, nil
	}
	cfg := testConfig(srv.URL + "/dir")
	svc.DirectoryForEnvironment = func(string) string { return cfg.Main.ACMEDirectory }

	report, err := svc.Issue(context.Background(), "0.5.0", cfg, cfg.Certificates[0])
	if !errors.Is(err, context.Canceled) || report.OK {
		t.Fatalf("report=%+v err=%v, want stale context cancellation", report, err)
	}
	certPath, keyPath := svc.certPaths("cert_test")
	if _, statErr := os.Stat(certPath); !os.IsNotExist(statErr) {
		t.Fatalf("stale generation published certificate: %v", statErr)
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("stale generation published key: %v", statErr)
	}
	if len(provider.upserts) != 1 || len(provider.deletes) != 1 {
		t.Fatalf("DNS cleanup lost for stale generation: upserts=%v deletes=%v", provider.upserts, provider.deletes)
	}
	if _, statErr := os.Stat(svc.renewalAttemptPath("cert_test")); !os.IsNotExist(statErr) {
		t.Fatalf("stale generation published renewal status: %v", statErr)
	}
}

func TestIssueErrorClassifiesNetworkFailureAsRetryable(t *testing.T) {
	err := &net.DNSError{Err: "network unreachable", Name: "acme.example"}
	r := issueError("0.5.0", "cert1", []string{"example.com"}, err)
	if r.ErrorKind != string(dnsprovider.ErrorNetworkUnavailable) || !r.Retryable {
		t.Fatalf("report=%+v", r)
	}
}
