package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"homegate.local/homegate/internal/access"
	"homegate.local/homegate/internal/certstore"
	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/logger"
)

func writeTestTLSPair(t testing.TB, dir string, pair tls.Certificate) {
	t.Helper()
	if len(pair.Certificate) == 0 || pair.PrivateKey == nil {
		t.Fatal("test TLS pair missing")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func atomicReplaceTestFile(t testing.TB, path string, data []byte, mode os.FileMode) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func webConfig(target string) config.Snapshot {
	return config.Snapshot{Configured: true, Main: config.Main{ProxyHTTPSPort: 10443, ProxyHTTPPort: 10080}, Certificates: []config.Certificate{{ID: "cert1", Enabled: true, Domains: []string{"test.example.com"}}}, Web: []config.WebRule{{ID: "web1", Enabled: true, Domain: "test.example.com", Target: target, HTTPS: true, Certificate: "cert1"}}}
}

func TestCertMatchesWildcard(t *testing.T) {
	if !certstore.MatchesPattern("a.example.com", "*.example.com") {
		t.Fatal("expected wildcard match")
	}
	if certstore.MatchesPattern("a.b.example.com", "*.example.com") {
		t.Fatal("wildcard matched multiple labels")
	}
}

func TestHandlerSNIHostReverseProxy(t *testing.T) {
	var expectedHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != expectedHost {
			t.Errorf("backend host=%q want=%q", r.Host, expectedHost)
		}
		if r.Header.Get("X-Forwarded-Host") != "test.example.com" {
			t.Errorf("xfh=%q", r.Header.Get("X-Forwarded-Host"))
		}
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("xfp=%q", r.Header.Get("X-Forwarded-Proto"))
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	expectedHost = strings.TrimPrefix(backend.URL, "http://")
	cfg := webConfig(backend.URL)
	routes, err := buildRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := New(t.TempDir(), nil, "0.5.0")
	m.routes = routes
	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/hello", nil)
	req.Host = "test.example.com"
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != 200 || rr.Body.String() != "ok" {
		t.Fatalf("code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestHandlerRedirectsHTTPToHTTPSForHTTPSRule(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("backend should not be called") }))
	defer backend.Close()
	routes, err := buildRoutes(webConfig(backend.URL))
	if err != nil {
		t.Fatal(err)
	}
	m := New(t.TempDir(), nil, "0.5.0")
	m.routes = routes
	m.publicHTTPSPort = 443
	req := httptest.NewRequest(http.MethodGet, "http://test.example.com/a/b?q=1", nil)
	req.Host = "test.example.com"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("code=%d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://test.example.com/a/b?q=1" {
		t.Fatalf("location=%q", got)
	}
}

func TestHandlerRedirectUsesConfiguredHTTPSPort(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("backend should not be called") }))
	defer backend.Close()
	routes, err := buildRoutes(webConfig(backend.URL))
	if err != nil {
		t.Fatal(err)
	}
	m := New(t.TempDir(), nil, "0.5.0")
	m.routes = routes
	m.publicHTTPSPort = 8443
	req := httptest.NewRequest(http.MethodGet, "http://test.example.com/hello", nil)
	req.Host = "test.example.com"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("code=%d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://test.example.com:8443/hello" {
		t.Fatalf("location=%q", got)
	}
}

func TestBuildStatusInvalidTarget(t *testing.T) {
	cfg := webConfig("not-a-url")
	st := BuildStatus("0.5.0", cfg)
	if st.OK || st.Error == "" {
		t.Fatalf("status=%+v", st)
	}
}

func TestHTTPSRuleStartsHTTPRedirectListener(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer backend.Close()
	httpsReserve, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	httpsPort := httpsReserve.Addr().(*net.TCPAddr).Port
	httpsReserve.Close()
	httpReserve, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := httpReserve.Addr().(*net.TCPAddr).Port
	httpReserve.Close()
	cfg := webConfig(backend.URL)
	cfg.Main.ProxyHTTPSPort = httpsPort
	cfg.Main.ProxyHTTPPort = httpPort
	m := New(t.TempDir(), nil, "0.5.0")
	m.StatusPath = t.TempDir() + "/proxy.json"
	st, err := m.Apply(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	if !st.HTTPSListening || !st.HTTPListening || st.HTTPSPort != httpsPort || st.HTTPPort != httpPort {
		t.Fatalf("status=%+v", st)
	}
}

func TestHTTPPortReloadFailureKeepsOldListener(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer backend.Close()
	reserve, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	oldPort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	cfg := config.Snapshot{Configured: true, Main: config.Main{ProxyHTTPPort: oldPort}, Web: []config.WebRule{{ID: "web1", Enabled: true, Domain: "test.example.com", Target: backend.URL, HTTPS: false}}}
	m := New(t.TempDir(), nil, "0.5.0")
	m.StatusPath = t.TempDir() + "/proxy.json"
	if st, err := m.Apply(context.Background(), cfg); err != nil || !st.HTTPListening || st.HTTPPort != oldPort {
		t.Fatalf("apply st=%+v err=%v", st, err)
	}
	defer m.Close(context.Background())

	blocker, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blockedPort := blocker.Addr().(*net.TCPAddr).Port
	cfg.Main.ProxyHTTPPort = blockedPort
	st, err := m.Apply(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected occupied-port reload failure")
	}
	if !st.HTTPListening || st.HTTPPort != oldPort {
		t.Fatalf("last-good listener not preserved: %+v", st)
	}
}

func TestReloadFailureKeepsOldRouteAndAccessPolicy(t *testing.T) {
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "A") }))
	defer backendA.Close()
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "B") }))
	defer backendB.Close()

	reserve, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	oldPort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()

	t.Setenv("HOMEGATE_ACCESS_RECENT", filepath.Join(t.TempDir(), "access.json"))
	oldCfg := config.Snapshot{
		Configured: true,
		Main: config.Main{
			ProxyHTTPPort: oldPort,
			AccessEnabled: true,
			AccessAllow:   "192.0.2.55/32",
		},
		Web: []config.WebRule{{ID: "web1", Enabled: true, Domain: "test.example.com", Target: backendA.URL, HTTPS: false}},
	}
	m := New(t.TempDir(), nil, "0.5.0")
	m.StatusPath = filepath.Join(t.TempDir(), "proxy.json")
	if _, err := m.Apply(context.Background(), oldCfg); err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())

	blocker, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blockedPort := blocker.Addr().(*net.TCPAddr).Port

	candidate := oldCfg
	candidate.Main.ProxyHTTPPort = blockedPort
	candidate.Main.AccessAllow = ""
	candidate.Main.AccessDeny = "192.0.2.55/32"
	candidate.Web = []config.WebRule{{ID: "web1", Enabled: true, Domain: "test.example.com", Target: backendB.URL, HTTPS: false}}
	st, err := m.Apply(context.Background(), candidate)
	if err == nil {
		t.Fatal("expected occupied-port reload failure")
	}
	if !st.HTTPListening || st.HTTPPort != oldPort || st.Error == "" {
		t.Fatalf("failed reload status=%+v", st)
	}

	req := httptest.NewRequest(http.MethodGet, "http://test.example.com/", nil)
	req.Host = "test.example.com"
	req.RemoteAddr = "192.0.2.55:12345"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "A" {
		t.Fatalf("failed reload polluted runtime: code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestStaleGenerationCannotOverwriteAccessPolicy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	reserve, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()

	t.Setenv("HOMEGATE_ACCESS_RECENT", filepath.Join(t.TempDir(), "access.json"))
	cfg := config.Snapshot{
		Configured: true,
		Main:       config.Main{ProxyHTTPPort: port, AccessEnabled: true, AccessAllow: "192.0.2.55/32"},
		Web:        []config.WebRule{{ID: "web1", Enabled: true, Domain: "test.example.com", Target: backend.URL, HTTPS: false}},
	}
	m := New(t.TempDir(), nil, "0.5.0")
	m.StatusPath = filepath.Join(t.TempDir(), "proxy.json")
	if _, err := m.ApplyGeneration(context.Background(), cfg, 2); err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())

	stale := cfg.Main
	stale.AccessAllow = ""
	stale.AccessDeny = "192.0.2.55/32"
	committed, err := m.RefreshAccessPolicyGeneration(stale, 1)
	if err != nil {
		t.Fatal(err)
	}
	if committed {
		t.Fatal("stale generation unexpectedly committed")
	}

	req := httptest.NewRequest(http.MethodGet, "http://test.example.com/", nil)
	req.Host = "test.example.com"
	req.RemoteAddr = "192.0.2.55:12345"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Fatalf("stale policy overwrote current generation: code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestGetCertificateLoadsR6CompatiblePaths(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ts.Close()
	home := t.TempDir()
	dir := filepath.Join(home, "certs", "cert1")
	writeTestTLSPair(t, dir, ts.TLS.Certificates[0])
	m := New(home, nil, "0.5.0")
	routes, err := buildRoutes(webConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	m.routes = routes
	got, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "test.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Certificate) == 0 {
		t.Fatal("certificate not loaded")
	}
}

func TestGetCertificateCachesUnchangedPair(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ts.Close()
	home := t.TempDir()
	dir := filepath.Join(home, "certs", "cert1")
	writeTestTLSPair(t, dir, ts.TLS.Certificates[0])
	m := New(home, nil, "0.5.0")
	routes, err := buildRoutes(webConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	m.routes = routes
	first, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "test.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "test.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("unchanged certificate was reparsed instead of using cache")
	}
}

func TestGetCertificateReloadsAfterAtomicRotation(t *testing.T) {
	firstServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer firstServer.Close()
	secondServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer secondServer.Close()
	home := t.TempDir()
	dir := filepath.Join(home, "certs", "cert1")
	writeTestTLSPair(t, dir, firstServer.TLS.Certificates[0])
	m := New(home, nil, "0.5.0")
	routes, err := buildRoutes(webConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	m.routes = routes
	first, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "test.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	pair := secondServer.TLS.Certificates[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	atomicReplaceTestFile(t, filepath.Join(dir, "privkey.pem"), keyPEM, 0o600)
	atomicReplaceTestFile(t, filepath.Join(dir, "fullchain.pem"), certPEM, 0o600)

	second, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "test.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("rotated certificate reused stale cache entry")
	}
	if len(second.Certificate) == 0 || string(second.Certificate[0]) != string(pair.Certificate[0]) {
		t.Fatal("rotated certificate was not loaded")
	}
}

func TestDeniedLogMapIsBounded(t *testing.T) {
	log := logger.New("error", filepath.Join(t.TempDir(), "homegate.log"), 64)
	m := New(t.TempDir(), log, "0.5.0")
	for i := 0; i < denyLogMaxEntries+500; i++ {
		m.logAccessDenied(fmt.Sprintf("2001:db8::%x", i), "vault.example.com", "denied")
	}
	m.mu.RLock()
	n := len(m.denyLogged)
	m.mu.RUnlock()
	if n > denyLogMaxEntries {
		t.Fatalf("deny log throttle map grew to %d entries, max=%d", n, denyLogMaxEntries)
	}
}

func TestHandlerAccessRestrictionManualAllow(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "allowed") }))
	defer backend.Close()
	cfg := webConfig(backend.URL)
	routes, err := buildRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := New(t.TempDir(), nil, "0.5.0")
	m.routes = routes
	m.accessPolicy = &access.Policy{Enabled: true, Manual: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	m.accessRecorder = access.NewRecorder(filepath.Join(t.TempDir(), "access.json"))
	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/", nil)
	req.Host = "test.example.com"
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = "192.0.2.55:12345"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "allowed" {
		t.Fatalf("code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestHandlerAccessRestrictionDenied(t *testing.T) {
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer backend.Close()
	cfg := webConfig(backend.URL)
	routes, err := buildRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := New(t.TempDir(), nil, "0.5.0")
	m.routes = routes
	m.accessPolicy = &access.Policy{Enabled: true, Manual: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	m.accessRecorder = access.NewRecorder(filepath.Join(t.TempDir(), "access.json"))
	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/", nil)
	req.Host = "test.example.com"
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = "203.0.113.55:12345"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%q", rr.Code, rr.Body.String())
	}
	if called {
		t.Fatal("backend should not be called for denied source")
	}
}

func TestHandlerAccessRestrictionAllowedThenHTTPRedirect(t *testing.T) {
	cfg := webConfig("http://127.0.0.1:1")
	routes, err := buildRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recent := filepath.Join(t.TempDir(), "access.json")
	m := New(t.TempDir(), nil, "0.5.0")
	m.routes = routes
	m.publicHTTPSPort = 443
	m.accessPolicy = &access.Policy{Enabled: true, Manual: []netip.Prefix{netip.MustParsePrefix("192.0.2.55/32")}}
	m.accessRecorder = access.NewRecorder(recent)
	req := httptest.NewRequest(http.MethodGet, "http://test.example.com/a?q=1", nil)
	req.Host = "test.example.com"
	req.RemoteAddr = "192.0.2.55:12345"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusPermanentRedirect || rr.Header().Get("Location") != "https://test.example.com/a?q=1" {
		t.Fatalf("code=%d location=%q", rr.Code, rr.Header().Get("Location"))
	}
	report := access.ReadRecent(recent)
	if !report.OK || len(report.Entries) != 1 || !report.Entries[0].Allowed || report.Entries[0].Reason != "ip" {
		t.Fatalf("recent=%+v", report)
	}
}

func TestHandlerAccessRestrictionDeniedBeforeHTTPRedirect(t *testing.T) {
	cfg := webConfig("http://127.0.0.1:1")
	routes, err := buildRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := New(t.TempDir(), nil, "0.5.0")
	m.routes = routes
	m.publicHTTPSPort = 443
	m.accessPolicy = &access.Policy{Enabled: true, Manual: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	req := httptest.NewRequest(http.MethodGet, "http://test.example.com/a?q=1", nil)
	req.Host = "test.example.com"
	req.TLS = nil
	req.RemoteAddr = "203.0.113.55:12345"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d location=%q", rr.Code, rr.Header().Get("Location"))
	}
	if rr.Header().Get("Location") != "" {
		t.Fatalf("denied client must not receive HTTPS redirect: %q", rr.Header().Get("Location"))
	}
}

func TestHandlerManualDenyOverridesNoRestriction(t *testing.T) {
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer backend.Close()
	routes, err := buildRoutes(webConfig(backend.URL))
	if err != nil {
		t.Fatal(err)
	}
	recent := filepath.Join(t.TempDir(), "access.json")
	m := New(t.TempDir(), nil, "0.5.0")
	m.routes = routes
	m.accessPolicy = &access.Policy{Enabled: false, Deny: []netip.Prefix{netip.MustParsePrefix("2001:db8::7/128")}}
	m.accessRecorder = access.NewRecorder(recent)
	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/", nil)
	req.Host = "test.example.com"
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = "[2001:db8::7]:12345"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%q", rr.Code, rr.Body.String())
	}
	if called {
		t.Fatal("backend should not be called for explicit deny in no-restriction mode")
	}
	report := access.ReadRecent(recent)
	if !report.OK || len(report.Entries) != 1 || report.Entries[0].Allowed || report.Entries[0].Reason != "manual-deny" {
		t.Fatalf("recent=%+v", report)
	}
}

func TestAccessGeoResolverBuildsAsyncAndBackfillsRecorder(t *testing.T) {
	home := t.TempDir()
	regions := filepath.Join(home, "access", "regions")
	if err := os.MkdirAll(regions, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regions, "CN.cidr"), []byte("203.0.113.0/24\n2001:db8::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regions, "CN-GD.cidr"), []byte("203.0.113.0/25\n2001:db8::/48\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	recent := filepath.Join(t.TempDir(), "access.json")
	r := access.NewRecorder(recent)
	r.Record("203.0.113.10", "vault.example.com", access.Decision{Allowed: true, Reason: "disabled", PolicyMode: "disabled"})
	m := New(home, nil, "0.5.0")
	m.accessRecorder = r
	m.ensureAccessGeoAsync(r)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		report := access.ReadRecent(recent)
		if report.OK && len(report.Entries) == 1 && report.Entries[0].Geo == "CN-GD" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("geo backfill did not complete: %+v", access.ReadRecent(recent))
}

func TestBuildRoutesCertificateSelectionPrefersExactOverWildcard(t *testing.T) {
	cfg := config.Snapshot{
		Main: config.Main{ProxyHTTPSPort: 10443, ProxyHTTPPort: 10080},
		Certificates: []config.Certificate{
			{ID: "wild", Enabled: true, Domains: []string{"*.chenos.cn"}},
			{ID: "exact", Enabled: true, Domains: []string{"vault.chenos.cn"}},
		},
		Web: []config.WebRule{{ID: "web1", Enabled: true, Domain: "vault.chenos.cn", Target: "http://127.0.0.1:9", HTTPS: true}},
	}
	routes, err := buildRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := routes["vault.chenos.cn"].CertID; got != "exact" {
		t.Fatalf("selected certificate %q, want exact", got)
	}
}

func TestBuildRoutesRejectsInvalidExplicitCertificateReference(t *testing.T) {
	base := config.Snapshot{
		Main: config.Main{ProxyHTTPSPort: 10443, ProxyHTTPPort: 10080},
		Certificates: []config.Certificate{
			{ID: "disabled", Enabled: false, Domains: []string{"vault.chenos.cn"}},
			{ID: "other", Enabled: true, Domains: []string{"home.chenos.cn"}},
		},
	}
	cases := []struct {
		name string
		id   string
		want string
	}{
		{name: "missing", id: "missing", want: "was not found"},
		{name: "disabled", id: "disabled", want: "is disabled"},
		{name: "uncovered", id: "other", want: "does not cover vault.chenos.cn"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Web = []config.WebRule{{ID: "web1", Enabled: true, Domain: "vault.chenos.cn", Target: "http://127.0.0.1:9", HTTPS: true, Certificate: tc.id}}
			if _, err := buildRoutes(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("buildRoutes error=%v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestBuildRoutesRejectsAmbiguousEnabledCertificatePattern(t *testing.T) {
	cfg := config.Snapshot{
		Main: config.Main{ProxyHTTPSPort: 10443, ProxyHTTPPort: 10080},
		Certificates: []config.Certificate{
			{ID: "one", Enabled: true, Domains: []string{"*.chenos.cn"}},
			{ID: "two", Enabled: true, Domains: []string{"*.CHENOS.cn."}},
		},
		Web: []config.WebRule{{ID: "web1", Enabled: true, Domain: "vault.chenos.cn", Target: "http://127.0.0.1:9", HTTPS: true}},
	}
	if _, err := buildRoutes(cfg); err == nil || !strings.Contains(err.Error(), "is duplicated") {
		t.Fatalf("buildRoutes error=%v, want duplicate certificate pattern rejection", err)
	}
}

func TestRepeatedSameConfigReusesListeners(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()

	reserve, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()

	t.Setenv("HOMEGATE_ACCESS_RECENT", filepath.Join(t.TempDir(), "access.json"))
	cfg := config.Snapshot{
		Configured: true,
		Main: config.Main{
			ProxyHTTPPort: port,
			AccessEnabled: false,
		},
		Web: []config.WebRule{{ID: "web1", Enabled: true, Domain: "test.example.com", Target: backend.URL, HTTPS: false}},
	}

	m := New(t.TempDir(), nil, "0.5.0")
	m.StatusPath = filepath.Join(t.TempDir(), "proxy.json")
	if _, err := m.ApplyGeneration(context.Background(), cfg, 1); err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())

	m.mu.RLock()
	firstListener := m.httpListener
	firstServer := m.httpServer
	m.mu.RUnlock()
	if firstListener == nil || firstServer == nil {
		t.Fatal("first apply did not create HTTP listener")
	}

	if _, err := m.ApplyGeneration(context.Background(), cfg, 2); err != nil {
		t.Fatal(err)
	}

	m.mu.RLock()
	secondListener := m.httpListener
	secondServer := m.httpServer
	generation := m.runtimeGeneration
	m.mu.RUnlock()

	if secondListener != firstListener || secondServer != firstServer {
		t.Fatal("identical reconcile replaced an unchanged listener")
	}
	if generation != 2 {
		t.Fatalf("runtime generation=%d want=2", generation)
	}

	req := httptest.NewRequest(http.MethodGet, "http://test.example.com/", nil)
	req.Host = "test.example.com"
	rr := httptest.NewRecorder()
	m.handler(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Fatalf("repeated reconcile changed route behavior: code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestUnexpectedListenerFailurePublishesAndCanRecover(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()

	reserve, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()

	t.Setenv("HOMEGATE_ACCESS_RECENT", filepath.Join(t.TempDir(), "access.json"))
	cfg := config.Snapshot{
		Configured: true,
		Main:       config.Main{ProxyHTTPPort: port, AccessEnabled: false},
		Web:        []config.WebRule{{ID: "web1", Enabled: true, Domain: "test.example.com", Target: backend.URL, HTTPS: false}},
	}

	m := New(t.TempDir(), nil, "0.5.0")
	m.StatusPath = filepath.Join(t.TempDir(), "proxy.json")
	if _, err := m.ApplyGeneration(context.Background(), cfg, 1); err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())

	m.mu.RLock()
	failedListener := m.httpListener
	m.mu.RUnlock()
	if failedListener == nil {
		t.Fatal("HTTP listener was not created")
	}
	if err := failedListener.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case failure := <-m.Failures():
		if failure.Protocol != "http" || failure.Port != port || failure.Err == nil {
			t.Fatalf("unexpected failure: %+v", failure)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unexpected listener failure was not published")
	}

	failed, err := ReadStatus(m.StatusPath, "0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if failed.OK || failed.HTTPListening || failed.HTTPPort != 0 || failed.Error == "" {
		t.Fatalf("failed listener status not fail-closed: %+v", failed)
	}

	if _, err := m.ApplyGeneration(context.Background(), cfg, 1); err != nil {
		t.Fatalf("reconcile after listener failure: %v", err)
	}
	m.mu.RLock()
	recoveredListener := m.httpListener
	m.mu.RUnlock()
	if recoveredListener == nil || recoveredListener == failedListener {
		t.Fatal("listener was not rebound after unexpected failure")
	}

	recovered, err := ReadStatus(m.StatusPath, "0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.OK || !recovered.HTTPListening || recovered.HTTPPort != port || recovered.Error != "" {
		t.Fatalf("recovered listener status invalid: %+v", recovered)
	}
}
