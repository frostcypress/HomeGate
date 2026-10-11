package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"homegate.local/homegate/internal/config"
)

func TestNormalizeAllowDualStack(t *testing.T) {
	got, err := NormalizeAllow("192.0.2.7, 2001:db8::1; 192.0.2.0/24 2001:db8:1::/48")
	if err != nil {
		t.Fatal(err)
	}
	want := "192.0.2.0/24, 192.0.2.7, 2001:db8:1::/48, 2001:db8::1"
	if got != want {
		t.Fatalf("normalize=%q want=%q", got, want)
	}
}

func TestNormalizeAllowRejectsInvalid(t *testing.T) {
	if _, err := NormalizeAllow("192.0.2.1, not-an-ip"); err == nil {
		t.Fatal("expected invalid IP/CIDR error")
	}
}

func TestPolicyManualAndUnknownDeny(t *testing.T) {
	prefixes, err := ParseAllow("192.0.2.0/24, 2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Enabled: true, Manual: prefixes}
	if d := p.Evaluate(netip.MustParseAddr("192.0.2.99")); !d.Allowed || d.Reason != "ip" {
		t.Fatalf("manual v4 decision=%+v", d)
	}
	if d := p.Evaluate(netip.MustParseAddr("2001:db8::99")); !d.Allowed || d.Reason != "ip" {
		t.Fatalf("manual v6 decision=%+v", d)
	}
	if d := p.Evaluate(netip.MustParseAddr("203.0.113.1")); d.Allowed || d.Reason != "denied" {
		t.Fatalf("unknown decision=%+v", d)
	}
}

func TestLoadPolicyRegionDualStack(t *testing.T) {
	home := t.TempDir()
	path := cachePath(home, "CN-GD")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("192.0.2.0/24\n2001:db8::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(netip.MustParseAddr("192.0.2.7")); !d.Allowed || d.Reason != "region" || d.Region != "China / Guangdong" {
		t.Fatalf("v4 region decision=%+v", d)
	}
	if d := p.Evaluate(netip.MustParseAddr("2001:db8::7")); !d.Allowed || d.Reason != "region" {
		t.Fatalf("v6 region decision=%+v", d)
	}
	if d := p.Evaluate(netip.MustParseAddr("203.0.113.7")); d.Allowed {
		t.Fatalf("unexpected allow=%+v", d)
	}
}

func TestLoadPolicyRequiresDualStackRegion(t *testing.T) {
	home := t.TempDir()
	path := cachePath(home, "CN-GD")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(configMain(true, "", "CN-GD"), home); err == nil {
		t.Fatal("expected dual-stack validation failure")
	}
}

func TestDisabledPolicyNeedsNoRegionCache(t *testing.T) {
	p, err := LoadPolicy(configMain(false, "", "CN-GD"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(netip.MustParseAddr("203.0.113.9")); !d.Allowed || d.Reason != "disabled" {
		t.Fatalf("disabled decision=%+v", d)
	}
}

func TestClientAddr(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.3:4567", "192.0.2.3"},
		{"[2001:db8::3]:4567", "2001:db8::3"},
		{"fe80::1%eth0", "fe80::1"},
		{"[::ffff:192.0.2.9]:443", "192.0.2.9"},
	} {
		got, err := ClientAddr(tc.in)
		if err != nil || got.String() != tc.want {
			t.Fatalf("ClientAddr(%q)=%v,%v want=%s", tc.in, got, err, tc.want)
		}
	}
}

func TestGuangdongMobileIPv6RepresentativeRange(t *testing.T) {
	p := &Policy{Enabled: true, RegionLabel: "China / Guangdong", Region: []netip.Prefix{netip.MustParsePrefix("2409:8a55:4000::/34")}}
	if d := p.Evaluate(netip.MustParseAddr("2409:8a55:4f0c:353:7d9e:dab6:918d:f902")); !d.Allowed || d.Reason != "region" {
		t.Fatalf("guangdong mobile IPv6 decision=%+v", d)
	}
}

func TestPrefixMatcherBoundariesDualStack(t *testing.T) {
	m := newPrefixMatcher([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/25"),
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("2001:db8::/127"),
	})
	for _, raw := range []string{"192.0.2.0", "192.0.2.255", "2001:db8::", "2001:db8::1"} {
		if !m.Contains(netip.MustParseAddr(raw)) {
			t.Fatalf("expected matcher to contain %s", raw)
		}
	}
	for _, raw := range []string{"192.0.3.0", "2001:db8::2"} {
		if m.Contains(netip.MustParseAddr(raw)) {
			t.Fatalf("expected matcher to reject %s", raw)
		}
	}
	if len(m.v4) != 1 {
		t.Fatalf("adjacent IPv4 prefixes should merge, intervals=%d", len(m.v4))
	}
}

func TestLoadPolicyUsesMatcherWithoutKeepingRegionPrefixCopy(t *testing.T) {
	home := t.TempDir()
	path := cachePath(home, "CN-GD")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("192.0.2.0/24\n2001:db8::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	if p.RegionCount != 2 || len(p.Region) != 0 || p.regionMatcher == nil {
		t.Fatalf("policy region_count=%d retained=%d matcher_nil=%t", p.RegionCount, len(p.Region), p.regionMatcher == nil)
	}
	st := BuildStatus(configMain(true, "", "CN-GD"), home)
	if !st.OK || st.RegionPrefixes != 2 {
		t.Fatalf("status=%+v", st)
	}
}

func withRegionTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	oldSources := accessRegionSourceURLs
	oldClient := accessRegionHTTPClient
	accessRegionSourceURLs = func(string) []string { return []string{server.URL + "/region.cidr"} }
	accessRegionHTTPClient = func() *http.Client { return server.Client() }
	t.Cleanup(func() {
		accessRegionSourceURLs = oldSources
		accessRegionHTTPClient = oldClient
		server.Close()
	})
	return server
}

func writeTestRegionCache(t *testing.T, home, key, body string, age time.Duration) string {
	t.Helper()
	path := cachePath(home, key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRegionPlusExactIPv6Exception(t *testing.T) {
	home := t.TempDir()
	writeTestRegionCache(t, home, "CN-GD", "192.0.2.0/24\n2001:db8::/32\n", time.Hour)
	mobile := "2409:895b:4e0e:33f2:d93b:986:444d:e32b"
	p, err := LoadPolicy(configMain(true, mobile+"/128", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(netip.MustParseAddr(mobile)); !d.Allowed || d.Reason != "ip" {
		t.Fatalf("exact exception decision=%+v", d)
	}
	if d := p.Evaluate(netip.MustParseAddr("2001:db8::7")); !d.Allowed || d.Reason != "region" {
		t.Fatalf("region decision=%+v", d)
	}
	if d := p.Evaluate(netip.MustParseAddr("2001:db9::7")); d.Allowed || d.Reason != "denied" {
		t.Fatalf("outside decision=%+v", d)
	}
}

func TestManualOnlyModeEmptyFailClosed(t *testing.T) {
	p, err := LoadPolicy(configMain(true, "", ""), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode() != "manual" || !p.Enabled || len(p.Manual) != 0 {
		t.Fatalf("policy=%+v", p)
	}
	for _, raw := range []string{"192.0.2.7", "2001:db8::7"} {
		d := p.Evaluate(netip.MustParseAddr(raw))
		if d.Allowed || d.Reason != "denied" || d.PolicyMode != "manual" {
			t.Fatalf("empty-manual %s decision=%+v", raw, d)
		}
	}
}

func TestManualOnlyModeDualStack(t *testing.T) {
	p, err := LoadPolicy(configMain(true, "192.0.2.7/32, 2001:db8::7/128", ""), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"192.0.2.7", "2001:db8::7"} {
		if d := p.Evaluate(netip.MustParseAddr(raw)); !d.Allowed || d.Reason != "ip" {
			t.Fatalf("manual %s decision=%+v", raw, d)
		}
	}
	if d := p.Evaluate(netip.MustParseAddr("192.0.2.8")); d.Allowed {
		t.Fatalf("unexpected manual-only allow=%+v", d)
	}
}

func TestUpdateRegionFreshCacheSkipsNetwork(t *testing.T) {
	var hits atomic.Int32
	withRegionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "should not be called", http.StatusServiceUnavailable)
	})
	home := t.TempDir()
	writeTestRegionCache(t, home, "CN", "192.0.2.0/24\n2001:db8::/32\n", time.Hour)
	report, err := UpdateRegion(context.Background(), home, "CN")
	if err != nil || !report.OK || report.Source != "cache" || report.IPv4 != 1 || report.IPv6 != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if hits.Load() != 0 {
		t.Fatalf("fresh cache unexpectedly hit upstream %d times", hits.Load())
	}
}

func TestUpdateRegionFirstDownloadFailureHasNoFallback(t *testing.T) {
	withRegionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	})
	home := t.TempDir()
	report, err := UpdateRegion(context.Background(), home, "CN")
	if err == nil || report.OK || report.Source != "" || report.Error == "" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if _, statErr := os.Stat(cachePath(home, "CN")); !os.IsNotExist(statErr) {
		t.Fatalf("failed first download must not create cache, stat=%v", statErr)
	}
}

func TestUpdateRegionStaleCacheFallbackSucceeds(t *testing.T) {
	withRegionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	})
	home := t.TempDir()
	path := writeTestRegionCache(t, home, "CN", "192.0.2.0/24\n2001:db8::/32\n", regionRefreshAge+time.Hour)
	before, _ := os.ReadFile(path)
	report, err := UpdateRegion(context.Background(), home, "CN")
	if err != nil || !report.OK || report.Source != "stale-cache" || report.Warning == "" || report.IPv4 != 1 || report.IPv6 != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("stale fallback must preserve last validated cache bytes")
	}
}

func TestRefreshRegionStaleCacheFallbackReportsFailureButPreservesCache(t *testing.T) {
	withRegionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	})
	home := t.TempDir()
	path := writeTestRegionCache(t, home, "CN", "192.0.2.0/24\n2001:db8::/32\n", time.Hour)
	before, _ := os.ReadFile(path)
	report, err := RefreshRegion(context.Background(), home, "CN")
	if err == nil || !report.OK || report.Source != "stale-cache" || report.Warning == "" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("forced refresh fallback must preserve last validated cache bytes")
	}
}

func TestRefreshRegionRejectsSingleStackAndKeepsValidatedCache(t *testing.T) {
	withRegionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("2|apnic|20261009|1|19830613|20261008|+1000\napnic|*|ipv4|*|1|summary\napnic|CN|ipv4|198.51.100.0|256|20261008|allocated\n"))
	})
	home := t.TempDir()
	path := writeTestRegionCache(t, home, "CN", "192.0.2.0/24\n2001:db8::/32\n", time.Hour)
	before, _ := os.ReadFile(path)
	report, err := RefreshRegion(context.Background(), home, "CN")
	if err == nil || report.Source != "stale-cache" || !strings.Contains(report.Warning, "dual-stack") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("invalid single-stack refresh must not replace validated cache")
	}
}

func TestRefreshRegionSuccessfulAtomicReplacement(t *testing.T) {
	server := withRegionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(delegatedFixture))
	})
	home := t.TempDir()
	path := writeTestRegionCache(t, home, "CN", "192.0.2.0/24\n2001:db8::/32\n", regionRefreshAge+time.Hour)
	report, err := RefreshRegion(context.Background(), home, "CN")
	if err != nil || !report.OK || report.Source != server.URL+"/region.cidr" || report.Warning != "" || report.IPv4 != 1 || report.IPv6 != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	prefixes, v4, v6, err := readPrefixFile(path)
	if err != nil || v4 != 1 || v6 != 1 || len(prefixes) != 2 {
		t.Fatalf("cache prefixes=%v v4=%d v6=%d err=%v", prefixes, v4, v6, err)
	}
	joined := prefixes[0].String() + " " + prefixes[1].String()
	if !strings.Contains(joined, "198.51.100.0/24") || !strings.Contains(joined, "2001:db8:abcd::/48") {
		t.Fatalf("unexpected replacement cache %q", joined)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary cache should not remain, stat=%v", err)
	}
}

func TestBuildStatusReportsModeAndCacheHealth(t *testing.T) {
	home := t.TempDir()
	writeTestRegionCache(t, home, "CN-GD", "192.0.2.0/24\n2001:db8::/32\n", regionRefreshAge+time.Hour)
	st := BuildStatus(configMain(false, "2001:db8:ffff::1/128", "CN-GD"), home)
	if !st.OK || st.Enabled || st.Mode != "disabled" || st.ManualPrefixes != 1 || st.Region != "CN-GD" || st.RegionLabel != "China / Guangdong" {
		t.Fatalf("status=%+v", st)
	}
	if !st.CacheValid || !st.CacheStale || st.CacheUpdated == "" || st.CacheIPv4 != 1 || st.CacheIPv6 != 1 || st.RegionPrefixes != 2 {
		t.Fatalf("cache status=%+v", st)
	}
	manual := BuildStatus(configMain(true, "192.0.2.7/32", ""), home)
	if !manual.OK || manual.Mode != "manual" || !manual.Enabled || manual.ManualPrefixes != 1 || manual.CacheValid || manual.Region != "" {
		t.Fatalf("manual status=%+v", manual)
	}
}

func TestRecorderCoalescesRecent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.Record("192.0.2.1", "vault.example.com", Decision{Allowed: false, Reason: "denied"})
	r.Record("192.0.2.1", "vault.example.com", Decision{Allowed: false, Reason: "denied"})
	r.Flush()
	report := ReadRecent(path)
	if !report.OK || len(report.Entries) != 1 || report.Entries[0].Count != 2 {
		t.Fatalf("report=%+v", report)
	}
}

func TestRecorderCoalescesDuplicateWritesWithBoundedFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.flushDelay = time.Hour
	d := Decision{Allowed: false, Reason: "denied", PolicyMode: "manual"}
	r.Record("192.0.2.9", "vault.example.com", d)
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 99; i++ {
		r.Record("192.0.2.9", "vault.example.com", d)
	}
	beforeFlush := ReadRecent(path)
	if len(beforeFlush.Entries) != 1 || beforeFlush.Entries[0].Count != 1 {
		t.Fatalf("duplicate hot path unexpectedly rewrote runtime file: %+v", beforeFlush)
	}
	second, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(first, second) {
		t.Fatal("duplicate hot path replaced access.json before bounded flush")
	}
	r.Flush()
	afterFlush := ReadRecent(path)
	if len(afterFlush.Entries) != 1 || afterFlush.Entries[0].Count != 100 {
		t.Fatalf("flush did not persist coalesced count: %+v", afterFlush)
	}
}

func TestRecorderBoundedTimerPersistsTrailingDuplicateCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.flushDelay = 20 * time.Millisecond
	d := Decision{Allowed: false, Reason: "denied", PolicyMode: "manual"}
	r.Record("192.0.2.10", "vault.example.com", d)
	for i := 0; i < 9; i++ {
		r.Record("192.0.2.10", "vault.example.com", d)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		report := ReadRecent(path)
		if len(report.Entries) == 1 && report.Entries[0].Count == 10 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("trailing duplicate count was not flushed: %+v", ReadRecent(path))
}

func TestRecorderPendingDuplicatesDoNotResurrectAfterExternalClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.flushDelay = time.Hour
	d := Decision{Allowed: false, Reason: "denied", PolicyMode: "manual"}
	r.Record("192.0.2.11", "vault.example.com", d)
	r.Record("192.0.2.11", "vault.example.com", d)
	if _, err := ClearRecent(path); err != nil {
		t.Fatal(err)
	}
	r.Flush()
	report := ReadRecent(path)
	if !report.OK || len(report.Entries) != 0 {
		t.Fatalf("pending duplicates resurrected after external clear: %+v", report)
	}
}

func TestClearDeniedRecentKeepsAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.Record("192.0.2.1", "allowed.example.com", Decision{Allowed: true, Reason: "disabled"})
	r.Record("192.0.2.2", "denied.example.com", Decision{Allowed: false, Reason: "denied"})
	report, err := ClearDeniedRecent(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 1 || !report.Entries[0].Allowed || report.Entries[0].IP != "192.0.2.1" {
		t.Fatalf("cleared report=%+v", report)
	}
	readBack := ReadRecent(path)
	if !readBack.OK || len(readBack.Entries) != 1 || !readBack.Entries[0].Allowed {
		t.Fatalf("read back=%+v", readBack)
	}
}

// Keep access tests independent from the config parser internals while still
// exercising the exact Main shape LoadPolicy consumes.
func configMain(enabled bool, allow, region string) config.Main {
	return config.Main{AccessEnabled: enabled, AccessAllow: allow, AccessRegion: region}
}

func TestRecorderKeepsLatestSummaryPerSourceHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.Record("2001:db8::1", "vault.example.com", Decision{Allowed: true, Reason: "region", Region: "China / Guangdong", PolicyMode: "region"})
	r.Record("2001:db8::1", "vault.example.com", Decision{Allowed: false, Reason: "denied", PolicyMode: "manual"})
	report := ReadRecent(path)
	if !report.OK || len(report.Entries) != 1 {
		t.Fatalf("report=%+v", report)
	}
	e := report.Entries[0]
	if e.Allowed || e.Reason != "denied" || e.PolicyMode != "manual" || e.Count != 2 {
		t.Fatalf("latest summary=%+v", e)
	}
}

func TestReadRecentCollapsesLegacyDuplicateRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	legacy := RecentReport{APIVersion: 1, OK: true, Phase: "access", Entries: []Event{
		{Time: "2026-09-08T00:00:00Z", IP: "192.0.2.1", Host: "vault.example.com", Allowed: true, Reason: "disabled", Count: 3},
		{Time: "2026-09-08T01:00:00Z", IP: "192.0.2.1", Host: "vault.example.com", Allowed: false, Reason: "denied", PolicyMode: "manual", Count: 2},
	}}
	b, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	report := ReadRecent(path)
	if len(report.Entries) != 1 || report.Entries[0].Allowed || report.Entries[0].Count != 5 || report.Entries[0].PolicyMode != "manual" {
		t.Fatalf("collapsed=%+v", report)
	}
}

func TestClearRecentRemovesAllRuntimeRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.Record("192.0.2.1", "allowed.example.com", Decision{Allowed: true, Reason: "disabled", PolicyMode: "disabled"})
	r.Record("192.0.2.2", "denied.example.com", Decision{Allowed: false, Reason: "denied", PolicyMode: "manual"})
	report, err := ClearRecent(path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Entries) != 0 {
		t.Fatalf("cleared report=%+v", report)
	}
	readBack := ReadRecent(path)
	if !readBack.OK || len(readBack.Entries) != 0 {
		t.Fatalf("read back=%+v", readBack)
	}
}

func TestAnnotateRecentGeoUsesProvinceChinaAndForeignFallbacks(t *testing.T) {
	home := t.TempDir()
	writeTestRegionCache(t, home, "CN", "203.0.113.0/24\n2001:db8::/32\n", 0)
	writeTestRegionCache(t, home, "CN-GD", "203.0.113.0/25\n2001:db8::/48\n", 0)
	report := RecentReport{APIVersion: 1, OK: true, Phase: "access", Entries: []Event{
		{IP: "203.0.113.10"},
		{IP: "203.0.113.200"},
		{IP: "198.51.100.10"},
	}}
	report = AnnotateRecentGeo(report, home)
	got := []string{report.Entries[0].Geo, report.Entries[1].Geo, report.Entries[2].Geo}
	want := []string{"CN-GD", "CN", "FOREIGN"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("geo[%d]=%q want %q report=%+v", i, got[i], want[i], report)
		}
	}
}

func TestManualDenyOverridesAllowRegionAndDisabled(t *testing.T) {
	deny := netip.MustParsePrefix("2001:db8::7/128")
	allow := netip.MustParsePrefix("2001:db8::/32")
	region := netip.MustParsePrefix("2001:db8::/32")
	for _, p := range []*Policy{
		{Enabled: true, Manual: []netip.Prefix{allow}, Deny: []netip.Prefix{deny}, RegionLabel: "China / Guangdong", Region: []netip.Prefix{region}},
		{Enabled: false, Deny: []netip.Prefix{deny}},
	} {
		p.manualMatcher = newPrefixMatcher(p.Manual)
		p.denyMatcher = newPrefixMatcher(p.Deny)
		p.regionMatcher = newPrefixMatcher(p.Region)
		d := p.Evaluate(netip.MustParseAddr("2001:db8::7"))
		if p.Enabled {
			if d.Allowed || d.Reason != "manual-deny" {
				t.Fatalf("enabled deny=%+v", d)
			}
		} else if d.Allowed || d.Reason != "manual-deny" {
			t.Fatalf("disabled manual-deny decision=%+v", d)
		}
	}
}

func TestLoadPolicyDenyPrecedence(t *testing.T) {
	home := t.TempDir()
	writeTestRegionCache(t, home, "CN-GD", "192.0.2.0/24\n2001:db8::/32\n", time.Hour)
	main := configMain(true, "2001:db8::7/128", "CN-GD")
	main.AccessDeny = "2001:db8::7/128"
	p, err := LoadPolicy(main, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Deny) != 1 {
		t.Fatalf("deny=%v", p.Deny)
	}
	d := p.Evaluate(netip.MustParseAddr("2001:db8::7"))
	if d.Allowed || d.Reason != "manual-deny" || d.PolicyMode != "region" {
		t.Fatalf("decision=%+v", d)
	}
	st := BuildStatus(main, home)
	if !st.OK || st.ManualPrefixes != 1 || st.DenyPrefixes != 1 {
		t.Fatalf("status=%+v", st)
	}
}

func TestAnnotateRecentCurrent(t *testing.T) {
	allow := netip.MustParsePrefix("192.0.2.1/32")
	deny := netip.MustParsePrefix("192.0.2.2/32")
	p := &Policy{Enabled: true, Manual: []netip.Prefix{allow}, Deny: []netip.Prefix{deny}}
	p.manualMatcher = newPrefixMatcher(p.Manual)
	p.denyMatcher = newPrefixMatcher(p.Deny)
	report := RecentReport{APIVersion: 1, OK: true, Phase: "access", Entries: []Event{
		{IP: "192.0.2.1", Host: "a.example", Allowed: false, Reason: "denied"},
		{IP: "192.0.2.2", Host: "b.example", Allowed: true, Reason: "disabled"},
	}}
	report = AnnotateRecentCurrent(report, p)
	if report.Entries[0].CurrentAllowed == nil || !*report.Entries[0].CurrentAllowed || report.Entries[0].CurrentReason != "ip" {
		t.Fatalf("allow current=%+v", report.Entries[0])
	}
	if report.Entries[1].CurrentAllowed == nil || *report.Entries[1].CurrentAllowed || report.Entries[1].CurrentReason != "manual-deny" {
		t.Fatalf("deny current=%+v", report.Entries[1])
	}
}

func TestClearRecentEntryOnlyMatchingSourceHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	report := RecentReport{APIVersion: 1, OK: true, Phase: "access", Entries: []Event{
		{Time: "2026-09-08T00:00:00Z", IP: "2001:db8::1", Host: "a.example", Allowed: true, Reason: "disabled", Count: 1},
		{Time: "2026-09-08T00:01:00Z", IP: "2001:db8::1", Host: "b.example", Allowed: true, Reason: "disabled", Count: 1},
	}}
	b, _ := json.Marshal(report)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ClearRecentEntry(path, "2001:db8::1", "a.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Host != "b.example" {
		t.Fatalf("got=%+v", got)
	}
}

func TestRecorderPersistsGeoAndCurrentWithoutReadTimeAnnotation(t *testing.T) {
	home := t.TempDir()
	writeTestRegionCache(t, home, "CN", "203.0.113.0/24\n2001:db8::/32\n", 0)
	writeTestRegionCache(t, home, "CN-GD", "203.0.113.0/25\n2001:db8::/48\n", 0)
	geo := LoadGeoResolver(home)

	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.SetGeoResolver(geo)
	r.Record("203.0.113.10", "vault.example.com", Decision{Allowed: true, Reason: "region", Region: "China / Guangdong", PolicyMode: "region"})

	report := ReadRecent(path)
	if !report.OK || len(report.Entries) != 1 {
		t.Fatalf("report=%+v", report)
	}
	e := report.Entries[0]
	if e.Geo != "CN-GD" || e.CurrentAllowed == nil || !*e.CurrentAllowed || e.CurrentReason != "region" || e.CurrentPolicyMode != "region" {
		t.Fatalf("persisted event=%+v", e)
	}
}

func TestRecorderReevaluateCurrentPersistsPolicyChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.Record("192.0.2.7", "vault.example.com", Decision{Allowed: true, Reason: "disabled", PolicyMode: "disabled"})

	deny := netip.MustParsePrefix("192.0.2.7/32")
	p := &Policy{Enabled: false, Deny: []netip.Prefix{deny}}
	p.denyMatcher = newPrefixMatcher(p.Deny)
	r.ReevaluateCurrent(p)

	report := ReadRecent(path)
	if !report.OK || len(report.Entries) != 1 {
		t.Fatalf("report=%+v", report)
	}
	e := report.Entries[0]
	if e.CurrentAllowed == nil || *e.CurrentAllowed || e.CurrentReason != "manual-deny" || e.CurrentPolicyMode != "disabled" {
		t.Fatalf("reevaluated event=%+v", e)
	}
}

func TestLoadPolicyReusesParsedRegionSnapshotUntilFileChanges(t *testing.T) {
	home := t.TempDir()
	path := writeTestRegionCache(t, home, "CN-GD", "192.0.2.0/24\n2001:db8::/32\n", 0)

	first, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	if first.regionMatcher == nil || first.regionMatcher != second.regionMatcher {
		t.Fatalf("unchanged region cache did not reuse immutable matcher snapshot")
	}

	if err := os.WriteFile(path, []byte("198.51.100.0/24\n2001:db9::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	third, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	if third.regionMatcher == first.regionMatcher {
		t.Fatalf("changed region cache reused stale matcher snapshot")
	}
	if d := third.Evaluate(netip.MustParseAddr("192.0.2.7")); d.Allowed {
		t.Fatalf("old region unexpectedly allowed after cache replacement: %+v", d)
	}
	if d := third.Evaluate(netip.MustParseAddr("198.51.100.7")); !d.Allowed || d.Reason != "region" {
		t.Fatalf("new region not active after cache replacement: %+v", d)
	}
}

func TestWriteRegionCacheInvalidatesParsedSnapshot(t *testing.T) {
	home := t.TempDir()
	path := writeTestRegionCache(t, home, "CN-GD", "192.0.2.0/24\n2001:db8::/32\n", 0)
	first, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	region, ok := regionByKey("CN-GD")
	if !ok {
		t.Fatal("CN-GD missing")
	}
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if err := writeRegionCache(path, region, "test", prefixes); err != nil {
		t.Fatal(err)
	}
	second, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	if first.regionMatcher == second.regionMatcher {
		t.Fatalf("atomic region cache write did not invalidate parsed snapshot")
	}
}

func TestBuildStatusWarmsPolicyRegionSnapshot(t *testing.T) {
	home := t.TempDir()
	path := writeTestRegionCache(t, home, "CN-GD", "192.0.2.0/24\n2001:db8::/32\n", 0)
	st := BuildStatus(configMain(true, "", "CN-GD"), home)
	if !st.OK || st.RegionPrefixes != 2 {
		t.Fatalf("status=%+v", st)
	}
	regionParseCache.Lock()
	cached, ok := regionParseCache.byPath[path]
	regionParseCache.Unlock()
	if !ok || cached.matcher == nil {
		t.Fatal("BuildStatus did not populate parsed region snapshot")
	}
	policy, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	if policy.regionMatcher != cached.matcher {
		t.Fatal("LoadPolicy rebuilt matcher after BuildStatus warmed the same file")
	}
}

func TestLoadPolicyRejectsSameMetadataAtomicReplacement(t *testing.T) {
	home := t.TempDir()
	path := writeTestRegionCache(t, home, "CN-GD", "192.0.2.0/24\n2001:db8::/32\n", 0)
	first, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	tmp := path + ".replacement"
	if err := os.WriteFile(tmp, []byte("192.0.3.0/24\n2001:db9::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if replacement, err := os.Stat(tmp); err != nil {
		t.Fatal(err)
	} else if replacement.Size() != st.Size() || replacement.ModTime().UnixNano() != st.ModTime().UnixNano() {
		t.Fatalf("test replacement metadata differs: old=(%d,%d) new=(%d,%d)", st.Size(), st.ModTime().UnixNano(), replacement.Size(), replacement.ModTime().UnixNano())
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	second, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	if second.regionMatcher == first.regionMatcher {
		t.Fatal("same-size/same-mtime atomic replacement reused stale matcher")
	}
	if d := second.Evaluate(netip.MustParseAddr("192.0.2.7")); d.Allowed {
		t.Fatalf("old region unexpectedly allowed after same-metadata replacement: %+v", d)
	}
	if d := second.Evaluate(netip.MustParseAddr("192.0.3.7")); !d.Allowed || d.Reason != "region" {
		t.Fatalf("replacement region not active: %+v", d)
	}
}

func TestGeoResolverReusesParsedRegionMatcher(t *testing.T) {
	home := t.TempDir()
	writeTestRegionCache(t, home, "CN-GD", "192.0.2.0/24\n2001:db8::/32\n", 0)
	policy, err := LoadPolicy(configMain(true, "", "CN-GD"), home)
	if err != nil {
		t.Fatal(err)
	}
	geo := LoadGeoResolver(home)
	if len(geo.provinces) != 1 || geo.provinces[0].key != "CN-GD" {
		t.Fatalf("geo provinces=%+v", geo.provinces)
	}
	if geo.provinces[0].matcher != policy.regionMatcher {
		t.Fatal("GeoResolver rebuilt matcher instead of reusing parsed region snapshot")
	}
}

func TestRecorderDoesNotResurrectRowsAfterExternalClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	r := NewRecorder(path)
	r.Record("192.0.2.1", "old.example", Decision{Allowed: false, Reason: "denied", PolicyMode: "manual"})
	if _, err := ClearRecent(path); err != nil {
		t.Fatal(err)
	}
	r.Record("192.0.2.2", "new.example", Decision{Allowed: true, Reason: "disabled", PolicyMode: "disabled"})
	got := ReadRecent(path)
	if !got.OK {
		t.Fatalf("read recent failed: %+v", got)
	}
	if len(got.Entries) != 1 || got.Entries[0].Host != "new.example" {
		t.Fatalf("external clear was not adopted by recorder: %+v", got.Entries)
	}
}

func TestWriteRegionCacheConcurrentWritersDoNotShareTempFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CN-GD.cidr")
	region := Region{Key: "CN-GD", Label: "China / Guangdong"}
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := writeRegionCache(path, region, "test", prefixes); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent region-cache write failed: %v", err)
	}
	got, v4, v6, err := readPrefixFile(path)
	if err != nil || len(got) != 2 || v4 != 1 || v6 != 1 {
		t.Fatalf("final region cache invalid: prefixes=%v v4=%d v6=%d err=%v", got, v4, v6, err)
	}
}
