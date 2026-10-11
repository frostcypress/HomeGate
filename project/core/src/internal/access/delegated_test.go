package access

import (
	"context"
	"homegate.local/homegate/internal/config"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestRetiredProvinceKeepsManualRulesFailClosed(t *testing.T) {
	parsed, err := config.ParseShow("homegate.main=homegate\nhomegate.main.access_enabled='1'\nhomegate.main.access_region='CN-GD'\nhomegate.main.access_allow='192.0.2.7,2001:db8::1'\nhomegate.main.access_deny='192.0.2.7'\n")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadPolicy(parsed.Main, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Enabled || policy.RegionKey != "" {
		t.Fatal("migration widened scope", policy)
	}
	for raw, want := range map[string]bool{"192.0.2.7": false, "192.0.2.8": false, "2001:db8::1": true, "2409:8000::1": false} {
		if policy.Evaluate(netip.MustParseAddr(raw)).Allowed != want {
			t.Fatalf("unexpected migrated permission for %s", raw)
		}
	}
	status := BuildStatus(parsed.Main, t.TempDir())
	if status.Mode != "manual" || status.RetiredRegion != "CN-GD" {
		t.Fatal(status)
	}
}

func TestDelegatedOfficialSnapshot(t *testing.T) {
	path := os.Getenv("HOMEGATE_APNIC_SNAPSHOT")
	if path == "" {
		t.Skip("optional downloaded official snapshot")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ps, v4, v6, err := parseDelegatedChina(f)
	if err != nil || v4 < 8000 || v6 < 2000 {
		t.Fatal(v4, v6, err)
	}
	if !newPrefixMatcher(ps).Contains(netip.MustParseAddr("2409:8000::1")) {
		t.Fatal("representative China Mobile allocation absent from official CN data")
	}
	t.Logf("official snapshot validated: IPv4 prefixes=%d IPv6 prefixes=%d", v4, v6)
}

const delegatedFixture = "2|apnic|20261009|2|19830613|20261008|+1000\napnic|*|ipv4|*|1|summary\napnic|*|ipv6|*|1|summary\napnic|CN|ipv4|198.51.100.0|256|20261008|allocated\napnic|CN|ipv6|2001:db8:abcd::|48|20261008|assigned\n"

func TestDelegatedChinaExactRange(t *testing.T) {
	raw := strings.Replace(delegatedFixture, "198.51.100.0|256", "198.51.100.3|7", 1)
	ps, v4, v6, err := parseDelegatedChina(strings.NewReader(raw))
	if err != nil || v4 != 3 || v6 != 1 {
		t.Fatalf("prefixes=%v v4=%d v6=%d err=%v", ps, v4, v6, err)
	}
	m := newPrefixMatcher(ps)
	for i := 0; i < 14; i++ {
		a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		if got := m.Contains(a); got != (i >= 3 && i < 10) {
			t.Fatalf("range includes/excludes %s incorrectly", a)
		}
	}
}

func TestDelegatedChinaRejectsIncompleteAndMalformed(t *testing.T) {
	for _, raw := range []string{
		"<html>proxy error</html>",
		strings.Replace(delegatedFixture, "|2|19830613", "|3|19830613", 1),
		strings.Replace(delegatedFixture, "ipv6|*|1|summary", "ipv6|*|2|summary", 1),
		strings.Replace(delegatedFixture, "198.51.100.0|256", "255.255.255.255|2", 1),
		strings.Replace(delegatedFixture, "2001:db8:abcd::|48", "2001:db8:abcd::1|48", 1),
		strings.Replace(delegatedFixture, "2001:db8:abcd::|48", "::|0", 1),
		strings.Replace(delegatedFixture, "198.51.100.0|256", "0.0.0.0|4294967296", 1),
	} {
		if _, _, _, err := parseDelegatedChina(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted invalid input %q", raw)
		}
	}
}

func TestDelegatedChinaSkipsOtherCountriesAndUnallocated(t *testing.T) {
	raw := strings.Replace(delegatedFixture, "|2|19830613", "|4|19830613", 1)
	raw = strings.Replace(raw, "ipv4|*|1|summary", "ipv4|*|3|summary", 1)
	raw += "apnic|US|ipv4|203.0.113.0|256|20261008|allocated\napnic|CN|ipv4|192.0.2.0|256|20261008|reserved\n"
	ps, v4, v6, err := parseDelegatedChina(strings.NewReader(raw))
	if err != nil || v4 != 1 || v6 != 1 {
		t.Fatal(ps, v4, v6, err)
	}
	m := newPrefixMatcher(ps)
	if m.Contains(netip.MustParseAddr("203.0.113.1")) || m.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("non-CN/unallocated range allowed")
	}
}

func TestOfficialMirrorFallbackAndProvinceRetirement(t *testing.T) {
	server := withRegionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			_, _ = w.Write([]byte("truncated"))
			return
		}
		_, _ = w.Write([]byte(delegatedFixture))
	})
	accessRegionSourceURLs = func(string) []string { return []string{server.URL + "/broken", server.URL + "/valid"} }
	report, err := UpdateRegion(context.Background(), t.TempDir(), "CN")
	if err != nil || !report.OK || !strings.HasSuffix(report.Source, "/valid") {
		t.Fatal(report, err)
	}
	if _, err := UpdateRegion(context.Background(), t.TempDir(), "CN-GD"); err == nil {
		t.Fatal("retired province downloadable")
	}
	for _, url := range sourceURLs("") {
		if !strings.HasPrefix(url, "https://ftp.apnic.net/") && !strings.HasPrefix(url, "https://ftp.ripe.net/") {
			t.Fatalf("unofficial source %s", url)
		}
	}
}
