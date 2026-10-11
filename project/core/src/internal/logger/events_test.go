package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEventUserFacingClassificationKeepsRawDetail(t *testing.T) {
	tests := []struct {
		line, category, kind string
		important            bool
	}{
		{"2026-09-16 09:05:00 [INFO] WAN reconciled firewall wan6=pppoe-wan source=public-ip https=443->10443 http=80->10080", "network", "network_updated", true},
		{"2026-09-16 09:10:00 [INFO] DDNS home.example -> 2001:db8::1 (unchanged)", "ddns", "ddns_unchanged", false},
		{"2026-09-16 10:21:00 [INFO] certificate cert1 issued/renewed expires=2026-12-01T00:00:00Z", "certificate", "certificate_renewed", true},
		{"2026-09-16 10:22:00 [INFO] access region refreshed region=CN-GD ipv4=1 ipv6=1 source=network", "access", "access_updated", true},
		{"2026-09-16 10:23:00 [ERROR] proxy startup apply failed: listen HTTPS 10443: address in use", "public", "public_error", true},
	}
	for _, tt := range tests {
		got := ParseEvent(tt.line)
		if got.Category != tt.category || got.Kind != tt.kind || got.Important != tt.important {
			t.Fatalf("ParseEvent(%q) = category=%s kind=%s important=%v", tt.line, got.Category, got.Kind, got.Important)
		}
		if got.Raw != tt.line || got.Timestamp == "" {
			t.Fatalf("raw/timestamp not preserved: %+v", got)
		}
	}
}

func TestParseEventSanitizesLegacyRawLine(t *testing.T) {
	got := ParseEvent("2026-09-16 10:00:00 [ERROR] request token=very-secret Authorization: Bearer abc")
	if strings.Contains(got.Raw, "very-secret") || strings.Contains(got.Raw, "Bearer abc") {
		t.Fatalf("structured raw leaked credentials: %q", got.Raw)
	}
	if !strings.Contains(got.Raw, "<redacted>") {
		t.Fatalf("expected redaction: %q", got.Raw)
	}
}

func TestReadEventsKeepsNewestLinesAndMachineReadableContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "homegate.log")
	data := strings.Join([]string{
		"2026-09-16 09:00:00 [INFO] old event",
		"2026-09-16 09:01:00 [WARN] access region using validated stale cache region=CN-GD ipv4=1 ipv6=1: timeout",
		"2026-09-16 09:02:00 [INFO] HomeGate 1.2.0 common runtime started pid=1 enabled=true",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ReadEvents(path, "1.2.0", 2)
	if !got.OK || got.Version != "1.2.0" || got.Phase != "log-events" || got.Count != 2 || len(got.Events) != 2 {
		t.Fatalf("unexpected report: %+v", got)
	}
	if got.Events[0].Timestamp != "2026-09-16 09:01:00" || got.Events[1].Kind != "system_started" {
		t.Fatalf("wrong retained events: %+v", got.Events)
	}
}
