package recovery

import (
	"path/filepath"
	"testing"
	"time"
)

func TestReportLifecycle(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	r := Empty("0.5.0")
	if !r.OK || r.Degraded || len(r.Modules) != 0 {
		t.Fatalf("empty=%+v", r)
	}
	r.Set("ddns", StateRetrying, true, 1, 5, now.Add(5*time.Second), "network_unavailable", "WAN unavailable", now)
	if r.OK || !r.Degraded || len(r.Modules) != 1 || r.Modules[0].State != StateRetrying {
		t.Fatalf("retrying=%+v", r)
	}
	r.Set("firewall", StateRequiresUserAction, false, 0, 0, time.Time{}, "invalid_request", "iptables rejected", now)
	if len(r.Modules) != 2 || r.Modules[0].Module != "ddns" || r.Modules[1].Module != "firewall" {
		t.Fatalf("sorted modules=%+v", r.Modules)
	}
	r.ClearModule("ddns")
	if len(r.Modules) != 1 || r.Modules[0].Module != "firewall" || r.OK {
		t.Fatalf("clear ddns=%+v", r)
	}
	r.ClearModule("firewall")
	if !r.OK || r.Degraded || len(r.Modules) != 0 {
		t.Fatalf("clear all=%+v", r)
	}
}

func TestStoreRoundTripAndMissingIsHealthy(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "recovery.json")}
	missing := s.Read("0.5.0")
	if !missing.OK || missing.Degraded {
		t.Fatalf("missing=%+v", missing)
	}
	r := Empty("0.5.0")
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	r.Set("ddns", StateDegraded, true, 5, 5, time.Time{}, "network_unavailable", "still unavailable", now)
	if err := s.Write(r); err != nil {
		t.Fatal(err)
	}
	got := s.Read("0.5.0")
	if got.OK || !got.Degraded || len(got.Modules) != 1 || got.Modules[0].Attempt != 5 {
		t.Fatalf("got=%+v", got)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if got := s.Read("0.5.0"); !got.OK || got.Degraded {
		t.Fatalf("after clear=%+v", got)
	}
}
