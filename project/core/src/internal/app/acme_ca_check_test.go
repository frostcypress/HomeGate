package app

import (
	"context"
	"strings"
	"testing"
)

func TestACMECACheckRejectsRemovedPresetWithoutNetwork(t *testing.T) {
	a := New("1.1.0")
	report, err := a.ACMECACheck(context.Background(), "google", "production")
	if err == nil {
		t.Fatal("expected removed CA rejection")
	}
	if report.OK || report.Reachable || !report.Direct || !strings.Contains(report.Error, "unsupported ACME CA") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}
