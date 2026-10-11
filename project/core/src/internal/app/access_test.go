package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"homegate.local/homegate/internal/access"
	"homegate.local/homegate/internal/config"
)

type panicConfigLoader struct{}

func (panicConfigLoader) Load(context.Context) (config.Snapshot, error) {
	panic("AccessRecent must not reload config or region policy")
}

func TestAccessRecentIsRuntimeFileOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	allowed := false
	report := access.RecentReport{APIVersion: 1, OK: true, Phase: "access", Entries: []access.Event{{
		Time: "2026-09-09T05:01:27Z", IP: "2001:db8::1", Host: "vault.example.com",
		Allowed: false, Reason: "manual-deny", PolicyMode: "manual", Geo: "CN",
		CurrentAllowed: &allowed, CurrentReason: "manual-deny", CurrentPolicyMode: "manual", Count: 29,
	}}}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEGATE_ACCESS_RECENT", path)

	a := App{Config: config.NewManager(panicConfigLoader{}), HomeDir: t.TempDir()}
	got := a.AccessRecent(context.Background())
	if !got.OK || len(got.Entries) != 1 || got.Entries[0].Geo != "CN" || got.Entries[0].CurrentReason != "manual-deny" {
		t.Fatalf("got=%+v", got)
	}
}
