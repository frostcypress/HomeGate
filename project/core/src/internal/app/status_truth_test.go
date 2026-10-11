package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"homegate.local/homegate/internal/proxy"
	runtimestate "homegate.local/homegate/internal/runtime"
)

func writeProxyStatusFixture(t *testing.T, path string, st proxy.Status) {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProxyStatusDoesNotTrustStaleListenerSnapshotWhenDaemonStopped(t *testing.T) {
	dir := t.TempDir()
	proxyPath := filepath.Join(dir, "proxy.json")
	writeProxyStatusFixture(t, proxyPath, proxy.Status{
		APIVersion:     1,
		OK:             true,
		Version:        "0.5.0",
		Phase:          proxy.Phase,
		Configured:     1,
		Enabled:        1,
		HTTPSListening: true,
		HTTPListening:  true,
		HTTPSPort:      10443,
		HTTPPort:       10080,
		Domains:        []string{"vault.example"},
	})

	a := App{
		Version:         "0.5.0",
		Runtime:         runtimestate.Store{Path: filepath.Join(dir, "missing-runtime.json")},
		ProxyStatusPath: proxyPath,
	}
	st := a.ProxyStatus(context.Background())
	if st.HTTPSListening || st.HTTPListening || st.HTTPSPort != 0 || st.HTTPPort != 0 {
		t.Fatalf("stale proxy listener snapshot survived stopped runtime: %+v", st)
	}
	if !st.OK || st.Configured != 1 || st.Enabled != 1 || len(st.Domains) != 1 {
		t.Fatalf("last-known proxy metadata was unnecessarily discarded: %+v", st)
	}
}

func TestProxyStatusFailsClosedWhenRuntimeIdentityCannotBeProbed(t *testing.T) {
	dir := t.TempDir()
	proxyPath := filepath.Join(dir, "proxy.json")
	runtimePath := filepath.Join(dir, "runtime.json")
	writeProxyStatusFixture(t, proxyPath, proxy.Status{
		APIVersion:     1,
		OK:             true,
		Version:        "0.5.0",
		Phase:          proxy.Phase,
		HTTPSListening: true,
		HTTPListening:  true,
		HTTPSPort:      10443,
		HTTPPort:       10080,
		Domains:        []string{},
	})
	if err := os.WriteFile(runtimePath, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := App{Version: "0.5.0", Runtime: runtimestate.Store{Path: runtimePath}, ProxyStatusPath: proxyPath}
	st := a.ProxyStatus(context.Background())
	if st.OK || st.HTTPSListening || st.HTTPListening || st.HTTPSPort != 0 || st.HTTPPort != 0 {
		t.Fatalf("runtime probe error did not fail proxy listener state closed: %+v", st)
	}
	if !strings.Contains(st.Error, "runtime probe:") {
		t.Fatalf("missing runtime probe diagnostic: %+v", st)
	}
}
