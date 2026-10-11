package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/firewall"
	"homegate.local/homegate/internal/network"
	"homegate.local/homegate/internal/proxy"
)

type reloadSequenceLoader struct {
	values []config.Snapshot
	index  int
}

func (l *reloadSequenceLoader) Load(context.Context) (config.Snapshot, error) {
	if l.index >= len(l.values) {
		return config.Snapshot{}, context.Canceled
	}
	v := l.values[l.index]
	l.index++
	return v, nil
}

func reserveTCP6Port(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func reserveDistinctTCP6Port(t *testing.T, avoid int) int {
	t.Helper()
	for i := 0; i < 32; i++ {
		port := reserveTCP6Port(t)
		if port != avoid {
			return port
		}
	}
	t.Fatal("could not reserve a distinct IPv6 loopback port")
	return 0
}

func reloadConfig(port int, target string) config.Snapshot {
	return config.Snapshot{
		Configured: true,
		Main: config.Main{
			ProxyHTTPPort: port,
			DDNSInterval:  300,
			LogLevel:      "info",
			LogMaxLines:   1024,
		},
		Web: []config.WebRule{{ID: "web1", Enabled: true, Domain: "test.example.com", Target: target, HTTPS: false}},
	}
}

type appFirewallRunner struct {
	calls        []string
	failPublic   string
	failRestore  string
	candidateHit bool
}

func (r *appFirewallRunner) Run(_ context.Context, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if strings.Contains(line, " -D ") || strings.Contains(line, " -F ") || strings.Contains(line, " -X ") {
		return errors.New("not present")
	}
	if r.failPublic != "" && strings.Contains(line, "--dport "+r.failPublic+" ") {
		r.candidateHit = true
		return errors.New("candidate firewall failure")
	}
	if r.candidateHit && r.failRestore != "" && strings.Contains(line, "--dport "+r.failRestore+" ") {
		return errors.New("restore firewall failure")
	}
	return nil
}

type appWANRunner struct{}

func (appWANRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	switch {
	case strings.Contains(line, "addr show scope global"):
		return []byte("2: pppoe-wan inet6 2001:db8::1234/64 scope global\n"), nil
	case strings.Contains(line, "route show default"):
		return []byte("default via fe80::1 dev pppoe-wan metric 512\n"), nil
	case strings.Contains(line, "network.interface.wan6"):
		return []byte(`{"up":true,"l3_device":"pppoe-wan"}`), nil
	default:
		return nil, errors.New("unexpected network command")
	}
}

func attachNoopFirewall(a *App, t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	a.Firewall = firewall.Controller{
		Runner:           &appFirewallRunner{},
		Network:          network.New(appWANRunner{}),
		StatusPath:       dir + "/firewall.json",
		CompatStatusPath: dir + "/firewall.status",
	}
}

func readProxyBody(t *testing.T, port int) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://[::1]:"+fmt.Sprint(port)+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "test.example.com"
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestReconcileProxyCandidateRejectKeepsConfigCurrent(t *testing.T) {
	oldPort := reserveTCP6Port(t)
	old := reloadConfig(oldPort, "http://127.0.0.1:18080")

	blocker, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	candidate := reloadConfig(blocker.Addr().(*net.TCPAddr).Port, "http://127.0.0.1:28080")

	loader := &reloadSequenceLoader{values: []config.Snapshot{old, candidate}}
	manager := config.NewManager(loader)
	if _, err := manager.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := App{Version: "0.5.0", Config: manager, HomeDir: t.TempDir()}
	attachNoopFirewall(&a, t)
	generation := newDaemonGeneration(context.Background())
	defer generation.Stop()
	oldWork := generation.Work(old)
	pm := proxy.New(a.HomeDir, nil, a.Version)
	pm.StatusPath = t.TempDir() + "/proxy.json"
	if _, err := pm.ApplyGeneration(context.Background(), old, oldWork.Generation); err != nil {
		t.Fatal(err)
	}
	defer pm.Close(context.Background())

	result, err := a.reconcileRuntimeCandidate(context.Background(), pm, generation, nil)
	if err == nil || !result.Restored {
		t.Fatalf("expected rejected candidate with restored generation: result=%+v err=%v", result, err)
	}
	current, ok := manager.Current()
	if !ok || len(current.Web) != 1 || current.Web[0].Target != old.Web[0].Target || current.Main.ProxyHTTPPort != oldPort {
		t.Fatalf("Config.Current changed after rejected runtime: %+v ok=%v", current, ok)
	}
	if generation.IsCurrent(oldWork.Generation) {
		t.Fatal("pre-reload generation retained commit authority")
	}
	if !generation.IsCurrent(result.Work.Generation) {
		t.Fatalf("restored generation is not current: %+v", result.Work)
	}
}

func TestReconcileProxyCandidateCommitsAfterProxyAccepts(t *testing.T) {
	port := reserveTCP6Port(t)
	old := reloadConfig(port, "http://127.0.0.1:18080")
	candidate := reloadConfig(port, "http://127.0.0.1:28080")
	candidate.Main.LogLevel = "debug"

	loader := &reloadSequenceLoader{values: []config.Snapshot{old, candidate}}
	manager := config.NewManager(loader)
	if _, err := manager.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := App{Version: "0.5.0", Config: manager, HomeDir: t.TempDir()}
	attachNoopFirewall(&a, t)
	generation := newDaemonGeneration(context.Background())
	defer generation.Stop()
	oldWork := generation.Work(old)
	pm := proxy.New(a.HomeDir, nil, a.Version)
	pm.StatusPath = t.TempDir() + "/proxy.json"
	if _, err := pm.ApplyGeneration(context.Background(), old, oldWork.Generation); err != nil {
		t.Fatal(err)
	}
	defer pm.Close(context.Background())

	result, err := a.reconcileRuntimeCandidate(context.Background(), pm, generation, nil)
	if err != nil || result.Restored {
		t.Fatalf("candidate rejected unexpectedly: result=%+v err=%v", result, err)
	}
	current, ok := manager.Current()
	if !ok || current.Main.LogLevel != "debug" || len(current.Web) != 1 || current.Web[0].Target != candidate.Web[0].Target {
		t.Fatalf("accepted candidate not committed: %+v ok=%v", current, ok)
	}
	if generation.IsCurrent(oldWork.Generation) || !generation.IsCurrent(result.Work.Generation) {
		t.Fatalf("generation transition invalid old=%d new=%d", oldWork.Generation, result.Work.Generation)
	}
}

func TestReconcileRuntimeCandidateFirewallRejectKeepsConfigAndProxyOld(t *testing.T) {
	port := reserveTCP6Port(t)
	candidatePort := reserveDistinctTCP6Port(t, port)
	oldBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "old") }))
	defer oldBackend.Close()
	newBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "new") }))
	defer newBackend.Close()

	old := reloadConfig(port, oldBackend.URL)
	old.Main.AutoFirewall = true
	old.Main.HTTPPort = 8080
	candidate := reloadConfig(candidatePort, newBackend.URL)
	candidate.Main.AutoFirewall = true
	candidate.Main.HTTPPort = 8081

	loader := &reloadSequenceLoader{values: []config.Snapshot{old, candidate}}
	manager := config.NewManager(loader)
	if _, err := manager.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	fwRunner := &appFirewallRunner{failPublic: "8081"}
	fwDir := t.TempDir()
	a := App{
		Version: "0.5.0",
		Config:  manager,
		HomeDir: t.TempDir(),
		Firewall: firewall.Controller{
			Runner:           fwRunner,
			Network:          network.New(appWANRunner{}),
			StatusPath:       fwDir + "/firewall.json",
			CompatStatusPath: fwDir + "/firewall.status",
		},
	}
	if _, err := a.Firewall.Apply(context.Background(), a.Version, old); err != nil {
		t.Fatal(err)
	}

	generation := newDaemonGeneration(context.Background())
	defer generation.Stop()
	oldWork := generation.Work(old)
	pm := proxy.New(a.HomeDir, nil, a.Version)
	pm.StatusPath = t.TempDir() + "/proxy.json"
	if _, err := pm.ApplyGeneration(context.Background(), old, oldWork.Generation); err != nil {
		t.Fatal(err)
	}
	defer pm.Close(context.Background())
	if got := readProxyBody(t, port); got != "old" {
		t.Fatalf("precondition proxy body=%q", got)
	}

	result, err := a.reconcileRuntimeCandidate(context.Background(), pm, generation, nil)
	if err == nil || !result.Restored || !result.FirewallReconciled || result.FirewallRetry {
		t.Fatalf("unexpected reject result=%+v err=%v", result, err)
	}
	current, ok := manager.Current()
	if !ok || current.Main.HTTPPort != old.Main.HTTPPort || current.Web[0].Target != old.Web[0].Target {
		t.Fatalf("Config.Current changed after firewall reject: %+v ok=%v", current, ok)
	}
	if got := readProxyBody(t, port); got != "old" {
		t.Fatalf("proxy published rejected candidate body=%q", got)
	}
	ln, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", candidatePort))
	if err != nil {
		t.Fatalf("prepared candidate listener was not aborted on firewall reject: %v", err)
	}
	_ = ln.Close()
	fw := a.Firewall.Read(a.Version)
	if !fw.OK || !fw.Active || fw.HTTP != fmt.Sprintf("%d->%d", old.Main.HTTPPort, old.Main.ProxyHTTPPort) {
		t.Fatalf("old firewall was not restored: %+v", fw)
	}
	if !strings.Contains(strings.Join(fwRunner.calls, "\n"), "--dport 8081") {
		t.Fatalf("candidate firewall path was not exercised: %v", fwRunner.calls)
	}
}

func TestReconcileRuntimeCandidateReportsFirewallRestoreFailure(t *testing.T) {
	port := reserveTCP6Port(t)
	old := reloadConfig(port, "http://127.0.0.1:18080")
	old.Main.AutoFirewall = true
	old.Main.HTTPPort = 8080
	candidate := reloadConfig(port, "http://127.0.0.1:28080")
	candidate.Main.AutoFirewall = true
	candidate.Main.HTTPPort = 8081

	loader := &reloadSequenceLoader{values: []config.Snapshot{old, candidate}}
	manager := config.NewManager(loader)
	if _, err := manager.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	fwRunner := &appFirewallRunner{}
	fwDir := t.TempDir()
	a := App{
		Version: "0.5.0",
		Config:  manager,
		HomeDir: t.TempDir(),
		Firewall: firewall.Controller{
			Runner:           fwRunner,
			Network:          network.New(appWANRunner{}),
			StatusPath:       fwDir + "/firewall.json",
			CompatStatusPath: fwDir + "/firewall.status",
		},
	}
	if _, err := a.Firewall.Apply(context.Background(), a.Version, old); err != nil {
		t.Fatal(err)
	}
	fwRunner.failPublic = "8081"
	fwRunner.failRestore = "8080"

	generation := newDaemonGeneration(context.Background())
	defer generation.Stop()
	oldWork := generation.Work(old)
	pm := proxy.New(a.HomeDir, nil, a.Version)
	pm.StatusPath = t.TempDir() + "/proxy.json"
	if _, err := pm.ApplyGeneration(context.Background(), old, oldWork.Generation); err != nil {
		t.Fatal(err)
	}
	defer pm.Close(context.Background())

	result, err := a.reconcileRuntimeCandidate(context.Background(), pm, generation, nil)
	if err == nil || !result.Restored || !result.FirewallReconciled {
		t.Fatalf("unexpected result=%+v err=%v", result, err)
	}
	if !strings.Contains(err.Error(), "restore previous firewall") || !strings.Contains(err.Error(), "restore firewall failure") {
		t.Fatalf("restore failure diagnostic missing: %v", err)
	}
	current, ok := manager.Current()
	if !ok || current.Main.HTTPPort != old.Main.HTTPPort || current.Web[0].Target != old.Web[0].Target {
		t.Fatalf("Config.Current changed despite restore failure: %+v ok=%v", current, ok)
	}
	fw := a.Firewall.Read(a.Version)
	if fw.OK || fw.Active || !strings.Contains(fw.Error, "restore firewall failure") {
		t.Fatalf("firewall status does not expose restore failure: %+v", fw)
	}
}
