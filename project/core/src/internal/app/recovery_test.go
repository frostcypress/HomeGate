package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"homegate.local/homegate/internal/access"
	"homegate.local/homegate/internal/acme"
	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/ddns"
	"homegate.local/homegate/internal/dnsprovider"
	"homegate.local/homegate/internal/network"
	"homegate.local/homegate/internal/recovery"
	runtimestate "homegate.local/homegate/internal/runtime"
)

type appRecoveryProvider struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (p *appRecoveryProvider) Upsert(context.Context, string, string, string, string, int) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return "", p.err
	}
	return "unchanged", nil
}
func (p *appRecoveryProvider) Delete(context.Context, string, string, string, string) error {
	return nil
}
func (p *appRecoveryProvider) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type transientWANRunner struct {
	mu            sync.Mutex
	addrFailures  int
	addrCallCount int
}

func (r *transientWANRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	switch {
	case strings.Contains(line, "addr show scope global"):
		r.mu.Lock()
		r.addrCallCount++
		call := r.addrCallCount
		failures := r.addrFailures
		r.mu.Unlock()
		if call <= failures {
			return nil, errors.New("temporary WAN address lookup failure")
		}
		return []byte("2: pppoe-wan inet6 2001:db8::1234/64 scope global\n"), nil
	case strings.Contains(line, "route show default"):
		return []byte("default via fe80::1 dev pppoe-wan metric 512\n"), nil
	case strings.Contains(line, "network.interface.wan6"):
		return []byte(`{"up":true,"l3_device":"pppoe-wan"}`), nil
	default:
		return nil, errors.New("unexpected network command")
	}
}

func recoverySnapshot() config.Snapshot {
	return config.Snapshot{
		Configured: true,
		Main: config.Main{
			Enabled:       true,
			LogLevel:      "info",
			LogMaxLines:   1024,
			DDNSInterval:  3600,
			AccessEnabled: false,
			WOLInterface:  config.DefaultWOLInterface,
		},
		Accounts: map[string]config.DNSAccount{
			"dns1": {ID: "dns1", Provider: "aliyun", KeyID: "id", Secret: "secret"},
		},
		DDNS: []config.DDNSRule{{
			ID: "ddns1", Enabled: true, Name: "recover.example.com", Account: "dns1",
			Zone: "example.com", Host: "recover", Type: "AAAA", Source: "auto", TTL: 600,
		}},
	}
}

func newRecoveryTestApp(t *testing.T, cfg config.Snapshot, runner network.CommandRunner, provider ddns.ProviderFactory) App {
	t.Helper()
	dir := t.TempDir()
	a := App{
		Version:         "0.5.0",
		Config:          config.NewManager(&staticSnapshotLoader{cfg: cfg}),
		Runtime:         runtimestate.Store{Path: filepath.Join(dir, "runtime.json")},
		LogPath:         filepath.Join(dir, "homegate.log"),
		Network:         network.New(runner),
		DDNSStatus:      ddns.Store{Path: filepath.Join(dir, "ddns.json")},
		Recovery:        recovery.Store{Path: filepath.Join(dir, "recovery.json")},
		DDNSProvider:    provider,
		HomeDir:         filepath.Join(dir, "home"),
		ProxyStatusPath: filepath.Join(dir, "proxy.json"),
		DaemonLockPath:  filepath.Join(dir, "daemon.lock"),
	}
	attachNoopFirewall(&a, t)
	return a
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool, label string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", label)
}

func TestClassifyDDNSRecoveryPrefersRetryableFailure(t *testing.T) {
	r := ddns.Report{Results: []ddns.Result{
		{Status: "error", ErrorKind: string(dnsprovider.ErrorAuthentication), Message: "bad secret"},
		{Status: "error", ErrorKind: string(dnsprovider.ErrorNetworkUnavailable), Retryable: true, Message: "WAN down"},
	}}
	got := classifyDDNSRecovery(r)
	if !got.Failed || !got.Retryable || got.ErrorKind != string(dnsprovider.ErrorNetworkUnavailable) || got.Error != "WAN down" {
		t.Fatalf("decision=%+v", got)
	}
}

func TestDaemonDDNSTemporaryFailureRetriesAndRecovers(t *testing.T) {
	oldDelays := ddnsRecoveryDelays
	ddnsRecoveryDelays = []time.Duration{120 * time.Millisecond, 200 * time.Millisecond}
	defer func() { ddnsRecoveryDelays = oldDelays }()

	runner := &transientWANRunner{addrFailures: 1}
	provider := &appRecoveryProvider{}
	a := newRecoveryTestApp(t, recoverySnapshot(), runner, func(config.DNSAccount) (ddns.Provider, error) { return provider, nil })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.RunDaemon(ctx) }()

	waitFor(t, time.Second, func() bool {
		r := a.RecoveryStatus()
		return r.Degraded && len(r.Modules) == 1 && r.Modules[0].Module == "ddns" && r.Modules[0].State == recovery.StateRetrying && r.Modules[0].Retryable
	}, "DDNS retrying recovery state")

	waitFor(t, 2*time.Second, func() bool {
		r := a.DDNSReport()
		return r.OK && len(r.Results) == 1 && r.Results[0].Status == "unchanged" && a.RecoveryStatus().OK
	}, "DDNS automatic recovery")

	if provider.Calls() != 1 {
		t.Fatalf("provider calls=%d want=1 after WAN recovered", provider.Calls())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunDaemon: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestDaemonDDNSPermanentFailureRequiresUserActionWithoutRetry(t *testing.T) {
	oldDelays := ddnsRecoveryDelays
	ddnsRecoveryDelays = []time.Duration{20 * time.Millisecond}
	defer func() { ddnsRecoveryDelays = oldDelays }()

	runner := &transientWANRunner{}
	provider := &appRecoveryProvider{err: dnsprovider.NewError("aliyun", "records.upsert", dnsprovider.ErrorAuthentication, "InvalidAccessKeyId.NotFound", "authentication failed", false, nil)}
	a := newRecoveryTestApp(t, recoverySnapshot(), runner, func(config.DNSAccount) (ddns.Provider, error) { return provider, nil })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.RunDaemon(ctx) }()

	waitFor(t, time.Second, func() bool {
		r := a.RecoveryStatus()
		return r.Degraded && len(r.Modules) == 1 && r.Modules[0].Module == "ddns" && r.Modules[0].State == recovery.StateRequiresUserAction && !r.Modules[0].Retryable && r.Modules[0].ErrorKind == string(dnsprovider.ErrorAuthentication)
	}, "DDNS permanent recovery state")

	time.Sleep(80 * time.Millisecond)
	if provider.Calls() != 1 {
		t.Fatalf("permanent failure retried provider calls=%d", provider.Calls())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunDaemon: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestClassifyACMERecoveryPermanentTakesPrecedence(t *testing.T) {
	r := acme.RenewReport{Results: []acme.IssueReport{
		{OK: false, Certificate: "retry", Error: "network down", ErrorKind: string(dnsprovider.ErrorNetworkUnavailable), Retryable: true},
		{OK: false, Certificate: "auth", Error: "bad secret", ErrorKind: string(dnsprovider.ErrorAuthentication), Retryable: false},
	}}
	got := classifyACMERecovery(r)
	if !got.Failed || got.Retryable || got.ErrorKind != string(dnsprovider.ErrorAuthentication) || got.Error != "bad secret" {
		t.Fatalf("decision=%+v", got)
	}
}

func TestDaemonACMETemporaryFailureRetriesAndRecovers(t *testing.T) {
	oldDelays := acmeRecoveryDelays
	acmeRecoveryDelays = []time.Duration{80 * time.Millisecond, 120 * time.Millisecond}
	defer func() { acmeRecoveryDelays = oldDelays }()

	runner := &transientWANRunner{}
	provider := &appRecoveryProvider{}
	a := newRecoveryTestApp(t, recoverySnapshot(), runner, func(config.DNSAccount) (ddns.Provider, error) { return provider, nil })
	var mu sync.Mutex
	calls := 0
	a.ACMERenewDue = func(context.Context, string, config.Snapshot) acme.RenewReport {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return acme.RenewReport{APIVersion: 1, OK: false, Version: "0.5.0", Phase: acme.Phase, Results: []acme.IssueReport{{APIVersion: 1, OK: false, Certificate: "cert1", Error: "temporary network failure", ErrorKind: string(dnsprovider.ErrorNetworkUnavailable), Retryable: true}}}
		}
		return acme.RenewReport{APIVersion: 1, OK: true, Version: "0.5.0", Phase: acme.Phase, Results: []acme.IssueReport{}}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.RunDaemon(ctx) }()

	waitFor(t, time.Second, func() bool {
		r := a.RecoveryStatus()
		return r.Degraded && len(r.Modules) == 1 && r.Modules[0].Module == "acme" && r.Modules[0].State == recovery.StateRetrying && r.Modules[0].Retryable
	}, "ACME retrying recovery state")

	waitFor(t, 2*time.Second, func() bool { return a.RecoveryStatus().OK }, "ACME automatic recovery")
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("ACME calls=%d want=2", gotCalls)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunDaemon: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestDaemonACMEPermanentFailureRequiresUserActionWithoutRetry(t *testing.T) {
	oldDelays := acmeRecoveryDelays
	acmeRecoveryDelays = []time.Duration{20 * time.Millisecond}
	defer func() { acmeRecoveryDelays = oldDelays }()

	a := newRecoveryTestApp(t, recoverySnapshot(), &transientWANRunner{}, func(config.DNSAccount) (ddns.Provider, error) { return &appRecoveryProvider{}, nil })
	var mu sync.Mutex
	calls := 0
	a.ACMERenewDue = func(context.Context, string, config.Snapshot) acme.RenewReport {
		mu.Lock()
		calls++
		mu.Unlock()
		return acme.RenewReport{APIVersion: 1, OK: false, Version: "0.5.0", Phase: acme.Phase, Results: []acme.IssueReport{{APIVersion: 1, OK: false, Certificate: "cert1", Error: "authentication failed", ErrorKind: string(dnsprovider.ErrorAuthentication), Retryable: false}}}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.RunDaemon(ctx) }()

	waitFor(t, time.Second, func() bool {
		r := a.RecoveryStatus()
		return r.Degraded && len(r.Modules) == 1 && r.Modules[0].Module == "acme" && r.Modules[0].State == recovery.StateRequiresUserAction && !r.Modules[0].Retryable
	}, "ACME permanent recovery state")

	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("permanent ACME failure retried calls=%d", gotCalls)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunDaemon: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
}

func writeRecoveryAccessCache(t *testing.T, home string) {
	t.Helper()
	path := filepath.Join(home, "access", "regions", "CN-GD.cidr")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "# HomeGate access region cache\n# region=CN-GD\n# source=test\n# updated=2026-09-11T00:00:00Z\n1.2.3.0/24\n2001:db8::/32\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonAccessStaleCacheFailureRetriesAndRecovers(t *testing.T) {
	oldDelays := accessRecoveryDelays
	accessRecoveryDelays = []time.Duration{80 * time.Millisecond, 120 * time.Millisecond}
	defer func() { accessRecoveryDelays = oldDelays }()

	cfg := recoverySnapshot()
	cfg.Main.AccessEnabled = true
	cfg.Main.AccessRegion = "CN-GD"
	a := newRecoveryTestApp(t, cfg, &transientWANRunner{}, func(config.DNSAccount) (ddns.Provider, error) { return &appRecoveryProvider{}, nil })
	writeRecoveryAccessCache(t, a.HomeDir)

	var mu sync.Mutex
	calls := 0
	a.AccessUpdater = func(context.Context, string) (access.UpdateReport, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return access.UpdateReport{APIVersion: 1, OK: true, Phase: "access", Region: "CN-GD", IPv4: 1, IPv6: 1, Source: "stale-cache", Warning: "temporary upstream failure"}, nil
		}
		return access.UpdateReport{APIVersion: 1, OK: true, Phase: "access", Region: "CN-GD", IPv4: 1, IPv6: 1, Source: "cache"}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.RunDaemon(ctx) }()

	waitFor(t, time.Second, func() bool {
		r := a.RecoveryStatus()
		return r.Degraded && len(r.Modules) == 1 && r.Modules[0].Module == "access" && r.Modules[0].State == recovery.StateRetrying && r.Modules[0].Retryable
	}, "Access retrying recovery state")
	waitFor(t, 2*time.Second, func() bool { return a.RecoveryStatus().OK }, "Access automatic recovery")

	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("Access updater calls=%d want=2", gotCalls)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunDaemon: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestDaemonWorkerPanicIsolatedAndRecovered(t *testing.T) {
	oldDelays := ddnsRecoveryDelays
	ddnsRecoveryDelays = []time.Duration{60 * time.Millisecond, 100 * time.Millisecond}
	defer func() { ddnsRecoveryDelays = oldDelays }()

	provider := &appRecoveryProvider{}
	var mu sync.Mutex
	factoryCalls := 0
	factory := func(config.DNSAccount) (ddns.Provider, error) {
		mu.Lock()
		factoryCalls++
		call := factoryCalls
		mu.Unlock()
		if call == 1 {
			panic("synthetic provider factory panic")
		}
		return provider, nil
	}

	a := newRecoveryTestApp(t, recoverySnapshot(), &transientWANRunner{}, factory)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.RunDaemon(ctx) }()

	waitFor(t, time.Second, func() bool {
		r := a.RecoveryStatus()
		return r.Degraded && len(r.Modules) == 1 && r.Modules[0].Module == "ddns" && r.Modules[0].State == recovery.StateRetrying && r.Modules[0].Retryable && r.Modules[0].ErrorKind == "runtime_failure"
	}, "worker panic isolated recovery state")

	select {
	case err := <-done:
		t.Fatalf("worker panic terminated daemon: %v", err)
	default:
	}

	waitFor(t, 2*time.Second, func() bool {
		r := a.DDNSReport()
		return r.OK && len(r.Results) == 1 && r.Results[0].Status == "unchanged" && a.RecoveryStatus().OK
	}, "worker panic bounded recovery")

	mu.Lock()
	gotFactoryCalls := factoryCalls
	mu.Unlock()
	if gotFactoryCalls != 2 {
		t.Fatalf("provider factory calls=%d want=2", gotFactoryCalls)
	}
	if provider.Calls() != 1 {
		t.Fatalf("provider calls=%d want=1", provider.Calls())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunDaemon: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestDaemonACMEWorkerPanicIsolatedAndRecovered(t *testing.T) {
	oldDelays := acmeRecoveryDelays
	acmeRecoveryDelays = []time.Duration{60 * time.Millisecond, 100 * time.Millisecond}
	defer func() { acmeRecoveryDelays = oldDelays }()

	a := newRecoveryTestApp(t, recoverySnapshot(), &transientWANRunner{}, func(config.DNSAccount) (ddns.Provider, error) { return &appRecoveryProvider{}, nil })
	var mu sync.Mutex
	calls := 0
	a.ACMERenewDue = func(context.Context, string, config.Snapshot) acme.RenewReport {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		if call == 1 {
			panic("synthetic ACME worker panic")
		}
		return acme.RenewReport{APIVersion: 1, OK: true, Version: "0.5.0", Phase: acme.Phase, Results: []acme.IssueReport{}}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.RunDaemon(ctx) }()

	waitFor(t, time.Second, func() bool {
		r := a.RecoveryStatus()
		for _, module := range r.Modules {
			if module.Module == "acme" && module.State == recovery.StateRetrying && module.Retryable && module.ErrorKind == "runtime_failure" {
				return true
			}
		}
		return false
	}, "ACME worker panic recovery state")
	waitFor(t, 2*time.Second, func() bool { return a.RecoveryStatus().OK }, "ACME worker panic recovery")

	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("ACME calls=%d want=2", gotCalls)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunDaemon: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestDaemonAccessWorkerPanicIsolatedAndRecovered(t *testing.T) {
	oldDelays := accessRecoveryDelays
	accessRecoveryDelays = []time.Duration{60 * time.Millisecond, 100 * time.Millisecond}
	defer func() { accessRecoveryDelays = oldDelays }()

	cfg := recoverySnapshot()
	cfg.Main.AccessEnabled = true
	cfg.Main.AccessRegion = "CN-GD"
	a := newRecoveryTestApp(t, cfg, &transientWANRunner{}, func(config.DNSAccount) (ddns.Provider, error) { return &appRecoveryProvider{}, nil })
	writeRecoveryAccessCache(t, a.HomeDir)

	var mu sync.Mutex
	calls := 0
	a.AccessUpdater = func(context.Context, string) (access.UpdateReport, error) {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		if call == 1 {
			panic("synthetic Access worker panic")
		}
		return access.UpdateReport{APIVersion: 1, OK: true, Phase: "access", Region: "CN-GD", IPv4: 1, IPv6: 1, Source: "cache"}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.RunDaemon(ctx) }()

	waitFor(t, time.Second, func() bool {
		r := a.RecoveryStatus()
		for _, module := range r.Modules {
			if module.Module == "access" && module.State == recovery.StateRetrying && module.Retryable && module.ErrorKind == "runtime_failure" {
				return true
			}
		}
		return false
	}, "Access worker panic recovery state")
	waitFor(t, 2*time.Second, func() bool { return a.RecoveryStatus().OK }, "Access worker panic recovery")

	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("Access calls=%d want=2", gotCalls)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunDaemon: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
}
