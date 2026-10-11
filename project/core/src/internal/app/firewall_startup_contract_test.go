package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/firewall"
	"homegate.local/homegate/internal/network"
	"homegate.local/homegate/internal/proxy"
	runtimestate "homegate.local/homegate/internal/runtime"
)

type permanentFirewallRunner struct{}

func (permanentFirewallRunner) Run(_ context.Context, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	if strings.Contains(line, " -D ") || strings.Contains(line, " -F ") || strings.Contains(line, " -X ") {
		return errors.New("not present")
	}
	if strings.Contains(line, " -N HOMEGATE_NAT") {
		return errors.New("permanent firewall startup failure")
	}
	return nil
}

func startupFirewallConfig(httpPort, httpsPort int) config.Snapshot {
	return config.Snapshot{
		Configured: true,
		Main: config.Main{
			Enabled:        true,
			LogLevel:       "info",
			LogMaxLines:    1024,
			DDNSInterval:   300,
			ProxyHTTPPort:  httpPort,
			ProxyHTTPSPort: httpsPort,
			HTTPPort:       80,
			HTTPSPort:      443,
			AutoFirewall:   true,
			AccessEnabled:  false,
			WOLInterface:   config.DefaultWOLInterface,
		},
		Web: []config.WebRule{{
			ID:      "web1",
			Enabled: true,
			Domain:  "startup-firewall.example.com",
			Target:  "http://[::1]:9",
			HTTPS:   false,
		}},
	}
}

func freeTCP6Port(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestPermanentFirewallStartupFailureIsFailFastAndReleasesRuntime(t *testing.T) {
	dir := t.TempDir()
	httpPort := freeTCP6Port(t)
	httpsPort := freeTCP6Port(t)
	loader := &staticSnapshotLoader{cfg: startupFirewallConfig(httpPort, httpsPort)}
	fwStatusPath := filepath.Join(dir, "firewall.json")
	a := App{
		Version:         "0.5.0",
		Config:          config.NewManager(loader),
		Runtime:         runtimestate.Store{Path: filepath.Join(dir, "runtime.json")},
		LogPath:         filepath.Join(dir, "homegate.log"),
		HomeDir:         filepath.Join(dir, "home"),
		ProxyStatusPath: filepath.Join(dir, "proxy.json"),
		DaemonLockPath:  filepath.Join(dir, "daemon.lock"),
		Firewall: firewall.Controller{
			Runner:           permanentFirewallRunner{},
			Network:          network.New(appWANRunner{}),
			StatusPath:       fwStatusPath,
			CompatStatusPath: filepath.Join(dir, "firewall.status"),
		},
	}

	start := time.Now()
	err := a.RunDaemon(context.Background())
	if err == nil || !strings.Contains(err.Error(), "firewall startup apply") {
		t.Fatalf("RunDaemon error = %v, want permanent firewall startup failure", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("permanent firewall startup failure did not fail fast")
	}
	if _, statErr := os.Stat(a.Runtime.Path); !os.IsNotExist(statErr) {
		t.Fatalf("runtime state left after failed startup: %v", statErr)
	}
	lock, lockErr := runtimestate.AcquireDaemonLock(a.DaemonLockPath)
	if lockErr != nil {
		t.Fatalf("daemon lock not released after failed startup: %v", lockErr)
	}
	_ = lock.Close()

	proxyStatus, readErr := proxy.ReadStatus(a.ProxyStatusPath, a.Version)
	if readErr != nil {
		t.Fatalf("read proxy status: %v", readErr)
	}
	if proxyStatus.HTTPListening || proxyStatus.HTTPSListening {
		t.Fatalf("proxy status left listening after failed startup: %+v", proxyStatus)
	}

	fwStatus := a.Firewall.Read(a.Version)
	if fwStatus.OK || fwStatus.Active || !strings.Contains(fwStatus.Error, "permanent firewall startup failure") {
		t.Fatalf("firewall failure status lost after fail-fast: %+v", fwStatus)
	}

	ln, listenErr := net.Listen("tcp6", "[::]:"+fmt.Sprint(httpPort))
	if listenErr != nil {
		t.Fatalf("proxy HTTP listener not released after failed startup: %v", listenErr)
	}
	_ = ln.Close()
}

type unavailableWANRunner struct{}

func (unavailableWANRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	return nil, errors.New("WAN not ready")
}

func TestRetryableWANStartupFailureKeepsDaemonForBoundedRecovery(t *testing.T) {
	dir := t.TempDir()
	httpPort := freeTCP6Port(t)
	cfg := startupFirewallConfig(httpPort, freeTCP6Port(t))
	loader := &staticSnapshotLoader{cfg: cfg}
	a := App{
		Version:         "0.5.0",
		Config:          config.NewManager(loader),
		Runtime:         runtimestate.Store{Path: filepath.Join(dir, "runtime.json")},
		LogPath:         filepath.Join(dir, "homegate.log"),
		HomeDir:         filepath.Join(dir, "home"),
		ProxyStatusPath: filepath.Join(dir, "proxy.json"),
		DaemonLockPath:  filepath.Join(dir, "daemon.lock"),
		Firewall: firewall.Controller{
			Runner:           &appFirewallRunner{},
			Network:          network.New(unavailableWANRunner{}),
			StatusPath:       filepath.Join(dir, "firewall.json"),
			CompatStatusPath: filepath.Join(dir, "firewall.status"),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := a.RunDaemon(ctx)
	if err != nil {
		t.Fatalf("retryable WAN startup failure must stay resident, got %v", err)
	}
	if time.Since(start) < 60*time.Millisecond {
		t.Fatalf("retryable WAN startup failure returned before context cancellation")
	}
	if _, statErr := os.Stat(a.Runtime.Path); !os.IsNotExist(statErr) {
		t.Fatalf("runtime state not cleared at final shutdown: %v", statErr)
	}
}
