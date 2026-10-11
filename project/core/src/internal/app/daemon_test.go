package app

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"homegate.local/homegate/internal/config"
	runtimestate "homegate.local/homegate/internal/runtime"
)

type staticSnapshotLoader struct {
	cfg   config.Snapshot
	calls int
}

func (l *staticSnapshotLoader) Load(context.Context) (config.Snapshot, error) {
	l.calls++
	return l.cfg, nil
}

func TestRunDaemonRejectsSecondOwnerBeforeConfigOrRuntimeMutation(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "daemon.lock")
	runtimePath := filepath.Join(dir, "runtime.json")

	held, err := runtimestate.AcquireDaemonLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	loader := &staticSnapshotLoader{}
	a := App{
		Config:         config.NewManager(loader),
		Runtime:        runtimestate.Store{Path: runtimePath},
		DaemonLockPath: lockPath,
	}
	err = a.RunDaemon(context.Background())
	if !errors.Is(err, runtimestate.ErrDaemonAlreadyRunning) {
		t.Fatalf("RunDaemon error = %v, want ErrDaemonAlreadyRunning", err)
	}
	if loader.calls != 0 {
		t.Fatalf("config loader called %d times before singleton rejection", loader.calls)
	}
	if _, statErr := os.Stat(runtimePath); !os.IsNotExist(statErr) {
		t.Fatalf("runtime state mutated by rejected daemon: %v", statErr)
	}
}

func TestRunDaemonProxyStartupFailureIsFailFastAndClearsRuntime(t *testing.T) {
	blocker, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 wildcard listener unavailable: %v", err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port

	cfg := config.Snapshot{
		Configured: true,
		Main: config.Main{
			Enabled:        true,
			LogLevel:       "info",
			LogMaxLines:    1024,
			DDNSInterval:   300,
			ProxyHTTPPort:  port,
			ProxyHTTPSPort: port + 1,
			HTTPPort:       80,
			HTTPSPort:      443,
			AutoFirewall:   true,
			AccessEnabled:  false,
			WOLInterface:   config.DefaultWOLInterface,
		},
		Web: []config.WebRule{{
			ID:      "web1",
			Enabled: true,
			Domain:  "startup.example.com",
			Target:  "http://[::1]:9",
			HTTPS:   false,
		}},
	}

	dir := t.TempDir()
	loader := &staticSnapshotLoader{cfg: cfg}
	a := App{
		Version:         "0.5.0",
		Config:          config.NewManager(loader),
		Runtime:         runtimestate.Store{Path: filepath.Join(dir, "runtime.json")},
		LogPath:         filepath.Join(dir, "homegate.log"),
		HomeDir:         filepath.Join(dir, "home"),
		ProxyStatusPath: filepath.Join(dir, "proxy.json"),
		DaemonLockPath:  filepath.Join(dir, "daemon.lock"),
	}
	attachNoopFirewall(&a, t)

	err = a.RunDaemon(context.Background())
	if err == nil || !strings.Contains(err.Error(), "proxy startup apply") {
		t.Fatalf("RunDaemon error = %v, want proxy startup failure", err)
	}
	if _, statErr := os.Stat(a.Runtime.Path); !os.IsNotExist(statErr) {
		t.Fatalf("runtime state left after failed startup: %v", statErr)
	}
	lock, lockErr := runtimestate.AcquireDaemonLock(a.DaemonLockPath)
	if lockErr != nil {
		t.Fatalf("daemon lock not released after failed startup: %v", lockErr)
	}
	_ = lock.Close()
}
