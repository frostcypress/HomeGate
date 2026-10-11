package runtime

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestDaemonLockRejectsConcurrentOwnerAndReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lock")
	first, err := AcquireDaemonLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	if _, err := AcquireDaemonLock(path); !errors.Is(err, ErrDaemonAlreadyRunning) {
		t.Fatalf("second lock error = %v, want ErrDaemonAlreadyRunning", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireDaemonLock(path)
	if err != nil {
		t.Fatalf("lock not reusable after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
