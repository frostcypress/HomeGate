package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const DefaultDaemonLockPath = "/var/run/homegate/daemon.lock"

var ErrDaemonAlreadyRunning = errors.New("homegate daemon is already running")

type DaemonLock struct {
	file *os.File
}

func AcquireDaemonLock(path string) (*DaemonLock, error) {
	if path == "" {
		path = DefaultDaemonLockPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create daemon lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open daemon lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrDaemonAlreadyRunning
		}
		return nil, fmt.Errorf("lock daemon singleton: %w", err)
	}
	return &DaemonLock{file: f}, nil
}

func (l *DaemonLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	closeErr := f.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock daemon singleton: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close daemon lock: %w", closeErr)
	}
	return nil
}
