package acme

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const certificateLockPoll = 100 * time.Millisecond

func (s Service) certificateLockPath(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || id == "." || id == ".." || filepath.Base(id) != id {
		return ""
	}
	home := filepath.Clean(strings.TrimSpace(s.HomeDir))
	if home == "." || home == "" || home == "/etc/homegate" {
		return filepath.Join("/var/run/homegate/acme-lock", id+".lock")
	}
	return filepath.Join(home, "runtime", "acme-lock", id+".lock")
}

func (s Service) acquireCertificateLock(ctx context.Context, id string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("wait for certificate renewal lock: %w", err)
	}
	path := s.certificateLockPath(id)
	if path == "" {
		return nil, fmt.Errorf("invalid certificate id for renewal lock")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create certificate renewal lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open certificate renewal lock: %w", err)
	}
	release := func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return release, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			_ = f.Close()
			return nil, fmt.Errorf("lock certificate renewal: %w", err)
		}
		timer := time.NewTimer(certificateLockPoll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = f.Close()
			return nil, fmt.Errorf("wait for certificate renewal lock: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
