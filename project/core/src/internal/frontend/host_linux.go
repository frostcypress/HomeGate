package frontend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// OSHost is only used by the privileged local bridge. The remote RPC API cannot
// provide command text, source code, filesystem roots or executable paths.
type OSHost struct{ touchedRuntime bool }

func (h *OSHost) Read(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	const limit = 32 * 1024 * 1024
	// Reading logs must never allocate the whole growing log file. Preserve the
	// newest complete lines; the controller's ring then applies its line limit.
	const logLimit = 8 * 1024 * 1024
	truncated := path == "/var/log/homegate.log" && info.Size() > logLimit
	if truncated {
		if _, err = file.Seek(-logLimit, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("file exceeds bridge limit")
	}
	if truncated {
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			body = body[i+1:]
		} else {
			body = nil
		}
	}
	return body, nil
}
func (h *OSHost) Remove(path string) error             { return os.Remove(path) }
func (h *OSHost) Chmod(path string, mode uint32) error { return os.Chmod(path, fs.FileMode(mode)) }
func (h *OSHost) Stat(path string) (map[string]any, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return map[string]any{"mtime": st.ModTime().Unix(), "size": st.Size()}, nil
}
func (h *OSHost) Write(path string, body []byte) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !parent.IsDir() || !ownedByProcess(parent) || (parent.Mode().Perm()&0022 != 0 && parent.Mode()&os.ModeSticky == 0) {
		return fmt.Errorf("unsafe private file parent")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !ownedByProcess(info) {
		return fmt.Errorf("unsafe private file")
	}
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if err = file.Truncate(0); err != nil {
		return err
	}
	_, err = file.Write(body)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func (h *OSHost) Shell(ctx context.Context, text string) (string, int) {
	if strings.Contains(text, "/etc/init.d/homegate ") && (strings.Contains(text, " reload") || strings.Contains(text, " start") || strings.Contains(text, " stop") || strings.Contains(text, " enable ") || strings.Contains(text, " disable ")) {
		h.touchedRuntime = true
	}

	// The frozen controller uses opkg's metadata shape. Translate only its three
	// constant package queries on APK firmware, preserving the full release.
	if strings.HasPrefix(text, "opkg status ") {
		if _, err := exec.LookPath("opkg"); err != nil {
			fields := strings.Fields(text)
			if len(fields) < 3 {
				return "", 1
			}
			pkg := fields[2]
			if pkg != "homegate" && pkg != "luci-app-homegate" && pkg != "luci-i18n-homegate-zh-cn" {
				return "", 1
			}
			output, err := exec.CommandContext(ctx, "apk", "list", "-I", pkg).Output()
			if err != nil {
				return "", 1
			}
			for _, line := range strings.Split(string(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 || !strings.HasPrefix(fields[0], pkg+"-") {
					continue
				}
				version := strings.Replace(strings.TrimPrefix(fields[0], pkg+"-"), "-r", "-", 1)
				if len(fields) < 2 {
					return "", 1
				}
				arch := fields[1]
				if pkg != "homegate" {
					arch = "all"
				}
				return fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\n", pkg, version, arch), 0
			}
			return "", 1
		}
	}
	command := exec.CommandContext(ctx, "/bin/sh", "-c", text)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 2 * time.Second
	output, err := command.Output()
	if err == nil {
		return string(output), 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(output), exit.ExitCode()
	}
	return string(output), 1
}
func (h *OSHost) Load(ctx context.Context, pkg string) (*Document, error) {
	if pkg != "homegate" && pkg != "network" && pkg != "dhcp" {
		return nil, fmt.Errorf("unsupported configuration")
	}
	out, err := exec.CommandContext(ctx, "uci", "-q", "-X", "show", pkg).Output()
	if err != nil {
		return nil, err
	}
	document, err := ParseDocument(string(out), pkg)
	if err != nil {
		return nil, err
	}
	exported, err := exec.CommandContext(ctx, "uci", "-q", "export", pkg).Output()
	if err != nil {
		return nil, err
	}
	if err := document.RestoreListTypes(string(exported)); err != nil {
		return nil, err
	}
	return document, nil
}
func atomicConfig(body []byte) error {
	file, err := os.CreateTemp("/etc/config", ".homegate-frontend-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, "/etc/config/homegate")
}
func (h *OSHost) Commit(ctx context.Context, document *Document) error {
	text, err := document.Text()
	if err != nil {
		return err
	}
	return atomicConfig([]byte(text))
}

func isDaemonCommand(body []byte) bool {
	args := bytes.Split(bytes.TrimRight(body, "\x00"), []byte{0})
	return len(args) == 2 && filepath.Base(string(args[0])) == "homegate" && string(args[1]) == "daemon"
}
func daemonRunning() bool {
	processes, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, path := range processes {
		body, err := os.ReadFile(path)
		if err == nil && isDaemonCommand(body) {
			return true
		}
	}
	return false
}

// Begin serializes writers and captures only HomeGate-owned persistent state.
// On a failed configuration action, restore config and original boot/run intent.
// Independent certificate renewals are deliberately outside this transaction.
func (h *OSHost) Begin(ctx context.Context) (func(bool) error, error) {
	if err := os.MkdirAll("/var/run/homegate", 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile("/var/run/homegate/frontend.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			lock.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			lock.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	release := func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }
	config, configErr := os.ReadFile("/etc/config/homegate")
	if configErr != nil && !os.IsNotExist(configErr) {
		release()
		return nil, configErr
	}
	wasRunning := daemonRunning()
	_, wasEnabled := h.Shell(ctx, "/etc/init.d/homegate enabled >/dev/null 2>&1")
	return func(success bool) error {
		defer release()
		if success {
			return nil
		}
		current, currentErr := os.ReadFile("/etc/config/homegate")
		// Validation failures must not rewrite files or disturb running services.
		// Certificate renewals run independently: never restore an entire tree
		// from an old snapshot, which could overwrite a successful renewal.
		if bytes.Equal(current, config) && errors.Is(currentErr, configErr) && !h.touchedRuntime {
			return nil
		}
		if configErr == nil {
			if err := atomicConfig(config); err != nil {
				return err
			}
		} else if err := os.Remove("/etc/config/homegate"); err != nil && !os.IsNotExist(err) {
			return err
		}
		// Use an independent bounded context even if the request timed out.
		recovery, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		return restoreIntent(recovery, h.Shell, wasRunning, wasEnabled == 0)
	}, nil
}

func restoreIntent(ctx context.Context, shell func(context.Context, string) (string, int), running, enabled bool) error {
	var failures []error
	action := "stop"
	if running {
		action = "reload"
	}
	if _, code := shell(ctx, "/etc/init.d/homegate "+action+" >/dev/null 2>&1"); code != 0 {
		failures = append(failures, fmt.Errorf("runtime recovery failed"))
	}
	// Even if runtime recovery fails, still attempt to restore boot intent.
	action = "disable"
	if enabled {
		action = "enable"
	}
	if _, code := shell(ctx, "/etc/init.d/homegate "+action+" >/dev/null 2>&1"); code != 0 {
		failures = append(failures, fmt.Errorf("boot intent recovery failed"))
	}
	return errors.Join(failures...)
}
