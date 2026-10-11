package logger

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const DefaultPath = "/var/log/homegate.log"

var (
	querySecretRE = regexp.MustCompile(`(?i)(accesskeyid|access_key_id|accesskeysecret|access_key_secret|signature|signaturenonce|token|api[_-]?token|secret|password)=([^&\s"]+)`)
	authHeaderRE  = regexp.MustCompile(`(?i)(authorization:\s*)([^\s]+(?:\s+[^\s]+)?)`)
)

// Sanitize removes credentials and request-signing material before a message is
// written to stderr or persistent storage. Provider code must still avoid
// logging secrets directly; this is a final common-layer safety net.
func Sanitize(message string) string {
	message = querySecretRE.ReplaceAllString(message, `$1=<redacted>`)
	message = authHeaderRE.ReplaceAllString(message, `$1<redacted>`)
	return message
}

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

type Logger struct {
	mu       sync.Mutex
	level    Level
	path     string
	maxLines int
	writes   int
}

func New(level, path string, maxLines int) *Logger {
	if path == "" {
		path = DefaultPath
	}
	if maxLines <= 0 {
		maxLines = 1024
	}
	return &Logger{level: parseLevel(level), path: path, maxLines: maxLines}
}

func parseLevel(v string) Level {
	switch strings.ToLower(v) {
	case "debug":
		return Debug
	case "warn":
		return Warn
	case "error":
		return Error
	default:
		return Info
	}
}

// Reconfigure applies validated common logging settings without restarting the
// daemon. The log path is intentionally fixed for the process lifetime.
func (l *Logger) Reconfigure(level string, maxLines int) {
	if maxLines <= 0 {
		maxLines = 1024
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = parseLevel(level)
	l.maxLines = maxLines
	_ = trimFile(l.path, maxLines)
}

func (l *Logger) Debugf(format string, args ...any) { l.log(Debug, "DEBUG", format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.log(Info, "INFO", format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.log(Warn, "WARN", format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.log(Error, "ERROR", format, args...) }

func (l *Logger) log(level Level, label, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level < l.level {
		return
	}

	message := Sanitize(fmt.Sprintf(format, args...))
	line := fmt.Sprintf("%s [%s] %s", time.Now().Format("2006-01-02 15:04:05"), label, message)
	fmt.Fprintln(os.Stderr, line)

	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(f, line)
	_ = f.Close()
	l.writes++
	if l.writes == 1 || l.writes%128 == 0 {
		_ = trimFile(l.path, l.maxLines)
	}
}

func trimFile(path string, maxLines int) error {
	if maxLines <= 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	lines, truncated, err := readTail(f, maxLines)
	if err != nil {
		return err
	}
	if !truncated {
		return nil
	}
	// Release the input handle before replacing the file.
	if err := f.Close(); err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	if err := out.Chmod(0o600); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	w := bufio.NewWriter(out)
	for _, line := range lines {
		_, _ = fmt.Fprintln(w, line)
	}
	if err := w.Flush(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
