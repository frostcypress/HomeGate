package recovery

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"homegate.local/homegate/internal/api"
	"homegate.local/homegate/internal/runtimefile"
)

const (
	Phase             = "recovery"
	DefaultStatusPath = "/var/run/homegate/recovery.json"
)

type State string

const (
	StateRetrying           State = "retrying"
	StateDegraded           State = "degraded"
	StateRequiresUserAction State = "requires_user_action"
)

type ModuleStatus struct {
	Module      string `json:"module"`
	State       State  `json:"state"`
	Retryable   bool   `json:"retryable"`
	Attempt     int    `json:"attempt,omitempty"`
	MaxAttempts int    `json:"max_attempts,omitempty"`
	NextRetryAt string `json:"next_retry_at,omitempty"`
	ErrorKind   string `json:"error_kind,omitempty"`
	Error       string `json:"error,omitempty"`
	UpdatedAt   string `json:"updated_at"`
}

type Report struct {
	APIVersion int            `json:"api_version"`
	OK         bool           `json:"ok"`
	Version    string         `json:"version"`
	Phase      string         `json:"phase"`
	Degraded   bool           `json:"degraded"`
	Modules    []ModuleStatus `json:"modules"`
}

type Store struct{ Path string }

func (s Store) path() string { return strings.TrimSpace(s.Path) }

func Empty(version string) Report {
	return Report{APIVersion: api.Version, OK: true, Version: version, Phase: Phase, Degraded: false, Modules: []ModuleStatus{}}
}

func (r *Report) normalize() {
	if r.APIVersion == 0 {
		r.APIVersion = api.Version
	}
	if r.Phase == "" {
		r.Phase = Phase
	}
	if r.Modules == nil {
		r.Modules = []ModuleStatus{}
	}
	sort.Slice(r.Modules, func(i, j int) bool { return r.Modules[i].Module < r.Modules[j].Module })
	r.Degraded = len(r.Modules) > 0
	r.OK = !r.Degraded
}

func (r *Report) Set(module string, state State, retryable bool, attempt, maxAttempts int, nextRetry time.Time, errorKind, message string, now time.Time) {
	module = strings.TrimSpace(module)
	if module == "" {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	st := ModuleStatus{
		Module:      module,
		State:       state,
		Retryable:   retryable,
		Attempt:     attempt,
		MaxAttempts: maxAttempts,
		ErrorKind:   strings.TrimSpace(errorKind),
		Error:       strings.TrimSpace(message),
		UpdatedAt:   now.UTC().Format(time.RFC3339),
	}
	if !nextRetry.IsZero() {
		st.NextRetryAt = nextRetry.UTC().Format(time.RFC3339)
	}
	for i := range r.Modules {
		if r.Modules[i].Module == module {
			r.Modules[i] = st
			r.normalize()
			return
		}
	}
	r.Modules = append(r.Modules, st)
	r.normalize()
}

func (r Report) HasModule(module string) bool {
	module = strings.TrimSpace(module)
	for _, st := range r.Modules {
		if st.Module == module {
			return true
		}
	}
	return false
}

func (r *Report) ClearModule(module string) {
	module = strings.TrimSpace(module)
	if module == "" || len(r.Modules) == 0 {
		r.normalize()
		return
	}
	out := r.Modules[:0]
	for _, st := range r.Modules {
		if st.Module != module {
			out = append(out, st)
		}
	}
	r.Modules = out
	r.normalize()
}

func (s Store) Write(report Report) error {
	if s.path() == "" {
		return nil
	}
	report.normalize()
	return runtimefile.WriteJSONAtomic(s.path(), report, 0o644)
}

func (s Store) Read(version string) Report {
	if s.path() == "" {
		return Empty(version)
	}
	b, err := os.ReadFile(s.path())
	if err != nil {
		return Empty(version)
	}
	var r Report
	if json.Unmarshal(b, &r) != nil {
		return Empty(version)
	}
	if strings.TrimSpace(r.Version) == "" {
		r.Version = version
	}
	r.normalize()
	return r
}

func (s Store) Clear() error {
	if s.path() == "" {
		return nil
	}
	err := os.Remove(s.path())
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
