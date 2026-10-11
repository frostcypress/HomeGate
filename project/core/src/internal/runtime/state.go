package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"homegate.local/homegate/internal/runtimefile"
)

const DefaultStatePath = "/var/run/homegate/runtime.json"

type State struct {
	PID               int       `json:"pid"`
	StartedAt         time.Time `json:"started_at"`
	Version           string    `json:"version"`
	ProcessStartTicks uint64    `json:"process_start_ticks,omitempty"`
}

type Probe struct {
	Running bool   `json:"running"`
	State   *State `json:"state,omitempty"`
}

type Store struct {
	Path     string
	ProcRoot string
}

func NewStore() Store {
	return Store{Path: DefaultStatePath}
}

func (s Store) path() string {
	if s.Path == "" {
		return DefaultStatePath
	}
	return s.Path
}

func (s Store) procRoot() string {
	if s.ProcRoot == "" {
		return "/proc"
	}
	return s.ProcRoot
}

func (s Store) processStartTicks(pid int) (uint64, error) {
	b, err := os.ReadFile(filepath.Join(s.procRoot(), strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(string(b))
	endComm := strings.LastIndexByte(line, ')')
	if endComm < 0 || endComm+1 >= len(line) {
		return 0, fmt.Errorf("invalid proc stat for pid %d", pid)
	}
	fields := strings.Fields(line[endComm+1:])
	// /proc/<pid>/stat field 22 is process start time in clock ticks. fields
	// starts at field 3 (state), so starttime is index 19 here.
	if len(fields) <= 19 {
		return 0, fmt.Errorf("invalid proc stat for pid %d: missing starttime", pid)
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse proc starttime for pid %d: %w", pid, err)
	}
	return ticks, nil
}

func (s Store) MarkStarted(version string) (State, error) {
	state := State{PID: os.Getpid(), StartedAt: time.Now().UTC(), Version: version}
	// ProcessStartTicks makes runtime.json resilient to PID reuse. Keep the
	// field optional so legacy state files and unusual systems without readable
	// procfs retain the historical live-PID fallback rather than blocking start.
	if ticks, err := s.processStartTicks(state.PID); err == nil {
		state.ProcessStartTicks = ticks
	}
	if err := runtimefile.WriteJSONAtomic(s.path(), state, 0o644); err != nil {
		return State{}, fmt.Errorf("write runtime state: %w", err)
	}
	return state, nil
}

func (s Store) Clear(pid int) error {
	probe, err := s.Probe()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if probe.State != nil && probe.State.PID != pid {
		return nil
	}
	if err := os.Remove(s.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove runtime state: %w", err)
	}
	return nil
}

func (s Store) Probe() (Probe, error) {
	data, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Probe{Running: false}, nil
		}
		return Probe{}, fmt.Errorf("read runtime state: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return Probe{}, fmt.Errorf("decode runtime state: %w", err)
	}
	if state.PID <= 0 {
		return Probe{Running: false, State: &state}, nil
	}
	err = syscall.Kill(state.PID, 0)
	if err == nil || errors.Is(err, syscall.EPERM) {
		if state.ProcessStartTicks != 0 {
			actual, statErr := s.processStartTicks(state.PID)
			if statErr != nil {
				if errors.Is(statErr, os.ErrNotExist) {
					return Probe{Running: false, State: &state}, nil
				}
				return Probe{}, fmt.Errorf("verify daemon pid %d identity: %w", state.PID, statErr)
			}
			if actual != state.ProcessStartTicks {
				return Probe{Running: false, State: &state}, nil
			}
		}
		return Probe{Running: true, State: &state}, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return Probe{Running: false, State: &state}, nil
	}
	return Probe{}, fmt.Errorf("probe daemon pid %d: %w", state.PID, err)
}
