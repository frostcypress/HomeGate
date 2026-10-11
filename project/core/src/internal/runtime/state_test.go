package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreLifecycle(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "runtime.json")}
	before, err := s.Probe()
	if err != nil || before.Running {
		t.Fatalf("unexpected initial probe: %+v err=%v", before, err)
	}
	state, err := s.MarkStarted("0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if state.PID != os.Getpid() {
		t.Fatalf("pid=%d want=%d", state.PID, os.Getpid())
	}
	probe, err := s.Probe()
	if err != nil || !probe.Running || probe.State == nil {
		t.Fatalf("unexpected running probe: %+v err=%v", probe, err)
	}
	if err := s.Clear(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	after, err := s.Probe()
	if err != nil || after.Running || after.State != nil {
		t.Fatalf("unexpected final probe: %+v err=%v", after, err)
	}
}

func writeFakeProcStat(t *testing.T, root string, pid int, startTicks uint64) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// fields after ")" start at proc stat field 3. Put starttime at field 22.
	fields := []string{"S"}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	fields = append(fields, fmt.Sprint(startTicks))
	fields = append(fields, "0", "0")
	line := fmt.Sprintf("%d (homegate test) %s\n", pid, strings.Join(fields, " "))
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProbeRejectsReusedPIDByProcessStartTicks(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	path := filepath.Join(dir, "runtime.json")
	pid := os.Getpid()
	writeFakeProcStat(t, proc, pid, 222)
	state := State{PID: pid, StartedAt: time.Now().UTC(), Version: "0.5.0", ProcessStartTicks: 111}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	probe, err := (Store{Path: path, ProcRoot: proc}).Probe()
	if err != nil {
		t.Fatal(err)
	}
	if probe.Running {
		t.Fatalf("reused pid reported running: %+v", probe)
	}
	if probe.State == nil || probe.State.PID != pid {
		t.Fatalf("probe lost stale state: %+v", probe)
	}
}

func TestProbeAcceptsMatchingProcessStartTicks(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	path := filepath.Join(dir, "runtime.json")
	pid := os.Getpid()
	writeFakeProcStat(t, proc, pid, 333)
	state := State{PID: pid, StartedAt: time.Now().UTC(), Version: "0.5.0", ProcessStartTicks: 333}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	probe, err := (Store{Path: path, ProcRoot: proc}).Probe()
	if err != nil || !probe.Running {
		t.Fatalf("matching process identity rejected: %+v err=%v", probe, err)
	}
}

func TestProbeKeepsLegacyPIDOnlyStateCompatible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	state := State{PID: os.Getpid(), StartedAt: time.Now().UTC(), Version: "0.5.0"}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	probe, err := (Store{Path: path, ProcRoot: filepath.Join(t.TempDir(), "missing-proc")}).Probe()
	if err != nil || !probe.Running {
		t.Fatalf("legacy runtime state lost compatibility: %+v err=%v", probe, err)
	}
}
