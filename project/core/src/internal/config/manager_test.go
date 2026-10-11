package config

import (
	"context"
	"errors"
	"testing"
)

type sequenceLoader struct {
	values []Snapshot
	errs   []error
	index  int
}

func (l *sequenceLoader) Load(context.Context) (Snapshot, error) {
	i := l.index
	l.index++
	var s Snapshot
	if i < len(l.values) {
		s = l.values[i]
	}
	if i < len(l.errs) {
		return s, l.errs[i]
	}
	return s, nil
}

func TestManagerKeepsLastGoodSnapshotOnReloadError(t *testing.T) {
	good := Snapshot{Configured: true, Main: Main{Enabled: true, LogLevel: "info", LogMaxLines: 1024}}
	loader := &sequenceLoader{
		values: []Snapshot{good, {}},
		errs:   []error{nil, errors.New("bad reload")},
	}
	m := NewManager(loader)
	if _, err := m.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reload(context.Background()); err == nil {
		t.Fatal("expected reload error")
	}
	got, ok := m.Current()
	if !ok || got.Main.LogLevel != "info" || !got.Main.Enabled {
		t.Fatalf("last good snapshot lost: %+v ok=%v", got, ok)
	}
}

func TestManagerWithoutLoader(t *testing.T) {
	m := NewManager(nil)
	if _, err := m.Reload(context.Background()); !errors.Is(err, ErrNoLoader) {
		t.Fatalf("err=%v", err)
	}
}

func TestManagerCandidateDoesNotPublishUntilCommit(t *testing.T) {
	old := Snapshot{Configured: true, Main: Main{Enabled: true, LogLevel: "info", LogMaxLines: 1024}}
	next := Snapshot{Configured: true, Main: Main{Enabled: false, LogLevel: "debug", LogMaxLines: 2048}}
	loader := &sequenceLoader{values: []Snapshot{old, next}}
	m := NewManager(loader)
	if _, err := m.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	candidate, err := m.LoadCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := m.Current()
	if !ok || got.Main.LogLevel != "info" || !got.Main.Enabled {
		t.Fatalf("candidate leaked into Current before commit: %+v ok=%v", got, ok)
	}
	m.Commit(candidate)
	got, ok = m.Current()
	if !ok || got.Main.LogLevel != "debug" || got.Main.Enabled {
		t.Fatalf("candidate not committed: %+v ok=%v", got, ok)
	}
}
