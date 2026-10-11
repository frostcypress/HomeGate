package app

import (
	"context"
	"testing"
	"time"

	"homegate.local/homegate/internal/config"
)

func TestDaemonGenerationAdvanceCancelsOldWork(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newDaemonGeneration(parent)
	old := g.Work(config.Snapshot{Main: config.Main{LogLevel: "info"}})
	if !g.IsCurrent(old.Generation) {
		t.Fatal("initial generation should be current")
	}
	next := g.Advance(config.Snapshot{Main: config.Main{LogLevel: "debug"}})
	select {
	case <-old.Context.Done():
	default:
		t.Fatal("old generation context was not cancelled")
	}
	if g.IsCurrent(old.Generation) {
		t.Fatal("old generation remained current")
	}
	if !g.IsCurrent(next.Generation) || next.Config.Main.LogLevel != "debug" {
		t.Fatalf("new generation not current: %+v", next)
	}
}

func TestDaemonGenerationStopInvalidatesCurrent(t *testing.T) {
	g := newDaemonGeneration(context.Background())
	work := g.Work(config.Snapshot{})
	g.Stop()
	if g.IsCurrent(work.Generation) {
		t.Fatal("stopped generation remained current")
	}
	select {
	case <-work.Context.Done():
	default:
		t.Fatal("stop did not cancel current context")
	}
}

func TestDaemonGenerationCommitRejectsStaleWork(t *testing.T) {
	g := newDaemonGeneration(context.Background())
	old := g.Work(config.Snapshot{})
	_ = g.Advance(config.Snapshot{})
	called := false
	committed, err := g.Commit(old.Generation, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if committed || called {
		t.Fatalf("stale commit escaped fence: committed=%v called=%v", committed, called)
	}
}

func TestDaemonGenerationCommitLinearizesWithAdvance(t *testing.T) {
	g := newDaemonGeneration(context.Background())
	work := g.Work(config.Snapshot{})
	entered := make(chan struct{})
	release := make(chan struct{})
	commitDone := make(chan struct{})
	go func() {
		defer close(commitDone)
		committed, err := g.Commit(work.Generation, func() error {
			close(entered)
			<-release
			return nil
		})
		if err != nil || !committed {
			t.Errorf("commit err=%v committed=%v", err, committed)
		}
	}()
	<-entered

	advanceDone := make(chan daemonWork, 1)
	go func() {
		advanceDone <- g.Advance(config.Snapshot{})
	}()
	select {
	case <-advanceDone:
		t.Fatal("Advance passed an in-flight commit fence")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	<-commitDone
	select {
	case next := <-advanceDone:
		if next.Generation == work.Generation || !g.IsCurrent(next.Generation) {
			t.Fatalf("bad next generation: %+v", next)
		}
	case <-time.After(time.Second):
		t.Fatal("Advance did not complete after commit released")
	}
}

func TestDaemonGenerationStopRejectsCommit(t *testing.T) {
	g := newDaemonGeneration(context.Background())
	work := g.Work(config.Snapshot{})
	g.Stop()
	called := false
	committed, err := g.Commit(work.Generation, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if committed || called {
		t.Fatalf("stopped generation committed: committed=%v called=%v", committed, called)
	}
}
