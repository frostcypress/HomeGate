package app

import (
	"context"
	"sync"

	"homegate.local/homegate/internal/config"
)

// daemonGeneration owns the cancellation boundary for configuration-dependent
// background work. A reload advances the generation before publishing new
// runtime state, so an older job can be cancelled and, critically, can no
// longer commit a late result into the current runtime.
type daemonGeneration struct {
	mu     sync.RWMutex
	parent context.Context
	id     uint64
	ctx    context.Context
	cancel context.CancelFunc
}

type daemonWork struct {
	Generation uint64
	Context    context.Context
	Config     config.Snapshot
}

func newDaemonGeneration(parent context.Context) *daemonGeneration {
	g := &daemonGeneration{parent: parent}
	g.advanceLocked()
	return g
}

func (g *daemonGeneration) advanceLocked() {
	if g.cancel != nil {
		g.cancel()
	}
	g.id++
	g.ctx, g.cancel = context.WithCancel(g.parent)
}

func (g *daemonGeneration) Advance(cfg config.Snapshot) daemonWork {
	g.mu.Lock()
	g.advanceLocked()
	work := daemonWork{Generation: g.id, Context: g.ctx, Config: cfg}
	g.mu.Unlock()
	return work
}

func (g *daemonGeneration) Work(cfg config.Snapshot) daemonWork {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return daemonWork{Generation: g.id, Context: g.ctx, Config: cfg}
}

func (g *daemonGeneration) IsCurrent(id uint64) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.id == id && g.ctx != nil && g.ctx.Err() == nil
}

// Commit linearizes an async worker side effect against generation changes.
// Advance/Stop take the write lock, so once a newer generation exists an older
// worker cannot publish late runtime state. If the worker acquires this read
// lock first, its commit is defined to happen before the generation transition.
func (g *daemonGeneration) Commit(id uint64, fn func() error) (bool, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.id != id || g.ctx == nil || g.ctx.Err() != nil {
		return false, nil
	}
	if fn == nil {
		return true, nil
	}
	return true, fn()
}

func (g *daemonGeneration) Stop() {
	g.mu.Lock()
	if g.cancel != nil {
		g.cancel()
	}
	g.mu.Unlock()
}
