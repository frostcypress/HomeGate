package config

import (
	"context"
	"sync"
)

// Manager owns the daemon's current immutable common-config snapshot.
// Reload validates a fresh snapshot first and only publishes it on success,
// so a malformed UCI edit cannot replace the last known-good configuration.
type Manager struct {
	mu      sync.RWMutex
	loader  Loader
	current Snapshot
	loaded  bool
}

func NewManager(loader Loader) *Manager {
	return &Manager{loader: loader}
}

// LoadCandidate loads and validates a fresh snapshot without publishing it as
// Current. Daemon reload uses this prepare step so a runtime reconciliation
// failure cannot make Config.Current diverge from the last-known-good runtime.
func (m *Manager) LoadCandidate(ctx context.Context) (Snapshot, error) {
	if m == nil || m.loader == nil {
		return Snapshot{}, ErrNoLoader
	}
	return m.loader.Load(ctx)
}

// Commit publishes an already-loaded immutable snapshot. Callers must only
// commit after every runtime component that can reject the configuration has
// accepted it.
func (m *Manager) Commit(next Snapshot) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.current = next
	m.loaded = true
	m.mu.Unlock()
}

// Reload preserves the historical load+publish API used by one-shot CLI
// commands. Long-lived daemon reloads use LoadCandidate + Commit explicitly.
func (m *Manager) Reload(ctx context.Context) (Snapshot, error) {
	next, err := m.LoadCandidate(ctx)
	if err != nil {
		return next, err
	}
	m.Commit(next)
	return next, nil
}

func (m *Manager) Current() (Snapshot, bool) {
	if m == nil {
		return Snapshot{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current, m.loaded
}
