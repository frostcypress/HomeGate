package frontend

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type writerGuardHost struct {
	*memoryHost
	active   bool
	busy     bool
	loads    int
	finished int
}

func (h *writerGuardHost) Begin(ctx context.Context) (func(bool) error, error) {
	if h.busy || h.active {
		return nil, errors.New("fixture busy")
	}
	finish, err := h.memoryHost.Begin(ctx)
	if err != nil {
		return nil, err
	}
	h.active = true
	return func(ok bool) error {
		defer func() {
			h.active = false
			h.finished++
		}()
		return finish(ok)
	}, nil
}

func (h *writerGuardHost) Load(ctx context.Context, pkg string) (*Document, error) {
	h.loads++
	if !h.active {
		return nil, errors.New("cursor outside writer transaction")
	}
	return h.memoryHost.Load(ctx, pkg)
}

func (h *writerGuardHost) Commit(ctx context.Context, document *Document) error {
	if !h.active {
		return errors.New("commit outside writer transaction")
	}
	return h.memoryHost.Commit(ctx, document)
}

func TestWrappedWriterUsesExistingTransactionExactlyOnce(t *testing.T) {
	for _, name := range []string{"basic_apply", "public_apply", "public_account_apply", "certificate_apply",
		"public_action", "access_update", "access_clear_all", "access_clear_entry", "access_clear_denied",
		"access_delete_all", "access_delete_entry", "access_delete_rule", "wol_apply", "wol_action",
		"maintenance_apply", "log_clear", "config_reset"} {
		t.Run(name, func(t *testing.T) {
			h := &writerGuardHost{memoryHost: fixtureHost()}
			r := (Engine{Host: h}).Run(context.Background(), Request{Route: name, Write: true, Form: map[string]string{
				"mode": "save", "ddns_interval": "300", "https_port": "443", "proxy_https_port": "10443"}})
			if h.begins != 1 || h.finished != 1 || h.active || strings.Contains(r.Error, "Invalid writer dispatch") {
				t.Fatalf("writer transaction not shared: begins=%d finished=%d error=%s", h.begins, h.finished, r.Error)
			}
		})
	}
}

func TestBusyTransactionCannotOpenNativeWrappedCursor(t *testing.T) {
	h := &writerGuardHost{memoryHost: fixtureHost(), busy: true}
	r := (Engine{Host: h}).Run(context.Background(), Request{Route: "basic_apply", Write: true})
	if r.OK || h.loads != 0 || h.commits != 0 || h.finished != 0 {
		t.Fatal("busy writer reached configuration or finalized an unowned transaction")
	}
}
