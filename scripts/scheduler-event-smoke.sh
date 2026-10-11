#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$ROOT/project/core/src"
go test ./internal/scheduler -count=1

grep -q 'scheduler.New(12)' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'scheduler.EventConfigChanged' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'scheduler.EventWANChanged' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'scheduler.EventFirewallRetry' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'scheduler.EventProxyRetry' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'scheduler.EventDDNSRetry' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'scheduler.EventACMERetry' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'scheduler.EventAccessRetry' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'syscall.SIGUSR1' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'generation.Advance(current)' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'proxyManager.AdoptGeneration(work.Generation)' "$ROOT/project/core/src/internal/app/app.go"

grep -q '^EXTRA_COMMANDS="network_changed"$' "$ROOT/project/core/files/etc/init.d/homegate"
grep -q "procd_send_signal homegate '\*' USR1" "$ROOT/project/core/files/etc/init.d/homegate"
grep -q '/etc/init.d/homegate network_changed' "$ROOT/project/core/files/etc/hotplug.d/iface/95-homegate"
! grep -q '/etc/init.d/homegate reload' "$ROOT/project/core/files/etc/hotplug.d/iface/95-homegate"

echo 'scheduler/event smoke PASS'
