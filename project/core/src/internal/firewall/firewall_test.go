package firewall

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/network"
)

func TestExecRunnerAddsBoundedXTablesWait(t *testing.T) {
	got := commandArgs("ip6tables", []string{"-t", "nat", "-L"})
	want := []string{"-w", xtablesWaitSeconds, "-t", "nat", "-L"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("ip6tables args=%v want=%v", got, want)
	}

	original := []string{"-6", "route", "show", "default"}
	got = commandArgs("ip", original)
	if strings.Join(got, " ") != strings.Join(original, " ") {
		t.Fatalf("non-iptables args changed: %v", got)
	}
}

func TestXTablesWaitUnsupportedDetection(t *testing.T) {
	for _, msg := range []string{
		"ip6tables: unknown option --wait",
		"ip6tables: unrecognized option '-w'",
		"ip6tables: invalid option -- 'w'",
	} {
		if !xtablesWaitUnsupported([]byte(msg)) {
			t.Fatalf("expected unsupported wait detection for %q", msg)
		}
	}
	if xtablesWaitUnsupported([]byte("Another app is currently holding the xtables lock")) {
		t.Fatal("lock contention must not be mistaken for unsupported -w")
	}
}

type runLog struct{ calls []string }

func (r *runLog) Run(ctx context.Context, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if strings.Contains(line, " -D ") || strings.Contains(line, " -F ") || strings.Contains(line, " -X ") {
		return errors.New("not present")
	}
	return nil
}

type netRunner struct{}

func (netRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	joined := name + " " + strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "addr show scope global"):
		return []byte("24: br-lan inet6 2409:8a55:4fc3:9df0::1/60 scope global\n26: pppoe-wan inet6 2409:8a55:4f0c:353::1234/64 scope global\n"), nil
	case strings.Contains(joined, "route show default"):
		return []byte("default from 2409:8a55:4f0c:353::/64 via fe80::1 dev pppoe-wan metric 512\n"), nil
	case strings.Contains(joined, "network.interface.wan6"):
		return []byte(`{"l3_device":"eth4"}`), nil
	}
	return nil, errors.New("unexpected")
}

func fwConfig(enabled bool) config.Snapshot {
	return config.Snapshot{Configured: true, Main: config.Main{AutoFirewall: true, HTTPSPort: 443, HTTPPort: 0, ProxyHTTPSPort: 10443, ProxyHTTPPort: 10080}, Web: []config.WebRule{{ID: "web1", Enabled: enabled, Domain: "test.chenos.cn", Target: "http://192.168.2.3", HTTPS: true, Certificate: "cert1"}}}
}

func TestApplyUsesActualPPPoEWAN(t *testing.T) {
	rl := &runLog{}
	nr := network.New(netRunner{})
	c := Controller{Runner: rl, Network: nr, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	st, err := c.Apply(context.Background(), "0.5.0", fwConfig(true))
	if err != nil {
		t.Fatal(err)
	}
	if !st.OK || !st.Active || st.WANDevice != "pppoe-wan" || st.WANSource != "public-ip" || st.HTTPS != "443->10443" || st.HTTP != "80->10080" {
		t.Fatalf("status=%+v", st)
	}
	all := strings.Join(rl.calls, "\n")
	if !strings.Contains(all, "-i pppoe-wan -p tcp --dport 443 -j REDIRECT --to-ports 10443") {
		t.Fatalf("missing pppoe redirect:\n%s", all)
	}
	if !strings.Contains(all, "-i pppoe-wan -p tcp --dport 80 -j REDIRECT --to-ports 10080") {
		t.Fatalf("missing HTTP-to-HTTPS redirect mapping:\n%s", all)
	}
	if strings.Contains(all, "-i eth4 -p tcp --dport 443") {
		t.Fatalf("used wrong eth4:\n%s", all)
	}
	if !strings.Contains(all, "HOMEGATE_INPUT -i pppoe-wan -p tcp --dport 10443 -j ACCEPT") {
		t.Fatalf("missing input rule:\n%s", all)
	}
	if !strings.Contains(all, "HOMEGATE_INPUT -i pppoe-wan -p tcp --dport 10080 -j ACCEPT") {
		t.Fatalf("missing HTTP redirect input rule:\n%s", all)
	}
}

func TestPublicHTTPPortsPreserveLegacyPlainHTTPPort(t *testing.T) {
	cfg := fwConfig(true)
	cfg.Main.HTTPPort = 8080
	ports := publicHTTPPorts(cfg, true, true)
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 8080 {
		t.Fatalf("ports=%v", ports)
	}
}

func TestNoEnabledWebLeavesNoChains(t *testing.T) {
	rl := &runLog{}
	nr := network.New(netRunner{})
	c := Controller{Runner: rl, Network: nr, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	st, err := c.Apply(context.Background(), "0.5.0", fwConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	if st.Active {
		t.Fatalf("status=%+v", st)
	}
	all := strings.Join(rl.calls, "\n")
	if strings.Contains(all, " -N HOMEGATE_NAT") || strings.Contains(all, " -N HOMEGATE_INPUT") {
		t.Fatalf("created chains:\n%s", all)
	}
}

func TestAutoFirewallDisabled(t *testing.T) {
	cfg := fwConfig(true)
	cfg.Main.AutoFirewall = false
	rl := &runLog{}
	nr := network.New(netRunner{})
	c := Controller{Runner: rl, Network: nr, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	st, err := c.Apply(context.Background(), "0.5.0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Managed || st.Active {
		t.Fatalf("status=%+v", st)
	}
}

type noWANRunner struct{}

func (noWANRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	joined := name + " " + strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "addr show scope global"):
		return []byte(""), nil
	case strings.Contains(joined, "route show default"):
		return []byte(""), nil
	case strings.Contains(joined, "network.interface.wan6"):
		return []byte(`{"up":false}`), nil
	}
	return nil, errors.New("unexpected")
}

func TestWANNotReadyIsRetryable(t *testing.T) {
	rl := &runLog{}
	nr := network.New(noWANRunner{})
	c := Controller{Runner: rl, Network: nr, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	st, err := c.Apply(context.Background(), "0.5.0", fwConfig(true))
	if err == nil {
		t.Fatal("expected WAN-not-ready error")
	}
	if !Retryable(err) {
		t.Fatalf("expected retryable error, got %v", err)
	}
	if st.OK || st.Active || st.Error != "no public IPv6 address detected; no WAN6 device detected" {
		t.Fatalf("unexpected status=%+v", st)
	}
}

type natFailRunner struct{ runLog }

func (r *natFailRunner) Run(ctx context.Context, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if strings.Contains(line, " -D ") || strings.Contains(line, " -F ") || strings.Contains(line, " -X ") {
		return errors.New("not present")
	}
	if line == "ip6tables -t nat -N HOMEGATE_NAT" {
		return errors.New("nat unavailable")
	}
	return nil
}

func TestPermanentIPTablesFailureIsNotRetryable(t *testing.T) {
	rl := &natFailRunner{}
	nr := network.New(netRunner{})
	c := Controller{Runner: rl, Network: nr, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	_, err := c.Apply(context.Background(), "0.5.0", fwConfig(true))
	if err == nil {
		t.Fatal("expected ip6tables failure")
	}
	if Retryable(err) {
		t.Fatalf("permanent ip6tables error must not be retryable: %v", err)
	}
}

func TestCleanupTreatsLegacyMissingHomeGateJumpTargetAsAbsent(t *testing.T) {
	legacyMissing := errors.New("ip6tables v1.8.3 (legacy): Couldn't load target `HOMEGATE_NAT':No such file or directory\n\nTry `ip6tables -h' or 'ip6tables --help' for more information.: exit status 2")
	if !isAbsentRuleError(legacyMissing) {
		t.Fatalf("legacy QWRT missing HomeGate jump target must be treated as absent: %v", legacyMissing)
	}

	unrelatedMissing := errors.New("ip6tables v1.8.3 (legacy): Couldn't load target `SOME_EXTENSION':No such file or directory: exit status 2")
	if isAbsentRuleError(unrelatedMissing) {
		t.Fatalf("unrelated missing target must remain a real error: %v", unrelatedMissing)
	}
}

type legacyAbsentCleanupRunner struct{ calls []string }

func (r *legacyAbsentCleanupRunner) Run(_ context.Context, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	switch {
	case strings.Contains(line, "-t nat -D PREROUTING -j HOMEGATE_NAT"):
		return errors.New("ip6tables v1.8.3 (legacy): Couldn't load target `HOMEGATE_NAT':No such file or directory: exit status 2")
	case strings.Contains(line, "-D INPUT -j HOMEGATE_INPUT"):
		return errors.New("ip6tables v1.8.3 (legacy): Couldn't load target `HOMEGATE_INPUT':No such file or directory: exit status 2")
	case strings.Contains(line, " -F ") || strings.Contains(line, " -X "):
		return errors.New("ip6tables: No chain/target/match by that name.: exit status 1")
	default:
		return nil
	}
}

func TestCleanupAcceptsQWRTLegacyAlreadyAbsentChains(t *testing.T) {
	rl := &legacyAbsentCleanupRunner{}
	c := Controller{Runner: rl, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	st := c.Cleanup(context.Background(), "0.5.0")
	if !st.OK || st.Error != "" {
		t.Fatalf("legacy already-absent cleanup should succeed: %+v", st)
	}
}

type cleanupFailureRunner struct{ calls []string }

func (r *cleanupFailureRunner) Run(_ context.Context, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if strings.Contains(line, "-t nat -D PREROUTING -j HOMEGATE_NAT") {
		return errors.New("permission denied")
	}
	if strings.Contains(line, " -D ") || strings.Contains(line, " -F ") || strings.Contains(line, " -X ") {
		return errors.New("not present")
	}
	return nil
}

func TestCleanupReportsRealHookFailureAndDoesNotFlushReferencedChain(t *testing.T) {
	rl := &cleanupFailureRunner{}
	c := Controller{Runner: rl, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	st := c.Cleanup(context.Background(), "0.5.0")
	if st.OK || !strings.Contains(st.Error, "permission denied") {
		t.Fatalf("cleanup false-positive status=%+v", st)
	}
	all := strings.Join(rl.calls, "\n")
	if strings.Contains(all, "-t nat -F HOMEGATE_NAT") || strings.Contains(all, "-t nat -X HOMEGATE_NAT") {
		t.Fatalf("cleanup flushed/deleted chain after hook delete failure:\n%s", all)
	}
}

type partialApplyFailureRunner struct {
	calls       []string
	createdHook bool
}

func (r *partialApplyFailureRunner) Run(_ context.Context, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if strings.Contains(line, " -D ") || strings.Contains(line, " -F ") || strings.Contains(line, " -X ") {
		if r.createdHook && strings.Contains(line, "-t nat -D PREROUTING -j HOMEGATE_NAT") {
			return errors.New("cleanup permission denied")
		}
		return errors.New("not present")
	}
	if line == "ip6tables -t nat -I PREROUTING 1 -j HOMEGATE_NAT" {
		r.createdHook = true
		return nil
	}
	if strings.Contains(line, "--dport 443") {
		return errors.New("redirect add failed")
	}
	return nil
}

func TestApplyReportsOriginalAndCleanupFailure(t *testing.T) {
	rl := &partialApplyFailureRunner{}
	nr := network.New(netRunner{})
	c := Controller{Runner: rl, Network: nr, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	st, err := c.Apply(context.Background(), "0.5.0", fwConfig(true))
	if err == nil || !RuntimeFailed(err) {
		t.Fatalf("expected runtime failure: status=%+v err=%v", st, err)
	}
	if st.OK || st.Active || !strings.Contains(st.Error, "redirect add failed") || !strings.Contains(st.Error, "cleanup incomplete") {
		t.Fatalf("incomplete failure status=%+v", st)
	}
	if !strings.Contains(err.Error(), "cleanup permission denied") {
		t.Fatalf("cleanup diagnostic missing: %v", err)
	}
}

func TestStatusWriteFailureIsSeparatedFromRuntimeFailure(t *testing.T) {
	rl := &runLog{}
	nr := network.New(netRunner{})
	parentFile := t.TempDir() + "/not-a-dir"
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Controller{
		Runner:           rl,
		Network:          nr,
		StatusPath:       parentFile + "/fw.json",
		CompatStatusPath: t.TempDir() + "/fw.status",
	}
	st, err := c.Apply(context.Background(), "0.5.0", fwConfig(true))
	if err == nil || RuntimeFailed(err) || !StatusWriteFailed(err) {
		t.Fatalf("expected status-only error: status=%+v err=%v", st, err)
	}
	if !st.Active {
		t.Fatalf("firewall runtime should remain active despite status write failure: %+v", st)
	}
}

type idempotentIPTablesRunner struct {
	natChain, inputChain bool
	natHooks, inputHooks int
	natRules, inputRules int
}

func (r *idempotentIPTablesRunner) Run(_ context.Context, name string, args ...string) error {
	if name != "ip6tables" {
		return nil
	}
	line := strings.Join(args, " ")
	switch {
	case line == "-t nat -D PREROUTING -j HOMEGATE_NAT":
		if r.natHooks == 0 {
			return errors.New("not present")
		}
		r.natHooks--
		return nil
	case line == "-D INPUT -j HOMEGATE_INPUT":
		if r.inputHooks == 0 {
			return errors.New("not present")
		}
		r.inputHooks--
		return nil
	case line == "-t nat -F HOMEGATE_NAT":
		if !r.natChain {
			return errors.New("not present")
		}
		r.natRules = 0
		return nil
	case line == "-t nat -X HOMEGATE_NAT":
		if !r.natChain {
			return errors.New("not present")
		}
		if r.natHooks != 0 {
			return errors.New("chain referenced")
		}
		r.natChain = false
		return nil
	case line == "-F HOMEGATE_INPUT":
		if !r.inputChain {
			return errors.New("not present")
		}
		r.inputRules = 0
		return nil
	case line == "-X HOMEGATE_INPUT":
		if !r.inputChain {
			return errors.New("not present")
		}
		if r.inputHooks != 0 {
			return errors.New("chain referenced")
		}
		r.inputChain = false
		return nil
	case line == "-t nat -N HOMEGATE_NAT":
		if r.natChain {
			return errors.New("chain already exists")
		}
		r.natChain = true
		return nil
	case line == "-t nat -I PREROUTING 1 -j HOMEGATE_NAT":
		r.natHooks++
		return nil
	case strings.HasPrefix(line, "-t nat -A HOMEGATE_NAT "):
		if !r.natChain {
			return errors.New("missing nat chain")
		}
		r.natRules++
		return nil
	case line == "-N HOMEGATE_INPUT":
		if r.inputChain {
			return errors.New("chain already exists")
		}
		r.inputChain = true
		return nil
	case line == "-I INPUT 1 -j HOMEGATE_INPUT":
		r.inputHooks++
		return nil
	case strings.HasPrefix(line, "-A HOMEGATE_INPUT "):
		if !r.inputChain {
			return errors.New("missing input chain")
		}
		r.inputRules++
		return nil
	default:
		return nil
	}
}

func TestApplyRepeatedSameConfigLeavesSingleRuleSet(t *testing.T) {
	runner := &idempotentIPTablesRunner{}
	nr := network.New(netRunner{})
	c := Controller{Runner: runner, Network: nr, StatusPath: t.TempDir() + "/fw.json", CompatStatusPath: t.TempDir() + "/fw.status"}
	cfg := fwConfig(true)

	for i := 0; i < 5; i++ {
		st, err := c.Apply(context.Background(), "0.5.0", cfg)
		if err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
		if !st.Active || !st.Managed {
			t.Fatalf("apply %d status=%+v", i, st)
		}
	}

	if !runner.natChain || !runner.inputChain {
		t.Fatalf("chains missing after repeated apply: %+v", runner)
	}
	if runner.natHooks != 1 || runner.inputHooks != 1 {
		t.Fatalf("duplicate hooks after repeated apply: nat=%d input=%d", runner.natHooks, runner.inputHooks)
	}
	if runner.natRules != 2 || runner.inputRules != 2 {
		t.Fatalf("unexpected final rule counts: nat=%d input=%d", runner.natRules, runner.inputRules)
	}
}
