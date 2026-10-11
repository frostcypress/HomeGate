package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/network"
	"homegate.local/homegate/internal/runtimefile"
)

const (
	Phase                   = "firewall"
	StandardHTTPPort        = 80
	DefaultStatusPath       = "/var/run/homegate/firewall.json"
	DefaultCompatStatusPath = "/var/run/homegate/firewall.status"
	maxCleanupHooks         = 32
	xtablesWaitSeconds      = "3"
)

// ErrWANUnavailable marks a transient firewall reconciliation failure caused by
// WAN/public-IPv6 not being ready yet. The status JSON keeps the original human
// readable resolver error while daemon startup logic can classify the failure
// for bounded retry without retrying permanent ip6tables errors.
var ErrWANUnavailable = errors.New("WAN6/public IPv6 unavailable")

func Retryable(err error) bool { return errors.Is(err, ErrWANUnavailable) }

// ApplyError separates a real firewall-runtime failure from a status-file
// publication failure. A status-only error must be logged, but it must not roll
// back an otherwise valid firewall runtime.
type ApplyError struct {
	Runtime error
	Status  error
}

func (e *ApplyError) Error() string {
	switch {
	case e == nil:
		return ""
	case e.Runtime != nil && e.Status != nil:
		return fmt.Sprintf("%v; publish firewall status: %v", e.Runtime, e.Status)
	case e.Runtime != nil:
		return e.Runtime.Error()
	case e.Status != nil:
		return "publish firewall status: " + e.Status.Error()
	default:
		return ""
	}
}

func (e *ApplyError) Unwrap() []error {
	if e == nil {
		return nil
	}
	out := make([]error, 0, 2)
	if e.Runtime != nil {
		out = append(out, e.Runtime)
	}
	if e.Status != nil {
		out = append(out, e.Status)
	}
	return out
}

func RuntimeFailed(err error) bool {
	if err == nil {
		return false
	}
	var applyErr *ApplyError
	if errors.As(err, &applyErr) {
		return applyErr.Runtime != nil
	}
	return true
}

func StatusWriteFailed(err error) bool {
	var applyErr *ApplyError
	return errors.As(err, &applyErr) && applyErr.Status != nil
}

type Runner interface {
	Run(context.Context, string, ...string) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	runArgs := commandArgs(name, args)
	out, err := exec.CommandContext(ctx, name, runArgs...).CombinedOutput()
	if err != nil && name == "ip6tables" && xtablesWaitUnsupported(out) {
		// Very old ip6tables variants may not implement -w. Keep HomeGate
		// compatible with them, while QWRT/OpenWrt builds that support the
		// native xtables lock wait get bounded serialization instead of
		// spuriously failing Apply/Cleanup/rollback on a transient lock owner.
		out, err = exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		return err
	}
	return fmt.Errorf("%s: %w", detail, err)
}

func commandArgs(name string, args []string) []string {
	if name != "ip6tables" {
		return args
	}
	out := make([]string, 0, len(args)+2)
	out = append(out, "-w", xtablesWaitSeconds)
	out = append(out, args...)
	return out
}

func xtablesWaitUnsupported(out []byte) bool {
	msg := strings.ToLower(string(out))
	return strings.Contains(msg, "unknown option") ||
		strings.Contains(msg, "unrecognized option") ||
		strings.Contains(msg, "invalid option")
}

type Status struct {
	APIVersion int    `json:"api_version"`
	OK         bool   `json:"ok"`
	Version    string `json:"version"`
	Phase      string `json:"phase"`
	Active     bool   `json:"active"`
	Managed    bool   `json:"managed"`
	WANDevice  string `json:"wan_device,omitempty"`
	WANSource  string `json:"wan_source,omitempty"`
	HTTPS      string `json:"https,omitempty"`
	HTTP       string `json:"http,omitempty"`
	Error      string `json:"error,omitempty"`
}

type Controller struct {
	Runner           Runner
	Network          network.Resolver
	StatusPath       string
	CompatStatusPath string
}

func New(netResolver network.Resolver) Controller {
	return Controller{Runner: ExecRunner{}, Network: netResolver, StatusPath: DefaultStatusPath, CompatStatusPath: DefaultCompatStatusPath}
}

func enabledProtocols(cfg config.Snapshot) (https, http bool) {
	for _, r := range cfg.Web {
		if !r.Enabled {
			continue
		}
		if r.HTTPS {
			https = true
		} else {
			http = true
		}
	}
	return
}

func publicHTTPPorts(cfg config.Snapshot, https, http bool) []int {
	ports := make([]int, 0, 2)
	seen := map[int]bool{}
	add := func(port int) {
		if port > 0 && !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	// A standard port-80 entry is always present for enabled HTTPS services so
	// typing only the hostname can be upgraded to HTTPS. This is independent of
	// the legacy http_port value and therefore works with existing configs where
	// http_port is intentionally 0.
	if https {
		add(StandardHTTPPort)
	}
	// Preserve the historical plain-HTTP service mapping when explicitly set.
	if http {
		add(cfg.Main.HTTPPort)
	}
	return ports
}

func (c Controller) Apply(ctx context.Context, version string, cfg config.Snapshot) (Status, error) {
	if c.Runner == nil {
		c.Runner = ExecRunner{}
	}
	https, http := enabledProtocols(cfg)
	st := Status{APIVersion: 1, OK: true, Version: version, Phase: Phase, Managed: cfg.Main.AutoFirewall}

	// Phase 4G keeps the historical cleanup-first rule layout, but cleanup is no
	// longer allowed to lie. A real cleanup failure rejects this candidate so the
	// daemon can restore the previous config's firewall immediately.
	if err := c.cleanupRules(ctx); err != nil {
		st.OK = false
		st.Error = "pre-apply cleanup failed: " + err.Error()
		return c.finish(st, "cleanup failed", err)
	}
	if !https && !http {
		return c.finish(st, "web inactive", nil)
	}
	if !cfg.Main.AutoFirewall {
		return c.finish(st, "auto firewall disabled", nil)
	}
	wan, err := c.Network.ResolveWAN(ctx)
	if err != nil || strings.TrimSpace(wan.Device) == "" {
		if err == nil {
			err = errors.New("no WAN6 device detected")
		}
		st.OK = false
		st.Error = err.Error()
		return c.finish(st, "no wan6 device", fmt.Errorf("%w: %s", ErrWANUnavailable, err.Error()))
	}
	st.WANDevice, st.WANSource = wan.Device, wan.Source

	if err := c.run(ctx, "ip6tables", "-t", "nat", "-N", "HOMEGATE_NAT"); err != nil {
		return c.applyFailure(ctx, st, "ipv6 nat unsupported", "ipv6 nat unsupported: "+err.Error(), err)
	}
	if err := c.run(ctx, "ip6tables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "HOMEGATE_NAT"); err != nil {
		return c.applyFailure(ctx, st, "nat hook failed", "nat hook failed: "+err.Error(), err)
	}
	if https && cfg.Main.HTTPSPort > 0 && cfg.Main.ProxyHTTPSPort > 0 {
		if err := c.run(ctx, "ip6tables", "-t", "nat", "-A", "HOMEGATE_NAT", "-i", wan.Device, "-p", "tcp", "--dport", fmt.Sprint(cfg.Main.HTTPSPort), "-j", "REDIRECT", "--to-ports", fmt.Sprint(cfg.Main.ProxyHTTPSPort)); err != nil {
			return c.applyFailure(ctx, st, "https redirect failed", "https redirect failed: "+err.Error(), err)
		}
		st.HTTPS = fmt.Sprintf("%d->%d", cfg.Main.HTTPSPort, cfg.Main.ProxyHTTPSPort)
	}
	httpMappings := make([]string, 0, 2)
	if cfg.Main.ProxyHTTPPort > 0 {
		for _, publicPort := range publicHTTPPorts(cfg, https, http) {
			if err := c.run(ctx, "ip6tables", "-t", "nat", "-A", "HOMEGATE_NAT", "-i", wan.Device, "-p", "tcp", "--dport", fmt.Sprint(publicPort), "-j", "REDIRECT", "--to-ports", fmt.Sprint(cfg.Main.ProxyHTTPPort)); err != nil {
				return c.applyFailure(ctx, st, "http redirect failed", "http redirect failed: "+err.Error(), err)
			}
			httpMappings = append(httpMappings, fmt.Sprintf("%d->%d", publicPort, cfg.Main.ProxyHTTPPort))
		}
	}
	st.HTTP = strings.Join(httpMappings, ",")
	if st.HTTPS == "" && st.HTTP == "" {
		if err := c.cleanupRules(ctx); err != nil {
			st.OK = false
			st.Error = "web ports disabled; cleanup failed: " + err.Error()
			return c.finish(st, "web ports disabled cleanup failed", err)
		}
		st.Managed = false
		return c.finish(st, "web ports disabled", nil)
	}
	if err := c.run(ctx, "ip6tables", "-N", "HOMEGATE_INPUT"); err != nil {
		return c.applyFailure(ctx, st, "input chain failed", "input chain failed: "+err.Error(), err)
	}
	if err := c.run(ctx, "ip6tables", "-I", "INPUT", "1", "-j", "HOMEGATE_INPUT"); err != nil {
		return c.applyFailure(ctx, st, "input hook failed", "input hook failed: "+err.Error(), err)
	}
	if st.HTTPS != "" {
		if err := c.run(ctx, "ip6tables", "-A", "HOMEGATE_INPUT", "-i", wan.Device, "-p", "tcp", "--dport", fmt.Sprint(cfg.Main.ProxyHTTPSPort), "-j", "ACCEPT"); err != nil {
			return c.applyFailure(ctx, st, "https input failed", "https input failed: "+err.Error(), err)
		}
	}
	if st.HTTP != "" {
		if err := c.run(ctx, "ip6tables", "-A", "HOMEGATE_INPUT", "-i", wan.Device, "-p", "tcp", "--dport", fmt.Sprint(cfg.Main.ProxyHTTPPort), "-j", "ACCEPT"); err != nil {
			return c.applyFailure(ctx, st, "http input failed", "http input failed: "+err.Error(), err)
		}
	}
	st.Active = true
	compat := fmt.Sprintf("ok wan6=%s source=%s", wan.Device, wan.Source)
	if st.HTTPS != "" {
		compat += " https=" + st.HTTPS
	}
	if st.HTTP != "" {
		compat += " http=" + st.HTTP
	}
	return c.finish(st, compat, nil)
}

func (c Controller) applyFailure(ctx context.Context, st Status, compat, message string, cause error) (Status, error) {
	st.OK = false
	st.Active = false
	st.Error = message
	cleanupErr := c.cleanupRules(ctx)
	if cleanupErr != nil {
		st.Error += "; cleanup incomplete: " + cleanupErr.Error()
		cause = errors.Join(cause, fmt.Errorf("cleanup incomplete: %w", cleanupErr))
	}
	return c.finish(st, compat, cause)
}

func (c Controller) finish(st Status, compat string, runtimeErr error) (Status, error) {
	published, statusErr := c.writeStatus(st, compat)
	if runtimeErr == nil && statusErr == nil {
		return published, nil
	}
	return published, &ApplyError{Runtime: runtimeErr, Status: statusErr}
}

func (c Controller) Cleanup(ctx context.Context, version string) Status {
	err := c.cleanupRules(ctx)
	st := Status{APIVersion: 1, OK: err == nil, Version: version, Phase: Phase}
	if err != nil {
		st.Error = "cleanup incomplete: " + err.Error()
	}
	published, statusErr := c.writeStatus(st, "cleanup")
	if statusErr != nil {
		published.OK = false
		if published.Error != "" {
			published.Error += "; "
		}
		published.Error += "publish firewall status: " + statusErr.Error()
	}
	return published
}

func isAbsentRuleError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "bad rule (does a matching rule exist in that chain?)") ||
		strings.Contains(msg, "no chain/target/match by that name") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "not present") ||
		isMissingHomeGateJumpTarget(msg)
}

// Legacy ip6tables validates a user-chain jump target before looking for the
// rule being deleted. If HOMEGATE_* itself is already absent, deleting the
// PREROUTING/INPUT hook therefore fails with "Couldn't load target ... No such
// file or directory" instead of the newer "No chain/target/match" wording.
// This is still an idempotent-cleanup absence, not a real command failure.
// Restrict the compatibility match to HomeGate-owned user chains so unrelated
// missing extensions/targets are never hidden.
func isMissingHomeGateJumpTarget(msg string) bool {
	if !strings.Contains(msg, "couldn't load target") || !strings.Contains(msg, "no such file or directory") {
		return false
	}
	return strings.Contains(msg, "homegate_nat") || strings.Contains(msg, "homegate_input")
}

func (c Controller) cleanupRules(ctx context.Context) error {
	if c.Runner == nil {
		c.Runner = ExecRunner{}
	}
	var errs []error
	deleteHooks := func(label string, args ...string) bool {
		for i := 0; i < maxCleanupHooks; i++ {
			err := c.run(ctx, "ip6tables", args...)
			if err == nil {
				continue
			}
			if isAbsentRuleError(err) {
				return true
			}
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
			return false
		}
		errs = append(errs, fmt.Errorf("%s: exceeded %d duplicate hooks", label, maxCleanupHooks))
		return false
	}
	cleanupChain := func(label string, flushArgs, deleteArgs []string) {
		if err := c.run(ctx, "ip6tables", flushArgs...); err != nil && !isAbsentRuleError(err) {
			errs = append(errs, fmt.Errorf("flush %s: %w", label, err))
			return
		}
		if err := c.run(ctx, "ip6tables", deleteArgs...); err != nil && !isAbsentRuleError(err) {
			errs = append(errs, fmt.Errorf("delete %s: %w", label, err))
		}
	}

	if deleteHooks("HOMEGATE_NAT PREROUTING hook", "-t", "nat", "-D", "PREROUTING", "-j", "HOMEGATE_NAT") {
		cleanupChain("HOMEGATE_NAT", []string{"-t", "nat", "-F", "HOMEGATE_NAT"}, []string{"-t", "nat", "-X", "HOMEGATE_NAT"})
	}
	if deleteHooks("HOMEGATE_INPUT INPUT hook", "-D", "INPUT", "-j", "HOMEGATE_INPUT") {
		cleanupChain("HOMEGATE_INPUT", []string{"-F", "HOMEGATE_INPUT"}, []string{"-X", "HOMEGATE_INPUT"})
	}
	return errors.Join(errs...)
}

func (c Controller) run(ctx context.Context, name string, args ...string) error {
	return c.Runner.Run(ctx, name, args...)
}

func (c Controller) writeStatus(st Status, compat string) (Status, error) {
	path := c.StatusPath
	if path == "" {
		path = DefaultStatusPath
	}
	compatPath := c.CompatStatusPath
	if compatPath == "" {
		compatPath = DefaultCompatStatusPath
	}

	var errs []error
	if err := runtimefile.WriteAtomic(compatPath, []byte(compat+"\n"), 0o600); err != nil {
		errs = append(errs, fmt.Errorf("compat: %w", err))
		st.OK = false
		if st.Error != "" {
			st.Error += "; "
		}
		st.Error += "compat status write failed: " + err.Error()
	}
	if err := runtimefile.WriteJSONAtomic(path, st, 0o600); err != nil {
		errs = append(errs, fmt.Errorf("json: %w", err))
		st.OK = false
		if st.Error != "" {
			st.Error += "; "
		}
		st.Error += "JSON status write failed: " + err.Error()
	}
	return st, errors.Join(errs...)
}

func (c Controller) Read(version string) Status {
	path := c.StatusPath
	if path == "" {
		path = DefaultStatusPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Status{APIVersion: 1, OK: true, Version: version, Phase: Phase}
		}
		return Status{APIVersion: 1, OK: false, Version: version, Phase: Phase, Error: err.Error()}
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return Status{APIVersion: 1, OK: false, Version: version, Phase: Phase, Error: err.Error()}
	}
	st.Version = version
	return st
}
