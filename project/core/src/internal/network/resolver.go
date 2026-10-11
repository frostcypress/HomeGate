package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const DefaultLANBridge = "br-lan"

// CommandRunner makes Linux/OpenWrt network discovery testable without
// hard-coding shell pipelines into business modules.
type CommandRunner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}

// ExecRunner is the production runner used on OpenWrt/QWRT.
type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type WANResult struct {
	PublicIPv6 string `json:"public_ipv6,omitempty"`
	Device     string `json:"device,omitempty"`
	Source     string `json:"source,omitempty"`
}

type LANResult struct {
	Bridge  string   `json:"bridge"`
	Members []string `json:"members"`
}

type Result struct {
	WAN WANResult `json:"wan"`
	LAN LANResult `json:"lan"`
}

type Resolver struct {
	Runner      CommandRunner
	SysClassNet string
}

func New(runner CommandRunner) Resolver {
	return Resolver{Runner: runner, SysClassNet: "/sys/class/net"}
}

func (r Resolver) Resolve(ctx context.Context, lanBridge string) (Result, error) {
	wan, wanErr := r.ResolveWAN(ctx)
	lan, lanErr := r.ResolveLAN(lanBridge)
	result := Result{WAN: wan, LAN: lan}
	var problems []string
	if wanErr != nil {
		problems = append(problems, wanErr.Error())
	}
	if lanErr != nil {
		problems = append(problems, lanErr.Error())
	}
	if len(problems) > 0 {
		return result, errors.New(strings.Join(problems, "; "))
	}
	return result, nil
}

// ResolveWAN resolves the public IPv6 and the netdevice that actually owns the
// ingress path. WAN consumers (DDNS, Proxy/Firewall) can use it without being
// coupled to LAN bridge health.
func (r Resolver) ResolveWAN(ctx context.Context) (WANResult, error) {
	if r.Runner == nil {
		return WANResult{}, errors.New("network command runner is not configured")
	}
	var result WANResult
	addrOut, addrErr := r.Runner.Output(ctx, "ip", "-6", "-o", "addr", "show", "scope", "global")
	routeOut, routeErr := r.Runner.Output(ctx, "ip", "-6", "route", "show", "default")

	candidates := ParseGlobalIPv6Addrs(string(addrOut))
	defaultDev := ParseDefaultRouteDevice(string(routeOut))
	ubusDev := ""
	var ubusErr error

	// When the default-route device directly owns a public IPv6 address, ubus
	// cannot change the selected WAN tuple. Keep ubus as a fallback for QWRT
	// layouts where wan6.l3_device is needed to disambiguate the owner.
	defaultOwnsPublic := false
	if defaultDev != "" {
		for _, candidate := range candidates {
			if candidate.Device == defaultDev {
				defaultOwnsPublic = true
				break
			}
		}
	}
	if !defaultOwnsPublic {
		ubusOut, err := r.Runner.Output(ctx, "ubus", "call", "network.interface.wan6", "status")
		ubusErr = err
		ubusDev = ParseUbusL3Device(ubusOut)
	}

	if ip, dev := choosePublicIPv6(candidates, defaultDev, ubusDev); ip != "" {
		result.PublicIPv6 = ip
		result.Device = dev
		result.Source = "public-ip"
	} else if defaultDev != "" {
		result.Device = defaultDev
		result.Source = "default-route"
	} else if ubusDev != "" {
		result.Device = ubusDev
		result.Source = "ubus"
	}

	var problems []string
	if addrErr != nil {
		problems = append(problems, fmt.Sprintf("read global IPv6 addresses: %v", addrErr))
	}
	if result.PublicIPv6 == "" {
		problems = append(problems, "no public IPv6 address detected")
	}
	if result.Device == "" {
		if routeErr != nil {
			problems = append(problems, fmt.Sprintf("read IPv6 default route: %v", routeErr))
		}
		if ubusErr != nil {
			problems = append(problems, fmt.Sprintf("read wan6 status: %v", ubusErr))
		}
		problems = append(problems, "no WAN6 device detected")
	}
	if len(problems) > 0 {
		return result, errors.New(strings.Join(problems, "; "))
	}
	return result, nil
}

// ResolveLAN resolves only the configured bridge and its current member ports.
// WOL can therefore operate independently of WAN/public-IPv6 availability.
func (r Resolver) ResolveLAN(lanBridge string) (LANResult, error) {
	if strings.TrimSpace(lanBridge) == "" {
		lanBridge = DefaultLANBridge
	}
	result := LANResult{Bridge: lanBridge, Members: []string{}}
	members, err := r.bridgeMembers(lanBridge)
	if members != nil {
		result.Members = members
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

type Addr struct {
	Device string
	IP     string
}

func ParseGlobalIPv6Addrs(text string) []Addr {
	var out []Addr
	seen := map[string]bool{}
	for _, raw := range strings.Split(text, "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 4 {
			continue
		}
		dev := strings.TrimSuffix(fields[1], ":")
		if i := strings.IndexByte(dev, '@'); i >= 0 {
			dev = dev[:i]
		}
		var cidr string
		unusable := false
		for i, f := range fields {
			if f == "tentative" || f == "dadfailed" || f == "deprecated" {
				unusable = true
			}
			if f == "inet6" && i+1 < len(fields) {
				cidr = fields[i+1]
			}
		}
		if cidr == "" || unusable {
			continue
		}
		ipText := strings.SplitN(cidr, "/", 2)[0]
		ip := net.ParseIP(ipText)
		if !PublicIPv6(ip) {
			continue
		}
		key := dev + "\x00" + ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Addr{Device: dev, IP: ip.String()})
	}
	return out
}

func PublicIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	s := strings.ToLower(ip.String())
	return !strings.HasPrefix(s, "fc") && !strings.HasPrefix(s, "fd")
}

func ParseDefaultRouteDevice(text string) string {
	for _, raw := range strings.Split(text, "\n") {
		fields := strings.Fields(raw)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				return strings.SplitN(fields[i+1], "@", 2)[0]
			}
		}
	}
	return ""
}

func ParseUbusL3Device(data []byte) string {
	var v struct {
		L3Device string `json:"l3_device"`
	}
	if json.Unmarshal(data, &v) != nil {
		return ""
	}
	return strings.TrimSpace(v.L3Device)
}

func choosePublicIPv6(addrs []Addr, defaultDev, ubusDev string) (string, string) {
	// Prefer the interface that actually owns the public address and also owns
	// the default route. This avoids QWRT's wan6.l3_device=eth4 trap when the
	// public IPv6 is really on pppoe-wan.
	for _, preferred := range []string{defaultDev, ubusDev} {
		if preferred == "" {
			continue
		}
		for _, a := range addrs {
			if a.Device == preferred {
				return a.IP, a.Device
			}
		}
	}
	// PPP/tunnel/WAN-like netdevices are stronger WAN candidates than LAN
	// bridges when delegated global addresses exist on both sides.
	for _, prefix := range []string{"pppoe-", "ppp", "wan", "eth"} {
		for _, a := range addrs {
			if strings.HasPrefix(a.Device, prefix) && !strings.HasPrefix(a.Device, "br-") {
				return a.IP, a.Device
			}
		}
	}
	// Do not fall back to an arbitrary remaining global address. During a real
	// PPPoE/WAN outage the LAN bridge can keep a delegated global IPv6 address
	// even though no WAN ingress path exists. Treating that LAN address as WAN
	// would make DDNS target the LAN-side address and could rebind HomeGate's
	// firewall rules to the LAN bridge. Without a default-route owner, ubus WAN
	// owner, or a WAN-like netdevice, WAN identity is unavailable.
	return "", ""
}

func (r Resolver) bridgeMembers(bridge string) ([]string, error) {
	root := r.SysClassNet
	if root == "" {
		root = "/sys/class/net"
	}
	bridgePath := filepath.Join(root, bridge)
	if _, err := os.Stat(bridgePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("LAN bridge %s does not exist", bridge)
		}
		return nil, fmt.Errorf("stat LAN bridge %s: %w", bridge, err)
	}
	entries, err := os.ReadDir(filepath.Join(bridgePath, "brif"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("read LAN bridge %s members: %w", bridge, err)
	}
	members := make([]string, 0, len(entries))
	for _, e := range entries {
		members = append(members, e.Name())
	}
	sort.Strings(members)
	return members, nil
}
