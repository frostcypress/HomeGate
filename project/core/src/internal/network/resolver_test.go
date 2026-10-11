package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	outputs map[string]string
	errors  map[string]error
}

func (f fakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if err := f.errors[key]; err != nil {
		return nil, err
	}
	return []byte(f.outputs[key]), nil
}

func TestParseGlobalIPv6Addrs(t *testing.T) {
	text := "5: pppoe-wan    inet6 2409:8a55:4f0c:353::1234/64 scope global dynamic\n" +
		"6: br-lan    inet6 fd00::1/64 scope global\n" +
		"7: br-lan    inet6 2409:8a55:4f0c:354::1/64 scope global\n"
	got := ParseGlobalIPv6Addrs(text)
	want := []Addr{{Device: "pppoe-wan", IP: "2409:8a55:4f0c:353::1234"}, {Device: "br-lan", IP: "2409:8a55:4f0c:354::1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestParseGlobalIPv6RejectsUnusableAddresses(t *testing.T) {
	text := "5: pppoe-wan inet6 2409::1/64 scope global tentative\n" +
		"5: pppoe-wan inet6 2409::2/64 scope global dadfailed\n" +
		"5: pppoe-wan inet6 2409::3/64 scope global deprecated\n" +
		"5: pppoe-wan inet6 2409::4/64 scope global dynamic\n"
	got := ParseGlobalIPv6Addrs(text)
	want := []Addr{{Device: "pppoe-wan", IP: "2409::4"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestChoosePublicIPv6PrefersDefaultRouteOwner(t *testing.T) {
	addrs := []Addr{{Device: "br-lan", IP: "2409:1::1"}, {Device: "pppoe-wan", IP: "2409:2::1"}}
	ip, dev := choosePublicIPv6(addrs, "pppoe-wan", "eth4")
	if ip != "2409:2::1" || dev != "pppoe-wan" {
		t.Fatalf("got %s %s", ip, dev)
	}
}

func TestChoosePublicIPv6RejectsLANOnlyCandidate(t *testing.T) {
	addrs := []Addr{{Device: "br-lan", IP: "2409:8a55:4fc0:f020::1"}}
	ip, dev := choosePublicIPv6(addrs, "", "")
	if ip != "" || dev != "" {
		t.Fatalf("LAN-only delegated address must not become WAN: got %s %s", ip, dev)
	}
}

func TestResolveWANRejectsDelegatedLANAddressWhenUplinkDown(t *testing.T) {
	f := fakeRunner{outputs: map[string]string{
		"ip -6 -o addr show scope global":         "13: br-lan inet6 2409:8a55:4fc0:f020::1/64 scope global\n",
		"ip -6 route show default":                "",
		"ubus call network.interface.wan6 status": `{"up":false}`,
	}}
	got, err := (Resolver{Runner: f}).ResolveWAN(context.Background())
	if err == nil {
		t.Fatal("expected WAN unavailable error while only delegated LAN address remains")
	}
	if got.PublicIPv6 != "" || got.Device != "" || got.Source != "" {
		t.Fatalf("LAN-only address leaked into WAN result: %+v", got)
	}
	if !strings.Contains(err.Error(), "no public IPv6 address detected") || !strings.Contains(err.Error(), "no WAN6 device detected") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveQWRTPPPoE(t *testing.T) {
	root := t.TempDir()
	brif := filepath.Join(root, "br-lan", "brif")
	if err := os.MkdirAll(brif, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"eth3", "eth1"} {
		if err := os.WriteFile(filepath.Join(brif, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := fakeRunner{outputs: map[string]string{
		"ip -6 -o addr show scope global":         "12: pppoe-wan    inet6 2409:8a55:4f0c:353:7d9e:dab6:918d:f902/64 scope global dynamic\n13: br-lan inet6 2409:8a55:4f0c:354::1/64 scope global\n",
		"ip -6 route show default":                "default from 2409:8a55:4f0c:353::/64 via fe80::1 dev pppoe-wan proto static metric 512 pref medium\n",
		"ubus call network.interface.wan6 status": `{"up":true,"l3_device":"eth4"}`,
	}}
	got, err := (Resolver{Runner: f, SysClassNet: root}).Resolve(context.Background(), "br-lan")
	if err != nil {
		t.Fatal(err)
	}
	if got.WAN.PublicIPv6 != "2409:8a55:4f0c:353:7d9e:dab6:918d:f902" || got.WAN.Device != "pppoe-wan" || got.WAN.Source != "public-ip" {
		t.Fatalf("unexpected %#v", got)
	}
	if !reflect.DeepEqual(got.LAN.Members, []string{"eth1", "eth3"}) {
		t.Fatalf("members %#v", got.LAN.Members)
	}
}

func TestResolveFallsBackToDefaultRouteDevice(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "br-lan"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := fakeRunner{outputs: map[string]string{
		"ip -6 -o addr show scope global":         "",
		"ip -6 route show default":                "default via fe80::1 dev pppoe-wan metric 512\n",
		"ubus call network.interface.wan6 status": `{"l3_device":"eth4"}`,
	}}
	got, err := (Resolver{Runner: f, SysClassNet: root}).Resolve(context.Background(), "br-lan")
	if err == nil {
		t.Fatal("expected missing public IPv6 error")
	}
	if got.WAN.Device != "pppoe-wan" || got.WAN.Source != "default-route" {
		t.Fatalf("unexpected %#v", got)
	}
}

func TestResolveReportsCommandError(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "br-lan"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := fakeRunner{outputs: map[string]string{"ip -6 route show default": "", "ubus call network.interface.wan6 status": "{}"}, errors: map[string]error{"ip -6 -o addr show scope global": errors.New("ip failed")}}
	_, err := (Resolver{Runner: f, SysClassNet: root}).Resolve(context.Background(), "br-lan")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveLANMissingBridgeKeepsEmptyMembersArray(t *testing.T) {
	root := t.TempDir()
	got, err := (Resolver{SysClassNet: root}).ResolveLAN("br-lan")
	if err == nil {
		t.Fatal("expected missing bridge error")
	}
	if got.Bridge != "br-lan" {
		t.Fatalf("bridge=%q", got.Bridge)
	}
	if got.Members == nil {
		t.Fatal("members must be non-nil so JSON remains [] rather than null")
	}
	if len(got.Members) != 0 {
		t.Fatalf("members=%#v", got.Members)
	}
}

type countingRunner struct {
	outputs map[string]string
	errors  map[string]error
	calls   map[string]int
}

func (r *countingRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[key]++
	if err := r.errors[key]; err != nil {
		return nil, err
	}
	return []byte(r.outputs[key]), nil
}

func TestResolveWANSkipsUbusWhenDefaultRouteOwnsPublicIPv6(t *testing.T) {
	runner := &countingRunner{outputs: map[string]string{
		"ip -6 -o addr show scope global": "12: pppoe-wan inet6 2409:8a55:4f0c:353::1234/64 scope global dynamic\n",
		"ip -6 route show default":        "default via fe80::1 dev pppoe-wan metric 512\n",
	}}
	got, err := (Resolver{Runner: runner}).ResolveWAN(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicIPv6 != "2409:8a55:4f0c:353::1234" || got.Device != "pppoe-wan" {
		t.Fatalf("got=%+v", got)
	}
	if calls := runner.calls["ubus call network.interface.wan6 status"]; calls != 0 {
		t.Fatalf("ubus calls=%d want=0", calls)
	}
}

func TestResolveWANUsesUbusWhenDefaultRouteDoesNotOwnPublicIPv6(t *testing.T) {
	runner := &countingRunner{outputs: map[string]string{
		"ip -6 -o addr show scope global":         "12: odd-wan inet6 2409:8a55:4f0c:353::1234/64 scope global dynamic\n",
		"ip -6 route show default":                "default via fe80::1 dev pppoe-wan metric 512\n",
		"ubus call network.interface.wan6 status": `{"up":true,"l3_device":"odd-wan"}`,
	}}
	got, err := (Resolver{Runner: runner}).ResolveWAN(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicIPv6 != "2409:8a55:4f0c:353::1234" || got.Device != "odd-wan" {
		t.Fatalf("got=%+v", got)
	}
	if calls := runner.calls["ubus call network.interface.wan6 status"]; calls != 1 {
		t.Fatalf("ubus calls=%d want=1", calls)
	}
}
