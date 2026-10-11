package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/network"
	"homegate.local/homegate/internal/wol"
)

type staticConfigLoader struct{ cfg config.Snapshot }

func (l staticConfigLoader) Load(context.Context) (config.Snapshot, error) { return l.cfg, nil }

type fakeWOLSender struct {
	ifname  string
	members []string
	mac     string
	result  wol.SendResult
	err     error
}

func (s *fakeWOLSender) Send(ifname string, members []string, mac string) (wol.SendResult, error) {
	s.ifname = ifname
	s.members = append([]string(nil), members...)
	s.mac = mac
	return s.result, s.err
}

func TestWakeWOLHostUsesLANResolverAndSavedHost(t *testing.T) {
	cfg, err := config.ParseShow(`homegate.main=homegate
homegate.main.wol_interface='br-lan'
homegate.main.last_wol_host='wol_pve'
homegate.wol_pve=wol_host
homegate.wol_pve.name='PVE'
homegate.wol_pve.mac='c8:7f:54:53:6b:80'
`)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "br-lan", "brif"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"eth5", "eth1"} {
		if err := os.WriteFile(filepath.Join(root, "br-lan", "brif", name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fake := &fakeWOLSender{result: wol.SendResult{RawSent: 9, UDPSent: 6, Interfaces: []string{"br-lan", "eth1", "eth5"}}}
	a := App{
		Version:   "0.5.0",
		Config:    config.NewManager(staticConfigLoader{cfg: cfg}),
		Network:   network.Resolver{SysClassNet: root},
		WOLSender: fake,
		LogPath:   filepath.Join(t.TempDir(), "homegate.log"),
	}
	r, err := a.WakeWOLHost(context.Background(), "wol_pve")
	if err != nil {
		t.Fatal(err)
	}
	if fake.ifname != "br-lan" || fake.mac != "C8:7F:54:53:6B:80" {
		t.Fatalf("sender if=%q mac=%q", fake.ifname, fake.mac)
	}
	if !reflect.DeepEqual(fake.members, []string{"eth1", "eth5"}) {
		t.Fatalf("members=%v", fake.members)
	}
	if !r.OK || r.Host != "wol_pve" || r.RawSent != 9 || r.UDPSent != 6 || len(r.Interfaces) != 3 {
		t.Fatalf("report=%+v", r)
	}
}

func TestWOLStatusPreservesR6Selection(t *testing.T) {
	cfg, err := config.ParseShow(`homegate.main=homegate
homegate.main.wol_interface='br-lan'
homegate.main.last_wol_host='wol_pve'
homegate.wol_pve=wol_host
homegate.wol_pve.name='PVE'
homegate.wol_pve.mac='c8:7f:54:53:6b:80'
`)
	if err != nil {
		t.Fatal(err)
	}
	a := App{Version: "0.5.0", Config: config.NewManager(staticConfigLoader{cfg: cfg})}
	r := a.WOLStatus(context.Background())
	if !r.OK || r.Interface != "br-lan" || r.SelectedHost != "wol_pve" || len(r.Hosts) != 1 || r.Hosts[0].MAC != "C8:7F:54:53:6B:80" {
		t.Fatalf("status=%+v", r)
	}
}

func TestWakeWOLDirectDoesNotDependOnConfigValidity(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "br-lan", "brif"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "br-lan", "brif", "eth2"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeWOLSender{result: wol.SendResult{RawSent: 6, UDPSent: 6, Interfaces: []string{"br-lan", "eth2"}}}
	a := App{
		Version:   "0.5.0",
		Config:    nil,
		Network:   network.Resolver{SysClassNet: root},
		WOLSender: fake,
		LogPath:   filepath.Join(t.TempDir(), "homegate.log"),
	}
	r, err := a.WakeWOLDirect(context.Background(), "br-lan", "c8:7f:54:53:6b:80")
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || fake.ifname != "br-lan" || fake.mac != "c8:7f:54:53:6b:80" {
		t.Fatalf("report=%+v sender_if=%q mac=%q", r, fake.ifname, fake.mac)
	}
}
