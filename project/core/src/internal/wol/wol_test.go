package wol

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"homegate.local/homegate/internal/config"
)

func TestPacket(t *testing.T) {
	mac, _ := net.ParseMAC("C8:7F:54:53:6B:80")
	p := packet(mac)
	if len(p) != 102 {
		t.Fatalf("len=%d want 102", len(p))
	}
	if !bytes.Equal(p[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Fatalf("prefix=%x", p[:6])
	}
	for i := 0; i < 16; i++ {
		start := 6 + i*6
		if !bytes.Equal(p[start:start+6], mac) {
			t.Fatalf("copy %d=%x", i, p[start:start+6])
		}
	}
}

func TestEthernetFrame(t *testing.T) {
	src, _ := net.ParseMAC("00:03:7F:BA:DB:AD")
	dst, _ := net.ParseMAC("C8:7F:54:53:6B:80")
	f, err := ethernetFrame(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 116 {
		t.Fatalf("len=%d want 116", len(f))
	}
	if !bytes.Equal(f[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Fatalf("dst=%x", f[:6])
	}
	if !bytes.Equal(f[6:12], src) {
		t.Fatalf("src=%x", f[6:12])
	}
	if got := binary.BigEndian.Uint16(f[12:14]); got != 0x0842 {
		t.Fatalf("etherType=%04x", got)
	}
	if !bytes.Equal(f[14:], packet(dst)) {
		t.Fatal("payload mismatch")
	}
}

func TestUniqueInterfaces(t *testing.T) {
	got := uniqueInterfaces("br-lan", []string{"eth5", "eth1", "eth5", ""})
	want := []string{"br-lan", "eth1", "eth5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestBuildStatusEmptyArray(t *testing.T) {
	cfg, err := config.ParseShow("homegate.main=homegate\nhomegate.main.wol_interface='br-lan'\n")
	if err != nil {
		t.Fatal(err)
	}
	got := BuildStatus("0.5.0", cfg, nil)
	if !got.OK || got.Interface != "br-lan" || got.Hosts == nil || len(got.Hosts) != 0 {
		t.Fatalf("status=%+v", got)
	}
}

func TestFindHost(t *testing.T) {
	cfg, err := config.ParseShow("homegate.main=homegate\nhomegate.wol_pve=wol_host\nhomegate.wol_pve.name='PVE'\nhomegate.wol_pve.mac='c8:7f:54:53:6b:80'\n")
	if err != nil {
		t.Fatal(err)
	}
	h, err := FindHost(cfg, "wol_pve")
	if err != nil || h.MAC != "C8:7F:54:53:6B:80" {
		t.Fatalf("host=%+v err=%v", h, err)
	}
	if _, err := FindHost(cfg, "missing"); err == nil {
		t.Fatal("expected missing-host error")
	}
}
