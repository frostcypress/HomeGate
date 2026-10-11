package frontend

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAccountReuseAndSecretRedaction(t *testing.T) {
	h := fixtureHost()
	engine := Engine{Host: h}
	r := engine.Run(context.Background(), Request{Route: "public_account_apply", Write: true, Form: map[string]string{"provider": "aliyun", "key_id": "fixture-key", "secret": "fixture-secret-never-render"}})
	if !r.OK {
		t.Fatalf("account creation: %+v", r)
	}
	count := 0
	id := ""
	for _, s := range h.doc.Sections {
		if s.Type == "dns_account" {
			count++
			id = s.Name
		}
	}
	if count != 1 {
		t.Fatal("account was not created exactly once")
	}
	r = engine.Run(context.Background(), Request{Route: "public_account_apply", Write: true, Form: map[string]string{"provider": "aliyun", "key_id": "fixture-key", "secret": ""}})
	if !r.OK || h.doc.Find(id).Values["secret"] != "fixture-secret-never-render" {
		t.Fatalf("secret was lost: %+v", r)
	}
	count = 0
	for _, s := range h.doc.Sections {
		if s.Type == "dns_account" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("identity reuse created duplicate account")
	}
	r = engine.Run(context.Background(), Request{Route: "public"})
	body, _ := json.Marshal(r)
	if !r.OK || strings.Contains(string(body), "fixture-secret-never-render") {
		t.Fatal("page exposed secret or failed")
	}
}

func TestWOLFormRejectsDuplicateMACAndWAN(t *testing.T) {
	for _, form := range []map[string]string{
		{"mode": "save", "wol_interface": "wan", "wol_host_count": "0"},
		{"mode": "save", "wol_interface": "br-lan", "wol_host_count": "1", "wol_host_mac_1": "invalid"},
		{"mode": "save", "wol_interface": "br-lan", "wol_host_count": "2", "wol_host_mac_1": "AA:BB:CC:DD:EE:FF", "wol_host_mac_2": "AA:BB:CC:DD:EE:FF"},
	} {
		h := fixtureHost()
		r := (Engine{Host: h}).Run(context.Background(), Request{Route: "wol_apply", Write: true, Form: form})
		if r.OK || h.commits != 0 {
			t.Fatalf("invalid WOL form accepted: %+v", r)
		}
	}
}

func TestSelfTest(t *testing.T) {
	report := SelfTest(context.Background(), "1.3.0-1")
	if !report.OK {
		for _, c := range report.Cases {
			if c.Status == "FAIL" {
				t.Error(c.Name)
			}
		}
	}
}

func TestPagesAndReadACL(t *testing.T) {
	for _, name := range []string{"basic", "public", "wol", "maintenance"} {
		t.Run(name, func(t *testing.T) {
			h := fixtureHost()
			r := (Engine{Host: h}).Run(context.Background(), Request{Route: name})
			if !r.OK || r.Template != "homegate/"+name {
				t.Fatalf("%+v", r)
			}
			if h.begins != 0 || h.commits != 0 {
				t.Fatal("read mutated state")
			}
		})
	}
	for name, route := range Routes() {
		if route.Write {
			h := fixtureHost()
			r := (Engine{Host: h}).Run(context.Background(), Request{Route: name})
			if r.OK || h.begins != 0 || len(h.calls) != 0 {
				t.Fatalf("read ACL failed: %s %+v", name, r)
			}
		}
	}
}
func TestBasicSaveAndValidation(t *testing.T) {
	h := fixtureHost()
	r := (Engine{Host: h}).Run(context.Background(), Request{Route: "basic_apply", Write: true, Form: map[string]string{"mode": "save", "ddns_interval": "600", "https_port": "443", "proxy_https_port": "10443"}})
	if !r.OK || h.commits != 1 || h.doc.Find("main").Values["ddns_interval"] != "600" {
		t.Fatalf("save: %+v commits=%d", r, h.commits)
	}
	h = fixtureHost()
	before, _ := h.doc.Text()
	r = (Engine{Host: h}).Run(context.Background(), Request{Route: "basic_apply", Write: true, Form: map[string]string{"ddns_interval": "1"}})
	if r.OK || h.commits != 0 || func() string { s, _ := h.doc.Text(); return s }() != before {
		t.Fatalf("invalid input: %+v", r)
	}
	h = fixtureHost()
	h.failCommit = true
	r = (Engine{Host: h}).Run(context.Background(), Request{Route: "basic_apply", Write: true, Form: map[string]string{"mode": "save", "ddns_interval": "600"}})
	if r.OK || h.doc.Find("main").Values["ddns_interval"] != "300" {
		t.Fatalf("commit failure: %+v", r)
	}
}
func TestRequestLimits(t *testing.T) {
	for _, r := range []Request{{Route: "unknown"}, {Route: "basic", Form: map[string]string{"bad-key": "x"}}, {Route: "basic", Form: map[string]string{"x": "a\x00b"}}, {Route: "basic", Form: map[string]string{"x": strings.Repeat("x", 2*1024*1024)}}} {
		h := fixtureHost()
		out := (Engine{Host: h}).Run(context.Background(), r)
		if out.OK || len(h.calls) != 0 {
			t.Fatal("invalid request executed")
		}
	}
}
func TestUCIRoundTrip(t *testing.T) {
	d, err := ParseDocument("homegate.main=homegate\nhomegate.main.label='a'\\''b'\nhomegate.main.items='a b' 'c'\n", "homegate")
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Text()
	if err != nil || !strings.Contains(out, "list items 'a b'") || d.Find("main").Values["label"] != "a'b" {
		t.Fatalf("%s %v", out, err)
	}
}

func TestSingleItemListSurvivesSave(t *testing.T) {
	d, err := ParseDocument("homegate.main=homegate\nhomegate.main.items='one'\n", "homegate")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RestoreListTypes("package homegate\nconfig homegate 'main'\n list items 'one'\n"); err != nil {
		t.Fatal(err)
	}
	out, err := d.Text()
	if err != nil || !strings.Contains(out, "list items 'one'") || strings.Contains(out, "option items") {
		t.Fatalf("%s %v", out, err)
	}
}
