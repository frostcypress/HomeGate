package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"homegate.local/homegate/internal/dnsprovider"
	"sort"
	"strings"
	"time"
)

// Isolated host: no shell commands, network calls or router files are accessed.
type memoryHost struct {
	doc             *Document
	calls           []string
	commits, begins int
	failCommit      bool
	files           map[string][]byte
}

func fixtureHost() *memoryHost {
	d, _ := ParseDocument("homegate.main=homegate\nhomegate.main.enabled='0'\nhomegate.main.ddns_interval='300'\nhomegate.main.https_port='443'\nhomegate.main.proxy_https_port='10443'\n", "homegate")
	return &memoryHost{doc: d, files: map[string][]byte{}}
}
func clone(d *Document) *Document {
	b, _ := json.Marshal(d)
	var result Document
	json.Unmarshal(b, &result)
	return &result
}
func (h *memoryHost) Load(_ context.Context, p string) (*Document, error) {
	if p == "homegate" {
		return clone(h.doc), nil
	}
	return &Document{}, nil
}
func (h *memoryHost) Commit(_ context.Context, d *Document) error {
	h.commits++
	if h.failCommit {
		return fmt.Errorf("fixture failure")
	}
	h.doc = clone(d)
	return nil
}
func (h *memoryHost) Begin(_ context.Context) (func(bool) error, error) {
	h.begins++
	before := clone(h.doc)
	return func(ok bool) error {
		if !ok {
			h.doc = before
		}
		return nil
	}, nil
}
func (h *memoryHost) Read(p string) ([]byte, error) {
	if b, ok := h.files[p]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("missing fixture file")
}
func (h *memoryHost) Write(p string, b []byte) error {
	h.files[p] = append([]byte(nil), b...)
	return nil
}
func (h *memoryHost) Remove(p string) error { delete(h.files, p); return nil }
func (h *memoryHost) Stat(p string) (map[string]any, error) {
	if _, ok := h.files[p]; ok {
		return map[string]any{"mtime": 1}, nil
	}
	return nil, fmt.Errorf("missing fixture file")
}
func (h *memoryHost) Chmod(string, uint32) error { return nil }
func (h *memoryHost) Shell(_ context.Context, cmd string) (string, int) {
	h.calls = append(h.calls, cmd)
	if strings.Contains(cmd, "echo \"B|$bn\"") {
		return "B|br-lan\nM|br-lan|eth0|ethernet\n", 0
	}
	if strings.HasPrefix(cmd, "opkg status ") {
		return "Package: homegate\nVersion: 1.3.0-1\nArchitecture: aarch64_cortex-a53\n", 0
	}
	if strings.Contains(cmd, "dns-provider-catalog") {
		b, _ := json.Marshal(map[string]any{"ok": true, "providers": dnsprovider.Definitions()})
		return string(b), 0
	}
	if strings.Contains(cmd, "acme-ca-catalog") {
		return `{"ok":true,"cas":[]}`, 0
	}
	if strings.Contains(cmd, "/usr/bin/homegate") {
		return `{"api_version":1,"ok":true,"version":"1.3.0-1"}`, 0
	}
	return "", 0
}

type OfflineCase struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Scope  string `json:"scope"`
}
type OfflineReport struct {
	APIVersion int           `json:"api_version"`
	Version    string        `json:"version"`
	OK         bool          `json:"ok"`
	DurationMS int64         `json:"duration_ms"`
	Cases      []OfflineCase `json:"cases"`
}

func SelfTest(ctx context.Context, version string) OfflineReport {
	start := time.Now()
	report := OfflineReport{APIVersion: 1, Version: version, OK: true}
	check := func(name string, passed bool) {
		status := "PASS"
		if !passed {
			status = "FAIL"
			report.OK = false
		}
		report.Cases = append(report.Cases, OfflineCase{Name: name, Status: status, Scope: "isolated-fake-host"})
	}
	for name, route := range Routes() {
		h := fixtureHost()
		result := (Engine{Host: h, Version: version}).Run(ctx, Request{Route: name})
		if route.Write {
			check("ACL/read-denies/"+name, !result.OK && h.begins == 0 && len(h.calls) == 0)
		} else {
			check("read/"+name, result.OK && h.begins == 0 && h.commits == 0)
		}
	}
	h := fixtureHost()
	result := (Engine{Host: h}).Run(ctx, Request{Route: "basic_apply", Write: true, Form: map[string]string{"mode": "save", "ddns_interval": "600"}})
	check("basic/save", result.OK && h.commits == 1 && h.doc.Find("main").Values["ddns_interval"] == "600")
	h = fixtureHost()
	result = (Engine{Host: h}).Run(ctx, Request{Route: "basic_apply", Write: true, Form: map[string]string{"ddns_interval": "1"}})
	check("basic/reject-invalid", !result.OK && h.commits == 0)
	h = fixtureHost()
	h.failCommit = true
	result = (Engine{Host: h}).Run(ctx, Request{Route: "basic_apply", Write: true, Form: map[string]string{"mode": "save", "ddns_interval": "600"}})
	check("basic/commit-failure", !result.OK && h.doc.Find("main").Values["ddns_interval"] == "300")
	for name, form := range map[string]map[string]string{"unknown-route": {}, "invalid-field": {"bad-field": "secret-fixture"}, "nul-field": {"x": "a\x00b"}, "oversize": {"x": strings.Repeat("a", 2*1024*1024)}} {
		h := fixtureHost()
		route := "basic"
		if name == "unknown-route" {
			route = "unknown"
		}
		result = (Engine{Host: h}).Run(ctx, Request{Route: route, Form: form})
		check("request/"+name, !result.OK && len(h.calls) == 0)
	}
	report.Cases = append(report.Cases, OfflineCase{Name: "live-DNS-ACME-proxy-firewall-WOL", Status: "SKIP", Scope: "requires-router-and-external-infrastructure"})
	sort.Slice(report.Cases, func(i, j int) bool { return report.Cases[i].Name < report.Cases[j].Name })
	report.DurationMS = time.Since(start).Milliseconds()
	return report
}
