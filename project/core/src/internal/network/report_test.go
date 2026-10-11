package network

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestReportSerializesFailedLANMembersAsArray(t *testing.T) {
	r := BuildReport("0.5.0", Result{
		WAN: WANResult{PublicIPv6: "2409::1", Device: "pppoe-wan", Source: "public-ip"},
		LAN: LANResult{Bridge: "br-lan", Members: []string{}},
	}, errors.New("LAN bridge br-lan does not exist"))
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"members":[]`) {
		t.Fatalf("schema regression: %s", s)
	}
	if strings.Contains(s, `"members":null`) {
		t.Fatalf("schema regression: %s", s)
	}
}
