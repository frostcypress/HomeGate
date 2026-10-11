package dnsprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDNSPodSigningAndZoneList(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TC-Action") != "DescribeDomainList" || r.Header.Get("X-TC-Version") != "2021-03-23" {
			t.Fatalf("headers=%v", r.Header)
		}
		auth := r.Header.Get("Authorization")
		if !strings.Contains(auth, "TC3-HMAC-SHA256 Credential=sid/2026-09-16/dnspod/tc3_request") || !strings.Contains(auth, "Signature=") {
			t.Fatalf("auth=%q", auth)
		}
		io.WriteString(w, `{"Response":{"DomainList":[{"Name":"B.EXAMPLE."},{"Name":"a.example"}],"RequestId":"r"}}`)
	}))
	defer srv.Close()
	p := &DNSPodProvider{SecretID: "sid", SecretKey: "skey", Endpoint: srv.URL, Now: func() time.Time { return now }}
	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0] != "a.example" || zones[1] != "b.example" {
		t.Fatalf("zones=%v", zones)
	}
}

func TestDNSPodTXTExactDelete(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.Header.Get("X-TC-Action") {
		case "DescribeRecordList":
			io.WriteString(w, `{"Response":{"RecordList":[{"RecordId":1,"Value":"keep"},{"RecordId":2,"Value":"challenge"}]}}`)
		case "DeleteRecord":
			if body["RecordId"].(float64) != 2 {
				t.Fatalf("body=%v", body)
			}
			io.WriteString(w, `{"Response":{"RecordId":2}}`)
		default:
			t.Fatalf("action=%s", r.Header.Get("X-TC-Action"))
		}
	}))
	defer srv.Close()
	p := &DNSPodProvider{SecretID: "sid", SecretKey: "skey", Endpoint: srv.URL, Now: time.Now}
	if err := p.Delete(context.Background(), "example.com", "_acme-challenge", "TXT", "challenge"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}
