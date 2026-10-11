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

func fixedHuaweiProvider(endpoint string) *HuaweiCloudProvider {
	return &HuaweiCloudProvider{
		AccessKey: "ak", SecretKey: "sk", AccountID: "domain-id", Endpoint: endpoint,
		Now: func() time.Time { return time.Date(2026, 9, 16, 15, 0, 0, 0, time.UTC) },
	}
}

func TestHuaweiSigningHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Sdk-Date") != "20260916T150000Z" || r.Header.Get("X-Domain-ID") != "domain-id" {
			t.Fatalf("headers=%v", r.Header)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "SDK-HMAC-SHA256 Access=ak, SignedHeaders=content-type;host;x-domain-id;x-sdk-date, Signature=") {
			t.Fatalf("auth=%q", auth)
		}
		io.WriteString(w, `{"zones":[],"metadata":{"total_count":0}}`)
	}))
	defer srv.Close()
	if err := fixedHuaweiProvider(srv.URL).ValidateCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHuaweiTXTAppendAndExactCleanup(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1, 4: // zone resolve
			io.WriteString(w, `{"zones":[{"id":"z1","name":"example.com."}],"metadata":{"total_count":1}}`)
		case 2: // record list before upsert
			io.WriteString(w, `{"recordsets":[{"id":"r1","name":"_acme-challenge.example.com.","type":"TXT","ttl":300,"records":["\"unrelated\""]}],"metadata":{"total_count":1}}`)
		case 3: // update append
			if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/recordsets/r1") {
				t.Fatalf("update %s %s", r.Method, r.URL.Path)
			}
			var body struct {
				Records []string `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.Records) != 2 || body.Records[0] != `"unrelated"` || body.Records[1] != `"challenge"` {
				t.Fatalf("records=%q", body.Records)
			}
			io.WriteString(w, `{}`)
		case 5: // record list before delete
			io.WriteString(w, `{"recordsets":[{"id":"r1","name":"_acme-challenge.example.com.","type":"TXT","ttl":300,"records":["\"unrelated\"","\"challenge\""]}],"metadata":{"total_count":1}}`)
		case 6: // update exact cleanup
			var body struct {
				Records []string `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.Records) != 1 || body.Records[0] != `"unrelated"` {
				t.Fatalf("records=%q", body.Records)
			}
			io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected call %d %s %s", calls, r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	p := fixedHuaweiProvider(srv.URL)
	op, err := p.Upsert(context.Background(), "example.com", "_acme-challenge", "TXT", "challenge", 300)
	if err != nil || op != "created" {
		t.Fatalf("op=%s err=%v", op, err)
	}
	if err := p.Delete(context.Background(), "example.com", "_acme-challenge", "TXT", "challenge"); err != nil {
		t.Fatal(err)
	}
	if calls != 6 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestHuaweiDeleteLastTXTDeletesRecordSet(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			io.WriteString(w, `{"zones":[{"id":"z1","name":"example.com."}]}`)
		case 2:
			io.WriteString(w, `{"recordsets":[{"id":"r1","name":"_acme-challenge.example.com.","type":"TXT","ttl":300,"records":["\"challenge\""]}]}`)
		case 3:
			if r.Method != http.MethodDelete {
				t.Fatalf("method=%s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("call=%d", calls)
		}
	}))
	defer srv.Close()
	if err := fixedHuaweiProvider(srv.URL).Delete(context.Background(), "example.com", "_acme-challenge", "TXT", "challenge"); err != nil {
		t.Fatal(err)
	}
}

func TestHuaweiErrorIsSanitized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"code":"APIG.0301","message":"denied"}`)
	}))
	defer srv.Close()
	p := &HuaweiCloudProvider{AccessKey: "visible-ak", SecretKey: "super-secret-sk", AccountID: "domain-id", Endpoint: srv.URL}
	err := p.ValidateCredentials(context.Background())
	if err == nil || strings.Contains(err.Error(), "super-secret-sk") || strings.Contains(err.Error(), "visible-ak") {
		t.Fatalf("err=%v", err)
	}
	kind, _, code := ErrorDetails(err)
	if kind != ErrorAuthentication || code != "APIG.0301" {
		t.Fatalf("kind=%s code=%s err=%v", kind, code, err)
	}
}
