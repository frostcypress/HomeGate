package dnsprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudflareTXTExactCreateAndDelete(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer token-secret" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1, 4: // zone lookup
			io.WriteString(w, `{"success":true,"result":[{"id":"z1","name":"example.com"}],"result_info":{"page":1,"total_pages":1}}`)
		case 2: // list before create
			io.WriteString(w, `{"success":true,"result":[{"id":"old","type":"TXT","name":"_acme-challenge.example.com","content":"unrelated","ttl":300}],"result_info":{"page":1,"total_pages":1}}`)
		case 3: // create challenge
			if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/dns_records") {
				t.Fatalf("create %s %s", r.Method, r.URL.Path)
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["content"] != "challenge" {
				t.Fatalf("body=%v", body)
			}
			io.WriteString(w, `{"success":true,"result":{"id":"new"}}`)
		case 5: // list before exact delete
			io.WriteString(w, `{"success":true,"result":[{"id":"old","type":"TXT","name":"_acme-challenge.example.com","content":"unrelated"},{"id":"new","type":"TXT","name":"_acme-challenge.example.com","content":"challenge"}],"result_info":{"page":1,"total_pages":1}}`)
		case 6:
			if r.Method != http.MethodDelete || !strings.HasSuffix(r.URL.Path, "/dns_records/new") {
				t.Fatalf("delete %s %s", r.Method, r.URL.Path)
			}
			io.WriteString(w, `{"success":true,"result":{"id":"new"}}`)
		default:
			t.Fatalf("unexpected call %d", calls)
		}
	}))
	defer srv.Close()
	p := &CloudflareProvider{Token: "token-secret", Endpoint: srv.URL}
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

func TestCloudflareErrorDoesNotEchoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`)
	}))
	defer srv.Close()
	p := &CloudflareProvider{Token: "super-secret-token", Endpoint: srv.URL}
	err := p.ValidateCredentials(context.Background())
	if err == nil || strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("err=%v", err)
	}
	kind, retryable, code := ErrorDetails(err)
	if kind != ErrorAuthentication || retryable || code != "9109" {
		t.Fatalf("kind=%s retryable=%v code=%s", kind, retryable, code)
	}
}
