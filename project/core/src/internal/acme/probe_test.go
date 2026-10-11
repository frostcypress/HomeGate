package acme

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeDirectoryValidatesACMEDirectory(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/directory" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, srv.URL+"/nonce", srv.URL+"/account", srv.URL+"/order")
	}))
	defer srv.Close()

	if err := probeDirectory(context.Background(), srv.URL+"/directory", srv.Client()); err != nil {
		t.Fatal(err)
	}
}

func TestProbeDirectoryRejectsIncompleteDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"newNonce":"https://example/nonce"}`)
	}))
	defer srv.Close()

	if err := probeDirectory(context.Background(), srv.URL, srv.Client()); err == nil {
		t.Fatal("expected incomplete directory rejection")
	}
}

func TestProbeCARejectsRemovedPresetWithoutNetwork(t *testing.T) {
	if _, err := ProbeCA(context.Background(), "google", "production"); err == nil {
		t.Fatal("expected removed Google preset rejection")
	}
	if _, err := ProbeCA(context.Background(), "custom", "production"); err == nil {
		t.Fatal("expected removed custom ACME preset rejection")
	}
}
