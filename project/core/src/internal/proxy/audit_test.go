package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyRebuildsForwardingHeaders(t *testing.T) {
	for _, connection := range []string{"", "X-Forwarded-Host, X-Forwarded-Proto"} {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("X-Forwarded-For"); got != "192.0.2.5" {
				t.Errorf("spoofed source forwarded: %q", got)
			}
			if got := r.Header.Get("Forwarded"); got != "" {
				t.Errorf("spoofed Forwarded preserved: %q", got)
			}
			if r.Header.Get("X-Forwarded-Host") != "test.example.com" || r.Header.Get("X-Forwarded-Proto") != "http" {
				t.Error("trusted forwarding metadata lost")
			}
		}))
		cfg := webConfig(backend.URL)
		cfg.Web[0].HTTPS = false
		routes, err := buildRoutes(cfg)
		if err != nil {
			t.Fatal(err)
		}
		m := New(t.TempDir(), nil, "test")
		m.routes = routes
		req := httptest.NewRequest("GET", "http://test.example.com/path?q=1", nil)
		req.RemoteAddr = "192.0.2.5:12345"
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("Forwarded", "for=127.0.0.1")
		req.Header.Set("Connection", connection)
		rr := httptest.NewRecorder()
		m.handler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d", rr.Code)
		}
		backend.Close()
	}
}

func TestFindRouteExactWildcardAndDepth(t *testing.T) {
	m := New(t.TempDir(), nil, "test")
	m.routes = map[string]route{
		"*.example.com":   {Domain: "*.example.com"},
		"www.example.com": {Domain: "www.example.com"},
	}
	for _, tc := range []struct{ host, want string }{
		{"WWW.EXAMPLE.COM.:443", "www.example.com"},
		{"a.example.com", "*.example.com"},
		{"example.com", ""},
		{"a.b.example.com", ""},
		{".example.com", ""},
		{"unrelated.example", ""},
	} {
		r, ok := m.findRoute(tc.host)
		if ok != (tc.want != "") || r.Domain != tc.want {
			t.Fatalf("%s => %q, %v", tc.host, r.Domain, ok)
		}
	}
}

func TestCloseAfterDeadlineClosesActiveConnection(t *testing.T) {
	m := New(t.TempDir(), nil, "test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered, disconnected := make(chan struct{}), make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(disconnected)
	})}
	m.httpServer, m.httpListener = srv, ln
	go srv.Serve(ln)
	defer srv.Close()
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.closeHTTP(ctx); err == nil {
		t.Fatal("expected cancelled graceful shutdown")
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("active connection survived shutdown")
	}
}

func BenchmarkFindRouteWildcard(b *testing.B) {
	m := New(b.TempDir(), nil, "test")
	for i := 0; i < 1000; i++ {
		d := fmt.Sprintf("host-%d.example.com", i)
		m.routes[d] = route{Domain: d}
	}
	m.routes["*.example.com"] = route{Domain: "*.example.com"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.findRoute("wild.example.com")
	}
}
