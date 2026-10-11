package acme

import (
	"net/http"
	"testing"
)

func TestDefaultHTTPClientDisablesEnvironmentProxy(t *testing.T) {
	h, ok := defaultHTTPClient().(*http.Client)
	if !ok {
		t.Fatalf("default client type %T", defaultHTTPClient())
	}
	tr, ok := h.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type %T", h.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("ACME transport must not inherit HTTP_PROXY/HTTPS_PROXY")
	}
}
