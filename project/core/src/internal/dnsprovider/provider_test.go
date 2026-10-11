package dnsprovider

import (
	"errors"
	"testing"
)

func TestErrorDetailsFindsWrappedProviderError(t *testing.T) {
	base := NewError("aliyun", "zones.list", ErrorRateLimit, "Throttling.User", "slow down", true, nil)
	wrapped := errors.Join(errors.New("outer"), base)
	kind, retryable, code := ErrorDetails(wrapped)
	if kind != ErrorRateLimit || !retryable || code != "Throttling.User" {
		t.Fatalf("kind=%s retryable=%v code=%q", kind, retryable, code)
	}
}

func TestUnsupportedIsMachineReadable(t *testing.T) {
	err := Unsupported("example", "zones.list")
	kind, retryable, _ := ErrorDetails(err)
	if kind != ErrorUnsupported || retryable {
		t.Fatalf("kind=%s retryable=%v", kind, retryable)
	}
}
