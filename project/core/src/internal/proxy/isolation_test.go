package proxy

import (
	"fmt"
	"os"
	"testing"
)

// The standalone offline test binary can run as root on an active router.
// New() and runtime reloads use the default access recorder unless overridden;
// every test must stay private even when it omits its own recorder fixture.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "homegate-proxy-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.Setenv("HOMEGATE_ACCESS_RECENT", dir+"/access.json"); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}
