//go:build linux

package frontend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPKMetadataPreservesInstalledArchitecture(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	for _, arch := range []string{"aarch64", "aarch64_generic", "aarch64_cortex-a53", "aarch64_cortex-a72"} {
		body := "#!/bin/sh\nprintf '%s\\n' 'homegate-1.3.0-r4 " + arch + " {homegate} [installed]'\n"
		if err := os.WriteFile(filepath.Join(dir, "apk"), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		h := &OSHost{}
		output, code := h.Shell(context.Background(), "opkg status homegate")
		if code != 0 || !strings.Contains(output, "Version: 1.3.0-4\n") || !strings.Contains(output, "Architecture: "+arch+"\n") {
			t.Fatalf("arch=%s: code=%d output=%q", arch, code, output)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "apk"), []byte("#!/bin/sh\necho homegate-1.3.0-r4\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if output, code := (&OSHost{}).Shell(context.Background(), "opkg status homegate"); code == 0 || output != "" {
		t.Fatalf("malformed APK metadata accepted: %d %q", code, output)
	}
}
