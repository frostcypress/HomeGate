package frontend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateRequestAndJobLifecycle(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	input := filepath.Join(root, "input")
	for _, body := range []string{`{"route":"basic","form":{},"write":false}`, `{"route":"basic","unknown":"x"}`, `{"route":"basic"} {}`, strings.Repeat("x", 2*1024*1024+1)} {
		if err := os.WriteFile(input, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadRequest(input)
		if (err == nil) != (strings.Contains(body, `"form"`)) {
			t.Fatalf("request validity mismatch: %v", err)
		}
	}
	os.WriteFile(input, []byte(`{"route":"basic"}`), 0644)
	os.Chmod(input, 0644)
	if _, err := ReadRequest(input); err == nil {
		t.Fatal("public request accepted")
	}
	link := filepath.Join(root, "link")
	os.Symlink(input, link)
	if _, err := ReadRequest(link); err == nil {
		t.Fatal("symlink request accepted")
	}
	store := JobStore{Root: filepath.Join(root, "jobs")}
	os.Mkdir(store.Root, 0700)
	if store.Status("../escape", false).OK {
		t.Fatal("path traversal accepted")
	}
	id := strings.Repeat("a", 32)
	dir := filepath.Join(store.Root, id)
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "request"), []byte(`{"route":"basic_apply","form":{"mode":"save","ddns_interval":"600"},"write":true}`), 0600)
	if !store.Status(id, false).Pending {
		t.Fatal("missing pending state")
	}
	h := fixtureHost()
	if err := store.Work(context.Background(), id, Engine{Host: h}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "request")); !os.IsNotExist(err) {
		t.Fatal("credential request retained")
	}
	status := store.Status(id, false)
	if !status.OK || status.Pending || status.Result == nil || !status.Result.OK {
		t.Fatalf("%+v", status)
	}
	if err := store.Work(context.Background(), id, Engine{Host: h}); err == nil {
		t.Fatal("job executed twice")
	}
	store.Status(id, true)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("ack retained private result")
	}
}

func TestDaemonDetectionIgnoresBridgeCommands(t *testing.T) {
	for _, command := range []string{"/usr/bin/homegate\x00web-job\x00abcdef\x00", "/usr/bin/homegate\x00web-read\x00/tmp/request\x00", "/usr/bin/homegate\x00status\x00", "/usr/bin/other\x00daemon\x00", ""} {
		if isDaemonCommand([]byte(command)) {
			t.Fatalf("transient command counted as daemon: %q", command)
		}
	}
	if !isDaemonCommand([]byte("/usr/bin/homegate\x00daemon\x00")) {
		t.Fatal("actual daemon not recognized")
	}
}

func TestRecoveryRestoresBootIntentAfterRuntimeFailure(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var calls []string
		err := restoreIntent(context.Background(), func(_ context.Context, command string) (string, int) {
			calls = append(calls, command)
			if len(calls) == 1 {
				return "", 1
			}
			return "", 0
		}, true, enabled)
		if err == nil || len(calls) != 2 {
			t.Fatalf("calls=%v err=%v", calls, err)
		}
		wanted := "disable"
		if enabled {
			wanted = "enable"
		}
		if calls[1] != "/etc/init.d/homegate "+wanted+" >/dev/null 2>&1" {
			t.Fatal(calls)
		}
	}
}
