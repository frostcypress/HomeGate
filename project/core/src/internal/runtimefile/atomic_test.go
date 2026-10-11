package runtimefile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicReplacesCompleteFileAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("x"), 128*1024)
	want = append(want, '\n')
	if err := WriteAtomic(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("final runtime file mismatch: got=%d want=%d", len(got), len(want))
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".status.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

func TestWriteJSONAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	if err := WriteJSONAtomic(path, map[string]any{"ok": true, "n": 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\"n\":3,\"ok\":true}\n" {
		t.Fatalf("unexpected JSON: %q", got)
	}
}
