package runtimefile

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteAtomic replaces path with data using a unique temporary file in the
// same directory. Readers therefore observe either the previous complete file
// or the new complete file, never a truncated in-place write.
func WriteAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}

	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create runtime temp file: %w", err)
	}
	tmp := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(tmp)
		}
	}()

	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod runtime temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write runtime temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync runtime temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close runtime temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("install runtime file: %w", err)
	}
	keep = true
	return nil
}

// WriteJSONAtomic marshals v as one JSON line and atomically replaces path.
func WriteJSONAtomic(path string, v any, mode fs.FileMode) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode runtime JSON: %w", err)
	}
	return WriteAtomic(path, append(data, '\n'), mode)
}
