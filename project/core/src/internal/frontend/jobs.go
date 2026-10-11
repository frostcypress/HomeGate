package frontend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// JobStore contains sensitive request/result files in root-only directories.
// Request fields never become command-line arguments. Only opaque IDs do.
type JobStore struct{ Root string }
type JobStatus struct {
	OK      bool    `json:"ok"`
	Job     string  `json:"job,omitempty"`
	Pending bool    `json:"pending,omitempty"`
	Result  *Result `json:"result,omitempty"`
	Error   string  `json:"error,omitempty"`
}

var jobID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ReadRequest(path string) (Request, error) {
	var request Request
	info, err := os.Lstat(path)
	if err != nil {
		return request, err
	}
	if !info.Mode().IsRegular() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 || info.Size() > 2*1024*1024 {
		return request, fmt.Errorf("unsafe request file")
	}
	file, err := os.Open(path)
	if err != nil {
		return request, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 2*1024*1024+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&request); err != nil {
		return request, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return request, fmt.Errorf("trailing request data")
	}
	return request, nil
}
func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("unsafe job directory")
	}
	return nil
}
func (s JobStore) path(id string) (string, error) {
	if !jobID.MatchString(id) {
		return "", fmt.Errorf("invalid job ID")
	}
	return filepath.Join(s.Root, id), nil
}
func (s JobStore) Submit(request Request) (JobStatus, error) {
	if !request.Write {
		return JobStatus{}, fmt.Errorf("write permission required")
	}
	entry, ok := Routes()[request.Route]
	if !ok || !entry.Write {
		return JobStatus{}, fmt.Errorf("not a write route")
	}
	if err := privateDir(s.Root); err != nil {
		return JobStatus{}, err
	}
	// A short allocation lock makes the queue bound effective across RPC processes.
	lock := filepath.Join(s.Root, ".allocation")
	if info, err := os.Lstat(lock); err == nil && info.IsDir() && time.Since(info.ModTime()) > 30*time.Second {
		_ = os.Remove(lock)
	}
	if err := os.Mkdir(lock, 0700); err != nil {
		return JobStatus{}, fmt.Errorf("queue busy; retry")
	}
	defer os.Remove(lock)
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return JobStatus{}, err
	}
	active := 0
	for _, item := range entries {
		if !jobID.MatchString(item.Name()) {
			continue
		}
		info, err := item.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > 10*time.Minute {
			os.RemoveAll(filepath.Join(s.Root, item.Name()))
		} else {
			active++
		}
	}
	if active >= 8 {
		return JobStatus{}, fmt.Errorf("job queue full")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return JobStatus{}, err
	}
	id := hex.EncodeToString(random)
	dir, _ := s.path(id)
	if err := os.Mkdir(dir, 0700); err != nil {
		return JobStatus{}, err
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > 2*1024*1024 {
		os.RemoveAll(dir)
		return JobStatus{}, fmt.Errorf("invalid request size")
	}
	if err = os.WriteFile(filepath.Join(dir, "request"), body, 0600); err != nil {
		os.RemoveAll(dir)
		return JobStatus{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		os.RemoveAll(dir)
		return JobStatus{}, err
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		os.RemoveAll(dir)
		return JobStatus{}, err
	}
	defer null.Close()
	worker := exec.Command(executable, "web-job", id)
	worker.Stdin = null
	worker.Stdout = null
	worker.Stderr = null
	if err = worker.Start(); err != nil {
		os.RemoveAll(dir)
		return JobStatus{}, err
	}
	_ = worker.Process.Release()
	return JobStatus{OK: true, Job: id, Pending: true}, nil
}
func (s JobStore) Work(ctx context.Context, id string, engine Engine) error {
	if err := privateDir(s.Root); err != nil {
		return err
	}
	dir, err := s.path(id)
	if err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("unsafe job")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "working"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	lock.Close()
	request, err := ReadRequest(filepath.Join(dir, "request"))
	result := Result{APIVersion: 1, Error: "Invalid job request"}
	if err == nil {
		result = engine.Run(ctx, request)
	}
	os.Remove(filepath.Join(dir, "request")) // secrets disappear immediately after execution
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	pending := filepath.Join(dir, "result.tmp")
	if err = os.WriteFile(pending, body, 0600); err != nil {
		return err
	}
	return os.Rename(pending, filepath.Join(dir, "result"))
}
func (s JobStore) Status(id string, ack bool) JobStatus {
	if err := privateDir(s.Root); err != nil {
		return JobStatus{Error: "Unsafe job store"}
	}
	dir, err := s.path(id)
	if err != nil {
		return JobStatus{Error: "Invalid job ID"}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return JobStatus{Error: "Job not found"}
	}
	body, err := os.ReadFile(filepath.Join(dir, "result"))
	if os.IsNotExist(err) {
		if time.Since(info.ModTime()) > 4*time.Minute {
			return JobStatus{Error: "Job timed out"}
		}
		return JobStatus{OK: true, Job: id, Pending: true}
	}
	var result Result
	if err != nil || len(body) > 5*1024*1024 || json.Unmarshal(body, &result) != nil {
		return JobStatus{Error: "Invalid job result"}
	}
	if ack {
		os.RemoveAll(dir)
	}
	return JobStatus{OK: true, Job: id, Result: &result}
}
