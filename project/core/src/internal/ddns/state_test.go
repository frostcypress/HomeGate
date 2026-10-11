package ddns

import (
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
)

func TestStatusStoreRoundTripAndStableEmptyResults(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "ddns.json")}
	report := BuildReport("0.5.0", 300, nil)
	if report.Results == nil {
		t.Fatal("results must be [] not nil")
	}
	if err := store.Write(report); err != nil {
		t.Fatal(err)
	}
	got, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Results == nil {
		t.Fatal("read results must be [] not nil")
	}
	b, _ := json.Marshal(got)
	if string(b) == "" || !json.Valid(b) {
		t.Fatalf("json=%s", b)
	}
}

func TestStoreConcurrentWritesUseIndependentTempFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ddns.json")
	store := Store{Path: path}
	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			report := BuildReport("0.5.0", 300+i, []Result{})
			if err := store.Write(report); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent status write failed: %v", err)
	}
	if _, err := store.Read(); err != nil {
		t.Fatalf("final status unreadable: %v", err)
	}
}
