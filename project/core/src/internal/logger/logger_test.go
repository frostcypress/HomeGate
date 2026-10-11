package logger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestReconfigureChangesLevelAndImmediatelyShrinksExistingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "homegate.log")
	l := New("error", path, 100)
	l.Infof("hidden")
	l.Errorf("old-one")
	l.Errorf("old-two")
	l.Errorf("old-three")

	// Lowering maxLines on reload trims the existing file immediately. Normal
	// writes remain batch-trimmed to avoid rewriting flash for every log line.
	l.Reconfigure("debug", 2)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 2 {
		t.Fatalf("reload retention not applied: %d lines: %s", len(lines), data)
	}

	l.Debugf("new-debug")
	l.Infof("new-info")
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "hidden") || !strings.Contains(text, "new-debug") || !strings.Contains(text, "new-info") {
		t.Fatalf("unexpected log after reconfigure: %s", text)
	}
}

func TestSanitizeSecrets(t *testing.T) {
	in := `GET https://alidns.aliyuncs.com/?AccessKeyId=LTAI-demo&Action=DescribeSubDomainRecords&Signature=abc%2F123&SignatureNonce=nonce Authorization: Bearer very-secret-token`
	got := Sanitize(in)
	for _, secret := range []string{"LTAI-demo", "abc%2F123", "nonce", "very-secret-token"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret leaked in %q", got)
		}
	}
	if !strings.Contains(got, "Action=DescribeSubDomainRecords") || !strings.Contains(got, "<redacted>") {
		t.Fatalf("useful context lost in %q", got)
	}
}

func TestConcurrentTrimUsesIndependentTempFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "homegate.log")
	var content strings.Builder
	for i := 0; i < 256; i++ {
		content.WriteString("line\n")
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := trimFile(path, 64); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent trim failed: %v", err)
	}
}
