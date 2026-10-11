package logger

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTailOrderAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		input    string
		limit    int
		want     []string
		overflow bool
	}{
		{"", 3, []string{}, false},
		{"a\nb\n", 3, []string{"a", "b"}, false},
		{"a\nb\nc\n", 3, []string{"a", "b", "c"}, false},
		{"a\nb\nc\nd\ne\n", 3, []string{"c", "d", "e"}, true},
		{"a\nb\nc\nd\n", 1, []string{"d"}, true},
	} {
		got, overflow, err := readTail(strings.NewReader(tc.input), tc.limit)
		if err != nil || !reflect.DeepEqual(got, tc.want) || overflow != tc.overflow {
			t.Fatalf("tail(%q, %d) = %v, %v, %v", tc.input, tc.limit, got, overflow, err)
		}
	}
}

func TestTrimAtLimitDoesNotReplaceFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if err := trimFile(path, 3); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("log at retention limit was needlessly rewritten")
	}
}

func BenchmarkTail(b *testing.B) {
	var input strings.Builder
	for i := 0; i < 40000; i++ {
		fmt.Fprintf(&input, "line-%d\n", i)
	}
	text := input.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = readTail(strings.NewReader(text), 20000)
	}
}

func BenchmarkTailBeforeAudit(b *testing.B) {
	var input strings.Builder
	for i := 0; i < 40000; i++ {
		fmt.Fprintf(&input, "line-%d\n", i)
	}
	text := input.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lines := make([]string, 0, 20001)
		s := bufio.NewScanner(strings.NewReader(text))
		for s.Scan() {
			lines = append(lines, s.Text())
			if len(lines) > 20000 {
				copy(lines, lines[len(lines)-20000:])
				lines = lines[:20000]
			}
		}
	}
}
