package logger

import (
	"bufio"
	"io"
)

// readTail retains the final limit lines in order with O(n) scanning and
// O(limit) memory. Each overflow replaces one slot instead of moving the tail.
func readTail(r io.Reader, limit int) ([]string, bool, error) {
	lines := make([]string, 0, limit)
	next := 0
	truncated := false
	s := bufio.NewScanner(r)
	for s.Scan() {
		if len(lines) < limit {
			lines = append(lines, s.Text())
		} else {
			truncated = true
			lines[next] = s.Text()
			next = (next + 1) % limit
		}
	}
	if err := s.Err(); err != nil {
		return nil, false, err
	}
	if next != 0 {
		ordered := make([]string, 0, len(lines))
		ordered = append(ordered, lines[next:]...)
		ordered = append(ordered, lines[:next]...)
		lines = ordered
	}
	return lines, truncated, nil
}
