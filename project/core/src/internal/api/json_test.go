package api

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteJSONKeepsUnicode(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, map[string]string{"name": "家庭公网服务"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\\u") {
		t.Fatalf("unicode escaped: %s", b.String())
	}
}
