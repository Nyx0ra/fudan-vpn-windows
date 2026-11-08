package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSavedLogViewerLoadsBoundedRedactedHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desktop.log")
	data := strings.Repeat("old line\n", 1000) + "request https://example.test/?code=SECRET sid=TOKEN\nlast event\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	lines, err := readSavedLogs(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 800 || lines[len(lines)-1] != "last event" {
		t.Fatal("missing recent bounded history", len(lines))
	}
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "SECRET") || strings.Contains(joined, "TOKEN") {
		t.Fatal("credential escaped viewer")
	}
}
