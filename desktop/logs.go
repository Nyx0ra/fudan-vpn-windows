package main

import (
	"bufio"
	"io"
	"os"
)

// Read a bounded tail and redact again at the display boundary, including
// history written by an older client. Never launch a shell or change associations.
func readSavedLogs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	const limit = 256 << 10
	if info.Size() > limit {
		start = info.Size() - limit
	}
	scan := bufio.NewScanner(io.NewSectionReader(f, start, info.Size()-start))
	scan.Buffer(make([]byte, 4096), limit+1)
	if start > 0 {
		scan.Scan()
	}
	lines := []string{}
	for scan.Scan() {
		lines = append(lines, safeLog(scan.Text()))
		if len(lines) > maxLogLen {
			lines = lines[len(lines)-maxLogLen:]
		}
	}
	return lines, scan.Err()
}
