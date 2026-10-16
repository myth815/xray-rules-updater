package verify

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const diagnosticLogLimit = 64 << 10

// Reject overlap in either direction: a private diagnostic mount must neither
// contain the publication root nor be reachable inside the served tree.
func pathsOverlap(a, b string) bool {
	within := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return within(a, b) || within(b, a)
}

func prepareDiagnosticDir(dir, publish string) error {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return failure("verify_diagnostics")
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	resolvedPublish, err := filepath.EvalSymlinks(publish)
	if err != nil || pathsOverlap(resolvedDir, resolvedPublish) {
		return failure("verify_diagnostics")
	}
	return os.Chmod(dir, 0700)
}

// writeDiagnostics runs after both children have been reaped and logs closed.
// The directory is a separately mounted private destination, never /publish.
func writeDiagnostics(dir string, s Summary, xrayLog, mosdnsLog string) error {
	for _, log := range []struct{ name, source string }{{"last-xray.log", xrayLog}, {"last-mosdns.log", mosdnsLog}} {
		if s.Status == "verified" || log.source == "" {
			if err := removeDiagnostic(filepath.Join(dir, log.name)); err != nil {
				return err
			}
			continue
		}
		body, err := readDiagnostic(log.source, diagnosticLogLimit)
		if os.IsNotExist(err) {
			if err = removeDiagnostic(filepath.Join(dir, log.name)); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if err = writeSummary(dir, s.RunID, log.name, body); err != nil {
			return err
		}
	}
	metadata := struct {
		Summary
		MemoryEvents   string `json:"memory_events,omitempty"`
		MemoryPressure string `json:"memory_pressure,omitempty"`
	}{Summary: s}
	if s.Status != "verified" {
		// Optional cgroup v2 evidence is bounded and remains in private metadata.
		if b, err := readDiagnostic("/sys/fs/cgroup/memory.events", 4096); err == nil {
			metadata.MemoryEvents = string(b)
		}
		if b, err := readDiagnostic("/sys/fs/cgroup/memory.pressure", 4096); err == nil {
			metadata.MemoryPressure = string(b)
		}
	}
	body, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return writeSummary(dir, s.RunID, "last.json", append(body, '\n'))
}

func removeDiagnostic(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func readDiagnostic(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
