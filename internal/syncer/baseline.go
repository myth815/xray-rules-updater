package syncer

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
)

const baselineLimit = 4 << 20

// SnapshotBaselineDirectory returns the same strict snapshot used by generation
// so a native verifier can reject baseline edits after publication.
func SnapshotBaselineDirectory(dir string) ([]byte, error) {
	return readBaseline(Config{BaselineDirectory: dir})
}

// readBaseline supports the conventional one-top-level-module-per-file layout.
// It deliberately rejects duplicate modules instead of guessing Xray's merge
// semantics. Two identical reads detect edits during snapshot construction.
func readBaseline(c Config) ([]byte, error) {
	if c.BaselineDirectory == "" {
		return readLimited(c.Baseline, baselineLimit)
	}
	first, err := readModules(c.BaselineDirectory)
	if err != nil {
		return nil, err
	}
	second, err := readModules(c.BaselineDirectory)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(first, second) {
		return nil, errors.New("baseline directory changed during snapshot")
	}
	modules := map[string]json.RawMessage{}
	for _, body := range first {
		dec := json.NewDecoder(strings.NewReader(body))
		start, err := dec.Token()
		if err != nil || start != json.Delim('{') {
			return nil, errors.New("baseline module must be an object")
		}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return nil, errors.New("invalid baseline module")
			}
			name, ok := key.(string)
			if !ok || name == "" {
				return nil, errors.New("invalid baseline module name")
			}
			if _, exists := modules[name]; exists {
				return nil, errors.New("duplicate baseline module; native merge required")
			}
			var raw json.RawMessage
			if dec.Decode(&raw) != nil {
				return nil, errors.New("invalid baseline module value")
			}
			modules[name] = raw
		}
		if _, err = dec.Token(); err != nil {
			return nil, errors.New("invalid baseline module end")
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			return nil, errors.New("trailing baseline module data")
		}
	}
	if len(modules) == 0 {
		return nil, errors.New("empty baseline directory")
	}
	body, err := json.Marshal(modules)
	if err != nil || len(body) > baselineLimit {
		return nil, errors.New("baseline snapshot exceeds limit")
	}
	return body, nil
}

func readModules(dir string) (map[string]string, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("baseline directory must be a real directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("baseline directory read failed")
	}
	result := map[string]string{}
	total := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if len(result) >= 256 {
			return nil, errors.New("too many baseline modules")
		}
		fd, err := syscall.Open(filepath.Join(dir, entry.Name()), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, errors.New("baseline module open failed")
		}
		f := os.NewFile(uintptr(fd), entry.Name())
		stat, e := f.Stat()
		if e != nil || !stat.Mode().IsRegular() || stat.Size() > baselineLimit {
			_ = f.Close()
			return nil, errors.New("invalid baseline module file")
		}
		body, e := io.ReadAll(io.LimitReader(f, int64(baselineLimit-total)+1))
		_ = f.Close()
		total += len(body)
		if e != nil || total > baselineLimit {
			return nil, errors.New("baseline snapshot exceeds limit")
		}
		result[entry.Name()] = string(body)
	}
	return result, nil
}
