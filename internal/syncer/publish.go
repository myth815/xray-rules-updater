package syncer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type FileInfo struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type Manifest struct {
	SchemaVersion    int                 `json:"schema_version"`
	GeneratorVersion string              `json:"generator_version"`
	Version          string              `json:"version"`
	CreatedAt        string              `json:"created_at"`
	Release          string              `json:"geo_release"`
	BaselineSHA256   string              `json:"baseline_sha256"`
	PolicySHA256     string              `json:"policy_sha256"`
	Files            map[string]FileInfo `json:"files"`
	Counts           map[string]int      `json:"counts"`
	Activation       string              `json:"activation"`
}

func freeBytes(root string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(root, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}
func usedBytes(root string) (int64, error) {
	var n int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		i, e := d.Info()
		if e != nil {
			return e
		}
		n += i.Size()
		return nil
	})
	return n, err
}
func capacity(root string, budget, reserve, extra int64) error {
	used, err := usedBytes(root)
	if err != nil {
		return errors.New("storage inspection failed")
	}
	free, err := freeBytes(root)
	if err != nil {
		return errors.New("free space inspection failed")
	}
	if extra < 0 || used > budget-extra || free < reserve || extra > free-reserve {
		return errors.New("storage budget or free space exhausted")
	}
	return nil
}
func durableWrite(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func pointer(root, name string) (string, error) {
	target, err := os.Readlink(filepath.Join(root, name))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", errors.New("publication pointer is not a symlink")
	}
	if filepath.Dir(target) != "versions" || !identifier.MatchString(filepath.Base(target)) {
		return "", errors.New("unsafe publication pointer")
	}
	return target, nil
}
func switchPointer(root, name, target, runID string) error {
	temporary := filepath.Join(root, "."+name+"-"+runID)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, filepath.Join(root, name)); err != nil {
		return err
	}
	if err := syncDir(root); err != nil {
		return &commitSyncError{name: name}
	}
	return nil
}

type commitSyncError struct{ name string }

func (e *commitSyncError) Error() string {
	return fmt.Sprintf("%s pointer committed but directory durability unconfirmed", e.name)
}
func validVersion(root, target string) (*Manifest, error) {
	data, err := readLimited(filepath.Join(root, target, "manifest.json"), 1<<20)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if json.Unmarshal(data, &m) != nil || m.SchemaVersion != 1 || m.Version != filepath.Base(target) || len(m.Files) < 3 {
		return nil, errors.New("invalid published manifest")
	}
	for name, info := range m.Files {
		if filepath.Base(name) != name || !filenameToken.MatchString(name) || !digest.MatchString(info.SHA256) || info.Bytes < 0 || info.Bytes > 128<<20 {
			return nil, errors.New("unsafe published file")
		}
		content, err := readLimited(filepath.Join(root, target, name), info.Bytes)
		if err != nil || int64(len(content)) != info.Bytes || hash(content) != info.SHA256 {
			return nil, errors.New("published file integrity failure")
		}
	}
	return &m, nil
}
func prune(root string) error {
	keep := map[string]bool{}
	for _, name := range []string{"current", "previous"} {
		p, err := pointer(root, name)
		if err != nil {
			return err
		}
		if p != "" {
			keep[filepath.Base(p)] = true
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "versions"))
	if err != nil {
		return err
	}
	for _, d := range entries {
		if !d.IsDir() || !identifier.MatchString(d.Name()) || keep[d.Name()] {
			continue
		}
		target := filepath.Join("versions", d.Name())
		if _, err := validVersion(root, target); err != nil {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, target)); err != nil {
			return err
		}
	}
	return nil
}
func publish(c Config, runID, version string, files map[string][]byte, m Manifest) (bool, error) {
	root := c.PublishDir
	target := filepath.Join("versions", version)
	existing, err := pointer(root, "current")
	if err != nil {
		return false, err
	}
	if existing != "" {
		if _, err := validVersion(root, existing); err != nil {
			return false, err
		}
	}
	if _, err := checkApplyAck(c, existing, target); err != nil {
		return false, err
	}
	if existing == target {
		return false, nil
	}
	m.SchemaVersion = 1
	m.Version = version
	m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	m.Files = map[string]FileInfo{}
	var total int64
	for name, data := range files {
		if filepath.Base(name) != name || !filenameToken.MatchString(name) {
			return false, errors.New("invalid generated filename")
		}
		m.Files[name] = FileInfo{hash(data), int64(len(data))}
		total += int64(len(data))
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return false, err
	}
	body = append(body, '\n')
	total += int64(len(body))
	if err := capacity(root, c.BudgetBytes, c.MinFreeBytes, total+(64<<10)); err != nil {
		return false, err
	}
	stage := filepath.Join(root, ".stage-"+runID)
	if err := os.Mkdir(stage, 0700); err != nil {
		return false, err
	}
	defer os.RemoveAll(stage)
	for name, data := range files {
		if err := durableWrite(filepath.Join(stage, name), data); err != nil {
			return false, errors.New("candidate write failed")
		}
	}
	if err := durableWrite(filepath.Join(stage, "manifest.json"), body); err != nil {
		return false, err
	}
	if c.ServeGroupID != nil {
		if err := groupReadable(stage, *c.ServeGroupID); err != nil {
			return false, errors.New("candidate group permissions failed")
		}
	}
	if err := syncDir(stage); err != nil {
		return false, err
	}
	destination := filepath.Join(root, target)
	if _, err := os.Lstat(destination); err == nil {
		previous, err := validVersion(root, target)
		if err != nil {
			return false, err
		}
		if len(previous.Files) != len(m.Files) {
			return false, errors.New("immutable version collision")
		}
		for name, info := range m.Files {
			if previous.Files[name] != info {
				return false, errors.New("immutable version collision")
			}
		}
	} else if os.IsNotExist(err) {
		if err := os.Rename(stage, destination); err != nil {
			return false, err
		}
		if err := syncDir(filepath.Join(root, "versions")); err != nil {
			return false, err
		}
	} else {
		return false, err
	}
	if existing != "" {
		if err := switchPointer(root, "previous", existing, runID); err != nil {
			return false, err
		}
	}
	if err := switchPointer(root, "current", target, runID); err != nil {
		var committed *commitSyncError
		return errors.As(err, &committed), err
	}
	// A pruning failure must not misreport a successfully committed pointer as unpublished.
	_ = pruneApplied(c)
	return true, nil
}
func prepareRoot(c Config, runID string) (func(), error) {
	if err := os.MkdirAll(c.PublishDir, 0700); err != nil {
		return nil, errors.New("publication directory creation failed")
	}
	info, err := os.Lstat(c.PublishDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("unsafe publication directory")
	}
	lock := filepath.Join(c.PublishDir, ".lock")
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("run lock open failed")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another run holds the lock")
	}
	cleanup := func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }
	if err := f.Truncate(0); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := f.WriteString(runID + "\n"); err != nil {
		cleanup()
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(c.PublishDir, "versions"), 0700); err != nil {
		cleanup()
		return nil, err
	}
	versions, err := os.Lstat(filepath.Join(c.PublishDir, "versions"))
	if err != nil || !versions.IsDir() || versions.Mode()&os.ModeSymlink != 0 {
		cleanup()
		return nil, errors.New("unsafe versions directory")
	}
	entries, err := os.ReadDir(c.PublishDir)
	if err != nil {
		cleanup()
		return nil, err
	}
	for _, d := range entries {
		if d.IsDir() && strings.HasPrefix(d.Name(), ".stage-") && identifier.MatchString(strings.TrimPrefix(d.Name(), ".stage-")) {
			if err := os.RemoveAll(filepath.Join(c.PublishDir, d.Name())); err != nil {
				cleanup()
				return nil, err
			}
		}
	}
	// Recover completed but unreferenced versions left by a crash before commit.
	for _, name := range []string{"current", "previous"} {
		target, e := pointer(c.PublishDir, name)
		if e != nil {
			cleanup()
			return nil, e
		}
		if target != "" {
			if _, e = validVersion(c.PublishDir, target); e != nil {
				cleanup()
				return nil, e
			}
		}
	}
	current, err := pointer(c.PublishDir, "current")
	if err != nil {
		cleanup()
		return nil, err
	}
	canPrune, err := checkApplyAck(c, current, "")
	if err != nil {
		cleanup()
		return nil, err
	}
	if canPrune {
		if err := pruneApplied(c); err != nil {
			cleanup()
			return nil, err
		}
	}
	if c.ServeGroupID != nil {
		if err := groupReadable(c.PublishDir, *c.ServeGroupID); err != nil {
			cleanup()
			return nil, errors.New("publication group permissions failed")
		}
	}
	return cleanup, nil
}

func groupReadable(root string, gid int) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if err := os.Chown(path, -1, gid); err != nil {
			return err
		}
		mode := os.FileMode(0640)
		if d.IsDir() {
			mode = 0750
		}
		return os.Chmod(path, mode)
	})
}
