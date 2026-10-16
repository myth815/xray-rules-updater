// Package verify runs mounted native validators in a short-lived, isolated
// container namespace. It never applies files to a production consumer.
package verify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/myth815/xray-rules-updater/internal/syncer"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	PublishDir      string `json:"publish_dir"`
	XrayBinary      string `json:"xray_binary"`
	XrayConfigDir   string `json:"xray_config_dir"`
	MosDNSBinary    string `json:"mosdns_binary"`
	MosDNSConfigDir string `json:"mosdns_config_dir"`
	DiagnosticDir   string `json:"diagnostic_dir,omitempty"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
}
type Summary struct {
	RunID               string           `json:"run_id"`
	Version             string           `json:"version,omitempty"`
	BaselineSHA256      string           `json:"baseline_sha256,omitempty"`
	Status              string           `json:"status"`
	ErrorCode           string           `json:"error_code,omitempty"`
	DiagnosticErrorCode string           `json:"diagnostic_error_code,omitempty"`
	Phase               string           `json:"phase,omitempty"`
	PhaseDurationsMS    map[string]int64 `json:"phase_durations_ms,omitempty"`
	DurationMS          int64            `json:"duration_ms"`
}
type failure string

func (e failure) Error() string { return string(e) }

var token = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var filename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._!-]{0,127}$`)
var digest = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var versionAssetPath = regexp.MustCompile(`/rules/versions/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/`)

func LoadConfig(data []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if len(data) > 1<<20 || dec.Decode(&c) != nil {
		return c, failure("verify_config")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return c, failure("verify_config")
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	return c, nil
}
func (c *Config) validate() error {
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 60
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 90 {
		return failure("verify_config")
	}
	for _, p := range []string{c.PublishDir, c.XrayBinary, c.XrayConfigDir, c.MosDNSBinary, c.MosDNSConfigDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return failure("verify_config")
		}
	}
	if c.DiagnosticDir != "" && (!filepath.IsAbs(c.DiagnosticDir) || filepath.Clean(c.DiagnosticDir) != c.DiagnosticDir || pathsOverlap(c.PublishDir, c.DiagnosticDir)) {
		return failure("verify_config")
	}
	return nil
}

// Run writes a safe verification.json summary. Native stdout/stderr goes to
// bounded temporary files, retained only after failure in an optional private
// diagnostic directory. Each run replaces the same diagnostic filenames.
func Run(parent context.Context, c Config) (s Summary, err error) {
	start := time.Now()
	var nonce [8]byte
	canWriteStatus := false
	var temporaryDir, diagnosticDir, xrayLog, mosdnsLog string
	if _, e := rand.Read(nonce[:]); e != nil {
		return s, failure("verify_identity")
	}
	s.RunID = hex.EncodeToString(nonce[:])
	s.Status = "failed"
	s.Phase = "configuration"
	s.PhaseDurationsMS = make(map[string]int64)
	phaseStarted := start
	finishPhase := func() {
		s.PhaseDurationsMS[s.Phase] += time.Since(phaseStarted).Milliseconds()
	}
	setPhase := func(phase string) {
		finishPhase()
		s.Phase = phase
		phaseStarted = time.Now()
	}
	defer func() {
		// All later process/log defers run before this one. Preserve diagnostic
		// bytes before removing the private temporary configuration and logs.
		if temporaryDir != "" {
			defer os.RemoveAll(temporaryDir)
		}
		finishPhase()
		s.DurationMS = time.Since(start).Milliseconds()
		if err != nil {
			var f failure
			if errors.As(err, &f) {
				s.ErrorCode = string(f)
			} else {
				s.ErrorCode = "verify_internal"
			}
		}
		if diagnosticDir != "" {
			if e := writeDiagnostics(diagnosticDir, s, xrayLog, mosdnsLog); e != nil {
				s.DiagnosticErrorCode = "verify_diagnostics_write"
				if err == nil {
					s.Status = "failed"
					s.ErrorCode = s.DiagnosticErrorCode
					err = failure(s.ErrorCode)
				}
			}
		}
		if canWriteStatus {
			body, _ := json.Marshal(s)
			if e := writeSummary(c.PublishDir, s.RunID, "verification.json", append(body, '\n')); e != nil && err == nil {
				s.Status = "failed"
				s.ErrorCode = "verify_status_write"
				err = failure(s.ErrorCode)
			}
		}
	}()
	if e := c.validate(); e != nil {
		return s, e
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	setPhase("publication")
	info, e := os.Lstat(c.PublishDir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return s, failure("verify_publication")
	}
	lock, e := os.OpenFile(filepath.Join(c.PublishDir, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return s, failure("verify_lock")
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
		return s, failure("verify_busy")
	}
	canWriteStatus = true
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if c.DiagnosticDir != "" {
		if e := prepareDiagnosticDir(c.DiagnosticDir, c.PublishDir); e != nil {
			return s, failure("verify_diagnostics")
		}
		diagnosticDir = c.DiagnosticDir
	}
	current, manifest, e := snapshot(ctx, c.PublishDir)
	if e != nil {
		return s, e
	}
	s.Version = manifest.Version
	s.BaselineSHA256 = manifest.BaselineSHA256
	for _, binary := range []string{c.XrayBinary, c.MosDNSBinary} {
		st, e := os.Stat(binary)
		if e != nil || !st.Mode().IsRegular() || st.Mode()&0111 == 0 {
			return s, failure("verify_binary")
		}
	}
	for _, dir := range []string{c.XrayConfigDir, c.MosDNSConfigDir} {
		st, e := os.Lstat(dir)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return s, failure("verify_native_config")
		}
	}
	setPhase("baseline_snapshot")
	baseline, e := syncer.SnapshotBaselineDirectory(c.XrayConfigDir)
	if e != nil || sumHex(baseline) != manifest.BaselineSHA256 {
		return s, failure("verify_baseline_changed")
	}
	if e := os.MkdirAll("/tmp", 0700); e != nil {
		return s, failure("verify_temp")
	}
	tmp, e := os.MkdirTemp("/tmp", "xray-rules-verify-")
	if e != nil {
		return s, failure("verify_temp")
	}
	temporaryDir = tmp
	setPhase("native_prepare")
	fullConfig := filepath.Join(tmp, "full-xray.json")
	if e := os.WriteFile(fullConfig, baseline, 0600); e != nil {
		return s, failure("verify_temp")
	}
	xrayLog = filepath.Join(tmp, "xray.log")
	xlog, e := newLog(xrayLog)
	if e != nil {
		return s, failure("verify_log")
	}
	defer xlog.Close()
	x := exec.CommandContext(ctx, c.XrayBinary, "run", "-test", "-config", fullConfig)
	x.Env = withAsset(os.Environ(), current)
	x.Stdout = xlog
	x.Stderr = xlog
	configureProcess(x)
	setPhase("xray_run_test")
	if e = x.Run(); e != nil {
		if ctx.Err() != nil {
			return s, failure("verify_timeout")
		}
		return s, failure("verify_xray")
	}
	setPhase("mosdns_prepare")
	mosdir := filepath.Join(tmp, "mosdns")
	if e = cloneMosDNS(c.MosDNSConfigDir, mosdir, current); e != nil {
		return s, e
	}
	mosdnsLog = filepath.Join(tmp, "mosdns.log")
	mlog, e := newLog(mosdnsLog)
	if e != nil {
		return s, failure("verify_log")
	}
	defer mlog.Close()
	m := exec.CommandContext(ctx, c.MosDNSBinary, "start", "--dir", mosdir)
	m.Stdout = mlog
	m.Stderr = mlog
	configureProcess(m)
	setPhase("mosdns_start")
	if e = m.Start(); e != nil {
		return s, failure("verify_mosdns_start")
	}
	p := watchProcess(m)
	defer p.stop()
	setPhase("mosdns_ready")
	if e = ready(ctx, p, "127.0.0.1:53"); e != nil {
		return s, e
	}
	for _, name := range []string{"www.baidu.com", "github.com"} {
		phase := "mosdns_probe_baidu"
		if name == "github.com" {
			phase = "mosdns_probe_github"
		}
		setPhase(phase)
		if e = query(ctx, "127.0.0.1:53", name, 0, true); e != nil {
			if ctx.Err() != nil {
				return s, failure("verify_timeout")
			}
			return s, failure("verify_dns_answer")
		}
	}
	select {
	case <-p.done:
		return s, failure("verify_mosdns_exit")
	default:
	}
	setPhase("baseline_recheck")
	baselineAfter, e := syncer.SnapshotBaselineDirectory(c.XrayConfigDir)
	if e != nil || sumHex(baselineAfter) != manifest.BaselineSHA256 {
		return s, failure("verify_baseline_changed")
	}
	s.Status = "verified"
	setPhase("complete")
	return s, nil
}

func writeSummary(root, id, name string, data []byte) error {
	p := filepath.Join(root, ".verification-"+id)
	f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(p)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(p, filepath.Join(root, name)); e != nil {
		return e
	}
	d, e := os.Open(root)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func withAsset(env []string, dir string) []string {
	out := make([]string, 0, len(env)+1)
	for _, v := range env {
		if !strings.HasPrefix(v, "XRAY_LOCATION_ASSET=") {
			out = append(out, v)
		}
	}
	return append(out, "XRAY_LOCATION_ASSET="+dir)
}

type manifest struct {
	SchemaVersion  int    `json:"schema_version"`
	Version        string `json:"version"`
	BaselineSHA256 string `json:"baseline_sha256"`
	Files          map[string]struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	} `json:"files"`
}

func sumHex(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func snapshot(ctx context.Context, root string) (string, *manifest, error) {
	target, e := os.Readlink(filepath.Join(root, "current"))
	if e != nil || filepath.Dir(target) != "versions" || !token.MatchString(filepath.Base(target)) {
		return "", nil, failure("verify_pointer")
	}
	for _, p := range []string{filepath.Join(root, "versions"), filepath.Join(root, target)} {
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return "", nil, failure("verify_pointer")
		}
	}
	dir := filepath.Join(root, target)
	body, e := readFile(filepath.Join(dir, "manifest.json"), 1<<20)
	if e != nil {
		return "", nil, failure("verify_manifest")
	}
	var m manifest
	if json.Unmarshal(body, &m) != nil || m.SchemaVersion != 1 || m.Version != filepath.Base(target) || !digest.MatchString(m.BaselineSHA256) {
		return "", nil, failure("verify_manifest")
	}
	for _, name := range []string{"geoip.dat", "geosite.dat", "onexray.json"} {
		if _, ok := m.Files[name]; !ok {
			return "", nil, failure("verify_manifest")
		}
	}
	for name, f := range m.Files {
		if ctx.Err() != nil {
			return "", nil, failure("verify_timeout")
		}
		if filepath.Base(name) != name || !filename.MatchString(name) || !digest.MatchString(f.SHA256) || f.Bytes < 0 || f.Bytes > 128<<20 {
			return "", nil, failure("verify_manifest")
		}
		p := filepath.Join(dir, name)
		st, e := os.Lstat(p)
		if e != nil || !st.Mode().IsRegular() || st.Size() != f.Bytes {
			return "", nil, failure("verify_integrity")
		}
		file, e := os.Open(p)
		if e != nil {
			return "", nil, failure("verify_integrity")
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(file, f.Bytes+1))
		file.Close()
		if e != nil || n != f.Bytes || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), f.SHA256) {
			return "", nil, failure("verify_integrity")
		}
	}
	return dir, &m, nil
}
func readFile(path string, limit int64) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, failure("verify_native_config")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, failure("verify_native_config")
	}
	return b, nil
}
func cloneMosDNS(source, dest, assets string) error {
	if e := os.MkdirAll(filepath.Join(dest, "rule"), 0700); e != nil {
		return failure("verify_temp")
	}
	for _, name := range []string{"config.yaml", "dns.yaml", "dat_exec.yaml"} {
		b, e := readFile(filepath.Join(source, name), 256<<10)
		if e != nil {
			return failure("verify_mosdns_config")
		}
		if bytes.Contains(b, []byte("geosite_ads")) || bytes.Contains(b, []byte("geosite_category-ads-all")) {
			return failure("verify_mosdns_ads_reference")
		}
		b = bytes.ReplaceAll(b, []byte("/etc/mosdns/"), []byte(dest+"/"))
		b = bytes.ReplaceAll(b, []byte("/var/mosdns/"), []byte(assets+"/"))
		b = bytes.ReplaceAll(b, []byte("/rules/current/"), []byte(assets+"/"))
		b = versionAssetPath.ReplaceAllFunc(b, func([]byte) []byte { return []byte(assets + "/") })
		if e = os.WriteFile(filepath.Join(dest, name), b, 0600); e != nil {
			return failure("verify_temp")
		}
	}
	entries, e := os.ReadDir(filepath.Join(source, "rule"))
	if e != nil {
		return failure("verify_mosdns_config")
	}
	if len(entries) > 64 {
		return failure("verify_mosdns_config")
	}
	var total int
	for _, entry := range entries {
		if !filename.MatchString(entry.Name()) || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return failure("verify_mosdns_config")
		}
		b, e := readFile(filepath.Join(source, "rule", entry.Name()), 1<<20)
		if e != nil {
			return failure("verify_mosdns_config")
		}
		total += len(b)
		if total > 8<<20 {
			return failure("verify_mosdns_config")
		}
		if e = os.WriteFile(filepath.Join(dest, "rule", entry.Name()), b, 0600); e != nil {
			return failure("verify_temp")
		}
	}
	return nil
}

// logFile drains output while storing no more than 64 KiB. It must report the
// original write length to avoid aborting a valid child after truncation.
type logFile struct {
	f    *os.File
	left int
	mu   sync.Mutex
}

func newLog(path string) (*logFile, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	return &logFile{f: f, left: 64 << 10}, e
}
func (l *logFile) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(b)
	store := n
	if store > l.left {
		store = l.left
	}
	if store > 0 {
		written, e := l.f.Write(b[:store])
		l.left -= written
		if e != nil {
			return 0, e
		}
	}
	return n, nil
}
func (l *logFile) Close() error { return l.f.Close() }
func configureProcess(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error {
		if c.Process == nil {
			return os.ErrProcessDone
		}
		e := syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	c.WaitDelay = time.Second
}

type process struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func watchProcess(cmd *exec.Cmd) *process {
	p := &process{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	return p
}
func (p *process) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	<-p.done
}
