// Package hostcontrol performs local, durable host transactions. It runs in the
// same one-shot image with an explicit host-only writable mount set; publishers
// retain their read-only state mount. Requests cannot supply filesystem paths.
package hostcontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	PublishDir      string `json:"publish_dir"`
	StateDir        string `json:"state_dir"`
	MosDNSData      string `json:"mosdns_data"`
	MosDNSTemplate  string `json:"mosdns_template"`
	NginxControlDir string `json:"nginx_control_dir"`
	RequestPath     string `json:"request_path"`
	MaxFileBytes    int64  `json:"max_file_bytes"`
}

type Request struct {
	RequestID     string `json:"request_id"`
	Action        string `json:"action"`
	TransactionID string `json:"transaction_id,omitempty"`
	Content       string `json:"content,omitempty"`
	Outcome       string `json:"outcome,omitempty"`
	Version       string `json:"version,omitempty"`
}

type Summary struct {
	RunID         string `json:"run_id"`
	RequestID     string `json:"request_id,omitempty"`
	Action        string `json:"action,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	Status        string `json:"status"`
	ErrorCode     string `json:"error_code,omitempty"`
	Version       string `json:"version,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Bytes         int    `json:"bytes,omitempty"`
	DurationMS    int64  `json:"duration_ms"`
	Completed     bool   `json:"completed"`
}

type failure string

func (e failure) Error() string { return string(e) }

var nonce = regexp.MustCompile(`^[a-f0-9]{16}$`)
var version = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var include = regexp.MustCompile(`^set \$rules_version "([A-Za-z0-9][A-Za-z0-9._-]{0,63})";\n?$`)

// Injectable only by package tests; production has no environment or request
// switch that can bypass either durability operation.
var syncFile = func(f *os.File) error { return f.Sync() }
var syncDirectory = syncDir

func decode(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return failure("host_input")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return failure("host_input")
	}
	return nil
}

func LoadConfig(data []byte) (Config, error) {
	var c Config
	if len(data) > 1<<20 || decode(data, &c) != nil {
		return c, failure("host_config")
	}
	if c.MaxFileBytes == 0 {
		c.MaxFileBytes = 60000
	}
	if c.MaxFileBytes < 1024 || c.MaxFileBytes > 60000 {
		return c, failure("host_config")
	}
	for _, p := range []string{c.PublishDir, c.StateDir, c.MosDNSData, c.MosDNSTemplate, c.NginxControlDir, c.RequestPath} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, failure("host_config")
		}
	}
	for _, p := range []string{c.StateDir, filepath.Dir(c.MosDNSData), c.NginxControlDir} {
		if overlap(c.PublishDir, p) || overlap(filepath.Dir(c.RequestPath), p) {
			return c, failure("host_config")
		}
	}
	if overlap(c.StateDir, c.NginxControlDir) || overlap(c.StateDir, filepath.Dir(c.MosDNSData)) || overlap(c.NginxControlDir, filepath.Dir(c.MosDNSData)) {
		return c, failure("host_config")
	}
	return c, nil
}

func overlap(a, b string) bool {
	within := func(a, b string) bool {
		r, e := filepath.Rel(a, b)
		return e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
	}
	return within(a, b) || within(b, a)
}

func realDir(p string) error {
	s, e := os.Lstat(p)
	if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
		return failure("host_directory")
	}
	r, e := filepath.EvalSymlinks(p)
	if e != nil || r != p {
		return failure("host_directory")
	}
	return nil
}
func read(p string, limit int64) ([]byte, error) {
	f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > limit {
		return nil, failure("host_file")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, failure("host_file")
	}
	return b, nil
}
func optional(p string, limit int64) ([]byte, bool, error) {
	b, e := read(p, limit)
	if os.IsNotExist(e) {
		return nil, false, nil
	}
	return b, e == nil, e
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Each rename is followed by a directory sync, including first creation. Never
// report completion solely because bytes are visible in the filesystem cache.
func atomicWrite(p string, body []byte, mode os.FileMode) error {
	if e := realDir(filepath.Dir(p)); e != nil {
		return e
	}
	if s, e := os.Lstat(p); e == nil && !s.Mode().IsRegular() {
		return failure("host_file")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".host-next-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(body)
	}
	if e == nil {
		e = syncFile(f)
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(tmp, p); e != nil {
		return e
	}
	if e = syncDirectory(filepath.Dir(p)); e != nil {
		return e
	}
	b, e := read(p, int64(len(body))+1)
	if e != nil || !bytes.Equal(b, body) {
		return failure("host_readback")
	}
	return nil
}
func syncDir(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func durableRemove(p string) error {
	if e := realDir(filepath.Dir(p)); e != nil {
		return e
	}
	s, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return syncDirectory(filepath.Dir(p))
	}
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() {
		return failure("host_file")
	}
	if e = os.Remove(p); e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(p))
}

// Publish a completion capability only after a durable completed=false receipt
// and all action writes have passed their fences. This final marker may be lost
// after power loss; losing it means re-inspect/recover, never invent success.
// There must be no fallible durability check after exposing completed=true.
func publishCompletion(p string, body []byte) error {
	f, e := os.CreateTemp(filepath.Dir(p), ".host-receipt-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(body)
	}
	if e == nil {
		e = syncFile(f)
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(tmp, p)
}

type journal struct {
	RunID           string `json:"run_id"`
	Desired         string `json:"desired_version"`
	OldVersion      string `json:"old_applied_version"`
	OldAssetPresent *bool  `json:"old_asset_present"`
	OldAsset        string `json:"old_asset_value"`
	OldMos          string `json:"old_mosdns_data"`
	OldAckPresent   *bool  `json:"old_ack_present"`
	OldAck          string `json:"old_ack_content"`
	Phase           string `json:"phase"`
}

func parseJournal(b []byte) (journal, map[string]json.RawMessage, error) {
	var j journal
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &j) != nil || json.Unmarshal(b, &fields) != nil || fields == nil || !nonce.MatchString(j.RunID) || !version.MatchString(j.Desired) || j.OldAssetPresent == nil || j.OldAckPresent == nil || len(j.OldMos) == 0 || len(j.OldMos) > 60000 {
		return j, nil, failure("host_journal")
	}
	if j.Phase != "" && j.Phase != "prepared" && j.Phase != "applying" && j.Phase != "acknowledged" && j.Phase != "rolling_back" {
		return j, nil, failure("host_journal")
	}
	if *j.OldAckPresent {
		if !version.MatchString(j.OldVersion) || j.OldVersion == j.Desired || validateAck([]byte(j.OldAck), j.OldVersion, "") != nil {
			return j, nil, failure("host_journal")
		}
	} else if j.OldAck != "" || j.OldVersion != "" {
		return j, nil, failure("host_journal")
	}
	return j, fields, nil
}
func validateAck(b []byte, v, txn string) error {
	var a struct {
		Version string `json:"version"`
		RunID   string `json:"run_id"`
	}
	if json.Unmarshal(b, &a) != nil || a.Version != v || !nonce.MatchString(a.RunID) || (txn != "" && a.RunID != txn) {
		return failure("host_ack")
	}
	return nil
}
func (c Config) journal(txn string) (journal, map[string]json.RawMessage, error) {
	b, e := read(filepath.Join(c.StateDir, "transaction.json"), c.MaxFileBytes)
	if e != nil {
		return journal{}, nil, failure("host_journal")
	}
	j, f, e := parseJournal(b)
	if e != nil || j.RunID != txn {
		return j, nil, failure("host_owner")
	}
	return j, f, nil
}
func (c Config) nextMos(j journal) ([]byte, error) {
	b, e := read(c.MosDNSTemplate, c.MaxFileBytes)
	if e != nil || !bytes.Contains(b, []byte("@@RULES_ASSET_DIR@@")) {
		return nil, failure("host_template")
	}
	b = bytes.ReplaceAll(b, []byte("@@RULES_ASSET_DIR@@"), []byte("/rules/versions/"+j.Desired))
	if int64(len(b)) > c.MaxFileBytes {
		return nil, failure("host_limit")
	}
	return b, nil
}
func (c Config) knownMos(j journal) ([]byte, error) {
	n, e := c.nextMos(j)
	if e != nil {
		return nil, e
	}
	b, e := read(c.MosDNSData, c.MaxFileBytes)
	if e != nil || (!bytes.Equal(b, n) && string(b) != j.OldMos) {
		return nil, failure("host_mos_drift")
	}
	return n, nil
}

func (c Config) knownAck(j journal) error {
	b, present, e := optional(filepath.Join(c.StateDir, "applied.json"), c.MaxFileBytes)
	if e != nil {
		return failure("host_ack_drift")
	}
	if *j.OldAckPresent && present && string(b) == j.OldAck {
		return nil
	}
	if !*j.OldAckPresent && !present {
		return nil
	}
	if present && validateAck(b, j.Desired, j.RunID) == nil {
		return nil
	}
	return failure("host_ack_drift")
}
func (c Config) assertNginx(v, txn string) ([]byte, error) {
	b, e := read(filepath.Join(c.NginxControlDir, "active.inc"), 256)
	if e != nil {
		return nil, failure("host_nginx")
	}
	m := include.FindSubmatch(b)
	if m == nil || string(m[1]) != v {
		return nil, failure("host_nginx_version")
	}
	t, e := read(filepath.Join(c.NginxControlDir, ".active.previous.token"), 128)
	if e != nil || !nonce.MatchString(strings.TrimSpace(string(t))) {
		return nil, failure("host_nginx_owner")
	}
	var state struct {
		RunID   string `json:"run_id"`
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	s, e := read(filepath.Join(c.NginxControlDir, "apply-state.json"), 4096)
	if e != nil || json.Unmarshal(s, &state) != nil || state.Version != v || state.RunID != strings.TrimSpace(string(t)) || (txn != "" && state.RunID != txn) || (state.Status != "activated" && state.Status != "committed" && state.Status != "restored") || (txn == "" && state.Status == "activated") {
		return nil, failure("host_nginx_state")
	}
	return b, nil
}

func Run(ctx context.Context, c Config, expected string) (s Summary, err error) {
	start := time.Now()
	encoded, _ := json.Marshal(c)
	validated, validationError := LoadConfig(encoded)
	if validationError != nil {
		return s, validationError
	}
	c = validated
	var n [8]byte
	if _, e := rand.Read(n[:]); e != nil {
		return s, failure("host_identity")
	}
	s.RunID = hex.EncodeToString(n[:])
	s.Status = "failed"
	canWrite := false
	defer func() {
		s.DurationMS = time.Since(start).Milliseconds()
		if err != nil {
			var f failure
			if errors.As(err, &f) {
				s.ErrorCode = string(f)
			} else {
				s.ErrorCode = "host_io"
			}
		}
		if canWrite {
			s.Completed = false
			b, _ := json.Marshal(s)
			p := filepath.Join(c.PublishDir, "host-control.json")
			if e := atomicWrite(p, append(b, '\n'), 0600); e != nil {
				s.Status = "failed"
				s.ErrorCode = "host_result_write"
				err = failure(s.ErrorCode)
				return
			}
			s.Completed = true
			b, _ = json.Marshal(s)
			if e := publishCompletion(p, append(b, '\n')); e != nil {
				s.Completed = false
				s.Status = "failed"
				s.ErrorCode = "host_result_write"
				err = failure(s.ErrorCode)
			}
		}
	}()
	if !nonce.MatchString(expected) {
		return s, failure("host_request_id")
	}
	for _, p := range []string{c.PublishDir, c.StateDir, filepath.Dir(c.MosDNSData), c.NginxControlDir, filepath.Dir(c.RequestPath)} {
		if e := realDir(p); e != nil {
			return s, e
		}
	}
	canWrite = true
	l, e := os.OpenFile(filepath.Join(c.StateDir, ".host-control.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return s, e
	}
	defer l.Close()
	if e = syscall.Flock(int(l.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return s, failure("host_busy")
	}
	defer syscall.Flock(int(l.Fd()), syscall.LOCK_UN)
	// Share the Nginx helper's inode and lock order. Offline recovery and local
	// assertions must not race a separately invoked activate/restore helper.
	nl, e := os.OpenFile(filepath.Join(c.NginxControlDir, ".apply.flock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return s, e
	}
	defer nl.Close()
	if e = syscall.Flock(int(nl.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return s, failure("host_nginx_busy")
	}
	defer syscall.Flock(int(nl.Fd()), syscall.LOCK_UN)
	if ctx.Err() != nil {
		return s, failure("host_cancelled")
	}
	b, e := read(c.RequestPath, c.MaxFileBytes)
	if e != nil {
		return s, failure("host_request")
	}
	var r Request
	if decode(b, &r) != nil || r.RequestID != expected {
		return s, failure("host_request_mismatch")
	}
	s.RequestID = r.RequestID
	s.Action = r.Action
	s.TransactionID = r.TransactionID
	if r.Action == "assert_nginx" {
		if !version.MatchString(r.Version) || (r.TransactionID != "" && !nonce.MatchString(r.TransactionID)) {
			return s, failure("host_request")
		}
		b, e = c.assertNginx(r.Version, r.TransactionID)
		if e != nil {
			return s, e
		}
		s.Version = r.Version
	} else {
		if !nonce.MatchString(r.TransactionID) {
			return s, failure("host_owner")
		}
		b, e = c.perform(r)
		if e != nil {
			return s, e
		}
	}
	if b != nil {
		s.Bytes = len(b)
		s.SHA256 = digest(b)
		if strings.Contains(r.Action, "nginx") {
			if m := include.FindSubmatch(b); m != nil {
				s.Version = string(m[1])
			}
		}
	}
	s.Status = "complete"
	return s, nil
}

func (c Config) perform(r Request) ([]byte, error) {
	jp := filepath.Join(c.StateDir, "transaction.json")
	ap := filepath.Join(c.StateDir, "applied.json")
	if r.Action == "write_journal" {
		j, fields, e := parseJournal([]byte(r.Content))
		if e != nil || j.RunID != r.TransactionID {
			return nil, failure("host_journal")
		}
		if old, exists, e := optional(jp, c.MaxFileBytes); e != nil {
			return nil, e
		} else if exists {
			oj, _, e := parseJournal(old)
			if e != nil || oj.RunID != j.RunID {
				return nil, failure("host_owner")
			}
			return nil, failure("host_journal_exists")
		}
		ack, present, e := optional(ap, c.MaxFileBytes)
		if e != nil || present != *j.OldAckPresent || (present && string(ack) != j.OldAck) {
			return nil, failure("host_ack_drift")
		}
		mos, e := read(c.MosDNSData, c.MaxFileBytes)
		if e != nil || string(mos) != j.OldMos {
			return nil, failure("host_mos_drift")
		}
		fields["phase"] = json.RawMessage(`"prepared"`)
		body, e := json.Marshal(fields)
		if e != nil || int64(len(body)) > c.MaxFileBytes {
			return nil, failure("host_limit")
		}
		return body, atomicWrite(jp, body, 0600)
	}
	j, fields, e := c.journal(r.TransactionID)
	if e != nil {
		return nil, e
	}
	if r.Action != "check_nginx" {
		if e := c.knownAck(j); e != nil {
			return nil, e
		}
	}
	switch r.Action {
	case "check_nginx":
		b, e := read(filepath.Join(c.NginxControlDir, "active.inc"), 256)
		if e != nil {
			return nil, failure("host_nginx")
		}
		m := include.FindSubmatch(b)
		if m == nil || (string(m[1]) != j.Desired && string(m[1]) != j.OldVersion) {
			return nil, failure("host_nginx_version")
		}
		t, e := read(filepath.Join(c.NginxControlDir, ".active.previous.token"), 128)
		if e != nil {
			return nil, failure("host_nginx_owner")
		}
		if strings.TrimSpace(string(t)) == j.RunID {
			// A kill between token/include/state writes is a recoverable owned
			// intermediate state. The durable backup must prove exactly old V.
			old, e := read(filepath.Join(c.NginxControlDir, ".active.previous.inc"), 256)
			if e != nil {
				return nil, failure("host_nginx_backup")
			}
			om := include.FindSubmatch(old)
			if om == nil || string(om[1]) != j.OldVersion {
				return nil, failure("host_nginx_backup")
			}
			return b, nil
		}
		if string(m[1]) != j.OldVersion {
			return nil, failure("host_nginx_owner")
		}
		return c.assertNginx(j.OldVersion, "")
	case "begin_restore":
		if e := c.knownAck(j); e != nil {
			return nil, e
		}
		fields["phase"] = json.RawMessage(`"rolling_back"`)
		b, e := json.Marshal(fields)
		if e != nil {
			return nil, e
		}
		return b, atomicWrite(jp, b, 0600)
	case "apply_mosdns", "restore_mosdns":
		b, e := c.knownMos(j)
		if e != nil {
			return nil, e
		}
		if r.Action == "apply_mosdns" && j.Phase == "rolling_back" {
			return nil, failure("host_phase")
		}
		if r.Action == "restore_mosdns" {
			if j.Phase != "rolling_back" {
				return nil, failure("host_phase")
			}
			b = []byte(j.OldMos)
		}
		return b, atomicWrite(c.MosDNSData, b, 0600)
	case "write_ack":
		if e := c.knownAck(j); e != nil {
			return nil, e
		}
		if j.Phase == "rolling_back" || validateAck([]byte(r.Content), j.Desired, j.RunID) != nil || int64(len(r.Content)) > c.MaxFileBytes {
			return nil, failure("host_ack")
		}
		next, e := c.nextMos(j)
		if e != nil {
			return nil, e
		}
		actual, e := read(c.MosDNSData, c.MaxFileBytes)
		if e != nil || !bytes.Equal(actual, next) {
			return nil, failure("host_mos_drift")
		}
		if _, e = c.assertNginx(j.Desired, j.RunID); e != nil {
			return nil, e
		}
		return []byte(r.Content), atomicWrite(ap, []byte(r.Content), 0600)
	case "restore_ack":
		if e := c.knownAck(j); e != nil {
			return nil, e
		}
		if j.Phase != "rolling_back" {
			return nil, failure("host_phase")
		}
		if *j.OldAckPresent {
			return []byte(j.OldAck), atomicWrite(ap, []byte(j.OldAck), 0600)
		}
		return nil, durableRemove(ap)
	case "restore_nginx_offline":
		if j.Phase != "rolling_back" {
			return nil, failure("host_phase")
		}
		// Revalidate immediately before changing the include, under the shared
		// Nginx lock; a caller's earlier inspection is not a write capability.
		if _, e := c.perform(Request{Action: "check_nginx", TransactionID: r.TransactionID}); e != nil {
			return nil, e
		}
		t, e := read(filepath.Join(c.NginxControlDir, ".active.previous.token"), 128)
		if e != nil {
			return nil, failure("host_nginx_owner")
		}
		if strings.TrimSpace(string(t)) != j.RunID {
			// Activation may not have happened. Only accept the proven previous
			// complete version; never mark a stranger's active transaction restored.
			if _, e = c.assertNginx(j.OldVersion, ""); e != nil {
				return nil, failure("host_nginx_owner")
			}
			return nil, nil
		}
		b, e := read(filepath.Join(c.NginxControlDir, ".active.previous.inc"), 256)
		if e != nil {
			return nil, failure("host_nginx_backup")
		}
		m := include.FindSubmatch(b)
		if m == nil || string(m[1]) != j.OldVersion {
			return nil, failure("host_nginx_backup")
		}
		if e = atomicWrite(filepath.Join(c.NginxControlDir, "active.inc"), b, 0644); e != nil {
			return nil, e
		}
		state := map[string]string{"run_id": j.RunID, "status": "restored", "version": j.OldVersion, "error_code": "", "applied_utc": time.Now().UTC().Format(time.RFC3339)}
		sb, _ := json.Marshal(state)
		if e = atomicWrite(filepath.Join(c.NginxControlDir, "apply-state.json"), append(sb, '\n'), 0600); e != nil {
			return nil, e
		}
		return b, nil
	case "remove_journal":
		v := j.Desired
		expected := r.TransactionID
		if r.Outcome == "restored" {
			if j.Phase != "rolling_back" {
				return nil, failure("host_phase")
			}
			v = j.OldVersion
			expected = ""
		} else if r.Outcome != "committed" || j.Phase == "rolling_back" {
			return nil, failure("host_outcome")
		}
		ack, present, e := optional(ap, c.MaxFileBytes)
		if e != nil {
			return nil, e
		}
		if r.Outcome == "restored" && !*j.OldAckPresent {
			if present {
				return nil, failure("host_ack_drift")
			}
		} else if !present || validateAck(ack, v, expected) != nil || (r.Outcome == "restored" && string(ack) != j.OldAck) {
			return nil, failure("host_ack_drift")
		}
		n, e := c.nextMos(j)
		if e != nil {
			return nil, e
		}
		if r.Outcome == "restored" {
			n = []byte(j.OldMos)
		}
		mos, e := read(c.MosDNSData, c.MaxFileBytes)
		if e != nil || !bytes.Equal(mos, n) {
			return nil, failure("host_mos_drift")
		}
		if _, e = c.assertNginx(v, expected); e != nil {
			return nil, e
		}
		if r.Outcome == "committed" {
			var state struct {
				Status string `json:"status"`
			}
			b, e := read(filepath.Join(c.NginxControlDir, "apply-state.json"), 4096)
			if e != nil || json.Unmarshal(b, &state) != nil || state.Status != "committed" {
				return nil, failure("host_nginx_uncommitted")
			}
		}
		return nil, durableRemove(jp)
	default:
		return nil, failure("host_action")
	}
}
