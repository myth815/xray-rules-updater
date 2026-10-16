package hostcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const oldID = "1111111111111111"
const txID = "2222222222222222"
const reqID = "3333333333333333"

func fixture(t *testing.T) (Config, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"publish", "state", "mos", "nginx", "config"} {
		if e := os.Mkdir(filepath.Join(root, p), 0700); e != nil {
			t.Fatal(e)
		}
	}
	c := Config{PublishDir: filepath.Join(root, "publish"), StateDir: filepath.Join(root, "state"), MosDNSData: filepath.Join(root, "mos", "dat_exec.yaml"), MosDNSTemplate: filepath.Join(root, "config", "template.yaml"), NginxControlDir: filepath.Join(root, "nginx"), RequestPath: filepath.Join(root, "config", "request.json"), MaxFileBytes: 60000}
	put(t, c.MosDNSData, "files: /rules/versions/old/data.txt\n")
	put(t, c.MosDNSTemplate, "files: @@RULES_ASSET_DIR@@/data.txt\n")
	ack := `{"version":"old","run_id":"` + oldID + `"}`
	put(t, filepath.Join(c.StateDir, "applied.json"), ack)
	nginx(t, c, "old", oldID, "committed")
	return c, ack
}
func put(t *testing.T, p, v string) {
	t.Helper()
	if e := os.WriteFile(p, []byte(v), 0600); e != nil {
		t.Fatal(e)
	}
}
func nginx(t *testing.T, c Config, v, id, status string) {
	t.Helper()
	put(t, filepath.Join(c.NginxControlDir, "active.inc"), `set $rules_version "`+v+`";`+"\n")
	put(t, filepath.Join(c.NginxControlDir, ".active.previous.token"), id+"\n")
	b, _ := json.Marshal(map[string]string{"version": v, "run_id": id, "status": status})
	put(t, filepath.Join(c.NginxControlDir, "apply-state.json"), string(b))
}
func journalBody(ack string) string {
	b, _ := json.Marshal(map[string]any{"run_id": txID, "desired_version": "new", "old_applied_version": "old", "old_asset_present": true, "old_asset_value": "/rules/versions/old", "old_mosdns_data": "files: /rules/versions/old/data.txt\n", "old_ack_present": true, "old_ack_content": ack, "consumer_snapshots": map[string]string{"xray": "frozen-identity"}})
	return string(b)
}
func call(t *testing.T, c Config, r Request) (Summary, error) {
	t.Helper()
	if r.RequestID == "" {
		r.RequestID = reqID
	}
	b, _ := json.Marshal(r)
	put(t, c.RequestPath, string(b))
	return Run(context.Background(), c, reqID)
}
func ok(t *testing.T, c Config, action, content string) Summary {
	t.Helper()
	s, e := call(t, c, Request{Action: action, TransactionID: txID, Content: content})
	if e != nil || s.Status != "complete" {
		t.Fatalf("%s: %+v %v", action, s, e)
	}
	return s
}
func prepare(t *testing.T, c Config, ack string) {
	t.Helper()
	ok(t, c, "write_journal", journalBody(ack))
}
func content(t *testing.T, p string) string {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func TestDurableCommitAndReadback(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	j, fields, e := c.journal(txID)
	if e != nil || j.Phase != "prepared" || fields["consumer_snapshots"] == nil {
		t.Fatal("journal identity/phase lost")
	}
	ok(t, c, "apply_mosdns", "")
	nginx(t, c, "new", txID, "committed")
	a := `{"version":"new","run_id":"` + txID + `","verification_run_id":"4444444444444444"}`
	ok(t, c, "write_ack", a)
	s, e := call(t, c, Request{Action: "remove_journal", TransactionID: txID, Outcome: "committed"})
	if e != nil || s.Status != "complete" {
		t.Fatalf("commit: %+v %v", s, e)
	}
	if _, e = os.Stat(filepath.Join(c.StateDir, "transaction.json")); !os.IsNotExist(e) {
		t.Fatal("journal retained")
	}
	if content(t, filepath.Join(c.StateDir, "applied.json")) != a || content(t, c.MosDNSData) != "files: /rules/versions/new/data.txt\n" {
		t.Fatal("consumer state mismatch")
	}
	if _, e = os.Stat(filepath.Join(c.StateDir, ".host-control.lock")); e != nil {
		t.Fatal("lock inode removed")
	}
	files, _ := filepath.Glob(filepath.Join(c.StateDir, ".host-next-*"))
	if len(files) != 0 {
		t.Fatal("temporary writes leaked")
	}
}

func TestDurableRestoreOfflineAndOldAck(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	ok(t, c, "apply_mosdns", "")
	nginx(t, c, "new", txID, "activated")
	put(t, filepath.Join(c.NginxControlDir, ".active.previous.inc"), "set $rules_version \"old\";\n")
	ok(t, c, "write_ack", `{"version":"new","run_id":"`+txID+`"}`)
	ok(t, c, "begin_restore", "")
	ok(t, c, "restore_mosdns", "")
	ok(t, c, "restore_nginx_offline", "")
	ok(t, c, "restore_ack", "")
	s, e := call(t, c, Request{Action: "remove_journal", TransactionID: txID, Outcome: "restored"})
	if e != nil || s.Status != "complete" {
		t.Fatalf("restore: %+v %v", s, e)
	}
	if content(t, filepath.Join(c.StateDir, "applied.json")) != ack {
		t.Fatal("old ack not restored exactly")
	}
	if _, e = c.assertNginx("old", ""); e != nil {
		t.Fatal(e)
	}
}

func TestStagedRequestCannotReplayAnotherNonce(t *testing.T) {
	c, ack := fixture(t)
	s, e := call(t, c, Request{RequestID: "5555555555555555", Action: "write_journal", TransactionID: txID, Content: journalBody(ack)})
	if e != failure("host_request_mismatch") || s.Status != "failed" {
		t.Fatalf("nonce: %+v %v", s, e)
	}
	if _, e = os.Stat(filepath.Join(c.StateDir, "transaction.json")); !os.IsNotExist(e) {
		t.Fatal("replayed stale request")
	}
}

func TestWrongOwnerAndUnknownMosFailBeforeWrite(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	_, e := call(t, c, Request{Action: "restore_mosdns", TransactionID: oldID})
	if e != failure("host_owner") {
		t.Fatal(e)
	}
	put(t, c.MosDNSData, "unrelated user configuration\n")
	_, e = call(t, c, Request{Action: "apply_mosdns", TransactionID: txID})
	if e != failure("host_mos_drift") {
		t.Fatal(e)
	}
	if content(t, c.MosDNSData) != "unrelated user configuration\n" {
		t.Fatal("external edit clobbered")
	}
}

func TestRollingBackCannotCommitOrWriteNewAck(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	ok(t, c, "begin_restore", "")
	for _, r := range []Request{{Action: "write_ack", Content: `{"version":"new","run_id":"` + txID + `"}`}, {Action: "apply_mosdns"}, {Action: "remove_journal", Outcome: "committed"}} {
		r.TransactionID = txID
		s, e := call(t, c, r)
		if e == nil || s.Status != "failed" {
			t.Fatalf("rollback accepted %s", r.Action)
		}
	}
	j, fields, e := c.journal(txID)
	if e != nil || j.Phase != "rolling_back" || fields["consumer_snapshots"] == nil {
		t.Fatal("durable rollback intent lost")
	}
}

func TestRemoveJournalRefusesSplitConsumers(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	nginx(t, c, "new", txID, "committed")
	// Reproduce an already-written new ACK followed by partial rollback to old
	// MosDNS, rather than asking the writer to approve a split new ACK.
	put(t, filepath.Join(c.StateDir, "applied.json"), `{"version":"new","run_id":"`+txID+`"}`)
	_, e := call(t, c, Request{Action: "remove_journal", TransactionID: txID, Outcome: "committed"})
	if e != failure("host_mos_drift") {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(c.StateDir, "transaction.json")); e != nil {
		t.Fatal("split consumers lost recovery record")
	}
}

func TestOfflineRestoreBeforeActivationIsSafeNoop(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	ok(t, c, "begin_restore", "")
	ok(t, c, "restore_nginx_offline", "")
	if _, e := c.assertNginx("old", oldID); e != nil {
		t.Fatal(e)
	}
}

func TestFilesSymlinksAndRequestLimitFailClosed(t *testing.T) {
	c, ack := fixture(t)
	put(t, c.RequestPath, strings.Repeat("x", 60001))
	if _, e := Run(context.Background(), c, reqID); e != failure("host_request") {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	put(t, outside, "safe")
	if e := os.Symlink(outside, filepath.Join(c.StateDir, "transaction.json")); e != nil {
		t.Fatal(e)
	}
	_, e := call(t, c, Request{Action: "write_journal", TransactionID: txID, Content: journalBody(ack)})
	if e == nil || content(t, outside) != "safe" {
		t.Fatal("symlink followed")
	}
}

func TestFileSyncFailureDoesNotPublishJournal(t *testing.T) {
	c, ack := fixture(t)
	prior := syncFile
	t.Cleanup(func() { syncFile = prior })
	failed := false
	syncFile = func(f *os.File) error {
		if !failed && filepath.Dir(f.Name()) == c.StateDir {
			failed = true
			return errors.New("injected file sync failure")
		}
		return prior(f)
	}
	s, e := call(t, c, Request{Action: "write_journal", TransactionID: txID, Content: journalBody(ack)})
	if e == nil || s.Status == "complete" {
		t.Fatal("durability failure acknowledged")
	}
	if _, e = os.Stat(filepath.Join(c.StateDir, "transaction.json")); !os.IsNotExist(e) {
		t.Fatal("journal exposed before file sync")
	}
	if content(t, c.MosDNSData) != "files: /rules/versions/old/data.txt\n" {
		t.Fatal("consumer changed")
	}
}

func TestDirectorySyncFailureIsNotReportedComplete(t *testing.T) {
	c, ack := fixture(t)
	prior := syncDirectory
	t.Cleanup(func() { syncDirectory = prior })
	failed := false
	syncDirectory = func(p string) error {
		if !failed && p == c.StateDir {
			failed = true
			return errors.New("injected directory sync failure")
		}
		return prior(p)
	}
	s, e := call(t, c, Request{Action: "write_journal", TransactionID: txID, Content: journalBody(ack)})
	if e == nil || s.Status == "complete" {
		t.Fatal("rename visibility confused with durability")
	}
	if content(t, c.MosDNSData) != "files: /rules/versions/old/data.txt\n" {
		t.Fatal("consumer changed")
	}
	// A visible but unacknowledged journal remains an owned recovery record.
	syncDirectory = prior
	ok(t, c, "begin_restore", "")
}

func TestCheckNginxDistinguishesOwnedPartialAndForeignTransaction(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	s, e := call(t, c, Request{Action: "check_nginx", TransactionID: txID})
	if e != nil || s.Version != "old" {
		t.Fatalf("old: %+v %v", s, e)
	}
	// Activation can be killed after publishing its owner and include, while
	// apply-state still describes the old complete generation.
	put(t, filepath.Join(c.NginxControlDir, ".active.previous.inc"), "set $rules_version \"old\";\n")
	put(t, filepath.Join(c.NginxControlDir, ".active.previous.token"), txID+"\n")
	put(t, filepath.Join(c.NginxControlDir, "active.inc"), "set $rules_version \"new\";\n")
	s, e = call(t, c, Request{Action: "check_nginx", TransactionID: txID})
	if e != nil || s.Version != "new" {
		t.Fatalf("owned partial: %+v %v", s, e)
	}
	nginx(t, c, "old", oldID, "activated")
	if _, e = call(t, c, Request{Action: "check_nginx", TransactionID: txID}); e == nil {
		t.Fatal("foreign pending transaction accepted")
	}
	nginx(t, c, "other", oldID, "committed")
	if _, e = call(t, c, Request{Action: "check_nginx", TransactionID: txID}); e == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestActivatedNginxCannotDiscardRecoveryJournal(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	ok(t, c, "apply_mosdns", "")
	nginx(t, c, "new", txID, "activated")
	ok(t, c, "write_ack", `{"version":"new","run_id":"`+txID+`"}`)
	_, e := call(t, c, Request{Action: "remove_journal", TransactionID: txID, Outcome: "committed"})
	if e != failure("host_nginx_uncommitted") {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(c.StateDir, "transaction.json")); e != nil {
		t.Fatal("uncommitted journal discarded")
	}
}

func TestAckWriteRejectsSplitLocalConsumers(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	nginx(t, c, "new", txID, "activated")
	_, e := call(t, c, Request{Action: "write_ack", TransactionID: txID, Content: `{"version":"new","run_id":"` + txID + `"}`})
	if e != failure("host_mos_drift") {
		t.Fatal(e)
	}
	if content(t, filepath.Join(c.StateDir, "applied.json")) != ack {
		t.Fatal("split consumers acknowledged")
	}
}

func TestForeignAckNeverOverwrittenByApplyOrRestore(t *testing.T) {
	for _, action := range []string{"write_ack", "restore_ack", "begin_restore"} {
		t.Run(action, func(t *testing.T) {
			c, ack := fixture(t)
			prepare(t, c, ack)
			if action == "restore_ack" {
				ok(t, c, "begin_restore", "")
			}
			foreign := `{"version":"foreign","run_id":"5555555555555555"}`
			put(t, filepath.Join(c.StateDir, "applied.json"), foreign)
			_, e := call(t, c, Request{Action: action, TransactionID: txID, Content: `{"version":"new","run_id":"` + txID + `"}`})
			if e != failure("host_ack_drift") {
				t.Fatal(e)
			}
			if content(t, filepath.Join(c.StateDir, "applied.json")) != foreign {
				t.Fatal("foreign ACK overwritten")
			}
			if _, e = os.Stat(filepath.Join(c.StateDir, "transaction.json")); e != nil {
				t.Fatal("recovery record lost")
			}
		})
	}
}

func TestOfflineRestoreRefusesForeignActiveDespiteOwnedToken(t *testing.T) {
	c, ack := fixture(t)
	prepare(t, c, ack)
	ok(t, c, "begin_restore", "")
	nginx(t, c, "foreign", txID, "activated")
	put(t, filepath.Join(c.NginxControlDir, ".active.previous.inc"), "set $rules_version \"old\";\n")
	_, e := call(t, c, Request{Action: "restore_nginx_offline", TransactionID: txID})
	if e != failure("host_nginx_version") {
		t.Fatal(e)
	}
	if content(t, filepath.Join(c.NginxControlDir, "active.inc")) != "set $rules_version \"foreign\";\n" {
		t.Fatal("foreign include clobbered")
	}
}

func TestReceiptDirectorySyncFailureNeverExposesCompletedTrue(t *testing.T) {
	c, ack := fixture(t)
	prior := syncDirectory
	t.Cleanup(func() { syncDirectory = prior })
	syncDirectory = func(p string) error {
		if p == c.PublishDir {
			return errors.New("injected receipt directory sync failure")
		}
		return prior(p)
	}
	s, e := call(t, c, Request{Action: "write_journal", TransactionID: txID, Content: journalBody(ack)})
	if e == nil || s.Completed || s.Status != "failed" {
		t.Fatal("receipt sync failure accepted")
	}
	var saved Summary
	b, er := os.ReadFile(filepath.Join(c.PublishDir, "host-control.json"))
	if er != nil {
		t.Fatal(er)
	}
	if json.Unmarshal(b, &saved) != nil || saved.Completed {
		t.Fatal("fresh completion marker exposed before durability fence")
	}
	// The owned journal action itself is durable; absence of a capability holds
	// the caller before consumer mutation and allows normal later recovery.
	if content(t, c.MosDNSData) != "files: /rules/versions/old/data.txt\n" {
		t.Fatal("consumer changed")
	}
	syncDirectory = prior
	ok(t, c, "begin_restore", "")
}
