package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateDiagnosticDirectoryRejectsSymlinkAndAliases(t *testing.T) {
	root := publication(t)
	private := t.TempDir()
	if e := os.Chmod(private, 0755); e != nil {
		t.Fatal(e)
	}
	if e := prepareDiagnosticDir(private, root); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(private)
	if st.Mode().Perm() != 0700 {
		t.Fatal("diagnostic directory is not private")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if e := os.Symlink(private, alias); e != nil {
		t.Fatal(e)
	}
	if e := prepareDiagnosticDir(alias, root); e == nil {
		t.Fatal("diagnostic directory symlink accepted")
	}
	alias = filepath.Join(t.TempDir(), "published")
	if e := os.Symlink(root, alias); e != nil {
		t.Fatal(e)
	}
	inside := filepath.Join(alias, "diagnostic")
	if e := os.Mkdir(inside, 0700); e != nil {
		t.Fatal(e)
	}
	if e := prepareDiagnosticDir(inside, root); e == nil {
		t.Fatal("aliased publication subtree accepted")
	}
}

func TestDiagnosticsAreBoundedReplacedAndClearedOnSuccess(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(t.TempDir(), "native.log")
	if e := os.WriteFile(source, bytes.Repeat([]byte("secret"), 20000), 0600); e != nil {
		t.Fatal(e)
	}
	s := Summary{RunID: "one", Status: "failed", ErrorCode: "verify_timeout", Phase: "mosdns_ready"}
	if e := writeDiagnostics(dir, s, source, source); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"last-xray.log", "last-mosdns.log", "last.json"} {
		st, e := os.Stat(filepath.Join(dir, name))
		if e != nil || st.Mode().Perm() != 0600 || st.Size() > diagnosticLogLimit {
			t.Fatalf("diagnostic limits: %s %+v %v", name, st, e)
		}
		if name != "last.json" && st.Size() != diagnosticLogLimit {
			t.Fatalf("log not capped: %d", st.Size())
		}
	}
	if e := os.WriteFile(source, []byte("new"), 0600); e != nil {
		t.Fatal(e)
	}
	s.RunID = "two"
	if e := writeDiagnostics(dir, s, source, ""); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "last-xray.log"))
	if string(b) != "new" {
		t.Fatal("prior native log was appended or retained")
	}
	if _, e := os.Stat(filepath.Join(dir, "last-mosdns.log")); !os.IsNotExist(e) {
		t.Fatal("prior unstarted MosDNS log retained")
	}
	s = Summary{RunID: "three", Status: "verified", Phase: "complete"}
	if e := writeDiagnostics(dir, s, source, source); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 || entries[0].Name() != "last.json" {
		t.Fatalf("diagnostic history retained: %v %v", entries, e)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "last.json"))
	var saved Summary
	if json.Unmarshal(b, &saved) != nil || saved.RunID != s.RunID || saved.Status != "verified" || saved.ErrorCode != "" {
		t.Fatal("success metadata retained prior failure")
	}
}

func TestNativeTimeoutRecordsPhaseAndReapsBeforeDiagnostics(t *testing.T) {
	root := publication(t)
	native := t.TempDir()
	diagnostics := t.TempDir()
	x := filepath.Join(native, "xray")
	if e := os.WriteFile(x, []byte("#!/bin/sh\nprintf 'started\\n'\nsleep 30\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(native, "01.json"), []byte(`{"outbounds":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := Run(context.Background(), Config{PublishDir: root, XrayBinary: x, XrayConfigDir: native, MosDNSBinary: "/bin/sh", MosDNSConfigDir: native, DiagnosticDir: diagnostics, TimeoutSeconds: 1})
	if e != failure("verify_timeout") || s.Phase != "xray_run_test" || s.PhaseDurationsMS["xray_run_test"] < 800 {
		t.Fatalf("timeout diagnostics: %+v %v", s, e)
	}
	b, e := os.ReadFile(filepath.Join(diagnostics, "last-xray.log"))
	if e != nil || string(b) != "started\n" {
		t.Fatalf("timeout native log: %q %v", b, e)
	}
}
