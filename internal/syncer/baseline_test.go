package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSingleBaselinePreservesExactBytesAndPublicationHash(t *testing.T) {
	c := fixture(t)
	body, err := os.ReadFile(c.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	body = append(append([]byte("\n \t"), body...), '\n')
	if err := os.WriteFile(c.Baseline, body, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := SnapshotBaselineFile(c.Baseline)
	if err != nil || !bytes.Equal(snapshot, body) {
		t.Fatalf("single-file bytes changed: %v", err)
	}
	summary, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(c.PublishDir, "versions", summary.Version, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		BaselineSHA256 string `json:"baseline_sha256"`
	}
	if json.Unmarshal(manifest, &value) != nil || value.BaselineSHA256 != hash(body) {
		t.Fatal("publication does not bind the exact authoritative file")
	}
}

func TestSingleBaselineRejectsUnsafeFiles(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "config.json")
	if err := os.WriteFile(file, []byte(`{"outbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(root, "large.json")
	if err := os.WriteFile(large, bytes.Repeat([]byte{' '}, baselineLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, fifo, large, root, filepath.Join(root, "missing.json")} {
		if _, err := SnapshotBaselineFile(path); err == nil {
			t.Fatalf("accepted unsafe baseline: %s", path)
		}
	}
}

func TestRunPublishesAndRechecksDirectoryBaseline(t *testing.T) {
	c := fixture(t)
	body, err := os.ReadFile(c.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	var modules map[string]json.RawMessage
	if err = json.Unmarshal(body, &modules); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, module := range modules {
		part, _ := json.Marshal(map[string]json.RawMessage{name: module})
		if err = os.WriteFile(filepath.Join(dir, name+".json"), part, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c.Baseline = ""
	c.BaselineDirectory = dir
	first, err := Run(context.Background(), c)
	if err != nil || first.Status != "published" {
		t.Fatalf("directory publish: %+v %v", first, err)
	}
	assertCurrent(t, c, first.Version)
	repeat, err := Run(context.Background(), c)
	if err != nil || repeat.Status != "unchanged" || repeat.Version != first.Version {
		t.Fatalf("directory repeat: %+v %v", repeat, err)
	}
}

func TestBaselineDirectoryKeepsNativeModules(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{"01.json": `{"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"domain":["full:a.invalid"],"port":"443","outboundTag":"a"}]}}`, "02.json": `{"outbounds":[{"tag":"a","protocol":"freedom"}]}`, "03.json": `{}`, "backup.json.bak": `not active`}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	body, err := readBaseline(Config{BaselineDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if json.Unmarshal(body, &got) != nil || len(got) != 2 {
		t.Fatalf("bad module snapshot: %s", body)
	}
	var routing map[string]any
	_ = json.Unmarshal(got["routing"], &routing)
	rules := routing["rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["port"] != "443" {
		t.Fatal("AND condition changed")
	}
}

func TestBaselineDirectoryRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"duplicate-files", `{"routing":{}}`, `{"routing":{}}`},
		{"duplicate-key", `{"routing":{},"routing":{}}`, `{}`},
		{"array", `[]`, `{}`},
		{"trailing", `{} {}`, `{}`},
		{"malformed", `{"outbounds":`, `{}`},
		{"empty", `{}`, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.WriteFile(filepath.Join(dir, "a.json"), []byte(tc.a), 0600)
			_ = os.WriteFile(filepath.Join(dir, "b.json"), []byte(tc.b), 0600)
			if _, err := readBaseline(Config{BaselineDirectory: dir}); err == nil {
				t.Fatal("accepted unsafe baseline")
			}
		})
	}
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(target, []byte(`{"outbounds":[]}`), 0600)
	if err := os.Symlink(target, filepath.Join(dir, "a.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readBaseline(Config{BaselineDirectory: dir}); err == nil {
		t.Fatal("followed a module symlink")
	}
	link := filepath.Join(t.TempDir(), "link")
	_ = os.Symlink(dir, link)
	if _, err := readBaseline(Config{BaselineDirectory: link}); err == nil {
		t.Fatal("followed directory symlink")
	}
}
