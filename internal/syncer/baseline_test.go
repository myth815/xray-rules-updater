package syncer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
