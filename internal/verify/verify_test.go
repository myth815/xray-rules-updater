package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func publication(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "versions", "test-v1")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	m := manifest{SchemaVersion: 1, Version: "test-v1", BaselineSHA256: sumHex([]byte(`{"outbounds":[]}`)), Files: make(map[string]struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	})}
	for _, name := range []string{"geoip.dat", "geosite.dat", "onexray.json"} {
		body := []byte("fixture-" + name)
		sum := sha256.Sum256(body)
		m.Files[name] = struct {
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
		}{hex.EncodeToString(sum[:]), int64(len(body))}
		if e := os.WriteFile(filepath.Join(dir, name), body, 0600); e != nil {
			t.Fatal(e)
		}
	}
	body, _ := json.Marshal(m)
	if e := os.WriteFile(filepath.Join(dir, "manifest.json"), body, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("versions/test-v1", filepath.Join(root, "current")); e != nil {
		t.Fatal(e)
	}
	return root
}
func TestSnapshotIntegrityAndPaths(t *testing.T) {
	root := publication(t)
	dir, m, e := snapshot(context.Background(), root)
	if e != nil || m.Version != "test-v1" || dir != filepath.Join(root, "versions", "test-v1") {
		t.Fatalf("snapshot: %q %+v %v", dir, m, e)
	}
	if e = os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = snapshot(context.Background(), root); e != failure("verify_integrity") {
		t.Fatalf("corruption accepted: %v", e)
	}
	root = publication(t)
	os.Remove(filepath.Join(root, "current"))
	os.Symlink("../../outside", filepath.Join(root, "current"))
	if _, _, e = snapshot(context.Background(), root); e != failure("verify_pointer") {
		t.Fatalf("unsafe pointer: %v", e)
	}
	root = publication(t)
	dir = filepath.Join(root, "versions", "test-v1")
	os.Remove(filepath.Join(dir, "geoip.dat"))
	os.Symlink("onexray.json", filepath.Join(dir, "geoip.dat"))
	if _, _, e = snapshot(context.Background(), root); e != failure("verify_integrity") {
		t.Fatalf("symlink accepted: %v", e)
	}
}
func TestLoadConfigRejectsUnsafeOrTrailing(t *testing.T) {
	c := Config{PublishDir: "/publish", XrayBinary: "/native/xray", XrayConfigDir: "/native/xray-config", MosDNSBinary: "/native/mosdns", MosDNSConfigDir: "/native/mosdns-config", TimeoutSeconds: 60}
	b, _ := json.Marshal(c)
	if _, e := LoadConfig(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, b...), []byte(" rubbish")...), []byte(`{"timeout_seconds":91}`)} {
		if _, e := LoadConfig(bad); e == nil {
			t.Fatal("bad configuration accepted")
		}
	}
	c.PublishDir = "relative"
	b, _ = json.Marshal(c)
	if _, e := LoadConfig(b); e == nil {
		t.Fatal("relative path accepted")
	}
	c.PublishDir = "/publish"
	for _, path := range []string{"relative", "/publish", "/publish/private", "/"} {
		c.DiagnosticDir = path
		b, _ = json.Marshal(c)
		if _, e := LoadConfig(b); e == nil {
			t.Fatalf("unsafe diagnostic path accepted: %q", path)
		}
	}
	c.DiagnosticDir = "/diagnostics"
	b, _ = json.Marshal(c)
	if _, e := LoadConfig(b); e != nil {
		t.Fatal(e)
	}
}

func TestLoadConfigSelectsExactlyOneNativeBaseline(t *testing.T) {
	c := Config{PublishDir: "/publish", XrayBinary: "/native/xray", XrayConfigFile: "/native/config.json", MosDNSBinary: "/native/mosdns", MosDNSConfigDir: "/native/mosdns-config"}
	b, _ := json.Marshal(c)
	if _, err := LoadConfig(b); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.XrayConfigFile = "" },
		func(c *Config) { c.XrayConfigDir = "/native/modules" },
		func(c *Config) { c.XrayConfigFile = "relative.json" },
		func(c *Config) { c.XrayConfigFile = "/native/../config.json" },
	} {
		bad := c
		mutate(&bad)
		b, _ := json.Marshal(bad)
		if _, err := LoadConfig(b); err == nil {
			t.Fatalf("unsafe or ambiguous native input accepted: %+v", bad)
		}
	}
}

func TestNativeSingleFileReceivesExactPublishedBaseline(t *testing.T) {
	root := publication(t)
	native := t.TempDir()
	x := filepath.Join(native, "xray")
	input, captured := filepath.Join(native, "config.json"), filepath.Join(native, "captured.json")
	body := []byte("\n {\"outbounds\":[],\"env\":{\"xray.cone.disabled\":\"true\"},\"inbounds\":[{\"tag\":\"tunIn\",\"protocol\":\"tun\"}]}\n")
	if err := os.WriteFile(input, body, 0600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "versions", "test-v1", "manifest.json")
	manifestBody, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var value manifest
	if err := json.Unmarshal(manifestBody, &value); err != nil {
		t.Fatal(err)
	}
	value.BaselineSHA256 = sumHex(body)
	manifestBody, _ = json.Marshal(value)
	if err := os.WriteFile(manifestPath, manifestBody, 0600); err != nil {
		t.Fatal(err)
	}
	// Stop at the native validation phase after capturing its actual config.
	// The candidate contains the gateway env and TUN fields omitted by the old
	// module snapshot, so dropping those before validation would fail this test.
	script := "#!/bin/sh\n[ \"$1\" = run ] && [ \"$2\" = -test ] && [ \"$3\" = -config ] || exit 8\ncat \"$4\" > '" + captured + "'\nexit 7\n"
	if err := os.WriteFile(x, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	c := Config{PublishDir: root, XrayBinary: x, XrayConfigFile: input, MosDNSBinary: "/bin/sh", MosDNSConfigDir: native, TimeoutSeconds: 2}
	s, err := Run(context.Background(), c)
	if err == nil || s.ErrorCode != "verify_xray" || s.BaselineSHA256 != sumHex(body) {
		t.Fatalf("single-file native invocation failed: %+v %v", s, err)
	}
	got, err := os.ReadFile(captured)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("native input differs from the published baseline: %v", err)
	}
	if err := os.WriteFile(input, append(body, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	s, err = Run(context.Background(), c)
	if err == nil || s.ErrorCode != "verify_baseline_changed" {
		t.Fatalf("changed single-file baseline accepted: %+v %v", s, err)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(captured, input); err != nil {
		t.Fatal(err)
	}
	s, err = Run(context.Background(), c)
	if err == nil || s.ErrorCode != "verify_baseline_changed" {
		t.Fatalf("symlink single-file baseline accepted: %+v %v", s, err)
	}
}
func TestCloneMosDNSRewritesOnlyTemporaryCopy(t *testing.T) {
	source := t.TempDir()
	os.Mkdir(filepath.Join(source, "rule"), 0700)
	original := []byte("include: /etc/mosdns/dns.yaml\nfile: /var/mosdns/geosite_cn.txt\nold: /rules/versions/old-v1/geosite_cn.txt\nstable: /rules/current/geosite_cn.txt\n")
	for _, name := range []string{"config.yaml", "dns.yaml", "dat_exec.yaml"} {
		os.WriteFile(filepath.Join(source, name), original, 0600)
	}
	os.WriteFile(filepath.Join(source, "rule", "whitelist.txt"), []byte("full:fixture.invalid\n"), 0600)
	dest := filepath.Join(t.TempDir(), "mosdns")
	if e := cloneMosDNS(source, dest, "/publish/versions/test-v1"); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(dest, "config.yaml"))
	if strings.Contains(string(b), "/etc/mosdns/") || !strings.Contains(string(b), dest+"/dns.yaml") || !strings.Contains(string(b), "/publish/versions/test-v1/geosite_cn.txt") {
		t.Fatalf("rewrite: %s", b)
	}
	if strings.Contains(string(b), "/rules/current/") || strings.Contains(string(b), "/rules/versions/old-v1/") {
		t.Fatal("old assets retained")
	}
	b, _ = os.ReadFile(filepath.Join(source, "config.yaml"))
	if !bytes.Equal(b, original) {
		t.Fatal("source changed")
	}
	os.Symlink("/etc/passwd", filepath.Join(source, "rule", "unsafe.txt"))
	if e := cloneMosDNS(source, filepath.Join(t.TempDir(), "bad"), "/publish/versions/v1"); e == nil {
		t.Fatal("rule symlink accepted")
	}
}
func TestBoundedLogAndAssetEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "native.log")
	l, e := newLog(p)
	if e != nil {
		t.Fatal(e)
	}
	body := bytes.Repeat([]byte("secret"), 20000)
	if n, e := l.Write(body); e != nil || n != len(body) {
		t.Fatalf("drain: %d %v", n, e)
	}
	l.Close()
	st, _ := os.Stat(p)
	if st.Size() != 64<<10 || st.Mode().Perm() != 0600 {
		t.Fatalf("log limits: %+v", st)
	}
	env := withAsset([]string{"XRAY_LOCATION_ASSET=/old", "OTHER=kept"}, "/new")
	if strings.Join(env, "|") != "OTHER=kept|XRAY_LOCATION_ASSET=/new" {
		t.Fatal(env)
	}
}
func TestDNSResponseValidation(t *testing.T) {
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p, 123)
	p[2] = 0x81
	p[3] = 0x80
	p[7] = 1
	p = append(p, 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 2, 3, 4)
	if e := checkReply(p, 123, 0, true); e != nil {
		t.Fatal(e)
	}
	if e := checkReply(p, 124, 0, true); e == nil {
		t.Fatal("wrong identity accepted")
	}
	if e := checkReply(p[:len(p)-1], 123, 0, true); e == nil {
		t.Fatal("truncation accepted")
	}
	p = make([]byte, 12)
	binary.BigEndian.PutUint16(p, 123)
	p[2] = 0x81
	p[3] = 0x83
	if e := checkReply(p, 123, 3, false); e != nil {
		t.Fatal(e)
	}
	if e := checkReply(p, 123, 0, true); e == nil {
		t.Fatal("NXDOMAIN accepted as A answer")
	}
}
func TestProcessHelper(t *testing.T) {
	if os.Getenv("VERIFY_PROCESS_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}
func TestCancelledChildIsReaped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProcessHelper$")
	c.Env = append(os.Environ(), "VERIFY_PROCESS_HELPER=1")
	configureProcess(c)
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	pid := c.Process.Pid
	p := watchProcess(c)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		p.stop()
		t.Fatal("child not stopped")
	}
	p.stop()
	if c.ProcessState == nil {
		t.Fatal("child not waited")
	}
	if syscall.Kill(pid, 0) != syscall.ESRCH {
		t.Fatal("child still exists")
	}
}
func TestNativeFailureStopsBeforeMosDNSAndWritesSafeStatus(t *testing.T) {
	root := publication(t)
	diagnostics := t.TempDir()
	native := t.TempDir()
	x := filepath.Join(native, "xray")
	m := filepath.Join(native, "mosdns")
	marker := filepath.Join(native, "mosdns-started")
	os.WriteFile(x, []byte("#!/bin/sh\nprintf 'PRIVATE_NATIVE_OUTPUT\\n'\nexit 7\n"), 0700)
	os.WriteFile(m, []byte("#!/bin/sh\necho started > '"+marker+"'\n"), 0700)
	os.WriteFile(filepath.Join(native, "01_outbounds.json"), []byte(`{"outbounds":[]}`), 0600)
	c := Config{PublishDir: root, XrayBinary: x, XrayConfigDir: native, MosDNSBinary: m, MosDNSConfigDir: native, DiagnosticDir: diagnostics, TimeoutSeconds: 2}
	s, e := Run(context.Background(), c)
	if e == nil || s.ErrorCode != "verify_xray" || s.Status != "failed" || s.Version != "test-v1" {
		t.Fatalf("failure: %+v %v", s, e)
	}
	if _, e = os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("MosDNS started after Xray failure")
	}
	body, e := os.ReadFile(filepath.Join(root, "verification.json"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(body, []byte("PRIVATE_NATIVE_OUTPUT")) || bytes.Contains(body, []byte(native)) {
		t.Fatal("native output leaked")
	}
	var saved Summary
	if json.Unmarshal(body, &saved) != nil || saved.RunID != s.RunID || saved.ErrorCode != "verify_xray" {
		t.Fatal("status mismatch")
	}
	if s.Phase != "xray_run_test" {
		t.Fatalf("failure phase: %q", s.Phase)
	}
	if _, ok := s.PhaseDurationsMS["xray_run_test"]; !ok {
		t.Fatal("native phase timing missing")
	}
	log, e := os.ReadFile(filepath.Join(diagnostics, "last-xray.log"))
	if e != nil || !bytes.Contains(log, []byte("PRIVATE_NATIVE_OUTPUT")) {
		t.Fatalf("private diagnostic missing: %v", e)
	}
	meta, e := os.ReadFile(filepath.Join(diagnostics, "last.json"))
	if e != nil || json.Unmarshal(meta, &saved) != nil || saved.RunID != s.RunID || saved.Phase != s.Phase || saved.ErrorCode != "verify_xray" {
		t.Fatalf("private metadata mismatch: %v", e)
	}
	if bytes.Contains(meta, []byte("PRIVATE_NATIVE_OUTPUT")) || bytes.Contains(meta, []byte(native)) {
		t.Fatal("raw native output leaked into metadata")
	}
}

func TestBaselineDriftStopsBeforeNative(t *testing.T) {
	root := publication(t)
	native := t.TempDir()
	os.WriteFile(filepath.Join(native, "01.json"), []byte(`{"outbounds":[{"tag":"changed"}]}`), 0600)
	c := Config{PublishDir: root, XrayBinary: "/bin/sh", XrayConfigDir: native, MosDNSBinary: "/bin/sh", MosDNSConfigDir: native, TimeoutSeconds: 2}
	s, e := Run(context.Background(), c)
	if e == nil || s.ErrorCode != "verify_baseline_changed" {
		t.Fatalf("baseline drift: %+v %v", s, e)
	}
	if s.BaselineSHA256 != sumHex([]byte(`{"outbounds":[]}`)) {
		t.Fatal("audit baseline missing")
	}
}
func TestMosDNSAdsReferenceIsNotSilentlyRemoved(t *testing.T) {
	source := t.TempDir()
	os.Mkdir(filepath.Join(source, "rule"), 0700)
	for _, name := range []string{"config.yaml", "dns.yaml", "dat_exec.yaml"} {
		os.WriteFile(filepath.Join(source, name), []byte("files: /rules/current/geosite_category-ads-all.txt\n"), 0600)
	}
	if e := cloneMosDNS(source, filepath.Join(t.TempDir(), "mosdns"), "/publish/versions/v1"); e != failure("verify_mosdns_ads_reference") {
		t.Fatalf("ads accepted: %v", e)
	}
}

func TestMosDNSAdsRequireExactVerifiedPublicationAsset(t *testing.T) {
	root := publication(t)
	versionDir := filepath.Join(root, "versions", "test-v1")
	manifestPath := filepath.Join(versionDir, "manifest.json")
	manifestBody, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var published manifest
	if err := json.Unmarshal(manifestBody, &published); err != nil {
		t.Fatal(err)
	}
	asset := []byte("full:ad.example.invalid\n")
	const name = "geosite_category-ads-all.txt"
	published.Files[name] = struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}{sumHex(asset), int64(len(asset))}
	manifestBody, _ = json.Marshal(published)
	if err := os.WriteFile(manifestPath, manifestBody, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, name), asset, 0600); err != nil {
		t.Fatal(err)
	}
	verifiedDir, verified, err := snapshot(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "rule"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"config.yaml", "dns.yaml", "dat_exec.yaml"} {
		if err := os.WriteFile(filepath.Join(source, file), []byte("files: /rules/current/"+name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dest := filepath.Join(t.TempDir(), "mosdns")
	if err := cloneMosDNSWithAds(source, dest, verifiedDir, verified); err != nil {
		t.Fatalf("explicit verified category asset rejected: %v", err)
	}
	copy, err := os.ReadFile(filepath.Join(dest, "config.yaml"))
	if err != nil || !bytes.Contains(copy, []byte(verifiedDir+"/"+name)) {
		t.Fatalf("allowed asset was not bound to the verified version: %v", err)
	}
	if err := cloneMosDNS(source, filepath.Join(t.TempDir(), "default"), verifiedDir); err != failure("verify_mosdns_ads_reference") {
		t.Fatalf("unverified ads reference accepted: %v", err)
	}
	empty := *verified
	empty.Files = map[string]struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}{name: {SHA256: sumHex(nil), Bytes: 0}}
	if err := cloneMosDNSWithAds(source, filepath.Join(t.TempDir(), "empty"), verifiedDir, &empty); err != failure("verify_mosdns_ads_reference") {
		t.Fatalf("empty ads asset accepted: %v", err)
	}
	for _, missing := range []*manifest{nil, {Files: map[string]struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}{}}} {
		if err := cloneMosDNSWithAds(source, filepath.Join(t.TempDir(), "missing"), verifiedDir, missing); err != failure("verify_mosdns_ads_reference") {
			t.Fatalf("missing manifest asset accepted: %v", err)
		}
	}
	for _, bad := range []string{"geosite_ads.txt", "geosite_category-ads-all", "geosite_category-ads-all.txt.bak", "prefix-geosite_category-ads-all.txt"} {
		if err := os.WriteFile(filepath.Join(source, "config.yaml"), []byte("files: /rules/current/"+bad+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := cloneMosDNSWithAds(source, filepath.Join(t.TempDir(), "bad"), verifiedDir, verified); err != failure("verify_mosdns_ads_reference") {
			t.Fatalf("legacy or unverified ads name accepted: %s: %v", bad, err)
		}
	}
	if err := os.WriteFile(filepath.Join(versionDir, name), []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := snapshot(context.Background(), root); err != failure("verify_integrity") {
		t.Fatalf("corrupted opt-in asset passed publication verification: %v", err)
	}
}
