package syncer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/myth815/xray-rules-updater/internal/client"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pv(n uint64) []byte {
	var b []byte
	for n >= 128 {
		b = append(b, byte(n)|128)
		n >>= 7
	}
	return append(b, byte(n))
}
func pb(field byte, data []byte) []byte {
	return append(append([]byte{field<<3 | 2}, pv(uint64(len(data)))...), data...)
}
func fixture(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	ipentry := append(pb(1, []byte("cn")), pb(2, append(pb(1, []byte{1, 0, 1, 0}), []byte{16, 24}...))...)
	ip := pb(1, ipentry)
	dom := append([]byte{8, 2}, pb(2, []byte("example.cn"))...)
	site := pb(1, append(pb(1, []byte("cn")), pb(2, dom)...))
	baseline := []byte(`{"dns":{"servers":["1.1.1.1"]},"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["geosite:cn"],"outboundTag":"direct"}]}}`)
	paths := map[string][]byte{"geoip.dat": ip, "geosite.dat": site, "baseline.json": baseline}
	for name, b := range paths {
		if err := os.WriteFile(filepath.Join(root, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := Config{SchemaVersion: 1, GeneratorVersion: "test", Baseline: filepath.Join(root, "baseline.json"), PublishDir: filepath.Join(root, "publish"), BudgetBytes: 4 << 20, MinFreeBytes: 1, MaxAssetBytes: 64 << 10, TimeoutSeconds: 30, RouterOSCandidate: true, Client: client.Overlay{Name: "Test"}, Sites: map[string]string{"cn.txt": "cn"}, IPs: map[string]string{"ip.txt": "cn"}, Source: Source{ReleaseID: "fixture-v1", GeoIP: Asset{Path: filepath.Join(root, "geoip.dat"), SHA256: hash(ip), Size: int64(len(ip))}, GeoSite: Asset{Path: filepath.Join(root, "geosite.dat"), SHA256: hash(site), Size: int64(len(site))}}}
	return c
}
func assertCurrent(t *testing.T, c Config, version string) {
	t.Helper()
	target, err := pointer(c.PublishDir, "current")
	if err != nil || target != "versions/"+version {
		t.Fatalf("current changed: %q %v", target, err)
	}
	if _, err = validVersion(c.PublishDir, target); err != nil {
		t.Fatal(err)
	}
}
func TestPublishNoChangeAndRollbackRetention(t *testing.T) {
	c := fixture(t)
	a, err := Run(context.Background(), c)
	if err != nil || a.Status != "published" {
		t.Fatalf("first: %+v %v", a, err)
	}
	assertCurrent(t, c, a.Version)
	same, err := Run(context.Background(), c)
	if err != nil || same.Status != "unchanged" {
		t.Fatalf("repeat: %+v %v", same, err)
	}
	if same.RunID == a.RunID {
		t.Fatal("run ID reused")
	}
	body, err := os.ReadFile(filepath.Join(c.PublishDir, "current", "onexray.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if json.Unmarshal(body, &entry) != nil || entry["name"] != "Test / "+a.Version {
		t.Fatal("versioned subscription name missing")
	}
	for _, gen := range []string{"test-2", "test-3"} {
		c.GeneratorVersion = gen
		s, e := Run(context.Background(), c)
		if e != nil || s.Status != "published" {
			t.Fatalf("new generator: %+v %v", s, e)
		}
	}
	dirs, err := os.ReadDir(filepath.Join(c.PublishDir, "versions"))
	if err != nil || len(dirs) != 2 {
		t.Fatalf("retention: %d %v", len(dirs), err)
	}
	prev, err := pointer(c.PublishDir, "previous")
	if err != nil || prev == "" {
		t.Fatal("rollback pointer missing")
	}
	if _, err = validVersion(c.PublishDir, prev); err != nil {
		t.Fatal(err)
	}
}
func TestFailurePreservesCurrent(t *testing.T) {
	for _, test := range []string{"digest", "baseline", "missing-geo", "capacity", "lock"} {
		t.Run(test, func(t *testing.T) {
			c := fixture(t)
			a, err := Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			switch test {
			case "digest":
				c.Source.GeoIP.SHA256 = strings.Repeat("0", 64)
			case "baseline":
				_ = os.WriteFile(c.Baseline, []byte(`{"outbounds":[]}`), 0600)
			case "missing-geo":
				c.Sites["missing.txt"] = "missing"
			case "capacity":
				c.GeneratorVersion = "new"
				c.BudgetBytes = 1 << 20
				c.MaxAssetBytes = 1 << 20
				c.Source.GeoIP.Size = 0
				c.Source.GeoSite.Size = 0
			case "lock":
				unlock, e := prepareRoot(c, "other")
				if e != nil {
					t.Fatal(e)
				}
				defer unlock()
			}
			s, e := Run(context.Background(), c)
			if e == nil || s.Status != "failed" {
				t.Fatalf("failure accepted: %+v %v", s, e)
			}
			assertCurrent(t, c, a.Version)
		})
	}
}

func TestOrdinaryExportBudgetRefusalPreservesCurrent(t *testing.T) {
	c := fixture(t)
	first, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	entry := pb(1, []byte("cn"))
	for i := 0; i < 2000; i++ {
		value := fmt.Sprintf("%s%08d.example", strings.Repeat("a", 50), i)
		domain := append([]byte{8, 2}, pb(2, []byte(value))...)
		entry = append(entry, pb(2, domain)...)
	}
	site := pb(1, entry)
	if err := os.WriteFile(c.Source.GeoSite.Path, site, 0600); err != nil {
		t.Fatal(err)
	}
	c.Source.GeoSite.SHA256, c.Source.GeoSite.Size = hash(site), int64(len(site))
	c.BudgetBytes, c.MaxAssetBytes = 1<<20, 256<<10
	c.RouterOSCandidate, c.IPs = false, nil
	c.Sites = map[string]string{}
	for i := 0; i < 8; i++ {
		c.Sites[fmt.Sprintf("cn-%02d.txt", i)] = "cn"
	}
	failed, err := Run(context.Background(), c)
	if err == nil || failed.ErrorCode != "capacity" {
		t.Fatalf("ordinary export limit did not fail as resource admission: %+v %v", failed, err)
	}
	assertCurrent(t, c, first.Version)
	entries, err := os.ReadDir(filepath.Join(c.PublishDir, "versions"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("refused export left another version: %v %v", entries, err)
	}
}

func TestOrdinaryExportAdmissionIncludesRetainedRootBytes(t *testing.T) {
	c := fixture(t)
	first, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	// Unknown retained bytes are intentionally not pruned by the publisher, but
	// must still reduce the candidate's construction budget.
	if err := os.WriteFile(filepath.Join(c.PublishDir, "retained-fixture"), make([]byte, 512<<10), 0600); err != nil {
		t.Fatal(err)
	}
	entry := pb(1, []byte("cn"))
	for i := 0; i < 2000; i++ {
		value := fmt.Sprintf("%s%08d.example", strings.Repeat("a", 50), i)
		entry = append(entry, pb(2, append([]byte{8, 2}, pb(2, []byte(value))...))...)
	}
	site := pb(1, entry)
	if err := os.WriteFile(c.Source.GeoSite.Path, site, 0600); err != nil {
		t.Fatal(err)
	}
	c.Source.GeoSite.SHA256, c.Source.GeoSite.Size = hash(site), int64(len(site))
	c.BudgetBytes, c.MaxAssetBytes = 1<<20, 256<<10
	c.RouterOSCandidate, c.IPs = false, nil
	c.Sites = map[string]string{}
	for i := 0; i < 5; i++ {
		c.Sites[fmt.Sprintf("cn-%02d.txt", i)] = "cn"
	}
	failed, err := Run(context.Background(), c)
	if err == nil || failed.ErrorCode != "capacity" || !strings.Contains(err.Error(), "export size limit") {
		t.Fatalf("retained bytes were not deducted before export materialization: %+v %v", failed, err)
	}
	assertCurrent(t, c, first.Version)
}
func TestLockReleaseAndInterruptedStageCleanup(t *testing.T) {
	c := fixture(t)
	unlock, err := prepareRoot(c, "old")
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(c.PublishDir, ".stage-abcd")
	_ = os.Mkdir(stage, 0700)
	_ = os.WriteFile(filepath.Join(stage, "partial"), []byte("partial"), 0600)
	unlock()
	s, err := Run(context.Background(), c)
	if err != nil || s.Status != "published" {
		t.Fatalf("recovery: %+v %v", s, err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("interrupted staging not removed")
	}
}
func TestCorruptedPublicationRefused(t *testing.T) {
	c := fixture(t)
	s, e := Run(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(c.PublishDir, "versions", s.Version, "geoip.dat")
	_ = os.WriteFile(p, []byte("corrupt"), 0600)
	if _, e = Run(context.Background(), c); e == nil {
		t.Fatal("corrupt cached publication accepted")
	}
}
func TestConfigRejectsAmbiguity(t *testing.T) {
	c := fixture(t)
	raw, _ := json.Marshal(c)
	if _, err := LoadConfig(append(raw, []byte(" rubbish")...), "/"); err == nil {
		t.Fatal("trailing garbage accepted")
	}
	if _, err := LoadConfig(append(raw, []byte(" {}")...), "/"); err == nil {
		t.Fatal("multiple objects accepted")
	}
	c.Sites["../escape"] = "cn"
	if err := c.validate(); err == nil {
		t.Fatal("path escape accepted")
	}
}

func TestOrphanVersionRecoveredBeforeCapacityCheck(t *testing.T) {
	c := fixture(t)
	s, e := Run(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	orphan := "orphan-v1"
	root := filepath.Join(c.PublishDir, "versions", orphan)
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(c.PublishDir, "versions", s.Version, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var m Manifest
	_ = json.Unmarshal(data, &m)
	m.Version = orphan
	for name := range m.Files {
		b, e := os.ReadFile(filepath.Join(c.PublishDir, "versions", s.Version, name))
		if e != nil {
			t.Fatal(e)
		}
		_ = os.WriteFile(filepath.Join(root, name), b, 0600)
	}
	data, _ = json.Marshal(m)
	_ = os.WriteFile(filepath.Join(root, "manifest.json"), data, 0600)
	if _, e = Run(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("completed unreferenced version retained")
	}
	assertCurrent(t, c, s.Version)
}

func TestServingGroupPermissions(t *testing.T) {
	c := fixture(t)
	gid := os.Getgid()
	c.ServeGroupID = &gid
	if _, e := Run(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	i, e := os.Stat(filepath.Join(c.PublishDir, "current", "onexray.json"))
	if e != nil || i.Mode().Perm() != 0640 {
		t.Fatalf("file mode %v %v", i, e)
	}
	i, e = os.Stat(filepath.Join(c.PublishDir, "current"))
	if e != nil || i.Mode().Perm() != 0750 {
		t.Fatalf("directory mode %v %v", i, e)
	}
	i, e = os.Stat(filepath.Join(c.PublishDir, "status.json"))
	if e != nil || i.Mode().Perm() != 0640 {
		t.Fatalf("status mode %v %v", i, e)
	}
}

func TestExampleConfigurationIsAccepted(t *testing.T) {
	body, e := os.ReadFile("../../examples/config.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = LoadConfig(body, t.TempDir()); e != nil {
		t.Fatal(e)
	}
	c := fixture(t)
	c.Sites["geosite_geolocation-!cn.txt"] = "cn"
	if _, e = Run(context.Background(), c); e != nil {
		t.Fatal(e)
	}
}
