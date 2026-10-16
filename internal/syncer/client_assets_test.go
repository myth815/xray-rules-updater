package syncer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionedClientAssetsBindNativeReferencesWithoutDATCopies(t *testing.T) {
	c := fixture(t)
	c.OneXrayVersionedGEO = true
	c.ClientAssetBaseURL = "https://rules.example.internal"
	s, e := Run(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(c.PublishDir, "current")
	ip, _ := os.ReadFile(filepath.Join(dir, "geoip.dat"))
	site, _ := os.ReadFile(filepath.Join(dir, "geosite.dat"))
	var m Manifest
	b, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	if len(m.ClientAssets) != 2 {
		t.Fatal("missing typed asset bindings")
	}
	for key, body := range map[string][]byte{"geoip.dat": ip, "geosite.dat": site} {
		a := m.ClientAssets[key]
		if a.SHA256 != hash(body) || a.Bytes != int64(len(body)) || a.URL != "https://rules.example.internal/versions/"+s.Version+"/"+key {
			t.Fatalf("wrong immutable asset: %+v", a)
		}
	}
	one, _ := os.ReadFile(filepath.Join(dir, "onexray.json"))
	if !strings.Contains(string(one), "ext:home_geosite_"+hash(site)+".dat:cn") || strings.Contains(string(one), "geosite:cn") {
		t.Fatal("client not bound to exact DAT")
	}
	links, _ := os.ReadFile(filepath.Join(dir, "onexray-geodata.txt"))
	lines := strings.Split(strings.TrimSpace(string(links)), "\n")
	if len(lines) != 2 {
		t.Fatal("not a DAT-only import")
	}
	for i, key := range []string{"geoip.dat", "geosite.dat"} {
		u, e := url.Parse(lines[i])
		a := m.ClientAssets[key]
		if e != nil || u.Scheme != "onexray" || u.Host != "onexray.com" || u.Path != "/dat/add" || u.Query().Get("type") != a.Type || u.Query().Get("url") != a.URL || u.Fragment != a.Name {
			t.Fatal("invalid typed import link")
		}
	}
	full, _ := os.ReadFile(filepath.Join(dir, "onexray-import.txt"))
	parts := strings.Split(strings.TrimSpace(string(full)), "\n")
	if len(parts) != 3 {
		t.Fatal("initial transfer must include raw config and two DATs")
	}
	rawURL, e := url.Parse(parts[0])
	if e != nil || rawURL.Path != "/config/add" || rawURL.Query().Get("type") != "raw" || len([]rune(rawURL.Fragment)) > 32 {
		t.Fatal("invalid raw transfer link")
	}
	decoded, e := base64.StdEncoding.DecodeString(rawURL.Query().Get("data"))
	if e != nil || string(decoded) != string(one) {
		t.Fatal("transfer changed full native config")
	}
	configOnly, _ := os.ReadFile(filepath.Join(dir, "onexray-config.txt"))
	if strings.TrimSpace(string(configOnly)) != parts[0] {
		t.Fatal("config-only transfer differs")
	}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "home_geo") {
			t.Fatal("DAT duplicated on small router")
		}
	}
	if _, e = validVersion(c.PublishDir, "versions/"+s.Version); e != nil {
		t.Fatal(e)
	}
	// A policy-only change uses the same DAT filenames and bytes on the phone.
	c.GeneratorVersion = "policy-update"
	next, e := Run(context.Background(), c)
	if e != nil || next.Version == s.Version {
		t.Fatal("policy did not advance")
	}
	b, _ = os.ReadFile(filepath.Join(c.PublishDir, "current", "manifest.json"))
	var n Manifest
	_ = json.Unmarshal(b, &n)
	for key, a := range m.ClientAssets {
		if n.ClientAssets[key].Name != a.Name || n.ClientAssets[key].SHA256 != a.SHA256 {
			t.Fatal("identical DAT needlessly renamed")
		}
	}
}

func TestVersionedClientAssetsRequireHTTPSOrigin(t *testing.T) {
	for _, origin := range []string{"", "http://rules.example.internal", "https://user:secret@rules.example.internal", "https://rules.example.internal/path", "https://rules.example.internal?token=x", "https://rules.example.internal#x"} {
		c := fixture(t)
		c.OneXrayVersionedGEO = true
		c.ClientAssetBaseURL = origin
		if e := c.validate(); e == nil {
			t.Fatalf("unsafe asset origin accepted: %q", origin)
		}
	}
	c := fixture(t)
	c.ClientAssetBaseURL = "https://rules.example.internal"
	if e := c.validate(); e == nil {
		t.Fatal("unused origin accepted")
	}
}
