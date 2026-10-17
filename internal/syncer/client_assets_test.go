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

	"github.com/myth815/xray-rules-updater/internal/client"
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

// Exercise Generate through native GEO binding, provider metadata, versioned
// publication and the complete Raw transfer. No core, network or real node is used.
func TestOneXrayFakeDNSPublishedTransferRetainsStrictUDP(t *testing.T) {
	c := fixture(t)
	c.OneXrayVersionedGEO = true
	c.OneXrayProviderGEOMetadata = true
	c.ClientAssetBaseURL = "https://rules.example.internal"
	baseline := []byte(`{
		"dns":{"servers":[
			{"address":"https://resolver.example.invalid/dns-query","tag":"dns-ai","domains":["domain:ai.example.invalid"],"skipFallback":true},
			"https://ordinary.example.invalid/dns-query"
		]},
		"outbounds":[
			{"tag":"direct","protocol":"freedom"},
			{"tag":"block","protocol":"blackhole"},
			{"tag":"usa-ai","protocol":"socks","settings":{"servers":[{"address":"192.0.2.10","port":1080}]}},
			{"tag":"mobile-dns-out","protocol":"dns","settings":{"rules":[{"qType":"1,28","action":"hijack"},{"action":"direct"}]}}
		],
		"routing":{"domainStrategy":"IPIfNonMatch","rules":[
			{"domain":["domain:ai.example.invalid"],"outboundTag":"usa-ai"},
			{"domain":["geosite:cn"],"outboundTag":"direct"},
			{"ip":["geoip:cn"],"outboundTag":"direct"},
			{"network":"tcp,udp","outboundTag":"direct"}
		]}
	}`)
	if err := os.WriteFile(c.Baseline, baseline, 0600); err != nil {
		t.Fatal(err)
	}
	c.Client.OneXrayFakeDNS = &client.OneXrayFakeDNS{OutboundTag: "usa-ai", DNSServerTag: "dns-ai", DNSOutboundTag: "mobile-dns-out"}
	c.Client.PrependRules = []json.RawMessage{json.RawMessage(`{"inboundTag":["tunIn"],"port":"53","outboundTag":"mobile-dns-out"}`)}
	result, err := Run(context.Background(), c)
	if err != nil || result.Status != "published" {
		t.Fatalf("opt-in publication: %+v %v", result, err)
	}
	assertCurrent(t, c, result.Version)
	dir := filepath.Join(c.PublishDir, "current")
	published, err := os.ReadFile(filepath.Join(dir, "onexray.json"))
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Env     map[string]string `json:"env"`
		FakeDNS json.RawMessage   `json:"fakedns"`
		Geodata json.RawMessage   `json:"geodata"`
		Name    string            `json:"name"`
	}
	if err := json.Unmarshal(published, &top); err != nil {
		t.Fatal(err)
	}
	if len(top.Env) != 1 || top.Env["xray.cone.disabled"] != "true" || len(top.FakeDNS) == 0 || len(top.Geodata) == 0 || top.Name != c.Client.Name+" / "+result.Version {
		t.Fatal("full opt-in publication lost strict UDP, provider assets or versioned identity")
	}
	transfer, err := os.ReadFile(filepath.Join(dir, "onexray-import.txt"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSpace(string(transfer)), "\n")
	if len(parts) != 3 {
		t.Fatal("complete transfer must include the configuration and two native DATs")
	}
	u, err := url.Parse(parts[0])
	if err != nil || u.Path != "/config/add" || u.Query().Get("type") != "raw" {
		t.Fatal("complete opt-in transfer is not a Raw configuration link")
	}
	decoded, err := base64.StdEncoding.DecodeString(u.Query().Get("data"))
	if err != nil || string(decoded) != string(published) {
		t.Fatal("complete transfer did not retain the exact published configuration")
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
