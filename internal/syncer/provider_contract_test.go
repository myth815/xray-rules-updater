package syncer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/myth815/xray-rules-updater/internal/client"
)

// The resulting full raw JSON is consumed verbatim by the OneXray Dart adapter
// contract test. This fixture has synthetic identities and tiny native DATs;
// it never includes private deployment inputs or downloads from its fake URLs.
func TestOneXrayProviderProducerContract(t *testing.T) {
	dataDir := filepath.Join("..", "..", "testdata", "onexray-provider-geodata")
	input, err := os.ReadFile(filepath.Join(dataDir, "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ReleaseID          string          `json:"release_id"`
		GeneratorVersion   string          `json:"generator_version"`
		ClientAssetBaseURL string          `json:"client_asset_base_url"`
		GeoIP              string          `json:"geoip_base64"`
		GeoSite            string          `json:"geosite_base64"`
		Baseline           json.RawMessage `json:"baseline"`
		Client             client.Overlay  `json:"client"`
	}
	if err := json.Unmarshal(input, &fixture); err != nil {
		t.Fatal(err)
	}
	ip, err := base64.StdEncoding.DecodeString(fixture.GeoIP)
	if err != nil {
		t.Fatal(err)
	}
	site, err := base64.StdEncoding.DecodeString(fixture.GeoSite)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for name, body := range map[string][]byte{"baseline.json": fixture.Baseline, "geoip.dat": ip, "geosite.dat": site} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := Config{
		SchemaVersion: 1, GeneratorVersion: fixture.GeneratorVersion,
		Baseline: filepath.Join(root, "baseline.json"), PublishDir: filepath.Join(root, "publish"),
		Client: fixture.Client, OneXrayVersionedGEO: true, OneXrayProviderGEOMetadata: true,
		ClientAssetBaseURL: fixture.ClientAssetBaseURL, BudgetBytes: 4 << 20, MinFreeBytes: 1,
		MaxAssetBytes: 64 << 10, TimeoutSeconds: 30,
		Source: Source{ReleaseID: fixture.ReleaseID,
			GeoIP:   Asset{Path: filepath.Join(root, "geoip.dat"), SHA256: hash(ip), Size: int64(len(ip))},
			GeoSite: Asset{Path: filepath.Join(root, "geosite.dat"), SHA256: hash(site), Size: int64(len(site))}},
	}
	first, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	provider, _ := os.ReadFile(filepath.Join(c.PublishDir, "current", "onexray.json"))
	var top map[string]json.RawMessage
	if err := json.Unmarshal(provider, &top); err != nil {
		t.Fatal(err)
	}
	if len(top["geodata"]) == 0 {
		t.Fatal("contract lacks subscription dependency metadata")
	}
	delete(top, "geodata")
	native, _ := json.MarshalIndent(top, "", "  ")
	native = append(native, '\n')
	for name, actual := range map[string][]byte{"provider.json": provider, "native.json": native} {
		path := filepath.Join(dataDir, name)
		// Only deliberate fixture maintenance writes tracked golden JSON. Normal
		// tests are read-only, so producer drift fails both language contracts.
		if os.Getenv("UPDATE_XRAY_PROVIDER_FIXTURE") == "1" {
			if err := os.WriteFile(path, actual, 0644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatalf("producer/Dart fixture %s changed; regenerate deliberately: %v", name, err)
		}
	}
	// A policy-only refresh changes immutable publication URLs, while the full
	// hash basenames and expected bytes remain reusable by the Dart adapter.
	c.GeneratorVersion += "-policy-only"
	second, err := Run(context.Background(), c)
	if err != nil || first.Version == second.Version {
		t.Fatal("policy-only fixture did not advance")
	}
	updated, _ := os.ReadFile(filepath.Join(c.PublishDir, "current", "onexray.json"))
	var next map[string]json.RawMessage
	_ = json.Unmarshal(updated, &next)
	var a, b struct {
		Assets []map[string]string `json:"assets"`
	}
	var original map[string]json.RawMessage
	_ = json.Unmarshal(provider, &original)
	_ = json.Unmarshal(original["geodata"], &a)
	_ = json.Unmarshal(next["geodata"], &b)
	if len(a.Assets) != 2 || len(b.Assets) != 2 {
		t.Fatal("contract dependency set changed")
	}
	for i := range a.Assets {
		if a.Assets[i]["file"] != b.Assets[i]["file"] || a.Assets[i]["url"] == b.Assets[i]["url"] {
			t.Fatal("policy-only change did not preserve content identity and advance URL")
		}
	}
	updatedPath := filepath.Join(dataDir, "provider-policy-only.json")
	if os.Getenv("UPDATE_XRAY_PROVIDER_FIXTURE") == "1" {
		if err := os.WriteFile(updatedPath, updated, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(updatedPath)
	if err != nil || !bytes.Equal(updated, want) {
		t.Fatal("policy-only producer/Dart fixture changed")
	}
}
