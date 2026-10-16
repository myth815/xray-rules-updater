package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myth815/xray-rules-updater/internal/client"
)

func TestProviderGEOMetadataRequiresExplicitVersionedOptIn(t *testing.T) {
	c := fixture(t)
	c.OneXrayProviderGEOMetadata = true
	if err := c.validate(); err == nil {
		t.Fatal("provider metadata accepted without versioned GEO")
	}
	if _, _, _, err := bindClientAssets(c, "test-v1", nil, nil, []byte(`{}`)); err == nil {
		t.Fatal("binding bypassed explicit versioned GEO requirement")
	}
	c.OneXrayVersionedGEO = true
	if err := c.validate(); err == nil {
		t.Fatal("provider metadata accepted without HTTPS origin")
	}
}

func TestProviderGEOMetadataActualDependenciesAndNoDATCopies(t *testing.T) {
	for _, test := range []struct {
		name, routing, dns string
		want               []string
	}{
		{"domain only", `[{"domain":["geosite:cn","geosite:cn"],"outboundTag":"direct"}]`, `["1.1.1.1"]`, []string{"geosite.dat"}},
		{"DNS only", `[{"domain":["domain:example.invalid"],"outboundTag":"direct"}]`, `[{"address":"1.1.1.1","domains":["geosite:cn"]}]`, []string{"geosite.dat"}},
		{"IP only", `[{"ip":["geoip:cn"],"outboundTag":"direct"}]`, `["1.1.1.1"]`, []string{"geoip.dat"}},
		{"both", `[{"ip":["geoip:cn"],"domain":["geosite:cn"],"outboundTag":"direct"}]`, `["1.1.1.1"]`, []string{"geoip.dat", "geosite.dat"}},
		{"none", `[{"domain":["domain:example.invalid"],"outboundTag":"direct"}]`, `["1.1.1.1"]`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := fixture(t)
			c.OneXrayVersionedGEO, c.OneXrayProviderGEOMetadata = true, true
			c.ClientAssetBaseURL = "https://rules.example.internal"
			baseline := `{"outbounds":[{"tag":"direct","protocol":"freedom"}],"dns":{"servers":` + test.dns + `},"routing":{"rules":` + test.routing + `}}`
			if err := os.WriteFile(c.Baseline, []byte(baseline), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(c.PublishDir, "current")
			var m Manifest
			body, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			body, _ = os.ReadFile(filepath.Join(dir, "onexray.json"))
			var top map[string]json.RawMessage
			_ = json.Unmarshal(body, &top)
			if len(m.ClientAssets) != len(test.want) {
				t.Fatal("manifest includes unused or missing dependencies")
			}
			if len(test.want) == 0 {
				if _, exists := top["geodata"]; exists {
					t.Fatal("zero dependencies should not require a provider manifest")
				}
			} else {
				var metadata map[string][]map[string]string
				if err := json.Unmarshal(top["geodata"], &metadata); err != nil || len(metadata) != 1 || len(metadata["assets"]) != len(test.want) {
					t.Fatal("invalid producer/Dart metadata contract")
				}
				for i, key := range test.want {
					asset := metadata["assets"][i]
					bound := m.ClientAssets[key]
					if len(asset) != 2 || asset["file"] != bound.Name || !strings.HasSuffix(asset["file"], "_"+bound.SHA256+".dat") || asset["url"] != c.ClientAssetBaseURL+"/versions/"+s.Version+"/"+key {
						t.Fatal("metadata differs from exact immutable dependencies")
					}
				}
				links, _ := os.ReadFile(filepath.Join(dir, "onexray-geodata.txt"))
				if len(strings.Split(strings.TrimSpace(string(links)), "\n")) != len(test.want) {
					t.Fatal("manual links do not match actual provider dependencies")
				}
			}
			entries, _ := os.ReadDir(dir)
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "home_geo") {
					t.Fatal("content-addressed DAT needlessly copied on router")
				}
			}
		})
	}
}

func TestProviderMetadataPreservesRawNativeValuesAndCredentials(t *testing.T) {
	c := Config{OneXrayVersionedGEO: true, ClientAssetBaseURL: "https://rules.example.internal"}
	raw := []byte(`{"routing":{"rules":[{"domain":["geosite:cn"],"ip":["geoip:!cn"],"network":"tcp","port":"443","outboundTag":"usa-ai"}]},"policy":{"levels":{"0":{"bufferSize":9007199254740993}}},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"usa-ai","protocol":"vless","settings":{"vnext":[{"address":"node.example.invalid","port":443,"users":[{"id":"SYNTHETIC-CLIENT-ID","encryption":"none"}]}]},"streamSettings":{"realitySettings":{"publicKey":"geosite:credential-text"}}}]}`)
	before := append([]byte(nil), raw...)
	legacy, _, _, err := bindClientAssets(c, "test-v1", []byte("IP"), []byte("SITE"), raw)
	if err != nil {
		t.Fatal(err)
	}
	c.OneXrayProviderGEOMetadata = true
	provider, _, _, err := bindClientAssets(c, "test-v1", []byte("IP"), []byte("SITE"), raw)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	_ = json.Unmarshal(provider, &top)
	delete(top, "geodata")
	stripped, _ := json.MarshalIndent(top, "", "  ")
	stripped = append(stripped, '\n')
	if !bytes.Equal(stripped, legacy) || !bytes.Equal(raw, before) || !bytes.Contains(provider, []byte("9007199254740993")) {
		t.Fatal("provider metadata changed native policy, credential values or integer precision")
	}
}

func TestProviderMetadataDisabledPreservesPolicyIdentity(t *testing.T) {
	for _, versioned := range []bool{false, true} {
		c := fixture(t)
		c.OneXrayVersionedGEO = versioned
		if versioned {
			c.ClientAssetBaseURL = "https://rules.example.internal"
		}
		s, err := Run(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		var m Manifest
		body, _ := os.ReadFile(filepath.Join(c.PublishDir, "current", "manifest.json"))
		_ = json.Unmarshal(body, &m)
		// Exact pre-metadata policy encoding: a false flag must not change IDs
		// and trigger an update for an existing disabled deployment.
		legacyPolicy, _ := json.Marshal(struct {
			Client       client.Overlay
			Sites, IPs   map[string]string
			RouterOS     bool
			DomainSets   map[string]string
			VersionedGEO bool
			AssetBaseURL string
		}{c.Client, c.Sites, c.IPs, c.RouterOSCandidate, c.DomainSetsFromOutbounds, c.OneXrayVersionedGEO, c.ClientAssetBaseURL})
		if m.PolicySHA256 != hash(legacyPolicy) {
			t.Fatal("disabled metadata changed existing policy identity")
		}
		legacyIdentity, _ := json.Marshal([]string{"format-v1", c.GeneratorVersion, c.Source.ReleaseID, strings.ToLower(c.Source.GeoIP.SHA256), strings.ToLower(c.Source.GeoSite.SHA256), m.BaselineSHA256, hash(legacyPolicy)})
		if s.Version != c.Source.ReleaseID+"-"+hash(legacyIdentity)[:12] {
			t.Fatal("disabled metadata changed the pre-metadata publication version")
		}
		one, _ := os.ReadFile(filepath.Join(c.PublishDir, "current", "onexray.json"))
		if bytes.Contains(one, []byte(`"geodata"`)) {
			t.Fatal("metadata enabled by default")
		}
		c.OneXrayProviderGEOMetadata = false
		next, err := Run(context.Background(), c)
		if err != nil || next.Status != "unchanged" || next.Version != s.Version {
			t.Fatal("explicit false changed an existing publication")
		}
		if versioned {
			c.OneXrayProviderGEOMetadata = true
			next, err = Run(context.Background(), c)
			if err != nil || next.Version == s.Version {
				t.Fatal("explicit opt-in missing from publication identity")
			}
		}
	}
}

func TestProviderMetadataRejectsConflictsAndMutableVersion(t *testing.T) {
	c := Config{OneXrayVersionedGEO: true, OneXrayProviderGEOMetadata: true, ClientAssetBaseURL: "https://rules.example.internal"}
	for _, v := range []string{"", "latest", "../other", "v1?token=x", "v1/else"} {
		if _, _, _, err := bindClientAssets(c, v, nil, nil, []byte(`{}`)); err == nil {
			t.Fatal("unsafe or mutable publication URL accepted")
		}
	}
	for _, rule := range []string{`"geosite:cn"`, `"domain:ordinary.example"`} {
		raw := []byte(`{"geodata":{"assets":[]},"routing":{"rules":[{"domain":[` + rule + `]}]}}`)
		if _, _, _, err := bindClientAssets(c, "v1", nil, nil, raw); err == nil {
			t.Fatal("silently replaced existing provider metadata, including zero actual dependencies")
		}
		legacy := c
		legacy.OneXrayProviderGEOMetadata = false
		if _, _, _, err := bindClientAssets(legacy, "v1", nil, nil, raw); err != nil {
			t.Fatal("new metadata conflict guard changed the legacy disabled behavior")
		}
	}
}
