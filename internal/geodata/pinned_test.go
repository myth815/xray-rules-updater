package geodata

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestPinnedFixture is optional because real DAT assets are deliberately not
// checked into the source tree or baked into the runtime image. It compares
// this implementation to the independently verified 202610132205 snapshot.
func TestPinnedFixture(t *testing.T) {
	dir := os.Getenv("POLICY_SYNC_FIXTURE_DIR")
	if dir == "" {
		t.Skip("POLICY_SYNC_FIXTURE_DIR not set")
	}
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	geoip, geosite := read("geoip.dat"), read("geosite.dat")
	if fmt.Sprintf("%x", sha256.Sum256(geoip)) != "116cc0f03d48991962f7f9cdbbcf53d45d89777f9c3cd1a663210853e5df6093" ||
		fmt.Sprintf("%x", sha256.Sum256(geosite)) != "c5a73fbd415bb0506ecf8fa574caadc6f54a71d9308c265e97da49e4cebf8466" {
		t.Fatal("fixture is not the independently verified 202610132205 release")
	}
	sites := map[string]string{
		"geosite_cn.txt": "cn", "geosite_apple-cn.txt": "apple-cn", "geosite_google-cn.txt": "google-cn",
		"geosite_gfw.txt": "gfw", "geosite_geolocation-!cn.txt": "geolocation-!cn",
	}
	ips := map[string]string{"geoip_cn.txt": "cn", "geoip_private.txt": "private"}
	r, err := Export(geoip, geosite, sites, ips, "CandidateCN202610132205")
	if err != nil {
		t.Fatal(err)
	}
	for name := range sites {
		if !bytes.Equal(r.Files[name], read(name)) {
			t.Errorf("%s differs from independent converter output", name)
		}
	}
	for name := range ips {
		if !bytes.Equal(r.Files[name], read(name)) {
			t.Errorf("%s differs from independent exact-coverage converter output", name)
		}
	}
	if r.Counts["routeros-cn-v4.rsc"] != 6163 || r.Counts["geosite_cn.txt"] != 110622 {
		t.Fatalf("unexpected pinned output counts: %v", r.Counts)
	}
	refs := []string{
		"geoip:cn", "geoip:!cn", "geoip:private", "geosite:cn", "geosite:geolocation-!cn",
		"geosite:openai", "geosite:anthropic", "geosite:google-gemini", "geosite:google-deepmind",
		"geosite:huggingface", "geosite:perplexity", "geosite:category-ai-!cn",
	}
	if err := ValidateReferences(geoip, geosite, refs); err != nil {
		t.Fatal(err)
	}
	t.Logf("pinned native DAT export and required GEO references verified: %v", r.Counts)
}
