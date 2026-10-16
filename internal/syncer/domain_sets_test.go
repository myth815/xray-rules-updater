package syncer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDerivedDomainPublicationAndIdentityPreserveBaselineHash(t *testing.T) {
	c := fixture(t)
	baseline, err := os.ReadFile(c.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	c.DomainSetsFromOutbounds = map[string]string{"business.txt": "direct"}
	c.Client.DNS = json.RawMessage(`{"servers":[{"tag":"one","address":"1.1.1.1","finalQuery":true},{"tag":"two","address":"8.8.8.8","skipFallback":true}]}`)
	c.Client.DNSServersFromOutbounds = map[string]string{"one": "direct"}
	first, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c.PublishDir, "versions", first.Version)
	data, _ := os.ReadFile(filepath.Join(dir, "business.txt"))
	if string(data) != "domain:example.cn\n" {
		t.Fatalf("business set: %q", data)
	}
	var manifest Manifest
	data, _ = os.ReadFile(filepath.Join(dir, "manifest.json"))
	if json.Unmarshal(data, &manifest) != nil || manifest.BaselineSHA256 != hash(baseline) || manifest.Counts["business.txt"] != 1 {
		t.Fatal("baseline hash or derived manifest changed")
	}
	c.DomainSetsFromOutbounds = map[string]string{"renamed.txt": "direct"}
	second, err := Run(context.Background(), c)
	if err != nil || second.Version == first.Version {
		t.Fatalf("domain export mapping absent from identity: %+v %v", second, err)
	}
	c.Client.DNSServersFromOutbounds = map[string]string{"two": "direct"}
	third, err := Run(context.Background(), c)
	if err != nil || third.Version == second.Version {
		t.Fatalf("client DNS mapping absent from identity: %+v %v", third, err)
	}
	after, _ := os.ReadFile(c.Baseline)
	if hash(after) != hash(baseline) {
		t.Fatal("authoritative baseline bytes changed")
	}
}

func TestDerivedDomainFilenamesCannotCollide(t *testing.T) {
	for _, filename := range []string{"cn.txt", "ip.txt", "geoip.dat", "geosite.dat", "onexray.json", "manifest.json", "status.json", "verification.json", "health.json", "routeros-cn-v4.rsc", "../bad"} {
		c := fixture(t)
		c.DomainSetsFromOutbounds = map[string]string{filename: "direct"}
		if err := c.validate(); err == nil {
			t.Fatalf("reserved/duplicate filename accepted: %s", filename)
		}
	}
}

func TestMosDNSCommentDelimiterRefusalPreservesCurrent(t *testing.T) {
	for _, source := range []string{"geo", "manual-derived"} {
		t.Run(source, func(t *testing.T) {
			c := fixture(t)
			first, err := Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			if source == "geo" {
				domain := append([]byte{8, 1}, pb(2, []byte(`^api[#]tail$`))...)
				site := pb(1, append(pb(1, []byte("cn")), pb(2, domain)...))
				if err := os.WriteFile(c.Source.GeoSite.Path, site, 0600); err != nil {
					t.Fatal(err)
				}
				c.Source.GeoSite.SHA256, c.Source.GeoSite.Size = hash(site), int64(len(site))
			} else {
				baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["regexp:^api\\#tail$"],"outboundTag":"direct"}]}}`)
				if err := os.WriteFile(c.Baseline, baseline, 0600); err != nil {
					t.Fatal(err)
				}
				c.DomainSetsFromOutbounds = map[string]string{"business.txt": "direct"}
			}
			failed, err := Run(context.Background(), c)
			if err == nil || failed.ErrorCode != "dat_invalid" {
				t.Fatalf("lossy MosDNS matcher was not refused: %+v %v", failed, err)
			}
			assertCurrent(t, c, first.Version)
		})
	}
}
