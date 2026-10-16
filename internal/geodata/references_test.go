package geodata

import (
	"testing"
)

func TestValidateReferences(t *testing.T) {
	ips := category("cn", cidrMessage("1.2.0.0/16"))
	sites := category("cn", domainMessage(2, "example.org", boolAttr("mobile", false), intAttr("score", 0)))
	for _, refs := range [][]string{
		nil,
		{"geosite:CN", "geoip:cn", "geoip:!CN"},
		{"geosite:cn@mobile@score"},
	} {
		if err := ValidateReferences(ips, sites, refs); err != nil {
			t.Fatalf("valid references %v rejected: %v", refs, err)
		}
	}
	for _, ref := range []string{"geosite:missing", "geoip:missing", "geoip:!!cn", "geoip:cn@mobile", "geosite:cn@missing", "geosite:cn@!mobile", "geosite:cn@score=0", "ext:custom.dat:cn", "ext-ip:custom.dat:cn", "domain:example.org"} {
		if err := ValidateReferences(ips, sites, []string{ref}); err == nil {
			t.Errorf("invalid or empty reference accepted: %s", ref)
		}
	}
	if err := ValidateReferences(category("cn"), sites, []string{"geoip:cn"}); err == nil {
		t.Fatal("empty required GeoIP accepted")
	}
	if err := ValidateReferences(ips, category("cn"), []string{"geosite:cn"}); err == nil {
		t.Fatal("empty required GeoSite accepted")
	}
	if err := ValidateReferences(ips, category("cn", domainMessage(99, "example.org")), []string{"geosite:cn"}); err == nil {
		t.Fatal("invalid required domain type accepted")
	}
}
