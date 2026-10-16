package geodata

import (
	"errors"
	"testing"
)

func TestDomainSetExportMergesKindsAttributesAndManual(t *testing.T) {
	sites := category("AI", domainMessage(2, "suffix.example", boolAttr("mobile", false)), domainMessage(3, "api.example", intAttr("mobile", 0)), domainMessage(0, "key", boolAttr("mobile", true)), domainMessage(1, `^api\.`, boolAttr("mobile", true)), domainMessage(2, "excluded.example"))
	r, err := ExportDomainSets(sites, map[string][]string{"business.txt": {"geosite:ai@MOBILE", "full:api.example", "domain:manual.example", "keyword:key", "plain-keyword", `regexp:^api\.`}})
	if err != nil {
		t.Fatal(err)
	}
	want := "domain:manual.example\ndomain:suffix.example\nfull:api.example\nkeyword:key\nkeyword:plain-keyword\nregexp:^api\\.\n"
	if string(r.Files["business.txt"]) != want || r.Counts["business.txt"] != 6 {
		t.Fatalf("semantic export: %q %v", r.Files["business.txt"], r.Counts)
	}
}

func TestDomainSetExportFailsForMissingOrEmptyGEOAndUnknownMatchers(t *testing.T) {
	sites := category("ai", domainMessage(2, "example"))
	for _, expression := range []string{"geosite:missing", "geosite:ai@absent", "ext:custom.dat:ai", "dotless:", "future:example", "full:", "regexp:[", "full:unsafe\nline"} {
		if _, err := ExportDomainSets(sites, map[string][]string{"business.txt": {expression}}); err == nil {
			t.Fatalf("unsupported expression accepted: %q", expression)
		}
	}
}

func TestDomainSetExportStopsAtFileAndAggregateBudgets(t *testing.T) {
	sets := map[string][]string{"a.txt": {"full:a.example", "full:a.example"}, "b.txt": {"full:b.example"}}
	if _, err := ExportDomainSetsBounded(nil, sets, 15, 30); err != nil {
		t.Fatal("deduplication incorrectly spent budget", err)
	}
	for _, limit := range [][2]int64{{14, 100}, {100, 29}} {
		if _, err := ExportDomainSetsBounded(nil, sets, limit[0], limit[1]); !errors.Is(err, ErrExportLimit) {
			t.Fatalf("export exceeded budget: %v", limit)
		}
	}
}

func TestDerivedMosDNSDomainSetsRejectCommentDelimiter(t *testing.T) {
	for _, expression := range []string{"plain#tail", "full:api#tail.example", "domain:api#tail.example", "keyword:api#tail", `regexp:^api#tail$`, `regexp:^api\#tail$`, `regexp:^api[#]tail$`} {
		if err := ValidateDomainExpressions([]string{expression}); err != nil {
			t.Fatalf("native matcher was changed or rejected: %q %v", expression, err)
		}
		if got, err := ExportDomainSets(nil, map[string][]string{"business.txt": {expression}}); got != nil || err == nil {
			t.Fatalf("MosDNS comment delimiter accepted: %q %v %v", expression, got, err)
		}
	}
	sites := category("ai", domainMessage(1, `^api[#]tail$`), domainMessage(3, "safe.example", boolAttr("safe", true)))
	if got, err := ExportDomainSets(sites, map[string][]string{"business.txt": {"geosite:ai"}}); got != nil || err == nil {
		t.Fatalf("GEO-derived comment delimiter accepted: %v %v", got, err)
	}
	got, err := ExportDomainSets(sites, map[string][]string{"business.txt": {"geosite:ai@safe"}})
	if err != nil || string(got.Files["business.txt"]) != "full:safe.example\n" {
		t.Fatalf("unselected native GEO matcher affected safe domain set: %v %v", got, err)
	}
}
