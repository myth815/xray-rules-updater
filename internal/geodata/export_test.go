package geodata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestExportBoundedCountsEveryOutputAndDeduplicates(t *testing.T) {
	sites := category("cn", domainMessage(2, "example.org"), domainMessage(2, "example.org"))
	ips := category("cn", cidrMessage("1.2.0.0/25"), cidrMessage("1.2.0.128/25"))
	selectedSites := map[string]string{"a.txt": "cn", "b.txt": "cn"}
	selectedIPs := map[string]string{"ip.txt": "cn"}
	want, err := Export(ips, sites, selectedSites, selectedIPs, "CandidateCN")
	if err != nil {
		t.Fatal(err)
	}
	var total, largest int64
	for _, body := range want.Files {
		n := int64(len(body))
		total += n
		if n > largest {
			largest = n
		}
	}
	got, err := ExportBounded(ips, sites, selectedSites, selectedIPs, "CandidateCN", largest, total)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("exact byte budget changed output or charged duplicates: %v %v", got, err)
	}
	for _, limits := range [][2]int64{{largest - 1, total}, {largest, total - 1}} {
		got, err := ExportBounded(ips, sites, selectedSites, selectedIPs, "CandidateCN", limits[0], limits[1])
		if got != nil || !errors.Is(err, ErrExportLimit) {
			t.Fatalf("per-file/aggregate budget not enforced across MosDNS and RouterOS: %v %v", got, err)
		}
	}
}

func TestExportBoundedRefusesOrdinaryExportAmplification(t *testing.T) {
	var domains [][]byte
	for i := 0; i < 2000; i++ {
		domains = append(domains, domainMessage(2, fmt.Sprintf("%s%08d.example", strings.Repeat("a", 50), i)))
	}
	sites := category("cn", domains...)
	selected := map[string]string{}
	for i := 0; i < 32; i++ {
		selected[fmt.Sprintf("cn-%02d.txt", i)] = "cn"
	}
	if got, err := ExportBounded(nil, sites, selected, nil, "", 256<<10, 1<<20); got != nil || !errors.Is(err, ErrExportLimit) {
		t.Fatalf("amplified ordinary exports escaped the aggregate limit: %v %v", got, err)
	}
}

func TestMosDNSExportRejectsCommentDelimiterWithoutChangingNativeDAT(t *testing.T) {
	for kind := uint64(0); kind <= 3; kind++ {
		for _, value := range []string{"api#tail.example", `^api\#tail\.example$`, `^api[#]tail\.example$`} {
			t.Run(fmt.Sprintf("kind-%d-%s", kind, value), func(t *testing.T) {
				data := category("cn", domainMessage(kind, value), domainMessage(2, "safe.example", boolAttr("safe", true)))
				original := append([]byte(nil), data...)
				if err := ValidateReferences(nil, data, []string{"geosite:cn"}); err != nil {
					t.Fatal("native GEO reference was incorrectly rejected", err)
				}
				if got, err := Export(nil, data, map[string]string{"cn.txt": "cn"}, nil, ""); err == nil || got != nil {
					t.Fatalf("MosDNS would truncate a selected matcher: %v %v", got, err)
				}
				got, err := Export(nil, data, map[string]string{"safe.txt": "cn@safe"}, nil, "")
				if err != nil || string(got.Files["safe.txt"]) != "domain:safe.example\n" {
					t.Fatalf("unselected native matcher affected a safe export: %v %v", got, err)
				}
				if !bytes.Equal(original, data) {
					t.Fatal("native DAT was rewritten")
				}
			})
		}
	}
}

func varField(number, value uint64) []byte {
	b := binary.AppendUvarint(nil, number<<3)
	return binary.AppendUvarint(b, value)
}

func bytesField(number uint64, value []byte) []byte {
	b := binary.AppendUvarint(nil, number<<3|2)
	b = binary.AppendUvarint(b, uint64(len(value)))
	return append(b, value...)
}

func join(fields ...[]byte) []byte { return bytes.Join(fields, nil) }

func boolAttr(key string, value bool) []byte {
	n := uint64(0)
	if value {
		n = 1
	}
	return join(bytesField(1, []byte(key)), varField(2, n))
}

func intAttr(key string, value int64) []byte {
	return join(bytesField(1, []byte(key)), varField(3, uint64(value)))
}

func domainMessage(kind uint64, value string, attrs ...[]byte) []byte {
	b := join(varField(1, kind), bytesField(2, []byte(value)))
	for _, attr := range attrs {
		b = append(b, bytesField(3, attr)...)
	}
	return b
}

func category(code string, items ...[]byte) []byte {
	b := bytesField(1, []byte(code))
	for _, item := range items {
		b = append(b, bytesField(2, item)...)
	}
	return bytesField(1, b)
}

func cidrMessage(value string) []byte {
	p := netip.MustParsePrefix(value)
	return join(bytesField(1, p.Addr().AsSlice()), varField(2, uint64(p.Bits())))
}

func TestExportDomainKindsAndAttributes(t *testing.T) {
	sites := join(category("CN",
		domainMessage(0, "plain-key", boolAttr("ads", false)),
		domainMessage(1, `^regex\.example$`, intAttr("ads", 0), boolAttr("mobile", true)),
		domainMessage(2, "suffix.example", intAttr("score", -3)),
		domainMessage(3, "exact.example", boolAttr("ads", true), intAttr("mobile", 42)),
		domainMessage(2, "suffix.example", intAttr("score", -3))),
		category("geolocation-!cn", domainMessage(2, "overseas.example")))
	r, err := Export(nil, sites, map[string]string{
		"all.txt": "CN", "ads.txt": "cn@ADS", "both.txt": "cn@ads@mobile", "absent.txt": "cn@missing", "foreign.txt": "geolocation-!cn",
	}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"all.txt":  "domain:suffix.example\nfull:exact.example\nkeyword:plain-key\nregexp:^regex\\.example$\n",
		"ads.txt":  "full:exact.example\nkeyword:plain-key\nregexp:^regex\\.example$\n",
		"both.txt": "full:exact.example\nregexp:^regex\\.example$\n", "absent.txt": "",
		"foreign.txt": "domain:overseas.example\n",
	}
	for filename, text := range want {
		if string(r.Files[filename]) != text {
			t.Errorf("%s = %q, want %q", filename, r.Files[filename], text)
		}
	}
	if r.Counts["all.txt"] != 4 || r.Counts["ads.txt"] != 3 || r.Counts["both.txt"] != 2 || r.Counts["absent.txt"] != 0 {
		t.Fatalf("counts: %v", r.Counts)
	}
	// The typed values are retained while filtering uses key presence, exactly
	// like the fixed Xray version; false/zero/negative are not discarded.
	d, err := readDomain(domainMessage(2, "example.org", boolAttr("a", false), intAttr("b", -3)))
	if err != nil || len(d.attrs) != 2 || d.attrs[0].boolValue || d.attrs[1].intValue != -3 {
		t.Fatalf("attribute typed values lost: %+v, %v", d.attrs, err)
	}
}

func TestExportIPCanonicalAndCandidateOnly(t *testing.T) {
	data := category("CN", cidrMessage("1.2.0.0/25"), cidrMessage("1.2.0.128/25"),
		cidrMessage("1.2.0.64/26"), cidrMessage("1.2.0.0/25"), cidrMessage("1.2.1.0/24"),
		cidrMessage("2001:db8::/33"), cidrMessage("2001:db8:8000::/33"),
		cidrMessage("2001:db8::/48"), cidrMessage("2001:db9::/32"))
	r, err := Export(data, nil, nil, map[string]string{"mosdns/cn.txt": "cn"}, "CandidateCN_20261016")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(r.Files["mosdns/cn.txt"]), "1.2.0.0/23\n2001:db8::/31\n"; got != want {
		t.Fatalf("IP text %q, want %q", got, want)
	}
	if r.Counts["mosdns/cn.txt"] != 2 || r.Counts["routeros-cn-v4.rsc"] != 1 {
		t.Fatal(r.Counts)
	}
	rsc := string(r.Files["routeros-cn-v4.rsc"])
	if !strings.Contains(rsc, "add list=CandidateCN_20261016 address=1.2.0.0/23 ") || strings.Contains(rsc, "2001:") {
		t.Fatal(rsc)
	}
	for _, forbidden := range []string{"remove", "disable", "enable=", "mangle", "routing", "socksify", "set ", "filter", "FastTrack"} {
		for _, line := range strings.Split(rsc, "\n") {
			if !strings.HasPrefix(line, "#") && strings.Contains(line, forbidden) {
				t.Errorf("candidate script contains operation %q: %s", forbidden, line)
			}
		}
	}
}

func TestCanonicalExactCoverage(t *testing.T) {
	// Exhaust all addresses within a small region, including holes. Verify
	// canonicalization by independent membership comparisons, not only text.
	input := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/28"), netip.MustParsePrefix("10.0.0.16/28"),
		netip.MustParsePrefix("10.0.0.48/29"), netip.MustParsePrefix("10.0.0.48/30"),
		netip.MustParsePrefix("10.0.0.64/26"), netip.MustParsePrefix("10.0.0.128/27"),
		netip.MustParsePrefix("2001:db8::/125"), netip.MustParsePrefix("2001:db8::8/125"),
		netip.MustParsePrefix("2001:db8::20/127"),
	}
	out := canonicalPrefixes(input)
	contains := func(ps []netip.Prefix, addr netip.Addr) bool {
		for _, p := range ps {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, start := range []string{"10.0.0.0", "2001:db8::"} {
		addr := netip.MustParseAddr(start)
		for i := 0; i < 256; i++ {
			if contains(input, addr) != contains(out, addr) {
				t.Fatalf("coverage changed at %s: %v -> %v", addr, input, out)
			}
			addr = addr.Next()
		}
	}
	if !reflect.DeepEqual(canonicalPrefixes(out), out) {
		t.Fatal("canonicalization is not idempotent")
	}
	for i, a := range out {
		for j, b := range out {
			if i != j && covers(a, b) {
				t.Fatalf("covered prefix retained: %s covers %s", a, b)
			}
		}
	}
}

func TestMalformedDataRejected(t *testing.T) {
	validSite := category("cn", domainMessage(2, "example.org"))
	validIP := category("cn", cidrMessage("1.2.0.0/16"))
	reverse := bytesField(1, join(bytesField(1, []byte("cn")), bytesField(2, cidrMessage("1.2.0.0/16")), varField(3, 1)))
	cases := []struct {
		name string
		ip   []byte
		site []byte
	}{
		{"truncated key", validIP, []byte{0x80}},
		{"varint overflow", validIP, bytes.Repeat([]byte{0xff}, 11)},
		{"zero field", validIP, []byte{0}},
		{"unknown wire", validIP, []byte{0x0b}},
		{"truncated length", validIP, []byte{0x0a, 0x80}},
		{"truncated payload", validIP, []byte{0x0a, 2, 0}},
		{"truncated fixed64", validIP, []byte{0x09, 0}},
		{"truncated fixed32", validIP, []byte{0x0d, 0}},
		{"wrong envelope wire", validIP, varField(1, 2)},
		{"missing category", validIP, category("us", domainMessage(2, "example.org"))},
		{"duplicate category", validIP, join(validSite, validSite)},
		{"invalid domain enum", validIP, category("cn", domainMessage(4, "example.org"))},
		{"invalid regexp", validIP, category("cn", domainMessage(1, "["))},
		{"newline injection", validIP, category("cn", domainMessage(2, "example.org\nfull:evil.org"))},
		{"attribute truncated", validIP, category("cn", domainMessage(2, "example.org", []byte{0x0a, 9, 0}))},
		{"attribute missing key", validIP, category("cn", domainMessage(2, "example.org", varField(2, 1)))},
		{"attribute ambiguous oneof", validIP, category("cn", domainMessage(2, "example.org", join(boolAttr("a", true), varField(3, 4))))},
		{"CIDR prefix overflow", category("cn", join(bytesField(1, []byte{1, 2, 0, 0}), varField(2, 33))), validSite},
		{"CIDR invalid bytes", category("cn", join(bytesField(1, []byte{1, 2, 0}), varField(2, 8))), validSite},
		{"CIDR host bits", category("cn", join(bytesField(1, []byte{1, 2, 0, 1}), varField(2, 16))), validSite},
		{"CIDR wrong wire", category("cn", varField(1, 7)), validSite},
		{"CIDR reverse", reverse, validSite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Export(tc.ip, tc.site, map[string]string{"sites.txt": "cn"}, map[string]string{"ips.txt": "cn"}, "")
			if err == nil || r != nil {
				t.Fatalf("accepted malformed input: result=%v error=%v", r, err)
			}
		})
	}
}

func TestUnknownValidFieldsAndProtoDefaults(t *testing.T) {
	// Plain type and prefix /0 may be omitted under proto3 defaults. Unknown
	// fields of supported wire types must not change the interpreted data.
	unknown := join(varField(20, 7), bytesField(21, []byte("extra")), []byte{0xb1, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}, []byte{0xbd, 0x01, 0, 0, 0, 0})
	sites := join(category("cn", join(bytesField(2, []byte("plain")), unknown)), unknown)
	ips := category("private", bytesField(1, []byte{0, 0, 0, 0}))
	r, err := Export(ips, sites, map[string]string{"s.txt": "cn"}, map[string]string{"i.txt": "private"}, "")
	if err != nil || string(r.Files["s.txt"]) != "keyword:plain\n" || string(r.Files["i.txt"]) != "0.0.0.0/0\n" {
		t.Fatalf("defaults/unknowns: %v %v", r, err)
	}
}

func TestSelectorsFilenamesAndRouterGuards(t *testing.T) {
	sites := category("cn", domainMessage(2, "example.org"))
	ips := category("cn", cidrMessage("1.2.0.0/16"))
	for _, value := range []string{"", "!cn", "cn@", "cn@!ads", "cn@ads=true", "cn:ads", "cn@x y"} {
		t.Run("selector-"+value, func(t *testing.T) {
			if _, err := Export(ips, sites, map[string]string{"s.txt": value}, nil, ""); err == nil {
				t.Fatalf("accepted unsupported selector %q", value)
			}
		})
	}
	for _, filename := range []string{"", ".", "..", "../escape", "/absolute", "a/../b", "a\\b", "a\nfile"} {
		if _, err := Export(ips, sites, map[string]string{filename: "cn"}, nil, ""); err == nil {
			t.Errorf("accepted filename %q", filename)
		}
	}
	if _, err := Export(ips, sites, map[string]string{"same.txt": "cn"}, map[string]string{"same.txt": "cn"}, ""); err == nil {
		t.Fatal("duplicate output accepted")
	}
	for _, list := range []string{"a;remove", "a b", "a\"", strings.Repeat("x", 65)} {
		if _, err := Export(ips, sites, nil, nil, list); err == nil {
			t.Errorf("accepted list %q", list)
		}
	}
	for _, badCN := range [][]byte{category("cn"), category("cn", cidrMessage("2001:db8::/32")), category("cn", cidrMessage("2.0.0.0/7")), category("cn", cidrMessage("2.0.0.0/8"), cidrMessage("3.0.0.0/8"))} {
		if _, err := Export(badCN, nil, nil, nil, "CandidateCN"); err == nil {
			t.Fatal("empty or overly broad CN candidate accepted")
		}
	}
	if _, err := Export(ips, nil, nil, map[string]string{"ip.txt": "cn@ads"}, ""); err == nil {
		t.Fatal("GeoIP attribute selector accepted")
	}
}

func FuzzCanonicalCoverage(f *testing.F) {
	f.Add([]byte{0, 8, 16, 24, 64, 128, 160, 248})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 256 {
			input = input[:256]
		}
		var prefixes []netip.Prefix
		want := [256]bool{}
		for _, n := range input {
			prefixes = append(prefixes, netip.MustParsePrefix(fmt.Sprintf("10.0.0.%d/32", n)))
			want[n] = true
		}
		out := canonicalPrefixes(prefixes)
		for n := range want {
			addr := netip.AddrFrom4([4]byte{10, 0, 0, byte(n)})
			got := false
			for _, p := range out {
				got = got || p.Contains(addr)
			}
			if got != want[n] {
				t.Fatalf("coverage changed at %s", addr)
			}
		}
	})
}
