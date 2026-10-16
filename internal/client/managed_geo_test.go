package client

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

var testManagedGeoIP = "home_geoip_" + strings.Repeat("a", 64) + ".dat"
var testManagedGeoSite = "home_geosite_" + strings.Repeat("b", 64) + ".dat"

func TestBindNativeGeoAssetsPreservesNativePolicyAndIdentities(t *testing.T) {
	input := []byte(`{
 "name":"provider metadata",
 "routing":{"domainStrategy":"IPIfNonMatch","rules":[
  {"domain":["geosite:openai@api","domain:manual.example","regexp:^api\\."],"ip":["geoip:!cn","!geoip:private","192.0.2.0/24"],"network":"tcp","port":"443","outboundTag":"usa-ai"},
  {"domain":"geosite:cn","outboundTag":"direct"},
  {"network":"tcp,udp","outboundTag":"direct"}]},
 "dns":{"tag":"mobile-dns","servers":[{"address":"tcp://1.1.1.1:53","tag":"dns-ai","domains":["geosite:openai@api","domain:manual.example"],"finalQuery":true,"skipFallback":true},"223.5.5.5"]},
 "policy":{"levels":{"0":{"bufferSize":9007199254740993}}},
 "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"usa-ai","protocol":"vless","settings":{"vnext":[{"address":"node.example.invalid","port":443,"users":[{"id":"SYNTHETIC-CLIENT-ID","encryption":"none"}]}]},"streamSettings":{"realitySettings":{"publicKey":"geosite:credential-text-is-not-a-rule"},"sockopt":{"dialerProxy":"home_out"}}},{"tag":"home_out","protocol":"socks","settings":{"servers":[{"address":"home.example.invalid","port":1080,"users":[{"user":"ext:credential.dat:value","pass":"geoip:credential-text"}]}]}}]
}`)
	before := append([]byte(nil), input...)
	bound, err := BindNativeGeoAssets(input, testManagedGeoIP, testManagedGeoSite)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, before) {
		t.Fatal("binding mutated the source")
	}
	original, output := decodeObject(t, before), decodeObject(t, bound)
	for _, field := range []string{"outbounds", "policy", "name"} {
		assertJSONEqual(t, original[field], output[field])
	}
	if !bytes.Contains(bound, []byte("9007199254740993")) {
		t.Fatal("large numeric policy value changed")
	}
	want := strings.ReplaceAll(string(before), `"geosite:openai@api"`, `"ext:`+testManagedGeoSite+`:openai@api"`)
	want = strings.ReplaceAll(want, `"geosite:cn"`, `"ext:`+testManagedGeoSite+`:cn"`)
	want = strings.ReplaceAll(want, `"geoip:!cn"`, `"ext:`+testManagedGeoIP+`:!cn"`)
	want = strings.ReplaceAll(want, `"!geoip:private"`, `"!ext:`+testManagedGeoIP+`:private"`)
	assertJSONEqual(t, bound, []byte(want))
	again, err := BindNativeGeoAssets(bound, testManagedGeoIP, testManagedGeoSite)
	if err != nil || !bytes.Equal(bound, again) {
		t.Fatalf("managed asset binding is not idempotent: %v", err)
	}
}

func TestBindNativeGeoAssetsRequiresContentAddressedNames(t *testing.T) {
	for _, names := range [][2]string{
		{"geoip.dat", testManagedGeoSite},
		{testManagedGeoIP, "geosite.dat"},
		{"home_geoip_short.dat", testManagedGeoSite},
		{testManagedGeoIP, "home_geosite_" + strings.Repeat("B", 64) + ".dat"},
		{"../" + testManagedGeoIP, testManagedGeoSite},
		{testManagedGeoIP, testManagedGeoSite + ":cn"},
		{testManagedGeoSite, testManagedGeoIP},
	} {
		if _, err := BindNativeGeoAssets([]byte(`{}`), names[0], names[1]); err == nil {
			t.Fatal("accepted a non-content-addressed or unsafe filename")
		}
	}
}

func TestBindNativeGeoAssetsRejectsUnknownOrWrongTypedReferences(t *testing.T) {
	for _, rule := range []string{
		`{"domain":["ext:other.dat:cn"]}`,
		`{"domain":["ext:geosite.dat:cn"]}`,
		`{"domain":["ext-domain:other.dat:cn"]}`,
		`{"domain":["geoip:cn"]}`,
		`{"ip":["geosite:cn"]}`,
		`{"ip":["!ext:other.dat:cn"]}`,
		`{"domain":["ext:` + testManagedGeoIP + `:cn"]}`,
		`{"ip":["ext:` + testManagedGeoSite + `:cn"]}`,
		`{"domain":["geosite:"]}`,
		`{"domain":["geosite:cn@@api"]}`,
		`{"ip":["geoip:!"]}`,
		`{"ip":["geoip:cn@api"]}`,
		`{"domain":[3]}`,
	} {
		input := []byte(`{"routing":{"rules":[` + rule + `]}}`)
		if _, err := BindNativeGeoAssets(input, testManagedGeoIP, testManagedGeoSite); err == nil {
			t.Fatalf("unsupported reference accepted: %s", rule)
		}
	}
	for _, input := range []string{`null`, `{`, `{"routing":{"rules":[],"rules":[]}}`} {
		if _, err := BindNativeGeoAssets([]byte(input), testManagedGeoIP, testManagedGeoSite); err == nil {
			t.Fatal("invalid or ambiguous source JSON accepted")
		}
	}
}

func TestBindNativeGeoAssetsRejectsKnownReferencesOutsideAllowedPaths(t *testing.T) {
	for _, input := range []string{
		`{"routing":{"rules":[{"sourceIP":["geoip:cn"]}]}}`,
		`{"routing":{"rules":[{"localIP":["ext:other.dat:cn"]}]}}`,
		`{"routing":{"rules":[{"source":"geoip:private"}]}}`,
		`{"dns":{"hosts":{"geosite:cn":"192.0.2.1"}}}`,
		`{"dns":{"servers":[{"address":"1.1.1.1","expectedIPs":["geoip:cn"]}]}}`,
		`{"dns":{"servers":[{"address":"1.1.1.1","expectIPs":["geoip:cn"]}]}}`,
		`{"dns":{"servers":[{"address":"1.1.1.1","unexpectedIPs":["geoip:private"]}]}}`,
		`{"inbounds":[{"sniffing":{"domainsExcluded":["geosite:cn"]}}]}`,
		`{"inbounds":[{"sniffing":{"ipsExcluded":["geoip:cn"]}}]}`,
		`{"outbounds":[{"protocol":"dns","settings":{"rules":[{"domain":["geosite:openai"],"action":"return"}]}}]}`,
	} {
		if _, err := BindNativeGeoAssets([]byte(input), testManagedGeoIP, testManagedGeoSite); err == nil {
			t.Fatalf("left known GEO-bearing field partly bound: %s", input)
		}
	}
}

func TestBindNativeGeoAssetsLeavesNonGEOFieldsAndShapeAlone(t *testing.T) {
	input := []byte(`{"note":"ext:unrelated.dat:metadata","routing":{"rules":[{"domain":null,"ip":[],"sourceIP":["192.0.2.0/24"],"outboundTag":"direct"}]},"dns":{"hosts":{"host.example":"192.0.2.1"},"servers":[{"address":"223.5.5.5","domains":[],"expectedIPs":["192.0.2.0/24"]}]},"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	output, err := BindNativeGeoAssets(input, testManagedGeoIP, testManagedGeoSite)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, input, output)
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestBindNativeGeoAssetsReportsOnlyTypedPolicyReferences(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		want      map[string]string
	}{
		{"domain only", `{"routing":{"rules":[{"domain":["geosite:cn","geosite:cn"]}]}}`, map[string]string{testManagedGeoSite: "domain"}},
		{"DNS only", `{"dns":{"servers":[{"address":"1.1.1.1","domains":["geosite:cn"]}]}}`, map[string]string{testManagedGeoSite: "domain"}},
		{"IP only", `{"routing":{"rules":[{"ip":["geoip:!cn","!geoip:private"]}]}}`, map[string]string{testManagedGeoIP: "ip"}},
		{"both", `{"routing":{"rules":[{"domain":["geosite:cn"],"ip":["geoip:cn"]}]}}`, map[string]string{testManagedGeoIP: "ip", testManagedGeoSite: "domain"}},
		{"none", `{"routing":{"rules":[{"domain":["domain:cn.example"],"ip":[]}]}}`, map[string]string{}},
		{"credentials excluded", `{"outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"node.example","users":[{"pass":"ext:` + testManagedGeoIP + `:cn"}]}]}}]}`, map[string]string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			bound, refs, err := BindNativeGeoAssetsWithReferences([]byte(test.raw), testManagedGeoIP, testManagedGeoSite)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(refs)
			want, _ := json.Marshal(test.want)
			if !bytes.Equal(got, want) {
				t.Fatalf("wrong actual dependencies: %s != %s", got, want)
			}
			basic, err := BindNativeGeoAssets([]byte(test.raw), testManagedGeoIP, testManagedGeoSite)
			if err != nil || !bytes.Equal(bound, basic) {
				t.Fatal("reference reporting changed native policy encoding")
			}
			_, again, err := BindNativeGeoAssetsWithReferences(bound, testManagedGeoIP, testManagedGeoSite)
			reencoded, _ := json.Marshal(again)
			if err != nil || !bytes.Equal(got, reencoded) {
				t.Fatal("already-bound references changed dependencies")
			}
		})
	}
}
