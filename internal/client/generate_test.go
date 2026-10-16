package client

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const baselineFixture = `{
  "log":{"access":"/router/access.log","error":"/router/error.log"},
  "inbounds":[{"tag":"server","protocol":"vless","settings":{"clients":[{"id":"SERVER-ONLY-ID"}]},"streamSettings":{"realitySettings":{"privateKey":"SERVER-ONLY-KEY"}}}],
  "api":{"tag":"server-api"},"stats":{},"metrics":{},"transport":{},
  "dns":{"servers":["https://1.1.1.1/dns-query"],"queryStrategy":"UseIPv4"},
  "policy":{"levels":{"0":{"handshake":4}},"system":{"statsOutboundUplink":false}},
  "routing":{"domainStrategy":"IPIfNonMatch","domainMatcher":"hybrid","rules":[
    {"type":"field","inboundTag":["server"],"outboundTag":"unused"},
    {"domain":["geosite:openai@api","regexp:^api\\."],"network":"tcp","port":"443","outboundTag":"usa"},
    {"ip":["geoip:!cn"],"outboundTag":"usa"},
    {"network":"tcp,udp","outboundTag":"direct"}
  ]},
  "outbounds":[
    {"tag":"direct","protocol":"freedom","sendThrough":"0.0.0.0","settings":{}},
    {"tag":"block","protocol":"blackhole","settings":{}},
    {"tag":"usa","protocol":"socks","settings":{"servers":[{"address":"192.0.2.10","port":1080,"users":[{"user":"SYNTHETIC-USER","pass":"SYNTHETIC-PASS"}]}]},"proxySettings":{"tag":"hop","transportLayer":true}},
    {"tag":"hop","protocol":"vless","settings":{"vnext":[{"address":"relay.example","port":443,"users":[{"id":"SYNTHETIC-ID","encryption":"none"}]}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/socket?ed=2048"},"sockopt":{"dialerProxy":"node","mark":0,"interface":""}}},
    {"tag":"node","protocol":"wireguard","settings":{"secretKey":"SYNTHETIC-CLIENT-KEY","address":["192.0.2.2/32"],"peers":[{"publicKey":"SYNTHETIC-PUBLIC-KEY","endpoint":"vpn.example:51820"}]}},
    {"tag":"unused","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}
  ]
}`

func TestGeneratePreservesNativePolicyAndChain(t *testing.T) {
	baseline := []byte(baselineFixture)
	before := append([]byte(nil), baseline...)
	home := json.RawMessage(`{"ip":["10.20.30.0/24"],"outboundTag":"node","ruleTag":"home-first"}`)
	result, err := Generate(baseline, Overlay{
		Name: "phone", KeepOutbounds: []string{"direct", "block", "usa"},
		DropInboundRules: true, PrependRules: []json.RawMessage{home},
	}, "20261016-test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseline, before) {
		t.Fatal("Generate mutated baseline bytes")
	}
	output := decodeObject(t, result)
	if got := sortedKeys(output); !reflect.DeepEqual(got, []string{"dns", "outbounds", "policy", "routing"}) {
		t.Fatalf("output top-level fields: %v", got)
	}
	if bytes.Contains(result, []byte("SERVER-ONLY")) || bytes.Contains(result, []byte("20261016-test")) || bytes.Contains(result, []byte(`"name"`)) {
		t.Fatal("output contains platform secrets or app-owned metadata")
	}
	wantOuts := decodeArray(t, decodeObject(t, before)["outbounds"])
	wantOuts = wantOuts[:5]
	assertJSONEqual(t, output["outbounds"], marshal(t, wantOuts))
	if !bytes.Contains(result, []byte("SYNTHETIC-CLIENT-KEY")) {
		t.Fatal("client-owned WireGuard identity was lost")
	}
	routing := decodeObject(t, output["routing"])
	if string(routing["domainStrategy"]) != `"IPIfNonMatch"` {
		t.Fatal("routing strategy changed")
	}
	originalRules := decodeArray(t, decodeObject(t, decodeObject(t, before)["routing"])["rules"])
	wantRules := append([]json.RawMessage{home}, originalRules[1:]...)
	assertJSONEqual(t, routing["rules"], marshal(t, wantRules))
	assertJSONEqual(t, output["policy"], decodeObject(t, before)["policy"])
	assertJSONEqual(t, output["dns"], decodeObject(t, before)["dns"])
	second, err := Generate(baseline, Overlay{Name: "different-manifest-name", KeepOutbounds: []string{"usa", "block", "direct"}, DropInboundRules: true, PrependRules: []json.RawMessage{home}}, "different-version")
	if err != nil || !bytes.Equal(result, second) {
		t.Fatal("output is not deterministic or selection reordered the baseline")
	}
}

func TestGenerateKeepAllAndPreserveInboundRules(t *testing.T) {
	result, err := Generate([]byte(baselineFixture), Overlay{}, "")
	if err != nil {
		t.Fatal(err)
	}
	original := decodeObject(t, []byte(baselineFixture))
	output := decodeObject(t, result)
	assertJSONEqual(t, output["outbounds"], original["outbounds"])
	assertJSONEqual(t, output["routing"], original["routing"])
}

func TestGenerateDNSOverlayAndExplicitPrepend(t *testing.T) {
	dns := json.RawMessage(`{"servers":[{"address":"https://8.8.8.8/dns-query","domains":["geosite:geolocation-!cn"],"expectedIPs":["geoip:!cn"],"tag":"client-dns"}],"queryStrategy":"UseIPv4"}`)
	prepended := json.RawMessage(`{"inboundTag":["client-dns"],"domain":["full:dns.example"],"outboundTag":"usa"}`)
	result, err := Generate([]byte(baselineFixture), Overlay{DNS: dns, DropInboundRules: true, PrependRules: []json.RawMessage{prepended}}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	output := decodeObject(t, result)
	assertJSONEqual(t, output["dns"], dns)
	rules := decodeArray(t, decodeObject(t, output["routing"])["rules"])
	assertJSONEqual(t, rules[0], prepended)
}

func TestGenerateExtraHomeOutboundsAndRules(t *testing.T) {
	baseline := []byte(baselineFixture)
	before := append([]byte(nil), baseline...)
	extras := []json.RawMessage{
		json.RawMessage(`{"tag":"home_out","protocol":"wireguard","settings":{"secretKey":"SYNTHETIC-HOME-CLIENT-KEY","address":["192.0.2.2/32"],"peers":[{"publicKey":"SYNTHETIC-HOME-PUBLIC-KEY","endpoint":"vpn.home.example:51820"}]},"streamSettings":{"sockopt":{"dialerProxy":"home_transport"}}}`),
		json.RawMessage(`{"tag":"home_transport","protocol":"socks","settings":{"servers":[{"address":"192.0.2.20","port":1080}]}}`),
	}
	prepended := []json.RawMessage{
		json.RawMessage(`{"domain":["domain:home.example"],"outboundTag":"home_out"}`),
		json.RawMessage(`{"ip":["10.20.30.0/24"],"outboundTag":"home_out"}`),
		json.RawMessage(`{"ip":["geoip:private"],"outboundTag":"direct"}`),
	}
	overlay := Overlay{
		KeepOutbounds:  []string{"direct", "block", "usa", "home_out"},
		ExtraOutbounds: extras, DropInboundRules: true, PrependRules: prepended,
	}
	overlayBefore := marshal(t, overlay)
	result, err := Generate(baseline, overlay, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, baseline) || !bytes.Equal(overlayBefore, marshal(t, overlay)) {
		t.Fatal("Generate mutated its inputs")
	}
	output := decodeObject(t, result)
	originalOutbounds := decodeArray(t, decodeObject(t, before)["outbounds"])
	wantOutbounds := append(originalOutbounds[:5:5], extras...)
	assertJSONEqual(t, output["outbounds"], marshal(t, wantOutbounds))
	originalRules := decodeArray(t, decodeObject(t, decodeObject(t, before)["routing"])["rules"])
	wantRules := append(append([]json.RawMessage(nil), prepended...), originalRules[1:]...)
	assertJSONEqual(t, decodeObject(t, output["routing"])["rules"], marshal(t, wantRules))
}

func TestGenerateExtraOutboundsWithoutSelection(t *testing.T) {
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	extra := json.RawMessage(`{"tag":"home_out","protocol":"socks","settings":{"servers":[{"address":"192.0.2.20","port":1080}]}}`)
	result, err := Generate(baseline, Overlay{ExtraOutbounds: []json.RawMessage{extra}}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	want := append(decodeArray(t, decodeObject(t, baseline)["outbounds"]), extra)
	assertJSONEqual(t, decodeObject(t, result)["outbounds"], marshal(t, want))
	withoutExtras, err := Generate(baseline, Overlay{ExtraOutbounds: []json.RawMessage{}}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	original, err := Generate(baseline, Overlay{}, "v1")
	if err != nil || !bytes.Equal(withoutExtras, original) {
		t.Fatal("empty extra_outbounds changed previous output")
	}
}

func TestGenerateExplicitSockoptOmissionsPreserveIdentityAndChain(t *testing.T) {
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"192.0.2.2","port":1080,"users":[{"user":"SYNTHETIC-USER","pass":"SYNTHETIC-PASSWORD"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"proxy.example.invalid"},"sockopt":{"mark":66,"interface":"router-only","tcpNoDelay":true,"dialerProxy":"hop","domainStrategy":"UseIPv4"}}},{"tag":"hop","protocol":"freedom"}]}`)
	before := append([]byte(nil), baseline...)
	if _, err := Generate(baseline, Overlay{}, "v1"); err == nil {
		t.Fatal("default overlay accepted host-specific binding")
	}
	overlay := Overlay{KeepOutbounds: []string{"direct", "proxy"}, OutboundSockoptOmissions: map[string][]string{"proxy": {"mark", "interface", "tcpNoDelay"}}}
	result, err := Generate(baseline, overlay, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, baseline) {
		t.Fatal("authoritative baseline was mutated")
	}
	original := decodeArray(t, decodeObject(t, baseline)["outbounds"])
	actual := decodeArray(t, decodeObject(t, result)["outbounds"])
	if len(actual) != 3 {
		t.Fatal("required dialerProxy dependency was lost")
	}
	assertJSONEqual(t, actual[0], original[0])
	assertJSONEqual(t, actual[2], original[2])
	wantProxy := decodeObject(t, original[1])
	stream := decodeObject(t, wantProxy["streamSettings"])
	stream["sockopt"] = json.RawMessage(`{"dialerProxy":"hop","domainStrategy":"UseIPv4"}`)
	wantProxy["streamSettings"] = marshal(t, stream)
	assertJSONEqual(t, actual[1], marshal(t, wantProxy))
	// Explicitly absent platform fields are an idempotent omission, while
	// removing the chain or resolution strategy remains forbidden.
	second, err := Generate(result, overlay, "v1")
	if err != nil || !bytes.Equal(second, result) {
		t.Fatal("explicit client omissions were not idempotent")
	}
}

func TestGenerateSockoptOmissionsFailClosed(t *testing.T) {
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"socks","streamSettings":{"sockopt":{"mark":66,"interface":"router-only","dialerProxy":"direct"}}}]}`)
	tests := []struct {
		name     string
		omit     map[string][]string
		contains string
	}{
		{"chain cannot be removed", map[string][]string{"proxy": {"dialerProxy"}}, "not an approved"},
		{"DNS semantics cannot be removed", map[string][]string{"proxy": {"domainStrategy"}}, "not an approved"},
		{"unknown field", map[string][]string{"proxy": {"futureField"}}, "not an approved"},
		{"unknown tag", map[string][]string{"missing": {"mark"}}, "specified outbound tag not found"},
		{"wildcard tag", map[string][]string{"*": {"mark"}}, "specified outbound tag not found"},
		{"empty tag", map[string][]string{"": {"mark"}}, "exact tag"},
		{"empty list", map[string][]string{"proxy": {}}, "nonempty field list"},
		{"duplicate field", map[string][]string{"proxy": {"mark", "mark"}}, "duplicate field"},
		{"remaining binding", map[string][]string{"proxy": {"mark"}}, "interface binding"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Generate(baseline, Overlay{OutboundSockoptOmissions: tc.omit}, "v1")
			if err == nil || result != nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("Generate rejection = %v; want %q", err, tc.contains)
			}
		})
	}
}

func TestGenerateExplicitLegacyAdMigrationPreservesOtherRules(t *testing.T) {
	baseline := []byte(`{"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","domain":["geosite:category-ads-all"],"outboundTag":"block","ruleTag":"legacy-ad"},{"domain":["geosite:openai"],"network":"tcp","port":"443","outboundTag":"direct"},{"network":"tcp,udp","outboundTag":"direct"}]},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}`)
	original := append([]byte(nil), baseline...)
	unchanged, err := Generate(baseline, Overlay{}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, unchanged, baseline)
	home := json.RawMessage(`{"ip":["10.20.30.15"],"port":"8096","outboundTag":"direct"}`)
	result, err := Generate(baseline, Overlay{DropLegacyAdRule: true, PrependRules: []json.RawMessage{home}}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, baseline) {
		t.Fatal("legacy migration changed authoritative baseline")
	}
	want := decodeArray(t, decodeObject(t, decodeObject(t, baseline)["routing"])["rules"])
	want = append([]json.RawMessage{home}, want[1:]...)
	assertJSONEqual(t, decodeObject(t, decodeObject(t, result)["routing"])["rules"], marshal(t, want))
}

func TestGenerateLegacyAdMigrationRejectsDrift(t *testing.T) {
	known := `{"domain":["geosite:category-ads-all"],"outboundTag":"block"}`
	tests := []struct{ name, rules string }{
		{"missing", `[{"network":"tcp,udp","outboundTag":"direct"}]`},
		{"duplicate", `[` + known + `,` + known + `]`},
		{"additional domains", `[{"domain":["geosite:category-ads-all","geosite:cn"],"outboundTag":"block"}]`},
		{"additional AND condition", `[{"domain":["geosite:category-ads-all"],"network":"tcp","outboundTag":"block"}]`},
		{"side effect", `[{"domain":["geosite:category-ads-all"],"outboundTag":"block","webhook":{"url":"https://example.invalid/hook"}}]`},
		{"changed action", `[{"domain":["geosite:category-ads-all"],"outboundTag":"direct"}]`},
		{"changed type", `[{"type":"future","domain":["geosite:category-ads-all"],"outboundTag":"block"}]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseline := []byte(`{"routing":{"rules":` + tc.rules + `},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}`)
			result, err := Generate(baseline, Overlay{DropLegacyAdRule: true}, "v1")
			if err == nil || result != nil || !strings.Contains(err.Error(), "drop_legacy_ad_rule") {
				t.Fatalf("unsafe legacy migration was not rejected: %v", err)
			}
		})
	}
}

func TestGenerateRejectsUnsafeExtraOutbounds(t *testing.T) {
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	tests := []struct {
		name     string
		overlay  Overlay
		contains string
	}{
		{"tag replaces baseline", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"direct","protocol":"blackhole"}`)}}, "duplicate outbound tag"},
		{"duplicate added tag", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"freedom"}`), json.RawMessage(`{"tag":"home_out","protocol":"blackhole"}`)}}, "duplicate outbound tag"},
		{"bad protocol", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"unsupported"}`)}}, "unsupported outbound protocol"},
		{"host binding", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"freedom","streamSettings":{"sockopt":{"interface":"router-only"}}}`)}}, "interface binding"},
		{"missing dependency", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"socks","proxySettings":{"tag":"missing"}}`)}}, "missing dependency"},
		{"cycle", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"socks","proxySettings":{"tag":"home_transport"}}`), json.RawMessage(`{"tag":"home_transport","protocol":"socks","streamSettings":{"sockopt":{"dialerProxy":"home_out"}}}`)}}, "dependency cycle"},
		{"unselected home route", Overlay{KeepOutbounds: []string{"direct"}, ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"socks"}`)}, PrependRules: []json.RawMessage{json.RawMessage(`{"ip":["10.20.30.0/24"],"outboundTag":"home_out"}`)}}, "missing or invalid outbound"},
		{"missing home route", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"socks"}`)}, PrependRules: []json.RawMessage{json.RawMessage(`{"ip":["10.20.30.0/24"],"outboundTag":"absent"}`)}}, "missing or invalid outbound"},
		{"malformed JSON", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{`)}}, "invalid JSON"},
		{"null outbound", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`null`)}}, "expected JSON object"},
		{"shadowed extra key", Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"socks","protocol":"freedom"}`)}}, "duplicate JSON object key"},
		{"drop original default", Overlay{KeepOutbounds: []string{"home_out"}, ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"socks"}`)}}, "baseline first outbound would change default routing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Generate(baseline, tc.overlay, "v1")
			if err == nil || result != nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("Generate returned result=%t, err=%v; want rejection containing %q", result != nil, err, tc.contains)
			}
		})
	}
	if _, err := Generate([]byte(`{"outbounds":[]}`), Overlay{ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"home_out","protocol":"freedom"}`)}}, "v1"); err == nil {
		t.Fatal("extra outbounds silently supplied a missing authoritative default")
	}
}

func TestGenerateBalancerPreservesAllPrefixMatchesAndFallback(t *testing.T) {
	baseline := `{
  "routing":{"rules":[{"network":"tcp,udp","balancerTag":"pool"}],"balancers":[{"tag":"pool","selector":["edge-"],"fallbackTag":"fallback","strategy":{"type":"roundRobin","settings":{}}}]},
  "outbounds":[
    {"tag":"direct","protocol":"freedom"},
    {"tag":"edge-a","protocol":"socks","proxySettings":{"tag":"hop"}},
    {"tag":"edge-b","protocol":"socks"},
    {"tag":"edge-c","protocol":"socks"},
    {"tag":"hop","protocol":"socks"},
    {"tag":"fallback","protocol":"freedom"},
    {"tag":"unused","protocol":"blackhole"}
  ]
}`
	result, err := Generate([]byte(baseline), Overlay{KeepOutbounds: []string{"direct"}}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	out := decodeObject(t, result)
	want := decodeArray(t, decodeObject(t, []byte(baseline))["outbounds"])[:6]
	assertJSONEqual(t, out["outbounds"], marshal(t, want))
	assertJSONEqual(t, out["routing"], decodeObject(t, []byte(baseline))["routing"])
}

func TestGenerateRejectsExtraOutboundExpandingBaselineBalancer(t *testing.T) {
	baseline := []byte(`{"routing":{"rules":[{"network":"tcp,udp","balancerTag":"pool"}],"balancers":[{"tag":"pool","selector":["edge-"],"strategy":{"type":"roundRobin"}}]},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"edge-original","protocol":"socks"}]}`)
	for _, keep := range [][]string{nil, {"direct"}, {"direct", "edge-home"}} {
		_, err := Generate(baseline, Overlay{
			KeepOutbounds:  keep,
			ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"edge-home","protocol":"freedom"}`)},
		}, "v1")
		if err == nil || !strings.Contains(err.Error(), "extra outbound would expand a baseline balancer selector") {
			t.Fatalf("keep=%v: expanded baseline pool accepted: %v", keep, err)
		}
	}

	// A disjoint client identity remains selectable without changing the pool,
	// original outbound order or default.
	extra := json.RawMessage(`{"tag":"home_out","protocol":"freedom"}`)
	result, err := Generate(baseline, Overlay{
		KeepOutbounds:  []string{"direct", "home_out"},
		ExtraOutbounds: []json.RawMessage{extra},
	}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	out := decodeObject(t, result)
	want := append(decodeArray(t, decodeObject(t, baseline)["outbounds"]), extra)
	assertJSONEqual(t, out["outbounds"], marshal(t, want))
	assertJSONEqual(t, out["routing"], decodeObject(t, baseline)["routing"])
}

func TestGenerateDoesNotInventRoutingOrMetadata(t *testing.T) {
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	result, err := Generate(baseline, Overlay{Name: "one"}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, result, baseline)
	withName := []byte(`{"name":"baseline app name","outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	result, err = Generate(withName, Overlay{Name: "new app name"}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, result, baseline)
	result, err = Generate(baseline, Overlay{PrependRules: []json.RawMessage{json.RawMessage(`{"ip":["geoip:private"],"outboundTag":"direct"}`)}}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(decodeArray(t, decodeObject(t, decodeObject(t, result)["routing"])["rules"])) != 1 {
		t.Fatal("explicit overlay rule was not included")
	}
}

func TestGeneratePreservesLargeNumbersAndNativeGEO(t *testing.T) {
	baseline := []byte(`{"policy":{"levels":{"0":{"bufferSize":9007199254740993}}},"routing":{"rules":[{"domain":["geosite:example@region"],"ip":["geoip:!cn"],"outboundTag":"direct"}]},"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	result, err := Generate(baseline, Overlay{}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(result, []byte("9007199254740993")) || !bytes.Contains(result, []byte("geosite:example@region")) || !bytes.Contains(result, []byte("geoip:!cn")) {
		t.Fatal("native values were transformed")
	}
}

func TestGenerateRejectsUnsafeOrAmbiguousAdaptation(t *testing.T) {
	minimal := `{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`
	tests := []struct {
		name     string
		baseline string
		overlay  Overlay
		contains string
	}{
		{"malformed baseline", `{`, Overlay{}, "invalid JSON"},
		{"baseline null", `null`, Overlay{}, "expected JSON object"},
		{"trailing JSON", minimal + `{}`, Overlay{}, "trailing JSON data"},
		{"duplicate top key", `{"outbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom"}]}`, Overlay{}, "duplicate JSON"},
		{"duplicate nested key", `{"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"a":1,"a":2}}]}`, Overlay{}, "duplicate JSON"},
		{"unknown top level", `{"observatory":{},"outbounds":[{"tag":"direct","protocol":"freedom"}]}`, Overlay{}, "unsupported top-level"},
		{"nonempty shared transport", `{"transport":{"wsSettings":{"path":"/shared"}},"outbounds":[{"tag":"direct","protocol":"freedom"}]}`, Overlay{}, "shared settings must be explicitly adapted"},
		{"missing outbounds", `{}`, Overlay{}, "invalid JSON"},
		{"empty outbounds", `{"outbounds":[]}`, Overlay{}, "at least one"},
		{"null outbounds", `{"outbounds":null}`, Overlay{}, "expected JSON array"},
		{"untagged outbound", `{"outbounds":[{"protocol":"freedom"}]}`, Overlay{}, "expected string"},
		{"duplicate outbound tag", `{"outbounds":[{"tag":"same","protocol":"freedom"},{"tag":"same","protocol":"blackhole"}]}`, Overlay{}, "duplicate outbound tag"},
		{"selected missing tag", minimal, Overlay{KeepOutbounds: []string{"absent"}}, "unknown or empty"},
		{"duplicate selection", minimal, Overlay{KeepOutbounds: []string{"direct", "direct"}}, "duplicate tag"},
		{"removed default outbound", `{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"socks"}]}`, Overlay{KeepOutbounds: []string{"proxy"}}, "baseline first outbound would change default routing"},
		{"missing proxy dependency", `{"outbounds":[{"tag":"direct","protocol":"freedom","proxySettings":{"tag":"absent"}}]}`, Overlay{}, "missing dependency"},
		{"missing dialer dependency", `{"outbounds":[{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"dialerProxy":"absent"}}}]}`, Overlay{}, "missing dependency"},
		{"self cycle", `{"outbounds":[{"tag":"direct","protocol":"freedom","proxySettings":{"tag":"direct"}}]}`, Overlay{}, "dependency cycle"},
		{"mixed chain cycle", `{"outbounds":[{"tag":"a","protocol":"socks","proxySettings":{"tag":"b"}},{"tag":"b","protocol":"socks","streamSettings":{"sockopt":{"dialerProxy":"a"}}}]}`, Overlay{}, "dependency cycle"},
		{"unknown protocol", `{"outbounds":[{"tag":"direct","protocol":"foreign-protocol"}]}`, Overlay{}, "unsupported outbound protocol"},
		{"loopback outbound", `{"outbounds":[{"tag":"direct","protocol":"loopback","settings":{"inboundTag":"server"}}]}`, Overlay{}, "platform-owned inbounds"},
		{"host sendThrough", `{"outbounds":[{"tag":"direct","protocol":"freedom","sendThrough":"10.20.30.2"}]}`, Overlay{}, "host-bound sendThrough"},
		{"source sendThrough", `{"outbounds":[{"tag":"direct","protocol":"freedom","sendThrough":"srcip"}]}`, Overlay{}, "host-bound sendThrough"},
		{"router mark", `{"outbounds":[{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":66}}}]}`, Overlay{}, "mark requires"},
		{"null mark", `{"outbounds":[{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":null}}}]}`, Overlay{}, "mark requires"},
		{"router interface", `{"outbounds":[{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"interface":"VethXray"}}}]}`, Overlay{}, "interface binding"},
		{"transparent socket", `{"outbounds":[{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"tproxy":"tproxy"}}}]}`, Overlay{}, "transparent socket mode"},
		{"certificate file", `{"outbounds":[{"tag":"direct","protocol":"freedom","streamSettings":{"tlsSettings":{"certificates":[{"certificateFile":"/router/client.pem"}]}}}]}`, Overlay{}, "external local files"},
		{"socket address", `{"outbounds":[{"tag":"direct","protocol":"socks","settings":{"servers":[{"address":"/var/run/proxy.sock"}]}}]}`, Overlay{}, "local socket"},
		{"domain socket stream", `{"outbounds":[{"tag":"direct","protocol":"freedom","streamSettings":{"network":"domainsocket"}}]}`, Overlay{}, "domain sockets"},
		{"foreign dependency", `{"outbounds":[{"tag":"direct","protocol":"freedom","detour":"another"}]}`, Overlay{}, "unsupported outbound reference"},
		{"unknown proxy dependency field", `{"outbounds":[{"tag":"direct","protocol":"freedom","proxySettings":{"outboundTag":"direct"}}]}`, Overlay{}, "unsupported field"},
		{"dialer wrong location", `{"outbounds":[{"tag":"direct","protocol":"freedom","dialerProxy":"direct"}]}`, Overlay{}, "unsupported dialerProxy location"},
		{"rule missing outbound", withRouting(`{"rules":[{"network":"tcp","outboundTag":"absent"}]}`), Overlay{}, "missing or invalid outbound"},
		{"removed route outbound", `{"routing":{"rules":[{"network":"tcp","outboundTag":"removed"}]},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"removed","protocol":"blackhole"}]}`, Overlay{KeepOutbounds: []string{"direct"}}, "missing or invalid outbound"},
		{"rule missing balancer", withRouting(`{"rules":[{"network":"tcp","balancerTag":"absent"}]}`), Overlay{}, "missing or invalid balancer"},
		{"rule ambiguous targets", withRouting(`{"rules":[{"network":"tcp","outboundTag":"direct","balancerTag":"anything"}]}`), Overlay{}, "exactly one"},
		{"rule missing target", withRouting(`{"rules":[{"network":"tcp"}]}`), Overlay{}, "exactly one"},
		{"unsupported rule type", withRouting(`{"rules":[{"type":"lua","network":"tcp","outboundTag":"direct"}]}`), Overlay{}, "unsupported routing rule type"},
		{"mixed inbound business conditions", withRouting(`{"rules":[{"inboundTag":["server"],"domain":["geosite:cn"],"outboundTag":"direct"}]}`), Overlay{DropInboundRules: true}, "cannot drop inboundTag"},
		{"invalid removed rule", withRouting(`{"rules":[{"inboundTag":["server"],"outboundTag":"absent"}]}`), Overlay{DropInboundRules: true}, "missing or invalid outbound"},
		{"empty inbound predicate", withRouting(`{"rules":[{"inboundTag":[],"outboundTag":"direct"}]}`), Overlay{DropInboundRules: true}, "nonempty string array"},
		{"DNS tag dispatch cannot drop", `{"dns":{"tag":"dns-generated","servers":["1.1.1.1"]},"routing":{"rules":[{"inboundTag":["dns-generated"],"outboundTag":"direct"}]},"outbounds":[{"tag":"direct","protocol":"freedom"}]}`, Overlay{DropInboundRules: true}, "DNS-generated tag"},
		{"per-server DNS tag cannot drop", `{"dns":{"servers":[{"address":"1.1.1.1","tag":"dns-generated"}]},"routing":{"rules":[{"inboundTag":["dns-generated"],"outboundTag":"direct"}]},"outbounds":[{"tag":"direct","protocol":"freedom"}]}`, Overlay{DropInboundRules: true}, "DNS-generated tag"},
		{"routing script", withRouting(`{"script":"/router/routing.lua"}`), Overlay{}, "external local files"},
		{"custom local GEO", withRouting(`{"rules":[{"domain":["ext:/router/custom.dat:cn"],"outboundTag":"direct"}]}`), Overlay{}, "custom GEO assets"},
		{"custom DNS GEO", minimal, Overlay{DNS: json.RawMessage(`{"servers":[{"address":"1.1.1.1","domains":["ext:custom.dat:cn"]}]}`)}, "custom GEO assets"},
		{"invalid DNS overlay", minimal, Overlay{DNS: json.RawMessage(`{"servers":`)}, "invalid JSON"},
		{"null DNS overlay", minimal, Overlay{DNS: json.RawMessage(`null`)}, "expected JSON object"},
		{"DNS missing target", minimal, Overlay{DNS: json.RawMessage(`{"servers":[{"address":"1.1.1.1","outboundTag":"absent"}]}`)}, "missing or invalid outbound"},
		{"DNS missing balancer", minimal, Overlay{DNS: json.RawMessage(`{"servers":[{"address":"1.1.1.1","balancerTag":"absent"}]}`)}, "missing or invalid balancer"},
		{"DNS foreign reference", minimal, Overlay{DNS: json.RawMessage(`{"servers":[{"address":"1.1.1.1","detour":"direct"}]}`)}, "unsupported reference form"},
		{"DNS script", minimal, Overlay{DNS: json.RawMessage(`{"script":"dns.lua","servers":["1.1.1.1"]}`)}, "external local files"},
		{"DNS FakeDNS", minimal, Overlay{DNS: json.RawMessage(`{"servers":["fakedns"]}`)}, "fakedns requires"},
		{"DNS malformed server", minimal, Overlay{DNS: json.RawMessage(`{"servers":[{"port":53}]}`)}, "expected string"},
		{"DNS invalid array", minimal, Overlay{DNS: json.RawMessage(`{"servers":null}`)}, "expected JSON array"},
		{"invalid prepend JSON", minimal, Overlay{PrependRules: []json.RawMessage{json.RawMessage(`{`)}}, "invalid JSON"},
		{"prepend missing target", minimal, Overlay{PrependRules: []json.RawMessage{json.RawMessage(`{"ip":["geoip:private"],"outboundTag":"home_out"}`)}}, "missing or invalid outbound"},
		{"balancer duplicate tag", withRouting(`{"balancers":[{"tag":"pool","selector":["direct"]},{"tag":"pool","selector":["direct"]}]}`), Overlay{}, "duplicate balancer"},
		{"balancer empty selector", withRouting(`{"balancers":[{"tag":"pool","selector":[]}]}`), Overlay{}, "nonempty string array"},
		{"balancer no candidates", withRouting(`{"balancers":[{"tag":"pool","selector":["missing-"]}]}`), Overlay{}, "selector matches no"},
		{"balancer missing fallback", withRouting(`{"balancers":[{"tag":"pool","selector":["direct"],"fallbackTag":"absent"}]}`), Overlay{}, "missing fallback"},
		{"balancer observation strategy", withRouting(`{"balancers":[{"tag":"pool","selector":["direct"],"strategy":{"type":"leastPing"}}]}`), Overlay{}, "unsupported observation"},
		{"balancer unsupported settings", withRouting(`{"balancers":[{"tag":"pool","selector":["direct"],"strategy":{"type":"random","settings":{"expected":2}}}]}`), Overlay{}, "nonempty balancer strategy settings"},
		{"balancer unknown fields", withRouting(`{"balancers":[{"tag":"pool","selector":["direct"],"detour":"direct"}]}`), Overlay{}, "unsupported balancer field"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Generate([]byte(tc.baseline), tc.overlay, "v1")
			if err == nil || result != nil {
				t.Fatal("unsafe adaptation produced a candidate")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error = %q; want substring %q", err, tc.contains)
			}
		})
	}
}

func TestErrorsDoNotEchoCredentials(t *testing.T) {
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"socks","settings":{"servers":[{"address":"192.0.2.1","users":[{"user":"DO-NOT-ECHO-USER","pass":"DO-NOT-ECHO-PASSWORD"}]}]},"proxySettings":{"tag":"DO-NOT-ECHO-TARGET"}}]}`)
	_, err := Generate(baseline, Overlay{}, "v1")
	if err == nil || strings.Contains(err.Error(), "DO-NOT-ECHO") {
		t.Fatal("error leaked configuration values or validation succeeded")
	}
}

func TestDeepJSONFailsClosed(t *testing.T) {
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"nested":` + strings.Repeat("[", 140) + "0" + strings.Repeat("]", 140) + `}}]}`)
	_, err := Generate(baseline, Overlay{}, "v1")
	if err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatal("deep input was not bounded")
	}
}

func withRouting(routing string) string {
	return `{"routing":` + routing + `,"outbounds":[{"tag":"direct","protocol":"freedom"}]}`
}

func decodeObject(t *testing.T, raw []byte) object {
	t.Helper()
	var result object
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeArray(t *testing.T, raw []byte) []json.RawMessage {
	t.Helper()
	var result []json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatal("native JSON semantics differ")
	}
}
