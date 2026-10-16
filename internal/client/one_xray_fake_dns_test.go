package client

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

const oneXrayBaselineFixture = `{
  "inbounds":[{"tag":"server","protocol":"vless","streamSettings":{"realitySettings":{"privateKey":"SYNTHETIC-SERVER-ONLY-KEY"}}}],
  "dns":{"tag":"client-dns","queryStrategy":"UseIP","servers":[
    {"address":"223.5.5.5","tag":"dns-cn","domains":["geosite:cn","domain:ai.example.invalid"],"skipFallback":true},
    {"address":"https://1.1.1.1/dns-query","tag":"dns-ai","domains":["full:old.example.invalid"],"expectedIPs":["geoip:!cn"],"finalQuery":true,"skipFallback":true},
    "https://8.8.8.8/dns-query"
  ]},
  "routing":{"domainStrategy":"IPIfNonMatch","domainMatcher":"hybrid","rules":[
    {"inboundTag":["server"],"outboundTag":"unused"},
    {"type":"field","domain":["geosite:openai","domain:ai.example.invalid"],"outboundTag":"usa-ai","ruleTag":"authority-ai"},
    {"ip":["geoip:private"],"outboundTag":"direct"},
    {"ip":["geoip:!cn"],"outboundTag":"hongkong"},
    {"network":"tcp,udp","outboundTag":"direct"}
  ]},
  "outbounds":[
    {"tag":"direct","protocol":"freedom","settings":{}},
    {"tag":"block","protocol":"blackhole","settings":{}},
    {"tag":"usa-ai","protocol":"socks","settings":{"servers":[{"address":"192.0.2.10","port":1080}]},"streamSettings":{"sockopt":{"dialerProxy":"hop"}}},
    {"tag":"hop","protocol":"socks","settings":{"servers":[{"address":"192.0.2.11","port":1080}]}},
    {"tag":"hongkong","protocol":"socks","settings":{"servers":[{"address":"192.0.2.12","port":1080}]}},
    {"tag":"unused","protocol":"freedom"}
  ]
}`

func oneXrayFixtureOverlay() Overlay {
	return Overlay{
		KeepOutbounds: []string{"direct", "block", "usa-ai", "mobile-dns-out"}, DropInboundRules: true,
		ExtraOutbounds: []json.RawMessage{json.RawMessage(`{"tag":"mobile-dns-out","protocol":"dns","settings":{"rules":[{"action":"hijack","qType":"1,28"},{"action":"direct"}]},"streamSettings":{"sockopt":{"dialerProxy":"hongkong"}}}`)},
		PrependRules: []json.RawMessage{
			json.RawMessage(`{"domain":["full:home.example.invalid"],"port":"443","outboundTag":"direct","ruleTag":"home-first"}`),
			json.RawMessage(`{"inboundTag":["client-dns"],"outboundTag":"hongkong","ruleTag":"ordinary-dns"}`),
			json.RawMessage(`{"type":"field","inboundTag":["tunIn"],"port":"53","outboundTag":"mobile-dns-out","ruleTag":"dns-intercept"}`),
		},
		OneXrayFakeDNS: &OneXrayFakeDNS{OutboundTag: "usa-ai", DNSServerTag: "dns-ai", DNSOutboundTag: "mobile-dns-out"},
	}
}

func TestOneXrayFakeDNSExplicitNativePlatformGraph(t *testing.T) {
	baseline := []byte(oneXrayBaselineFixture)
	overlay := oneXrayFixtureOverlay()
	baselineBefore, overlayBefore := append([]byte(nil), baseline...), marshal(t, overlay)
	result, err := Generate(baseline, overlay, "manifest-only")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseline, baselineBefore) || !bytes.Equal(marshal(t, overlay), overlayBefore) {
		t.Fatal("adapter mutated caller-owned data")
	}
	if bytes.Contains(result, []byte("SERVER-ONLY")) || bytes.Contains(result, []byte("manifest-only")) {
		t.Fatal("server secret or app metadata copied into native configuration")
	}
	top := decodeObject(t, result)
	if got := sortedKeys(top); !reflect.DeepEqual(got, []string{"dns", "fakedns", "inbounds", "outbounds", "routing"}) {
		t.Fatalf("native platform fields: %v", got)
	}
	assertJSONEqual(t, top["inbounds"], json.RawMessage(`[{"tag":"tunIn","protocol":"tun","sniffing":{"enabled":true,"metadataOnly":true,"routeOnly":false,"destOverride":["fakedns"]}}]`))
	assertJSONEqual(t, top["fakedns"], json.RawMessage(`[{"ipPool":"198.19.0.0/16","poolSize":8192},{"ipPool":"fc00:1::/64","poolSize":8192}]`))
	sets, err := DomainSetsFromOutbounds(baseline, []string{"usa-ai"})
	if err != nil {
		t.Fatal(err)
	}
	rules := decodeArray(t, decodeObject(t, top["routing"])["rules"])
	assertJSONEqual(t, rules[0], overlay.PrependRules[2])
	ai := decodeObject(t, rules[1])
	assertJSONEqual(t, ai["domain"], marshal(t, sets["usa-ai"]))
	if string(ai["outboundTag"]) != `"usa-ai"` {
		t.Fatal("AI dispatch changed")
	}
	assertJSONEqual(t, rules[2], json.RawMessage(`{"type":"field","protocol":["fakedns"],"outboundTag":"block","ruleTag":"onexray-fake-protocol-block"}`))
	assertJSONEqual(t, rules[3], json.RawMessage(`{"type":"field","ip":["198.19.0.0/16","fc00:1::/64"],"outboundTag":"block","ruleTag":"onexray-fake-ip-block"}`))
	assertJSONEqual(t, rules[4], json.RawMessage(`{"type":"field","inboundTag":["tunIn"],"outboundTag":"onexray-ordinary-sniff","ruleTag":"onexray-ordinary-dispatch"}`))
	assertJSONEqual(t, rules[5], overlay.PrependRules[0])
	assertJSONEqual(t, rules[6], overlay.PrependRules[1])
	originalRules := decodeArray(t, decodeObject(t, decodeObject(t, baseline)["routing"])["rules"])
	assertJSONEqual(t, marshal(t, rules[7:]), marshal(t, originalRules[1:]))
	outs := decodeArray(t, top["outbounds"])
	var tags []string
	var dnsOut object
	for _, raw := range outs {
		out := decodeObject(t, raw)
		var tag string
		_ = json.Unmarshal(out["tag"], &tag)
		tags = append(tags, tag)
		if tag == "mobile-dns-out" {
			dnsOut = out
		}
	}
	if !reflect.DeepEqual(tags, []string{"direct", "block", "usa-ai", "hop", "hongkong", "mobile-dns-out", "onexray-ordinary-sniff"}) {
		t.Fatalf("default, closure or appended platform ownership changed: %v", tags)
	}
	originalOuts := decodeArray(t, decodeObject(t, baseline)["outbounds"])
	for i := 0; i < 5; i++ {
		assertJSONEqual(t, outs[i], originalOuts[i])
	}
	assertJSONEqual(t, outs[len(outs)-1], json.RawMessage(`{"tag":"onexray-ordinary-sniff","protocol":"loopback","settings":{"inboundTag":"onexray-ordinary-pass","sniffing":{"enabled":true,"metadataOnly":false,"routeOnly":false,"destOverride":["http","tls","quic"]}}}`))
	dnsRules := decodeArray(t, decodeObject(t, dnsOut["settings"])["rules"])
	originalDNSOut := decodeObject(t, overlay.ExtraOutbounds[0])
	originalDNSRules := decodeArray(t, decodeObject(t, originalDNSOut["settings"])["rules"])
	assertJSONEqual(t, dnsRules[0], originalDNSRules[0])
	assertJSONEqual(t, dnsRules[2], originalDNSRules[1])
	assertJSONEqual(t, dnsRules[1], oneXrayJSON(map[string]any{"domain": sets["usa-ai"], "action": "return", "rCode": 0}))
	assertJSONEqual(t, dnsOut["streamSettings"], originalDNSOut["streamSettings"])
	dns := decodeObject(t, top["dns"])
	servers := decodeArray(t, dns["servers"])
	aiServer := decodeObject(t, servers[0])
	assertJSONEqual(t, aiServer["domains"], marshal(t, sets["usa-ai"]))
	if string(aiServer["address"]) != `"fakedns"` || string(aiServer["tag"]) != `"dns-ai"` || string(aiServer["finalQuery"]) != "true" || string(aiServer["skipFallback"]) != "true" {
		t.Fatal("AI DNS is not terminal and private to its native domain set")
	}
	if len(aiServer) != 5 {
		t.Fatal("remote DNS filters or settings leaked into FakeDNS")
	}
	oldServers := decodeArray(t, decodeObject(t, decodeObject(t, baseline)["dns"])["servers"])
	assertJSONEqual(t, servers[1], oldServers[0])
	assertJSONEqual(t, servers[2], oldServers[2])
	second, err := Generate(baseline, overlay, "other-manifest")
	if err != nil || !bytes.Equal(result, second) {
		t.Fatal("platform generation is not deterministic")
	}
}

func TestOneXrayFakeDNSOmittedIsByteCompatible(t *testing.T) {
	o := oneXrayFixtureOverlay()
	o.OneXrayFakeDNS = nil
	// A nil legacy DNS RawMessage marshals as null; use an explicit unchanged
	// DNS object so this roundtrip tests only the new omitted optional feature.
	o.DNS = decodeObject(t, []byte(oneXrayBaselineFixture))["dns"]
	old, err := Generate([]byte(oneXrayBaselineFixture), o, "")
	if err != nil {
		t.Fatal(err)
	}
	var decoded Overlay
	if err := json.Unmarshal(marshal(t, o), &decoded); err != nil {
		t.Fatal(err)
	}
	again, err := Generate([]byte(oneXrayBaselineFixture), decoded, "")
	if err != nil || !bytes.Equal(old, again) {
		t.Fatal("omitted opt-in changed native output")
	}
	top := decodeObject(t, old)
	if top["inbounds"] != nil || top["fakedns"] != nil {
		t.Fatal("default adapter generated platform modules")
	}
	if bytes.Contains(old, []byte("onexray-ordinary")) {
		t.Fatal("default adapter injected a loopback")
	}
}

func TestOneXrayFakeDNSUnsafeInputsRejected(t *testing.T) {
	type mutation func(object, *Overlay)
	changeDNS := func(key string, value json.RawMessage) mutation {
		return func(b object, _ *Overlay) { d := decodeObject(t, b["dns"]); d[key] = value; b["dns"] = marshal(t, d) }
	}
	changeDNSOut := func(raw json.RawMessage) mutation { return func(_ object, o *Overlay) { o.ExtraOutbounds[0] = raw } }
	tests := []struct {
		name   string
		change mutation
	}{
		{"missing exact tag", func(_ object, o *Overlay) { o.OneXrayFakeDNS.DNSServerTag = "" }},
		{"overlapping explicit tags", func(_ object, o *Overlay) { o.OneXrayFakeDNS.DNSServerTag = "usa-ai" }},
		{"reserved option tag", func(_ object, o *Overlay) { o.OneXrayFakeDNS.DNSServerTag = "tunIn" }},
		{"block removed by selection", func(_ object, o *Overlay) { o.KeepOutbounds = []string{"direct", "usa-ai", "mobile-dns-out"} }},
		{"block wrong protocol", func(b object, _ *Overlay) {
			outs := decodeArray(t, b["outbounds"])
			out := decodeObject(t, outs[1])
			out["protocol"] = json.RawMessage(`"freedom"`)
			outs[1] = marshal(t, out)
			b["outbounds"] = marshal(t, outs)
		}},
		{"block chained", func(b object, _ *Overlay) {
			outs := decodeArray(t, b["outbounds"])
			out := decodeObject(t, outs[1])
			out["streamSettings"] = json.RawMessage(`{"sockopt":{"dialerProxy":"usa-ai"}}`)
			outs[1] = marshal(t, out)
			b["outbounds"] = marshal(t, outs)
		}},
		{"AI is direct", func(b object, _ *Overlay) {
			outs := decodeArray(t, b["outbounds"])
			out := decodeObject(t, outs[2])
			out["protocol"] = json.RawMessage(`"freedom"`)
			outs[2] = marshal(t, out)
			b["outbounds"] = marshal(t, outs)
		}},
		{"compound AI predicate", func(b object, _ *Overlay) {
			r := decodeObject(t, b["routing"])
			rules := decodeArray(t, r["rules"])
			rule := decodeObject(t, rules[1])
			rule["port"] = json.RawMessage(`"443"`)
			rules[1] = marshal(t, rule)
			r["rules"] = marshal(t, rules)
			b["routing"] = marshal(t, r)
		}},
		{"nonempty hosts", changeDNS("hosts", json.RawMessage(`{"ai.example.invalid":"192.0.2.9"}`))},
		{"DNS script", changeDNS("script", json.RawMessage(`"return 0"`))},
		{"system hosts", changeDNS("useSystemHosts", json.RawMessage(`true`))},
		{"global fallback disabled", changeDNS("disableFallback", json.RawMessage(`true`))},
		{"system IP strategy", changeDNS("queryStrategy", json.RawMessage(`"UseSystem"`))},
		{"global tag owns tunIn", changeDNS("tag", json.RawMessage(`"tunIn"`))},
		{"AI server tag is global tag", changeDNS("tag", json.RawMessage(`"dns-ai"`))},
		{"missing AI server", func(_ object, o *Overlay) { o.OneXrayFakeDNS.DNSServerTag = "missing" }},
		{"ordinary string FakeDNS", changeDNS("servers", json.RawMessage(`[{"address":"1.1.1.1","tag":"dns-ai","domains":["full:ai.example.invalid"],"skipFallback":true},"FakeDNS"]`))},
		{"ordinary object FakeDNS", changeDNS("servers", json.RawMessage(`[{"address":"1.1.1.1","tag":"dns-ai","domains":["full:ai.example.invalid"],"skipFallback":true},{"address":"fakedns","tag":"ordinary-fake"},"8.8.8.8"]`))},
		{"AI server owns ordinary fallback", func(b object, _ *Overlay) {
			d := decodeObject(t, b["dns"])
			servers := decodeArray(t, d["servers"])
			s := decodeObject(t, servers[1])
			s["skipFallback"] = json.RawMessage(`false`)
			servers[1] = marshal(t, s)
			d["servers"] = marshal(t, servers)
			b["dns"] = marshal(t, d)
		}},
		{"AI server lacks original domains", func(b object, _ *Overlay) {
			d := decodeObject(t, b["dns"])
			servers := decodeArray(t, d["servers"])
			s := decodeObject(t, servers[1])
			delete(s, "domains")
			servers[1] = marshal(t, s)
			d["servers"] = marshal(t, servers)
			b["dns"] = marshal(t, d)
		}},
		{"AI server has invalid original domains", func(b object, _ *Overlay) {
			d := decodeObject(t, b["dns"])
			servers := decodeArray(t, d["servers"])
			s := decodeObject(t, servers[1])
			s["domains"] = json.RawMessage(`["unknown:unsafe"]`)
			servers[1] = marshal(t, s)
			d["servers"] = marshal(t, servers)
			b["dns"] = marshal(t, d)
		}},
		{"duplicate server tag", func(b object, _ *Overlay) {
			d := decodeObject(t, b["dns"])
			servers := decodeArray(t, d["servers"])
			servers = append(servers, servers[1])
			d["servers"] = marshal(t, servers)
			b["dns"] = marshal(t, d)
		}},
		{"server tag is outbound", func(b object, _ *Overlay) {
			d := decodeObject(t, b["dns"])
			servers := decodeArray(t, d["servers"])
			s := decodeObject(t, servers[0])
			s["tag"] = json.RawMessage(`"usa-ai"`)
			servers[0] = marshal(t, s)
			d["servers"] = marshal(t, servers)
			b["dns"] = marshal(t, d)
		}},
		{"no ordinary fallback", func(b object, _ *Overlay) {
			d := decodeObject(t, b["dns"])
			servers := decodeArray(t, d["servers"])
			d["servers"] = marshal(t, servers[:2])
			b["dns"] = marshal(t, d)
		}},
		{"reserved original outbound even if removed", func(b object, _ *Overlay) {
			outs := decodeArray(t, b["outbounds"])
			outs = append(outs, json.RawMessage(`{"tag":"onexray-ordinary-sniff","protocol":"freedom"}`))
			b["outbounds"] = marshal(t, outs)
		}},
		{"reserved server listener", func(b object, _ *Overlay) {
			b["inbounds"] = json.RawMessage(`[{"tag":"tunIn","protocol":"vless","settings":{"secret":"SYNTHETIC-SERVER-KEY"}}]`)
		}},
		{"baseline fake module not inherited", func(b object, _ *Overlay) { b["fakedns"] = json.RawMessage(`{"ipPool":"10.0.0.0/24","poolSize":10}`) }},
		{"caller loopback is not trusted", func(_ object, o *Overlay) {
			o.ExtraOutbounds = append(o.ExtraOutbounds, json.RawMessage(`{"tag":"other-loop","protocol":"loopback","settings":{"inboundTag":"server"}}`))
		}},
		{"missing DNS interception", func(_ object, o *Overlay) { o.PrependRules = o.PrependRules[:2] }},
		{"UDP-only interception", func(_ object, o *Overlay) {
			o.PrependRules[2] = json.RawMessage(`{"inboundTag":["tunIn"],"port":"53","network":"udp","outboundTag":"mobile-dns-out"}`)
		}},
		{"compound interception", func(_ object, o *Overlay) {
			o.PrependRules[2] = json.RawMessage(`{"inboundTag":["tunIn"],"port":"53","domain":["geosite:cn"],"outboundTag":"mobile-dns-out"}`)
		}},
		{"duplicate interception", func(_ object, o *Overlay) { o.PrependRules = append(o.PrependRules, o.PrependRules[2]) }},
		{"extra tunIn route", func(_ object, o *Overlay) {
			o.PrependRules = append(o.PrependRules, json.RawMessage(`{"inboundTag":["tunIn"],"ip":["geoip:private"],"outboundTag":"direct"}`))
		}},
		{"ordinary virtual inbound is user-owned", func(_ object, o *Overlay) {
			o.PrependRules = append(o.PrependRules, json.RawMessage(`{"inboundTag":["onexray-ordinary-pass"],"outboundTag":"direct"}`))
		}},
		{"reserved generated rule tag", func(_ object, o *Overlay) {
			o.PrependRules[0] = json.RawMessage(`{"domain":["full:home.example.invalid"],"outboundTag":"direct","ruleTag":"onexray-fake-ip-block"}`)
		}},
		{"DNS outbound wrong protocol", changeDNSOut(json.RawMessage(`{"tag":"mobile-dns-out","protocol":"freedom","settings":{"rules":[{"action":"hijack","qType":"1,28"},{"action":"direct"}]}}`))},
		{"DNS hijack only A", changeDNSOut(json.RawMessage(`{"tag":"mobile-dns-out","protocol":"dns","settings":{"rules":[{"action":"hijack","qType":"1"},{"action":"direct"}]}}`))},
		{"DNS hijack has domain condition", changeDNSOut(json.RawMessage(`{"tag":"mobile-dns-out","protocol":"dns","settings":{"rules":[{"action":"hijack","qType":"1,28","domain":["geosite:cn"]},{"action":"direct"}]}}`))},
		{"DNS already has a third rule", changeDNSOut(json.RawMessage(`{"tag":"mobile-dns-out","protocol":"dns","settings":{"rules":[{"action":"hijack","qType":"1,28"},{"action":"return"},{"action":"direct"}]}}`))},
		{"DNS default filtered", changeDNSOut(json.RawMessage(`{"tag":"mobile-dns-out","protocol":"dns","settings":{"rules":[{"action":"hijack","qType":"1,28"},{"action":"direct","qType":"65"}]}}`))},
		{"DNS legacy policy", changeDNSOut(json.RawMessage(`{"tag":"mobile-dns-out","protocol":"dns","settings":{"nonIPQuery":"skip","rules":[{"action":"hijack","qType":"1,28"},{"action":"direct"}]}}`))},
		{"IPOnDemand", func(b object, _ *Overlay) {
			r := decodeObject(t, b["routing"])
			r["domainStrategy"] = json.RawMessage(`"IPOnDemand"`)
			b["routing"] = marshal(t, r)
		}},
		{"IPIfNonMatch without original catchall", func(b object, _ *Overlay) {
			r := decodeObject(t, b["routing"])
			rules := decodeArray(t, r["rules"])
			r["rules"] = marshal(t, rules[:len(rules)-1])
			b["routing"] = marshal(t, r)
		}},
		{"balancer gains platform loopback", func(b object, _ *Overlay) {
			outs := decodeArray(t, b["outbounds"])
			outs = append(outs, json.RawMessage(`{"tag":"onexray-old-node","protocol":"socks","settings":{"servers":[{"address":"192.0.2.19","port":1080}]}}`))
			b["outbounds"] = marshal(t, outs)
			r := decodeObject(t, b["routing"])
			r["balancers"] = json.RawMessage(`[{"tag":"balance","selector":["onexray-"]}]`)
			b["routing"] = marshal(t, r)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := decodeObject(t, []byte(oneXrayBaselineFixture))
			o := oneXrayFixtureOverlay()
			tc.change(b, &o)
			result, err := Generate(marshal(t, b), o, "")
			if err == nil || result != nil {
				t.Fatalf("unsafe platform graph accepted: err=%v", err)
			}
		})
	}
}

func TestOneXrayFakeDNSAsIsNeedsNoCatchallAndDefaultRemainsFirst(t *testing.T) {
	b := decodeObject(t, []byte(oneXrayBaselineFixture))
	r := decodeObject(t, b["routing"])
	r["domainStrategy"] = json.RawMessage(`"AsIs"`)
	rules := decodeArray(t, r["rules"])
	r["rules"] = marshal(t, rules[:len(rules)-1])
	b["routing"] = marshal(t, r)
	o := oneXrayFixtureOverlay()
	o.KeepOutbounds = nil
	result, err := Generate(marshal(t, b), o, "")
	if err != nil {
		t.Fatal(err)
	}
	outs := decodeArray(t, decodeObject(t, result)["outbounds"])
	if string(decodeObject(t, outs[0])["tag"]) != `"direct"` || !strings.Contains(string(outs[len(outs)-1]), "loopback") {
		t.Fatal("default moved when injecting platform outbound")
	}
}

func TestOneXrayFakeDNSRejectsOutboundTargetResolutionChanges(t *testing.T) {
	for _, routingStrategy := range []string{"AsIs", "IPIfNonMatch"} {
		for _, targetStrategy := range []string{"UseIP", "ForceIPv4", "ForceIPv6", "unknown", "null"} {
			t.Run(routingStrategy+"/"+targetStrategy, func(t *testing.T) {
				b := decodeObject(t, []byte(oneXrayBaselineFixture))
				r := decodeObject(t, b["routing"])
				r["domainStrategy"] = marshal(t, routingStrategy)
				b["routing"] = marshal(t, r)
				outs := decodeArray(t, b["outbounds"])
				out := decodeObject(t, outs[4]) // ordinary hongkong proxy
				out["targetStrategy"] = marshal(t, targetStrategy)
				if targetStrategy == "null" {
					out["targetStrategy"] = json.RawMessage(`null`)
				}
				outs[4] = marshal(t, out)
				b["outbounds"] = marshal(t, outs)
				result, err := Generate(marshal(t, b), oneXrayFixtureOverlay(), "")
				if err == nil || result != nil || !strings.Contains(err.Error(), "targetStrategy") {
					t.Fatalf("ordinary target resolution changed silently: err=%v", err)
				}
			})
		}
	}
}

func TestOneXrayFakeDNSPreservesTransportAndFreedomResolution(t *testing.T) {
	for _, targetStrategy := range []string{"", "AsIs"} {
		t.Run("targetStrategy="+targetStrategy, func(t *testing.T) {
			b := decodeObject(t, []byte(oneXrayBaselineFixture))
			outs := decodeArray(t, b["outbounds"])
			for _, index := range []int{0, 4} {
				out := decodeObject(t, outs[index])
				out["targetStrategy"] = marshal(t, targetStrategy)
				out["streamSettings"] = json.RawMessage(`{"sockopt":{"domainStrategy":"ForceIPv4"}}`)
				if index == 0 {
					out["settings"] = json.RawMessage(`{"domainStrategy":"UseIPv4"}`)
				}
				outs[index] = marshal(t, out)
			}
			b["outbounds"] = marshal(t, outs)
			result, err := Generate(marshal(t, b), oneXrayFixtureOverlay(), "")
			if err != nil {
				t.Fatal(err)
			}
			got := decodeArray(t, decodeObject(t, result)["outbounds"])
			assertJSONEqual(t, got[0], outs[0])
			assertJSONEqual(t, got[4], outs[4])
		})
	}
}

func TestOneXrayFakeDNSDocumentedFragmentGenerates(t *testing.T) {
	raw, err := os.ReadFile("../../examples/one-xray-fake-dns-fragment.json")
	if err != nil {
		t.Fatal(err)
	}
	var fragment struct {
		Client Overlay `json:"client"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fragment); err != nil {
		t.Fatal(err)
	}
	baseline := []byte(strings.ReplaceAll(oneXrayBaselineFixture, "usa-ai", "sample-egress"))
	result, err := Generate(baseline, fragment.Client, "")
	if err != nil {
		t.Fatal(err)
	}
	top := decodeObject(t, result)
	if top["fakedns"] == nil || top["inbounds"] == nil {
		t.Fatal("documented opt-in did not produce platform modules")
	}
}
