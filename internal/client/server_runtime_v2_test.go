package client

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func runtimeV2Fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/ai66-v2-server.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runtimeV2Overlay(t *testing.T) Overlay {
	t.Helper()
	o := runtimeOverlay(t)
	o.ServerRuntimeProfile = "ai66-v2"
	o.ServerLocalDomains = []string{"full:router.synthetic.invalid", "full:media.synthetic.invalid"}
	for i, raw := range o.ExtraOutbounds {
		o.ExtraOutbounds[i] = json.RawMessage(strings.ReplaceAll(string(raw), "Hongkong", "daily-overseas"))
	}
	for i, raw := range o.PrependRules {
		o.PrependRules[i] = json.RawMessage(strings.ReplaceAll(string(raw), "Hongkong", "daily-overseas"))
	}
	for i, tag := range o.KeepOutbounds {
		if tag == "Hongkong" {
			o.KeepOutbounds[i] = "daily-overseas"
		}
	}
	return o
}

func TestServerRuntimeV2PreservesPureBusinessPolicy(t *testing.T) {
	// Declared independently of the server fixture and the normalizer: explicit
	// local/force exceptions must disappear, not become global client rules.
	pure := []byte(`{
	 "routing":{"domainStrategy":"IPIfNonMatch","rules":[
	  {"type":"field","domain":["geosite:category-ads-all"],"outboundTag":"block"},
	  {"type":"field","domain":["domain:ai.example.invalid"],"outboundTag":"usa-ai"},
	  {"type":"field","domain":["domain:cn.example.invalid"],"outboundTag":"direct"},
	  {"type":"field","ip":["geoip:private"],"outboundTag":"direct"},
	  {"type":"field","ip":["geoip:!cn"],"outboundTag":"daily-overseas"},
	  {"type":"field","network":"tcp,udp","outboundTag":"direct"}]},
	 "outbounds":[
	  {"tag":"direct","protocol":"freedom","settings":{}},
	  {"tag":"block","protocol":"blackhole","settings":{}},
	  {"tag":"usa-ai","protocol":"socks","settings":{"servers":[{"address":"192.0.2.10","port":1080,"users":[{"user":"test","pass":"SYNTHETIC-CLIENT-NODE-CREDENTIAL"}]}]},"streamSettings":{"sockopt":{"dialerProxy":"hop"}}},
	  {"tag":"hop","protocol":"socks","settings":{"servers":[{"address":"192.0.2.11","port":1080}]}},
	  {"tag":"daily-overseas","protocol":"socks","settings":{"servers":[{"address":"192.0.2.12","port":1080}]}}]}`)
	for _, fakeDNS := range []bool{false, true} {
		for _, dropAds := range []bool{false, true} {
			o := runtimeV2Overlay(t)
			o.DropLegacyAdRule = dropAds
			if !fakeDNS {
				o.OneXrayFakeDNS = nil
			}
			before, overlayBefore := runtimeV2Fixture(t), marshal(t, o)
			got, err := Generate(before, o, "fixed-version")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, runtimeV2Fixture(t)) || !bytes.Equal(marshal(t, o), overlayBefore) {
				t.Fatal("mutated authoritative snapshot or overlay")
			}
			o.ServerRuntimeProfile, o.ServerLocalDomains = "", nil
			want, err := Generate(pure, o, "fixed-version")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("v2 changed ordinary client policy (FakeDNS=%v, dropAds=%v)", fakeDNS, dropAds)
			}
			for _, leaked := range []string{"SERVER-ONLY", "ai66-", "ai-guard-", "router.synthetic.invalid", "media.synthetic.invalid"} {
				if bytes.Contains(got, []byte(leaked)) {
					t.Fatalf("server-only data leaked into client: %s", leaked)
				}
			}
			if !bytes.Contains(got, []byte("SYNTHETIC-CLIENT-NODE-CREDENTIAL")) || !bytes.Contains(got, []byte(`"hop"`)) {
				t.Fatal("node identity or dependency was removed")
			}
		}
	}
}

func mutateRuntimeV2(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(runtimeV2Fixture(t), &top); err != nil {
		t.Fatal(err)
	}
	mutate(top)
	return marshal(t, top)
}

func TestServerRuntimeV2RejectsOwnershipAndOrderChanges(t *testing.T) {
	rules := func(top map[string]any) []any { return top["routing"].(map[string]any)["rules"].([]any) }
	rule := func(top map[string]any, n int) map[string]any { return rules(top)[n].(map[string]any) }
	find := func(top map[string]any, key, tag string) map[string]any {
		for _, entry := range top[key].([]any) {
			obj := entry.(map[string]any)
			if obj["tag"] == tag {
				return obj
			}
		}
		panic("missing test tag: " + tag)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"pool-range", func(t map[string]any) { t["fakedns"].(map[string]any)["ipPool"] = "198.18.0.0/15" }},
		{"pool-size", func(t map[string]any) { t["fakedns"].(map[string]any)["poolSize"] = 8192 }},
		{"parallel-dns", func(t map[string]any) { t["dns"].(map[string]any)["enableParallelQuery"] = true }},
		{"dns-owner", func(t map[string]any) {
			t["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["domains"] = []string{"full:other.invalid"}
		}},
		{"extra-fakedns", func(t map[string]any) {
			d := t["dns"].(map[string]any)
			d["servers"] = append(d["servers"].([]any), "fakedns")
		}},
		{"missing-general-helper", func(t map[string]any) { find(t, "outbounds", "ai-guard-loop-socks-general")["tag"] = "unowned-loop" }},
		{"helper-becomes-default", func(t map[string]any) {
			outs := t["outbounds"].([]any)
			outs[0], outs[5] = outs[5], outs[0]
		}},
		{"unknown-helper", func(t map[string]any) { find(t, "outbounds", "hop")["tag"] = "ai-guard-unknown" }},
		{"loop-target", func(t map[string]any) {
			find(t, "outbounds", "ai-guard-loop-socks-general")["settings"].(map[string]any)["inboundTag"] = "socks-general"
		}},
		{"loop-sniff", func(t map[string]any) {
			find(t, "outbounds", "ai-guard-loop-tunIn")["settings"].(map[string]any)["sniffing"].(map[string]any)["routeOnly"] = false
		}},
		{"missing-general-inlet", func(t map[string]any) { find(t, "inbounds", "socks-general")["tag"] = "ordinary" }},
		{"wrong-general-protocol", func(t map[string]any) { find(t, "inbounds", "socks-general")["protocol"] = "http" }},
		{"wrong-us-port", func(t map[string]any) { find(t, "inbounds", "socks-usa-ai")["port"] = 10804 }},
		{"first-pass-payload", func(t map[string]any) {
			find(t, "inbounds", "socks-general")["sniffing"].(map[string]any)["metadataOnly"] = false
		}},
		{"us-first-pass", func(t map[string]any) {
			find(t, "inbounds", "socks-usa-ai")["sniffing"].(map[string]any)["destOverride"] = []string{"tls"}
		}},
		{"dns-listener", func(t map[string]any) { find(t, "inbounds", "ai66-dns-in")["port"] = 1054 }},
		{"dns-helper-side-effect", func(t map[string]any) { find(t, "outbounds", "ai66-dns-out")["sendThrough"] = "127.0.0.1" }},
		{"block-direct", func(t map[string]any) { find(t, "outbounds", "block")["protocol"] = "freedom" }},
		{"ai-direct", func(t map[string]any) { find(t, "outbounds", "usa-ai")["protocol"] = "freedom" }},
		{"daily-direct", func(t map[string]any) { find(t, "outbounds", "daily-overseas")["protocol"] = "freedom" }},
		{"target-resolution", func(t map[string]any) { find(t, "outbounds", "daily-overseas")["targetStrategy"] = "ForceIPv4" }},
		{"ads-drift", func(t map[string]any) { rule(t, 1)["outboundTag"] = "direct" }},
		{"force-us-before-guard", func(t map[string]any) { r := rules(t); r[3], r[11] = r[11], r[3] }},
		{"local-before-guard", func(t map[string]any) { r := rules(t); r[4], r[9] = r[9], r[4] }},
		{"guard-broadened", func(t map[string]any) { rule(t, 4)["ip"] = []string{"0.0.0.0/0"} }},
		{"general-loop-dispatch", func(t map[string]any) { rule(t, 7)["outboundTag"] = "direct" }},
		{"local-rule-captures-tun", func(t map[string]any) { rule(t, 9)["inboundTag"] = []string{"tunIn"} }},
		{"local-ip-broadened", func(t map[string]any) { rule(t, 9)["ip"] = []string{"0.0.0.0/0"} }},
		{"local-ip-side-effect", func(t map[string]any) { rule(t, 9)["port"] = "443" }},
		{"local-domain-broadened", func(t map[string]any) { rule(t, 10)["domain"] = []string{"domain:synthetic.invalid"} }},
		{"local-domain-reordered", func(t map[string]any) {
			rule(t, 10)["domain"] = []string{"full:media.synthetic.invalid", "full:router.synthetic.invalid"}
		}},
		{"local-domain-additional", func(t map[string]any) {
			rule(t, 10)["domain"] = []string{"full:router.synthetic.invalid", "full:media.synthetic.invalid", "full:extra.synthetic.invalid"}
		}},
		{"force-us-direct", func(t map[string]any) { rule(t, 11)["outboundTag"] = "direct" }},
		{"force-daily-ai", func(t map[string]any) { rule(t, 12)["outboundTag"] = "usa-ai" }},
		{"owned-tail-rule", func(t map[string]any) { rule(t, 13)["ruleTag"] = "ai66-local-unknown" }},
		{"second-pass-tail-reference", func(t map[string]any) { rule(t, 13)["inboundTag"] = []string{"ai-guard-second-general"} }},
		{"first-pass-tail-reference", func(t map[string]any) { rule(t, 13)["inboundTag"] = []string{"socks-general"} }},
		{"balancer", func(t map[string]any) {
			t["routing"].(map[string]any)["balancers"] = []any{map[string]any{"tag": "daily-pool", "selector": []string{"daily-"}}}
		}},
		{"ip-on-demand", func(t map[string]any) { t["routing"].(map[string]any)["domainStrategy"] = "IPOnDemand" }},
		{"missing-catchall", func(t map[string]any) { r := rules(t); r[len(r)-1].(map[string]any)["network"] = "tcp" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Generate(mutateRuntimeV2(t, tc.mutate), runtimeV2Overlay(t), ""); err == nil || !strings.Contains(err.Error(), "server runtime adaptation:") {
				t.Fatalf("changed server runtime was accepted: %v", err)
			}
		})
	}
}

func TestServerRuntimeV2LocalDomainsAreExplicitExactNames(t *testing.T) {
	for _, domains := range [][]string{
		nil, {}, {"domain:synthetic.invalid"}, {"full:*.synthetic.invalid"}, {"full:192.0.2.3"}, {"full:2001:db8::1"},
		{"full:localhost"}, {"full:router..invalid"}, {"full:router.invalid."}, {"full:-router.invalid"},
		{"full:router-.invalid"}, {"full:router_.invalid"}, {"full:router.invalid", "full:ROUTER.invalid"},
		{"full:" + strings.Repeat("a", 64) + ".invalid"},
	} {
		o := runtimeV2Overlay(t)
		o.ServerLocalDomains = domains
		if _, err := Generate(runtimeV2Fixture(t), o, ""); err == nil {
			t.Fatalf("invalid exact local-domain declaration accepted: %v", domains)
		}
	}
	o := runtimeV2Overlay(t)
	o.ServerLocalDomains = []string{"full:router.synthetic.invalid", "full:wrong.synthetic.invalid"}
	if _, err := Generate(runtimeV2Fixture(t), o, ""); err == nil {
		t.Fatal("different overlay and server local-domain lists accepted")
	}
	for _, profile := range []string{"", "ai66-v1"} {
		o := runtimeOverlay(t)
		o.ServerRuntimeProfile = profile
		o.ServerLocalDomains = []string{"full:router.synthetic.invalid"}
		if _, err := Generate(runtimeFixture(t), o, ""); err == nil {
			t.Fatal("local-domain ownership silently ignored outside v2")
		}
	}
	for _, dns := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`[]`)} {
		o := runtimeV2Overlay(t)
		o.DNS = dns
		if _, err := Generate(runtimeV2Fixture(t), o, ""); err == nil {
			t.Fatal("v2 inherited implicit server DNS")
		}
	}
}

func TestServerRuntimeProfilesDoNotAcceptEachOthersGraphs(t *testing.T) {
	if _, err := Generate(runtimeV2Fixture(t), runtimeOverlay(t), ""); err == nil {
		t.Fatal("v1 accepted v2 graph")
	}
	if _, err := Generate(runtimeFixture(t), runtimeV2Overlay(t), ""); err == nil {
		t.Fatal("v2 accepted v1 graph")
	}
}
