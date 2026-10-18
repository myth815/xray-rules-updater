package client

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func runtimeV3Fixture(t *testing.T) []byte {
	t.Helper()
	top := decodeObject(t, runtimeV2Fixture(t))
	routing := decodeObject(t, top["routing"])
	var rules []json.RawMessage
	if err := json.Unmarshal(routing["rules"], &rules); err != nil {
		t.Fatal(err)
	}
	rules = append(rules[:len(rules)-1], json.RawMessage(`{"type":"field","ruleTag":"policy-ip-default","network":"tcp,udp","ip":["0.0.0.0/0","::/0"],"outboundTag":"direct"}`), json.RawMessage(`{"type":"field","ruleTag":"policy-resolve-unknown","network":"tcp,udp","outboundTag":"policy-resolve-unknown"}`))
	routing["rules"] = marshal(t, rules)
	top["routing"] = marshal(t, routing)
	var outs []json.RawMessage
	if err := json.Unmarshal(top["outbounds"], &outs); err != nil {
		t.Fatal(err)
	}
	outs = append(outs,
		json.RawMessage(`{"tag":"policy-resolve-unknown","protocol":"freedom","settings":{},"streamSettings":{"sockopt":{"domainStrategy":"ForceIPv4","dialerProxy":"policy-reclassify-resolved"}}}`),
		json.RawMessage(`{"tag":"policy-reclassify-resolved","protocol":"loopback","settings":{"inboundTag":"policy-resolved"}}`))
	top["outbounds"] = marshal(t, outs)
	return marshal(t, top)
}

func runtimeV3Overlay(t *testing.T) Overlay {
	o := runtimeV2Overlay(t)
	o.ServerRuntimeProfile = "ai66-v3"
	o.OneXrayFakeDNS = nil
	return o
}

func TestServerRuntimeV3PreservesNativeClientRouting(t *testing.T) {
	for _, dropAds := range []bool{false, true} {
		o := runtimeV3Overlay(t)
		o.DropLegacyAdRule = dropAds
		input, overlayBefore := runtimeV3Fixture(t), marshal(t, o)
		before := append([]byte(nil), input...)
		output, err := Generate(input, o, "same-version")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, before) || !bytes.Equal(marshal(t, o), overlayBefore) {
			t.Fatal("mutated source or overlay")
		}
		for _, forbidden := range []string{"policy-resolve-unknown", "policy-reclassify-resolved", "policy-resolved", "SERVER-ONLY", "ai-guard-", "ai66-"} {
			if bytes.Contains(output, []byte(forbidden)) {
				t.Fatalf("server helper leaked: %s", forbidden)
			}
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(output, &top); err != nil {
			t.Fatal(err)
		}
		routing := decodeObject(t, top["routing"])
		var outs []json.RawMessage
		if err := json.Unmarshal(top["outbounds"], &outs); err != nil {
			t.Fatal(err)
		}
		if !sameRuntimeJSON(decodeObject(t, outs[0])["tag"], "block") {
			t.Fatal("DNS failure could fall through to an unprotected default")
		}
		if !sameRuntimeJSON(routing["domainStrategy"], "IPIfNonMatch") {
			t.Fatal("native DNS strategy lost")
		}
		var rules []json.RawMessage
		if err := json.Unmarshal(routing["rules"], &rules); err != nil {
			t.Fatal(err)
		}
		want := json.RawMessage(`{"type":"field","ruleTag":"policy-ip-default","network":"tcp,udp","ip":["0.0.0.0/0","::/0"],"outboundTag":"direct"}`)
		if !sameRuntimeJSON(rules[len(rules)-1], want) {
			t.Fatal("IP-only fallback absent")
		}
		for _, raw := range rules {
			rule := decodeObject(t, raw)
			if _, ok := rule["network"]; ok {
				if _, ok := rule["ip"]; !ok {
					t.Fatal("unconditional network catchall leaked")
				}
			}
		}
		for _, must := range []string{"SYNTHETIC-CLIENT-NODE-CREDENTIAL", `"hop"`, "geoip:private", "geoip:!cn", "domain:ai.example.invalid", "domain:cn.example.invalid"} {
			if !bytes.Contains(output, []byte(must)) {
				t.Fatalf("lost baseline semantics: %s", must)
			}
		}
	}
}

func TestServerRuntimeV3RejectsLaneDrift(t *testing.T) {
	for _, kind := range []string{"strategy", "IP-tail", "no-IP-tail", "resolve-tail", "earlier-catchall", "helper-loop", "helper-nonforce", "helper-extra", "helper-omitted", "helper-default", "reserved-reference"} {
		t.Run(kind, func(t *testing.T) {
			var top map[string]any
			if err := json.Unmarshal(runtimeV3Fixture(t), &top); err != nil {
				t.Fatal(err)
			}
			routing := top["routing"].(map[string]any)
			rules := routing["rules"].([]any)
			outs := top["outbounds"].([]any)
			resolver := outs[len(outs)-2].(map[string]any)
			switch kind {
			case "strategy":
				routing["domainStrategy"] = "IPOnDemand"
			case "IP-tail":
				rules[len(rules)-2].(map[string]any)["outboundTag"] = "usa-ai"
			case "no-IP-tail":
				routing["rules"] = append(rules[:len(rules)-2], rules[len(rules)-1])
			case "resolve-tail":
				rules[len(rules)-1].(map[string]any)["outboundTag"] = "direct"
			case "earlier-catchall":
				routing["rules"] = append(append(rules[:len(rules)-2:len(rules)-2], map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "direct"}), rules[len(rules)-2:]...)
			case "helper-loop":
				outs[len(outs)-1].(map[string]any)["settings"].(map[string]any)["inboundTag"] = "socks-general"
			case "helper-nonforce":
				resolver["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["domainStrategy"] = "UseIPv4"
			case "helper-extra":
				resolver["sendThrough"] = "192.0.2.4"
			case "helper-omitted":
				top["outbounds"] = outs[:len(outs)-1]
			case "helper-default":
				outs[0], outs[len(outs)-2] = outs[len(outs)-2], outs[0]
			case "reserved-reference":
				outs[0].(map[string]any)["streamSettings"] = map[string]any{"sockopt": map[string]any{"dialerProxy": "policy-resolve-unknown"}}
			}
			if _, err := Generate(marshal(t, top), runtimeV3Overlay(t), ""); err == nil {
				t.Fatal("accepted changed resolver lane")
			}
		})
	}
}

func TestServerRuntimeV3RequiresExplicitProfileAndOrdinaryClient(t *testing.T) {
	for _, profile := range []string{"", "ai66-v1", "ai66-v2"} {
		o := runtimeV3Overlay(t)
		o.ServerRuntimeProfile = profile
		if _, err := Generate(runtimeV3Fixture(t), o, ""); err == nil {
			t.Fatalf("profile %q accepted v3 graph", profile)
		}
	}
	if _, err := Generate(runtimeV2Fixture(t), runtimeV3Overlay(t), ""); err == nil {
		t.Fatal("v3 accepted old v2 graph")
	}
	missingBlock := runtimeV3Overlay(t)
	missingBlock.KeepOutbounds = []string{"direct", "usa-ai", "daily-overseas"}
	if _, err := Generate(runtimeV3Fixture(t), missingBlock, ""); err == nil {
		t.Fatal("v3 allowed default block to be removed")
	}
	o := runtimeV3Overlay(t)
	o.OneXrayFakeDNS = runtimeV2Overlay(t).OneXrayFakeDNS
	if _, err := Generate(runtimeV3Fixture(t), o, ""); err == nil || !strings.Contains(err.Error(), "separate OneXray FakeDNS") {
		t.Fatalf("unsupported client two-pass was not rejected: %v", err)
	}
}

func TestServerRuntimeV3RejectsIneffectiveSelectors(t *testing.T) {
	for _, fields := range []string{`{}`, `{"domain":[]}`, `{"domain":null}`, `{"domain":""}`, `{"ip":[]}`, `{"ip":null}`, `{"domain":[],"ip":null}`, `{"unknown":["x"]}`, `{"source":["192.0.2.1"],"sourceIP":[]}`} {
		t.Run(fields, func(t *testing.T) {
			var rule map[string]any
			if err := json.Unmarshal([]byte(fields), &rule); err != nil {
				t.Fatal(err)
			}
			rule["type"], rule["network"], rule["outboundTag"] = "field", "tcp,udp", "direct"
			o := runtimeV3Overlay(t)
			o.PrependRules = append(o.PrependRules, marshal(t, rule))
			if _, err := Generate(runtimeV3Fixture(t), o, ""); err == nil {
				t.Fatal("ineffective client selector accepted")
			}
			var top map[string]any
			if err := json.Unmarshal(runtimeV3Fixture(t), &top); err != nil {
				t.Fatal(err)
			}
			routing := top["routing"].(map[string]any)
			rules := routing["rules"].([]any)
			routing["rules"] = append(append(rules[:len(rules)-2:len(rules)-2], rule), rules[len(rules)-2:]...)
			if _, err := Generate(marshal(t, top), runtimeV3Overlay(t), ""); err == nil {
				t.Fatal("ineffective server selector accepted")
			}
		})
	}
	// The profile's actual DNS and home-service selectors remain accepted.
	o := runtimeV3Overlay(t)
	o.PrependRules = append(o.PrependRules, json.RawMessage(`{"type":"field","inboundTag":["dns-ai"],"outboundTag":"usa-ai"}`))
	if _, err := Generate(runtimeV3Fixture(t), o, ""); err != nil {
		t.Fatal(err)
	}
}

func TestServerRuntimeV3RequiresIndependentDNSBootstrap(t *testing.T) {
	for _, address := range []string{"dns.example.invalid", "https://dns.example.invalid/dns-query", "tls://dns.example.invalid:853", "localhost"} {
		t.Run(address, func(t *testing.T) {
			var top map[string]any
			if err := json.Unmarshal(runtimeV3Fixture(t), &top); err != nil {
				t.Fatal(err)
			}
			top["dns"].(map[string]any)["servers"].([]any)[1] = address
			if _, err := Generate(marshal(t, top), runtimeV3Overlay(t), ""); err == nil {
				t.Fatal("recursive server DNS bootstrap accepted")
			}
		})
	}
	// This restriction is for server resolver-lane bootstrap only. Clients
	// use a fresh native routing context and retain their explicit DNS overlay.
	o := runtimeV3Overlay(t)
	o.DNS = json.RawMessage(`{"servers":["https://dns.example.invalid/dns-query"]}`)
	if _, err := Generate(runtimeV3Fixture(t), o, ""); err != nil {
		t.Fatal(err)
	}
}
