package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// ai66-v1 is an explicit structural contract for the router-owned AI DNS and
// two-pass listeners. Only its exact helpers are removed. The original node
// graph and native business rules remain the client's authoritative policy;
// the app gets its DNS/inbounds from its separately validated platform overlay.
// The syncer's baseline hash and native server verifier still use the full,
// unmodified server snapshot. This is never an automatic loopback allowance.
func normalizeServerRuntime(baseline []byte, overlay Overlay) ([]byte, error) {
	if overlay.ServerRuntimeProfile == "ai66-v2" {
		return normalizeServerRuntimeV2(baseline, overlay)
	}
	if len(overlay.ServerLocalDomains) != 0 {
		return nil, fmt.Errorf("server_local_domains requires ai66-v2")
	}
	if overlay.ServerRuntimeProfile == "" {
		return baseline, nil
	}
	if overlay.ServerRuntimeProfile != "ai66-v1" {
		return nil, fmt.Errorf("unknown server_runtime_profile")
	}
	if len(overlay.DNS) == 0 || bytes.Equal(bytes.TrimSpace(overlay.DNS), []byte("null")) {
		return nil, fmt.Errorf("ai66-v1 requires an explicit client DNS overlay")
	}
	if _, err := readObject(overlay.DNS, "client DNS overlay"); err != nil {
		return nil, err
	}
	top, err := readObject(baseline, "baseline")
	if err != nil {
		return nil, err
	}
	if !sameRuntimeJSON(top["fakedns"], map[string]any{"ipPool": "198.19.0.0/16", "poolSize": 4096}) {
		return nil, fmt.Errorf("ai66-v1 FakeDNS pool differs from the owned runtime")
	}
	sets, err := DomainSetsFromOutbounds(baseline, []string{"usa-ai"})
	if err != nil {
		return nil, err
	}
	dns, err := readObject(top["dns"], "server DNS")
	if err != nil {
		return nil, err
	}
	servers, err := readArray(dns["servers"], "server DNS servers")
	if err != nil || len(servers) < 2 || !sameRuntimeJSON(dns["enableParallelQuery"], false) ||
		!sameRuntimeJSON(servers[0], map[string]any{"address": "fakedns", "domains": sets["usa-ai"], "skipFallback": true}) {
		return nil, fmt.Errorf("ai66-v1 FakeDNS domain ownership differs from native AI policy")
	}
	for _, raw := range servers[1:] {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			if text == "fakedns" {
				return nil, fmt.Errorf("ai66-v1 additional FakeDNS server")
			}
			continue
		}
		server, err := readObject(raw, "server DNS server")
		if err != nil {
			return nil, err
		}
		if sameRuntimeJSON(server["address"], "fakedns") {
			return nil, fmt.Errorf("ai66-v1 additional FakeDNS server")
		}
	}
	first := map[string]any{"enabled": true, "metadataOnly": true, "destOverride": []string{"fakedns"}, "routeOnly": true}
	second := map[string]any{"enabled": true, "metadataOnly": false, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
	loopPairs := [][2]string{{"socks-route", "ai-guard-second-route"}, {"socks-hk", "ai-guard-second-hk"}, {"tunIn", "ai-guard-second-tun"}}
	helpers := map[string]any{"ai66-dns-out": map[string]any{"tag": "ai66-dns-out", "protocol": "dns", "settings": map[string]any{
		"rules": []any{map[string]any{"qType": "1", "action": "hijack"}, map[string]any{"action": "return", "rCode": 0}},
	}}}
	for _, pair := range loopPairs {
		tag := "ai-guard-loop-" + pair[0]
		helpers[tag] = map[string]any{"tag": tag, "protocol": "loopback", "settings": map[string]any{"inboundTag": pair[1], "sniffing": second}}
	}
	outs, err := readArray(top["outbounds"], "server outbounds")
	if err != nil {
		return nil, err
	}
	var keptOuts []json.RawMessage
	for _, raw := range outs {
		out, err := readObject(raw, "server outbound")
		if err != nil {
			return nil, err
		}
		tag, _ := requiredString(out["tag"], "server outbound.tag")
		if expected, owned := helpers[tag]; owned {
			if !sameRuntimeJSON(raw, expected) {
				return nil, fmt.Errorf("ai66-v1 outbound helper changed")
			}
			delete(helpers, tag)
		} else {
			if serverOwnedTag(tag) {
				return nil, fmt.Errorf("ai66-v1 unexpected or duplicate owned outbound")
			}
			keptOuts = append(keptOuts, raw)
		}
	}
	if len(helpers) != 0 {
		return nil, fmt.Errorf("ai66-v1 required outbound helper missing")
	}
	if len(keptOuts) == 0 || !bytes.Equal(outs[0], keptOuts[0]) {
		return nil, fmt.Errorf("ai66-v1 cannot remove the baseline default outbound")
	}
	retained := map[string]object{}
	for _, raw := range keptOuts {
		out, err := readObject(raw, "server retained outbound")
		if err != nil {
			return nil, err
		}
		tag, err := requiredString(out["tag"], "server retained outbound.tag")
		if err != nil || retained[tag] != nil {
			return nil, fmt.Errorf("ai66-v1 invalid or duplicate retained tag")
		}
		retained[tag] = out
		if raw, exists := out["targetStrategy"]; exists {
			strategy, err := optionalString(raw, "server outbound.targetStrategy")
			if err != nil || (strategy != "" && strategy != "AsIs") {
				return nil, fmt.Errorf("ai66-v1 outbound targetStrategy requires explicit two-pass adaptation")
			}
		}
	}
	// Do not apply the client's host-socket checks before the existing explicit
	// omission step: real server proxy nodes may carry RouterOS-only marks.
	block := retained["block"]
	if !sameRuntimeJSON(block["protocol"], "blackhole") {
		return nil, fmt.Errorf("ai66-v1 requires an unchained blackhole")
	}
	for key := range block {
		if key != "tag" && key != "protocol" && key != "settings" {
			return nil, fmt.Errorf("ai66-v1 block cannot carry a transport or proxy chain")
		}
	}
	ai := retained["usa-ai"]
	aiProtocol, err := requiredString(ai["protocol"], "server AI protocol")
	if err != nil || aiProtocol == "freedom" || aiProtocol == "dns" || aiProtocol == "blackhole" {
		return nil, fmt.Errorf("ai66-v1 AI outbound must remain a proxy")
	}
	inlets, err := readArray(top["inbounds"], "server inbounds")
	if err != nil {
		return nil, err
	}
	var keptInlets []json.RawMessage
	seenInlets := map[string]bool{}
	for _, raw := range inlets {
		in, err := readObject(raw, "server inbound")
		if err != nil {
			return nil, err
		}
		tag, _ := optionalString(in["tag"], "server inbound.tag")
		if seenInlets[tag] {
			return nil, fmt.Errorf("ai66-v1 duplicate inbound tag")
		}
		seenInlets[tag] = true
		if tag == "ai66-dns-in" {
			if !sameRuntimeJSON(raw, map[string]any{"tag": tag, "listen": "0.0.0.0", "port": 1053, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1", "port": 53, "network": "tcp,udp"}}) {
				return nil, fmt.Errorf("ai66-v1 DNS listener changed")
			}
			continue
		}
		if serverOwnedTag(tag) || tag == "tunIn" {
			return nil, fmt.Errorf("ai66-v1 baseline contains an unowned platform listener")
		}
		if (tag == "socks-route" || tag == "socks-hk") && (!sameRuntimeJSON(in["sniffing"], first) || !sameRuntimeJSON(in["protocol"], "socks")) {
			return nil, fmt.Errorf("ai66-v1 first-pass listener changed")
		}
		keptInlets = append(keptInlets, raw)
	}
	if !seenInlets["ai66-dns-in"] || !seenInlets["socks-route"] || !seenInlets["socks-hk"] {
		return nil, fmt.Errorf("ai66-v1 required inbound missing")
	}
	routing, err := readObject(top["routing"], "server routing")
	if err != nil {
		return nil, err
	}
	rules, err := readArray(routing["rules"], "server routing rules")
	if err != nil || len(rules) == 0 || !sameRuntimeJSON(rules[0], map[string]any{"type": "field", "ruleTag": "ai66-dns-intercept", "inboundTag": []string{"ai66-dns-in"}, "outboundTag": "ai66-dns-out"}) {
		return nil, fmt.Errorf("ai66-v1 first DNS interception changed")
	}
	if err := checkOneXrayOrdinaryRouting(routing, rules); err != nil {
		return nil, err
	}
	if raw, exists := routing["balancers"]; exists {
		entries, err := readArray(raw, "server routing.balancers")
		if err != nil {
			return nil, err
		}
		for _, raw := range entries {
			balancer, err := readObject(raw, "server balancer")
			if err != nil {
				return nil, err
			}
			selectors, err := nonEmptyStrings(balancer["selector"], "server balancer.selector")
			if err != nil {
				return nil, err
			}
			for _, prefix := range selectors {
				for _, pair := range loopPairs {
					if strings.HasPrefix("ai-guard-loop-"+pair[0], prefix) {
						return nil, fmt.Errorf("ai66-v1 balancer would acquire a server loopback")
					}
				}
				if strings.HasPrefix("ai66-dns-out", prefix) {
					return nil, fmt.Errorf("ai66-v1 balancer would acquire the server DNS helper")
				}
			}
		}
	}
	guards := []any{
		map[string]any{"type": "field", "ruleTag": "ai66-fake-protocol-block", "protocol": []string{"fakedns"}, "outboundTag": "block"},
		map[string]any{"type": "field", "ruleTag": "ai66-fake-ip-block", "ip": []string{"198.19.0.0/16"}, "outboundTag": "block"},
	}
	for _, pair := range loopPairs {
		guards = append(guards, map[string]any{"type": "field", "ruleTag": "ai66-second-pass-" + pair[0], "inboundTag": []string{pair[0]}, "outboundTag": "ai-guard-loop-" + pair[0]})
	}
	var keptRules []json.RawMessage
	guardSeen, hkSeen := false, false
	for i := 1; i < len(rules); i++ {
		rule, err := readObject(rules[i], "server routing rule")
		if err != nil {
			return nil, err
		}
		out, _ := optionalString(rule["outboundTag"], "server rule.outboundTag")
		if out == "usa-ai" && len(rule["domain"]) != 0 {
			if guardSeen || i+len(guards) >= len(rules) {
				return nil, fmt.Errorf("ai66-v1 AI guard position changed")
			}
			for n, expected := range guards {
				if !sameRuntimeJSON(rules[i+n+1], expected) {
					return nil, fmt.Errorf("ai66-v1 first/second-pass ordering changed")
				}
			}
			guardSeen = true
			keptRules = append(keptRules, rules[i])
			i += len(guards)
			continue
		}
		ruleTag, _ := optionalString(rule["ruleTag"], "server rule.ruleTag")
		if serverOwnedTag(ruleTag) || serverOwnedTag(out) {
			return nil, fmt.Errorf("ai66-v1 unexpected owned rule or target")
		}
		if raw, ok := rule["inboundTag"]; ok {
			tags, err := nonEmptyStrings(raw, "server rule.inboundTag")
			if err != nil {
				return nil, err
			}
			for _, tag := range tags {
				if serverOwnedTag(tag) {
					if tag != "ai-guard-second-hk" || hkSeen || out != "Hongkong" || !sameRuntimeJSON(raw, []string{"http-hk", "socks-hk", "ai-guard-second-hk"}) || len(rule) != 3 || !sameRuntimeJSON(rule["type"], "field") {
						return nil, fmt.Errorf("ai66-v1 second-pass inlet used outside owned HK rule")
					}
					hkSeen = true
					rule["inboundTag"] = oneXrayJSON([]string{"http-hk", "socks-hk"})
					rules[i] = oneXrayJSON(rule)
				}
			}
		}
		keptRules = append(keptRules, rules[i])
	}
	if !guardSeen || !hkSeen {
		return nil, fmt.Errorf("ai66-v1 incomplete routing ownership")
	}
	delete(top, "fakedns")
	top["outbounds"], top["inbounds"] = oneXrayJSON(keptOuts), oneXrayJSON(keptInlets)
	routing["rules"] = oneXrayJSON(keptRules)
	top["routing"] = oneXrayJSON(routing)
	// Do not inherit server FakeDNS even transiently into further adaptation.
	top["dns"] = append(json.RawMessage(nil), overlay.DNS...)
	return json.Marshal(top)
}

func serverOwnedTag(tag string) bool {
	return strings.HasPrefix(tag, "ai66-") || strings.HasPrefix(tag, "ai-guard-")
}

func sameRuntimeJSON(raw json.RawMessage, expected any) bool {
	var actual, want any
	if json.Unmarshal(raw, &actual) != nil || json.Unmarshal(oneXrayJSON(expected), &want) != nil {
		return false
	}
	return reflect.DeepEqual(actual, want)
}
