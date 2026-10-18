package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// ai66-v2 keeps the ordinary routing policy and node graph authoritative while
// explicitly owning the four metadata-first paths and public-only forced
// listeners. It is separate from v1 so a deployed v1 snapshot remains valid
// during an upgrade or rollback. No generic inbound-rule filter is relaxed.
func normalizeServerRuntimeV2(baseline []byte, overlay Overlay) ([]byte, error) {
	if len(overlay.DNS) == 0 || bytes.Equal(bytes.TrimSpace(overlay.DNS), []byte("null")) {
		return nil, fmt.Errorf("ai66-v2 requires an explicit client DNS overlay")
	}
	if _, err := readObject(overlay.DNS, "client DNS overlay"); err != nil {
		return nil, err
	}
	if err := validateServerLocalDomains(overlay.ServerLocalDomains); err != nil {
		return nil, err
	}
	top, err := readObject(baseline, "baseline")
	if err != nil {
		return nil, err
	}
	if !sameRuntimeJSON(top["fakedns"], map[string]any{"ipPool": "198.19.0.0/16", "poolSize": 4096}) {
		return nil, fmt.Errorf("ai66-v2 FakeDNS pool differs from the owned runtime")
	}
	sets, err := DomainSetsFromOutbounds(baseline, []string{"usa-ai"})
	if err != nil {
		return nil, err
	}
	if err := validateServerRuntimeV2DNS(top["dns"], sets["usa-ai"]); err != nil {
		return nil, err
	}
	keptOuts, err := normalizeServerRuntimeV2Outbounds(top["outbounds"])
	if err != nil {
		return nil, err
	}
	keptInlets, err := normalizeServerRuntimeV2Inlets(top["inbounds"])
	if err != nil {
		return nil, err
	}
	routing, err := readObject(top["routing"], "server routing")
	if err != nil {
		return nil, err
	}
	rules, err := readArray(routing["rules"], "server routing rules")
	if err != nil {
		return nil, err
	}
	if err := checkOneXrayOrdinaryRouting(routing, rules); err != nil {
		return nil, err
	}
	if raw, exists := routing["balancers"]; exists {
		balancers, err := readArray(raw, "server routing.balancers")
		if err != nil || len(balancers) != 0 {
			return nil, fmt.Errorf("ai66-v2 does not own a balancing policy")
		}
	}
	prefix := serverRuntimeV2Prefix(sets["usa-ai"], overlay.ServerLocalDomains)
	if len(rules) <= len(prefix) {
		return nil, fmt.Errorf("ai66-v2 ordinary routing tail missing")
	}
	for i, expected := range prefix {
		if !sameRuntimeJSON(rules[i], expected) {
			return nil, fmt.Errorf("ai66-v2 owned routing prefix differs at index %d", i)
		}
	}
	// Only the exact fixed prefix may contain platform selectors. Preserve the
	// original ad/business rule bytes; remove only the verified server rules.
	keptRules := []json.RawMessage{rules[1], rules[2]}
	for _, raw := range rules[len(prefix):] {
		rule, err := readObject(raw, "server ordinary rule")
		if err != nil {
			return nil, err
		}
		for _, key := range []string{"ruleTag", "outboundTag"} {
			rawTag, exists := rule[key]
			if !exists {
				continue
			}
			tag, err := optionalString(rawTag, "server ordinary rule."+key)
			if err != nil || serverOwnedTag(tag) {
				return nil, fmt.Errorf("ai66-v2 owned rule or target outside verified prefix")
			}
		}
		if raw, exists := rule["inboundTag"]; exists {
			tags, err := nonEmptyStrings(raw, "server ordinary rule.inboundTag")
			if err != nil {
				return nil, err
			}
			for _, tag := range tags {
				if serverOwnedTag(tag) || serverRuntimeV2Listener(tag) {
					return nil, fmt.Errorf("ai66-v2 platform selector outside verified prefix")
				}
			}
		}
		keptRules = append(keptRules, raw)
	}
	delete(top, "fakedns")
	top["outbounds"], top["inbounds"] = oneXrayJSON(keptOuts), oneXrayJSON(keptInlets)
	routing["rules"] = oneXrayJSON(keptRules)
	top["routing"] = oneXrayJSON(routing)
	top["dns"] = append(json.RawMessage(nil), overlay.DNS...)
	return json.Marshal(top)
}

func serverRuntimeV2Pairs() [][2]string {
	return [][2]string{{"socks-route", "ai-guard-second-route"}, {"socks-daily", "ai-guard-second-daily"},
		{"socks-general", "ai-guard-second-general"}, {"tunIn", "ai-guard-second-tun"}}
}

func serverRuntimeV2First() map[string]any {
	return map[string]any{"enabled": true, "metadataOnly": true, "destOverride": []string{"fakedns"}, "routeOnly": true}
}

func validateServerRuntimeV2DNS(raw json.RawMessage, domains []string) error {
	dns, err := readObject(raw, "server DNS")
	if err != nil {
		return err
	}
	servers, err := readArray(dns["servers"], "server DNS servers")
	if err != nil || len(servers) < 2 || !sameRuntimeJSON(dns["enableParallelQuery"], false) ||
		!sameRuntimeJSON(servers[0], map[string]any{"address": "fakedns", "domains": domains, "skipFallback": true}) {
		return fmt.Errorf("ai66-v2 FakeDNS domain ownership differs from native AI policy")
	}
	for _, raw := range servers[1:] {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			if text == "fakedns" {
				return fmt.Errorf("ai66-v2 additional FakeDNS server")
			}
			continue
		}
		server, err := readObject(raw, "server DNS server")
		if err != nil {
			return err
		}
		if sameRuntimeJSON(server["address"], "fakedns") {
			return fmt.Errorf("ai66-v2 additional FakeDNS server")
		}
	}
	return nil
}

func normalizeServerRuntimeV2Outbounds(raw json.RawMessage) ([]json.RawMessage, error) {
	second := map[string]any{"enabled": true, "metadataOnly": false, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
	helpers := map[string]any{"ai66-dns-out": map[string]any{"tag": "ai66-dns-out", "protocol": "dns", "settings": map[string]any{
		"rules": []any{map[string]any{"qType": "1", "action": "hijack"}, map[string]any{"action": "return", "rCode": 0}},
	}}}
	for _, pair := range serverRuntimeV2Pairs() {
		tag := "ai-guard-loop-" + pair[0]
		helpers[tag] = map[string]any{"tag": tag, "protocol": "loopback", "settings": map[string]any{"inboundTag": pair[1], "sniffing": second}}
	}
	outs, err := readArray(raw, "server outbounds")
	if err != nil {
		return nil, err
	}
	var kept []json.RawMessage
	retained := map[string]object{}
	for _, raw := range outs {
		out, err := readObject(raw, "server outbound")
		if err != nil {
			return nil, err
		}
		tag, err := requiredString(out["tag"], "server outbound.tag")
		if err != nil {
			return nil, err
		}
		if expected, owned := helpers[tag]; owned {
			if !sameRuntimeJSON(raw, expected) {
				return nil, fmt.Errorf("ai66-v2 outbound helper changed")
			}
			delete(helpers, tag)
			continue
		}
		if serverOwnedTag(tag) || retained[tag] != nil {
			return nil, fmt.Errorf("ai66-v2 unexpected or duplicate outbound")
		}
		if raw, exists := out["targetStrategy"]; exists {
			strategy, err := optionalString(raw, "server outbound.targetStrategy")
			if err != nil || (strategy != "" && strategy != "AsIs") {
				return nil, fmt.Errorf("ai66-v2 outbound targetStrategy requires explicit two-pass adaptation")
			}
		}
		retained[tag] = out
		kept = append(kept, raw)
	}
	if len(helpers) != 0 || len(kept) == 0 || !bytes.Equal(outs[0], kept[0]) {
		return nil, fmt.Errorf("ai66-v2 helper missing or baseline default outbound removed")
	}
	block := retained["block"]
	if !sameRuntimeJSON(block["protocol"], "blackhole") {
		return nil, fmt.Errorf("ai66-v2 requires an unchained blackhole")
	}
	for key := range block {
		if key != "tag" && key != "protocol" && key != "settings" {
			return nil, fmt.Errorf("ai66-v2 block cannot carry a transport or proxy chain")
		}
	}
	for _, tag := range []string{"usa-ai", "daily-overseas"} {
		protocol, err := requiredString(retained[tag]["protocol"], "server "+tag+" protocol")
		if err != nil || protocol == "freedom" || protocol == "dns" || protocol == "blackhole" || protocol == "loopback" {
			return nil, fmt.Errorf("ai66-v2 %s must remain a proxy", tag)
		}
	}
	return kept, nil
}

func serverRuntimeV2Listeners() map[string]struct {
	protocol string
	port     int
} {
	return map[string]struct {
		protocol string
		port     int
	}{"http-route": {"http", 10800}, "socks-general": {"socks", 10801},
		"http-daily": {"http", 10802}, "socks-daily": {"socks", 10803},
		"http-usa-ai": {"http", 10804}, "socks-usa-ai": {"socks", 10805},
		"socks-route": {"socks", 10866}}
}

func serverRuntimeV2Listener(tag string) bool {
	_, exists := serverRuntimeV2Listeners()[tag]
	return exists
}

func normalizeServerRuntimeV2Inlets(raw json.RawMessage) ([]json.RawMessage, error) {
	inlets, err := readArray(raw, "server inbounds")
	if err != nil {
		return nil, err
	}
	wanted, seen := serverRuntimeV2Listeners(), map[string]bool{}
	var kept []json.RawMessage
	for _, raw := range inlets {
		in, err := readObject(raw, "server inbound")
		if err != nil {
			return nil, err
		}
		tag, err := requiredString(in["tag"], "server inbound.tag")
		if err != nil || seen[tag] {
			return nil, fmt.Errorf("ai66-v2 invalid or duplicate inbound tag")
		}
		seen[tag] = true
		if tag == "ai66-dns-in" {
			if !sameRuntimeJSON(raw, map[string]any{"tag": tag, "listen": "0.0.0.0", "port": 1053, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1", "port": 53, "network": "tcp,udp"}}) {
				return nil, fmt.Errorf("ai66-v2 DNS listener changed")
			}
			continue
		}
		if serverOwnedTag(tag) || tag == "tunIn" {
			return nil, fmt.Errorf("ai66-v2 unowned platform listener")
		}
		if expected, ok := wanted[tag]; ok {
			if !sameRuntimeJSON(in["protocol"], expected.protocol) || !sameRuntimeJSON(in["port"], expected.port) ||
				!sameRuntimeJSON(in["sniffing"], serverRuntimeV2First()) {
				return nil, fmt.Errorf("ai66-v2 first-pass listener changed: %s", tag)
			}
			delete(wanted, tag)
		}
		kept = append(kept, raw)
	}
	if !seen["ai66-dns-in"] || len(wanted) != 0 {
		return nil, fmt.Errorf("ai66-v2 required inbound missing")
	}
	return kept, nil
}

func serverRuntimeV2Prefix(domains, localDomains []string) []any {
	localInlets := []string{"http-daily", "socks-daily", "ai-guard-second-daily", "http-usa-ai", "socks-usa-ai"}
	prefix := []any{
		map[string]any{"type": "field", "ruleTag": "ai66-dns-intercept", "inboundTag": []string{"ai66-dns-in"}, "outboundTag": "ai66-dns-out"},
		map[string]any{"type": "field", "domain": []string{"geosite:category-ads-all"}, "outboundTag": "block"},
		map[string]any{"type": "field", "domain": domains, "outboundTag": "usa-ai"},
		map[string]any{"type": "field", "ruleTag": "ai66-fake-protocol-block", "protocol": []string{"fakedns"}, "outboundTag": "block"},
		map[string]any{"type": "field", "ruleTag": "ai66-fake-ip-block", "ip": []string{"198.19.0.0/16"}, "outboundTag": "block"},
	}
	for _, pair := range serverRuntimeV2Pairs() {
		prefix = append(prefix, map[string]any{"type": "field", "ruleTag": "ai66-second-pass-" + pair[0], "inboundTag": []string{pair[0]}, "outboundTag": "ai-guard-loop-" + pair[0]})
	}
	return append(prefix,
		map[string]any{"type": "field", "ruleTag": "ai66-local-ip", "inboundTag": localInlets, "ip": []string{"geoip:private"}, "outboundTag": "direct"},
		map[string]any{"type": "field", "ruleTag": "ai66-local-domain", "inboundTag": localInlets, "domain": localDomains, "outboundTag": "direct"},
		map[string]any{"type": "field", "ruleTag": "ai66-force-us", "inboundTag": []string{"http-usa-ai", "socks-usa-ai"}, "outboundTag": "usa-ai"},
		map[string]any{"type": "field", "ruleTag": "ai66-force-daily", "inboundTag": []string{"http-daily", "socks-daily", "ai-guard-second-daily"}, "outboundTag": "daily-overseas"})
}

func validateServerLocalDomains(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("ai66-v2 requires explicit server_local_domains")
	}
	seen := map[string]bool{}
	for _, matcher := range domains {
		name, full := strings.CutPrefix(matcher, "full:")
		if !full || len(name) > 253 || !strings.Contains(name, ".") || seen[strings.ToLower(name)] {
			return fmt.Errorf("ai66-v2 server_local_domains requires unique exact DNS names")
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return fmt.Errorf("ai66-v2 server_local_domains cannot contain IP literals")
		}
		for _, label := range strings.Split(name, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return fmt.Errorf("ai66-v2 server_local_domains contains an invalid DNS name")
			}
			for _, ch := range label {
				if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
					return fmt.Errorf("ai66-v2 server_local_domains contains an invalid DNS name")
				}
			}
		}
		seen[strings.ToLower(name)] = true
	}
	return nil
}
