package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
)

// v3 owns only the late domain-resolution lane in addition to the exact v2
// server prefix. Native clients have a fresh routing context and can perform
// IPIfNonMatch themselves. They must not inherit the server's extra loopback.
func normalizeServerRuntimeV3(baseline []byte, overlay Overlay) ([]byte, error) {
	if overlay.OneXrayFakeDNS != nil {
		return nil, fmt.Errorf("ai66-v3 does not support the separate OneXray FakeDNS two-pass adapter")
	}
	if len(overlay.KeepOutbounds) > 0 {
		found := false
		for _, tag := range overlay.KeepOutbounds {
			found = found || tag == "block"
		}
		if !found {
			return nil, fmt.Errorf("ai66-v3 keep_outbounds must retain the default block outbound")
		}
	}
	top, err := readObject(baseline, "baseline")
	if err != nil {
		return nil, err
	}
	if err := validateRuntimeV3DNSBootstrap(top["dns"]); err != nil {
		return nil, err
	}
	for _, raw := range overlay.PrependRules {
		if hasRuntimeV3Reference(raw) {
			return nil, fmt.Errorf("ai66-v3 client prepend refers to an owned server lane")
		}
		rule, err := readObject(raw, "client prepend rule")
		if err != nil {
			return nil, err
		}
		if !runtimeV3EffectiveSelector(rule) {
			return nil, fmt.Errorf("ai66-v3 unconditional client prepend would bypass DNS routing")
		}
	}
	routing, err := readObject(top["routing"], "server routing")
	if err != nil {
		return nil, err
	}
	if !sameRuntimeJSON(routing["domainStrategy"], "IPIfNonMatch") {
		return nil, fmt.Errorf("ai66-v3 requires IPIfNonMatch")
	}
	rules, err := readArray(routing["rules"], "server routing rules")
	if err != nil || len(rules) < 2 || !sameRuntimeJSON(rules[len(rules)-2], serverRuntimeV3IPDefault()) ||
		!sameRuntimeJSON(rules[len(rules)-1], serverRuntimeV3DomainDefault()) {
		return nil, fmt.Errorf("ai66-v3 requires the exact IP-default and domain-resolution tail")
	}
	for _, rule := range rules[:len(rules)-2] {
		if hasRuntimeV3Reference(rule) {
			return nil, fmt.Errorf("ai66-v3 reserved lane reference outside owned tail")
		}
		obj, err := readObject(rule, "server routing rule")
		if err != nil {
			return nil, err
		}
		// Empty arrays and null do not create conditions in Xray. Merely seeing
		// a domain/ip/etc key is not evidence that this rule filters anything.
		if !runtimeV3EffectiveSelector(obj) {
			return nil, fmt.Errorf("ai66-v3 unconditional rule before resolution tail")
		}
	}
	outs, err := readArray(top["outbounds"], "server outbounds")
	if err != nil {
		return nil, err
	}
	helpers := serverRuntimeV3Helpers()
	kept := make([]json.RawMessage, 0, len(outs))
	for i, raw := range outs {
		out, err := readObject(raw, "server outbound")
		if err != nil {
			return nil, err
		}
		tag, err := requiredString(out["tag"], "server outbound.tag")
		if err != nil {
			return nil, err
		}
		if expected, owned := helpers[tag]; owned {
			if i == 0 || !sameRuntimeJSON(raw, expected) {
				return nil, fmt.Errorf("ai66-v3 resolution helper changed or became default")
			}
			delete(helpers, tag)
			continue
		}
		if hasRuntimeV3Reference(raw) {
			return nil, fmt.Errorf("ai66-v3 reserved lane reference outside owned helper")
		}
		kept = append(kept, raw)
	}
	if len(helpers) != 0 {
		return nil, fmt.Errorf("ai66-v3 resolution helper missing or duplicate")
	}
	// Reuse v2's unchanged prefix, inbounds, DNS and proxy/blackhole proofs.
	// Only this temporary validation copy gets its old, exact routing sentinel.
	legacyTail := oneXrayJSON(map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "direct"})
	routing["rules"] = oneXrayJSON(append(rules[:len(rules)-2:len(rules)-2], legacyTail))
	top["routing"], top["outbounds"] = oneXrayJSON(routing), oneXrayJSON(kept)
	normalized, err := normalizeServerRuntimeV2(oneXrayJSON(top), overlay)
	if err != nil {
		return nil, err
	}
	client, err := readObject(normalized, "normalized client")
	if err != nil {
		return nil, err
	}
	clientRouting, err := readObject(client["routing"], "normalized client routing")
	if err != nil {
		return nil, err
	}
	clientRules, err := readArray(clientRouting["rules"], "normalized client rules")
	if err != nil || len(clientRules) == 0 || !sameRuntimeJSON(clientRules[len(clientRules)-1], legacyTail) {
		return nil, fmt.Errorf("ai66-v3 temporary validation tail was not preserved")
	}
	clientRules[len(clientRules)-1] = oneXrayJSON(serverRuntimeV3IPDefault())
	clientRouting["rules"] = oneXrayJSON(clientRules)
	client["routing"] = oneXrayJSON(clientRouting)
	// Native IPIfNonMatch can return no route after DNS failure. A client's
	// default handler must fail closed, not retry via freedom/system DNS.
	clientOuts, err := readArray(client["outbounds"], "normalized client outbounds")
	if err != nil {
		return nil, err
	}
	defaultOuts := make([]json.RawMessage, 0, len(clientOuts))
	for _, raw := range clientOuts {
		out, err := readObject(raw, "normalized client outbound")
		if err != nil {
			return nil, err
		}
		if sameRuntimeJSON(out["tag"], "block") {
			defaultOuts = append(defaultOuts, raw)
		}
	}
	if len(defaultOuts) != 1 {
		return nil, fmt.Errorf("ai66-v3 default block outbound missing")
	}
	for _, raw := range clientOuts {
		out, _ := readObject(raw, "normalized client outbound")
		if !sameRuntimeJSON(out["tag"], "block") {
			defaultOuts = append(defaultOuts, raw)
		}
	}
	client["outbounds"] = oneXrayJSON(defaultOuts)
	return json.Marshal(client)
}

func validateRuntimeV3DNSBootstrap(raw json.RawMessage) error {
	dns, err := readObject(raw, "server DNS")
	if err != nil {
		return err
	}
	servers, err := readArray(dns["servers"], "server DNS servers")
	if err != nil || len(servers) < 2 {
		return fmt.Errorf("ai66-v3 DNS bootstrap missing")
	}
	for _, raw := range servers[1:] {
		var address string
		if json.Unmarshal(raw, &address) != nil {
			server, err := readObject(raw, "server DNS server")
			if err != nil {
				return err
			}
			address, err = requiredString(server["address"], "server DNS address")
			if err != nil {
				return err
			}
		}
		host := address
		if u, err := url.Parse(address); err == nil && u.Host != "" {
			host = u.Hostname()
		} else if h, _, err := net.SplitHostPort(address); err == nil {
			host = h
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("ai66-v3 server DNS needs literal-IP bootstrap to avoid resolver recursion")
		}
	}
	return nil
}

// This profile admits a deliberately narrow set of effective selectors. A
// network-only or port-only rule is not an acceptable late-resolution bypass.
// Invalid nonempty selector values still face the ordinary schema validator.
func runtimeV3EffectiveSelector(rule object) bool {
	for _, key := range []string{"domain", "domains", "ip", "sourceIP", "source", "localIP", "inboundTag", "protocol", "user", "process", "localOS"} {
		if key == "source" {
			if raw, ok := rule["sourceIP"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				continue
			}
		}
		raw, ok := rule[key]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) == nil && len(values) > 0 {
			return true
		}
	}
	if raw, ok := rule["attrs"]; ok {
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) == nil && len(values) > 0 {
			return true
		}
	}
	return false
}

func serverRuntimeV3IPDefault() map[string]any {
	return map[string]any{"type": "field", "ruleTag": "policy-ip-default", "network": "tcp,udp",
		"ip": []string{"0.0.0.0/0", "::/0"}, "outboundTag": "direct"}
}

func serverRuntimeV3DomainDefault() map[string]any {
	return map[string]any{"type": "field", "ruleTag": "policy-resolve-unknown", "network": "tcp,udp",
		"outboundTag": "policy-resolve-unknown"}
}

func serverRuntimeV3Helpers() map[string]any {
	return map[string]any{
		"policy-resolve-unknown": map[string]any{"tag": "policy-resolve-unknown", "protocol": "freedom", "settings": map[string]any{},
			"streamSettings": map[string]any{"sockopt": map[string]any{"domainStrategy": "ForceIPv4", "dialerProxy": "policy-reclassify-resolved"}}},
		"policy-reclassify-resolved": map[string]any{"tag": "policy-reclassify-resolved", "protocol": "loopback",
			"settings": map[string]any{"inboundTag": "policy-resolved"}},
	}
}

func hasRuntimeV3Reference(raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return true
	}
	var visit func(any) bool
	visit = func(value any) bool {
		switch v := value.(type) {
		case string:
			return v == "policy-resolve-unknown" || v == "policy-reclassify-resolved" || v == "policy-resolved" || v == "policy-ip-default"
		case []any:
			for _, x := range v {
				if visit(x) {
					return true
				}
			}
		case map[string]any:
			for _, x := range v {
				if visit(x) {
					return true
				}
			}
		}
		return false
	}
	return visit(value)
}
