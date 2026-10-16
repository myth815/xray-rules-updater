package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/myth815/xray-rules-updater/internal/geodata"
)

// DomainSetsFromOutbounds extracts declared pure domain predicates, not an
// evaluation of arbitrary routing rules or their reachability. AND conditions
// must never be silently removed to broaden a routing predicate into DNS.
func DomainSetsFromOutbounds(baseline []byte, tags []string) (map[string][]string, error) {
	result := map[string][]string{}
	if len(tags) == 0 {
		return result, nil
	}
	top, err := readObject(baseline, "baseline")
	if err != nil {
		return nil, err
	}
	outs, err := readArray(top["outbounds"], "outbounds")
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for _, raw := range outs {
		out, err := readObject(raw, "outbound")
		if err != nil {
			return nil, err
		}
		tag, err := requiredString(out["tag"], "outbound.tag")
		if err != nil || existing[tag] {
			return nil, fmt.Errorf("domain collection: invalid or duplicate outbound tag")
		}
		existing[tag] = true
	}
	seen := map[string]map[string]bool{}
	for _, tag := range tags {
		if tag == "" || !existing[tag] {
			return nil, fmt.Errorf("domain collection: specified outbound tag not found")
		}
		seen[tag] = map[string]bool{}
		result[tag] = nil
	}
	routing, err := readObject(top["routing"], "routing")
	if err != nil {
		return nil, err
	}
	rules, err := readArray(routing["rules"], "routing.rules")
	if err != nil {
		return nil, err
	}
	for _, raw := range rules {
		rule, err := readObject(raw, "routing rule")
		if err != nil {
			return nil, err
		}
		var tag string
		if json.Unmarshal(rule["outboundTag"], &tag) != nil || seen[tag] == nil {
			continue
		}
		domains, ok := rule["domain"]
		if !ok {
			// Only domain-free rules are skipped. The alias must not silently
			// disappear from a selected outbound's domain policy.
			if _, alias := rule["domains"]; alias {
				return nil, fmt.Errorf("domain collection: unsupported domains alias")
			}
			continue
		}
		for key := range rule {
			switch key {
			case "type", "ruleTag", "domain", "outboundTag":
			default:
				return nil, fmt.Errorf("domain collection: compound predicate or side effect cannot be projected")
			}
		}
		if raw, ok := rule["type"]; ok {
			kind, err := requiredString(raw, "routing rule.type")
			if err != nil || kind != "field" {
				return nil, fmt.Errorf("domain collection: unsupported rule type")
			}
		}
		if raw, ok := rule["ruleTag"]; ok {
			if _, err := optionalString(raw, "routing rule.ruleTag"); err != nil {
				return nil, err
			}
		}
		expressions, err := nonEmptyStrings(domains, "routing rule.domain")
		if err != nil {
			return nil, err
		}
		if err := geodata.ValidateDomainExpressions(expressions); err != nil {
			return nil, err
		}
		for _, expression := range expressions {
			if !seen[tag][expression] {
				seen[tag][expression] = true
				result[tag] = append(result[tag], expression)
			}
		}
	}
	for tag := range seen {
		if len(result[tag]) == 0 {
			return nil, fmt.Errorf("domain collection: outbound has no pure domain policy")
		}
	}
	return result, nil
}

func deriveDNSServerDomains(baseline []byte, raw json.RawMessage, mapping map[string]string) (json.RawMessage, error) {
	if len(mapping) == 0 {
		return raw, nil
	}
	if len(mapping) > 128 {
		return nil, fmt.Errorf("DNS domain mapping exceeds server limit")
	}
	tags := make([]string, 0, len(mapping))
	for serverTag, outboundTag := range mapping {
		if serverTag == "" || outboundTag == "" {
			return nil, fmt.Errorf("DNS domain mapping requires exact nonempty tags")
		}
		tags = append(tags, outboundTag)
	}
	sets, err := DomainSetsFromOutbounds(baseline, tags)
	if err != nil {
		return nil, err
	}
	dns, err := readObject(raw, "dns")
	if err != nil {
		return nil, err
	}
	servers, err := readArray(dns["servers"], "dns.servers")
	if err != nil {
		return nil, err
	}
	encoded := make(map[string]json.RawMessage, len(sets))
	for outbound, expressions := range sets {
		encoded[outbound], _ = json.Marshal(expressions)
	}
	const maxInjectedDomainBytes = 4 << 20
	var injectedBytes int
	objects := make([]object, len(servers))
	seen := map[string]bool{}
	for i, raw := range servers {
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) {
			continue
		}
		server, err := readObject(raw, "dns server")
		if err != nil {
			return nil, err
		}
		objects[i] = server
		value, hasTag := server["tag"]
		if !hasTag {
			continue
		}
		tag, err := optionalString(value, "dns server.tag")
		if err != nil {
			return nil, err
		}
		if tag != "" && seen[tag] {
			return nil, fmt.Errorf("DNS domain mapping: duplicate server tag")
		}
		seen[tag] = true
		if outbound, selected := mapping[tag]; selected {
			injectedBytes += len(encoded[outbound])
			if injectedBytes > maxInjectedDomainBytes {
				return nil, fmt.Errorf("DNS domain mapping exceeds aggregate 4 MiB injection limit")
			}
		}
	}
	for tag := range mapping {
		if !seen[tag] {
			return nil, fmt.Errorf("DNS domain mapping: specified server tag not found")
		}
	}
	// Charge every server's copy before serializing any replacements. One large
	// baseline set referenced by many servers must not multiply into unbounded
	// temporary JSON allocations in the short-lived router container.
	for i, server := range objects {
		if server == nil {
			continue
		}
		var tag string
		_ = json.Unmarshal(server["tag"], &tag)
		if outbound, selected := mapping[tag]; selected {
			server["domains"] = encoded[outbound]
			servers[i], _ = json.Marshal(server)
		}
	}
	dns["servers"], _ = json.Marshal(servers)
	return json.Marshal(dns)
}
