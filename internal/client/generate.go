// Package client adapts a native Xray baseline for an app-owned client runtime.
// It preserves native routing expressions instead of translating their meaning.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// Overlay contains the deliberate differences between the router baseline and
// a client. An empty KeepOutbounds preserves all outbounds. An explicit list is
// expanded by outbound chains and balancer selectors; baseline order is kept.
// ExtraOutbounds appends explicitly supplied client identities after the
// baseline; it cannot replace a tag or change the baseline's default outbound.
// Name and the Generate version argument belong in the release manifest, not in
// the native Xray configuration owned by the app.
type Overlay struct {
	Name                     string              `json:"name"`
	KeepOutbounds            []string            `json:"keep_outbounds"`
	ExtraOutbounds           []json.RawMessage   `json:"extra_outbounds"`
	OutboundSockoptOmissions map[string][]string `json:"outbound_sockopt_omissions"`
	DropLegacyAdRule         bool                `json:"drop_legacy_ad_rule"`
	DropInboundRules         bool                `json:"drop_inbound_rules"`
	PrependRules             []json.RawMessage   `json:"prepend_rules"`
	// RoutingDomainStrategy overrides only the generated client's routing
	// strategy. Empty inherits the authoritative baseline without changes.
	RoutingDomainStrategy   string            `json:"routing_domain_strategy,omitempty"`
	DNS                     json.RawMessage   `json:"dns"`
	DNSServersFromOutbounds map[string]string `json:"dns_servers_from_outbounds,omitempty"`
	OneXrayFakeDNS          *OneXrayFakeDNS   `json:"one_xray_fake_dns,omitempty"`
	ServerRuntimeProfile    string            `json:"server_runtime_profile,omitempty"`
	// ServerLocalDomains belongs to the ai66-v2/v3/v4 server adapters. These
	// explicit exact-match exceptions are never copied into client policy.
	ServerLocalDomains []string `json:"server_local_domains,omitempty"`
}

type object map[string]json.RawMessage

type outbound struct {
	tag  string
	raw  json.RawMessage
	deps []string
}

type balancer struct {
	tag  string
	deps []string
}

// Generate returns a full native configuration containing dns, routing,
// outbounds and policy. Server listeners and telemetry are omitted. The
// explicit OneXrayFakeDNS adaptation can generate its own platform inbound.
// This is a conservative structural adapter, not an Xray-core schema validator;
// the candidate must still pass the target core's configuration validation.
func Generate(baseline []byte, overlay Overlay, version string) ([]byte, error) {
	_ = version // Versioning is carried by the manifest and immutable URL.
	switch overlay.RoutingDomainStrategy {
	case "", "AsIs", "IPIfNonMatch", "IPOnDemand":
	default:
		return nil, fmt.Errorf("routing_domain_strategy: expected AsIs, IPIfNonMatch or IPOnDemand, or empty to inherit")
	}
	if overlay.OneXrayFakeDNS != nil && overlay.RoutingDomainStrategy == "IPOnDemand" {
		return nil, fmt.Errorf("routing_domain_strategy: IPOnDemand is incompatible with the one_xray_fake_dns two-pass adapter")
	}
	var err error
	baseline, err = normalizeServerRuntime(baseline, overlay)
	if err != nil {
		return nil, fmt.Errorf("server runtime adaptation: %w", err)
	}
	top, err := readObject(baseline, "baseline")
	if err != nil {
		return nil, err
	}
	for _, key := range sortedKeys(top) {
		switch key {
		case "dns", "routing", "outbounds", "policy":
		case "transport":
			shared, err := readObject(top[key], "transport")
			if err != nil {
				return nil, err
			}
			if len(shared) != 0 {
				return nil, fmt.Errorf("transport: shared settings must be explicitly adapted into outbounds before removing platform-owned transport")
			}
			delete(top, key)
		case "name":
			if _, err := optionalString(top[key], "baseline.name"); err != nil {
				return nil, err
			}
			delete(top, key)
		case "inbounds", "log", "api", "stats", "metrics":
			delete(top, key)
		default:
			return nil, fmt.Errorf("baseline: unsupported top-level field %q", key)
		}
	}
	if len(overlay.DNS) != 0 {
		// A present null is not an instruction to inherit or remove DNS.
		top["dns"] = append(json.RawMessage(nil), overlay.DNS...)
	}
	if len(overlay.DNSServersFromOutbounds) != 0 {
		top["dns"], err = deriveDNSServerDomains(baseline, top["dns"], overlay.DNSServersFromOutbounds)
		if err != nil {
			return nil, err
		}
	}
	var dnsTags map[string]bool
	if raw, ok := top["dns"]; ok {
		dnsTags, err = validateDNS(raw)
		if err != nil {
			return nil, err
		}
	}
	if raw, ok := top["policy"]; ok {
		if _, err := readObject(raw, "policy"); err != nil {
			return nil, err
		}
	}

	outboundJSON := top["outbounds"]
	if len(overlay.ExtraOutbounds) != 0 {
		entries, err := readArray(outboundJSON, "outbounds")
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("outbounds: at least one tagged baseline outbound is required before adding client outbounds")
		}
		for i, raw := range overlay.ExtraOutbounds {
			if _, err := readObject(raw, fmt.Sprintf("extra_outbounds[%d]", i)); err != nil {
				return nil, err
			}
			entries = append(entries, append(json.RawMessage(nil), raw...))
		}
		outboundJSON, err = json.Marshal(entries)
		if err != nil {
			return nil, fmt.Errorf("encode combined outbounds: %w", err)
		}
	}
	outboundJSON, err = omitOutboundSockopt(outboundJSON, overlay.OutboundSockoptOmissions)
	if err != nil {
		return nil, err
	}
	outs, byTag, err := readOutbounds(outboundJSON)
	if err != nil {
		return nil, err
	}
	if err := validateDependencyGraph(outs, byTag); err != nil {
		return nil, err
	}
	baselineTargets := make(map[string]bool, len(byTag))
	for tag := range byTag {
		baselineTargets[tag] = true
	}
	routing := object{}
	if raw, ok := top["routing"]; ok {
		routing, err = readObject(raw, "routing")
		if err != nil {
			return nil, err
		}
		if err := rejectFileReferences(routing, "routing"); err != nil {
			return nil, err
		}
	}
	if overlay.RoutingDomainStrategy != "" {
		routing["domainStrategy"], err = json.Marshal(overlay.RoutingDomainStrategy)
		if err != nil {
			return nil, fmt.Errorf("encode routing domain strategy: %w", err)
		}
	}
	extraTags := make(map[string]bool, len(overlay.ExtraOutbounds))
	for _, out := range outs[len(outs)-len(overlay.ExtraOutbounds):] {
		extraTags[out.tag] = true
	}
	balancers, err := readBalancers(routing["balancers"], outs, byTag, extraTags)
	if err != nil {
		return nil, err
	}
	selected, err := selectOutbounds(outs, byTag, balancers, overlay.KeepOutbounds)
	if err != nil {
		return nil, err
	}

	var rules []json.RawMessage
	if raw, ok := routing["rules"]; ok {
		rules, err = readArray(raw, "routing.rules")
		if err != nil {
			return nil, err
		}
	}
	if overlay.DropLegacyAdRule {
		rules, err = omitLegacyAdRule(rules)
		if err != nil {
			return nil, err
		}
	}
	adapted := make([]json.RawMessage, 0, len(rules)+len(overlay.PrependRules))
	for i, raw := range overlay.PrependRules {
		where := fmt.Sprintf("prepend_rules[%d]", i)
		if _, err := validateRule(raw, where, selected, balancers); err != nil {
			return nil, err
		}
		adapted = append(adapted, append(json.RawMessage(nil), raw...))
	}
	for i, raw := range rules {
		where := fmt.Sprintf("routing.rules[%d]", i)
		rule, err := readObject(raw, where)
		if err != nil {
			return nil, err
		}
		if inbound, ok := rule["inboundTag"]; ok && overlay.DropInboundRules {
			if _, err := validateRule(raw, where, baselineTargets, balancers); err != nil {
				return nil, err
			}
			tags, err := nonEmptyStrings(inbound, where+".inboundTag")
			if err != nil {
				return nil, err
			}
			for _, tag := range tags {
				if dnsTags[tag] {
					return nil, fmt.Errorf("%s: inboundTag includes a DNS-generated tag; explicit DNS routing adaptation required", where)
				}
			}
			for _, key := range sortedKeys(rule) {
				switch key {
				case "inboundTag", "type", "ruleTag", "outboundTag", "balancerTag":
				default:
					return nil, fmt.Errorf("%s: cannot drop inboundTag rule combined with field %q", where, key)
				}
			}
			// Only an explicit inbound-only dispatch is removed. Business
			// conditions are never stripped or widened into a global rule.
			continue
		}
		if _, err := validateRule(raw, where, selected, balancers); err != nil {
			return nil, err
		}
		adapted = append(adapted, raw)
	}
	if _, hasRouting := top["routing"]; hasRouting || len(overlay.PrependRules) != 0 || overlay.RoutingDomainStrategy != "" {
		routing["rules"], err = json.Marshal(adapted)
		if err != nil {
			return nil, fmt.Errorf("encode routing rules: %w", err)
		}
		top["routing"], err = json.Marshal(routing)
		if err != nil {
			return nil, fmt.Errorf("encode routing: %w", err)
		}
	}
	if raw, ok := top["dns"]; ok {
		if err := validateReferences(raw, "dns", selected, balancers); err != nil {
			return nil, err
		}
	}
	kept := make([]json.RawMessage, 0, len(selected))
	for _, out := range outs {
		if selected[out.tag] {
			kept = append(kept, out.raw)
		}
	}
	top["outbounds"], err = json.Marshal(kept)
	if err != nil {
		return nil, fmt.Errorf("encode outbounds: %w", err)
	}
	if overlay.OneXrayFakeDNS != nil {
		if err := adaptOneXrayFakeDNS(baseline, top, selected, byTag, balancers, *overlay.OneXrayFakeDNS); err != nil {
			return nil, fmt.Errorf("one_xray_fake_dns: %w", err)
		}
	}
	encoded, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode client configuration: %w", err)
	}
	return append(encoded, '\n'), nil
}

// omitOutboundSockopt applies an explicit client-only omission before normal
// validation. No wildcard tags or outbound replacements are supported.
func omitOutboundSockopt(raw json.RawMessage, omissions map[string][]string) (json.RawMessage, error) {
	if len(omissions) == 0 {
		return raw, nil
	}
	allowed := map[string]bool{
		"mark": true, "interface": true, "bindToDevice": true, "tproxy": true,
		"tcpFastOpen": true, "tcpKeepAliveIdle": true, "tcpKeepAliveInterval": true,
		"tcpMaxSeg": true, "tcpMptcp": true, "tcpNoDelay": true,
		"tcpUserTimeout": true, "tcpcongestion": true,
	}
	tags := make([]string, 0, len(omissions))
	for tag := range omissions {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		if tag == "" || len(omissions[tag]) == 0 {
			return nil, fmt.Errorf("outbound_sockopt_omissions: exact tag and nonempty field list required")
		}
		seen := map[string]bool{}
		for _, field := range omissions[tag] {
			if !allowed[field] {
				return nil, fmt.Errorf("outbound_sockopt_omissions: field is not an approved platform omission; dialerProxy and routing semantics must be preserved")
			}
			if seen[field] {
				return nil, fmt.Errorf("outbound_sockopt_omissions: duplicate field")
			}
			seen[field] = true
		}
	}
	entries, err := readArray(raw, "outbounds")
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for i, raw := range entries {
		where := fmt.Sprintf("outbounds[%d]", i)
		obj, err := readObject(raw, where)
		if err != nil {
			return nil, err
		}
		tag, err := requiredString(obj["tag"], where+".tag")
		if err != nil {
			return nil, err
		}
		fields, selected := omissions[tag]
		if !selected {
			continue
		}
		found[tag] = true
		streamJSON, present := obj["streamSettings"]
		if !present {
			continue
		}
		stream, err := readObject(streamJSON, where+".streamSettings")
		if err != nil {
			return nil, err
		}
		sockoptJSON, present := stream["sockopt"]
		if !present {
			continue
		}
		sockopt, err := readObject(sockoptJSON, where+".streamSettings.sockopt")
		if err != nil {
			return nil, err
		}
		for _, field := range fields {
			delete(sockopt, field)
		}
		if len(sockopt) == 0 {
			delete(stream, "sockopt")
		} else {
			stream["sockopt"], err = json.Marshal(sockopt)
			if err != nil {
				return nil, fmt.Errorf("encode adapted sockopt: %w", err)
			}
		}
		obj["streamSettings"], err = json.Marshal(stream)
		if err != nil {
			return nil, fmt.Errorf("encode adapted stream settings: %w", err)
		}
		entries[i], err = json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("encode adapted outbound: %w", err)
		}
	}
	for _, tag := range tags {
		if !found[tag] {
			return nil, fmt.Errorf("outbound_sockopt_omissions: specified outbound tag not found")
		}
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("encode adapted outbounds: %w", err)
	}
	return encoded, nil
}

// omitLegacyAdRule is deliberately narrower than a general rule filter. A
// changed predicate, absent rule, or duplicated rule stops publication so the
// caller must review its explicit migration request against the new baseline.
func omitLegacyAdRule(rules []json.RawMessage) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, 0, len(rules))
	removed := 0
	for i, raw := range rules {
		rule, err := readObject(raw, fmt.Sprintf("routing.rules[%d]", i))
		if err != nil {
			return nil, err
		}
		var domains []string
		if json.Unmarshal(rule["domain"], &domains) != nil {
			result = append(result, raw)
			continue
		}
		containsAds := false
		for _, domain := range domains {
			containsAds = containsAds || domain == "geosite:category-ads-all"
		}
		if !containsAds {
			result = append(result, raw)
			continue
		}
		if len(domains) != 1 {
			return nil, fmt.Errorf("drop_legacy_ad_rule: legacy ad predicate changed; refusing to remove additional domain conditions")
		}
		target, err := requiredString(rule["outboundTag"], "legacy ad rule outboundTag")
		if err != nil || target != "block" {
			return nil, fmt.Errorf("drop_legacy_ad_rule: legacy ad rule target changed")
		}
		for _, key := range sortedKeys(rule) {
			switch key {
			case "domain", "outboundTag":
			case "type":
				kind, err := requiredString(rule[key], "legacy ad rule type")
				if err != nil || kind != "field" {
					return nil, fmt.Errorf("drop_legacy_ad_rule: legacy ad rule type changed")
				}
			case "ruleTag":
				if _, err := optionalString(rule[key], "legacy ad rule ruleTag"); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("drop_legacy_ad_rule: legacy ad rule has additional conditions or effects")
			}
		}
		removed++
	}
	if removed != 1 {
		return nil, fmt.Errorf("drop_legacy_ad_rule: expected exactly one known legacy ad rule")
	}
	return result, nil
}

func readOutbounds(raw json.RawMessage) ([]outbound, map[string]outbound, error) {
	entries, err := readArray(raw, "outbounds")
	if err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("outbounds: at least one tagged outbound is required")
	}
	outs := make([]outbound, 0, len(entries))
	byTag := make(map[string]outbound, len(entries))
	for i, raw := range entries {
		where := fmt.Sprintf("outbounds[%d]", i)
		obj, err := readObject(raw, where)
		if err != nil {
			return nil, nil, err
		}
		tag, err := requiredString(obj["tag"], where+".tag")
		if err != nil {
			return nil, nil, err
		}
		if _, exists := byTag[tag]; exists {
			return nil, nil, fmt.Errorf("%s: duplicate outbound tag", where)
		}
		protocol, err := requiredString(obj["protocol"], where+".protocol")
		if err != nil {
			return nil, nil, err
		}
		switch protocol {
		case "blackhole", "dns", "freedom", "http", "shadowsocks", "socks", "trojan", "vless", "vmess", "hysteria", "wireguard":
		case "loopback":
			return nil, nil, fmt.Errorf("%s: loopback depends on platform-owned inbounds and requires explicit adaptation", where)
		default:
			return nil, nil, fmt.Errorf("%s: unsupported outbound protocol", where)
		}
		if err := rejectFileReferences(obj, where); err != nil {
			return nil, nil, err
		}
		if raw, ok := obj["sendThrough"]; ok {
			value, err := optionalString(raw, where+".sendThrough")
			if err != nil {
				return nil, nil, err
			}
			addr, parseErr := netip.ParseAddr(value)
			if value != "" && (parseErr != nil || !addr.IsUnspecified()) {
				return nil, nil, fmt.Errorf("%s: host-bound sendThrough requires explicit adaptation", where)
			}
		}
		out := outbound{tag: tag, raw: raw}
		if raw, ok := obj["proxySettings"]; ok {
			proxy, err := readObject(raw, where+".proxySettings")
			if err != nil {
				return nil, nil, err
			}
			for _, key := range sortedKeys(proxy) {
				if key != "tag" && key != "transportLayer" {
					return nil, nil, fmt.Errorf("%s.proxySettings: unsupported field %q", where, key)
				}
			}
			if raw, ok := proxy["tag"]; ok {
				dep, err := optionalString(raw, where+".proxySettings.tag")
				if err != nil {
					return nil, nil, err
				}
				if dep != "" {
					out.deps = append(out.deps, dep)
				}
			}
		}
		if raw, ok := obj["streamSettings"]; ok {
			stream, err := readObject(raw, where+".streamSettings")
			if err != nil {
				return nil, nil, err
			}
			if _, ok := stream["dsSettings"]; ok {
				return nil, nil, fmt.Errorf("%s: domain sockets require host-specific adaptation", where)
			}
			if raw, ok := stream["network"]; ok {
				network, err := optionalString(raw, where+".streamSettings.network")
				if err != nil {
					return nil, nil, err
				}
				if network == "domainsocket" || network == "ds" {
					return nil, nil, fmt.Errorf("%s: domain sockets require host-specific adaptation", where)
				}
			}
			if raw, ok := stream["sockopt"]; ok {
				sockopt, err := readObject(raw, where+".streamSettings.sockopt")
				if err != nil {
					return nil, nil, err
				}
				if err := validateSockopt(sockopt, where+".streamSettings.sockopt"); err != nil {
					return nil, nil, err
				}
				if raw, ok := sockopt["dialerProxy"]; ok {
					dep, err := optionalString(raw, where+".streamSettings.sockopt.dialerProxy")
					if err != nil {
						return nil, nil, err
					}
					if dep != "" {
						out.deps = append(out.deps, dep)
					}
				}
			}
		}
		// Unknown reference forms cannot be safely included in the closure.
		if err := rejectUnknownDependencies(obj, where); err != nil {
			return nil, nil, err
		}
		outs = append(outs, out)
		byTag[tag] = out
	}
	return outs, byTag, nil
}

func validateSockopt(sockopt object, where string) error {
	if raw, ok := sockopt["mark"]; ok {
		var mark uint32
		if json.Unmarshal(raw, &mark) != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("0")) {
			return fmt.Errorf("%s: nonzero or invalid mark requires host-specific adaptation", where)
		}
	}
	for _, key := range []string{"interface", "bindToDevice"} {
		if raw, ok := sockopt[key]; ok {
			value, err := optionalString(raw, where+"."+key)
			if err != nil {
				return err
			}
			if value != "" {
				return fmt.Errorf("%s: interface binding requires host-specific adaptation", where)
			}
		}
	}
	if raw, ok := sockopt["tproxy"]; ok {
		value, err := optionalString(raw, where+".tproxy")
		if err != nil {
			return err
		}
		if value != "" && value != "off" {
			return fmt.Errorf("%s: transparent socket mode requires host-specific adaptation", where)
		}
	}
	return nil
}

func validateDependencyGraph(outs []outbound, byTag map[string]outbound) error {
	state := make(map[string]uint8, len(outs))
	var visit func(string) error
	visit = func(tag string) error {
		switch state[tag] {
		case 1:
			return fmt.Errorf("outbounds: dependency cycle detected")
		case 2:
			return nil
		}
		out, ok := byTag[tag]
		if !ok {
			return fmt.Errorf("outbounds: missing dependency target")
		}
		state[tag] = 1
		for _, dep := range out.deps {
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[tag] = 2
		return nil
	}
	for _, out := range outs {
		if err := visit(out.tag); err != nil {
			return err
		}
	}
	return nil
}

func readBalancers(raw json.RawMessage, outs []outbound, byTag map[string]outbound, extraTags map[string]bool) (map[string]balancer, error) {
	result := map[string]balancer{}
	if len(raw) == 0 {
		return result, nil
	}
	entries, err := readArray(raw, "routing.balancers")
	if err != nil {
		return nil, err
	}
	for i, raw := range entries {
		where := fmt.Sprintf("routing.balancers[%d]", i)
		obj, err := readObject(raw, where)
		if err != nil {
			return nil, err
		}
		for _, key := range sortedKeys(obj) {
			switch key {
			case "tag", "selector", "fallbackTag", "strategy":
			default:
				return nil, fmt.Errorf("%s: unsupported balancer field %q", where, key)
			}
		}
		tag, err := requiredString(obj["tag"], where+".tag")
		if err != nil {
			return nil, err
		}
		if _, exists := result[tag]; exists {
			return nil, fmt.Errorf("%s: duplicate balancer tag", where)
		}
		selectors, err := nonEmptyStrings(obj["selector"], where+".selector")
		if err != nil {
			return nil, err
		}
		b := balancer{tag: tag}
		for _, prefix := range selectors {
			matched := false
			for _, out := range outs {
				if strings.HasPrefix(out.tag, prefix) {
					// Appending a client identity must not silently expand an
					// authoritative baseline pool, even when keep_outbounds
					// would otherwise omit that identity.
					if extraTags[out.tag] {
						return nil, fmt.Errorf("%s: extra outbound would expand a baseline balancer selector; change the authoritative baseline or extra tag explicitly", where)
					}
					matched = true
					b.deps = append(b.deps, out.tag)
				}
			}
			if !matched {
				return nil, fmt.Errorf("%s: selector matches no baseline outbound", where)
			}
		}
		if raw, ok := obj["fallbackTag"]; ok {
			fallback, err := optionalString(raw, where+".fallbackTag")
			if err != nil {
				return nil, err
			}
			if fallback != "" {
				if _, exists := byTag[fallback]; !exists {
					return nil, fmt.Errorf("%s: missing fallback outbound", where)
				}
				b.deps = append(b.deps, fallback)
			}
		}
		if raw, ok := obj["strategy"]; ok {
			strategy, err := readObject(raw, where+".strategy")
			if err != nil {
				return nil, err
			}
			for _, key := range sortedKeys(strategy) {
				if key != "type" && key != "settings" {
					return nil, fmt.Errorf("%s.strategy: unsupported field %q", where, key)
				}
			}
			if raw, ok := strategy["type"]; ok {
				kind, err := optionalString(raw, where+".strategy.type")
				if err != nil {
					return nil, err
				}
				if kind != "" && kind != "random" && kind != "roundRobin" {
					return nil, fmt.Errorf("%s: balancer strategy requires unsupported observation or explicit adaptation", where)
				}
			}
			if raw, ok := strategy["settings"]; ok {
				settings, err := readObject(raw, where+".strategy.settings")
				if err != nil {
					return nil, err
				}
				if len(settings) != 0 {
					return nil, fmt.Errorf("%s: nonempty balancer strategy settings require explicit adaptation", where)
				}
			}
		}
		result[tag] = b
	}
	return result, nil
}

func selectOutbounds(outs []outbound, byTag map[string]outbound, balancers map[string]balancer, keep []string) (map[string]bool, error) {
	selected := make(map[string]bool, len(outs))
	var include func(string) error
	include = func(tag string) error {
		if selected[tag] {
			return nil
		}
		out, ok := byTag[tag]
		if !ok {
			return fmt.Errorf("keep_outbounds: unknown or empty outbound tag")
		}
		selected[tag] = true
		for _, dep := range out.deps {
			if err := include(dep); err != nil {
				return err
			}
		}
		return nil
	}
	if len(keep) == 0 {
		for _, out := range outs {
			if err := include(out.tag); err != nil {
				return nil, err
			}
		}
	} else {
		seen := make(map[string]bool, len(keep))
		for _, tag := range keep {
			if seen[tag] {
				return nil, fmt.Errorf("keep_outbounds: duplicate tag")
			}
			seen[tag] = true
			if err := include(tag); err != nil {
				return nil, err
			}
		}
	}
	// Keep all original balancers and their original candidate populations.
	// Shrinking prefix matches would silently change load balancing policy.
	for _, tag := range sortedBalancerKeys(balancers) {
		for _, dep := range balancers[tag].deps {
			if err := include(dep); err != nil {
				return nil, err
			}
		}
	}
	if !selected[outs[0].tag] {
		return nil, fmt.Errorf("keep_outbounds: removing the baseline first outbound would change default routing; change the authoritative baseline explicitly")
	}
	return selected, nil
}

func validateRule(raw json.RawMessage, where string, outbounds map[string]bool, balancers map[string]balancer) (object, error) {
	rule, err := readObject(raw, where)
	if err != nil {
		return nil, err
	}
	if raw, ok := rule["type"]; ok {
		kind, err := requiredString(raw, where+".type")
		if err != nil {
			return nil, err
		}
		if kind != "field" {
			return nil, fmt.Errorf("%s: unsupported routing rule type", where)
		}
	}
	_, hasOut := rule["outboundTag"]
	_, hasBalancer := rule["balancerTag"]
	if hasOut == hasBalancer {
		return nil, fmt.Errorf("%s: specify exactly one outboundTag or balancerTag", where)
	}
	if raw, ok := rule["inboundTag"]; ok {
		if _, err := nonEmptyStrings(raw, where+".inboundTag"); err != nil {
			return nil, err
		}
	}
	if err := rejectFileReferences(rule, where); err != nil {
		return nil, err
	}
	if err := validateGeoReferences(rule, where); err != nil {
		return nil, err
	}
	if err := validateReferences(raw, where, outbounds, balancers); err != nil {
		return nil, err
	}
	return rule, nil
}

func validateDNS(raw json.RawMessage) (map[string]bool, error) {
	dns, err := readObject(raw, "dns")
	if err != nil {
		return nil, err
	}
	if err := rejectFileReferences(dns, "dns"); err != nil {
		return nil, err
	}
	if err := validateGeoReferences(dns, "dns"); err != nil {
		return nil, err
	}
	tags := map[string]bool{}
	if raw, ok := dns["tag"]; ok {
		tag, err := optionalString(raw, "dns.tag")
		if err != nil {
			return nil, err
		}
		if tag != "" {
			tags[tag] = true
		}
	}
	if raw, ok := dns["servers"]; ok {
		servers, err := readArray(raw, "dns.servers")
		if err != nil {
			return nil, err
		}
		for i, raw := range servers {
			where := fmt.Sprintf("dns.servers[%d]", i)
			var address string
			if len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '"' {
				address, err = requiredString(raw, where)
			} else {
				var server object
				server, err = readObject(raw, where)
				if err == nil {
					address, err = requiredString(server["address"], where+".address")
				}
				if err == nil {
					if raw, ok := server["tag"]; ok {
						var tag string
						tag, err = optionalString(raw, where+".tag")
						if tag != "" {
							tags[tag] = true
						}
					}
				}
			}
			if err != nil {
				return nil, err
			}
			if address == "fakedns" {
				return nil, fmt.Errorf("%s: fakedns requires a platform-owned module and explicit adaptation", where)
			}
			if unsafeSocketAddress(address) {
				return nil, fmt.Errorf("%s: local socket address requires explicit adaptation", where)
			}
		}
	}
	return tags, nil
}

// validateReferences examines known outbound reference names even inside a DNS
// overlay. It never treats ordinary DNS/inbound tags as outbound references.
func validateReferences(raw json.RawMessage, where string, outbounds map[string]bool, balancers map[string]balancer) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%s: invalid JSON", where)
	}
	var walk func(any, string) error
	walk = func(value any, path string) error {
		switch v := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				child := v[key]
				switch key {
				case "outboundTag", "dialerProxy":
					tag, ok := child.(string)
					if !ok || tag == "" || !outbounds[tag] {
						return fmt.Errorf("%s.%s: missing or invalid outbound reference", path, key)
					}
				case "balancerTag":
					tag, ok := child.(string)
					if _, exists := balancers[tag]; !ok || tag == "" || !exists {
						return fmt.Errorf("%s.%s: missing or invalid balancer reference", path, key)
					}
				case "proxySettings", "detour", "outboundTags", "proxyTag":
					return fmt.Errorf("%s.%s: unsupported reference form requires explicit adaptation", path, key)
				}
				if err := walk(child, path+"."+key); err != nil {
					return err
				}
			}
		case []any:
			for i, child := range v {
				if err := walk(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value, where)
}

func rejectUnknownDependencies(obj object, where string) error {
	// Only these two native chaining locations are supported. Detect likely
	// foreign-client reference fields rather than dropping them from the graph.
	var value any
	raw, _ := json.Marshal(obj)
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%s: invalid outbound JSON", where)
	}
	var walk func(any, string) error
	walk = func(value any, path string) error {
		switch v := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				childPath := path + "." + key
				switch key {
				case "detour", "outboundTag", "outboundTags", "balancerTag", "fallbackTag", "proxyTag":
					return fmt.Errorf("%s: unsupported outbound reference form", childPath)
				case "dialerProxy":
					if childPath != where+".streamSettings.sockopt.dialerProxy" {
						return fmt.Errorf("%s: unsupported dialerProxy location", childPath)
					}
				case "proxySettings":
					if childPath != where+".proxySettings" {
						return fmt.Errorf("%s: unsupported proxySettings location", childPath)
					}
				}
				if err := walk(v[key], childPath); err != nil {
					return err
				}
			}
		case []any:
			for i, child := range v {
				if err := walk(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value, where)
}

func rejectFileReferences(obj object, where string) error {
	var walk func(json.RawMessage, string) error
	walk = func(raw json.RawMessage, path string) error {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			return fmt.Errorf("%s: invalid JSON", path)
		}
		switch trimmed[0] {
		case '{':
			var nested object
			if err := json.Unmarshal(raw, &nested); err != nil {
				return fmt.Errorf("%s: invalid JSON object", path)
			}
			for _, key := range sortedKeys(nested) {
				child := nested[key]
				lower := strings.ToLower(key)
				if localFileKey(lower) {
					value, err := optionalString(child, path+"."+key)
					if err != nil {
						return err
					}
					if value != "" {
						return fmt.Errorf("%s.%s: external local files require explicit adaptation", path, key)
					}
				}
				if (lower == "address" || lower == "endpoint") && len(bytes.TrimSpace(child)) > 0 && bytes.TrimSpace(child)[0] == '"' {
					value, _ := optionalString(child, path+"."+key)
					if unsafeSocketAddress(value) {
						return fmt.Errorf("%s.%s: local socket address requires explicit adaptation", path, key)
					}
				}
				if err := walk(child, path+"."+key); err != nil {
					return err
				}
			}
		case '[':
			var nested []json.RawMessage
			if err := json.Unmarshal(raw, &nested); err != nil {
				return fmt.Errorf("%s: invalid JSON array", path)
			}
			for i, child := range nested {
				if err := walk(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	raw, _ := json.Marshal(obj)
	return walk(raw, where)
}

func localFileKey(key string) bool {
	switch key {
	case "script", "socketpath", "file", "certificatefile", "certificatechainfile", "keyfile", "cafile", "privatekeyfile", "publickeyfile", "passwordfile", "keylog", "keylogfile", "keylogpath", "masterkeylog":
		return true
	default:
		return false
	}
}

func validateGeoReferences(obj object, where string) error {
	for _, key := range sortedKeys(obj) {
		raw := bytes.TrimSpace(obj[key])
		switch key {
		case "domain", "domains", "ip", "source", "sourceIP", "localIP", "expectedIPs", "unexpectedIPs":
			if len(raw) == 0 || raw[0] != '[' {
				continue // Target-core validation handles general field types.
			}
			var items []json.RawMessage
			if err := json.Unmarshal(raw, &items); err != nil {
				return fmt.Errorf("%s.%s: invalid JSON array", where, key)
			}
			for _, item := range items {
				var value string
				if json.Unmarshal(item, &value) != nil {
					continue
				}
				parts := strings.SplitN(value, ":", 3)
				if len(parts) > 0 && (parts[0] == "ext" || strings.HasPrefix(parts[0], "ext-")) {
					if len(parts) != 3 || parts[0] != "ext" || parts[2] == "" || (parts[1] != "geoip.dat" && parts[1] != "geosite.dat") {
						return fmt.Errorf("%s.%s: custom GEO assets require explicit publication and adaptation", where, key)
					}
				}
			}
		}
		if len(raw) != 0 && raw[0] == '{' {
			var nested object
			if err := json.Unmarshal(raw, &nested); err != nil {
				return fmt.Errorf("%s.%s: invalid JSON object", where, key)
			}
			if err := validateGeoReferences(nested, where+"."+key); err != nil {
				return err
			}
		} else if len(raw) != 0 && raw[0] == '[' {
			var items []json.RawMessage
			if err := json.Unmarshal(raw, &items); err != nil {
				return fmt.Errorf("%s.%s: invalid JSON array", where, key)
			}
			for i, item := range items {
				trimmed := bytes.TrimSpace(item)
				if len(trimmed) != 0 && trimmed[0] == '{' {
					var nested object
					if err := json.Unmarshal(item, &nested); err != nil {
						return fmt.Errorf("%s.%s: invalid JSON object", where, key)
					}
					if err := validateGeoReferences(nested, fmt.Sprintf("%s.%s[%d]", where, key, i)); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func unsafeSocketAddress(value string) bool {
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") ||
		strings.HasPrefix(value, "../") || strings.HasPrefix(value, "@") ||
		strings.HasPrefix(value, "unix:") || strings.HasPrefix(value, "file:")
}

func readObject(raw []byte, where string) (object, error) {
	if err := validateJSON(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%s: expected JSON object", where)
	}
	var result object
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON object", where)
	}
	return result, nil
}

func readArray(raw []byte, where string) ([]json.RawMessage, error) {
	if err := validateJSON(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("%s: expected JSON array", where)
	}
	var result []json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON array", where)
	}
	return result, nil
}

func requiredString(raw json.RawMessage, where string) (string, error) {
	value, err := optionalString(raw, where)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("%s: nonempty string required", where)
	}
	return value, nil
}

func optionalString(raw json.RawMessage, where string) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", fmt.Errorf("%s: expected string", where)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s: invalid string", where)
	}
	return value, nil
}

func nonEmptyStrings(raw json.RawMessage, where string) ([]string, error) {
	items, err := readArray(raw, where)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%s: nonempty string array required", where)
	}
	result := make([]string, 0, len(items))
	for i, item := range items {
		value, err := requiredString(item, fmt.Sprintf("%s[%d]", where, i))
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func sortedKeys(obj object) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedBalancerKeys(values map[string]balancer) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// encoding/json accepts duplicate object keys. Reject them before adapting so
// validation and the target core cannot disagree about a shadowed field.
func validateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 128 {
			return fmt.Errorf("JSON nesting exceeds supported depth")
		}
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON")
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					keyToken, err := decoder.Token()
					if err != nil {
						return fmt.Errorf("invalid JSON object")
					}
					key, ok := keyToken.(string)
					if !ok {
						return fmt.Errorf("invalid JSON object key")
					}
					if seen[key] {
						return fmt.Errorf("duplicate JSON object key")
					}
					seen[key] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
					return fmt.Errorf("invalid JSON object")
				}
			case '[':
				for decoder.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
					return fmt.Errorf("invalid JSON array")
				}
			default:
				return fmt.Errorf("invalid JSON delimiter")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}
