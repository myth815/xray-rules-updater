package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/myth815/xray-rules-updater/internal/geodata"
)

// OneXrayFakeDNS opts into a platform-owned, two-pass OneXray runtime. Only
// pure native domain predicates of OutboundTag are projected into FakeDNS.
// Existing tagged DNS and outbounds must be explicitly retained by the overlay.
type OneXrayFakeDNS struct {
	OutboundTag    string `json:"outbound_tag"`
	DNSServerTag   string `json:"dns_server_tag"`
	DNSOutboundTag string `json:"dns_outbound_tag"`
}

const (
	oneXrayTunTag        = "tunIn"
	oneXrayOrdinaryTag   = "onexray-ordinary-sniff"
	oneXrayOrdinaryInTag = "onexray-ordinary-pass"
	oneXrayAIRuleTag     = "onexray-ai-outbound"
	oneXrayProtocolGuard = "onexray-fake-protocol-block"
	oneXrayIPGuard       = "onexray-fake-ip-block"
	oneXrayOrdinaryRule  = "onexray-ordinary-dispatch"
	oneXrayFakeIPv4Pool  = "198.19.0.0/16"
	oneXrayFakeIPv6Pool  = "fc00:1::/64"
)

// adaptOneXrayFakeDNS runs only after the normal adapter has validated input
// outbounds, their dependency closure and all retained rules. It never permits
// a baseline/extra loopback or baseline FakeDNS module through those checks.
func adaptOneXrayFakeDNS(baseline []byte, top object, selected map[string]bool, allOutbounds map[string]outbound, balancers map[string]balancer, cfg OneXrayFakeDNS) error {
	for _, tag := range []string{cfg.OutboundTag, cfg.DNSServerTag, cfg.DNSOutboundTag} {
		if tag == "" || strings.TrimSpace(tag) != tag || tag == "*" {
			return fmt.Errorf("requires exact nonempty outbound and DNS tags")
		}
	}
	if cfg.OutboundTag == cfg.DNSServerTag || cfg.OutboundTag == cfg.DNSOutboundTag || cfg.DNSServerTag == cfg.DNSOutboundTag {
		return fmt.Errorf("outbound and DNS tags must be distinct")
	}
	reserved := map[string]bool{oneXrayTunTag: true, oneXrayOrdinaryTag: true, oneXrayOrdinaryInTag: true}
	for tag := range reserved {
		if _, exists := allOutbounds[tag]; exists {
			return fmt.Errorf("generated platform tag conflicts with an existing outbound")
		}
		if _, exists := balancers[tag]; exists {
			return fmt.Errorf("generated platform tag conflicts with a balancer")
		}
	}
	for _, tag := range []string{cfg.OutboundTag, cfg.DNSServerTag, cfg.DNSOutboundTag} {
		if reserved[tag] {
			return fmt.Errorf("configured tag conflicts with generated platform ownership")
		}
	}
	for _, tag := range []string{cfg.OutboundTag, cfg.DNSOutboundTag, "block"} {
		if !selected[tag] {
			return fmt.Errorf("AI, DNS and block outbounds must already be retained")
		}
	}
	// Do not let a tag named after a country turn a direct or dropping outbound
	// into an apparent proxy. Geography still requires separate egress testing.
	aiOut, err := readObject(allOutbounds[cfg.OutboundTag].raw, "AI outbound")
	if err != nil {
		return err
	}
	aiProtocol, _ := requiredString(aiOut["protocol"], "AI outbound.protocol")
	if aiProtocol == "freedom" || aiProtocol == "dns" || aiProtocol == "blackhole" {
		return fmt.Errorf("AI outbound must be a proxy protocol")
	}
	block, err := readObject(allOutbounds["block"].raw, "block outbound")
	if err != nil {
		return err
	}
	blockProtocol, _ := requiredString(block["protocol"], "block outbound.protocol")
	if blockProtocol != "blackhole" || len(allOutbounds["block"].deps) != 0 {
		return fmt.Errorf("block must be an unchained blackhole outbound")
	}
	sets, err := DomainSetsFromOutbounds(baseline, []string{cfg.OutboundTag})
	if err != nil {
		return err
	}
	domains := sets[cfg.OutboundTag]
	// Three generated copies (dispatch, FakeDNS, non-IP DNS policy) share a
	// bounded aggregate budget rather than amplifying a large input predicate.
	if len(oneXrayJSON(domains)) > (4<<20)/3 {
		return fmt.Errorf("derived domain set exceeds aggregate 4 MiB injection limit")
	}
	dns, err := readObject(top["dns"], "dns")
	if err != nil {
		return err
	}
	servers, dnsTags, aiIndex, err := checkOneXrayDNS(dns, cfg.DNSServerTag, reserved, allOutbounds)
	if err != nil {
		return err
	}
	// Baseline listeners are never copied. Their reserved tags cannot silently
	// become the generated app-owned inlet or its virtual second pass.
	base, err := readObject(baseline, "baseline")
	if err != nil {
		return err
	}
	if raw, exists := base["inbounds"]; exists {
		entries, err := readArray(raw, "baseline.inbounds")
		if err != nil {
			return err
		}
		for _, raw := range entries {
			inbound, err := readObject(raw, "baseline inbound")
			if err != nil {
				return err
			}
			tag, err := optionalString(inbound["tag"], "baseline inbound.tag")
			if err != nil && len(inbound["tag"]) != 0 {
				return err
			}
			if reserved[tag] || dnsTags[tag] {
				return fmt.Errorf("baseline listener tag conflicts with platform or DNS ownership")
			}
		}
	}
	routing, err := readObject(top["routing"], "routing")
	if err != nil {
		return err
	}
	rules, err := readArray(routing["rules"], "routing.rules")
	if err != nil {
		return err
	}
	if err := checkOneXrayOrdinaryRouting(routing, rules); err != nil {
		return err
	}
	if err := checkOneXrayBalancerPrefixes(routing); err != nil {
		return err
	}
	dnsIntercept := -1
	for i, raw := range rules {
		rule, err := readObject(raw, "routing rule")
		if err != nil {
			return err
		}
		if rawTag, ok := rule["ruleTag"]; ok {
			tag, err := optionalString(rawTag, "routing rule.ruleTag")
			if err != nil {
				return err
			}
			if tag == oneXrayAIRuleTag || tag == oneXrayProtocolGuard || tag == oneXrayIPGuard || tag == oneXrayOrdinaryRule {
				return fmt.Errorf("generated rule tag conflicts with an existing rule")
			}
		}
		var outTag string
		_ = json.Unmarshal(rule["outboundTag"], &outTag)
		usesTun := false
		if rawTags, ok := rule["inboundTag"]; ok {
			tags, err := nonEmptyStrings(rawTags, "routing rule.inboundTag")
			if err != nil {
				return err
			}
			for _, tag := range tags {
				if tag == oneXrayOrdinaryTag || tag == oneXrayOrdinaryInTag {
					return fmt.Errorf("rule refers to a generated platform tag")
				}
				usesTun = usesTun || tag == oneXrayTunTag
			}
		}
		if usesTun || outTag == cfg.DNSOutboundTag {
			if !isOneXrayDNSIntercept(rule, cfg.DNSOutboundTag) || dnsIntercept != -1 {
				return fmt.Errorf("requires one exact tunIn TCP/UDP port-53 DNS interception rule")
			}
			dnsIntercept = i
		}
	}
	if dnsIntercept == -1 {
		return fmt.Errorf("requires one exact tunIn TCP/UDP port-53 DNS interception rule")
	}
	kept, err := readArray(top["outbounds"], "outbounds")
	if err != nil {
		return err
	}
	for i, raw := range kept {
		out, err := readObject(raw, "outbound")
		if err != nil {
			return err
		}
		// Native loopback sets Content.SkipDNSResolve, which also bypasses
		// proxyman's outbound targetStrategy resolution and ForceIP failure
		// behavior. Reject that strategy rather than silently changing ordinary
		// traffic. The transport's sockopt.domainStrategy and freedom's own
		// domainStrategy do not consult this flag and remain untouched.
		if raw, exists := out["targetStrategy"]; exists {
			strategy, err := optionalString(raw, "outbound.targetStrategy")
			if err != nil || (strategy != "" && strategy != "AsIs") {
				return fmt.Errorf("retained outbound targetStrategy requires explicit two-pass adaptation")
			}
		}
		var tag string
		_ = json.Unmarshal(out["tag"], &tag)
		if tag == cfg.DNSOutboundTag {
			if err := adaptOneXrayDNSOutbound(out, domains); err != nil {
				return err
			}
			kept[i] = oneXrayJSON(out)
		}
	}
	loopback := map[string]any{
		"tag": oneXrayOrdinaryTag, "protocol": "loopback",
		"settings": map[string]any{"inboundTag": oneXrayOrdinaryInTag, "sniffing": map[string]any{
			"enabled": true, "metadataOnly": false, "routeOnly": false, "destOverride": []string{"http", "tls", "quic"},
		}},
	}
	kept = append(kept, oneXrayJSON(loopback))
	newSelected := make(map[string]bool, len(selected)+1)
	for tag, value := range selected {
		newSelected[tag] = value
	}
	newSelected[oneXrayOrdinaryTag] = true
	prefix := []json.RawMessage{
		rules[dnsIntercept],
		oneXrayJSON(map[string]any{"type": "field", "domain": domains, "outboundTag": cfg.OutboundTag, "ruleTag": oneXrayAIRuleTag}),
		oneXrayJSON(map[string]any{"type": "field", "protocol": []string{"fakedns"}, "outboundTag": "block", "ruleTag": oneXrayProtocolGuard}),
		oneXrayJSON(map[string]any{"type": "field", "ip": []string{oneXrayFakeIPv4Pool, oneXrayFakeIPv6Pool}, "outboundTag": "block", "ruleTag": oneXrayIPGuard}),
		oneXrayJSON(map[string]any{"type": "field", "inboundTag": []string{oneXrayTunTag}, "outboundTag": oneXrayOrdinaryTag, "ruleTag": oneXrayOrdinaryRule}),
	}
	for i, raw := range rules {
		if i != dnsIntercept {
			prefix = append(prefix, raw)
		}
	}
	for i, raw := range prefix {
		if _, err := validateRule(raw, fmt.Sprintf("generated routing.rules[%d]", i), newSelected, balancers); err != nil {
			return err
		}
	}
	// Replace only the explicitly named AI DNS server, leaving ordinary server
	// objects in their relative order and retaining ordinary global DNS options.
	aiServer := oneXrayJSON(map[string]any{"address": "fakedns", "tag": cfg.DNSServerTag, "domains": domains, "finalQuery": true, "skipFallback": true})
	newServers := []json.RawMessage{aiServer}
	for i, raw := range servers {
		if i != aiIndex {
			newServers = append(newServers, raw)
		}
	}
	dns["servers"] = oneXrayJSON(newServers)
	routing["rules"] = oneXrayJSON(prefix)
	top["dns"], top["routing"], top["outbounds"] = oneXrayJSON(dns), oneXrayJSON(routing), oneXrayJSON(kept)
	// This explicit platform adapter selects the supported destination-isolated
	// UDP mode. Baseline env remains rejected; no arbitrary environment is copied.
	top["env"] = oneXrayJSON(map[string]string{"xray.cone.disabled": "true"})
	top["fakedns"] = oneXrayJSON([]any{
		map[string]any{"ipPool": oneXrayFakeIPv4Pool, "poolSize": 8192},
		map[string]any{"ipPool": oneXrayFakeIPv6Pool, "poolSize": 8192},
	})
	top["inbounds"] = oneXrayJSON([]any{map[string]any{
		"tag": oneXrayTunTag, "protocol": "tun",
		"sniffing": map[string]any{"enabled": true, "metadataOnly": true, "routeOnly": false, "destOverride": []string{"fakedns"}},
	}})
	return nil
}

func checkOneXrayDNS(dns object, aiTag string, reserved map[string]bool, outbounds map[string]outbound) ([]json.RawMessage, map[string]bool, int, error) {
	for key := range dns {
		switch key {
		case "servers", "hosts", "tag", "clientIp", "queryStrategy", "disableCache", "serveStale", "serveExpiredTTL", "disableFallback", "disableFallbackIfMatch", "enableParallelQuery", "useSystemHosts":
		default:
			return nil, nil, -1, fmt.Errorf("DNS field requires unsupported explicit adaptation")
		}
	}
	if raw, exists := dns["hosts"]; exists {
		hosts, err := readObject(raw, "dns.hosts")
		if err != nil || len(hosts) != 0 {
			return nil, nil, -1, fmt.Errorf("nonempty DNS hosts can bypass FakeDNS")
		}
	}
	for _, field := range []string{"disableFallback", "useSystemHosts"} {
		if raw, exists := dns[field]; exists && !bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
			return nil, nil, -1, fmt.Errorf("DNS %s must be absent or false", field)
		}
	}
	if raw, exists := dns["queryStrategy"]; exists {
		strategy, err := requiredString(raw, "dns.queryStrategy")
		if err != nil || (strategy != "UseIP" && strategy != "UseIPv4" && strategy != "UseIPv6") {
			return nil, nil, -1, fmt.Errorf("DNS queryStrategy requires explicit native IP mode")
		}
	}
	servers, err := readArray(dns["servers"], "dns.servers")
	if err != nil || len(servers) == 0 {
		return nil, nil, -1, fmt.Errorf("requires existing DNS servers and unique AI server tag")
	}
	tags := map[string]bool{}
	register := func(tag string) error {
		if tag == "" {
			return nil
		}
		if tags[tag] || reserved[tag] {
			return fmt.Errorf("DNS tag conflicts with DNS or platform ownership")
		}
		if _, exists := outbounds[tag]; exists {
			return fmt.Errorf("DNS tag conflicts with an outbound")
		}
		tags[tag] = true
		return nil
	}
	if raw, exists := dns["tag"]; exists {
		tag, err := optionalString(raw, "dns.tag")
		if err != nil {
			return nil, nil, -1, err
		}
		if err := register(tag); err != nil {
			return nil, nil, -1, err
		}
		if tag == aiTag {
			return nil, nil, -1, fmt.Errorf("AI DNS server tag cannot be the global DNS tag")
		}
	}
	aiIndex, ordinaryFallback := -1, false
	for i, raw := range servers {
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) {
			var address string
			_ = json.Unmarshal(raw, &address)
			if strings.EqualFold(address, "fakedns") {
				return nil, nil, -1, fmt.Errorf("ordinary DNS server cannot also allocate FakeDNS mappings")
			}
			ordinaryFallback = true
			continue
		}
		server, err := readObject(raw, "dns server")
		if err != nil {
			return nil, nil, -1, err
		}
		tag := ""
		if rawTag, exists := server["tag"]; exists {
			tag, err = optionalString(rawTag, "dns server.tag")
			if err != nil {
				return nil, nil, -1, err
			}
			if err := register(tag); err != nil {
				return nil, nil, -1, err
			}
		}
		if tag == aiTag {
			if !bytes.Equal(bytes.TrimSpace(server["skipFallback"]), []byte("true")) {
				return nil, nil, -1, fmt.Errorf("named AI DNS server must already skip ordinary fallback")
			}
			domains, err := nonEmptyStrings(server["domains"], "AI DNS server.domains")
			if err != nil {
				return nil, nil, -1, err
			}
			if err := geodata.ValidateDomainExpressions(domains); err != nil {
				return nil, nil, -1, err
			}
			aiIndex = i
		} else {
			var address string
			_ = json.Unmarshal(server["address"], &address)
			if strings.EqualFold(address, "fakedns") {
				return nil, nil, -1, fmt.Errorf("ordinary DNS server cannot also allocate FakeDNS mappings")
			}
			rawSkip, exists := server["skipFallback"]
			ordinaryFallback = ordinaryFallback || !exists || bytes.Equal(bytes.TrimSpace(rawSkip), []byte("false"))
		}
	}
	if aiIndex == -1 || !ordinaryFallback {
		return nil, nil, -1, fmt.Errorf("requires one named AI DNS server and a retained ordinary fallback server")
	}
	return servers, tags, aiIndex, nil
}

func adaptOneXrayDNSOutbound(out object, domains []string) error {
	protocol, _ := requiredString(out["protocol"], "DNS outbound.protocol")
	if protocol != "dns" {
		return fmt.Errorf("configured DNS outbound must use the dns protocol")
	}
	settings, err := readObject(out["settings"], "DNS outbound.settings")
	if err != nil {
		return err
	}
	for key := range settings {
		switch key {
		case "rules", "rewriteNetwork", "rewriteAddress", "rewritePort", "network", "address", "port", "userLevel":
		default:
			return fmt.Errorf("DNS outbound settings require unsupported explicit adaptation")
		}
	}
	rules, err := readArray(settings["rules"], "DNS outbound.rules")
	if err != nil || len(rules) != 2 {
		return fmt.Errorf("DNS outbound requires exact A/AAAA hijack and default direct rules")
	}
	first, err := readObject(rules[0], "DNS hijack rule")
	if err != nil {
		return err
	}
	last, err := readObject(rules[1], "DNS direct rule")
	if err != nil {
		return err
	}
	var action, qtype, lastAction string
	_ = json.Unmarshal(first["action"], &action)
	_ = json.Unmarshal(first["qType"], &qtype)
	_ = json.Unmarshal(last["action"], &lastAction)
	if len(first) != 2 || action != "hijack" || (qtype != "1,28" && qtype != "28,1") || len(last) != 1 || lastAction != "direct" {
		return fmt.Errorf("DNS outbound requires exact A/AAAA hijack and default direct rules")
	}
	settings["rules"] = oneXrayJSON([]json.RawMessage{rules[0], oneXrayJSON(map[string]any{"domain": domains, "action": "return", "rCode": 0}), rules[1]})
	out["settings"] = oneXrayJSON(settings)
	return nil
}

func isOneXrayDNSIntercept(rule object, outTag string) bool {
	for key := range rule {
		switch key {
		case "type", "ruleTag", "inboundTag", "port", "network", "outboundTag":
		default:
			return false
		}
	}
	var target, port, network string
	_ = json.Unmarshal(rule["outboundTag"], &target)
	_ = json.Unmarshal(rule["port"], &port)
	if port == "" && bytes.Equal(bytes.TrimSpace(rule["port"]), []byte("53")) {
		port = "53"
	}
	tags, err := nonEmptyStrings(rule["inboundTag"], "DNS interception inboundTag")
	if err != nil || len(tags) != 1 || tags[0] != oneXrayTunTag || port != "53" || target != outTag {
		return false
	}
	if raw, exists := rule["network"]; exists {
		_ = json.Unmarshal(raw, &network)
		return network == "tcp,udp" || network == "udp,tcp"
	}
	return true
}

func checkOneXrayOrdinaryRouting(routing object, rules []json.RawMessage) error {
	strategy := "AsIs"
	if raw, exists := routing["domainStrategy"]; exists {
		var err error
		strategy, err = requiredString(raw, "routing.domainStrategy")
		if err != nil {
			return err
		}
	}
	if strategy == "AsIs" {
		return nil
	}
	if strategy != "IPIfNonMatch" {
		return fmt.Errorf("routing strategy requires explicit two-pass adaptation")
	}
	// Native loopback marks its new context SkipDNSResolve. A guaranteed native
	// TCP+UDP catchall proves the original IPIfNonMatch lookup was unreachable;
	// otherwise silently disabling it would change ordinary business routing.
	for _, raw := range rules {
		rule, err := readObject(raw, "routing rule")
		if err != nil {
			return err
		}
		pure := true
		for key := range rule {
			switch key {
			case "type", "ruleTag", "network", "outboundTag", "balancerTag":
			default:
				pure = false
			}
		}
		var network string
		_ = json.Unmarshal(rule["network"], &network)
		if pure && (network == "tcp,udp" || network == "udp,tcp") {
			return nil
		}
	}
	return fmt.Errorf("IPIfNonMatch requires an existing unconditional TCP/UDP catchall to preserve ordinary lookup semantics")
}

func checkOneXrayBalancerPrefixes(routing object) error {
	raw, exists := routing["balancers"]
	if !exists {
		return nil
	}
	entries, err := readArray(raw, "routing.balancers")
	if err != nil {
		return err
	}
	for _, raw := range entries {
		entry, err := readObject(raw, "balancer")
		if err != nil {
			return err
		}
		selectors, err := nonEmptyStrings(entry["selector"], "balancer.selector")
		if err != nil {
			return err
		}
		for _, prefix := range selectors {
			if strings.HasPrefix(oneXrayOrdinaryTag, prefix) {
				return fmt.Errorf("generated loopback would expand an existing balancer selector")
			}
		}
	}
	return nil
}

// Only already-validated JSON trees and scalar platform constants reach here.
func oneXrayJSON(value any) json.RawMessage {
	raw, _ := json.Marshal(value)
	return raw
}
