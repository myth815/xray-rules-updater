package syncer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode"
)

const businessDirectFilename = "routeros-business-direct.json"
const businessDirectMaxBytes = 16 << 10
const businessDirectMaxEntries = 128
const businessDirectMaxAddresses = 65536

// RouterOSBusinessDirect is an explicit operator-approved projection, never a
// GEO/DNS expansion. Attestation is a human assertion, not proof that an IP is
// unshared or that moving classification ahead of domain routing is equivalent.
type RouterOSBusinessDirect struct {
	OutboundTag string                   `json:"outbound_tag"`
	Approved    []BusinessDirectApproval `json:"approved"`
}

type BusinessDirectApproval struct {
	CIDR                                 string `json:"cidr"`
	Reason                               string `json:"reason"`
	ExclusiveBusinessOperatorAttestation bool   `json:"exclusive_business_operator_attestation"`
	BaselineRuleSHA256                   string `json:"baseline_rule_sha256"`
}

// Explicit opt-in inputs reject duplicate keys as well as unknown fields.
func (c *RouterOSBusinessDirect) UnmarshalJSON(b []byte) error {
	type plain RouterOSBusinessDirect
	var value plain
	if err := decodeBusinessInput(b, &value, "outbound_tag", "approved"); err != nil {
		return err
	}
	*c = RouterOSBusinessDirect(value)
	return nil
}

func (a *BusinessDirectApproval) UnmarshalJSON(b []byte) error {
	type plain BusinessDirectApproval
	var value plain
	if err := decodeBusinessInput(b, &value, "cidr", "reason", "exclusive_business_operator_attestation", "baseline_rule_sha256"); err != nil {
		return err
	}
	*a = BusinessDirectApproval(value)
	return nil
}

func decodeBusinessInput(b []byte, target any, fieldNames ...string) error {
	if len(b) > businessDirectMaxBytes || checkBusinessJSON(b) != nil {
		return errors.New("RouterOS business direct: invalid input")
	}
	// encoding/json falls back to case-insensitive struct-field matching even
	// with DisallowUnknownFields. Require the exact decoded schema names for
	// these two new objects, so aliases cannot overwrite approval evidence.
	var object map[string]json.RawMessage
	if json.Unmarshal(b, &object) != nil || object == nil {
		return errors.New("RouterOS business direct: invalid input object")
	}
	for key := range object {
		known := false
		for _, name := range fieldNames {
			if key == name {
				known = true
				break
			}
		}
		if !known {
			return errors.New("RouterOS business direct: unknown or invalid input field")
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return errors.New("RouterOS business direct: unknown or invalid input field")
	}
	return nil
}

// Public unicast alone is insufficient: reject every covered special-purpose
// range, including both benchmark/FakeDNS pools. No external address database is
// used to infer new approvals. The hard aggregate cap also rejects broad routes.
var businessDirectExcluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
}

func validateBusinessDirect(c RouterOSBusinessDirect) error {
	if !identifier.MatchString(c.OutboundTag) || len(c.Approved) > businessDirectMaxEntries {
		return errors.New("RouterOS business direct: invalid tag or approval count")
	}
	var prefixes []netip.Prefix
	var addresses uint64
	for i, a := range c.Approved {
		fail := func() error { return fmt.Errorf("RouterOS business direct: invalid approval %d", i) }
		p, err := netip.ParsePrefix(a.CIDR)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != a.CIDR || p.Bits() < 16 {
			return fail()
		}
		for _, excluded := range businessDirectExcluded {
			if p.Overlaps(excluded) {
				return fail()
			}
		}
		for _, previous := range prefixes {
			if p.Overlaps(previous) {
				return fail()
			}
		}
		addresses += uint64(1) << (32 - p.Bits())
		if addresses > businessDirectMaxAddresses || !a.ExclusiveBusinessOperatorAttestation ||
			len(a.BaselineRuleSHA256) != 64 || !digest.MatchString(a.BaselineRuleSHA256) || strings.ToLower(a.BaselineRuleSHA256) != a.BaselineRuleSHA256 ||
			a.Reason == "" || a.Reason != strings.TrimSpace(a.Reason) || len(a.Reason) > 256 {
			return fail()
		}
		for _, r := range a.Reason {
			if unicode.IsControl(r) {
				return fail()
			}
		}
		prefixes = append(prefixes, p)
	}
	return nil
}

func generateBusinessDirect(baseline []byte, c *RouterOSBusinessDirect) ([]byte, error) {
	if c == nil {
		return nil, nil
	}
	if err := validateBusinessDirect(*c); err != nil {
		return nil, err
	}
	if err := checkBusinessJSON(baseline); err != nil {
		return nil, errors.New("RouterOS business direct: invalid baseline JSON")
	}
	var top struct {
		Outbounds []map[string]json.RawMessage `json:"outbounds"`
		FakeDNS   json.RawMessage              `json:"fakedns"`
		Routing   struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"routing"`
	}
	if json.Unmarshal(baseline, &top) != nil {
		return nil, errors.New("RouterOS business direct: invalid baseline")
	}
	if err := checkBusinessSyntheticPools(top.FakeDNS, c.Approved); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var direct map[string]json.RawMessage
	for _, out := range top.Outbounds {
		var tag string
		if json.Unmarshal(out["tag"], &tag) != nil || tag == "" || seen[tag] {
			return nil, errors.New("RouterOS business direct: invalid outbound identity")
		}
		seen[tag] = true
		if tag == c.OutboundTag {
			direct = out
		}
	}
	if err := plainBusinessFreedom(direct); err != nil {
		return nil, err
	}
	type ruleProof struct {
		prefixes map[string]bool
		count    int
	}
	proofs := map[string]ruleProof{}
	for _, raw := range top.Routing.Rules {
		var rule map[string]json.RawMessage
		if json.Unmarshal(raw, &rule) != nil {
			return nil, errors.New("RouterOS business direct: invalid baseline rule")
		}
		// Normalize JSON string escapes as well as object-key order; the proof
		// is the canonical rule object, not a particular source formatting.
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return nil, errors.New("RouterOS business direct: invalid baseline rule")
		}
		canonical, _ := json.Marshal(value)
		sha := hash(canonical)
		proof := proofs[sha]
		proof.count++
		proof.prefixes = pureBusinessIPRule(rule, c.OutboundTag)
		proofs[sha] = proof
	}
	for i, approval := range c.Approved {
		proof := proofs[approval.BaselineRuleSHA256]
		if proof.count != 1 || !proof.prefixes[approval.CIDR] {
			return nil, fmt.Errorf("RouterOS business direct: approval %d lacks a unique exact baseline rule", i)
		}
	}
	approved := append([]BusinessDirectApproval{}, c.Approved...)
	body, err := json.MarshalIndent(struct {
		SchemaVersion  int                      `json:"schema_version"`
		BaselineSHA256 string                   `json:"baseline_sha256"`
		OutboundTag    string                   `json:"outbound_tag"`
		Approved       []BusinessDirectApproval `json:"approved"`
		Activation     string                   `json:"activation"`
	}{1, hash(baseline), c.OutboundTag, approved, "data only; no RouterOS rules or address lists are applied"}, "", "  ")
	if err != nil || len(body)+1 > businessDirectMaxBytes {
		return nil, errors.New("RouterOS business direct: output size limit exceeded")
	}
	return append(body, '\n'), nil
}

func checkBusinessSyntheticPools(raw json.RawMessage, approved []BusinessDirectApproval) error {
	if len(raw) == 0 {
		return nil
	}
	var pools []struct {
		IPPool string `json:"ipPool"`
	}
	if json.Unmarshal(raw, &pools) != nil || pools == nil {
		return errors.New("RouterOS business direct: unsupported synthetic pool declaration")
	}
	for _, pool := range pools {
		p, err := netip.ParsePrefix(pool.IPPool)
		if err != nil || p != p.Masked() {
			return errors.New("RouterOS business direct: invalid synthetic pool")
		}
		for _, a := range approved {
			approvedPrefix, _ := netip.ParsePrefix(a.CIDR)
			if p.Overlaps(approvedPrefix) {
				return errors.New("RouterOS business direct: approval intersects a synthetic pool")
			}
		}
	}
	return nil
}

func plainBusinessFreedom(out map[string]json.RawMessage) error {
	fail := errors.New("RouterOS business direct: outbound is not plain native freedom")
	var protocol string
	if out == nil || json.Unmarshal(out["protocol"], &protocol) != nil || protocol != "freedom" {
		return fail
	}
	for key, raw := range out {
		switch key {
		case "tag", "protocol":
		case "targetStrategy":
			var strategy string
			if json.Unmarshal(raw, &strategy) != nil || strategy != "AsIs" {
				return fail
			}
		case "settings", "streamSettings":
			var settings map[string]json.RawMessage
			if json.Unmarshal(raw, &settings) != nil || settings == nil {
				return fail
			}
			for setting, value := range settings {
				var strategy string
				if key != "settings" || setting != "domainStrategy" || json.Unmarshal(value, &strategy) != nil || strategy != "AsIs" {
					return fail
				}
			}
		default:
			return fail
		}
	}
	return nil
}

func pureBusinessIPRule(rule map[string]json.RawMessage, tag string) map[string]bool {
	if len(rule) != 3 {
		return nil
	}
	var ruleType, outbound string
	var ips []string
	if json.Unmarshal(rule["type"], &ruleType) != nil || ruleType != "field" ||
		json.Unmarshal(rule["outboundTag"], &outbound) != nil || outbound != tag ||
		json.Unmarshal(rule["ip"], &ips) != nil || len(ips) == 0 {
		return nil
	}
	prefixes := map[string]bool{}
	for _, ip := range ips {
		p, err := netip.ParsePrefix(ip)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != ip || prefixes[ip] {
			return nil
		}
		prefixes[ip] = true
	}
	return prefixes
}

func checkBusinessJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, err := d.Token()
				key, ok := token.(string)
				if err != nil || !ok || seen[key] {
					return errors.New("ambiguous JSON object")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
