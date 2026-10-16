package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/myth815/xray-rules-updater/internal/geodata"
)

var managedGeoIPName = regexp.MustCompile(`^home_geoip_[0-9a-f]{64}\.dat$`)
var managedGeoSiteName = regexp.MustCompile(`^home_geosite_[0-9a-f]{64}\.dat$`)
var managedGeoCode = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_!.-]*$`)

// BindNativeGeoAssets binds an already-validated client policy to immutable,
// content-addressed DAT filenames without expanding any GEO collection. Callers
// must first validate the original references against the exact DAT bytes and
// derive the supplied filenames from those bytes' full lowercase SHA256.
//
// Only routing.rules[].domain/ip and dns.servers[].domains are adapted. Known
// GEO-bearing fields outside that scope reject GEO references rather than leave
// a policy partly bound. Credential, endpoint and arbitrary metadata strings
// are never searched or rewritten. Existing ext references must already name
// the corresponding managed asset, making a second binding idempotent.
func BindNativeGeoAssets(raw []byte, geoipName, geositeName string) ([]byte, error) {
	if !managedGeoIPName.MatchString(geoipName) || !managedGeoSiteName.MatchString(geositeName) {
		return nil, fmt.Errorf("managed GEO: filenames must use home_geoip_/home_geosite_ plus full lowercase SHA256 and .dat")
	}
	top, err := readObject(raw, "managed GEO client")
	if err != nil {
		return nil, err
	}
	if raw, ok := top["routing"]; ok {
		routing, err := readObject(raw, "routing")
		if err != nil {
			return nil, err
		}
		if raw, ok := routing["rules"]; ok {
			rules, err := readArray(raw, "routing.rules")
			if err != nil {
				return nil, err
			}
			for i, raw := range rules {
				where := fmt.Sprintf("routing.rules[%d]", i)
				rule, err := readObject(raw, where)
				if err != nil {
					return nil, err
				}
				for _, field := range []string{"domain", "ip"} {
					if raw, ok := rule[field]; ok {
						rule[field], err = bindManagedGeoList(raw, field == "ip", geoipName, geositeName, where+"."+field)
						if err != nil {
							return nil, err
						}
					}
				}
				for _, field := range []string{"source", "sourceIP", "localIP"} {
					if raw, ok := rule[field]; ok {
						if err := rejectUnboundGeoList(raw, where+"."+field); err != nil {
							return nil, err
						}
					}
				}
				rules[i] = oneXrayJSON(rule)
			}
			routing["rules"] = oneXrayJSON(rules)
		}
		top["routing"] = oneXrayJSON(routing)
	}
	if raw, ok := top["dns"]; ok {
		dns, err := readObject(raw, "dns")
		if err != nil {
			return nil, err
		}
		if raw, ok := dns["hosts"]; ok {
			hosts, err := readObject(raw, "dns.hosts")
			if err != nil {
				return nil, err
			}
			for key := range hosts {
				if managedGeoReference(key) {
					return nil, fmt.Errorf("dns.hosts: GEO keys require explicit managed asset adaptation")
				}
			}
		}
		if raw, ok := dns["servers"]; ok {
			servers, err := readArray(raw, "dns.servers")
			if err != nil {
				return nil, err
			}
			for i, raw := range servers {
				if bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) {
					continue
				}
				where := fmt.Sprintf("dns.servers[%d]", i)
				server, err := readObject(raw, where)
				if err != nil {
					return nil, err
				}
				if raw, ok := server["domains"]; ok {
					server["domains"], err = bindManagedGeoList(raw, false, geoipName, geositeName, where+".domains")
					if err != nil {
						return nil, err
					}
				}
				for _, field := range []string{"expectedIPs", "expectIPs", "unexpectedIPs"} {
					if raw, ok := server[field]; ok {
						if err := rejectUnboundGeoList(raw, where+"."+field); err != nil {
							return nil, err
						}
					}
				}
				servers[i] = oneXrayJSON(server)
			}
			dns["servers"] = oneXrayJSON(servers)
		}
		top["dns"] = oneXrayJSON(dns)
	}
	if err := rejectOtherManagedGeoFields(top); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("managed GEO: encode client: %w", err)
	}
	return append(encoded, '\n'), nil
}

func bindManagedGeoList(raw json.RawMessage, ip bool, geoipName, geositeName, where string) (json.RawMessage, error) {
	return mapManagedGeoList(raw, where, func(value string) (string, error) {
		prefix := ""
		if ip {
			trimmed := strings.TrimLeft(value, "!")
			prefix, value = value[:len(value)-len(trimmed)], trimmed
		}
		name, native := geositeName, "geosite:"
		if ip {
			name, native = geoipName, "geoip:"
		}
		selector := ""
		if strings.HasPrefix(value, native) {
			selector = strings.TrimPrefix(value, native)
		} else if strings.HasPrefix(value, "ext:"+name+":") {
			selector = strings.TrimPrefix(value, "ext:"+name+":")
		} else if managedGeoReference(value) {
			return "", fmt.Errorf("%s: unknown or wrong-type GEO asset reference", where)
		} else {
			return prefix + value, nil
		}
		if ip {
			if !managedGeoCode.MatchString(strings.TrimLeft(selector, "!")) {
				return "", fmt.Errorf("%s: invalid GeoIP selector", where)
			}
		} else if err := geodata.ValidateDomainExpressions([]string{"geosite:" + selector}); err != nil {
			return "", fmt.Errorf("%s: invalid GeoSite selector", where)
		}
		return prefix + "ext:" + name + ":" + selector, nil
	})
}

func managedGeoReference(value string) bool {
	value = strings.TrimLeft(value, "!")
	for _, prefix := range []string{"geoip:", "geosite:", "ext:", "ext-ip:", "ext-domain:", "ext-site:"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func rejectUnboundGeoList(raw json.RawMessage, where string) error {
	_, err := mapManagedGeoList(raw, where, func(value string) (string, error) {
		if managedGeoReference(value) {
			return "", fmt.Errorf("%s: GEO references require explicit managed asset adaptation", where)
		}
		return value, nil
	})
	return err
}

func mapManagedGeoList(raw json.RawMessage, where string, transform func(string) (string, error)) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return raw, nil
	}
	if bytes.HasPrefix(trimmed, []byte(`"`)) {
		value, err := optionalString(raw, where)
		if err != nil {
			return nil, err
		}
		value, err = transform(value)
		if err != nil {
			return nil, err
		}
		return oneXrayJSON(value), nil
	}
	items, err := readArray(raw, where)
	if err != nil {
		return nil, err
	}
	for i, raw := range items {
		value, err := optionalString(raw, where)
		if err != nil {
			return nil, err
		}
		value, err = transform(value)
		if err != nil {
			return nil, err
		}
		items[i] = oneXrayJSON(value)
	}
	return oneXrayJSON(items), nil
}

func rejectOtherManagedGeoFields(top object) error {
	for _, key := range []string{"inbounds", "outbounds"} {
		raw, ok := top[key]
		if !ok {
			continue
		}
		entries, err := readArray(raw, key)
		if err != nil {
			return err
		}
		for i, raw := range entries {
			where := fmt.Sprintf("%s[%d]", key, i)
			entry, err := readObject(raw, where)
			if err != nil {
				return err
			}
			if key == "inbounds" {
				if raw, ok := entry["sniffing"]; ok {
					sniffing, err := readObject(raw, where+".sniffing")
					if err != nil {
						return err
					}
					for _, field := range []string{"domainsExcluded", "ipsExcluded"} {
						if raw, ok := sniffing[field]; ok {
							if err := rejectUnboundGeoList(raw, where+".sniffing."+field); err != nil {
								return err
							}
						}
					}
				}
				continue
			}
			var protocol string
			_ = json.Unmarshal(entry["protocol"], &protocol)
			if protocol != "dns" {
				continue
			}
			if raw, ok := entry["settings"]; ok {
				settings, err := readObject(raw, where+".settings")
				if err != nil {
					return err
				}
				if raw, ok := settings["rules"]; ok {
					rules, err := readArray(raw, where+".settings.rules")
					if err != nil {
						return err
					}
					for _, raw := range rules {
						rule, err := readObject(raw, where+".settings.rules[]")
						if err != nil {
							return err
						}
						if raw, ok := rule["domain"]; ok {
							if err := rejectUnboundGeoList(raw, where+".settings.rules[].domain"); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}
