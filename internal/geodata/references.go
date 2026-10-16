package geodata

import (
	"fmt"
	"strings"
)

// ValidateReferences validates required native DAT references without expanding
// them into client JSON. A negated GeoIP reference validates its underlying
// category; no complement is generated. Custom ext: resources are rejected
// because this publisher has no declared asset for them. Required references
// must select at least one item, including after GeoSite attribute filtering.
func ValidateReferences(geoip, geosite []byte, refs []string) error {
	sites, ips := map[string][]selector{}, map[string]bool{}
	for _, ref := range refs {
		switch {
		case strings.HasPrefix(ref, "geosite:"):
			s, err := parseSelector(strings.TrimPrefix(ref, "geosite:"), true)
			if err != nil {
				return fmt.Errorf("GEO reference %q: %w", ref, err)
			}
			sites[s.code] = append(sites[s.code], s)
		case strings.HasPrefix(ref, "geoip:"):
			value := strings.TrimPrefix(ref, "geoip:")
			value = strings.TrimPrefix(value, "!")
			s, err := parseSelector(value, false)
			if err != nil {
				return fmt.Errorf("GEO reference %q: %w", ref, err)
			}
			ips[s.code] = true
		default:
			return fmt.Errorf("unsupported GEO reference %q; only native geoip:/geosite: resources are published", ref)
		}
	}
	if len(sites) > 0 {
		wanted := map[string]bool{}
		for code := range sites {
			wanted[code] = true
		}
		raw, err := entries(geosite, wanted)
		if err != nil {
			return fmt.Errorf("geosite.dat references: %w", err)
		}
		for code, selectors := range sites {
			matched := make([]bool, len(selectors))
			err := walk(raw[code], func(f wireField) error {
				if f.number != 2 {
					return nil
				}
				if err := expectWire(f, 2); err != nil {
					return err
				}
				d, err := readDomain(f.bytes)
				if err != nil {
					return err
				}
				for i, s := range selectors {
					matched[i] = matched[i] || matchesAttrs(d.attrs, s.attrs)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("geosite category %q: %w", code, err)
			}
			for i, s := range selectors {
				if !matched[i] {
					return fmt.Errorf("required geosite selector %q is empty", strings.Join(append([]string{s.code}, s.attrs...), "@"))
				}
			}
		}
	}
	if len(ips) > 0 {
		raw, err := entries(geoip, ips)
		if err != nil {
			return fmt.Errorf("geoip.dat references: %w", err)
		}
		for code, entry := range raw {
			count := 0
			err := walk(entry, func(f wireField) error {
				switch f.number {
				case 2:
					if err := expectWire(f, 2); err != nil {
						return err
					}
					if _, err := readCIDR(f.bytes); err != nil {
						return err
					}
					count++
				case 3:
					if err := expectWire(f, 0); err != nil {
						return err
					}
					if f.value != 0 {
						return fmt.Errorf("reverse GeoIP DAT entry is unsupported")
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("geoip category %q: %w", code, err)
			}
			if count == 0 {
				return fmt.Errorf("required geoip category %q is empty", code)
			}
		}
	}
	return nil
}
