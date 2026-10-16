// Package geodata derives explicitly selected address data from native Xray
// DAT files. It does not translate arbitrary Xray routing policies or enable
// RouterOS routing, NAT, firewall, or FastTrack rules.
package geodata

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

type Result struct {
	Files  map[string][]byte
	Counts map[string]int
}

type selector struct {
	code  string
	attrs []string
}

type attribute struct {
	key       string
	kind      uint64 // 0: no typed value, 2: bool, 3: signed int64.
	boolValue bool
	intValue  int64
}

type domain struct {
	kind  uint64
	value string
	attrs []attribute
}

var token = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var categoryToken = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_!.-]*$`)

// ErrExportLimit reports rejection before an output grows beyond its file or
// aggregate budget. Callers may distinguish resource admission from bad data.
var ErrExportLimit = errors.New("export exceeds file or publication size limit")

type exportBudget struct {
	maxFile, maxTotal, total int64
}

func (b *exportBudget) add(fileSize, bytes int64) error {
	if bytes < 0 || fileSize > b.maxFile-bytes || b.total > b.maxTotal-bytes {
		return ErrExportLimit
	}
	b.total += bytes
	return nil
}

// MosDNS strips # comments before parsing domain-set lines. Escaping a regexp
// cannot preserve that earlier text transformation, so reject rather than widen
// a matcher. Native DAT parsing remains independent of this text-only guard.
func validMosDNSDomainLine(line string) error {
	if strings.ContainsRune(line, '#') {
		return fmt.Errorf("domain matcher contains an unrepresentable MosDNS comment delimiter")
	}
	return nil
}

// Export maps output relative filenames to DAT selectors. GeoSite selectors
// support code@attribute@attribute (AND). As in Xray v26.3.27's
// infra/conf/router.go BooleanMatcher, matching checks attribute key presence,
// not the bool/int value. Negation and value comparisons are not supported.
// A present category with no matching attributes produces an empty file;
// callers decide whether that empty result is acceptable for their policy.
func Export(geoip, geosite []byte, sites map[string]string, ips map[string]string, routerList string) (*Result, error) {
	return ExportBounded(geoip, geosite, sites, ips, routerList, 128<<20, 128<<20)
}

// ExportBounded charges selected output lines before inserting or materializing
// them. Every MosDNS file and the optional RouterOS candidate share one budget.
func ExportBounded(geoip, geosite []byte, sites map[string]string, ips map[string]string, routerList string, maxFileBytes, maxTotalBytes int64) (*Result, error) {
	if maxFileBytes < 1 || maxFileBytes > 128<<20 || maxTotalBytes < 1 || len(sites)+len(ips) > 128 {
		return nil, fmt.Errorf("invalid export limits")
	}
	budget := exportBudget{maxFile: maxFileBytes, maxTotal: maxTotalBytes}
	r := &Result{Files: map[string][]byte{}, Counts: map[string]int{}}
	siteSelectors, ipSelectors := map[string]selector{}, map[string]selector{}
	wantedSites, wantedIPs := map[string]bool{}, map[string]bool{}
	for filename, value := range sites {
		if err := validFilename(filename); err != nil {
			return nil, err
		}
		s, err := parseSelector(value, true)
		if err != nil {
			return nil, fmt.Errorf("site %q: %w", filename, err)
		}
		siteSelectors[filename], wantedSites[s.code] = s, true
	}
	for filename, value := range ips {
		if err := validFilename(filename); err != nil {
			return nil, err
		}
		if _, exists := sites[filename]; exists {
			return nil, fmt.Errorf("duplicate output filename %q", filename)
		}
		s, err := parseSelector(value, false)
		if err != nil {
			return nil, fmt.Errorf("IP %q: %w", filename, err)
		}
		ipSelectors[filename], wantedIPs[s.code] = s, true
	}
	if routerList != "" {
		if len(routerList) > 64 || !token.MatchString(routerList) {
			return nil, fmt.Errorf("invalid RouterOS candidate list name")
		}
		if _, exists := sites["routeros-cn-v4.rsc"]; exists {
			return nil, fmt.Errorf("reserved output filename routeros-cn-v4.rsc")
		}
		if _, exists := ips["routeros-cn-v4.rsc"]; exists {
			return nil, fmt.Errorf("reserved output filename routeros-cn-v4.rsc")
		}
		wantedIPs["cn"] = true
	}
	var siteData map[string][]domain
	var ipData map[string][]netip.Prefix
	var err error
	if len(wantedSites) > 0 {
		siteData, err = readSites(geosite, wantedSites)
		if err != nil {
			return nil, fmt.Errorf("geosite.dat: %w", err)
		}
	}
	if len(wantedIPs) > 0 {
		ipData, err = readIPs(geoip, wantedIPs)
		if err != nil {
			return nil, fmt.Errorf("geoip.dat: %w", err)
		}
	}
	for filename, s := range siteSelectors {
		unique := map[string]bool{}
		var size int64
		for _, d := range siteData[s.code] {
			if matchesAttrs(d.attrs, s.attrs) {
				prefix := [...]string{"keyword:", "regexp:", "domain:", "full:"}[d.kind]
				line := prefix + d.value
				if err := validMosDNSDomainLine(line); err != nil {
					return nil, err
				}
				if !unique[line] {
					n := int64(len(line)) + 1
					if err := budget.add(size, n); err != nil {
						return nil, err
					}
					unique[line], size = true, size+n
				}
			}
		}
		lines := make([]string, 0, len(unique))
		for line := range unique {
			lines = append(lines, line)
		}
		sort.Strings(lines)
		r.Files[filename], r.Counts[filename] = textLines(lines), len(lines)
	}
	for filename, s := range ipSelectors {
		prefixes := ipData[s.code]
		var lines []string
		var size int64
		for _, p := range prefixes {
			line := p.String()
			n := int64(len(line)) + 1
			if err := budget.add(size, n); err != nil {
				return nil, err
			}
			lines, size = append(lines, line), size+n
		}
		r.Files[filename], r.Counts[filename] = textLines(lines), len(lines)
	}
	if routerList != "" {
		cn := ipData["cn"]
		v4Count := 0
		for _, p := range cn {
			if p.Addr().Is4() {
				if p.Bits() < 8 {
					return nil, fmt.Errorf("CN IPv4 prefix %s is too broad", p)
				}
				v4Count++
			}
		}
		if v4Count == 0 {
			return nil, fmt.Errorf("CN IPv4 candidate is empty")
		}
		var b strings.Builder
		add := func(line string) error {
			if err := budget.add(int64(b.Len()), int64(len(line))); err != nil {
				return err
			}
			b.WriteString(line)
			return nil
		}
		for _, line := range []string{
			"# Candidate address data only; no routing rules are enabled.\n",
			fmt.Sprintf(":if ([:len [/ip firewall address-list find where list=\"%s\"]] > 0) do={:error \"Candidate list already exists\"}\n", routerList),
			"/ip firewall address-list\n",
		} {
			if err := add(line); err != nil {
				return nil, err
			}
		}
		for _, p := range cn {
			if p.Addr().Is4() {
				if err := add(fmt.Sprintf("add list=%s address=%s comment=\"xray-rules-updater candidate\"\n", routerList, p)); err != nil {
					return nil, err
				}
			}
		}
		r.Files["routeros-cn-v4.rsc"] = []byte(b.String())
		r.Counts["routeros-cn-v4.rsc"] = v4Count
	}
	return r, nil
}

func validFilename(filename string) error {
	if filename == "" || filename == "." || filename == ".." || path.IsAbs(filename) || path.Clean(filename) != filename || strings.HasPrefix(filename, "../") || strings.ContainsAny(filename, "\\\r\n\x00") {
		return fmt.Errorf("invalid output relative filename %q", filename)
	}
	return nil
}

func parseSelector(value string, allowAttrs bool) (selector, error) {
	parts := strings.Split(value, "@")
	if !categoryToken.MatchString(parts[0]) || (!allowAttrs && (len(parts) != 1 || strings.Contains(parts[0], "!"))) {
		return selector{}, fmt.Errorf("unsupported selector %q", value)
	}
	s := selector{code: strings.ToLower(parts[0])}
	for _, attr := range parts[1:] {
		if !token.MatchString(attr) {
			return selector{}, fmt.Errorf("unsupported attribute selector %q", value)
		}
		s.attrs = append(s.attrs, strings.ToLower(attr))
	}
	return s, nil
}

func textLines(lines []string) []byte {
	if len(lines) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func matchesAttrs(attrs []attribute, wanted []string) bool {
	for _, key := range wanted {
		found := false
		for _, attr := range attrs {
			if attr.key == key {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// entries retains only requested category slices, while validating every
// top-level and category envelope. Unrequested domain/CIDR payloads are not
// materialized; selected payloads receive full schema validation below.
func entries(data []byte, wanted map[string]bool) (map[string][]byte, error) {
	out := map[string][]byte{}
	seen := map[string]bool{}
	err := walk(data, func(f wireField) error {
		if f.number != 1 {
			return nil // Valid unknown protobuf fields are forward-compatible.
		}
		if err := expectWire(f, 2); err != nil {
			return err
		}
		code := ""
		err := walk(f.bytes, func(g wireField) error {
			if g.number != 1 {
				return nil
			}
			if err := expectWire(g, 2); err != nil {
				return err
			}
			if code != "" || !utf8.Valid(g.bytes) || !categoryToken.Match(g.bytes) {
				return fmt.Errorf("invalid or repeated category name")
			}
			code = strings.ToLower(string(g.bytes))
			return nil
		})
		if err != nil {
			return err
		}
		if code == "" || seen[code] {
			return fmt.Errorf("missing or duplicate category %q", code)
		}
		seen[code] = true
		if wanted[code] {
			out[code] = f.bytes
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for code := range wanted {
		if _, found := out[code]; !found {
			return nil, fmt.Errorf("required category %q not found", code)
		}
	}
	return out, nil
}

func readSites(data []byte, wanted map[string]bool) (map[string][]domain, error) {
	raw, err := entries(data, wanted)
	if err != nil {
		return nil, err
	}
	out := map[string][]domain{}
	for code, entry := range raw {
		out[code] = nil
		err := walk(entry, func(f wireField) error {
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
			out[code] = append(out[code], d)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("category %q: %w", code, err)
		}
	}
	return out, nil
}

func readDomain(data []byte) (domain, error) {
	d := domain{}
	seen := map[uint64]bool{}
	err := walk(data, func(f wireField) error {
		switch f.number {
		case 1:
			if err := expectWire(f, 0); err != nil {
				return err
			}
			if seen[1] || f.value > 3 {
				return fmt.Errorf("invalid or repeated domain type")
			}
			seen[1], d.kind = true, f.value
		case 2:
			if err := expectWire(f, 2); err != nil {
				return err
			}
			if seen[2] || len(f.bytes) == 0 || !utf8.Valid(f.bytes) || strings.ContainsAny(string(f.bytes), "\r\n\x00") {
				return fmt.Errorf("invalid or repeated domain value")
			}
			seen[2], d.value = true, string(f.bytes)
		case 3:
			if err := expectWire(f, 2); err != nil {
				return err
			}
			a, err := readAttribute(f.bytes)
			if err != nil {
				return err
			}
			d.attrs = append(d.attrs, a)
		}
		return nil
	})
	if err == nil && !seen[2] {
		err = fmt.Errorf("domain value missing")
	}
	if err == nil && d.kind == 1 {
		if _, compileErr := regexp.Compile(d.value); compileErr != nil {
			err = fmt.Errorf("invalid domain regexp: %w", compileErr)
		}
	}
	return d, err
}

func readAttribute(data []byte) (attribute, error) {
	a := attribute{}
	keySeen := false
	err := walk(data, func(f wireField) error {
		switch f.number {
		case 1:
			if err := expectWire(f, 2); err != nil {
				return err
			}
			if keySeen || len(f.bytes) == 0 || !utf8.Valid(f.bytes) {
				return fmt.Errorf("invalid or repeated attribute key")
			}
			keySeen, a.key = true, string(f.bytes)
		case 2, 3:
			if err := expectWire(f, 0); err != nil {
				return err
			}
			if a.kind != 0 {
				return fmt.Errorf("repeated attribute typed value")
			}
			a.kind = f.number
			if f.number == 2 {
				a.boolValue = f.value != 0
			} else {
				a.intValue = int64(f.value)
			}
		}
		return nil
	})
	if err == nil && !keySeen {
		err = fmt.Errorf("attribute key missing")
	}
	return a, err
}

func readIPs(data []byte, wanted map[string]bool) (map[string][]netip.Prefix, error) {
	raw, err := entries(data, wanted)
	if err != nil {
		return nil, err
	}
	out := map[string][]netip.Prefix{}
	for code, entry := range raw {
		var prefixes []netip.Prefix
		err := walk(entry, func(f wireField) error {
			switch f.number {
			case 2:
				if err := expectWire(f, 2); err != nil {
					return err
				}
				p, err := readCIDR(f.bytes)
				if err != nil {
					return err
				}
				prefixes = append(prefixes, p)
			case 3:
				if err := expectWire(f, 0); err != nil {
					return err
				}
				if f.value != 0 {
					return fmt.Errorf("reverse GeoIP is unsupported")
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("category %q: %w", code, err)
		}
		out[code] = canonicalPrefixes(prefixes)
	}
	return out, nil
}

func readCIDR(data []byte) (netip.Prefix, error) {
	var rawIP []byte
	var bits uint64 // Proto3's absent prefix value means zero.
	seen := map[uint64]bool{}
	err := walk(data, func(f wireField) error {
		switch f.number {
		case 1:
			if err := expectWire(f, 2); err != nil {
				return err
			}
			if seen[1] {
				return fmt.Errorf("repeated CIDR address")
			}
			seen[1], rawIP = true, f.bytes
		case 2:
			if err := expectWire(f, 0); err != nil {
				return err
			}
			if seen[2] {
				return fmt.Errorf("repeated CIDR prefix")
			}
			seen[2], bits = true, f.value
		}
		return nil
	})
	if err != nil {
		return netip.Prefix{}, err
	}
	addr, ok := netip.AddrFromSlice(rawIP)
	if !ok || bits > uint64(addr.BitLen()) {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR address or prefix")
	}
	p := netip.PrefixFrom(addr, int(bits))
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("CIDR address has host bits set")
	}
	return p, nil
}
