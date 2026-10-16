package geodata

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// ValidateDomainExpressions accepts only the native domain matchers which can
// be represented exactly in both Xray DNS and MosDNS domain-set text.
func ValidateDomainExpressions(expressions []string) error {
	if len(expressions) == 0 {
		return fmt.Errorf("domain expression set is empty")
	}
	for _, expression := range expressions {
		if _, _, err := domainExpression(expression); err != nil {
			return err
		}
	}
	return nil
}

func domainExpression(value string) (*selector, string, error) {
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
		return nil, "", fmt.Errorf("invalid domain expression")
	}
	if strings.HasPrefix(value, "geosite:") {
		s, err := parseSelector(strings.TrimPrefix(value, "geosite:"), true)
		return &s, "", err
	}
	kind, pattern, prefixed := strings.Cut(value, ":")
	if !prefixed {
		kind, pattern = "keyword", value
	}
	if pattern == "" {
		return nil, "", fmt.Errorf("domain matcher is empty")
	}
	switch kind {
	case "domain", "full", "keyword":
	case "regexp":
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, "", fmt.Errorf("invalid domain regexp")
		}
	default:
		return nil, "", fmt.Errorf("unsupported domain matcher")
	}
	return nil, kind + ":" + pattern, nil
}

// ExportDomainSets expands only the selected GEO expressions into MosDNS text.
// The original native expressions remain available to the client generator.
func ExportDomainSets(geosite []byte, sets map[string][]string) (*Result, error) {
	return ExportDomainSetsBounded(geosite, sets, 128<<20, 128<<20)
}

// ExportDomainSetsBounded applies the caller's remaining publication budget
// while deduplicating, before materializing all of the output text files.
func ExportDomainSetsBounded(geosite []byte, sets map[string][]string, maxFileBytes, maxTotalBytes int64) (*Result, error) {
	if maxFileBytes < 1 || maxFileBytes > 128<<20 || maxTotalBytes < 1 || len(sets) > 128 {
		return nil, fmt.Errorf("invalid domain export limits")
	}
	r := &Result{Files: map[string][]byte{}, Counts: map[string]int{}}
	wanted := map[string]bool{}
	for name, expressions := range sets {
		if err := validFilename(name); err != nil {
			return nil, err
		}
		if err := ValidateDomainExpressions(expressions); err != nil {
			return nil, err
		}
		for _, expression := range expressions {
			s, _, _ := domainExpression(expression)
			if s != nil {
				wanted[s.code] = true
			}
		}
	}
	var data map[string][]domain
	if len(wanted) != 0 {
		var err error
		data, err = readSites(geosite, wanted)
		if err != nil {
			return nil, err
		}
	}
	budget := exportBudget{maxFile: maxFileBytes, maxTotal: maxTotalBytes}
	for name, expressions := range sets {
		unique := map[string]bool{}
		var size int64
		add := func(line string) error {
			if err := validMosDNSDomainLine(line); err != nil {
				return err
			}
			if unique[line] {
				return nil
			}
			n := int64(len(line)) + 1
			if err := budget.add(size, n); err != nil {
				return err
			}
			unique[line], size = true, size+n
			return nil
		}
		for _, expression := range expressions {
			s, manual, _ := domainExpression(expression)
			if s == nil {
				if err := add(manual); err != nil {
					return nil, err
				}
				continue
			}
			matched := false
			for _, d := range data[s.code] {
				if matchesAttrs(d.attrs, s.attrs) {
					matched = true
					prefix := [...]string{"keyword:", "regexp:", "domain:", "full:"}[d.kind]
					if err := add(prefix + d.value); err != nil {
						return nil, err
					}
				}
			}
			if !matched {
				return nil, fmt.Errorf("required domain GEO selector is empty")
			}
		}
		lines := make([]string, 0, len(unique))
		for line := range unique {
			lines = append(lines, line)
		}
		sort.Strings(lines)
		r.Files[name], r.Counts[name] = textLines(lines), len(lines)
	}
	return r, nil
}
