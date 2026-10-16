package geodata

import (
	"net/netip"
	"sort"
)

// canonicalPrefixes removes covered prefixes and merges only exact siblings.
// Unlike a broader supernet approximation, this never adds address coverage.
func canonicalPrefixes(input []netip.Prefix) []netip.Prefix {
	work := append([]netip.Prefix(nil), input...)
	sort.Slice(work, func(i, j int) bool {
		if c := work[i].Addr().Compare(work[j].Addr()); c != 0 {
			return c < 0
		}
		return work[i].Bits() < work[j].Bits()
	})
	out := make([]netip.Prefix, 0, len(work))
	for _, p := range work {
		if len(out) > 0 && covers(out[len(out)-1], p) {
			continue
		}
		out = append(out, p)
		for len(out) > 1 {
			a, b := out[len(out)-2], out[len(out)-1]
			if a.Bits() == 0 || a.Bits() != b.Bits() || a.Addr().BitLen() != b.Addr().BitLen() {
				break
			}
			parent := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
			if parent != netip.PrefixFrom(b.Addr(), b.Bits()-1).Masked() {
				break
			}
			out = append(out[:len(out)-2], parent)
		}
	}
	return out
}

func covers(a, b netip.Prefix) bool {
	return a.Addr().BitLen() == b.Addr().BitLen() && a.Bits() <= b.Bits() && a.Contains(b.Addr())
}
