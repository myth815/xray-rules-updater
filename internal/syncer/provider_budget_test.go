package syncer

import "testing"

func TestProviderGeoPublicationFitsConsumerDownloadBudget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		assets map[string]ClientAsset
		valid  bool
	}{
		{"no dependencies", nil, true},
		{"current-sized pair", map[string]ClientAsset{"geoip.dat": {Bytes: 20 << 20}, "geosite.dat": {Bytes: 7 << 20}}, true},
		{"largest supported pair", map[string]ClientAsset{"geoip.dat": {Bytes: 64 << 20}, "geosite.dat": {Bytes: 64 << 20}}, true},
		{"oversized single file", map[string]ClientAsset{"geoip.dat": {Bytes: (64 << 20) + 1}}, false},
		{"empty advertised asset", map[string]ClientAsset{"geosite.dat": {Bytes: 0}}, false},
		{"invalid size", map[string]ClientAsset{"geoip.dat": {Bytes: -1}}, false},
		{"aggregate overflow", map[string]ClientAsset{"first": {Bytes: 64 << 20}, "second": {Bytes: 64 << 20}, "third": {Bytes: 1}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateProviderGeoAssetBudget(tc.assets); (err == nil) != tc.valid {
				t.Fatalf("publication compatibility = %v; want accepted=%v", err, tc.valid)
			}
		})
	}
}
