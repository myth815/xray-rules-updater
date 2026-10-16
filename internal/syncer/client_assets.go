package syncer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/myth815/xray-rules-updater/internal/client"
	"net/url"
	"strings"
)

// ClientAsset binds an original immutable DAT URL to the exact custom filename
// referenced by native ext: selectors. The filename hashes bytes, not the policy
// version, so unchanged DATs are reused across policy-only updates on clients.
type ClientAsset struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// The opt-in provider adapter bounds a DAT to 64 MiB and one import to
// 128 MiB. Refuse an incompatible publication rather than advertising a
// configuration whose dependencies the client cannot install.
const providerGeoFileBytes int64 = 64 << 20
const providerGeoBatchBytes int64 = 128 << 20

func validateProviderGeoAssetBudget(assets map[string]ClientAsset) error {
	var total int64
	for _, asset := range assets {
		if asset.Bytes < 1 || asset.Bytes > providerGeoFileBytes || asset.Bytes > providerGeoBatchBytes-total {
			return errors.New("provider GEO dependencies exceed client download limits")
		}
		total += asset.Bytes
	}
	return nil
}

// Current OneXray can transactionally import raw config + linked DATs from one
// text/file transfer. This is an initial-import bundle, not a subscription: the
// app currently rejects duplicate custom DAT names. A config-only link is also
// emitted for an update whose exact immutable dependencies are already present.
func clientTransfer(raw, links []byte, v string, limit int64) ([]byte, []byte, error) {
	encodedLen := base64.StdEncoding.EncodedLen(len(raw))
	// Query encoding can expand each base64 byte to three ASCII bytes. Bound
	// allocation before encoding rather than discovering capacity after building.
	if limit < 1 || int64(encodedLen)*3+256+int64(len(links)) > limit {
		return nil, nil, errors.New("storage budget exhausted before client transfer")
	}
	short := v
	if len(short) > 12 {
		short = short[len(short)-12:]
	}
	u := url.URL{Scheme: "onexray", Host: "onexray.com", Path: "/config/add", RawQuery: url.Values{"type": {"raw"}, "data": {base64.StdEncoding.EncodeToString(raw)}}.Encode(), Fragment: "Home-" + short}
	single := []byte(u.String() + "\n")
	bundle := make([]byte, 0, len(single)+len(links))
	bundle = append(bundle, single...)
	bundle = append(bundle, links...)
	return single, bundle, nil
}

func validateClientAssetConfig(c Config) error {
	if !c.OneXrayVersionedGEO {
		if c.OneXrayProviderGEOMetadata {
			return errors.New("OneXray provider GEO metadata requires versioned GEO")
		}
		if c.ClientAssetBaseURL != "" {
			return errors.New("client asset origin requires versioned GEO")
		}
		return nil
	}
	u, e := url.Parse(c.ClientAssetBaseURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("versioned client GEO requires an HTTPS origin")
	}
	return nil
}

func bindClientAssets(c Config, v string, ip, site, raw []byte) ([]byte, map[string]ClientAsset, []byte, error) {
	if e := validateClientAssetConfig(c); e != nil {
		return nil, nil, nil, e
	}
	if !c.OneXrayVersionedGEO {
		return raw, nil, nil, nil
	}
	if !identifier.MatchString(v) || v == "latest" {
		return nil, nil, nil, errors.New("versioned client GEO requires an immutable publication version")
	}
	ipHash, siteHash := hash(ip), hash(site)
	ipName, siteName := "home_geoip_"+ipHash+".dat", "home_geosite_"+siteHash+".dat"
	one, referenced, e := client.BindNativeGeoAssetsWithReferences(raw, ipName, siteName)
	if e != nil {
		return nil, nil, nil, e
	}
	origin := strings.TrimRight(c.ClientAssetBaseURL, "/")
	assets := map[string]ClientAsset{
		"geoip.dat":   {Name: ipName, Type: "ip", URL: origin + "/versions/" + v + "/geoip.dat", SHA256: ipHash, Bytes: int64(len(ip))},
		"geosite.dat": {Name: siteName, Type: "domain", URL: origin + "/versions/" + v + "/geosite.dat", SHA256: siteHash, Bytes: int64(len(site))},
	}
	// Existing manual transfers keep their output unchanged. The patched-App
	// subscription contract forbids unused declarations, so its explicit opt-in
	// publishes metadata and import links only for actual typed ext: references.
	if c.OneXrayProviderGEOMetadata {
		for key, asset := range assets {
			if referenced[asset.Name] != asset.Type {
				delete(assets, key)
			}
		}
		if e = validateProviderGeoAssetBudget(assets); e != nil {
			return nil, nil, nil, e
		}
		one, e = attachProviderGeoMetadata(one, assets)
		if e != nil {
			return nil, nil, nil, e
		}
	}
	var links strings.Builder
	for _, key := range []string{"geoip.dat", "geosite.dat"} {
		a, exists := assets[key]
		if !exists {
			continue
		}
		u := url.URL{Scheme: "onexray", Host: "onexray.com", Path: "/dat/add", RawQuery: url.Values{"type": {a.Type}, "url": {a.URL}}.Encode(), Fragment: a.Name}
		links.WriteString(u.String())
		links.WriteByte('\n')
	}
	return one, assets, []byte(links.String()), nil
}

// This is provider metadata for an opt-in OneXray adapter, not Xray-core
// configuration. Official clients without that adapter must not enable it.
// Keep RawMessage values intact so adding metadata cannot round policy numbers
// or alter credentials, routing expressions or outbound order.
func attachProviderGeoMetadata(raw []byte, assets map[string]ClientAsset) ([]byte, error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || top == nil {
		return nil, errors.New("invalid native client for provider metadata")
	}
	if _, exists := top["geodata"]; exists {
		return nil, errors.New("provider GEO metadata already present")
	}
	if len(assets) == 0 {
		return raw, nil
	}
	type asset struct {
		File string `json:"file"`
		URL  string `json:"url"`
	}
	items := make([]asset, 0, len(assets))
	for _, key := range []string{"geoip.dat", "geosite.dat"} {
		if a, exists := assets[key]; exists {
			items = append(items, asset{a.Name, a.URL})
		}
	}
	if len(items) != len(assets) {
		return nil, errors.New("unknown provider GEO asset")
	}
	top["geodata"], _ = json.Marshal(struct {
		Assets []asset `json:"assets"`
	}{items})
	encoded, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return nil, errors.New("encode provider GEO metadata failed")
	}
	return append(encoded, '\n'), nil
}
