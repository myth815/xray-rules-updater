package syncer

import (
	"encoding/base64"
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
	if !c.OneXrayVersionedGEO {
		return raw, nil, nil, nil
	}
	if e := validateClientAssetConfig(c); e != nil {
		return nil, nil, nil, e
	}
	ipHash, siteHash := hash(ip), hash(site)
	ipName, siteName := "home_geoip_"+ipHash+".dat", "home_geosite_"+siteHash+".dat"
	one, e := client.BindNativeGeoAssets(raw, ipName, siteName)
	if e != nil {
		return nil, nil, nil, e
	}
	origin := strings.TrimRight(c.ClientAssetBaseURL, "/")
	assets := map[string]ClientAsset{
		"geoip.dat":   {Name: ipName, Type: "ip", URL: origin + "/versions/" + v + "/geoip.dat", SHA256: ipHash, Bytes: int64(len(ip))},
		"geosite.dat": {Name: siteName, Type: "domain", URL: origin + "/versions/" + v + "/geosite.dat", SHA256: siteHash, Bytes: int64(len(site))},
	}
	var links strings.Builder
	for _, key := range []string{"geoip.dat", "geosite.dat"} {
		a := assets[key]
		u := url.URL{Scheme: "onexray", Host: "onexray.com", Path: "/dat/add", RawQuery: url.Values{"type": {a.Type}, "url": {a.URL}}.Encode(), Fragment: a.Name}
		links.WriteString(u.String())
		links.WriteByte('\n')
	}
	return one, assets, []byte(links.String()), nil
}
