package syncer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/myth815/xray-rules-updater/internal/client"
	"github.com/myth815/xray-rules-updater/internal/geodata"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Summary struct {
	RunID      string `json:"run_id"`
	Status     string `json:"status"`
	Version    string `json:"version,omitempty"`
	Files      int    `json:"files,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
}

func Run(ctx context.Context, c Config) (summary Summary, err error) {
	started := time.Now()
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return summary, errors.New("run identity failed")
	}
	summary.RunID = hex.EncodeToString(nonce[:])
	summary.Status = "failed"
	defer func() {
		summary.DurationMS = time.Since(started).Milliseconds()
		if err != nil {
			summary.ErrorCode = errorCode(err)
		}
	}()
	if err = c.validate(); err != nil {
		return summary, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	unlock, e := prepareRoot(c, summary.RunID)
	if e != nil {
		return summary, e
	}
	defer unlock()
	defer func() {
		summary.DurationMS = time.Since(started).Milliseconds()
		if err != nil {
			summary.ErrorCode = errorCode(err)
			summary.Error = "generation failed; current publication retained"
			if summary.Status == "published_durability_uncertain" {
				summary.Error = "publication committed; directory durability unconfirmed"
			}
		}
		body, _ := json.Marshal(summary)
		tmp := filepath.Join(c.PublishDir, ".status-"+summary.RunID)
		if durableWrite(tmp, append(body, '\n')) == nil {
			if c.ServeGroupID != nil {
				if e := groupReadable(tmp, *c.ServeGroupID); e != nil {
					_ = os.Remove(tmp)
					return
				}
			}
			_ = os.Rename(tmp, filepath.Join(c.PublishDir, "status.json"))
			_ = syncDir(c.PublishDir)
		}
		_ = os.Remove(tmp)
	}()
	source, e := resolve(ctx, c.Source)
	if e != nil {
		return summary, e
	}
	baseline, e := readBaseline(c)
	if e != nil {
		return summary, e
	}
	baselineHash := hash(baseline)
	domainTargets := make([]string, 0, len(c.DomainSetsFromOutbounds))
	for _, target := range c.DomainSetsFromOutbounds {
		domainTargets = append(domainTargets, target)
	}
	domainSets, e := client.DomainSetsFromOutbounds(baseline, domainTargets)
	if e != nil {
		return summary, errors.New("baseline domain policy validation failed")
	}
	policy, _ := json.Marshal(struct {
		Client       client.Overlay
		Sites, IPs   map[string]string
		RouterOS     bool
		DomainSets   map[string]string
		VersionedGEO bool
		AssetBaseURL string
	}{c.Client, c.Sites, c.IPs, c.RouterOSCandidate, c.DomainSetsFromOutbounds, c.OneXrayVersionedGEO, c.ClientAssetBaseURL})
	policyHash := hash(policy)
	identity, _ := json.Marshal([]string{"format-v1", c.GeneratorVersion, source.ReleaseID, strings.ToLower(source.GeoIP.SHA256), strings.ToLower(source.GeoSite.SHA256), baselineHash, policyHash})
	// Keep IDs short enough for RouterOS list names as well as immutable paths.
	version := source.ReleaseID
	if len(version) > 40 {
		version = version[:40]
	}
	version += "-" + hash(identity)[:12]
	summary.Version = version
	current, e := pointer(c.PublishDir, "current")
	if e != nil {
		return summary, e
	}
	if _, e = checkApplyAck(c, current, "versions/"+version); e != nil {
		return summary, e
	}
	if current == "versions/"+version {
		if _, e = validVersion(c.PublishDir, current); e != nil {
			return summary, e
		}
		summary.Status = "unchanged"
		return summary, nil
	}
	// Inspect capacity before downloading; reserve an upper bound for both DAT files.
	estimate := source.GeoIP.Size + source.GeoSite.Size
	if estimate == 0 {
		estimate = 2 * c.MaxAssetBytes
	}
	if e = capacity(c.PublishDir, c.BudgetBytes, c.MinFreeBytes, estimate); e != nil {
		return summary, e
	}
	ip, e := loadAsset(ctx, source.GeoIP, c.MaxAssetBytes)
	if e != nil {
		return summary, e
	}
	site, e := loadAsset(ctx, source.GeoSite, c.MaxAssetBytes)
	if e != nil {
		return summary, e
	}
	if e = ctx.Err(); e != nil {
		return summary, errors.New("run deadline exceeded")
	}
	list := ""
	if c.RouterOSCandidate {
		list = "XrayCN_" + version
	}
	used, e := usedBytes(c.PublishDir)
	if e != nil {
		return summary, errors.New("storage inspection failed")
	}
	// Retained versions and the publisher's fixed write allowance also consume
	// admission space; do not construct outputs against the whole root budget.
	remaining := c.BudgetBytes - used - int64(len(ip)) - int64(len(site)) - (64 << 10)
	if remaining < 1 {
		return summary, errors.New("storage budget exhausted by DAT assets")
	}
	derived, e := geodata.ExportBounded(ip, site, c.Sites, c.IPs, list, c.MaxAssetBytes, remaining)
	if e != nil {
		if errors.Is(e, geodata.ErrExportLimit) {
			return summary, errors.New("storage budget or export size limit exhausted")
		}
		return summary, errors.New("DAT export validation failed")
	}
	if len(c.DomainSetsFromOutbounds) != 0 {
		exports := make(map[string][]string, len(c.DomainSetsFromOutbounds))
		for filename, target := range c.DomainSetsFromOutbounds {
			exports[filename] = domainSets[target]
		}
		for _, data := range derived.Files {
			remaining -= int64(len(data))
		}
		if remaining < 1 {
			return summary, errors.New("storage budget exhausted before domain exports")
		}
		domains, err := geodata.ExportDomainSetsBounded(site, exports, c.MaxAssetBytes, remaining)
		if err != nil {
			if errors.Is(err, geodata.ErrExportLimit) {
				return summary, errors.New("storage budget or domain export size limit exhausted")
			}
			return summary, errors.New("DAT export domain policy validation failed")
		}
		for name, data := range domains.Files {
			if int64(len(data)) > c.MaxAssetBytes {
				return summary, errors.New("DAT export domain file exceeds size limit")
			}
			if _, duplicate := derived.Files[name]; duplicate {
				return summary, errors.New("DAT export duplicate filename")
			}
			derived.Files[name], derived.Counts[name] = data, domains.Counts[name]
		}
	}
	one, e := client.Generate(baseline, c.Client, version)
	if e != nil {
		return summary, errors.New("client adaptation validation failed")
	}
	var native any
	if json.Unmarshal(one, &native) != nil {
		return summary, errors.New("generated client JSON invalid")
	}
	refs := []string{}
	var collect func(any)
	collect = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for _, x := range v {
				collect(x)
			}
		case []any:
			for _, x := range v {
				collect(x)
			}
		case string:
			if strings.HasPrefix(v, "geosite:") || strings.HasPrefix(v, "geoip:") || strings.HasPrefix(v, "ext:") {
				refs = append(refs, v)
			}
		}
	}
	collect(native)
	if e = geodata.ValidateReferences(ip, site, refs); e != nil {
		return summary, errors.New("client GEO dependency validation failed")
	}
	// Check the original native categories before binding them to immutable,
	// content-addressed app filenames. No DAT is expanded or duplicated.
	one, clientAssets, geoLinks, e := bindClientAssets(c, version, ip, site, one)
	if e != nil {
		return summary, errors.New("client adaptation GEO asset binding failed")
	}
	// OneXray uses name as subscription metadata; core routing stays unchanged.
	var entry map[string]json.RawMessage
	_ = json.Unmarshal(one, &entry)
	name := c.Client.Name
	if name == "" {
		name = "Network policy"
	}
	entry["name"], _ = json.Marshal(name + " / " + version)
	one, e = json.MarshalIndent(entry, "", "  ")
	if e != nil {
		return summary, e
	}
	one = append(one, '\n')
	// Detect a baseline edit during the run; never publish a mixed snapshot.
	baselineAfter, e := readBaseline(c)
	if e != nil || hash(baselineAfter) != baselineHash {
		return summary, errors.New("baseline changed during run")
	}
	files := derived.Files
	files["geoip.dat"] = ip
	files["geosite.dat"] = site
	files["onexray.json"] = one
	if len(geoLinks) != 0 {
		files["onexray-geodata.txt"] = geoLinks
		var existing int64
		for _, data := range files {
			existing += int64(len(data))
		}
		available := c.BudgetBytes - used - (64 << 10) - existing
		limit := available / 2
		if limit > c.MaxAssetBytes {
			limit = c.MaxAssetBytes
		}
		single, bundle, err := clientTransfer(one, geoLinks, version, limit)
		if err != nil {
			return summary, err
		}
		files["onexray-config.txt"], files["onexray-import.txt"] = single, bundle
	}
	if e = ctx.Err(); e != nil {
		return summary, errors.New("run deadline exceeded")
	}
	manifest := Manifest{GeneratorVersion: c.GeneratorVersion, Release: source.ReleaseID, BaselineSHA256: baselineHash, PolicySHA256: policyHash, Counts: derived.Counts, Activation: "published only; no consumer configuration or routing changes"}
	manifest.ClientAssets = clientAssets
	changed, e := publish(c, summary.RunID, version, files, manifest)
	if e != nil {
		if changed {
			summary.Status = "published_durability_uncertain"
		}
		return summary, e
	}
	summary.Status = "unchanged"
	if changed {
		summary.Status = "published"
	}
	summary.Files = len(files)
	for _, b := range files {
		summary.Bytes += int64(len(b))
	}
	return summary, nil
}

func errorCode(err error) string {
	var apply *applyAckError
	if errors.As(err, &apply) {
		return apply.code
	}
	var source *sourceFailure
	if errors.As(err, &source) {
		return source.Code
	}
	text := err.Error()
	for _, entry := range []struct{ key, code string }{
		{"storage", "capacity"}, {"space", "capacity"}, {"SHA256", "digest"}, {"GEO dependency", "geo_reference"}, {"DAT export", "dat_invalid"}, {"client adaptation", "client_invalid"}, {"source", "source_fetch"}, {"release", "source_release"}, {"baseline changed", "baseline_changed"}, {"lock", "busy"}, {"durability", "commit_durability"},
	} {
		if strings.Contains(text, entry.key) {
			return entry.code
		}
	}
	return "generation_failed"
}
