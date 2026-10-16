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
	baseline, e := readLimited(c.Baseline, 4<<20)
	if e != nil {
		return summary, e
	}
	baselineHash := hash(baseline)
	policy, _ := json.Marshal(struct {
		Client     client.Overlay
		Sites, IPs map[string]string
		RouterOS   bool
	}{c.Client, c.Sites, c.IPs, c.RouterOSCandidate})
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
	derived, e := geodata.Export(ip, site, c.Sites, c.IPs, list)
	if e != nil {
		return summary, errors.New("DAT export validation failed")
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
	baselineAfter, e := readLimited(c.Baseline, 4<<20)
	if e != nil || hash(baselineAfter) != baselineHash {
		return summary, errors.New("baseline changed during run")
	}
	files := derived.Files
	files["geoip.dat"] = ip
	files["geosite.dat"] = site
	files["onexray.json"] = one
	if e = ctx.Err(); e != nil {
		return summary, errors.New("run deadline exceeded")
	}
	manifest := Manifest{GeneratorVersion: c.GeneratorVersion, Release: source.ReleaseID, BaselineSHA256: baselineHash, PolicySHA256: policyHash, Counts: derived.Counts, Activation: "published only; no consumer configuration or routing changes"}
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
