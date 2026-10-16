package syncer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/myth815/xray-rules-updater/internal/client"
	"io"
	"path/filepath"
	"regexp"
)

type Asset struct {
	Path   string `json:"path,omitempty"`
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
}
type Source struct {
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`
	ReleaseID  string `json:"release_id,omitempty"`
	GeoIP      Asset  `json:"geoip,omitempty"`
	GeoSite    Asset  `json:"geosite,omitempty"`
}
type Config struct {
	GeneratorVersion        string            `json:"-"`
	SchemaVersion           int               `json:"schema_version"`
	Source                  Source            `json:"source"`
	Baseline                string            `json:"baseline"`
	BaselineDirectory       string            `json:"baseline_directory,omitempty"`
	RequireApplyAck         bool              `json:"require_apply_ack,omitempty"`
	ApplyAckPath            string            `json:"apply_ack_path,omitempty"`
	ApplyTransactionPath    string            `json:"apply_transaction_path,omitempty"`
	Client                  client.Overlay    `json:"client"`
	OneXrayVersionedGEO     bool              `json:"one_xray_versioned_geo,omitempty"`
	ClientAssetBaseURL      string            `json:"client_asset_base_url,omitempty"`
	Sites                   map[string]string `json:"sites"`
	IPs                     map[string]string `json:"ips"`
	DomainSetsFromOutbounds map[string]string `json:"domain_sets_from_outbounds,omitempty"`
	RouterOSCandidate       bool              `json:"routeros_candidate"`
	PublishDir              string            `json:"publish_dir"`
	BudgetBytes             int64             `json:"budget_bytes"`
	MinFreeBytes            int64             `json:"min_free_bytes"`
	MaxAssetBytes           int64             `json:"max_asset_bytes"`
	TimeoutSeconds          int               `json:"timeout_seconds"`
	ServeGroupID            *int              `json:"serve_group_id,omitempty"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var filenameToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._!-]{0,127}$`)
var repository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var digest = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func LoadConfig(data []byte, base string) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, errors.New("invalid configuration")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return c, errors.New("invalid trailing configuration data")
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	absolute := func(p string) string {
		if !filepath.IsAbs(p) {
			return filepath.Join(base, p)
		}
		return p
	}
	if c.Baseline != "" {
		c.Baseline = absolute(c.Baseline)
	}
	if c.BaselineDirectory != "" {
		c.BaselineDirectory = absolute(c.BaselineDirectory)
	}
	if c.ApplyAckPath != "" {
		c.ApplyAckPath = absolute(c.ApplyAckPath)
	}
	if c.ApplyTransactionPath != "" {
		c.ApplyTransactionPath = absolute(c.ApplyTransactionPath)
	}
	c.PublishDir = absolute(c.PublishDir)
	if c.Source.GeoIP.Path != "" {
		c.Source.GeoIP.Path = absolute(c.Source.GeoIP.Path)
	}
	if c.Source.GeoSite.Path != "" {
		c.Source.GeoSite.Path = absolute(c.Source.GeoSite.Path)
	}
	return c, nil
}
func (c *Config) validate() error {
	if err := validateClientAssetConfig(*c); err != nil {
		return err
	}
	if c.ServeGroupID != nil && (*c.ServeGroupID < 0 || *c.ServeGroupID > 2147483647) {
		return errors.New("invalid serve_group_id")
	}
	if c.SchemaVersion != 1 {
		return errors.New("unsupported configuration schema")
	}
	if (c.Baseline == "") == (c.BaselineDirectory == "") || c.PublishDir == "" {
		return errors.New("exactly one baseline or baseline_directory, and publish_dir are required")
	}
	if c.RequireApplyAck {
		if c.ApplyAckPath == "" {
			c.ApplyAckPath = "applied.json"
		}
		if c.ApplyTransactionPath == "" {
			c.ApplyTransactionPath = filepath.Join(filepath.Dir(c.ApplyAckPath), "transaction.json")
		}
		if filepath.Clean(c.ApplyAckPath) == filepath.Clean(c.ApplyTransactionPath) {
			return errors.New("apply acknowledgement and transaction paths must differ")
		}
	} else if c.ApplyAckPath != "" || c.ApplyTransactionPath != "" {
		return errors.New("apply state paths require require_apply_ack")
	}
	if c.BudgetBytes == 0 {
		c.BudgetBytes = 160 << 20
	}
	if c.MinFreeBytes == 0 {
		c.MinFreeBytes = 64 << 20
	}
	if c.MaxAssetBytes == 0 {
		c.MaxAssetBytes = 40 << 20
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 300
	}
	if c.BudgetBytes < 1<<20 || c.MinFreeBytes < 0 || c.MaxAssetBytes < 1 || c.MaxAssetBytes > 128<<20 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 1800 {
		return errors.New("invalid resource limits")
	}
	if c.Source.Repository != "" {
		if !repository.MatchString(c.Source.Repository) {
			return errors.New("invalid release repository")
		}
		if c.Source.Tag == "" {
			c.Source.Tag = "latest"
		}
		if !identifier.MatchString(c.Source.Tag) {
			return errors.New("invalid release tag")
		}
		if c.Source.ReleaseID != "" || c.Source.GeoIP.Path != "" || c.Source.GeoIP.URL != "" || c.Source.GeoSite.Path != "" || c.Source.GeoSite.URL != "" {
			return errors.New("release source cannot mix explicit assets")
		}
	} else {
		if !identifier.MatchString(c.Source.ReleaseID) || c.Source.ReleaseID == "latest" {
			return errors.New("explicit assets require a pinned release_id")
		}
		for _, a := range []Asset{c.Source.GeoIP, c.Source.GeoSite} {
			if (a.Path == "") == (a.URL == "") || !digest.MatchString(a.SHA256) {
				return errors.New("each asset requires one path or URL and SHA256")
			}
		}
	}
	reserved := map[string]bool{"geoip.dat": true, "geosite.dat": true, "onexray.json": true, "onexray-geodata.txt": true, "onexray-import.txt": true, "onexray-config.txt": true, "manifest.json": true, "status.json": true, "verification.json": true, "health.json": true, "host-control.json": true, "routeros-cn-v4.rsc": true}
	seen := map[string]bool{}
	for _, m := range []map[string]string{c.Sites, c.IPs, c.DomainSetsFromOutbounds} {
		for name, selector := range m {
			if filepath.Base(name) != name || !filenameToken.MatchString(name) || reserved[name] || seen[name] || selector == "" {
				return fmt.Errorf("invalid or duplicate export filename")
			}
			seen[name] = true
		}
	}
	if len(seen) > 128 || len(c.Client.DNSServersFromOutbounds) > 128 {
		return errors.New("domain exports exceed file/server count limit")
	}
	return nil
}
