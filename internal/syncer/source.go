package syncer

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// sourceFailure keeps useful diagnostics without exposing URLs or credentials.
type sourceFailure struct{ Code string }

func (e *sourceFailure) Error() string { return e.Code }
func transportFailure(err error) error {
	if errors.Is(err, context.Canceled) {
		return &sourceFailure{"source_cancelled"}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &sourceFailure{"source_timeout"}
	}
	for _, entry := range []struct {
		cause error
		code  string
	}{
		{syscall.EHOSTUNREACH, "source_network_unreachable"}, {syscall.ENETUNREACH, "source_network_unreachable"},
		{syscall.ECONNRESET, "source_connection_reset"}, {syscall.ECONNREFUSED, "source_connection_refused"},
		{io.EOF, "source_eof"}, {io.ErrUnexpectedEOF, "source_eof"},
	} {
		if errors.Is(err, entry.cause) {
			return &sourceFailure{entry.code}
		}
	}
	var certificate x509.UnknownAuthorityError
	if errors.As(err, &certificate) {
		return &sourceFailure{"source_tls_authority"}
	}
	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &invalidCertificate) {
		return &sourceFailure{"source_tls_certificate"}
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return &sourceFailure{"source_tls_hostname"}
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return &sourceFailure{"source_dns"}
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return &sourceFailure{"source_timeout"}
	}
	if strings.Contains(err.Error(), "Forbidden") {
		return &sourceFailure{"source_proxy_forbidden"}
	}
	return &sourceFailure{"source_transport"}
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Host == "" {
			return errors.New("invalid redirect")
		}
		return nil
	}}
}
func fetch(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid HTTPS source")
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, transportFailure(err)
		}
		data, err := fetchOnce(ctx, rawURL, limit)
		if err == nil {
			return data, nil
		}
		last = err
		if !retryableSource(err) || attempt == 2 {
			return nil, err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * sourceRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, &sourceFailure{"source_cancelled"}
		case <-timer.C:
		}
	}
	return nil, last
}

var sourceRetryDelay = 250 * time.Millisecond

func retryableSource(err error) bool {
	var failure *sourceFailure
	if !errors.As(err, &failure) {
		return false
	}
	switch failure.Code {
	case "source_network_unreachable", "source_connection_reset", "source_connection_refused", "source_eof", "source_timeout", "source_http_500", "source_http_502", "source_http_503", "source_http_504":
		return true
	}
	return false
}
func fetchOnce(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("source request failed")
	}
	req.Header.Set("User-Agent", "xray-rules-updater/1")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, transportFailure(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &sourceFailure{fmt.Sprintf("source_http_%d", resp.StatusCode)}
	}
	if resp.ContentLength > limit {
		return nil, errors.New("source exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, transportFailure(err)
	}
	if int64(len(data)) > limit {
		return nil, errors.New("source exceeds size limit")
	}
	return data, nil
}
func resolve(ctx context.Context, s Source) (Source, error) {
	if s.Repository == "" {
		return s, nil
	}
	endpoint := "https://api.github.com/repos/" + s.Repository + "/releases/"
	if s.Tag == "latest" {
		endpoint += "latest"
	} else {
		endpoint += "tags/" + url.PathEscape(s.Tag)
	}
	data, err := fetch(ctx, endpoint, 2<<20)
	if err != nil {
		return s, err
	}
	var release struct {
		Tag    string `json:"tag_name"`
		Draft  bool   `json:"draft"`
		Assets []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"assets"`
	}
	if json.Unmarshal(data, &release) != nil || release.Draft || !identifier.MatchString(release.Tag) || release.Tag == "latest" {
		return s, errors.New("invalid release metadata")
	}
	if s.Tag != "latest" && release.Tag != s.Tag {
		return s, errors.New("release tag mismatch")
	}
	s.ReleaseID = release.Tag
	found := map[string]bool{}
	for _, a := range release.Assets {
		if a.Name != "geoip.dat" && a.Name != "geosite.dat" {
			continue
		}
		if found[a.Name] || !strings.HasPrefix(a.Digest, "sha256:") || !digest.MatchString(strings.TrimPrefix(a.Digest, "sha256:")) || a.Size < 1 {
			return s, errors.New("release asset lacks SHA256 or size")
		}
		u, e := url.Parse(a.URL)
		expected := "/" + s.Repository + "/releases/download/" + release.Tag + "/" + a.Name
		if e != nil || u.Scheme != "https" || u.Host != "github.com" || u.Path != expected || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
			return s, errors.New("asset URL does not belong to pinned release")
		}
		v := Asset{URL: a.URL, SHA256: strings.TrimPrefix(a.Digest, "sha256:"), Size: a.Size}
		if a.Name == "geoip.dat" {
			s.GeoIP = v
		} else {
			s.GeoSite = v
		}
		found[a.Name] = true
	}
	if len(found) != 2 {
		return s, errors.New("release missing required DAT assets")
	}
	return s, nil
}
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input open failed")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > limit {
		return nil, errors.New("invalid input file or size")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("input read failed or size exceeded")
	}
	return data, nil
}
func loadAsset(ctx context.Context, a Asset, limit int64) ([]byte, error) {
	if a.Size > limit {
		return nil, errors.New("asset exceeds size limit")
	}
	var data []byte
	var err error
	if a.Path != "" {
		data, err = readLimited(a.Path, limit)
	} else {
		data, err = fetch(ctx, a.URL, limit)
	}
	if err != nil {
		return nil, err
	}
	if a.Size > 0 && int64(len(data)) != a.Size {
		return nil, errors.New("asset size mismatch")
	}
	if !strings.EqualFold(hash(data), a.SHA256) {
		return nil, errors.New("asset SHA256 mismatch")
	}
	return data, nil
}
func hash(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
