package verify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type HealthConfig struct {
	PublishDir     string `json:"publish_dir"`
	DNSServer      string `json:"dns_server"`
	ProxyURL       string `json:"proxy_url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

func LoadHealthConfig(data []byte) (HealthConfig, error) {
	var c HealthConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if len(data) > 1<<20 || dec.Decode(&c) != nil {
		return c, failure("health_config")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return c, failure("health_config")
	}
	if _, e := c.validate(); e != nil {
		return c, e
	}
	return c, nil
}
func (c *HealthConfig) validate() (*url.URL, error) {
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 30
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 || !filepath.IsAbs(c.PublishDir) || filepath.Clean(c.PublishDir) != c.PublishDir {
		return nil, failure("health_config")
	}
	if addr, e := netip.ParseAddr(c.DNSServer); e == nil {
		c.DNSServer = net.JoinHostPort(addr.String(), "53")
	}
	if addr, e := netip.ParseAddrPort(c.DNSServer); e != nil || addr.Port() == 0 {
		return nil, failure("health_config")
	}
	p, e := url.Parse(c.ProxyURL)
	if e != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || p.User != nil || p.RawQuery != "" || p.Fragment != "" || (p.Path != "" && p.Path != "/") {
		return nil, failure("health_config")
	}
	return p, nil
}

// Health waits for the DNS TCP and explicit proxy TCP listeners, then probes
// live consumers with two single DNS queries and one HTTPS request. Listener
// readiness is not a business request retry. No redirect or global proxy
// mutation is performed. A healthy result is not evidence of loaded GEO hashes.
func Health(parent context.Context, c HealthConfig) (s Summary, err error) {
	start := time.Now()
	var nonce [8]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return s, failure("health_identity")
	}
	s.RunID = hex.EncodeToString(nonce[:])
	s.Status = "failed"
	canWrite := false
	defer func() {
		s.DurationMS = time.Since(start).Milliseconds()
		if err != nil {
			var f failure
			if errors.As(err, &f) {
				s.ErrorCode = string(f)
			} else {
				s.ErrorCode = "health_internal"
			}
		}
		if canWrite {
			b, _ := json.Marshal(s)
			if e := writeSummary(c.PublishDir, s.RunID, "health.json", append(b, '\n')); e != nil && err == nil {
				s.Status = "failed"
				s.ErrorCode = "health_status_write"
				err = failure(s.ErrorCode)
			}
		}
	}()
	proxy, e := c.validate()
	if e != nil {
		return s, e
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	st, e := os.Lstat(c.PublishDir)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return s, failure("health_publication")
	}
	lock, e := os.OpenFile(filepath.Join(c.PublishDir, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return s, failure("health_lock")
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
		return s, failure("health_busy")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	canWrite = true
	_, m, e := snapshot(ctx, c.PublishDir)
	if e != nil {
		return s, e
	}
	s.Version = m.Version
	s.BaselineSHA256 = m.BaselineSHA256
	s.Phase = "health_ready"
	if e = waitHealthReady(ctx, c.DNSServer, proxy); e != nil {
		return s, e
	}
	s.Phase = "health_dns"
	for _, name := range []string{"www.baidu.com", "github.com"} {
		if e = query(ctx, c.DNSServer, name, 0, true); e != nil {
			if ctx.Err() != nil {
				return s, failure("health_timeout")
			}
			return s, failure("health_dns")
		}
	}
	s.Phase = "health_https"
	if e = healthHTTP(ctx, proxy); e != nil {
		return s, e
	}
	s.Status = "healthy"
	s.Phase = "complete"
	return s, nil
}

func waitHealthReady(ctx context.Context, dns string, proxy *url.URL) error {
	port := proxy.Port()
	if port == "" {
		port = "80"
		if proxy.Scheme == "https" {
			port = "443"
		}
	}
	if proxy.Hostname() == "" {
		return failure("health_ready")
	}
	targets := []string{net.JoinHostPort(proxy.Hostname(), port), dns}
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	for {
		ready := true
		for _, target := range targets {
			connection, err := dialer.DialContext(ctx, "tcp", target)
			if err != nil {
				ready = false
			} else {
				connection.Close()
			}
			if ctx.Err() != nil {
				return failure("health_timeout")
			}
		}
		if ready {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return failure("health_timeout")
		case <-timer.C:
		}
	}
}

func healthHTTP(ctx context.Context, proxy *url.URL) error {
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.gstatic.com/generate_204", nil)
	if e != nil {
		return failure("health_https")
	}
	response, e := client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return failure("health_timeout")
		}
		return failure("health_https")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return failure("health_http_status")
	}
	return nil
}
