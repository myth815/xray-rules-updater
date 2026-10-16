package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthConfigRestrictsInputs(t *testing.T) {
	c := HealthConfig{PublishDir: "/publish", DNSServer: "172.28.55.3", ProxyURL: "http://172.28.55.2:10802", TimeoutSeconds: 30}
	b, _ := json.Marshal(c)
	parsed, e := LoadHealthConfig(b)
	if e != nil || parsed.DNSServer != "172.28.55.3:53" {
		t.Fatalf("config: %+v %v", parsed, e)
	}
	for _, p := range []string{"file:///tmp/x", "http://user:secret@127.0.0.1:80", "http://127.0.0.1:80/arbitrary", "http://127.0.0.1:80?secret=1"} {
		c.ProxyURL = p
		b, _ = json.Marshal(c)
		if _, e := LoadHealthConfig(b); e == nil {
			t.Fatal("unsafe proxy accepted")
		}
	}
	c.ProxyURL = "http://127.0.0.1:80"
	c.TimeoutSeconds = 31
	b, _ = json.Marshal(c)
	if _, e := LoadHealthConfig(b); e == nil {
		t.Fatal("unbounded timeout accepted")
	}
	if _, e := LoadHealthConfig([]byte(`{"publish_dir":"/publish","dns_server":"127.0.0.1","proxy_url":"http://127.0.0.1:80","target":"https://arbitrary.invalid"}`)); e == nil {
		t.Fatal("arbitrary target accepted")
	}
}
func fakeDNS(t *testing.T) (string, func()) {
	t.Helper()
	address, closeUDP := fakeDNSUDP(t, nil)
	closeTCP := fakeTCPListener(t, address)
	return address, func() { closeTCP(); closeUDP() }
}

func fakeTCPListener(t *testing.T, address string) func() {
	t.Helper()
	listener, e := net.Listen("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, e := listener.Accept()
			if e != nil {
				return
			}
			connection.Close()
		}
	}()
	return func() { listener.Close(); <-done }
}

func fakeDNSUDP(t *testing.T, requests *atomic.Int32) (string, func()) {
	t.Helper()
	connection, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 4096)
		for {
			n, peer, e := connection.ReadFrom(packet)
			if e != nil {
				return
			}
			if n < 12 {
				continue
			}
			if requests != nil {
				requests.Add(1)
			}
			reply := append([]byte{}, packet[:n]...)
			reply[2] = 0x81
			reply[3] = 0x80
			reply[6] = 0
			reply[7] = 1
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 2, 3, 4)
			connection.WriteTo(reply, peer)
		}
	}()
	return connection.LocalAddr().String(), func() { connection.Close(); <-done }
}

func TestHealthWaitsForListenerBeforeSingleBusinessProbes(t *testing.T) {
	var dnsRequests, proxyRequests atomic.Int32
	dns, closeDNS := fakeDNSUDP(t, &dnsRequests)
	defer closeDNS()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests.Add(1)
		if r.Method != "CONNECT" || r.Host != "www.gstatic.com:443" {
			t.Error("unexpected business request")
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	c := HealthConfig{PublishDir: publication(t), DNSServer: dns, ProxyURL: proxy.URL, TimeoutSeconds: 3}
	type result struct {
		summary Summary
		err     error
	}
	done := make(chan result, 1)
	go func() {
		s, e := Health(context.Background(), c)
		done <- result{s, e}
	}()
	select {
	case result := <-done:
		t.Fatalf("health finished before DNS listener was started: %+v %v", result.summary, result.err)
	case <-time.After(150 * time.Millisecond):
	}
	if dnsRequests.Load() != 0 || proxyRequests.Load() != 0 {
		t.Fatal("business request sent before listener readiness")
	}
	closeTCP := fakeTCPListener(t, dns)
	defer closeTCP()
	select {
	case result := <-done:
		if result.err != failure("health_https") || result.summary.Phase != "health_https" {
			t.Fatalf("business result: %+v %v", result.summary, result.err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("health did not advance after the listener started")
	}
	if dnsRequests.Load() != 2 || proxyRequests.Load() != 1 {
		t.Fatalf("business requests retried: DNS=%d CONNECT=%d", dnsRequests.Load(), proxyRequests.Load())
	}
}

func TestHealthListenerTimeoutSendsNoBusinessRequests(t *testing.T) {
	for _, missing := range []string{"dns", "proxy"} {
		t.Run(missing, func(t *testing.T) {
			var dnsRequests, proxyRequests atomic.Int32
			dns, closeDNS := fakeDNSUDP(t, &dnsRequests)
			defer closeDNS()
			if missing != "dns" {
				closeTCP := fakeTCPListener(t, dns)
				defer closeTCP()
			}
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				proxyRequests.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}))
			defer proxy.Close()
			proxyURL := proxy.URL
			if missing == "proxy" {
				// Reserve a UDP-only loopback port; no TCP listener can be ready.
				unready, closeUnready := fakeDNSUDP(t, nil)
				defer closeUnready()
				proxyURL = "http://" + unready
			}
			start := time.Now()
			s, e := Health(context.Background(), HealthConfig{PublishDir: publication(t), DNSServer: dns, ProxyURL: proxyURL, TimeoutSeconds: 1})
			if e != failure("health_timeout") || s.Phase != "health_ready" || s.ErrorCode != "health_timeout" {
				t.Fatalf("readiness failure: %+v %v", s, e)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("readiness exceeded the health context deadline")
			}
			if dnsRequests.Load() != 0 || proxyRequests.Load() != 0 {
				t.Fatal("business request sent without both listeners")
			}
		})
	}
}
func TestHealthUsesFixedExplicitProxyWithoutRetryAndWritesFreshFailure(t *testing.T) {
	dns, closeDNS := fakeDNS(t)
	defer closeDNS()
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "CONNECT" || r.Host != "www.gstatic.com:443" {
			t.Errorf("unexpected proxy target")
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", "http://invalid.invalid:1")
	t.Setenv("NO_PROXY", "*")
	beforeProxy := os.Getenv("HTTPS_PROXY")
	beforeNoProxy := os.Getenv("NO_PROXY")
	root := publication(t)
	c := HealthConfig{PublishDir: root, DNSServer: dns, ProxyURL: proxy.URL, TimeoutSeconds: 3}
	first, e := Health(context.Background(), c)
	if e == nil || first.Status != "failed" || first.ErrorCode != "health_https" || first.Version != "test-v1" {
		t.Fatalf("result: %+v %v", first, e)
	}
	if requests.Load() != 1 {
		t.Fatalf("unexpected retry count: %d", requests.Load())
	}
	if os.Getenv("HTTPS_PROXY") != beforeProxy || os.Getenv("NO_PROXY") != beforeNoProxy {
		t.Fatal("global proxy changed")
	}
	second, e := Health(context.Background(), c)
	if e == nil || second.RunID == first.RunID {
		t.Fatal("fresh run identity missing")
	}
	b, e := os.ReadFile(filepath.Join(root, "health.json"))
	if e != nil {
		t.Fatal(e)
	}
	var saved Summary
	if json.Unmarshal(b, &saved) != nil || saved.RunID != second.RunID {
		t.Fatal("stale health file")
	}
	if bytes.Contains(b, []byte(proxy.URL)) || strings.Contains(string(b), "invalid.invalid") {
		t.Fatal("unsafe diagnostics")
	}
}
