package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sourceRoundTripper func(*http.Request) (*http.Response, error)

func (f sourceRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// These tests deliberately replace the default transport and never run in
// parallel. Unexpected requests fail locally instead of reaching the network.
func sourceTransport(t *testing.T, f sourceRoundTripper) {
	t.Helper()
	original := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = original })
}

func sourceResponse(r *http.Request, status int, body string, size int64) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: size, Request: r}
}

func sourceMetadata() map[string]any {
	return map[string]any{
		"tag_name": "202610132205", "draft": false,
		"assets": []any{
			map[string]any{"name": "geoip.dat", "browser_download_url": "https://github.com/example/rules/releases/download/202610132205/geoip.dat", "digest": "sha256:" + strings.Repeat("a", 64), "size": 17},
			map[string]any{"name": "geosite.dat", "browser_download_url": "https://github.com/example/rules/releases/download/202610132205/geosite.dat", "digest": "sha256:" + strings.Repeat("b", 64), "size": 23},
		},
	}
}

func sourceJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestResolveLatestPinsSingleMetadataResponse(t *testing.T) {
	calls := 0
	metadata := sourceJSON(t, sourceMetadata())
	sourceTransport(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.github.com/repos/example/rules/releases/latest" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("User-Agent") != "xray-rules-updater/1" || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Fatalf("missing source request headers: %v", r.Header)
		}
		return sourceResponse(r, 200, metadata, int64(len(metadata))), nil
	})
	s, err := resolve(context.Background(), Source{Repository: "example/rules", Tag: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || s.ReleaseID != "202610132205" || s.GeoIP.Size != 17 || s.GeoSite.Size != 23 {
		t.Fatalf("latest was not pinned once: calls=%d source=%+v", calls, s)
	}
	if s.GeoIP.SHA256 != strings.Repeat("a", 64) || s.GeoSite.SHA256 != strings.Repeat("b", 64) || !strings.Contains(s.GeoIP.URL, "/202610132205/") || !strings.Contains(s.GeoSite.URL, "/202610132205/") {
		t.Fatalf("assets are not from one pinned metadata response: %+v", s)
	}
}

func TestResolveFixedTagAndExplicitSource(t *testing.T) {
	calls := 0
	metadata := sourceJSON(t, sourceMetadata())
	sourceTransport(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/repos/example/rules/releases/tags/202610132205" {
			t.Fatalf("unexpected pinned metadata endpoint %s", r.URL)
		}
		return sourceResponse(r, 200, metadata, -1), nil
	})
	if _, err := resolve(context.Background(), Source{Repository: "example/rules", Tag: "202610132205"}); err != nil {
		t.Fatal(err)
	}
	explicit := Source{ReleaseID: "offline1", GeoIP: Asset{Path: "fixture-ip.dat"}, GeoSite: Asset{Path: "fixture-site.dat"}}
	got, err := resolve(context.Background(), explicit)
	if err != nil || got != explicit || calls != 1 {
		t.Fatalf("explicit source unexpectedly fetched metadata: %+v %v calls=%d", got, err, calls)
	}
}

func TestResolveRejectsUnpinnedOrInvalidMetadata(t *testing.T) {
	cases := []struct {
		name   string
		tag    string
		mutate func(map[string]any)
	}{
		{"missing digest", "latest", func(m map[string]any) { delete(m["assets"].([]any)[0].(map[string]any), "digest") }},
		{"invalid digest", "latest", func(m map[string]any) { m["assets"].([]any)[0].(map[string]any)["digest"] = "sha256:abc" }},
		{"wrong digest kind", "latest", func(m map[string]any) {
			m["assets"].([]any)[0].(map[string]any)["digest"] = "sha512:" + strings.Repeat("a", 64)
		}},
		{"missing size", "latest", func(m map[string]any) { delete(m["assets"].([]any)[0].(map[string]any), "size") }},
		{"negative size", "latest", func(m map[string]any) { m["assets"].([]any)[0].(map[string]any)["size"] = -1 }},
		{"duplicate asset", "latest", func(m map[string]any) { m["assets"] = append(m["assets"].([]any), m["assets"].([]any)[0]) }},
		{"missing asset", "latest", func(m map[string]any) { m["assets"] = m["assets"].([]any)[:1] }},
		{"cross repository URL", "latest", func(m map[string]any) {
			m["assets"].([]any)[0].(map[string]any)["browser_download_url"] = "https://github.com/other/rules/releases/download/202610132205/geoip.dat"
		}},
		{"cross tag URL", "latest", func(m map[string]any) {
			m["assets"].([]any)[0].(map[string]any)["browser_download_url"] = "https://github.com/example/rules/releases/download/202610142205/geoip.dat"
		}},
		{"cross asset URL", "latest", func(m map[string]any) {
			m["assets"].([]any)[0].(map[string]any)["browser_download_url"] = "https://github.com/example/rules/releases/download/202610132205/geosite.dat"
		}},
		{"asset HTTP", "latest", func(m map[string]any) {
			m["assets"].([]any)[0].(map[string]any)["browser_download_url"] = "http://github.com/example/rules/releases/download/202610132205/geoip.dat"
		}},
		{"asset userinfo", "latest", func(m map[string]any) {
			m["assets"].([]any)[0].(map[string]any)["browser_download_url"] = "https://user:password@github.com/example/rules/releases/download/202610132205/geoip.dat"
		}},
		{"asset query", "latest", func(m map[string]any) {
			m["assets"].([]any)[0].(map[string]any)["browser_download_url"] = "https://github.com/example/rules/releases/download/202610132205/geoip.dat?x=1"
		}},
		{"asset fragment", "latest", func(m map[string]any) {
			m["assets"].([]any)[0].(map[string]any)["browser_download_url"] = "https://github.com/example/rules/releases/download/202610132205/geoip.dat#fragment"
		}},
		{"draft", "latest", func(m map[string]any) { m["draft"] = true }},
		{"floating tag", "latest", func(m map[string]any) { m["tag_name"] = "latest" }},
		{"invalid tag", "latest", func(m map[string]any) { m["tag_name"] = "../../escape" }},
		{"tag mismatch", "202610142205", func(m map[string]any) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := sourceMetadata()
			tc.mutate(m)
			body := sourceJSON(t, m)
			sourceTransport(t, func(r *http.Request) (*http.Response, error) { return sourceResponse(r, 200, body, -1), nil })
			if _, err := resolve(context.Background(), Source{Repository: "example/rules", Tag: tc.tag}); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}

func TestFetchRejectsUnsafeSourcesBeforeRequest(t *testing.T) {
	sourceTransport(t, func(r *http.Request) (*http.Response, error) {
		t.Fatalf("unsafe source reached transport: %s", r.URL)
		return nil, errors.New("unreachable")
	})
	for _, raw := range []string{"http://example.invalid/data", "file:///tmp/data", "https:///data", "https://user:password@example.invalid/data", "https://example.invalid/data#fragment", "://bad"} {
		if _, err := fetch(context.Background(), raw, 8); err == nil {
			t.Errorf("accepted unsafe source %q", raw)
		}
	}
}

func TestFetchSizeAndStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		size   int64
		ok     bool
	}{
		{"known exact size", 200, "12345678", 8, true},
		{"unknown exact size", 200, "12345678", -1, true},
		{"declared oversize", 200, "x", 9, false},
		{"streamed oversize", 200, "123456789", -1, false},
		{"dishonest length", 200, "123456789", 1, false},
		{"not found", 404, "not found", -1, false},
		{"server error", 503, "temporary", -1, false},
		{"partial content", 206, "partial", -1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourceTransport(t, func(r *http.Request) (*http.Response, error) {
				return sourceResponse(r, tc.status, tc.body, tc.size), nil
			})
			got, err := fetch(context.Background(), "https://source.invalid/data", 8)
			if tc.ok {
				if err != nil || string(got) != tc.body {
					t.Fatalf("valid fetch failed: %q %v", got, err)
				}
			} else if err == nil || got != nil {
				t.Fatalf("invalid response accepted: %q %v", got, err)
			}
		})
	}
}

func TestFetchRedirectPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		location string
		ok       bool
	}{
		{"HTTPS asset CDN", "https://cdn.invalid/pinned-data?signature=public-test", true},
		{"HTTP downgrade", "http://cdn.invalid/pinned-data", false},
		{"userinfo redirect", "https://user:password@cdn.invalid/pinned-data", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			sourceTransport(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					resp := sourceResponse(r, 302, "", 0)
					resp.Header.Set("Location", tc.location)
					return resp, nil
				}
				if !tc.ok {
					t.Errorf("unsafe redirect reached transport: %s", r.URL)
				}
				return sourceResponse(r, 200, "ok", 2), nil
			})
			data, err := fetch(context.Background(), "https://source.invalid/data", 8)
			if tc.ok && (err != nil || string(data) != "ok" || calls != 2) {
				t.Fatalf("valid HTTPS redirect failed: %q %v calls=%d", data, err, calls)
			}
			if !tc.ok && (err == nil || calls != 1) {
				t.Fatalf("unsafe redirect accepted: %q %v calls=%d", data, err, calls)
			}
		})
	}
	t.Run("redirect loop is bounded", func(t *testing.T) {
		calls := 0
		sourceTransport(t, func(r *http.Request) (*http.Response, error) {
			calls++
			resp := sourceResponse(r, 302, "", 0)
			resp.Header.Set("Location", "https://source.invalid/loop")
			return resp, nil
		})
		if _, err := fetch(context.Background(), "https://source.invalid/data", 8); err == nil || calls > 6 {
			t.Fatalf("redirect loop unbounded: calls=%d err=%v", calls, err)
		}
	})
}

func TestLoadAssetValidatesHashAndSize(t *testing.T) {
	payload := []byte("synthetic-dat-payload")
	filename := filepath.Join(t.TempDir(), "fixture.dat")
	if err := os.WriteFile(filename, payload, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		asset Asset
		limit int64
		ok    bool
	}{
		{"valid local", Asset{Path: filename, SHA256: hash(payload), Size: int64(len(payload))}, 64, true},
		{"valid without declared size", Asset{Path: filename, SHA256: hash(payload)}, 64, true},
		{"bad local hash", Asset{Path: filename, SHA256: strings.Repeat("0", 64), Size: int64(len(payload))}, 64, false},
		{"bad declared size", Asset{Path: filename, SHA256: hash(payload), Size: int64(len(payload) + 1)}, 64, false},
		{"declared above limit", Asset{Path: filename, SHA256: hash(payload), Size: 65}, 64, false},
		{"actual above limit", Asset{Path: filename, SHA256: hash(payload)}, 2, false},
		{"missing file", Asset{Path: filename + ".missing", SHA256: hash(payload)}, 64, false},
		{"not regular file", Asset{Path: filepath.Dir(filename), SHA256: hash(payload)}, 64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadAsset(context.Background(), tc.asset, tc.limit)
			if tc.ok && (err != nil || !bytes.Equal(got, payload)) {
				t.Fatalf("valid asset failed: %q %v", got, err)
			}
			if !tc.ok && (err == nil || got != nil) {
				t.Fatalf("invalid asset accepted: %q %v", got, err)
			}
		})
	}
	for _, bad := range []string{"hash", "size", "none"} {
		t.Run("HTTPS "+bad, func(t *testing.T) {
			sourceTransport(t, func(r *http.Request) (*http.Response, error) { return sourceResponse(r, 200, string(payload), -1), nil })
			a := Asset{URL: "https://source.invalid/fixture.dat", SHA256: hash(payload), Size: int64(len(payload))}
			if bad == "hash" {
				a.SHA256 = strings.Repeat("0", 64)
			}
			if bad == "size" {
				a.Size++
			}
			got, err := loadAsset(context.Background(), a, 64)
			if bad == "none" && (err != nil || !bytes.Equal(got, payload)) {
				t.Fatalf("valid remote asset failed: %q %v", got, err)
			}
			if bad != "none" && (err == nil || got != nil) {
				t.Fatalf("invalid remote asset accepted: %q %v", got, err)
			}
		})
	}
}
