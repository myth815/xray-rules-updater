package client

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func runtimeFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/ai66-server.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runtimeOverlay(t *testing.T) Overlay {
	t.Helper()
	o := oneXrayFixtureOverlay()
	o.ServerRuntimeProfile = "ai66-v1"
	o.DNS = decodeObject(t, []byte(oneXrayBaselineFixture))["dns"]
	for i, raw := range o.ExtraOutbounds {
		o.ExtraOutbounds[i] = json.RawMessage(strings.ReplaceAll(string(raw), "hongkong", "Hongkong"))
	}
	for i, raw := range o.PrependRules {
		o.PrependRules[i] = json.RawMessage(strings.ReplaceAll(string(raw), "hongkong", "Hongkong"))
	}
	o.KeepOutbounds = append(o.KeepOutbounds, "Hongkong")
	return o
}

func TestServerRuntimeProducesSameClientPolicyAndNodes(t *testing.T) {
	server := runtimeFixture(t)
	// An independently declared pure baseline: the client's policy and node
	// identities do not depend on server DNS/listeners or their helper graph.
	pure := []byte(`{
	 "routing":{"domainStrategy":"IPIfNonMatch","rules":[
	  {"type":"field","domain":["domain:ai.example.invalid"],"outboundTag":"usa-ai"},
	  {"type":"field","domain":["domain:cn.example.invalid"],"outboundTag":"direct"},
	  {"type":"field","ip":["geoip:private"],"outboundTag":"direct"},
	  {"type":"field","ip":["geoip:!cn"],"outboundTag":"Hongkong"},
	  {"type":"field","network":"tcp,udp","outboundTag":"direct"}]},
	 "outbounds":[
	  {"tag":"direct","protocol":"freedom","settings":{}},
	  {"tag":"block","protocol":"blackhole","settings":{}},
	  {"tag":"usa-ai","protocol":"socks","settings":{"servers":[{"address":"192.0.2.10","port":1080,"users":[{"user":"test","pass":"SYNTHETIC-CLIENT-NODE-CREDENTIAL"}]}]},"streamSettings":{"sockopt":{"dialerProxy":"hop"}}},
	  {"tag":"hop","protocol":"socks","settings":{"servers":[{"address":"192.0.2.11","port":1080}]}},
	  {"tag":"Hongkong","protocol":"socks","settings":{"servers":[{"address":"192.0.2.12","port":1080}]}}]}`)
	for _, fakeDNS := range []bool{false, true} {
		overlay := runtimeOverlay(t)
		if !fakeDNS {
			overlay.OneXrayFakeDNS = nil
		}
		before, overlayBefore := append([]byte(nil), server...), marshal(t, overlay)
		got, err := Generate(server, overlay, "same-version")
		if err != nil {
			t.Fatal(err)
		}
		overlay.ServerRuntimeProfile = ""
		want, err := Generate(pure, overlay, "same-version")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("server profile changed native client output (FakeDNS=%v)", fakeDNS)
		}
		if !bytes.Equal(server, before) {
			t.Fatal("mutated authoritative server snapshot")
		}
		overlay.ServerRuntimeProfile = "ai66-v1"
		if !bytes.Equal(marshal(t, overlay), overlayBefore) {
			t.Fatal("mutated client overlay")
		}
		if bytes.Contains(got, []byte("SERVER-ONLY")) || bytes.Contains(got, []byte("ai66-")) || bytes.Contains(got, []byte("ai-guard-")) {
			t.Fatal("router-owned runtime leaked into client")
		}
		if !bytes.Contains(got, []byte("SYNTHETIC-CLIENT-NODE-CREDENTIAL")) || !bytes.Contains(got, []byte(`"hop"`)) {
			t.Fatal("node identity or its dependent hop lost")
		}
	}
}

func TestServerRuntimeRequiresExplicitOptInAndDNS(t *testing.T) {
	for _, profile := range []string{"", "ai66-v2", " ai66-v1"} {
		o := runtimeOverlay(t)
		o.ServerRuntimeProfile = profile
		if _, err := Generate(runtimeFixture(t), o, ""); err == nil {
			t.Fatal("unsafe profile accepted")
		}
	}
	for _, dns := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`[]`)} {
		o := runtimeOverlay(t)
		o.DNS = dns
		if _, err := Generate(runtimeFixture(t), o, ""); err == nil {
			t.Fatal("implicit server DNS inheritance accepted")
		}
	}
}

func TestServerRuntimeLeavesHostSocketAdaptationAtItsExistingStage(t *testing.T) {
	input := strings.Replace(string(runtimeFixture(t)), `"dialerProxy":"hop"`, `"dialerProxy":"hop","mark":11`, 1)
	o := runtimeOverlay(t)
	o.OutboundSockoptOmissions = map[string][]string{"usa-ai": {"mark"}}
	got, err := Generate([]byte(input), o, "")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte(`"mark"`)) || !bytes.Contains(got, []byte(`"dialerProxy": "hop"`)) {
		t.Fatal("host socket omission removed proxy semantics or retained the host mark")
	}
}

func TestServerRuntimeRejectsChangedOwnershipRatherThanDroppingIt(t *testing.T) {
	tests := []struct{ name, old, replacement string }{
		{"pool", `"poolSize":4096`, `"poolSize":8192`},
		{"pool-range", `"ipPool":"198.19.0.0/16"`, `"ipPool":"198.18.0.0/15"`},
		{"block-is-direct", `"tag":"block","protocol":"blackhole"`, `"tag":"block","protocol":"freedom"`},
		{"AI-is-direct", `"tag":"usa-ai","protocol":"socks"`, `"tag":"usa-ai","protocol":"freedom"`},
		{"domain-ownership", `"address":"fakedns","domains":["domain:ai.example.invalid"]`, `"address":"fakedns","domains":["domain:other.example.invalid"]`},
		{"parallel-dns", `"enableParallelQuery":false`, `"enableParallelQuery":true`},
		{"additional-fake-server", `"skipFallback":true},"1.1.1.1"`, `"skipFallback":true},"fakedns","1.1.1.1"`},
		{"dns-listener", `"port":1053`, `"port":1054`},
		{"first-pass", `"metadataOnly":true`, `"metadataOnly":false`},
		{"first-restoration", `"destOverride":["fakedns"]`, `"destOverride":[]`},
		{"DNS-return", `"action":"return","rCode":0`, `"action":"return","rCode":3`},
		{"loopback-to-freedom", `"tag":"ai-guard-loop-tunIn","protocol":"loopback"`, `"tag":"ai-guard-loop-tunIn","protocol":"freedom"`},
		{"second-tag", `"inboundTag":"ai-guard-second-tun"`, `"inboundTag":"socks-route"`},
		{"guard-widening", `"ip":["198.19.0.0/16"]`, `"ip":["0.0.0.0/0"]`},
		{"guard-target", `"protocol":["fakedns"],"outboundTag":"block"`, `"protocol":["fakedns"],"outboundTag":"direct"`},
		{"helper-side-effect", `"tag":"ai66-dns-out","protocol":"dns"`, `"tag":"ai66-dns-out","sendThrough":"127.0.0.1","protocol":"dns"`},
		{"HK-rule-side-effect", `"socks-hk","ai-guard-second-hk"],"outboundTag":"Hongkong"`, `"socks-hk","ai-guard-second-hk"],"port":"443","outboundTag":"Hongkong"`},
		{"unknown-owned-tag", `"tag":"private-server"`, `"tag":"ai66-unknown"`},
		{"missing-first-inlet", `"tag":"socks-route","protocol":"socks"`, `"tag":"ordinary","protocol":"socks"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := string(runtimeFixture(t))
			if !strings.Contains(input, tc.old) {
				t.Fatal("test mutation did not match")
			}
			input = strings.Replace(input, tc.old, tc.replacement, 1)
			if _, err := Generate([]byte(input), runtimeOverlay(t), ""); err == nil || !strings.Contains(err.Error(), "server runtime adaptation:") {
				t.Fatal("changed runtime was silently normalized")
			}
		})
	}
}
