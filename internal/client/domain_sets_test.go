package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func domainBaseline(rules string) []byte {
	return []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"usa","protocol":"freedom"}],"routing":{"rules":` + rules + `}}`)
}

func TestDomainCollectionKeepsNativeExpressionsAndDeduplicates(t *testing.T) {
	baseline := domainBaseline(`[{"type":"field","inboundTag":["server"],"outboundTag":"usa"},{"domain":["geosite:ai@mobile","full:api.example","geosite:ai@mobile"],"ruleTag":"business","outboundTag":"usa"},{"domain":["full:api.example","domain:example","keyword:ai","regexp:^api\\.","bare-keyword"],"outboundTag":"usa"},{"domain":["geosite:cn"],"network":"tcp","outboundTag":"direct"}]`)
	sets, err := DomainSetsFromOutbounds(baseline, []string{"usa"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"geosite:ai@mobile", "full:api.example", "domain:example", "keyword:ai", `regexp:^api\.`, "bare-keyword"}
	if !reflect.DeepEqual(sets["usa"], want) {
		t.Fatalf("native expressions changed: %#v", sets)
	}
}

func TestDomainCollectionCannotBroadenCompoundPolicies(t *testing.T) {
	for _, extra := range []string{`,"network":"tcp"`, `,"port":"443"`, `,"inboundTag":["server"]`, `,"ip":["geoip:cn"]`, `,"protocol":["tls"]`, `,"balancerTag":"other"`, `,"webhook":{"url":"https://example.invalid"}`} {
		baseline := domainBaseline(`[{"domain":["geosite:ai"],"outboundTag":"usa"` + extra + `}]`)
		if _, err := DomainSetsFromOutbounds(baseline, []string{"usa"}); err == nil {
			t.Fatalf("compound policy broadened: %s", extra)
		}
	}
	for _, rule := range []string{`{"inboundTag":["server"],"outboundTag":"usa"}`, `{"domain":[],"outboundTag":"usa"}`, `{"domains":["full:api.example"],"outboundTag":"usa"}`, `{"type":"future","domain":["full:api.example"],"outboundTag":"usa"}`, `{"domain":["unknown:api.example"],"outboundTag":"usa"}`, `{"domain":["regexp:["],"outboundTag":"usa"}`} {
		if _, err := DomainSetsFromOutbounds(domainBaseline("["+rule+"]"), []string{"usa"}); err == nil {
			t.Fatalf("unsafe or empty policy accepted: %s", rule)
		}
	}
	if _, err := DomainSetsFromOutbounds(domainBaseline(`[{"domain":["full:api.example"],"outboundTag":"usa"}]`), []string{"missing"}); err == nil {
		t.Fatal("missing outbound accepted")
	}
}

func TestClientDNSDerivationOnlyReplacesSelectedDomains(t *testing.T) {
	baseline := domainBaseline(`[{"domain":["geosite:ai@mobile","domain:manual.example"],"outboundTag":"usa"}]`)
	dns := json.RawMessage(`{"disableFallback":true,"servers":[{"tag":"ai-dns","address":"https://dns.example/dns-query","domains":["full:placeholder.invalid"],"finalQuery":true,"skipFallback":true,"timeoutMs":1234},{"tag":"other","address":"1.1.1.1","domains":["geosite:cn"]},"localhost"]}`)
	result, err := Generate(baseline, Overlay{DNS: dns, DNSServersFromOutbounds: map[string]string{"ai-dns": "usa"}}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	before := decodeObject(t, dns)
	after := decodeObject(t, decodeObject(t, result)["dns"])
	assertJSONEqual(t, after["disableFallback"], before["disableFallback"])
	oldServers, newServers := decodeArray(t, before["servers"]), decodeArray(t, after["servers"])
	oldServer, newServer := decodeObject(t, oldServers[0]), decodeObject(t, newServers[0])
	assertJSONEqual(t, newServer["domains"], json.RawMessage(`["geosite:ai@mobile","domain:manual.example"]`))
	delete(oldServer, "domains")
	delete(newServer, "domains")
	assertJSONEqual(t, marshal(t, newServer), marshal(t, oldServer))
	for i := 1; i < len(oldServers); i++ {
		assertJSONEqual(t, newServers[i], oldServers[i])
	}
}

func TestClientDNSDerivationRejectsMissingOrDuplicateTags(t *testing.T) {
	baseline := domainBaseline(`[{"domain":["full:api.example"],"outboundTag":"usa"}]`)
	for _, dns := range []string{`{"servers":[{"tag":"other","address":"1.1.1.1"}]}`, `{"servers":[{"tag":"ai","address":"1.1.1.1"},{"tag":"ai","address":"8.8.8.8"}]}`} {
		if _, err := Generate(baseline, Overlay{DNS: json.RawMessage(dns), DNSServersFromOutbounds: map[string]string{"ai": "usa"}}, "v1"); err == nil {
			t.Fatal("missing or ambiguous DNS server accepted")
		}
	}
	if _, err := Generate(baseline, Overlay{DNS: json.RawMessage(`{"servers":[{"tag":"ai","address":"1.1.1.1"}]}`), DNSServersFromOutbounds: map[string]string{"ai": "missing"}}, "v1"); err == nil {
		t.Fatal("missing DNS policy outbound accepted")
	}
}

func TestClientDNSDerivationLimitsRepeatedDomainCopiesBeforeMutation(t *testing.T) {
	expressions := make([]string, 70)
	for i := range expressions {
		expressions[i] = fmt.Sprintf("keyword:%d-%s", i, strings.Repeat("x", 1024))
	}
	domains, _ := json.Marshal(expressions)
	baseline := domainBaseline(`[{"domain":` + string(domains) + `,"outboundTag":"usa"}]`)
	original := append([]byte(nil), baseline...)
	servers := make([]map[string]any, 64)
	mapping := make(map[string]string, 64)
	for i := range servers {
		tag := fmt.Sprintf("dns-%d", i)
		servers[i] = map[string]any{"tag": tag, "address": "1.1.1.1"}
		mapping[tag] = "usa"
	}
	dns, _ := json.Marshal(map[string]any{"servers": servers})
	_, err := Generate(baseline, Overlay{DNS: dns, DNSServersFromOutbounds: mapping}, "v1")
	if err == nil || !strings.Contains(err.Error(), "4 MiB injection limit") {
		t.Fatalf("unbounded repeated domains accepted: %v", err)
	}
	if !bytes.Equal(baseline, original) {
		t.Fatal("rejected derivation mutated the baseline")
	}
}
