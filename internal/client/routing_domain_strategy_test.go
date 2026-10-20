package client

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateRoutingDomainStrategyOverridesOnlyClientRouting(t *testing.T) {
	baseline := []byte(baselineFixture)
	before := append([]byte(nil), baseline...)
	inherited, err := Generate(baseline, Overlay{}, "")
	if err != nil {
		t.Fatal(err)
	}
	want := decodeObject(t, inherited)
	wantRouting := decodeObject(t, want["routing"])
	delete(wantRouting, "domainStrategy")
	want["routing"] = marshal(t, wantRouting)

	for _, strategy := range []string{"AsIs", "IPIfNonMatch", "IPOnDemand"} {
		t.Run(strategy, func(t *testing.T) {
			// Exercise the persisted overlay JSON field, not only Go assignment.
			var overlay Overlay
			if err := json.Unmarshal([]byte(`{"routing_domain_strategy":"`+strategy+`"}`), &overlay); err != nil {
				t.Fatal(err)
			}
			overlayBefore := marshal(t, overlay)
			result, err := Generate(baseline, overlay, "")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(baseline, before) || !bytes.Equal(marshal(t, overlay), overlayBefore) {
				t.Fatal("client routing override mutated an input")
			}
			top := decodeObject(t, result)
			routing := decodeObject(t, top["routing"])
			assertJSONEqual(t, routing["domainStrategy"], marshal(t, strategy))
			delete(routing, "domainStrategy")
			top["routing"] = marshal(t, routing)
			// AI/domain/IP rule order, node payloads, DNS and default outbound
			// must remain exactly as the inherited projection generated them.
			assertJSONEqual(t, marshal(t, top), marshal(t, want))
		})
	}

	empty, err := Generate(baseline, Overlay{RoutingDomainStrategy: ""}, "")
	if err != nil || !bytes.Equal(empty, inherited) {
		t.Fatalf("empty routing strategy changed inherited output: %v", err)
	}
	if bytes.Contains(marshal(t, Overlay{}), []byte("routing_domain_strategy")) {
		t.Fatal("default overlay serialization gained an override")
	}
}

func TestGenerateRoutingDomainStrategyCanExplicitlyCreateRouting(t *testing.T) {
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	inherited, err := Generate(baseline, Overlay{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := decodeObject(t, inherited)["routing"]; exists {
		t.Fatal("omitted override invented routing")
	}
	result, err := Generate(baseline, Overlay{RoutingDomainStrategy: "IPOnDemand"}, "")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, decodeObject(t, result)["routing"], json.RawMessage(`{"domainStrategy":"IPOnDemand","rules":[]}`))
}

func TestGenerateRoutingDomainStrategyFollowsServerRuntimeValidation(t *testing.T) {
	baseline := runtimeV4Fixture(t)
	before := append([]byte(nil), baseline...)
	overlay := runtimeV3Overlay(t)
	overlay.ServerRuntimeProfile = "ai66-v4"
	overlay.RoutingDomainStrategy = "IPOnDemand"
	result, err := Generate(baseline, overlay, "")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, decodeObject(t, decodeObject(t, result)["routing"])["domainStrategy"], json.RawMessage(`"IPOnDemand"`))
	if !bytes.Equal(baseline, before) {
		t.Fatal("client override changed the authoritative server snapshot")
	}
	// The client override must not conceal drift in the server runtime contract.
	top := decodeObject(t, baseline)
	routing := decodeObject(t, top["routing"])
	routing["domainStrategy"] = json.RawMessage(`"AsIs"`)
	top["routing"] = marshal(t, routing)
	if _, err := Generate(marshal(t, top), overlay, ""); err == nil || !strings.Contains(err.Error(), "requires IPIfNonMatch") {
		t.Fatalf("client override hid invalid authoritative routing: %v", err)
	}
}

func TestGenerateRejectsInvalidRoutingDomainStrategy(t *testing.T) {
	for _, strategy := range []string{"ipondemand", "Asis", "IPOnDemand ", " IPIfNonMatch", "UseIP", "\n", "unknown"} {
		t.Run(strategy, func(t *testing.T) {
			result, err := Generate([]byte(baselineFixture), Overlay{RoutingDomainStrategy: strategy}, "")
			if err == nil || !strings.Contains(err.Error(), "routing_domain_strategy") || result != nil {
				t.Fatalf("invalid client routing strategy accepted: result=%q error=%v", result, err)
			}
		})
	}
}

func TestGenerateRoutingDomainStrategyRejectsOneXrayFakeDNSConflict(t *testing.T) {
	overlay := oneXrayFixtureOverlay()
	overlay.RoutingDomainStrategy = "IPOnDemand"
	if _, err := Generate([]byte(oneXrayBaselineFixture), overlay, ""); err == nil ||
		!strings.Contains(err.Error(), "routing_domain_strategy") || !strings.Contains(err.Error(), "one_xray_fake_dns") {
		t.Fatalf("IPOnDemand bypassed FakeDNS two-pass contract: %v", err)
	}
	// The adapter already supports AsIs and IPIfNonMatch. Explicitly selecting
	// either must retain its existing validation and generation behavior.
	for _, strategy := range []string{"AsIs", "IPIfNonMatch"} {
		t.Run(strategy, func(t *testing.T) {
			overlay.RoutingDomainStrategy = strategy
			if _, err := Generate([]byte(oneXrayBaselineFixture), overlay, ""); err != nil {
				t.Fatal(err)
			}
		})
	}
}
