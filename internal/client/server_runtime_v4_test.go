package client

import (
	"bytes"
	"encoding/json"
	"testing"
)

func runtimeV4Fixture(t *testing.T) []byte {
	t.Helper()
	top := decodeObject(t, runtimeV3Fixture(t))
	top["env"] = json.RawMessage(`{"xray.cone.disabled":"true"}`)
	top["log"] = json.RawMessage(`{"access":"none","error":"none","loglevel":"warning","dnsLog":false}`)
	var inlets []json.RawMessage
	if err := json.Unmarshal(top["inbounds"], &inlets); err != nil {
		t.Fatal(err)
	}
	inlets = append(inlets, json.RawMessage(`{"tag":"tunIn","protocol":"tun","settings":{"name":"xray0","MTU":1500,"userLevel":0},"sniffing":{"enabled":true,"metadataOnly":true,"destOverride":["fakedns"],"routeOnly":true}}`))
	top["inbounds"] = marshal(t, inlets)
	return marshal(t, top)
}

func TestServerRuntimeV4ProducesIdenticalClient(t *testing.T) {
	for _, dropAds := range []bool{false, true} {
		v3 := runtimeV3Overlay(t)
		v3.DropLegacyAdRule = dropAds
		want, err := Generate(runtimeV3Fixture(t), v3, "same-version")
		if err != nil {
			t.Fatal(err)
		}
		v4 := v3
		v4.ServerRuntimeProfile = "ai66-v4"
		input, overlayBefore := runtimeV4Fixture(t), marshal(t, v4)
		before := append([]byte(nil), input...)
		got, err := Generate(input, v4, "same-version")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("single-file adaptation changed client policy or node identities")
		}
		if !bytes.Equal(input, before) || !bytes.Equal(overlayBefore, marshal(t, v4)) {
			t.Fatal("single-file adaptation mutated the authoritative configuration")
		}
		for _, field := range []string{`"env"`, `"log"`, `"xray0"`} {
			if bytes.Contains(got, []byte(field)) {
				t.Fatalf("gateway-only field leaked: %s", field)
			}
		}
		gotTop := decodeObject(t, got)
		if _, exists := gotTop["inbounds"]; exists {
			t.Fatal("gateway listener leaked into the client platform configuration")
		}
	}
}

func TestServerRuntimeV4RejectsGatewayDrift(t *testing.T) {
	for _, kind := range []string{"missing-log", "extra-log", "access-log", "error-log", "log-level", "dns-log", "missing-env", "boolean-env", "extra-env", "disabled-env", "missing-tun", "duplicate-tun", "renamed-tun", "tun-protocol", "tun-device", "tun-mtu", "tun-level", "tun-sniff", "tun-extra", "policy-drift", "resolver-drift"} {
		t.Run(kind, func(t *testing.T) {
			var top map[string]any
			if err := json.Unmarshal(runtimeV4Fixture(t), &top); err != nil {
				t.Fatal(err)
			}
			inlets := top["inbounds"].([]any)
			tun := inlets[len(inlets)-1].(map[string]any)
			log := top["log"].(map[string]any)
			env := top["env"].(map[string]any)
			switch kind {
			case "missing-log":
				delete(top, "log")
			case "extra-log":
				log["maskAddress"] = "full"
			case "access-log":
				log["access"] = "/tmp/access.log"
			case "error-log":
				log["error"] = "/tmp/error.log"
			case "log-level":
				log["loglevel"] = "debug"
			case "dns-log":
				log["dnsLog"] = true
			case "missing-env":
				delete(top, "env")
			case "boolean-env":
				env["xray.cone.disabled"] = true
			case "extra-env":
				env["HOME"] = "/synthetic"
			case "disabled-env":
				env["xray.cone.disabled"] = "false"
			case "missing-tun":
				top["inbounds"] = inlets[:len(inlets)-1]
			case "duplicate-tun":
				top["inbounds"] = append(inlets, tun)
			case "renamed-tun":
				tun["tag"] = "other-tun"
			case "tun-protocol":
				tun["protocol"] = "socks"
			case "tun-device":
				tun["settings"].(map[string]any)["name"] = "another0"
			case "tun-mtu":
				tun["settings"].(map[string]any)["MTU"] = 9000
			case "tun-level":
				tun["settings"].(map[string]any)["userLevel"] = 1
			case "tun-sniff":
				tun["sniffing"].(map[string]any)["metadataOnly"] = false
			case "tun-extra":
				tun["listen"] = "0.0.0.0"
			case "policy-drift":
				top["routing"].(map[string]any)["domainStrategy"] = "AsIs"
			case "resolver-drift":
				outs := top["outbounds"].([]any)
				outs[len(outs)-1].(map[string]any)["protocol"] = "freedom"
			}
			o := runtimeV3Overlay(t)
			o.ServerRuntimeProfile = "ai66-v4"
			if _, err := Generate(marshal(t, top), o, ""); err == nil {
				t.Fatal("accepted drift from the complete gateway runtime")
			}
		})
	}
}

func TestServerRuntimeV4DoesNotRelaxOtherProfiles(t *testing.T) {
	for _, profile := range []string{"", "ai66-v1", "ai66-v2", "ai66-v3"} {
		o := runtimeV3Overlay(t)
		o.ServerRuntimeProfile = profile
		if _, err := Generate(runtimeV4Fixture(t), o, ""); err == nil {
			t.Fatalf("profile %q accepted the v4 gateway fields", profile)
		}
	}
	o := runtimeV3Overlay(t)
	o.ServerRuntimeProfile = "ai66-v4"
	if _, err := Generate(runtimeV3Fixture(t), o, ""); err == nil {
		t.Fatal("v4 accepted an incomplete pre-gateway baseline")
	}
}
