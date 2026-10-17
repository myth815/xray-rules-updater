package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// These numeric addresses are parser fixtures only. No test makes network
// requests, and they are not recommendations or approvals for a real network.
const businessFixtureCIDR = "1.2.3.4/32"

func businessBaseline(t *testing.T) []byte {
	t.Helper()
	return []byte(`{"dns":{"servers":["1.1.1.1"]},"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"AsIs"}},{"tag":"block","protocol":"blackhole"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","domain":["full:ai.example.invalid"],"outboundTag":"block"},{"type":"field","ip":["1.2.3.4/32","1.2.4.0/24"],"outboundTag":"direct"},{"type":"field","domain":["full:ordinary.example.invalid"],"outboundTag":"direct"}]}}`)
}

func businessApproval(t *testing.T, baseline []byte) *RouterOSBusinessDirect {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(baseline, &top); err != nil {
		t.Fatal(err)
	}
	rule := top["routing"].(map[string]any)["rules"].([]any)[1]
	canonical, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	return &RouterOSBusinessDirect{OutboundTag: "direct", Approved: []BusinessDirectApproval{{
		CIDR: businessFixtureCIDR, Reason: "Synthetic dedicated-address approval; never contacted",
		ExclusiveBusinessOperatorAttestation: true, BaselineRuleSHA256: hash(canonical),
	}}}
}

func businessConfig(t *testing.T) (Config, []byte) {
	t.Helper()
	c := fixture(t)
	baseline := businessBaseline(t)
	if err := os.WriteFile(c.Baseline, baseline, 0600); err != nil {
		t.Fatal(err)
	}
	return c, baseline
}

func readBusinessPublication(t *testing.T, c Config) (Manifest, []byte, map[string]any) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(c.PublishDir, "current", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	body, err = os.ReadFile(filepath.Join(c.PublishDir, "current", businessDirectFilename))
	if err != nil {
		t.Fatal(err)
	}
	info, present := manifest.Files[businessDirectFilename]
	if !present || info.SHA256 != hash(body) || info.Bytes != int64(len(body)) {
		t.Fatal("published business data is not bound to the actual manifest bytes")
	}
	native, err := os.ReadFile(filepath.Join(c.PublishDir, "current", "onexray.json"))
	if err != nil {
		t.Fatal(err)
	}
	var client map[string]any
	if err := json.Unmarshal(native, &client); err != nil {
		t.Fatal(err)
	}
	return manifest, body, client
}

func TestBusinessDirectPublicationApprovalAndRevocationPreserveNativeGraph(t *testing.T) {
	c, baseline := businessConfig(t)
	legacy, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.PublishDir, "current", businessDirectFilename)); !os.IsNotExist(err) {
		t.Fatal("omitted opt-in emitted business data")
	}
	legacyNative, err := os.ReadFile(filepath.Join(c.PublishDir, "current", "onexray.json"))
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	_ = json.Unmarshal(legacyNative, &graph)
	delete(graph, "name")

	c.RouterOSBusinessDirect = &RouterOSBusinessDirect{OutboundTag: "direct"}
	empty, err := Run(context.Background(), c)
	if err != nil || empty.Version == legacy.Version {
		t.Fatalf("explicit empty publication did not get its own identity: %v", err)
	}
	emptyManifest, body, native := readBusinessPublication(t, c)
	var artifact struct {
		SchemaVersion  int                      `json:"schema_version"`
		BaselineSHA256 string                   `json:"baseline_sha256"`
		Approved       []BusinessDirectApproval `json:"approved"`
		Activation     string                   `json:"activation"`
	}
	if json.Unmarshal(body, &artifact) != nil || artifact.Approved == nil || len(artifact.Approved) != 0 || artifact.SchemaVersion != 1 || artifact.BaselineSHA256 != hash(baseline) || !strings.HasPrefix(artifact.Activation, "data only;") {
		t.Fatal("explicit empty artifact lacks exact baseline binding or no-activation boundary")
	}
	delete(native, "name")
	if !reflect.DeepEqual(native, graph) {
		t.Fatal("empty opt-in changed the native client graph")
	}

	c.RouterOSBusinessDirect = businessApproval(t, baseline)
	approved, err := Run(context.Background(), c)
	if err != nil || approved.Version == empty.Version {
		t.Fatalf("approval did not change policy identity: %v", err)
	}
	manifest, body, native := readBusinessPublication(t, c)
	if json.Unmarshal(body, &artifact) != nil || len(artifact.Approved) != 1 || artifact.Approved[0] != c.RouterOSBusinessDirect.Approved[0] || manifest.Counts[businessDirectFilename] != 1 || manifest.PolicySHA256 == emptyManifest.PolicySHA256 {
		t.Fatal("publication lost approval evidence, count, or policy binding")
	}
	delete(native, "name")
	if !reflect.DeepEqual(native, graph) {
		t.Fatal("IP projection reordered domain rules or changed native outbounds")
	}
	if _, present := manifest.Files["routeros-cn-v4.rsc"]; !present {
		t.Fatal("independent CN candidate unexpectedly removed")
	}
	cn, _ := os.ReadFile(filepath.Join(c.PublishDir, "current", "routeros-cn-v4.rsc"))
	if bytes.Contains(cn, []byte(businessFixtureCIDR)) {
		t.Fatal("explicit business approval was merged into the GEO candidate")
	}

	c.RouterOSBusinessDirect = &RouterOSBusinessDirect{OutboundTag: "direct", Approved: []BusinessDirectApproval{}}
	revoked, err := Run(context.Background(), c)
	if err != nil || revoked.Version != empty.Version {
		t.Fatalf("revoking all approvals did not recover the exact empty policy: %v", err)
	}
	_, body, _ = readBusinessPublication(t, c)
	if bytes.Contains(body, []byte(businessFixtureCIDR)) {
		t.Fatal("revoked CIDR remains in the current business artifact")
	}
	if actual, err := os.ReadFile(c.Baseline); err != nil || !bytes.Equal(actual, baseline) {
		t.Fatal("producer changed the authoritative baseline")
	}
	if c.RouterOSBusinessDirect.Approved == nil {
		t.Fatal("caller configuration was changed")
	}
}

func TestBusinessDirectRejectsInvalidApprovalInput(t *testing.T) {
	baseline := businessBaseline(t)
	for _, cidr := range []string{
		"1.2.3.4", "1.2.3.4/24", " 1.2.3.4/32", "::ffff:1.2.3.4/128", "2001:db8::/32", "geoip:cn", "full:example.invalid", "1.2.3.4/32;quit",
		"0.0.0.0/0", "0.1.0.0/16", "10.0.0.0/16", "100.64.0.0/16", "127.0.0.0/16", "169.254.0.0/16", "172.16.0.0/16",
		"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24",
		"198.18.0.0/16", "198.19.0.0/16", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/16", "240.0.0.0/16", "255.255.255.255/32",
	} {
		t.Run(cidr, func(t *testing.T) {
			c := businessApproval(t, baseline)
			c.Approved[0].CIDR = cidr
			if err := validateBusinessDirect(*c); err == nil {
				t.Fatal("noncanonical, derived, broad, reserved or synthetic approval accepted")
			}
		})
	}
	for _, mode := range []string{"no-attestation", "empty-reason", "control-reason", "too-long-reason", "wrong-sha", "uppercase-sha", "overlap", "duplicate", "aggregate-too-large", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			c := businessApproval(t, baseline)
			switch mode {
			case "no-attestation":
				c.Approved[0].ExclusiveBusinessOperatorAttestation = false
			case "empty-reason":
				c.Approved[0].Reason = ""
			case "control-reason":
				c.Approved[0].Reason = "approval\nsecond line"
			case "too-long-reason":
				c.Approved[0].Reason = strings.Repeat("x", 257)
			case "wrong-sha":
				c.Approved[0].BaselineRuleSHA256 = "missing"
			case "uppercase-sha":
				c.Approved[0].BaselineRuleSHA256 = strings.Repeat("A", 64)
			case "overlap", "duplicate":
				c.Approved = append(c.Approved, c.Approved[0])
				if mode == "overlap" {
					c.Approved[1].CIDR = "1.2.3.0/24"
				}
			case "aggregate-too-large":
				c.Approved[0].CIDR = "1.2.0.0/16"
				c.Approved = append(c.Approved, c.Approved[0])
				c.Approved[1].CIDR = "1.3.0.0/16"
			case "too-many":
				c.Approved = make([]BusinessDirectApproval, 129)
			}
			if err := validateBusinessDirect(*c); err == nil {
				t.Fatal("unsafe or oversized approval accepted")
			}
		})
	}
}

func TestBusinessDirectRequiresExactUnconditionalBaselineProof(t *testing.T) {
	for _, mode := range []string{"wrong-proof", "subset", "superset", "domain", "inbound", "network", "port", "unknown-rule", "geo", "noncanonical-baseline-ip", "other-outbound", "duplicate-rule", "custom-synthetic-pool"} {
		t.Run(mode, func(t *testing.T) {
			baseline := businessBaseline(t)
			var top map[string]any
			_ = json.Unmarshal(baseline, &top)
			routing := top["routing"].(map[string]any)
			rules := routing["rules"].([]any)
			rule := rules[1].(map[string]any)
			switch mode {
			case "domain":
				rule["domain"] = []string{"full:ordinary.example.invalid"}
			case "inbound":
				rule["inboundTag"] = []string{"service"}
			case "network":
				rule["network"] = "tcp"
			case "port":
				rule["port"] = "443"
			case "unknown-rule":
				rule["unknown"] = true
			case "geo":
				rule["ip"] = []string{businessFixtureCIDR, "geoip:cn"}
			case "noncanonical-baseline-ip":
				rule["ip"] = []string{"1.2.3.4"}
			case "other-outbound":
				rule["outboundTag"] = "block"
			case "duplicate-rule":
				routing["rules"] = append(rules, rule)
			case "custom-synthetic-pool":
				top["fakedns"] = []any{map[string]any{"ipPool": "1.2.0.0/16", "poolSize": 8192}}
			}
			baseline, _ = json.Marshal(top)
			c := businessApproval(t, baseline)
			switch mode {
			case "wrong-proof":
				c.Approved[0].BaselineRuleSHA256 = strings.Repeat("0", 64)
			case "subset":
				c.Approved[0].CIDR = "1.2.4.0/25"
			case "superset":
				c.Approved[0].CIDR = "1.2.3.0/24"
			}
			if _, err := generateBusinessDirect(baseline, c); err == nil {
				t.Fatal("unsafe projection was accepted by matching only an IP or freedom tag")
			}
		})
	}
}

func TestBusinessDirectRuleProofIsIndependentOfJSONFormatting(t *testing.T) {
	baseline := businessBaseline(t)
	approval := businessApproval(t, baseline)
	// The selected rule has exactly the same native meaning after key sorting,
	// pretty-printing and a JSON escape for one character in its outbound tag.
	var top any
	_ = json.Unmarshal(baseline, &top)
	formatted, _ := json.MarshalIndent(top, "", "  ")
	formatted = bytes.Replace(formatted, []byte(`"outboundTag": "direct"`), []byte(`"outboundTag": "\u0064irect"`), 1)
	body, err := generateBusinessDirect(formatted, approval)
	if err != nil {
		t.Fatal("equivalent formatting invalidated the canonical native rule proof", err)
	}
	var artifact struct {
		BaselineSHA256 string `json:"baseline_sha256"`
	}
	if json.Unmarshal(body, &artifact) != nil || artifact.BaselineSHA256 != hash(formatted) {
		t.Fatal("artifact did not bind the actual source snapshot independently of its rule proof")
	}
}

func TestBusinessDirectRejectsFreedomWithAdditionalRuntimeBehavior(t *testing.T) {
	for _, extra := range []string{
		`"settings":{"redirect":"127.0.0.1:1234"}`, `"settings":{"fragment":{"packets":"tlshello"}}`,
		`"settings":{"domainStrategy":"UseIP"}`, `"settings":null`, `"streamSettings":null`,
		`"proxySettings":{"tag":"proxy"}`, `"proxySettings":{}`, `"sendThrough":"0.0.0.0"`,
		`"streamSettings":{"sockopt":{"dialerProxy":"proxy"}}`, `"streamSettings":{"sockopt":{"mark":100}}`,
		`"streamSettings":{"sockopt":{"interface":"ether1"}}`, `"targetStrategy":"ForceIPv4"`,
		`"mux":{"enabled":false}`, `"protocol":"socks"`, `"unknown":true`,
	} {
		t.Run(extra, func(t *testing.T) {
			var top map[string]any
			_ = json.Unmarshal(businessBaseline(t), &top)
			out := top["outbounds"].([]any)[0].(map[string]any)
			var replacement map[string]any
			if err := json.Unmarshal([]byte("{"+extra+"}"), &replacement); err != nil {
				t.Fatal(err)
			}
			for k, v := range replacement {
				out[k] = v
			}
			baseline, _ := json.Marshal(top)
			if _, err := generateBusinessDirect(baseline, businessApproval(t, baseline)); err == nil {
				t.Fatal("non-plain direct outbound accepted")
			}
		})
	}
}

func TestBusinessDirectStrictConfigAndFailedPublicationKeepCurrent(t *testing.T) {
	c, baseline := businessConfig(t)
	first, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.RouterOSBusinessDirect = businessApproval(t, baseline)
	c.RouterOSBusinessDirect.Approved[0].ExclusiveBusinessOperatorAttestation = false
	failed, err := Run(context.Background(), c)
	if err == nil || failed.ErrorCode != "routeros_business_invalid" {
		t.Fatal("missing operator approval did not refuse publication")
	}
	assertCurrent(t, c, first.Version)

	c.RouterOSBusinessDirect = nil
	config, _ := json.Marshal(c)
	var top map[string]json.RawMessage
	_ = json.Unmarshal(config, &top)
	valid, _ := json.Marshal(businessApproval(t, baseline))
	for _, raw := range []string{
		`{"outbound_tag":"direct","approved":[],"domains":["example.invalid"]}`,
		`{"outbound_tag":"direct","outbound_tag":"block","approved":[]}`,
		strings.Replace(string(valid), `"reason":`, `"derived_from_dns":true,"reason":`, 1),
		strings.Replace(string(valid), `"reason":`, `"reason":"first","reason":`, 1),
	} {
		top["routeros_business_direct"] = json.RawMessage(raw)
		input, _ := json.Marshal(top)
		if _, err := LoadConfig(input, filepath.Dir(c.Baseline)); err == nil {
			t.Fatal("unknown or ambiguous opt-in input accepted")
		}
	}
	// The artifact filename may be a legacy user export when the opt-in is nil;
	// only an enabled producer claims it, so omitted configurations stay valid.
	c.Sites[businessDirectFilename] = "cn"
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.RouterOSBusinessDirect = &RouterOSBusinessDirect{OutboundTag: "direct"}
	if err := c.validate(); err == nil {
		t.Fatal("enabled business artifact can overwrite a user export")
	}
}

func TestBusinessDirectOuterAmbiguityCannotReplaceCurrentPublication(t *testing.T) {
	for name, fields := range map[string]string{
		"valid-then-null":                    `"routeros_business_direct":{"outbound_tag":"direct","approved":[]},"routeros_business_direct":null`,
		"null-then-valid":                    `"routeros_business_direct":null,"routeros_business_direct":{"outbound_tag":"direct","approved":[]}`,
		"escaped-same-key":                   `"routeros_business_direct":{"outbound_tag":"direct","approved":[]},"routeros_business_\u0064irect":null`,
		"case-aliases":                       `"routeros_business_direct":{"outbound_tag":"direct","approved":[]},"ROUTEROS_BUSINESS_DIRECT":null`,
		"null-with-other-root-duplicate":     `"routeros_business_direct":null,"timeout_seconds":30,"timeout_seconds":31`,
		"escaped-null-with-nested-duplicate": `"routeros_business_\u0064irect":null,"sites":{"extra.txt":"cn","extra.txt":"cn"}`,
		"case-alias-with-other-duplicate":    `"ROUTEROS_BUSINESS_DIRECT":null,"timeout_seconds":30,"timeout_seconds":31`,
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := businessConfig(t)
			first, err := Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Join(c.PublishDir, "current", "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			config, _ := json.Marshal(c)
			if strings.Contains(fields, `"sites"`) {
				var root map[string]json.RawMessage
				_ = json.Unmarshal(config, &root)
				delete(root, "sites")
				config, _ = json.Marshal(root)
			}
			input := append(append([]byte{}, config[:len(config)-1]...), []byte(","+fields+"}")...)
			before := append([]byte{}, input...)
			loaded, loadErr := LoadConfig(input, filepath.Dir(c.Baseline))
			if loadErr == nil {
				// Exercise the same load-then-publish boundary as the executable.
				// A last-wins decoder must not silently remove or replace approval.
				_, _ = Run(context.Background(), loaded)
				t.Error("ambiguous config reached publication instead of failing input validation")
			}
			if !bytes.Equal(input, before) {
				t.Fatal("configuration loader changed caller input bytes")
			}
			assertCurrent(t, c, first.Version)
			actual, _ := os.ReadFile(filepath.Join(c.PublishDir, "current", "manifest.json"))
			if !bytes.Equal(actual, original) {
				t.Fatal("rejected configuration replaced current manifest")
			}
		})
	}
}

func TestBusinessDirectPresenceUsesDecodedKeysAndPreservesLegacyLoading(t *testing.T) {
	c, _ := businessConfig(t)
	config, _ := json.Marshal(c)
	for _, fields := range []string{
		`"routeros_business_\u0064irect":{"outbound_tag":"direct","approved":[]}`,
		`"ROUTEROS_BUSINESS_DIRECT":{"outbound_tag":"direct","approved":[]}`,
	} {
		input := append(append([]byte{}, config[:len(config)-1]...), []byte(","+fields+"}")...)
		loaded, err := LoadConfig(input, filepath.Dir(c.Baseline))
		if err != nil || loaded.RouterOSBusinessDirect == nil {
			t.Fatal("a single unambiguous decoded opt-in key stopped loading")
		}
	}
	// Unrelated legacy last-wins handling is deliberately unchanged when the
	// opt-in field is absent. This fix is not a new whole-configuration policy.
	input := append(append([]byte{}, config[:len(config)-1]...), []byte(`,"timeout_seconds":30,"timeout_seconds":31}`)...)
	loaded, err := LoadConfig(input, filepath.Dir(c.Baseline))
	if err != nil || loaded.TimeoutSeconds != 31 || loaded.RouterOSBusinessDirect != nil {
		t.Fatal("omitted opt-in changed valid legacy configuration loading")
	}
}

func TestBusinessDirectNestedAliasesCannotAuthorizeOrRevokePublication(t *testing.T) {
	for _, mode := range []string{
		"attestation-false-alias-true", "approved-alias-clears", "cidr-alias-swaps", "reason-alias-overrides",
		"single-attestation-alias", "single-approved-alias", "single-cidr-alias", "single-reason-alias", "single-outbound-alias", "unicode-reason-alias",
	} {
		t.Run(mode, func(t *testing.T) {
			c, baseline := businessConfig(t)
			c.RouterOSBusinessDirect = businessApproval(t, baseline)
			first, err := Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Join(c.PublishDir, "current", "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			business, _ := json.Marshal(c.RouterOSBusinessDirect)
			raw := string(business)
			switch mode {
			case "attestation-false-alias-true":
				raw = strings.Replace(raw, `"exclusive_business_operator_attestation":true`, `"exclusive_business_operator_attestation":false,"EXCLUSIVE_BUSINESS_OPERATOR_ATTESTATION":true`, 1)
			case "approved-alias-clears":
				raw = raw[:len(raw)-1] + `,"Approved":[]}`
			case "cidr-alias-swaps":
				// Both prefixes exist in the same proved rule, so generic proof
				// validation cannot independently catch this last-wins change.
				raw = strings.Replace(raw, `"cidr":"1.2.3.4/32"`, `"cidr":"1.2.3.4/32","CIDR":"1.2.4.0/24"`, 1)
			case "reason-alias-overrides":
				value, _ := json.Marshal(c.RouterOSBusinessDirect.Approved[0].Reason)
				field := `"reason":` + string(value)
				raw = strings.Replace(raw, field, field+`,"Reason":"Different approval evidence"`, 1)
			case "single-attestation-alias":
				raw = strings.Replace(raw, `"exclusive_business_operator_attestation":`, `"Exclusive_Business_Operator_Attestation":`, 1)
			case "single-approved-alias":
				raw = strings.Replace(raw, `"approved":`, `"Approved":`, 1)
			case "single-cidr-alias":
				raw = strings.Replace(raw, `"cidr":`, `"CIDR":`, 1)
			case "single-reason-alias":
				raw = strings.Replace(raw, `"reason":`, `"Reason":`, 1)
			case "single-outbound-alias":
				raw = strings.Replace(raw, `"outbound_tag":`, `"Outbound_Tag":`, 1)
			case "unicode-reason-alias":
				raw = strings.Replace(raw, `"reason":`, `"reaſon":`, 1)
			}
			if raw == string(business) {
				t.Fatal("alias fixture was not changed")
			}
			config, _ := json.Marshal(c)
			var top map[string]json.RawMessage
			_ = json.Unmarshal(config, &top)
			top["routeros_business_direct"] = json.RawMessage(raw)
			input, _ := json.Marshal(top)
			before := append([]byte{}, input...)
			loaded, loadErr := LoadConfig(input, filepath.Dir(c.Baseline))
			if loadErr == nil {
				_, _ = Run(context.Background(), loaded)
				t.Error("nested schema alias reached publication instead of failing input validation")
			}
			if !bytes.Equal(input, before) {
				t.Fatal("configuration loader changed caller input bytes")
			}
			assertCurrent(t, c, first.Version)
			actual, _ := os.ReadFile(filepath.Join(c.PublishDir, "current", "manifest.json"))
			if !bytes.Equal(actual, original) {
				t.Fatal("nested alias replaced current publication")
			}
		})
	}
}

func TestBusinessDirectExactSchemaAllowsEscapedCanonicalKeys(t *testing.T) {
	c, baseline := businessConfig(t)
	c.RouterOSBusinessDirect = businessApproval(t, baseline)
	business, _ := json.Marshal(c.RouterOSBusinessDirect)
	raw := string(business)
	for _, pair := range [][2]string{
		{`"outbound_tag"`, `"\u006futbound_tag"`},
		{`"approved"`, `"\u0061pproved"`},
		{`"cidr"`, `"\u0063idr"`},
		{`"reason"`, `"\u0072eason"`},
		{`"exclusive_business_operator_attestation"`, `"\u0065xclusive_business_operator_attestation"`},
		{`"baseline_rule_sha256"`, `"\u0062aseline_rule_sha256"`},
	} {
		raw = strings.Replace(raw, pair[0], pair[1], 1)
	}
	config, _ := json.Marshal(c)
	var top map[string]json.RawMessage
	_ = json.Unmarshal(config, &top)
	top["routeros_business_direct"] = json.RawMessage(raw)
	input, _ := json.Marshal(top)
	before := append([]byte{}, input...)
	loaded, err := LoadConfig(input, filepath.Dir(c.Baseline))
	if err != nil || !reflect.DeepEqual(loaded.RouterOSBusinessDirect, c.RouterOSBusinessDirect) || !bytes.Equal(input, before) {
		t.Fatal("escaped canonical keys stopped preserving the exact approval input")
	}
}

func TestBusinessDirectOutputLimitsRefuseBeforePublishing(t *testing.T) {
	c, baseline := businessConfig(t)
	first, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.RouterOSBusinessDirect = businessApproval(t, baseline)
	c.MaxAssetBytes = 256 // Both native DAT fixtures fit; the evidence artifact does not.
	if _, err := Run(context.Background(), c); err == nil {
		t.Fatal("per-file resource cap did not include the business artifact")
	}
	assertCurrent(t, c, first.Version)

	var top map[string]any
	_ = json.Unmarshal(baseline, &top)
	rule := top["routing"].(map[string]any)["rules"].([]any)[1].(map[string]any)
	var ips []string
	for i := 1; i <= 128; i++ {
		ips = append(ips, "1.2.3."+strconv.Itoa(i)+"/32")
	}
	rule["ip"] = ips
	baseline, _ = json.Marshal(top)
	approvals := businessApproval(t, baseline)
	for _, ip := range ips {
		a := approvals.Approved[0]
		a.CIDR, a.Reason = ip, strings.Repeat("r", 256)
		approvals.Approved = append(approvals.Approved, a)
	}
	approvals.Approved = approvals.Approved[1:]
	if _, err := generateBusinessDirect(baseline, approvals); err == nil {
		t.Fatal("aggregate evidence exceeded 16 KiB without refusal")
	}
}

func TestBusinessDirectAggregateStorageAdmissionIncludesArtifact(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			c, baseline := businessConfig(t)
			first, err := Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			used, err := usedBytes(c.PublishDir)
			if err != nil {
				t.Fatal(err)
			}
			candidateBytes, err := usedBytes(filepath.Join(c.PublishDir, "versions", first.Version))
			if err != nil {
				t.Fatal(err)
			}
			business := &RouterOSBusinessDirect{OutboundTag: "direct"}
			body, err := generateBusinessDirect(baseline, business)
			if err != nil {
				t.Fatal(err)
			}
			// Equal-length generator versions produce the same-sized ordinary
			// candidate. Leave room for that candidate but less than the additional
			// business artifact, against the actual retained bytes on disk.
			c.BudgetBytes = 1 << 20
			padding := c.BudgetBytes - used - candidateBytes - (64 << 10) - int64(len(body)/2)
			if padding <= 0 {
				t.Fatal("fixture has no admission margin")
			}
			if err := os.WriteFile(filepath.Join(c.PublishDir, "retained-fixture"), make([]byte, int(padding)), 0600); err != nil {
				t.Fatal(err)
			}
			c.GeneratorVersion = "next"
			if enabled {
				c.RouterOSBusinessDirect = business
			}
			result, err := Run(context.Background(), c)
			if !enabled {
				if err != nil || result.Status != "published" {
					t.Fatalf("ordinary candidate did not fit the control budget: %v", err)
				}
			} else {
				if err == nil || result.ErrorCode != "capacity" {
					t.Fatalf("business artifact exceeded the same storage budget without refusal: %+v %v", result, err)
				}
				assertCurrent(t, c, first.Version)
			}
		})
	}
}
