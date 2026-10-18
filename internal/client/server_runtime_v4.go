package client

import (
	"encoding/json"
	"fmt"
)

// v4 is the complete, single-file RouterOS runtime. The manifest and native
// validator retain this entire input; only the client projection removes the
// exact gateway-owned environment, log settings and TUN listener. The v3 policy
// contract is unchanged and validates everything that remains.
func normalizeServerRuntimeV4(baseline []byte, overlay Overlay) ([]byte, error) {
	top, err := readObject(baseline, "baseline")
	if err != nil {
		return nil, err
	}
	if !sameRuntimeJSON(top["log"], map[string]any{"access": "none", "error": "none", "loglevel": "warning", "dnsLog": false}) {
		return nil, fmt.Errorf("ai66-v4 gateway logging differs from the owned runtime")
	}
	if !sameRuntimeJSON(top["env"], map[string]any{"xray.cone.disabled": "true"}) {
		return nil, fmt.Errorf("ai66-v4 gateway environment differs from the owned runtime")
	}
	inlets, err := readArray(top["inbounds"], "server inbounds")
	if err != nil {
		return nil, err
	}
	kept := make([]json.RawMessage, 0, len(inlets))
	tunCount := 0
	for _, raw := range inlets {
		in, err := readObject(raw, "server inbound")
		if err != nil {
			return nil, err
		}
		if !sameRuntimeJSON(in["tag"], "tunIn") {
			kept = append(kept, raw)
			continue
		}
		tunCount++
		if !sameRuntimeJSON(raw, map[string]any{
			"tag": "tunIn", "protocol": "tun",
			"settings": map[string]any{"name": "xray0", "MTU": 1500, "userLevel": 0},
			"sniffing": serverRuntimeV2First(),
		}) {
			return nil, fmt.Errorf("ai66-v4 gateway TUN listener differs from the owned runtime")
		}
	}
	if tunCount != 1 {
		return nil, fmt.Errorf("ai66-v4 requires exactly one gateway TUN listener")
	}
	delete(top, "log")
	delete(top, "env")
	top["inbounds"] = oneXrayJSON(kept)
	return normalizeServerRuntimeV3(oneXrayJSON(top), overlay)
}
