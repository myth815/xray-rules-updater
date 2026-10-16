# Producer / OneXray adapter contract fixture

These files contain synthetic identities, fake HTTPS URLs and tiny native
protobuf DATs. They are safe to use without a network and are not a working
proxy subscription. The official OneXray release does not yet implement the
provider metadata adapter; this fixture targets that explicit patch contract.

- `input.json` is the producer input, including both DATs as base64 and a native
  baseline with synthetic nodes. Both opt-ins are set by the Go contract test.
- `provider.json` is a complete raw JSON produced by `syncer.Run`, including
  `geodata.assets: [{"file": "...", "url": "..."}]`, matching the existing
  OneXray asset schema.
- `native.json` is the exact same policy with only `geodata` removed, for Core's
  native configuration validation after dependencies are installed.
- `provider-policy-only.json` is the next policy version with unchanged DAT
  bytes. Its URLs change; file names and SHA256 values stay identical.

The patched provider-managed Dart reader should consume the raw JSON verbatim,
find native `ext:` references, infer `ip`/`domain` from their policy fields,
reject undeclared or unused dependencies, verify downloaded or reused bytes,
and install dependencies before native validation and transactional config save.
The custom basename must contain the complete lowercase content SHA256. The
patched reader and shared refresh/index path must derive that expected digest
and verify actual bytes; short or unhashed provider names cannot satisfy this
contract. The server's `manifest.client_assets` retains explicit SHA256. Standard
`geoip.dat`/`geosite.dat` names are not custom-file targets. There is no DAT
expansion or extra router DAT copy.

`TestOneXrayProviderProducerContract` compares actual Go output with these files,
including the policy-only refresh. To deliberately regenerate synthetic golden
JSON after a contract change:

```sh
UPDATE_XRAY_PROVIDER_FIXTURE=1 go test ./internal/syncer -run TestOneXrayProviderProducerContract -count=1
```

Prepare exact content-addressed DAT files and the metadata-free native JSON in
an empty scratch directory, then run a separately verified target Core offline:

```sh
scratch=$(mktemp -d)
python3 tools/prepare_onexray_provider_fixture.py "$scratch"
XRAY_LOCATION_ASSET="$scratch" /path/to/verified/xray run -test -config "$scratch/native.json"
```

A passing native check proves schema and DAT references only. It does not prove
app download/rollback/selection behavior, real egress geography or iOS capture.
