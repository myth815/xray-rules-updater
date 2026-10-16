# xray-rules-updater

A small, one-shot Go publisher for a home network using native Xray, MosDNS,
RouterOS and OneXray. The runtime image contains only the static executable and
CA certificates. It has no daemon, database, cron, management UI or proxy core.

## What v0.1 does

- Resolves one GitHub release, then verifies both native DAT assets against that
  release's SHA256 digests. Explicit pinned HTTPS or local assets are also supported.
- Retains `geoip.dat` and `geosite.dat` unchanged; does not expand Xray GEO rules
  into JSON.
- Exports selected MosDNS domain/IP files, preserving domain match types and
  Xray attribute-presence filtering (`category@attribute`, multiple attributes AND).
- Generates a versioned RouterOS CN IPv4 **candidate address list**. It does not
  activate firewall rules, NAT, policy routes or FastTrack.
- Adapts an explicitly supplied, validated full Xray baseline into a complete
  OneXray JSON subscription, preserving rule order, AND conditions, node chains
  and the default outbound. The subscription entry name includes its version.
- Publishes immutable versions, `current` and `previous` pointers, file hashes,
  counts and one overwritten `status.json`. Identical input skips regeneration.
- Uses a process-lifetime lock, checks storage budgets and recovers interrupted
  staging/unreferenced valid versions. It keeps current plus one rollback version.

**This release publishes candidates; it does not replace running Xray/MosDNS
assets, restart services, activate CN bypass or apply a client configuration.**
Those operations require separate target-core validation and host application
checks. A successful publication does not claim any consumer loaded the files.

## Run

Copy `examples/config.json` and replace `baseline.json` with a complete, already
validated baseline. Samples contain fictitious nodes and are not a working proxy.
The publisher deliberately does not merge a live Xray `confdir`; take a coherent
full snapshot before running it.

```sh
docker run --rm --memory=192m --cpus=1 \
  -v "$PWD/config:/config:ro" \
  -v "$PWD/publish:/publish" \
  ghcr.io/myth815/xray-rules-updater:v0.1.0
```

Mount the publication into an existing Nginx instance read-only. Serve
`current/onexray.json` as the stable complete-config subscription URL; immutable
`versions/<version>/...` URLs allow inspection and bounded rollback. Restrict
the subscription endpoint to LAN/return-home VPN: generated client files can
contain credentials, even though this repository and image contain none.

Default directories/files are private (`0700`/`0600`). For an Nginx worker with a
different UID, set `serve_group_id` to a shared numeric group and grant the worker
that group: output directories/files become `0750`/`0640`. Verify an actual GET
from that worker before considering publication integrated. Parent mount paths
must also permit traversal. Do not enable directory indexes or publish inputs.

Run daily or on baseline changes using the host scheduler. On RouterOS, import
the ARM64 image once, keep its root directory, disable start-on-boot/restart and
container log forwarding, then have the scheduler start the container. Completion
exits the process. Do not pull/delete the image or its root on every run. The
host should compare the old/new `status.json.run_id`, require a new successful
status (`published`/`unchanged`), and separately verify consumer application.
`stopped` or a previous success file alone is not success for a new run.

If downloads need a proxy, supply `HTTPS_PROXY` only to this task's environment;
the publisher honors Go's standard proxy environment variables. It never changes
system proxy, DNS or routing. For reproducibility replace `source.tag: latest`
with a fixed release tag. `latest` is queried once per run; the resolved tag and
both hashes are frozen before asset downloads. Assets without release SHA256
digests are rejected rather than trusted implicitly.

Explicit offline source format:

```json
{
  "release_id": "202610132205",
  "geoip": {"path": "/input/geoip.dat", "sha256": "<64 hex characters>"},
  "geosite": {"path": "/input/geosite.dat", "sha256": "<64 hex characters>"}
}
```

Replace the entire `source` object; do not mix it with `repository`/`tag`.

## Boundaries that matter

- The host remains responsible for routing priorities. Early CN IP bypass can
  override higher-priority domain policies and is not automatically equivalent
  to an Xray domain-first policy. The generated address list is intentionally idle.
- DNS upstream selection and traffic egress are related but different actions.
  Exporting common data does not automatically make those policies consistent.
- `client.keep_outbounds` retains dependency closure and baseline order; removing
  the baseline's first/default outbound is rejected. Pure inbound-only routing
  can be dropped explicitly. Mixed inbound/business conditions, DNS-generated
  inbound policies, unhandled observers and host-bound sockets/interfaces/marks
  require explicit adaptation and otherwise fail.
- Nonempty shared `transport`, arbitrary top-level modules and external file
  references are rejected. The adapter is structural, not a replacement for
  `xray run -test` with the target core and actual DAT files.
- Native GEO references in the client are checked for required categories and
  supported attribute selection. Unsupported expressions fail publication.
- No advertising category is exported by default. Existing MosDNS ad references
  must be migrated explicitly before changing production asset paths.
- OneXray full-config refresh and GEO updates are separate. In the validated
  client release, refresh inserts a new entry; selecting it and reconnecting are
  still client actions. The publisher does not claim an atomic client update.
- The storage budget counts retained publications plus the candidate; free-space
  reserve is additional. Defaults: 160 MiB publication budget, 64 MiB disk reserve,
  40 MiB per DAT, 300 seconds. Go uses one execution thread and a 96 MiB soft heap
  limit; container limits remain the hard resource boundary. Measure on the host.
- Pre-commit errors keep the old current version. Pointer changes are atomic,
  but current/previous are not one cross-file transaction. A directory-sync error
  after current changes reports `published_durability_uncertain`, not a false
  promise that current was unchanged. Corrupt/unknown old directories are not
  silently deleted; operator inspection may be required.

## Build and checks

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/xray-rules-updater
```

Tests use synthetic DATs, fake nodes and mocked HTTPS. Optional local fixture
tests can compare derived data against an independently generated pinned release.
CI tests then publishes Linux ARM64 and AMD64 images to GHCR, with immutable
commit tags and version tags. Deploy a tested version/digest; `latest` is a
convenience tag. Real baselines, DAT downloads and output directories are ignored
by Git and excluded from the Docker build context.

MIT licensed. Upstream data licenses remain with their respective publishers.
