# xray-rules-updater

Xray GEO 规则更新器：同步 MosDNS、RouterOS 数据，并生成 OneXray 完整配置。

A small, one-shot Go publisher for a home network using native Xray, MosDNS,
RouterOS and OneXray. The runtime image contains only the static executable and
CA certificates. It has no daemon, database, cron, management UI or proxy core.

## v0.2 scope (in preparation)

The interface below is being prepared for v0.2.0. It does not claim that a
production deployment, consumer reload or client update has passed acceptance.

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
- Supports a strict read-only snapshot of disjoint native configuration modules,
  explicit client socket-field omissions and an exact legacy-ad-rule migration.
- Publishes immutable versions, `current` and `previous` pointers, file hashes,
  counts and one overwritten `status.json`. Identical input skips regeneration.
- Uses a process-lifetime lock, checks storage budgets and recovers interrupted
  staging/unreferenced valid versions. It keeps current plus one rollback version.
- Can require a host-owned application acknowledgement before admitting another
  different publication. Native verification and live health checks are separate
  one-shot modes; the host still applies or rolls back consumer configuration.

**This release publishes candidates; it does not replace running Xray/MosDNS
assets, restart services, activate CN bypass or apply a client configuration.**
Those operations require separate target-core validation and host application
checks. A successful publication does not claim any consumer loaded the files.

## Run

Copy `examples/config.json` and replace `baseline.json` with a complete, already
validated baseline. Samples contain fictitious nodes and are not a working proxy.
Choose exactly one of `baseline` or `baseline_directory`. The latter reads the
immediate directory's regular `.json` files, accepts disjoint top-level modules
and empty `{}` files, and requires two identical reads. Duplicate modules,
symlink directories/files, detected edits and oversized snapshots fail closed.
The limits are 256 JSON files and 4 MiB in total. This supports the conventional
one-module-per-file layout; it does not reproduce arbitrary Xray `confdir` merge
semantics or make concurrent multi-file edits transactional. Mount it read-only
and complete coherent baseline edits before scheduling generation.

```sh
docker run --rm --memory=192m --cpus=1 \
  -v "$PWD/config:/config:ro" \
  -v "$PWD/publish:/publish" \
  ghcr.io/myth815/xray-rules-updater:v0.2.0
```

Mount the publication into an existing Nginx instance read-only. Immutable
`versions/<version>/...` URLs allow inspection and bounded rollback. For an
integrated deployment, point the stable subscription and DAT endpoints at the
host's explicitly selected **applied** version, for example through an Nginx
include. `current` identifies the publisher's candidate and may precede consumer
application; changing it must not silently advance the served applied version. Restrict
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

For an offline RouterOS import, a recent containerd-backed `docker save` may
include an OCI index that RouterOS 7.23 cannot extract. The build-only helper
converts that outer archive into classic Docker-save format, checking each
uncompressed layer against the original config's `diff_ids`; it does not change
the executable or layer contents and is not included in the runtime image.

```sh
docker pull --platform linux/arm64 ghcr.io/myth815/xray-rules-updater:v0.2.0
docker save --platform linux/arm64 -o image.tar ghcr.io/myth815/xray-rules-updater:v0.2.0
python3 tools/docker_save_for_routeros.py image.tar image-routeros.tar
```

If downloads need a proxy, supply `HTTPS_PROXY` only to this task's environment;
the publisher honors Go's standard proxy environment variables. It never changes
system proxy, DNS or routing. For reproducibility replace `source.tag: latest`
with a fixed release tag. One successful `latest` response is resolved per run; the tag and
both hashes are frozen before asset downloads. Assets without release SHA256
digests are rejected rather than trusted implicitly.

### RouterOS startup order

Prepare the configuration, mounts, proxy environment and bridge port before
starting the one-shot container. For its dedicated veth endpoint, with no
downstream bridge, explicitly set `edge=yes` on **that port only**:

```routeros
/interface bridge port set [find where interface="VethXrayRulesUpdater"] edge=yes
```

Use the actual updater veth name. On an RSTP bridge, `edge=auto` can initially
hold a freshly started veth out of forwarding, even when the container process
has started. This can recur on each stop/start. Image import completion is not
network readiness. [MikroTik documents the edge-port behavior here](https://help.mikrotik.com/docs/spaces/ROS/pages/328068/Bridging%2Band%2BSwitching).

In an isolated RB5009 A/B test, the same single-request probe with no retry or
warm-up failed once under `auto` and connected after about three seconds on its
second start. Under `yes`, both starts connected in 0–1 ms and returned HTTP 200.
Bridge monitoring confirmed the corresponding forwarding states. The updater
endpoint setting fixes this startup prerequisite; do not disable RSTP globally
or apply an edge setting to ports connected to another bridge.

The configured proxy must also be available before the scheduler launches this
task. Application requests then select the proxy, establish TCP/CONNECT and TLS,
resolve one release, download its pinned assets, validate and publish. No warm-up
request or fixed startup sleep is needed for the observed bridge issue.

Limited retries are fallback for unexpected transient faults, not a substitute
for those startup prerequisites. Transient connection failures,
connection resets/timeouts and HTTP 500/502/503/504
receive at most three attempts per HTTP request, including the initial attempt,
with bounded delays within the task deadline. Certificate,
hash, size and policy validation errors are not retried or bypassed. Error codes
distinguish transport/TLS/HTTP failures without logging URLs or credentials.

### Optional host application

`deploy/routeros/update.rsc` is a parameterized host script body, not an automatic
installer. `deploy/nginx/apply.sh` controls a small Nginx version include. Install
and validate each step on the target RouterOS before enabling a scheduler.

Complete the initial migration separately with a real rollback snapshot:

- Mount the entire publication read-only at `/rules` in Xray, MosDNS and Nginx.
- Attach the dedicated Xray environment list as the **only** source of
  `XRAY_LOCATION_ASSET`; each applied value pins `/rules/versions/<version>`.
- Migrate the complete MosDNS configuration away from retired advertising
  references. The daily script only renders `dat_exec.yaml` from a reviewed
  template containing `@@RULES_ASSET_DIR@@`; changing that file alone cannot
  fix an old main configuration which still uses an ads plugin.
- Mount the real target binaries/configurations read-only into the updater for
  native verification. Supply separate generation, verification and health JSON
  inputs. Its native health task checks the production DNS server and explicit
  HTTP proxy; container `running` alone is insufficient.
- Keep private inputs under `/config`, host acknowledgement/journal under
  `/state`, and publications under `/publish`. Set `require_apply_ack: true`,
  `apply_ack_path: "/state/applied.json"` and
  `apply_transaction_path: "/state/transaction.json"` in the updater config.
  The host can write state; the updater only reads these host-owned records.
- Configure Nginx's stable locations to use the controlled `active.inc` version,
  rather than following publisher `current` before native application passes.
- Publish the first controlled `current` and expose its manifest through an
  internal metadata endpoint before starting the daily body. RouterOS cannot
  traverse the `current` symlink through `/file`; only this metadata read uses
  HTTP, while status and host state files retain direct file reads. A failed
  metadata request aborts the task.

The host retries a pending current version before asking for another release.
It requires fresh task IDs for generation, verification and native health, then
restarts Xray before MosDNS, checks the stable subscription manifest, and writes
the application acknowledgement only after those checks pass. A bounded journal
stores the actual old environment/configuration/acknowledgement for recovery.
The bootstrap rollback uses the original assets and settings; it does not invent
a previous publication version. The host script does not activate CN bypass.

While the journal exists, the producer cannot publish another version or prune
rollback data, even after a new acknowledgement has been written. Remove it
only after host commit completes. Corrupt state fails closed; pending application
does not create an unbounded chain of retained versions. Nginx's helper uses a
process-lifetime `flock` where available and keeps one small include backup. Its
`activate`, `restore` and `commit` commands do not prove a configuration was
served: the host separately fetches the stable manifest and checks its version.

The host sample keeps generation/health at `memory-high=160 MiB` and
`memory-max=192 MiB`, temporarily raising only native verification to
`224/256 MiB` and restoring defaults during cleanup. Existing CPU pinning remains
unchanged. The 96 MiB Go soft limit does not include external target-core child
processes; the cgroup limit covers the combined task. Target-router observations
support allowing more room around `memory.high` during validation, but do not
establish an OOM event. Every task still exits rather than staying resident.

Explicit offline source format:

```json
{
  "release_id": "202610132205",
  "geoip": {"path": "/input/geoip.dat", "sha256": "<64 hex characters>"},
  "geosite": {"path": "/input/geosite.dat", "sha256": "<64 hex characters>"}
}
```

Replace the entire `source` object; do not mix it with `repository`/`tag`.

### Explicit client adaptation

Client adaptation is opt-in and leaves the router baseline unchanged. This
illustrative fragment contains no node credentials; `sample-egress` must be
replaced with an exact tag in the supplied baseline:

```json
{
  "client": {
    "name": "Example client",
    "drop_inbound_rules": true,
    "outbound_sockopt_omissions": {
      "sample-egress": ["mark", "interface"]
    },
    "drop_legacy_ad_rule": true
  }
}
```

`outbound_sockopt_omissions` only removes the named socket fields from the exact
named outbound. There are no wildcard tags or outbound replacements. Supported
fields are `mark`, `interface`, `bindToDevice`, `tproxy`, `tcpFastOpen`,
`tcpKeepAliveIdle`, `tcpKeepAliveInterval`, `tcpMaxSeg`, `tcpMptcp`, `tcpNoDelay`,
`tcpUserTimeout` and `tcpcongestion` (case-sensitive). Unknown tags/fields and
duplicate field requests fail. An already absent approved field is a no-op.
`dialerProxy`, resolution strategies and other routing/identity fields cannot be
removed this way. With no explicit omission, host bindings still fail validation.

`drop_legacy_ad_rule` is a narrow migration switch, not a general rule filter.
It requires exactly one baseline rule with only
`domain: ["geosite:category-ads-all"]` and `outboundTag: "block"`; optional
`type: "field"` and a string `ruleTag` are accepted. Additional conditions or
effects, a changed target, an absent rule or duplicate rules fail. It does not
filter explicit `prepend_rules`. After removing that rule from the authoritative
router baseline, set this switch to `false`; otherwise the expected-rule check
intentionally stops publication. Neither switch changes the default outbound,
rewrites the catchall nor repairs routing policy automatically.

### Application acknowledgement

For host-managed application, a configuration fragment can use:

```json
{
  "baseline_directory": "/live/xray",
  "require_apply_ack": true,
  "apply_ack_path": "/host-state/applied.json"
}
```

Remove `baseline` when using `baseline_directory`. Give the publisher read-only
access to the baseline and host-state mount. The host owns `applied.json` and
atomically writes `{"version":"<applied publication version>"}` only after all
required consumers have passed application checks. The publisher never writes
this acknowledgement. When enabled, a first publication is allowed without an
acknowledgement; retrying the same candidate remains possible, but a different
candidate requires acknowledgement of the existing `current` version. Invalid
state fails closed. This protects the retained predecessor while application is
pending; it does not apply files, authenticate consumer state or provide a
cross-service transaction.

### Native verification and live health

All three CLI modes finish and exit; invoke one mode per task:

```sh
xray-rules-updater -config /config/config.json
xray-rules-updater -verify-config /config/verify.json
xray-rules-updater -health-config /config/health.json
```

- `-config` downloads/derives/publishes candidates and writes `status.json`.
- `-verify-config` checks publication hashes and the baseline snapshot hash,
  runs the mounted target Xray binary with `run -test` against the complete
  server baseline and candidate DAT, and starts a temporary MosDNS instance to
  check its configuration and DNS answers. It writes `verification.json`.
- `-health-config` checks the current publication's integrity, queries the
  configured live DNS server and makes one fixed HTTPS request through the
  configured task-local HTTP proxy. It writes `health.json`; healthy responses
  do not prove the running consumers loaded particular GEO hashes.

Verification configuration supplies absolute `publish_dir`, `xray_binary`,
`xray_config_dir`, `mosdns_binary`, `mosdns_config_dir` paths and an optional
`timeout_seconds` (default 60, maximum 90). Native binaries are supplied as
read-only mounts and are not bundled into this image. Use a separate container
network namespace: temporary MosDNS binds its own DNS port and queries its
configured upstreams. It needs a private writable `/tmp`; bounded native logs
are deleted at completion. Baseline drift before or after verification rejects
the result. This is not a OneXray import, client VPN or traffic-policy test.

Health configuration supplies `publish_dir`, `dns_server`, `proxy_url` and an
optional `timeout_seconds` (default and maximum 30). DNS requires an IP address,
optionally with a port; the proxy must be HTTP/HTTPS without embedded credentials.
Health does not change system proxy settings or restart consumers.

The host coordinator must check fresh run IDs, the intended version and successful
results, then select concrete version paths, apply/reload consumers, verify live
health and write the acknowledgement. On failure it keeps or restores the last
working version. Native validation, publication, actual application, health and
client selection are distinct states; none alone proves the others.

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
- `client.extra_outbounds` can explicitly append client-only nodes such as a
  return-home `home_out`, then `client.prepend_rules` places exact NAS/media rules
  before private/direct routing. Extra nodes undergo the same tag, dependency and
  host-binding validation; they cannot overwrite baseline nodes or change the
  default outbound. Client identities must be supplied explicitly, never derived
  from a router server's private key.
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
  40 MiB per DAT, 300 seconds. Go CPU parallelism is limited to one, with a 96 MiB
  soft Go memory limit; container limits remain the hard resource boundary.
  Measure on the host.
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
CI tests then publishes Linux ARM64 and AMD64 images to GHCR using Docker media
types for RouterOS compatibility, with immutable
commit tags and version tags. Deploy a tested version/digest; `latest` is a
convenience tag. Real baselines, DAT downloads and output directories are ignored
by Git and excluded from the Docker build context.

MIT licensed. Upstream data licenses remain with their respective publishers.
