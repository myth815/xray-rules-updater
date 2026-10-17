# RouterOS host application

These files are deployment building blocks. They do not install containers,
change production mounts or enable schedulers. Review the public sample values
in `routeros/update.rsc` and perform the controlled migration below first.

## First deployment and upgrades

Bootstrap is a separate migration with an exact rollback snapshot. The daily
controller requires an existing valid ACK and a concrete old publication version;
it does not fabricate a previous version or migrate a legacy configuration.

1. Mount the entire publication read-only at `/rules` in Xray, MosDNS and Nginx.
   Attach one dedicated Xray environment list as the only source of
   `XRAY_LOCATION_ASSET`, initially `/rules/versions/<acknowledged-version>`.
   Direct container environment entries must not override it.
2. Migrate the **complete** MosDNS configuration to the reviewed configuration.
   Replacing only `dat_exec.yaml` cannot remove old advertising-filter references.
   Mount its complete configuration read-only at `/etc/mosdns`. Provide a data
   template containing `@@RULES_ASSET_DIR@@`; the controller compares the complete
   rendered data file, not just a matching version substring.
3. Provide generation, native-verification and health inputs. Verification needs
   the target Xray/MosDNS binaries and complete configurations mounted read-only.
   Health uses the production DNS server and explicit HTTP proxy.
4. Set `require_apply_ack: true`, `apply_ack_path: "/host-state/applied.json"`
   and `apply_transaction_path: "/host-state/transaction.json"`. The ordinary
   producer must mount host-owned state read-only. No publisher action writes it.
5. Prepare **two complete mount-list sets for the same stopped updater**:

   | Destination | Producer role | Host-control role |
   | --- | --- | --- |
   | `/config` | inputs, RO | same inputs, RO |
   | `/publish` | publication, RW | same publication, RW |
   | `/host-state` | ACK/journal directory, RO | same directory, RW |
   | `/host-mosdns` | absent | complete MosDNS configuration directory, RW |
   | `/host-nginx` | absent | Nginx managed control directory, RW |
   | `/diagnostics` | exact `diagnostics_root`, RW | absent |
   | verification binaries/configurations | RO as required | optional RO |

   Set `producer_mountlists` and `host_mountlists` to the actual attached list
   names in their exact order. The host controller validates each controlled
   source/destination/mode, forbids destination overrides and any extra RW mount.
   The explicit producer diagnostic directory preserves native-verification diagnostics and must not
   overlap publication, state, inputs, MosDNS or Nginx control directories.
   Keep updater `start-on-boot=no`, with no legacy direct `mount` entry. Before
   exposing host RW mounts it sets a non-authorizing host command; it restores
   producer RO mounts before another generation, verification or health run.
6. Use an image supporting `-host-control-config` and provide the local-only
   `/config/host-control.json`, for example:

   ```json
   {
     "publish_dir": "/publish",
     "state_dir": "/host-state",
     "mosdns_data": "/host-mosdns/dat_exec.yaml",
     "mosdns_template": "/config/mosdns-dat_exec.template.yaml",
     "nginx_control_dir": "/host-nginx",
     "request_path": "/config/host-request.json",
     "max_file_bytes": 60000
   }
   ```

   Match the physical directories to the script's `state_root`, `mosdns_data`
   and `nginx_state`. The helper never accepts arbitrary request paths. Verify
   the image's runtime UID/GID can read its inputs and sync/rename the three
   host directories; Nginx must also be able to read the managed include.
7. Install the Nginx helper and stable locations. Publish and acknowledge the
   first controlled version and enable the internal metadata endpoint. Verify
   actual Xray assets, full MosDNS data, Nginx authoritative state, DNS/proxy
   health and the HTTPS subscription before installing the daily controller.

For an upgrade, disable both owning schedulers and require no running owning
script job, a positively stopped worker, and **no pending journal**. Resolve an
old-format pending transaction with its matching controller first. Snapshot the
old image/mount attachments, helper, controller sources and scheduler settings.
Stage the new host config/mount definitions, then install the new image, helper
and named sources together; do not run new source against an older image/helper.
Validate the new roles and recovery source before enabling schedules. If no
transaction has begun, the saved image/mount/source/helper snapshot provides the
upgrade rollback. Once a new journal exists, resolve it using the new controller
and helper before reverting deployment files. Do not delete a journal to bypass
an upgrade check.

## Named scripts and schedules

`routeros/update.rsc` is a **script source**, not an importable installation file.
Importing the body executes it; anonymous execution is rejected because it
cannot participate in the named-job lock. Install two named `/system script`
sources with identical public parameters:

- `XrayRulesUpdate`: `mode="update"`.
- `XrayRulesRecover`: `mode="recover-only"`.

Keep `script_name` and `recover_script_name` distinct and identical in both
sources. The sum of jobs for those names must be exactly one. Invoke the named
script with `/system script run`; do not wrap its body in an anonymous `:execute`.
For background dispatch, execute `/system script run XrayRulesUpdate` inside
`:execute`, preserving the named job.

After isolated target-router validation, a daily scheduler can invoke the update
script at the selected time. A separate scheduler with `start-time=startup` and
`interval=0` invokes only `XrayRulesRecover`. Both script and scheduler need
`read,write,policy,test,sensitive`. RouterOS 7.23 named-script tests with forced
script permissions showed that the base set could create/write `.txt`, but
creating or renaming to `.json` was denied; adding `ftp` alone did not help.
Adding `sensitive` without `ftp` allowed inline and global-function JSON
creation/readback/removal. Request staging therefore needs `sensitive` even
though the Go host role writes the critical state. Validate installed permissions
and container operations on the target router.
Keep the updater itself stopped and not auto-started.

Recovery performs local journal/actual-state checks and repairs before needing
Nginx metadata or upstream DNS. It never generates/downloads a release. After
repair it starts the controlled consumers as needed and checks listener and
production health. An unavailable network may fail that final check; unresolved
owned state remains held for the next recovery attempt or intervention.

## Daily transaction and interruption recovery

With no pending application, the host runs the stopped producer once. If
`current` is pending, it handles that version before generating another release.
Every one-shot task requires a fresh completion `run_id` and the exact container
identity in a positively stopped state. Host-control actions also require a
fresh request nonce, expected action/transaction and `status=complete` with
`completed=true`. Its complete false payload is durably fenced before the true
marker is published; missing/false completion is rejected.
A stopped container or cached status alone proves nothing.

Before changing a consumer, the local Go host role atomically writes the journal,
syncs its file and parent directory, and checks exact readback. It verifies the
old ACK and MosDNS snapshot against the actual files. The journal binds the
three consumer identities and attachments to the concrete old/desired versions.
The producer cannot advance or prune while that journal exists.

The host stops Xray, pins its asset environment to the candidate and restarts it;
then stops MosDNS, durably renders the complete candidate data file and restarts
it. It checks those actual bindings and production health before activating
Nginx. The stable HTTPS manifest must serve the desired version before a durable
ACK is written. Nginx commits its authoritative state before durable journal
removal. The helper rechecks actual MosDNS, ACK and committed Nginx state before
removing the journal.

Recovery commits a new version only when **all** of these agree: ACK version and
transaction owner, actual Xray asset environment, complete actual MosDNS data,
and actual owned Nginx include/state. Generic connectivity and an ACK cannot
prove which GEO files a consumer uses. A durable `rolling_back` decision always
continues rollback, even if a new ACK survived. Unknown identities, attachments,
foreign state or data outside the recorded old/desired states are rejected before
stopping consumers.

Rollback first durably records `rolling_back`, then stops the three consumers.
The host role restores MosDNS and Nginx locally while Nginx is positively stopped;
it does not depend on an operational Nginx process or DNS to repair the include.
It restores Xray's old environment, starts the consumers and proves old actual
bindings, health and HTTPS version. Only then does it restore the old ACK and
durably remove the journal. A same-version ordinary update also rejects actual
asset drift; it cannot report success based solely on the publication version.

RouterOS `/file set` is used only for untrusted request staging and overwritten
telemetry. It is not a durability fence: RouterOS NAND writeback can be delayed.
All ACK/journal/MosDNS changes and journal deletion use file sync plus directory
sync in the host role. The Nginx helper uses atomic replacement and real Linux
`sync` for its owner/backup/include/state. No fixed writeback sleep substitutes
for these operations. [MikroTik Files documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/2555971/Files)

RouterOS's file API cannot follow the publisher's `current` symlink. Only current
metadata is read from `current_manifest_url`, an internal alias to
`/rules/current/manifest.json`; restrict it to trusted management clients. The
HTTPS subscription manifest represents the applied version. Ordinary status,
ACK and journal reads use their real host paths. Failed metadata requests are
never treated as an empty first publication.

The producer retains `current` and `previous`; the host keeps one bounded journal
and the Nginx helper one include backup. Telemetry is overwritten. The updater
exits after every task and no additional container remains resident. The host
never enables the generated RouterOS CN candidate address list.

## Resource limits

Generation, health and local host-control use `memory-high=160 MiB` /
`memory-max=192 MiB`. Only the exact native-verification command temporarily uses
`224 MiB` / `256 MiB`; final cleanup restores the generation limits and producer
RO role. Existing CPU pinning is unchanged.

The 96 MiB Go soft memory limit covers the Go runtime, while the cgroup limit also
covers native Xray/MosDNS validation children. On the target router verification
timed out at `160/192 MiB` with approximately `177.6 MiB` current memory; at
`224/256 MiB` it completed in `10.348 seconds`. This is consistent with a
`memory.high` reclaim window and does not establish an OOM event.

## Nginx helper

Run `nginx/apply.sh` inside the existing Nginx container using `/bin/sh` and
RouterOS `no-sh`. The host dispatches each shell call to an independent
`:execute` child job: a synchronous container shell takes over the SSH CLI,
and a second call in that context can terminate the parent sequence. The named
parent waits at most 35 seconds for both its fresh receipt and that exact child
to exit; receipt completion alone precedes helper EXIT and flock release. It
checks the child owner/start identity before cancellation and never cancels an
already departed job ID. No output-file capture or additional FTP policy is used.
Defaults are `/etc/nginx/rules` writable control and `/rules` read-only
publication; `RULES_CONTROL_DIR`, `RULES_PUBLISH_DIR` and `NGINX_BIN`
override them. `flock` and `sync` are mandatory. The host Go role and shell helper
share `.apply.flock`; keep its inode rather than unlinking it during cleanup.

Include `active.inc` in the stable server block:

```nginx
include /etc/nginx/rules/active.inc;
location = /onexray.json { alias /rules/versions/$rules_version/onexray.json; }
location = /geoip.dat { alias /rules/versions/$rules_version/geoip.dat; }
location = /geosite.dat { alias /rules/versions/$rules_version/geosite.dat; }
location = /manifest.json { alias /rules/versions/$rules_version/manifest.json; }
```

Before enabling versioned client GEO or provider subscription metadata, also
copy `nginx/versioned-assets.conf` into the stable Nginx configuration directory
and include it **inside the same private server block**:

```nginx
include /etc/nginx/rules/versioned-assets.conf;
```

The current-version routes above do not serve the immutable URLs generated for
the client. The additional route serves only
`/versions/<identifier>/geoip.dat` and `geosite.dat`, inherits the server's access
policy, rejects symlinks and does not expose configs or staging directories.
Its version header names the requested version rather than the current one.
Retained files remain readable; a pruned version returns 404. Validate both
current and previous DAT URLs and compare their downloaded SHA256 with the
corresponding manifest before enabling client metadata. Keep the publisher
mount read-only and do not replace this allowlist with a directory-wide alias.

`nginx/probe_versioned_assets.py` is an opt-in HTTP integration probe for an
isolated loopback fixture; it is separate from the default unit tests. Its
fixture uses `test-v1` with the script's two `BODIES`, `test-v0` with `OLD_BODY`,
a file and a directory symlink to an outside sentinel, and a server ACL that
allows only 127.0.0.1. Set `VERSIONED_ASSET_TEST_URL=http://127.0.0.1:8080` inside
that isolated network to check bytes, headers, ranges, access policy, allowlist
and symlink denial. Never point this synthetic fixture probe at production.

Apply the intended access policy: the complete client configuration contains
proxy credentials. The helper does not add authentication or expose a port.
Commands are `activate VERSION TOKEN REQUEST_ID`, `restore TOKEN REQUEST_ID` and
`commit TOKEN REQUEST_ID`. Legacy calls may omit the request ID, but the daily
controller always supplies and verifies a fresh 16-hex nonce.

`apply-state.json` remains the authoritative actual-owner record.
`apply-result.json` is a separate bounded per-request receipt. Its complete false
payload is synced before a fresh `completed:true` marker is exposed. The host
checks request, action, transaction, status and version. A pre-activation no-op
restore or rejected foreign request cannot overwrite the old authoritative owner.

Nginx reload is asynchronous. The host waits at most 20 seconds for HTTPS to serve
the desired manifest, accepting only a previous worker's 404 or older valid
version during that readiness window. TLS verification stays enabled; DNS,
transport, other HTTP and malformed metadata failures abort. Production DNS and
proxy business probes are each single requests after their listener readiness
conditions, rather than retrying media downloads.

## Local and target validation

Local tests never start a network service:

```sh
/bin/sh -n deploy/nginx/apply.sh
python3 -m unittest discover -s deploy/nginx -p 'test_apply.py' -v
python3 -m unittest discover -s deploy/routeros -p 'test_update.py' -v
```

Shell tests use fake Nginx/sync executables and real host-kernel flock semantics.
They cover ownership, fresh completion, interrupted sync, rollback and malformed
state; they do not simulate NAND power loss. RouterOS tests bind source contracts
to the interruption-state matrix; they do not execute RouterOS. Target validation
must additionally parse and define the actual functions, exercise isolated
worker/mount/helper primitives, run named-script fault fixtures and validate
startup scheduling. Keep those fixtures separate from production consumers.

## Native TUN routing barrier (experimental)

`xray-tun/fail_closed_routes.sh` manages IPv4 routing inside a dedicated gateway
network namespace. It is not installed or enabled by the updater. Host firewall
and complete gateway lifecycle acceptance are still required before deployment.

An unavailable proxy may interrupt service. It must not send protected traffic
through the ordinary domestic route. Install the barrier before accepting or
forwarding client packets, then add the active TUN route only after Core is ready:

```sh
sh /test/fail_closed_routes.sh prepare 172.28.66.0/24 20 2000 xray0
# Start Core and wait for xray0 inside this private namespace.
sh /test/fail_closed_routes.sh activate 172.28.66.0/24 20 2000 xray0
```

The source rule selects a table containing an `unreachable` default at metric
32767 and, while Core is ready, a TUN default at metric 10. Losing the TUN route
therefore rejects traffic instead of allowing lookup to continue to the main
table. The helper refuses occupied priorities/tables at preparation and rejects
foreign routes when checking its barrier. `XRAY_ROUTE_IP` can name the platform's
absolute IP-command path; it defaults to `/sbin/ip`.

Before orderly exit, disable packet forwarding in the gateway namespace. The
optional `deactivate` action removes only its active TUN route. Keep the source
rule and unreachable default until that namespace is destroyed. There is no
cleanup command that deletes the barrier. Core crashes and restarts must preserve
this behavior; the host must also prevent direct WAN fallback during container
creation and teardown. This helper alone is not proof of complete lifecycle or
IPv6 protection.

`xray-tun/host_barrier.rsc` is an opt-in RouterOS function. For an existing,
dedicated FIB table it prepares or checks a persistent blackhole default at
distance 254. It accepts at most one expected private unicast next hop, leaves
that next hop unchanged, and refuses other routes or ambiguous ownership. Keep
the blackhole when stopping or replacing the gateway. Its presence does not
prove firewall coverage, forwarding readiness, or actual traffic acceptance.

`xray-tun/gateway.sh` is a separate candidate PID 1 wrapper, not part of the
one-shot update worker. Mount its directory at `/gateway`, the existing JSON
modules at `/etc/xray`, and the shared publication at `/rules`, all read-only.
It requires `XRAY_GATEWAY_INTERFACE`, `XRAY_GATEWAY_ADDRESS`,
`XRAY_GATEWAY_SOURCE_CIDR`, `XRAY_LOCATION_ASSET` and
`XRAY_CONE_DISABLED=true`. Its Core must have passed native TUN and per-destination
UDP routing acceptance on the target platform; this repository does not bundle
or publish a Core binary.

The wrapper disables IPv4 forwarding, validates the original modules with the
native overlay, installs the source rejection table and a rejection rule for
other forwarded sources, starts Core, and enables forwarding after TUN readiness.
On exit it disables forwarding before terminating Core. It writes no ongoing
access or error logs. `native.json` adds one `tunIn` listener and logging settings;
it contains no nodes, DNS servers, routing policy or expanded GEO collections.

Modules are supplied individually in lexical order and the overlay is supplied
last. Xray appends `-confdir` modules after explicit config arguments, so combining
`-config native.json` with `-confdir /etc/xray` would not provide the same overlay
order. Configuration validation and update/recovery must continue to use the
actual consumer identity and asset version. Configure final boot and restart
properties while the candidate is stopped, then verify its process generation
and forwarding state after starting it. Do not change a running consumer's
lifecycle properties as a substitute for a verified restart procedure.
