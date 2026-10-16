# RouterOS host application

These files are deployment building blocks. They do not install containers,
change existing mounts, migrate production configurations, or enable a
scheduler. Review the public sample values in `routeros/update.rsc` before use.

## First deployment

Bootstrap is a separate, controlled migration with an actual rollback snapshot.
Complete and verify it before running the daily script:

1. Mount the entire publication read-only at `/rules` in Xray, MosDNS and Nginx.
   Mount private updater inputs at `/config`, writable publication output at
   `/publish`, and host-owned acknowledgement/journal state at `/state`.
2. Attach a dedicated Xray environment list as its only source of
   `XRAY_LOCATION_ASSET`. Confirm which original asset path must be restored if
   the first application fails.
3. Migrate the **complete** MosDNS configuration to the reviewed, advertising-free
   configuration. A replacement `dat_exec.yaml` cannot remove references from an
   older main configuration. Provide a daily data template containing
   `@@RULES_ASSET_DIR@@` and record the real production path in the script.
4. Provide generation, native-verification and production-health inputs. Native
   verification needs the target Xray/MosDNS binaries and complete configurations
   mounted read-only. Health checks use the actual production DNS server and
   explicit HTTP proxy.
5. Set `require_apply_ack: true`, `apply_ack_path: "/state/applied.json"` and
   `apply_transaction_path: "/state/transaction.json"`. Only the host writes
   these two records. Keep them outside the read-only configuration inputs.
6. Install the Nginx helper and stable locations, validate its configuration, and
   check that RouterOS can read the small state files through their actual host
   paths. Publish the first controlled `current` and enable its internal metadata
   endpoint before the daily body runs. Install the RouterOS script under the
   configured `script_name` and validate one manual run before enabling a scheduler.

`routeros/update.rsc` is the body of one named `/system script`; importing the
body executes it immediately. A scheduler should invoke the named script. The
body assumes the bootstrap mounts, environment attachment and complete MosDNS
migration are already correct. It applies only a controlled publisher `current`
version which passes native verification; it does not perform that initial
migration or activate the generated RouterOS CN candidate list.

RouterOS's file interface does not traverse the publisher's `current` symlink.
The script reads only that manifest from `current_manifest_url` (sample:
`http://172.28.55.5:8089/current-manifest`), served by an internal Nginx alias to
`/rules/current/manifest.json`. Keep this metadata endpoint reachable only within
the trusted management network. It is separate from the stable subscription's
applied-version manifest. Status files, ACK and journal retain direct file reads.
The daily body requires an existing current; HTTP, network and invalid-metadata
errors abort the task rather than being treated as an empty initial publication.

## Daily transaction

When no application is pending, the host runs the stopped updater once. If
`current` is already pending, it retries that version before requesting another
release. A fresh completion `run_id` is required for each generation,
verification and health task; a stopped container is not evidence of success.

For a changed version, the host records one bounded transaction journal, pins
Xray and MosDNS to `/rules/versions/<version>`, checks production health, then
switches Nginx's active include. It checks the stable manifest before writing the
acknowledgement. While the journal exists, the producer cannot advance or prune
rollback data, including the acknowledgement-to-commit window.

Nginx reload is asynchronous. The host waits up to 20 seconds for the HTTPS
manifest to serve the desired version, allowing only a previous worker's 404 or
older valid version during that window. TLS verification stays enabled; DNS,
transport, other HTTP and malformed metadata errors fail immediately.

An interrupted transaction is resolved before the next generation. Recovery
uses the actual saved environment, MosDNS data and acknowledgement. On the first
application, the original assets are the rollback target; no previous publication
version is invented. Failed recovery retains the journal for intervention.

The producer retains `current` and `previous`; the host keeps one journal and the
Nginx helper keeps one include backup. State and status files are overwritten,
not appended. The updater stops after each task.

The sample host uses `memory-high=160 MiB` / `memory-max=192 MiB` for generation
and health. Only the exact native-verification command temporarily uses
`224 MiB` / `256 MiB`; cleanup restores the generation limits. The host does not
change the existing CPU pinning. No updater process remains resident after a
completed task.

The updater's 96 MiB Go soft memory limit applies to its Go runtime, not the
external Xray/MosDNS validation children. The container cgroup limits cover their
combined memory. In the target-router trial, native verification timed out after
60 seconds at `160/192 MiB` with approximately `177.6 MiB` current memory; at
`224/256 MiB` it completed in `10.348 seconds`. These observations motivated the
phase-specific limits and are consistent with a `memory.high` reclaim window;
they do not establish an OOM event. This adjustment does not add network retries.

## Nginx helper

Run `nginx/apply.sh` inside the existing Nginx container using `/bin/sh` and
RouterOS `no-sh`. Its defaults are `/etc/nginx/rules` for writable control state
and `/rules` for the read-only publication. `RULES_CONTROL_DIR`,
`RULES_PUBLISH_DIR` and `NGINX_BIN` can override these paths.

Include `active.inc` in the server block containing the stable locations. It
contains only `set $rules_version "<version>";`. Locations should resolve the
controlled version, for example:

```nginx
include /etc/nginx/rules/active.inc;
location = /onexray.json { alias /rules/versions/$rules_version/onexray.json; }
location = /geoip.dat { alias /rules/versions/$rules_version/geoip.dat; }
location = /geosite.dat { alias /rules/versions/$rules_version/geosite.dat; }
location = /manifest.json { alias /rules/versions/$rules_version/manifest.json; }
```

Bootstrap must provide a valid initial include. Apply the intended access policy
to these locations: the generated complete configuration contains proxy
credentials. The helper itself neither adds authentication nor exposes a port.

Commands are `activate VERSION TOKEN`, `restore TOKEN` and `commit TOKEN`.
The helper uses a process-lifetime `flock` where available, validates before
reload, and atomically replaces `apply-state.json`. Its successful return proves
that the helper ran; the host separately checks what the stable manifest serves.
Without `flock`, only the single owning host script may call it.

Local helper tests use a fake Nginx executable and do not start a service:

```sh
/bin/sh -n deploy/nginx/apply.sh
python3 -m unittest discover -s deploy/nginx -p 'test_apply.py' -v
```

RouterOS command syntax, container names, filesystem paths, permissions and
startup behavior still require validation on the target router. These local
tests do not claim that the RouterOS script has passed production validation.
