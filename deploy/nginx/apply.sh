#!/bin/sh
# Existing Nginx container only; publication is read-only. Critical include,
# backup and owner writes are atomic and synced before the next mutation.
# activate VERSION TOKEN [REQUEST_ID] | restore TOKEN [REQUEST_ID] |
# commit TOKEN [REQUEST_ID]. The host requires a fresh completed receipt.
set -eu
umask 077

control=${RULES_CONTROL_DIR:-/etc/nginx/rules}
publication=${RULES_PUBLISH_DIR:-/rules}
nginx_bin=${NGINX_BIN:-nginx}
active=$control/active.inc
backup=$control/.active.previous.inc
absent=$control/.active.previous.absent
owner=$control/.active.previous.token
state=$control/apply-state.json
receipt=$control/apply-result.json
lock=$control/.apply.flock

valid_token() {
    case "$1" in ''|*[!A-Za-z0-9_-]*) return 1;; esac
    [ "${#1}" -le 64 ]
}
valid_version() {
    case "$1" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) return 1;; esac
    [ "${#1}" -le 64 ]
}
regular_optional() {
    [ ! -L "$1" ] && { [ ! -e "$1" ] || [ -f "$1" ]; }
}
bounded() { [ "$(wc -c < "$1")" -le "$2" ]; }
# sync with no arguments is supported by BusyBox and flushes file data plus
# directory metadata. Completion is never inferred from cached readback alone.
persist_next() {
    sync
    mv -f "$1" "$2"
    sync
}
current_version() {
    [ -f "$active" ] || return 0
    value=$(sed -n 's/^set \$rules_version "\([A-Za-z0-9._-]*\)";$/\1/p' "$active")
    valid_version "$value" || return 1
    [ "$(cat "$active")" = "$(printf 'set $rules_version "%s";' "$value")" ] || return 1
    printf '%s' "$value"
}
read_state() {
    [ -f "$state" ] && bounded "$state" 4096 || return 1
    body=$(cat "$state")
    saved_run=$(printf '%s' "$body" | sed -n 's/.*"run_id":"\([A-Za-z0-9_-]*\)".*/\1/p')
    saved_status=$(printf '%s' "$body" | sed -n 's/.*"status":"\([a-z_]*\)".*/\1/p')
    saved_version=$(printf '%s' "$body" | sed -n 's/.*"version":"\([A-Za-z0-9._-]*\)".*/\1/p')
    saved_error=$(printf '%s' "$body" | sed -n 's/.*"error_code":"\([a-z_]*\)".*/\1/p')
    saved_utc=$(printf '%s' "$body" | sed -n 's/.*"applied_utc":"\([0-9TZ:-]*\)".*/\1/p')
    valid_token "$saved_run" || return 1
    case "$saved_status" in activated|committed|restored|failed) ;; *) return 1;; esac
    [ -z "$saved_version" ] || valid_version "$saved_version" || return 1
    printf '%s' "$saved_utc" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || return 1
    # Accept the two canonical encoders: this helper and Go's sorted map keys.
    # No duplicate/unknown fields or arbitrary JSON substring is accepted.
    encoded=$(printf '{"run_id":"%s","status":"%s","version":"%s","error_code":"%s","applied_utc":"%s"}' "$saved_run" "$saved_status" "$saved_version" "$saved_error" "$saved_utc")
    encoded_go=$(printf '{"applied_utc":"%s","error_code":"%s","run_id":"%s","status":"%s","version":"%s"}' "$saved_utc" "$saved_error" "$saved_run" "$saved_status" "$saved_version")
    [ "$body" = "$encoded" ] || [ "$body" = "$encoded_go" ]
}
write_state() {
    utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '{"run_id":"%s","status":"%s","version":"%s","error_code":"%s","applied_utc":"%s"}\n' \
        "$token" "$1" "$2" "$3" "$utc" > "$state_next"
    persist_next "$state_next" "$state"
}
write_receipt() {
    utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    # False is a complete recoverable payload. Only after the durability fence
    # can a fresh completed=true receipt be observed by the RouterOS caller.
    for completed in false true; do
        printf '{"run_id":"%s","request_id":"%s","action":"%s","status":"%s","version":"%s","error_code":"%s","applied_utc":"%s","completed":%s}\n' \
            "$token" "$request_id" "$action" "$1" "$2" "$3" "$utc" "$completed" > "$receipt_next"
        mv -f "$receipt_next" "$receipt"
        [ "$completed" = true ] || sync
    done
}
fail() {
    write_receipt failed "${version:-}" "$1"
    exit 1
}
restore_include() {
    if [ -f "$absent" ]; then
        rm -f "$active"
        sync
    elif [ -f "$backup" ]; then
        cp "$backup" "$active_next"
        chmod 0644 "$active_next"
        persist_next "$active_next" "$active"
    else
        return 1
    fi
}
reload_nginx() {
    "$nginx_bin" -t >/dev/null 2>&1 && "$nginx_bin" -s reload >/dev/null 2>&1
}

action=${1:-}
case "$action" in
    activate) [ "$#" -eq 3 ] || [ "$#" -eq 4 ] || exit 2; version=$2; token=$3; request_id=${4:-}; valid_version "$version" || exit 2;;
    restore|commit) [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || exit 2; version=; token=$2; request_id=${3:-};;
    *) exit 2;;
esac
valid_token "$token" || exit 2
if [ -n "$request_id" ]; then
    [ "${#request_id}" -eq 16 ] || exit 2
    case "$request_id" in *[!a-f0-9]*) exit 2;; esac
fi
[ ! -L "$control" ] || exit 1
mkdir -p "$control"
command -v flock >/dev/null 2>&1 || { printf '%s\n' 'flock is required' >&2; exit 1; }
for path in "$active" "$backup" "$absent" "$owner" "$state" "$receipt" "$lock"; do
    regular_optional "$path" || exit 1
done
[ ! -f "$lock" ] || [ ! -s "$lock" ] || exit 1
# Keep the inode; unlinking an in-use lock permits concurrent owners.
exec 9>"$lock"
flock -n 9 || { printf '%s\n' 'rules helper is already active' >&2; exit 1; }
active_next=$control/.active.next.$token
backup_next=$control/.active.previous.next.$token
owner_next=$control/.active.previous.token.next.$token
absent_next=$control/.active.previous.absent.next.$token
state_next=$control/.apply-state.next.$token
receipt_next=$control/.apply-result.next.$token
for path in "$active_next" "$backup_next" "$owner_next" "$absent_next" "$state_next" "$receipt_next"; do regular_optional "$path" || exit 1; done
cleanup() { rm -f "$active_next" "$backup_next" "$owner_next" "$absent_next" "$state_next" "$receipt_next"; }
trap cleanup 0
trap 'exit 1' 1 2 15
for path in "$active" "$backup"; do [ ! -f "$path" ] || bounded "$path" 256 || fail include_too_large; done
[ ! -f "$absent" ] || [ ! -s "$absent" ] || fail invalid_absence_marker
saved_token=
if [ -f "$owner" ]; then
    bounded "$owner" 65 || fail invalid_owner
    saved_token=$(cat "$owner")
    valid_token "$saved_token" || fail invalid_owner
    [ "$(wc -c < "$owner")" -eq "${#saved_token}" ] || [ "$(wc -c < "$owner")" -eq "$((${#saved_token} + 1))" ] || fail invalid_owner
fi

case "$action" in
    activate)
        for asset in onexray.json geoip.dat geosite.dat manifest.json; do
            [ -r "$publication/versions/$version/$asset" ] || fail missing_asset
        done
        if [ "$saved_token" != "$token" ]; then
            if [ -n "$saved_token" ]; then
                read_state || fail previous_transaction_pending
                previous_version=$(current_version) || fail previous_transaction_pending
                [ "$saved_run" = "$saved_token" ] && [ "$saved_version" = "$previous_version" ] || fail previous_transaction_pending
                case "$saved_status" in committed|restored) ;; *) fail previous_transaction_pending;; esac
            elif [ -e "$state" ] || [ -e "$backup" ] || [ -e "$absent" ]; then
                fail unowned_previous_state
            fi
            if [ -f "$active" ]; then
                cp "$active" "$backup_next"
                persist_next "$backup_next" "$backup"
                rm -f "$absent"
                sync
            else
                : > "$absent_next"
                persist_next "$absent_next" "$absent"
                rm -f "$backup"
                sync
            fi
            printf '%s\n' "$token" > "$owner_next"
            persist_next "$owner_next" "$owner"
        else
            { [ -f "$backup" ] && [ ! -f "$absent" ]; } || { [ -f "$absent" ] && [ ! -f "$backup" ]; } || fail backup_missing
        fi
        printf 'set $rules_version "%s";\n' "$version" > "$active_next"
        chmod 0644 "$active_next"
        persist_next "$active_next" "$active"
        if ! reload_nginx; then
            restore_include || :
            reload_nginx || :
            write_state failed "$version" nginx_validation_or_reload
            fail nginx_validation_or_reload
        fi
        write_state activated "$version" ''
        write_receipt activated "$version" ''
        ;;
    restore)
        if [ "$saved_token" = "$token" ]; then
            restore_include || fail backup_missing
            reload_nginx || fail nginx_restore
            version=$(current_version) || fail invalid_active_include
            write_state restored "$version" ''
        else
            # No activation by this token: keep the previous authoritative
            # owner/state intact. A fresh receipt cannot impersonate that owner.
            if [ -n "$saved_token" ]; then
                read_state || fail foreign_previous_state
                version=$(current_version) || fail foreign_previous_state
                [ "$saved_run" = "$saved_token" ] && [ "$saved_version" = "$version" ] || fail foreign_previous_state
                case "$saved_status" in committed|restored) ;; *) fail foreign_previous_state;; esac
            else
                [ ! -e "$state" ] && [ ! -e "$backup" ] && [ ! -e "$absent" ] || fail unowned_previous_state
                version=$(current_version) || fail invalid_active_include
            fi
            reload_nginx || fail nginx_restore
        fi
        write_receipt restored "$version" ''
        ;;
    commit)
        [ "$saved_token" = "$token" ] || fail token_mismatch
        version=$(current_version) || fail invalid_active_include
        valid_version "$version" || fail invalid_active_include
        read_state || fail invalid_apply_state
        [ "$saved_run" = "$token" ] && [ "$saved_version" = "$version" ] || fail invalid_apply_state
        case "$saved_status" in activated|committed) ;; *) fail invalid_apply_state;; esac
        write_state committed "$version" ''
        write_receipt committed "$version" ''
        ;;
esac
cat "$receipt"
