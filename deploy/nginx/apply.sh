#!/bin/sh
# Run inside the existing Nginx container. This helper controls only the
# managed version include; the publication itself is mounted read-only.
# Usage: apply.sh activate VERSION TOKEN | restore TOKEN | commit TOKEN
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
lock=$control/.apply.flock

valid_token() {
    case "$1" in ''|*[!A-Za-z0-9_-]*) return 1;; esac
    [ "${#1}" -le 64 ]
}
valid_version() {
    case "$1" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) return 1;; esac
    [ "${#1}" -le 64 ]
}
write_state() {
    # All interpolated fields are controlled literals or validated tokens.
    utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '{"run_id":"%s","status":"%s","version":"%s","error_code":"%s","applied_utc":"%s"}\n' \
        "$token" "$1" "$2" "$3" "$utc" > "$control/.apply-state.next.$token"
    mv -f "$control/.apply-state.next.$token" "$state"
}
current_version() {
    [ -f "$active" ] || return 0
    sed -n 's/^set \$rules_version "\([A-Za-z0-9._-]*\)";$/\1/p' "$active"
}
restore_include() {
    if [ -f "$absent" ]; then
        rm -f "$active"
    elif [ -f "$backup" ]; then
        cp "$backup" "$control/.active.next.$token"
        chmod 0644 "$control/.active.next.$token"
        mv -f "$control/.active.next.$token" "$active"
    else
        return 1
    fi
}
reload_nginx() {
    "$nginx_bin" -t >/dev/null 2>&1 && "$nginx_bin" -s reload >/dev/null 2>&1
}

action=${1:-}
case "$action" in
    activate) [ "$#" -eq 3 ] || exit 2; version=$2; token=$3; valid_version "$version" || exit 2;;
    restore|commit) [ "$#" -eq 2 ] || exit 2; version=; token=$2;;
    *) exit 2;;
esac
valid_token "$token" || exit 2
mkdir -p "$control"
if command -v flock >/dev/null 2>&1; then
    # Keep the inode: unlinking an in-use lock file would allow two locks.
    # The kernel releases this lock even if the helper is killed.
    exec 9>"$lock"
    flock -n 9 || { printf '%s\n' 'rules helper is already active' >&2; exit 1; }
fi
# Without flock this helper requires the single owning host script. Do not use
# a persistent mkdir lock, which could survive a crash and block all recovery.
cleanup() {
    rm -f "$control/.active.next.$token" "$control/.active.previous.next.$token" \
        "$control/.active.previous.token.next.$token" "$control/.apply-state.next.$token"
}
trap cleanup 0
trap 'exit 1' 1 2 15
for staged in "$control"/.active.next.* "$control"/.active.previous.next.* \
    "$control"/.active.previous.token.next.* "$control"/.apply-state.next.*; do
    [ ! -f "$staged" ] || rm -f "$staged"
done

case "$action" in
    activate)
        for name in onexray.json geoip.dat geosite.dat manifest.json; do
            [ -r "$publication/versions/$version/$name" ] || {
                write_state failed "$version" missing_asset; exit 1;
            }
        done
        saved_token=
        [ ! -f "$owner" ] || saved_token=$(cat "$owner")
        if [ "$saved_token" != "$token" ]; then
            # A new transaction may replace the one bounded backup only after
            # the previous host transaction was committed or restored.
            if [ -n "$saved_token" ] && ! grep -Eq '"status":"(committed|restored)"' "$state"; then
                write_state failed "$version" previous_transaction_pending; exit 1
            fi
            if [ -f "$active" ]; then
                cp "$active" "$control/.active.previous.next.$token"
                mv -f "$control/.active.previous.next.$token" "$backup"
                rm -f "$absent"
            else
                : > "$absent"
                rm -f "$backup"
            fi
            printf '%s\n' "$token" > "$control/.active.previous.token.next.$token"
            mv -f "$control/.active.previous.token.next.$token" "$owner"
        fi
        printf 'set $rules_version "%s";\n' "$version" > "$control/.active.next.$token"
        chmod 0644 "$control/.active.next.$token"
        mv -f "$control/.active.next.$token" "$active"
        if ! reload_nginx; then
            restore_include || :
            reload_nginx || :
            write_state failed "$version" nginx_validation_or_reload
            exit 1
        fi
        write_state activated "$version" ''
        ;;
    restore)
        saved_token=
        [ ! -f "$owner" ] || saved_token=$(cat "$owner")
        if [ "$saved_token" = "$token" ]; then
            restore_include || { write_state failed '' backup_missing; exit 1; }
        fi
        # No matching token means activation never changed this include.
        # This is needed when Xray/MosDNS failed before the Nginx step.
        if ! reload_nginx; then
            write_state failed '' nginx_restore; exit 1
        fi
        write_state restored "$(current_version)" ''
        ;;
    commit)
        [ -f "$owner" ] && [ "$(cat "$owner")" = "$token" ] || {
            write_state failed '' token_mismatch; exit 1;
        }
        version=$(current_version)
        valid_version "$version" || { write_state failed '' invalid_active_include; exit 1; }
        write_state committed "$version" ''
        ;;
esac
cat "$state"
