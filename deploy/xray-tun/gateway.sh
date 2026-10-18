#!/bin/sh
# PID 1 in a dedicated RouterOS gateway namespace. The host owns rollback.
set -eu
umask 077
export XRAY_ROUTE_IP=/bin/ip
core_pid=
admitted=0

die() { echo "native TUN gateway: $*" >&2; exit 1; }
finish() {
    rc=$?
    trap - EXIT TERM INT
    set +e
    if [ "$admitted" = 1 ]; then
        echo 0 > /proc/sys/net/ipv4/ip_forward
    fi
    if [ -n "$core_pid" ]; then
        kill -TERM "$core_pid" 2>/dev/null
        i=0
        while kill -0 "$core_pid" 2>/dev/null && [ "$i" -lt 30 ]; do
            state=$(awk '{print $3}' "/proc/$core_pid/stat" 2>/dev/null)
            [ "$state" = Z ] && break
            i=$((i+1)); sleep .1
        done
        kill -KILL "$core_pid" 2>/dev/null
        wait "$core_pid"
    fi
    # Preserve the source rule, unreachable route and ingress rejection rule.
    # A new namespace may prepare them; an existing namespace must check them.
    exit "$rc"
}
trap finish EXIT
trap 'exit 0' TERM INT

[ "$#" -eq 0 ] || die 'arguments are not accepted'
: "${XRAY_GATEWAY_INTERFACE:?required}"
: "${XRAY_GATEWAY_ADDRESS:?required}"
: "${XRAY_GATEWAY_SOURCE_CIDR:?required}"
: "${XRAY_LOCATION_ASSET:?required}"
[ "$XRAY_CONE_DISABLED" = true ] || die 'strict UDP destination routing required'
case "$XRAY_GATEWAY_INTERFACE" in
    ''|*[!a-zA-Z0-9_]*|lo|xray0) die 'invalid gateway interface' ;;
esac
[ "${#XRAY_GATEWAY_INTERFACE}" -le 15 ] || die 'gateway interface too long'
[ -c /dev/net/tun ] && [ "$(stat -c '%t:%T' /dev/net/tun)" = a:c8 ] || die 'TUN device unavailable'
[ -d "/sys/class/net/$XRAY_GATEWAY_INTERFACE" ] || die 'gateway namespace interface absent'
[ "$(ls /sys/class/net | wc -l)" -eq 2 ] || die 'unexpected namespace interfaces'
admitted=1
echo 0 > /proc/sys/net/ipv4/ip_forward
/bin/ip -o -4 address show dev "$XRAY_GATEWAY_INTERFACE" | awk -v a="$XRAY_GATEWAY_ADDRESS" '
    $4==a {n++} END {if(n!=1) exit 1}
' || die 'gateway address drift'
[ -f "$XRAY_LOCATION_ASSET/geoip.dat" ] && [ -f "$XRAY_LOCATION_ASSET/geosite.dat" ] || die 'native GEO assets absent'

# This is the sole runtime input and the updater's baseline/verification input.
# Reject stale split modules or an environment-appended configuration directory.
config=/etc/xray/config.json
[ -f "$config" ] && [ ! -L "$config" ] || die 'single regular configuration required'
for file in /etc/xray/*.json; do
    [ "$file" = "$config" ] || die 'legacy configuration modules present'
done
[ ! -e /gateway/native.json ] || die 'legacy native overlay present'
[ -z "$(env | awk -F= '$1=="XRAY_LOCATION_CONFDIR" || $1=="xray.location.confdir" {print $0}')" ] || die 'configuration directory override is not allowed'
set -- /usr/local/bin/xray run -config "$config"
config_digest=$(sha256sum "$config")
/bin/busybox timeout -s TERM -k 1 15 "$@" -test >/dev/null
[ "$(sha256sum "$config")" = "$config_digest" ] || die 'configuration changed during validation'

for file in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$file"; done
if /bin/ip rule show | awk '$1=="2000:" {found=1} END {exit !found}'; then
    /bin/sh /gateway/fail_closed_routes.sh check "$XRAY_GATEWAY_SOURCE_CIDR" 20 2000 xray0
else
    /bin/sh /gateway/fail_closed_routes.sh prepare "$XRAY_GATEWAY_SOURCE_CIDR" 20 2000 xray0
fi
# Any other forwarded source arriving on the gateway interface is rejected.
if [ -z "$(/bin/ip rule show | awk '$1=="2001:" {print}')" ]; then
    /bin/ip rule add pref 2001 iif "$XRAY_GATEWAY_INTERFACE" type prohibit
fi
/bin/ip rule show | awk -v d="$XRAY_GATEWAY_INTERFACE" '
    $1=="2001:" {
        if(NF!=8 || $2!="from" || $3!="all" || $4!="iif" || $5!=d ||
           $6!="lookup" || $7!="main" || $8!="prohibit") exit 1
        n++
    }
    END {if(n!=1) exit 1}
' || die 'ingress rejection rule drift'
"$@" >/dev/null 2>&1 &
core_pid=$!
i=0
until /bin/ip link show xray0 >/dev/null 2>&1; do
    kill -0 "$core_pid" || die 'Core exited before TUN readiness'
    i=$((i+1)); [ "$i" -lt 100 ] || die 'TUN readiness timeout'
    sleep .1
done
/bin/sh /gateway/fail_closed_routes.sh activate "$XRAY_GATEWAY_SOURCE_CIDR" 20 2000 xray0
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 'native TUN gateway: ready'
# The kernel barrier handles a Core crash even before this wait returns.
wait "$core_pid"
