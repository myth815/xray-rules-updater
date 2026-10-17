#!/bin/sh
# Run only inside the dedicated gateway network namespace. Keep the source
# rule and unreachable route until namespace teardown, including during exit.
set -eu

die() { echo "fail-closed routing: $*" >&2; exit 1; }
[ "$#" -eq 5 ] || die 'expected action source-CIDR table priority tun-interface'
action=$1
source_cidr=$2
table=$3
priority=$4
tun=$5
ip_cmd=${XRAY_ROUTE_IP:-/sbin/ip}

case "$action" in prepare|activate|deactivate|check) ;; *) die 'unknown action' ;; esac
case "$table:$priority" in *[!0-9:]*|:*|*:) die 'invalid table or priority' ;; esac
[ "$table" -ge 1 ] && [ "$table" -le 252 ] || die 'reserved table'
[ "$priority" -ge 1 ] && [ "$priority" -le 32765 ] || die 'reserved priority'
case "$tun" in ''|*[!a-zA-Z0-9_]*|lo|eth*|veth*) die 'invalid TUN interface name' ;; esac
[ "${#tun}" -le 15 ] || die 'interface name too long'
printf '%s\n' "$source_cidr" | awk -F '[./]' '
 NF!=5 {exit 1}
 {for(i=1;i<=5;i++) if($i!~/^[0-9]+$/ || (length($i)>1 && substr($i,1,1)=="0")) exit 1}
 {for(i=1;i<=4;i++) if($i>255) exit 1}
 $5<1 || $5>32 {exit 1}
 !(($1==10 && $5>=8) || ($1==172 && $2>=16 && $2<=31 && $5>=12) || ($1==192 && $2==168 && $5>=16)) {exit 1}
' || die 'explicit private IPv4 source CIDR required'
[ -x "$ip_cmd" ] || die 'IP command unavailable'
source_rule=${source_cidr%/32}

rule_count() {
    "$ip_cmd" rule show | awk -v p="$priority:" '$1==p {n++} END {print n+0}'
}
check_barrier() {
    [ "$(rule_count)" -eq 1 ] || die 'source rule missing or ambiguous'
    "$ip_cmd" rule show | awk -v p="$priority:" -v s="$source_rule" -v t="$table" '
      $1==p {if(NF!=5 || $2!="from" || $3!=s || $4!="lookup" || $5!=t) exit 1; n++}
      END {if(n!=1) exit 1}
    ' || die 'source rule drift'
    "$ip_cmd" route show table "$table" | awk -v d="$tun" '
      $1=="unreachable" && $2=="default" && $3=="metric" && $4==32767 && NF==4 {n++; next}
      $1=="default" && $2=="dev" && $3==d && $4=="scope" && $5=="link" && $6=="metric" && $7==10 && NF==7 {next}
      {exit 1}
      END {if(n!=1) exit 1}
    ' || die 'unreachable barrier missing'
}

case "$action" in
prepare)
    [ "$(rule_count)" -eq 0 ] || die 'priority already in use'
    [ -z "$("$ip_cmd" route show table "$table")" ] || die 'table already in use'
    # The lower-priority rejection exists before the source rule is installed.
    # Never use "throw": it permits policy lookup to continue to main.
    "$ip_cmd" route add unreachable default metric 32767 table "$table"
    "$ip_cmd" rule add pref "$priority" from "$source_cidr" lookup "$table"
    check_barrier
    ;;
activate)
    check_barrier
    "$ip_cmd" link show "$tun" >/dev/null
    "$ip_cmd" route add default dev "$tun" metric 10 table "$table"
    check_barrier
    ;;
deactivate)
    check_barrier
    # Core exit normally removes this route with its interface. Never remove
    # the policy rule or the unreachable route while packets can still arrive.
    active=$("$ip_cmd" route show table "$table" | awk -v d="$tun" '
      $1=="default" && $2=="dev" && $3==d && $4=="scope" && $5=="link" && $6=="metric" && $7==10 && NF==7 {n++}
      END {print n+0}')
    [ "$active" -le 1 ] || die 'active route ambiguous'
    if [ "$active" -eq 1 ]; then
        "$ip_cmd" route del default dev "$tun" metric 10 table "$table"
    fi
    check_barrier
    ;;
check)
    check_barrier
    ;;
esac
