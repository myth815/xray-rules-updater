# Parse this file as a function, then call it with:
#   action (prepare/check), dedicated table name, expected private IPv4 next hop.
# It never changes a unicast route, enables forwarding, or removes the barrier.
:local action $1;
:local selectedTable $2;
:local expectedGateway $3;
:if (($action!="prepare") && ($action!="check")) do={:error "host barrier: invalid action";};
:if (([:typeof $selectedTable]!="str") || !($selectedTable~"^[A-Za-z][A-Za-z0-9_-]{0,31}\$")) do={:error "host barrier: invalid table name";};
:if (($selectedTable="main") || ($selectedTable="local") || ($selectedTable="default")) do={:error "host barrier: reserved table";};
:local hop [:toip $expectedGateway];
:if ([:typeof $hop]!="ip") do={:error "host barrier: IPv4 next hop required";};
:if (!(($hop in 10.0.0.0/8) || ($hop in 172.16.0.0/12) || ($hop in 192.168.0.0/16))) do={:error "host barrier: private next hop required";};
:if ([:tostr $hop]!=$expectedGateway) do={:error "host barrier: canonical next hop required";};
:local tables [/routing table print as-value where name=$selectedTable];
:if ([:len $tables]!=1) do={:error "host barrier: table missing or ambiguous";};
:local tableRow [:pick $tables 0];
:if ((($tableRow->"fib")!=true) || (($tableRow->"dynamic")=true)) do={:error "host barrier: dedicated FIB table required";};
:local ownerComment ("XrayTUN: fail-closed ".$selectedTable);
:local ownedCount 0;
:local unicastCount 0;
:local barrierID;
:foreach row in=[/ip route print as-value where routing-table=$selectedTable] do={
    :if ((($row->"dst-address")!="0.0.0.0/0") || (($row->"static")!=true)) do={:error "host barrier: unexpected route";};
    :if (($row->"comment")=$ownerComment) do={
        :set ownedCount ($ownedCount+1);
        :set barrierID ($row->".id");
    } else={
        :if (([:tostr ($row->"gateway")]!=$expectedGateway) || (($row->"distance")<1) || (($row->"distance")>=254)) do={:error "host barrier: foreign route";};
        :set unicastCount ($unicastCount+1);
    };
};
:if (($ownedCount>1) || ($unicastCount>1) || ([:len [/ip route find where comment=$ownerComment]]!=$ownedCount)) do={:error "host barrier: ownership ambiguous";};
:if ($ownedCount=0) do={
    :if ($action!="prepare") do={:error "host barrier: rejection route missing";};
    /ip route add blackhole dst-address=0.0.0.0/0 routing-table=$selectedTable distance=254 comment=$ownerComment;
    :local created [/ip route find where comment=$ownerComment];
    :if ([:len $created]!=1) do={:error "host barrier: creation ambiguous";};
    :set barrierID [:pick $created 0];
};
:if (([/ip route get $barrierID routing-table]!=$selectedTable) || ([/ip route get $barrierID dst-address]!="0.0.0.0/0") || ([/ip route get $barrierID distance]!=254) || ([/ip route get $barrierID blackhole]!=true) || ([/ip route get $barrierID disabled]!=false)) do={:error "host barrier: rejection route drift";};
:return {"id"=[:tostr $barrierID];"table"=$selectedTable;"gateway"=$expectedGateway;"distance"=254;"blackhole"=true};
