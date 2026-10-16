# Install two named sources: update mode and recover-only startup mode.
# Schedulers invoke the named scripts; anonymous/import execution is rejected.
# Deployment must create mounts/configs first. Values below are public samples.
# Required permissions: read,write,policy,test,sensitive (JSON file staging).
# No administrator credentials are embedded in this source.
# RouterOS 7.23 state is print as-value -> running; there is no status property.
# Functions are namespaced and hold code only. Persistent state is bounded JSON.
# The dedicated xray_env_list must be attached to the Xray container and must
# be its ONLY source of XRAY_LOCATION_ASSET. Consumer mounts expose /rules RO.
# Production updater config MUST require apply ack AND transaction hold paths.
# Bootstrap publishes the first current and enables its internal metadata URL
# before this daily body runs. RouterOS /file does not traverse current symlink.

:local settings {
    "script_name"="XrayRulesUpdate";
    "recover_script_name"="XrayRulesRecover";
    "mode"="update";
    "producer_mountlists"="XrayRulesProducer";
    "host_mountlists"="XrayRulesHostControl";
    "producer_state_dst"="/host-state";
    "updater"="xray-rules-updater";
    "xray"="xray-core:latest";
    "mosdns"="mosdns:latest";
    "nginx"="nginx:1.31.5";
    "xray_env_list"="XrayRulesAssets";
    "publish_root"="docker/xray-rules-updater/publish";
    "config_root"="docker/xray-rules-updater/config";
    "state_root"="docker/xray-rules-updater/state";
    "diagnostics_root"="docker/xray-rules-updater/diagnostics";
    "mosdns_data"="docker/mosdns/config/dat_exec.yaml";
    "mosdns_template"="docker/xray-rules-updater/config/mosdns-dat_exec.template.yaml";
    "nginx_state"="docker/nginx/config/rules/apply-state.json";
    "nginx_result"="docker/nginx/config/rules/apply-result.json";
    "nginx_helper"="/etc/nginx/rules/apply.sh";
    "current_manifest_url"="http://172.28.55.5:8089/current-manifest";
    "subscription_manifest_url"="https://rules.example.internal/manifest.json";
    "task_seconds"=330;
    "worker_memory_high"=167772160;
    "worker_memory_max"=201326592;
    "verify_memory_high"=234881024;
    "verify_memory_max"=268435456;
}

:global RUXReadJSON do={
    :local inputPath $1; :local required $2; :local inputBody ""; :local found true;
    :if ([:typeof $required] != "bool") do={ :error "rules JSON required flag must be boolean"; }
    :do { :set inputBody [/file get $inputPath contents]; } on-error={ :set found false; }
    :if (!$found) do={
        :if ($required) do={ :error "rules JSON input is unavailable"; }
        :return "";
    }
    :local decodedJSON [:deserialize from=json value=$inputBody options=json.no-string-conversion];
    :if ([:typeof $decodedJSON] != "array") do={ :error "rules JSON input is not an object"; }
    :return $decodedJSON;
}
:global RUXReadCurrent do={
    :local c $1;
    # Only current metadata uses HTTP: /file cannot follow this publication
    # symlink. Fetch/HTTP/JSON errors must abort, never impersonate no current.
    :local result [/tool fetch url=($c->"current_manifest_url") duration=5s idle-timeout=3s output=user as-value];
    :if (($result->"status") != "finished") do={ :error "rules current metadata request failed"; }
    :local manifest [:deserialize from=json value=($result->"data") options=json.no-string-conversion];
    :if ([:typeof $manifest] != "array") do={ :error "rules current metadata is not an object"; }
    :local version ($manifest->"version");
    :if ([:typeof $version] != "str") do={ :error "rules current metadata version is invalid"; }
    :if (!($version ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules current metadata version is invalid"; }
    :return $manifest;
}
:global RUXWriteFile do={
    :local targetPath $1; :local targetBody $2;
    :if ([:len $targetBody] > 60000) do={ :error "rules host state exceeds file limit"; }
    # RouterOS property names are reserved variables. Using local name here
    # makes where name=$name match every file instead of the requested path.
    :local fileIDs [/file find where name=$targetPath];
    :if ([:len $fileIDs] > 1) do={ :error "rules host state path is ambiguous"; }
    :if ([:len $fileIDs] = 0) do={
        /file add name=$targetPath type=file;
        :set fileIDs [/file find where name=$targetPath];
    }
    :if ([:len $fileIDs] != 1) do={ :error "rules host state file was not created"; }
    /file set [:pick $fileIDs 0] contents=$targetBody;
}
:global RUXContainer do={
    :local containerName $1; :local ids [/container find where name=$containerName];
    :if ([:len $ids] != 1) do={ :error "rules container name is missing or ambiguous"; }
    :return [:pick $ids 0];
}
# Worker role changes are allowed only while the exact owned container is
# positively stopped. Never execute producer code with host-state RW mounts.
:global RUXCSV do={
    :local entries $1; :local result "";
    :if ([:typeof $entries] = "str") do={ :return $entries; }
    :if ([:typeof $entries] != "array") do={ :error "rules list value is invalid"; }
    :foreach entry in=$entries do={
        :if (([:typeof $entry] != "str") || !($entry ~ "^[A-Za-z0-9_-]+\$")) do={ :error "rules list entry is invalid"; }
        :if ($result != "") do={ :set result ($result . ","); }
        :set result ($result . $entry);
    }
    :return $result;
}
:global RUXParentPath do={
    :local path $1; :local slash 0; :local next [:find $path "/"];
    :while ([:typeof $next] = "num") do={ :set slash $next; :set next [:find $path "/" ($next + 1)]; }
    :if ($slash = 0) do={ :error "rules controlled file path has no parent"; }
    :return [:pick $path 0 $slash];
}
:global RUXWorkerRole do={
    :global RUXContainer; :global RUXCSV; :global RUXParentPath;
    :local c $1; :local role $2; :local workerName ($c->"updater");
    :if (($role != "producer") && ($role != "host")) do={ :error "rules worker role is invalid"; }
    :local desired ($c->"producer_mountlists"); :if ($role = "host") do={ :set desired ($c->"host_mountlists"); }
    :if (([:typeof $desired] != "str") || ([:len $desired] = 0) || (($c->"producer_mountlists") = ($c->"host_mountlists"))) do={ :error "rules worker mount roles are invalid"; }
    :local workerID [$RUXContainer $workerName]; :local rows [/container print as-value where name=$workerName];
    :if ([:len $rows] != 1) do={ :error "rules worker role identity changed"; }
    :local row [:pick $rows 0];
    :if ((($row->".id") != $workerID) || (($row->"stopped") != true)) do={ :error "rules worker role requires positively stopped worker"; }
    :if ([/container get $workerID start-on-boot] != false) do={ :error "rules one-shot worker must not auto-start on boot"; }
    :local actual [$RUXCSV [/container get $workerID mountlists]];
    :if (($actual != ($c->"producer_mountlists")) && ($actual != ($c->"host_mountlists"))) do={ :error "rules worker mounts are outside controlled roles"; }
    :if ([:len [/container get $workerID mount]] != 0) do={ :error "rules worker has an uncontrolled direct mount"; }
    :local stateSource ("/" . ($c->"state_root")); :local stateCount 0;
    :local expectedSources {"/config"=("/" . ($c->"config_root"));"/publish"=("/" . ($c->"publish_root"))};
    :local expectedModes {"/config"="ro";"/publish"="rw"};
    :local counts [:toarray ""];
    :if ($role = "producer") do={
        :local diagnosticSource ("/" . ($c->"diagnostics_root"));
        :if (([:typeof ($c->"diagnostics_root")] != "str") || ([:len ($c->"diagnostics_root")] = 0)) do={ :error "rules diagnostic root is invalid"; }
        :foreach protectedSource in={("/" . ($c->"state_root"));("/" . ($c->"publish_root"));("/" . ($c->"config_root"));("/" . [$RUXParentPath ($c->"mosdns_data")]);("/" . [$RUXParentPath ($c->"nginx_state")])} do={
            :if (($diagnosticSource = $protectedSource) || ([:pick $diagnosticSource 0 ([:len $protectedSource] + 1)] = ($protectedSource . "/")) || ([:pick $protectedSource 0 ([:len $diagnosticSource] + 1)] = ($diagnosticSource . "/"))) do={ :error "rules diagnostic RW source overlaps a controlled directory"; }
        }
        :set ($expectedSources->"/diagnostics") $diagnosticSource; :set ($expectedModes->"/diagnostics") "rw";
    }
    :local stateDestination ($c->"producer_state_dst"); :local stateMode "ro";
    :if ($role = "host") do={
        :set stateDestination "/host-state"; :set stateMode "rw";
        :set ($expectedSources->"/host-mosdns") ("/" . [$RUXParentPath ($c->"mosdns_data")]);
        :set ($expectedSources->"/host-nginx") ("/" . [$RUXParentPath ($c->"nginx_state")]);
        :set ($expectedModes->"/host-mosdns") "rw"; :set ($expectedModes->"/host-nginx") "rw";
    }
    :set ($expectedSources->$stateDestination) $stateSource; :set ($expectedModes->$stateDestination) $stateMode;
    :foreach destination,expectedSource in=$expectedSources do={ :set ($counts->$destination) 0; }
    :foreach listName in=[:toarray $desired] do={
        :foreach entry in=[/container mounts find where list=$listName] do={
            :local sourcePath [/container mounts get $entry src]; :local entryMode [/container mounts get $entry mode]; :local targetPath [/container mounts get $entry dst];
            :if ($entryMode = "rw") do={
                :local allowedRW false;
                :foreach destination,expectedSource in=$expectedSources do={
                    :if (($targetPath = $destination) && ($sourcePath = $expectedSource) && (($expectedModes->$destination) = "rw")) do={ :set allowedRW true; }
                }
                :if (!$allowedRW) do={ :error "rules worker role has an uncontrolled RW mount"; }
            }
            :foreach destination,expectedSource in=$expectedSources do={
                :if ($targetPath = $destination) do={
                    :set ($counts->$destination) (($counts->$destination) + 1);
                    :if (($sourcePath != $expectedSource) || ($entryMode != ($expectedModes->$destination))) do={ :error "rules worker controlled mount has wrong source or mode"; }
                } else={
                    :if (([:pick $targetPath 0 ([:len $destination] + 1)] = ($destination . "/")) || ($targetPath = "/") || ([:pick $destination 0 ([:len $targetPath] + 1)] = ($targetPath . "/"))) do={ :error "rules worker mount overrides a controlled destination"; }
                }
            }
            :if ($sourcePath = $stateSource) do={
                :set stateCount ($stateCount + 1);
                :if (([/container mounts get $entry dst] != $stateDestination) || ($entryMode != $stateMode)) do={ :error "rules worker state mount mode or destination is unsafe"; }
            } else={ :if (($entryMode = "rw") && ([:pick $stateSource 0 ([:len $sourcePath] + 1)] = ($sourcePath . "/"))) do={ :error "rules worker RW ancestor exposes host state"; } }
        }
    }
    :if ($stateCount != 1) do={ :error "rules worker needs exactly one role-specific state mount"; }
    :foreach destination,count in=$counts do={ :if ($count != 1) do={ :error "rules worker controlled mount is missing or ambiguous"; } }
    # Change the command BEFORE exposing host RW mounts. A power loss or a
    # manual start in this handoff window must never run the producer with RW
    # state. The invalid nonce cannot authorize any host operation either.
    :if ($role = "host") do={ /container set $workerID cmd="-host-control-config /config/host-control.json -host-request-id invalid"; }
    /container set $workerID mountlists=$desired;
    :if ([$RUXCSV [/container get $workerID mountlists]] != $desired) do={ :error "rules worker role did not attach"; }
    :return true;
}
:global RUXRunOneShot do={
    :global RUXReadJSON; :global RUXContainer; :global RUXWorkerRole;
    :local c $1; :local command $2; :local statusFile $3; :local role "producer";
    :if ([:typeof $4] = "str") do={ :set role $4; }
    $RUXWorkerRole $c $role;
    :local workerName ($c->"updater"); :local id [$RUXContainer $workerName];
    :local rows [/container print as-value where name=$workerName];
    :if ([:len $rows] != 1) do={ :error "rules worker identity changed"; }
    :local row [:pick $rows 0];
    :if ((($row->".id") != $id) || (($row->"stopped") != true)) do={ :error "rules updater is not positively stopped"; }
    :local old ""; :local oldRun "";
    :do { :set old [$RUXReadJSON $statusFile (false)]; } on-error={ :set old ""; }
    :if ([:typeof $old] = "array") do={ :set oldRun ($old->"run_id"); }
    # Native verification includes the target Xray/MosDNS children in this
    # cgroup. Increase its transient limit only for this exact verify command.
    :if ($command = "-verify-config /config/verify.json") do={
        /container set $id cmd=$command memory-high=($c->"verify_memory_high") memory-max=($c->"verify_memory_max");
    } else={
        /container set $id cmd=$command memory-high=($c->"worker_memory_high") memory-max=($c->"worker_memory_max");
    }
    /container start $id;
    :for wait from=0 to=(($c->"task_seconds") * 2) do={
        :delay 500ms;
        :local state "";
        :do { :set state [$RUXReadJSON $statusFile (false)]; } on-error={ :set state ""; }
        :local currentRows [/container print as-value where name=$workerName];
        :if ([:len $currentRows] != 1) do={ :error "rules worker identity changed"; }
        :local now [:pick $currentRows 0];
        :if (($now->".id") != $id) do={ :error "rules worker identity changed"; }
        :if ([:typeof $state] = "array") do={
            :local newRun ($state->"run_id");
            :if (([:typeof $newRun] = "str") && ($newRun ~ "^[a-f0-9]{16}\$") && ($newRun != $oldRun) && (($now->"stopped") = true)) do={ :return $state; }
        }
    }
    /container stop $id;
    :error "rules task timed out or did not write a fresh completion record";
}
:global RUXStop do={
    :global RUXContainer;
    :local consumerName $1; :local id [$RUXContainer $consumerName];
    :local initial [:pick [/container print as-value where name=$consumerName] 0];
    :if ((($initial->".id") = $id) && (($initial->"stopped") = true)) do={ :return true; }
    /container stop $id;
    :for wait from=0 to=60 do={
        :local rows [/container print as-value where name=$consumerName];
        :if ([:len $rows] != 1) do={ :error "rules consumer identity changed while stopping"; }
        :local row [:pick $rows 0];
        :if (($row->".id") != $id) do={ :error "rules consumer identity changed while stopping"; }
        :if (($row->"stopped") = true) do={ :return true; }
        :delay 500ms;
    }
    :error "rules consumer did not stop";
}
:global RUXStart do={
    :global RUXContainer;
    :local consumerName $1; :local id [$RUXContainer $consumerName]; :local requested false;
    :for wait from=0 to=60 do={
        :local rows [/container print as-value where name=$consumerName];
        :if ([:len $rows] != 1) do={ :error "rules consumer identity changed while starting"; }
        :local row [:pick $rows 0];
        :if (($row->".id") != $id) do={ :error "rules consumer identity changed while starting"; }
        :if (($row->"running") = true) do={ :return true; }
        :if ((($row->"stopped") = true) && (!$requested)) do={ /container start $id; :set requested true; }
        :delay 500ms;
    }
    :error "rules consumer did not start";
}
:global RUXSetAsset do={
    :local listName $1; :local present $2; :local assetPath $3;
    :if ([:typeof $present] != "bool") do={ :error "rules asset presence flag must be boolean"; }
    :local ids [/container envs find where list=$listName and key="XRAY_LOCATION_ASSET"];
    :if ([:len $ids] > 1) do={ :error "rules asset environment is ambiguous"; }
    :if (!$present) do={ /container envs remove $ids; :return true; }
    :if ([:len $ids] = 0) do={
        /container envs add list=$listName key="XRAY_LOCATION_ASSET" value=$assetPath;
    } else={ /container envs set [:pick $ids 0] value=$assetPath; }
}
:global RUXRenderMos do={
    :local source $1; :local assets $2; :local marker "@@RULES_ASSET_DIR@@";
    :local result ""; :local begin 0; :local found [:find $source $marker $begin];
    :if ([:typeof $found] = "nil") do={ :error "rules MosDNS template marker is missing"; }
    :while ([:typeof $found] != "nil") do={
        :set result ($result . [:pick $source $begin $found] . $assets);
        :set begin ($found + [:len $marker]);
        :set found [:find $source $marker $begin];
    }
    :return ($result . [:pick $source $begin [:len $source]]);
}
# Bind a journal to the actual consumer identities and attached definitions.
# No credentials or complete proxy configuration are printed.
:global RUXSnapshotConsumer do={
    :global RUXContainer; :global RUXCSV;
    :local c $1; :local role $2; :local consumerName ($c->$role); :local id [$RUXContainer $consumerName];
    :if ([:len [/container get $id mount]] != 0) do={ :error "rules consumer has an uncontrolled direct mount"; }
    :local mountBindings [:toarray ""]; :local envBindings [:toarray ""];
    :foreach listName in=[:toarray [$RUXCSV [/container get $id mountlists]]] do={
        :foreach entry in=[/container mounts find where list=$listName] do={
            :local targetPath [/container mounts get $entry dst];
            :if ([:typeof ($mountBindings->$targetPath)] != "nothing") do={ :error "rules consumer has duplicate mount destinations"; }
            :set ($mountBindings->$targetPath) {"list"=$listName;"src"=[/container mounts get $entry src];"mode"=[/container mounts get $entry mode]};
        }
    }
    :foreach listName in=[:toarray [$RUXCSV [/container get $id envlists]]] do={
        :foreach entry in=[/container envs find where list=$listName] do={
            :local envKey [/container envs get $entry key];
            :if (!(($role = "xray") && ($envKey = "XRAY_LOCATION_ASSET") && ($listName = ($c->"xray_env_list")))) do={
                :if ([:typeof ($envBindings->$envKey)] != "nothing") do={ :error "rules consumer has duplicate environment keys"; }
                :set ($envBindings->$envKey) {"list"=$listName;"value"=[/container envs get $entry value]};
            }
        }
    }
    :return {"name"=$consumerName;"root"=[/container get $id root-dir];"interface"=[$RUXCSV [/container get $id interface]];"mountlists"=[$RUXCSV [/container get $id mountlists]];"envlists"=[$RUXCSV [/container get $id envlists]];"cmd"=[:tostr [/container get $id cmd]];"entrypoint"=[:tostr [/container get $id entrypoint]];"direct_env"=[:tostr [/container get $id env]];"mount_bindings"=[:serialize to=json value=$mountBindings options=json.no-string-conversion];"env_bindings"=[:serialize to=json value=$envBindings options=json.no-string-conversion]};
}
:global RUXCheckIdentities do={
    :global RUXSnapshotConsumer;
    :local c $1; :local journal $2; :local saved ($journal->"consumer_snapshots");
    :foreach role in={"xray";"mosdns";"nginx"} do={
        :local actual [$RUXSnapshotConsumer $c $role]; :local previous ($saved->$role);
        :foreach key in={"name";"root";"interface";"mountlists";"envlists";"cmd";"entrypoint";"direct_env";"mount_bindings";"env_bindings"} do={
            :if (($actual->$key) != ($previous->$key)) do={ :error "rules consumer identity or attachment changed outside transaction"; }
        }
    }
    :return true;
}
:global RUXCheckTopology do={
    :global RUXContainer; :global RUXCSV;
    :local c $1; :local expectedSource ("/" . ($c->"publish_root"));
    :foreach role in={"xray";"mosdns";"nginx"} do={
        :local id [$RUXContainer ($c->$role)]; :local count 0;
        :if ([:len [/container get $id mount]] != 0) do={ :error "rules consumer direct mount can override assets"; }
        :foreach listName in=[:toarray [$RUXCSV [/container get $id mountlists]]] do={
            :foreach entry in=[/container mounts find where list=$listName] do={
                :local targetPath [/container mounts get $entry dst];
                :if ($targetPath = "/rules") do={
                    :set count ($count + 1);
                    :if (([/container mounts get $entry src] != $expectedSource) || ([/container mounts get $entry mode] != "ro")) do={ :error "rules consumer publication mount is foreign or writable"; }
                } else={ :if (($targetPath = "/") || ([:pick $targetPath 0 7] = "/rules/")) do={ :error "rules consumer mount overrides publication assets"; } }
            }
        }
        :if ($count != 1) do={ :error "rules consumer must have exactly one publication mount"; }
    }
    :local xrayID [$RUXContainer ($c->"xray")];
    :if ([:typeof [:find [:tostr [/container get $xrayID env]] "XRAY_LOCATION_ASSET"]] = "num") do={ :error "rules direct environment overrides asset source"; }
    :local assetCount 0; :local assetValue "";
    :foreach listName in=[:toarray [$RUXCSV [/container get $xrayID envlists]]] do={
        :foreach entry in=[/container envs find where list=$listName and key="XRAY_LOCATION_ASSET"] do={
            :set assetCount ($assetCount + 1);
            :if ($listName != ($c->"xray_env_list")) do={ :error "rules asset is attached from a foreign environment list"; }
            :set assetValue [/container envs get $entry value];
        }
    }
    :if ($assetCount != 1) do={ :error "rules dedicated asset environment is not uniquely attached"; }
    :local dataPath ($c->"mosdns_data"); :local slash 0; :local next [:find $dataPath "/"];
    :while ([:typeof $next] = "num") do={ :set slash $next; :set next [:find $dataPath "/" ($next + 1)]; }
    :local expectedMosSource ("/" . [:pick $dataPath 0 $slash]);
    :local mosID [$RUXContainer ($c->"mosdns")]; :local mosCount 0;
    :foreach listName in=[:toarray [$RUXCSV [/container get $mosID mountlists]]] do={
        :foreach entry in=[/container mounts find where list=$listName] do={
            :local targetPath [/container mounts get $entry dst];
            :if ($targetPath = "/etc/mosdns") do={
                :set mosCount ($mosCount + 1);
                :if (([/container mounts get $entry src] != $expectedMosSource) || ([/container mounts get $entry mode] != "ro")) do={ :error "rules MosDNS data path is not the consumer configuration mount"; }
            } else={ :if (($targetPath = "/") || ($targetPath = "/etc") || ([:pick $targetPath 0 12] = "/etc/mosdns/")) do={ :error "rules MosDNS mount overrides configuration data"; } }
        }
    }
    :if ($mosCount != 1) do={ :error "rules MosDNS complete configuration mount is ambiguous"; }
    :return $assetValue;
}
:global RUXActualVersion do={
    :global RUXCheckTopology; :global RUXRenderMos;
    :local c $1; :local version $2;
    :if (([:typeof $version] != "str") || !($version ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules actual version request is invalid"; }
    :local asset [$RUXCheckTopology $c];
    :local template [/file get ($c->"mosdns_template") contents];
    :local data [/file get ($c->"mosdns_data") contents];
    :return (($asset = ("/rules/versions/" . $version)) && ($data = [$RUXRenderMos $template ("/rules/versions/" . $version)]));
}
:global RUXKnownState do={
    :global RUXCheckIdentities; :global RUXCheckTopology; :global RUXRenderMos;
    :local c $1; :local journal $2;
    $RUXCheckIdentities $c $journal;
    :local asset [$RUXCheckTopology $c]; :local desired ("/rules/versions/" . ($journal->"desired_version"));
    :local template [/file get ($c->"mosdns_template") contents]; :local nextData [$RUXRenderMos $template $desired];
    :local actualData [/file get ($c->"mosdns_data") contents];
    :if (($asset != ($journal->"old_asset_value")) && ($asset != $desired)) do={ :error "rules actual asset is outside transaction old/desired states"; }
    :if (($actualData != ($journal->"old_mosdns_data")) && ($actualData != $nextData)) do={ :error "rules actual MosDNS data is outside transaction old/desired states"; }
    :return (($asset = $desired) && ($actualData = $nextData));
}
# This role has host-state/MosDNS/Nginx RW mounts; the ordinary producer does
# not. Stage JSON is untrusted until Go checks the CLI nonce and schema, then
# atomically replaces and fsyncs the target plus its parent directory.
:global RUXHostControl do={
    :global RUXWriteFile; :global RUXRunOneShot; :global RUXWorkerRole;
    :local c $1; :local action $2; :local transactionID $3;
    :local content ""; :local version ""; :local outcome "";
    :if ([:typeof $4] = "str") do={ :set content $4; }
    :if ([:typeof $5] = "str") do={ :set version $5; }
    :if ([:typeof $6] = "str") do={ :set outcome $6; }
    :local requestID [:rndstr from="0123456789abcdef" length=16];
    :local request {"request_id"=$requestID;"action"=$action;"transaction_id"=$transactionID;"content"=$content;"version"=$version;"outcome"=$outcome};
    $RUXWriteFile (($c->"config_root") . "/host-request.json") [:serialize to=json value=$request options=json.no-string-conversion];
    :local result ""; :local failed false;
    :onerror hostError in={
        :set result [$RUXRunOneShot $c ("-host-control-config /config/host-control.json -host-request-id " . $requestID) (($c->"publish_root") . "/host-control.json") "host"];
    } do={ :set failed true; }
    :do { $RUXWorkerRole $c "producer"; } on-error={ :set failed true; }
    :if ($failed) do={ :error "rules host control did not finish or restore producer RO mounts"; }
    :local actualTransaction ($result->"transaction_id");
    :if (($transactionID = "") && ([:typeof $actualTransaction] = "nothing")) do={ :set actualTransaction ""; }
    :if (([:typeof $result] != "array") || (($result->"request_id") != $requestID) || (($result->"action") != $action) || ($actualTransaction != $transactionID)) do={ :error "rules host control returned a stale or foreign result"; }
    :if ((($result->"status") != "complete") || (($result->"completed") != true)) do={ :error ("rules host control failed or lacks a durable completion fence: " . $action . " " . ($result->"error_code")); }
    :return $result;
}
:global RUXProbe do={
    :global RUXRunOneShot;
    :local c $1;
    :local health [$RUXRunOneShot $c "-health-config /config/health.json" (($c->"publish_root") . "/health.json")];
    :if (($health->"status") != "healthy") do={ :error "rules native DNS/proxy health checks failed"; }
    # health.version identifies the publication inspected by the helper.
    # During rollback current is still desired; it does NOT identify loaded GEO.
    :return $health;
}
:global RUXNginx do={
    :global RUXReadJSON; :global RUXContainer;
    :local c $1; :local action $2; :local version $3; :local token $4;
    :if (!($token ~ "^[a-f0-9]{16}\$")) do={ :error "rules transaction token is invalid"; }
    :if (($action != "activate") && ($action != "restore") && ($action != "commit")) do={ :error "rules Nginx action is invalid"; }
    :local requestID [:rndstr from="0123456789abcdef" length=16];
    :local command ("/bin/sh " . ($c->"nginx_helper") . " " . $action);
    :if ($action = "activate") do={
        :if (!($version ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules version is invalid"; }
        :set command ($command . " " . $version);
    }
    :set command ($command . " " . $token . " " . $requestID);
    # shell takes over a CLI session. A second synchronous shell call in the
    # same named parent may never return. Isolate it in one owned background
    # job; no :execute file capture (which needs extra RouterOS permissions).
    :if (!(($c->"nginx_helper") ~ "^/[A-Za-z0-9_./-]+\$")) do={ :error "rules Nginx helper path is invalid"; }
    :local childSource ("/container shell " . [:tostr [$RUXContainer ($c->"nginx")]] . " cmd=\"" . $command . "\" no-sh timeout=30;");
    :local childJob [:execute $childSource];
    :local childOwner ""; :local childStarted ""; :local childGone false; :local childFingerprint false;
    :local childListed false;
    :foreach listedID in=[/system script job find] do={ :if ($listedID = $childJob) do={ :set childListed true; } }
    :if ($childListed) do={
        :do { :set childOwner [/system script job get $childJob owner]; :set childStarted [:tostr [/system script job get $childJob started]]; :set childFingerprint true; } on-error={}
        :if (!$childFingerprint) do={
            :set childListed false;
            :foreach listedID in=[/system script job find] do={ :if ($listedID = $childJob) do={ :set childListed true; } }
            :if ($childListed) do={ :error "rules live Nginx child identity could not be inspected"; }
            :set childGone true;
        }
    } else={ :set childGone true; }
    :local deadline ([:timestamp] + 35s); :local fresh false; :local state "";
    :while ([:timestamp] < $deadline) do={
        :do { :set state [$RUXReadJSON ($c->"nginx_result") (false)]; } on-error={ :set state ""; }
        :if (!$childGone) do={
            :set childListed false;
            :foreach listedID in=[/system script job find] do={ :if ($listedID = $childJob) do={ :set childListed true; } }
            :if (!$childListed) do={ :set childGone true; } else={
                :local inspected false;
                :do {
                    :if (([/system script job get $childJob owner] != $childOwner) || ([:tostr [/system script job get $childJob started]] != $childStarted)) do={ :set childGone true; }
                    :set inspected true;
                } on-error={}
                :if (!$inspected) do={
                    :set childListed false;
                    :foreach listedID in=[/system script job find] do={ :if ($listedID = $childJob) do={ :set childListed true; } }
                    :if ($childListed) do={ :error "rules live Nginx child identity inspection failed"; }
                    :set childGone true;
                }
            }
        }
        # Receipt completion precedes helper EXIT/FD9 flock release. Do not
        # start the next host action until this exact child has also exited.
        :if ($childGone && ([:typeof $state] = "array") && (($state->"request_id") = $requestID) && (($state->"run_id") = $token)) do={ :set fresh true; :break; }
        :delay 100ms;
    }
    :if (!$fresh) do={
        :if (!$childGone && $childFingerprint) do={
            :do { :if (([/system script job get $childJob owner] = $childOwner) && ([:tostr [/system script job get $childJob started]] = $childStarted)) do={ /system script job remove $childJob; } } on-error={}
        }
        :error "rules Nginx child did not exit with a fresh receipt within 35 seconds";
    }
    :local expected "";
    :if ($action = "activate") do={ :set expected "activated"; }
    :if ($action = "restore") do={ :set expected "restored"; }
    :if ($action = "commit") do={ :set expected "committed"; }
    :if ((($state->"run_id") != $token) || (($state->"request_id") != $requestID) || (($state->"action") != $action) || (($state->"completed") != true) || (($state->"status") != $expected)) do={ :error "rules Nginx action did not return a fresh completed receipt"; }
    :if (($version != "") && (($state->"version") != $version)) do={ :error "rules Nginx receipt version disagrees"; }
    :set ($state->"child_job_id") [:tostr $childJob]; :set ($state->"child_exited") $childGone; :set ($state->"child_fingerprint_captured") $childFingerprint;
    :return $state;
}
:global RUXWaitNginx do={
    :local c $1; :local deadline ([:timestamp] + 20s);
    :while (([:timestamp] + 2s) < $deadline) do={
        :local result ""; :local waiting false;
        :onerror readinessError in={ :set result [/tool fetch url=($c->"current_manifest_url") duration=2s idle-timeout=1s output=user as-value]; } do={ :set waiting true; }
        :if (!$waiting) do={
            :if (($result->"status") != "finished") do={ :error "rules Nginx metadata readiness failed"; }
            :local manifest [:deserialize from=json value=($result->"data") options=json.no-string-conversion];
            :if (([:typeof $manifest] != "array") || ([:typeof ($manifest->"version")] != "str") || !(($manifest->"version") ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules Nginx ready metadata is invalid"; }
            :return true;
        }
        :delay 200ms;
    }
    :error "rules Nginx listener did not become ready within 20 seconds";
}
:global RUXCheckSubscription do={
    :local c $1; :local version $2;
    :if ([:typeof $version] != "str") do={ :error "rules subscription desired version is invalid"; }
    :if (!($version ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules subscription desired version is invalid"; }
    # nginx -s reload returns before new workers serve the include. This is a
    # bounded metadata readiness barrier, not a retry of a media/business probe.
    :local deadline ([:timestamp] + 20s);
    :while (([:timestamp] + 2s) < $deadline) do={
        :local result ""; :local awaitingWorker false;
        :onerror requestError in={
            :set result [/tool fetch url=($c->"subscription_manifest_url") check-certificate=yes duration=2s idle-timeout=1s output=user as-value];
        } do={
            # Only the previous UNAPPLIED worker's 404 is a readiness state.
            # TLS, DNS, transport and other HTTP failures stay failures.
            :if ([:typeof [:find $requestError "Status 404"]] != "num") do={ :error $requestError; }
            :set awaitingWorker true;
        }
        :if (!$awaitingWorker) do={
            :if (($result->"status") != "finished") do={ :error "rules subscription request failed"; }
            :local manifest [:deserialize from=json value=($result->"data") options=json.no-string-conversion];
            :if ([:typeof $manifest] != "array") do={ :error "rules subscription metadata is invalid"; }
            :local observed ($manifest->"version");
            :if ([:typeof $observed] != "str") do={ :error "rules subscription metadata version is invalid"; }
            :if (!($observed ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules subscription metadata version is invalid"; }
            :if ($observed = $version) do={ :return true; }
        }
        :delay 200ms;
    }
    :error "rules subscription desired version did not become ready within 20 seconds";
}
:global RUXValidateJournal do={
    :local journal $1;
    :if ([:typeof $journal] != "array") do={ :error "rules transaction journal is invalid"; }
    :foreach field in={"run_id";"desired_version";"old_applied_version";"old_asset_value";"old_mosdns_data";"old_ack_content";"phase"} do={
        :if ([:typeof ($journal->$field)] != "str") do={ :error "rules transaction string field is invalid"; }
    }
    :foreach field in={"old_asset_present";"old_ack_present"} do={
        :if ([:typeof ($journal->$field)] != "bool") do={ :error "rules transaction boolean field is invalid"; }
    }
    :if (!(($journal->"run_id") ~ "^[a-f0-9]{16}\$")) do={ :error "rules transaction token is invalid"; }
    :if (!(($journal->"desired_version") ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules transaction desired version is invalid"; }
    :if (([:len ($journal->"old_mosdns_data")] = 0) || ([:len ($journal->"old_mosdns_data")] > 60000)) do={ :error "rules transaction MosDNS snapshot is invalid"; }
    :if (($journal->"old_ack_present") = true) do={
        :local previous ($journal->"old_applied_version");
        :if (!($previous ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules transaction previous version is invalid"; }
        :if ($previous = ($journal->"desired_version")) do={ :error "rules transaction previous version equals desired version"; }
        :local oldAck [:deserialize from=json value=($journal->"old_ack_content") options=json.no-string-conversion];
        :if ([:typeof $oldAck] != "array") do={ :error "rules transaction acknowledgement snapshot is invalid"; }
        :if (([:typeof ($oldAck->"version")] != "str") || (($oldAck->"version") != $previous) || ([:typeof ($oldAck->"run_id")] != "str") || !(($oldAck->"run_id") ~ "^[a-f0-9]{16}\$")) do={ :error "rules transaction previous acknowledgement disagrees"; }
    } else={
        :if ((($journal->"old_applied_version") != "") || (($journal->"old_ack_content") != "")) do={ :error "rules bootstrap journal has a fabricated acknowledgement"; }
    }
    :if ((($journal->"old_ack_present") != true) || (($journal->"old_asset_present") != true) || (($journal->"old_asset_value") != ("/rules/versions/" . ($journal->"old_applied_version")))) do={ :error "rules daily transaction requires an acknowledged concrete old asset"; }
    :local validPhase false;
    :foreach allowedPhase in={"prepared";"applying";"acknowledged";"rolling_back"} do={ :if (($journal->"phase") = $allowedPhase) do={ :set validPhase true; } }
    :if (!$validPhase) do={ :error "rules transaction phase is invalid"; }
    :local consumers ($journal->"consumer_snapshots");
    :if ([:typeof $consumers] != "array") do={ :error "rules transaction consumer snapshots are missing"; }
    :foreach role in={"xray";"mosdns";"nginx"} do={
        :local saved ($consumers->$role);
        :if ([:typeof $saved] != "array") do={ :error "rules transaction consumer snapshot is invalid"; }
        :foreach key in={"name";"root";"interface";"mountlists";"envlists";"cmd";"entrypoint";"direct_env";"mount_bindings";"env_bindings"} do={ :if ([:typeof ($saved->$key)] != "str") do={ :error "rules transaction consumer identity field is invalid"; } }
        :if ((($saved->"name") = "") || (($saved->"root") = "") || (($saved->"interface") = "")) do={ :error "rules transaction consumer identity is empty"; }
    }
    :return $journal;
}
:global RUXRestore do={
    :global RUXStop; :global RUXStart; :global RUXSetAsset; :global RUXReadJSON;
    :global RUXProbe; :global RUXCheckSubscription; :global RUXValidateJournal;
    :global RUXHostControl; :global RUXKnownState; :global RUXActualVersion; :global RUXWaitNginx;
    :local c $1; :local journal [$RUXValidateJournal $2];
    :local known [$RUXKnownState $c $journal];
    :local ownedNginx [$RUXHostControl $c "check_nginx" ($journal->"run_id")];
    # Persist the rollback decision BEFORE restoring either consumer. A new ACK
    # left behind by an interrupted rollback can never select commit on reboot.
    :local begun [$RUXHostControl $c "begin_restore" ($journal->"run_id")];
    :set journal [$RUXValidateJournal [$RUXReadJSON (($c->"state_root") . "/transaction.json") (true)]];
    :if (($journal->"phase") != "rolling_back") do={ :error "rules rollback decision was not durable"; }
    $RUXStop ($c->"nginx"); $RUXStop ($c->"mosdns"); $RUXStop ($c->"xray");
    $RUXSetAsset ($c->"xray_env_list") ($journal->"old_asset_present") ($journal->"old_asset_value");
    :local mos [$RUXHostControl $c "restore_mosdns" ($journal->"run_id")];
    :local nginx [$RUXHostControl $c "restore_nginx_offline" ($journal->"run_id")];
    $RUXStart ($c->"xray"); $RUXStart ($c->"mosdns"); $RUXStart ($c->"nginx");
    :local restoredVersion [$RUXActualVersion $c ($journal->"old_applied_version")];
    :if (!$restoredVersion) do={ :error "rules restored consumer assets disagree"; }
    $RUXWaitNginx $c;
    :local asserted [$RUXHostControl $c "assert_nginx" "" "" ($journal->"old_applied_version")];
    :local health [$RUXProbe $c];
    $RUXCheckSubscription $c ($journal->"old_applied_version");
    # ACK follows all actual old-state assertions, health and served version.
    :local ack [$RUXHostControl $c "restore_ack" ($journal->"run_id")];
    :local removed [$RUXHostControl $c "remove_journal" ($journal->"run_id") "" "" "restored"];
    :return $health;
}

# Both installed sources share these two configured names. Importing a body
# anonymously bypasses job ownership; install named scripts before scheduling.
:if (($settings->"script_name") = ($settings->"recover_script_name")) do={ :error "rules update and recovery script names must differ"; }
:local ownerJobs ([:len [/system script job find where script=($settings->"script_name")]] + [:len [/system script job find where script=($settings->"recover_script_name")]]);
:if ($ownerJobs != 1) do={ :error "rules host needs exactly one owning named script job"; }
:if ((($settings->"mode") != "update") && (($settings->"mode") != "recover-only")) do={ :error "rules host mode is invalid"; }
:local publish ($settings->"publish_root"); :local config ($settings->"config_root");
:local hostRoot ($settings->"state_root");
:local journalPath ($hostRoot . "/transaction.json"); :local ackPath ($hostRoot . "/applied.json");
:local token [:rndstr from="0123456789abcdef" length=16];
:local success false; :local applying false; :local current "";
:local phase "recover"; :local failedPhase ""; :local failureMessage ""; :local rollbackMessage "";

:onerror updateError in={
    # A crash may have left the stopped worker in host RW role. Reset this
    # before any producer/verify/health execution, even when no journal exists.
    $RUXWorkerRole $settings "producer";
    :local interrupted [$RUXReadJSON $journalPath (false)];
    :if ([:typeof $interrupted] = "array") do={
        :set interrupted [$RUXValidateJournal $interrupted];
        :set current ($interrupted->"desired_version");
        :local actualDesired [$RUXKnownState $settings $interrupted];
        :local nginxState [$RUXHostControl $settings "check_nginx" ($interrupted->"run_id")];
        :local acknowledged "";
        :do { :set acknowledged [$RUXReadJSON $ackPath (false)]; } on-error={ :set acknowledged ""; }
        :local ackDesired false;
        :if ([:typeof $acknowledged] = "array") do={
            :local oldAck [:deserialize from=json value=($interrupted->"old_ack_content") options=json.no-string-conversion];
            :local ackVersion ($acknowledged->"version"); :local ackRun ($acknowledged->"run_id");
            :if (($ackVersion = ($interrupted->"desired_version")) && ($ackRun = ($interrupted->"run_id"))) do={ :set ackDesired true; } else={
                :if (($ackVersion != ($oldAck->"version")) || ($ackRun != ($oldAck->"run_id"))) do={ :error "rules recovery encountered a foreign acknowledgement"; }
            }
        }
        # An ACK is evidence only when the actual complete bindings agree and
        # no rollback decision was persisted. Generic health cannot prove GEO.
        :set applying true;
        :if ($ackDesired && $actualDesired && (($nginxState->"version") = ($interrupted->"desired_version")) && (($interrupted->"phase") != "rolling_back")) do={
            $RUXStart ($settings->"xray"); $RUXStart ($settings->"mosdns"); $RUXStart ($settings->"nginx");
            $RUXWaitNginx $settings;
            :local asserted [$RUXHostControl $settings "assert_nginx" ($interrupted->"run_id") "" ($interrupted->"desired_version")];
            :local health [$RUXProbe $settings];
            $RUXCheckSubscription $settings ($interrupted->"desired_version");
            :local committed [$RUXNginx $settings "commit" ($interrupted->"desired_version") ($interrupted->"run_id")];
            :local removed [$RUXHostControl $settings "remove_journal" ($interrupted->"run_id") "" "" "committed"];
        } else={ :local restored [$RUXRestore $settings $interrupted]; }
        :set applying false;
    }

    :local applied [$RUXReadJSON $ackPath (true)];
    :local oldVersion ($applied->"version"); :local oldRun ($applied->"run_id");
    :if (([:typeof $oldVersion] != "str") || !($oldVersion ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$") || ([:typeof $oldRun] != "str") || !($oldRun ~ "^[a-f0-9]{16}\$")) do={ :error "rules daily host requires a valid bootstrap acknowledgement"; }
    :local actualOld [$RUXActualVersion $settings $oldVersion];
    :if (!$actualOld) do={ :error "rules applied acknowledgement disagrees with actual consumer assets"; }
    :local oldNginx [$RUXHostControl $settings "assert_nginx" "" "" $oldVersion];

    :if (($settings->"mode") = "recover-only") do={
        # Boot recovery is local first and does not fetch upstream, generate,
        # or depend on current metadata/DNS before repairing an owned journal.
        :set phase "recovered_health";
        $RUXStart ($settings->"xray"); $RUXStart ($settings->"mosdns"); $RUXStart ($settings->"nginx");
        $RUXWaitNginx $settings;
        :local health [$RUXProbe $settings];
        $RUXCheckSubscription $settings $oldVersion;
        :set current $oldVersion; :set success true;
    } else={
        :local manifest [$RUXReadCurrent $settings];
        :set current ($manifest->"version");
        :if ($current = $oldVersion) do={
            :set phase "generate";
            :local generated [$RUXRunOneShot $settings "-config /config/config.json" ($publish . "/status.json")];
            :if ((($generated->"status") != "published") && (($generated->"status") != "unchanged")) do={ :error "rules generation was not successful"; }
            :set manifest [$RUXReadCurrent $settings]; :set current ($manifest->"version");
            :if ($current != ($generated->"version")) do={ :error "rules generation and current manifest disagree"; }
        }
        :if (!($current ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules current version is invalid"; }
        :if ($current = $oldVersion) do={
            :set phase "unchanged_health";
            :local unchanged [$RUXActualVersion $settings $current];
            :if (!$unchanged) do={ :error "rules unchanged publication has drifted consumer bindings"; }
            :local asserted [$RUXHostControl $settings "assert_nginx" "" "" $current];
            :local health [$RUXProbe $settings];
            $RUXCheckSubscription $settings $current;
            :set success true;
        } else={
            :set phase "verify";
            :local verification [$RUXRunOneShot $settings "-verify-config /config/verify.json" ($publish . "/verification.json")];
            :if ((($verification->"status") != "verified") || (($verification->"version") != $current)) do={ :error "rules target-core verification failed"; }
            :local oldAsset [$RUXCheckTopology $settings];
            :local oldData [/file get ($settings->"mosdns_data") contents]; :local oldAck [/file get $ackPath contents];
            :local consumers [:toarray ""];
            :foreach role in={"xray";"mosdns";"nginx"} do={ :set ($consumers->$role) [$RUXSnapshotConsumer $settings $role]; }
            :local journal {"run_id"=$token;"desired_version"=$current;"old_applied_version"=$oldVersion;"old_asset_present"=true;"old_asset_value"=$oldAsset;"old_mosdns_data"=$oldData;"old_ack_present"=true;"old_ack_content"=$oldAck;"phase"="prepared";"consumer_snapshots"=$consumers};
            :set journal [$RUXValidateJournal $journal];
            :local written [$RUXHostControl $settings "write_journal" $token [:serialize to=json value=$journal options=json.no-string-conversion]];
            :set journal [$RUXValidateJournal [$RUXReadJSON $journalPath (true)]];
            :if (($journal->"run_id") != $token) do={ :error "rules durable journal readback owner disagrees"; }
            :set applying true;
            :local known [$RUXKnownState $settings $journal];
            :local nginxKnown [$RUXHostControl $settings "check_nginx" $token];
            :set phase "apply_xray";
            $RUXStop ($settings->"xray");
            $RUXSetAsset ($settings->"xray_env_list") (true) ("/rules/versions/" . $current);
            $RUXStart ($settings->"xray");
            :set phase "apply_mosdns";
            $RUXStop ($settings->"mosdns");
            :local mos [$RUXHostControl $settings "apply_mosdns" $token];
            $RUXStart ($settings->"mosdns");
            :local actualNext [$RUXActualVersion $settings $current];
            :if (!$actualNext) do={ :error "rules applied consumer asset bindings disagree"; }
            :set phase "native_health";
            :local health [$RUXProbe $settings];
            :set phase "activate_nginx";
            :local nginx [$RUXNginx $settings "activate" $current $token];
            :local asserted [$RUXHostControl $settings "assert_nginx" $token "" $current];
            $RUXCheckSubscription $settings $current;
            :set phase "acknowledge";
            :local ack {"version"=$current;"run_id"=$token;"verification_run_id"=($verification->"run_id");"health_run_id"=($health->"run_id");"applied_utc"=($nginx->"applied_utc")};
            :local acknowledged [$RUXHostControl $settings "write_ack" $token [:serialize to=json value=$ack options=json.no-string-conversion]];
            :set phase "commit";
            :local committed [$RUXNginx $settings "commit" $current $token];
            :local removed [$RUXHostControl $settings "remove_journal" $token "" "" "committed"];
            :set applying false; :set success true;
        }
    }
} do={
    :set failureMessage $updateError; :set failedPhase $phase;
    :if ($applying) do={
        :set phase "rollback";
        :onerror restoreError in={
            :local journal [$RUXReadJSON $journalPath (true)];
            :local restored [$RUXRestore $settings $journal];
        } do={ :set rollbackMessage $restoreError; :log error "xray-rules-updater: rollback incomplete; inspect transaction"; }
    }
}

:do {
    $RUXWorkerRole $settings "producer";
    /container set [$RUXContainer ($settings->"updater")] cmd="-config /config/config.json" memory-high=($settings->"worker_memory_high") memory-max=($settings->"worker_memory_max");
} on-error={ :set success false; :log error "xray-rules-updater: producer RO role was not restored"; }
:local outcome "failed"; :if ($success) do={ :set outcome "complete"; }
:local hostState {"run_id"=$token;"status"=$outcome;"mode"=($settings->"mode");"phase"=$phase;"failure_phase"=$failedPhase;"error"=$failureMessage;"rollback_error"=$rollbackMessage;"desired_version"=$current};
# Telemetry may use the file API; it is never an ACK, a durability fence or a
# recovery input. All critical state mutations above use the Go host role.
:do { $RUXWriteFile ($hostRoot . "/host-status.json") [:serialize to=json value=$hostState options=json.no-string-conversion]; } on-error={}
:if (!$success) do={ :error "xray-rules-updater: host update failed; inspect application state"; }
