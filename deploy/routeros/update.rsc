# Install this file's contents as the source of ONE named /system script.
# A scheduler invokes that script; importing this body executes one task.
# Deployment must create mounts/configs first. Values below are public samples.
# Required permissions: read,write,policy,test. No administrator credentials.
# RouterOS 7.23 state is print as-value -> running; there is no status property.
# Functions are namespaced and hold code only. Persistent state is bounded JSON.
# The dedicated xray_env_list must be attached to the Xray container and must
# be its ONLY source of XRAY_LOCATION_ASSET. Consumer mounts expose /rules RO.
# Production updater config MUST require apply ack AND transaction hold paths.
# Bootstrap publishes the first current and enables its internal metadata URL
# before this daily body runs. RouterOS /file does not traverse current symlink.

:local settings {
    "script_name"="XrayRulesUpdate";
    "updater"="xray-rules-updater";
    "xray"="xray-core:latest";
    "mosdns"="mosdns:latest";
    "nginx"="nginx:1.31.5";
    "xray_env_list"="XrayRulesAssets";
    "publish_root"="docker/xray-rules-updater/publish";
    "config_root"="docker/xray-rules-updater/config";
    "state_root"="docker/xray-rules-updater/state";
    "mosdns_data"="docker/mosdns/config/dat_exec.yaml";
    "mosdns_template"="docker/xray-rules-updater/config/mosdns-dat_exec.template.yaml";
    "nginx_state"="docker/nginx/config/rules/apply-state.json";
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
    :local result [/tool fetch url=($c->"current_manifest_url") output=user as-value];
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
:global RUXRunOneShot do={
    :global RUXReadJSON; :global RUXContainer;
    :local c $1; :local command $2; :local statusFile $3;
    :local workerName ($c->"updater"); :local id [$RUXContainer $workerName];
    :local row [:pick [/container print as-value where name=$workerName] 0];
    :if (($row->"running") = true) do={ :error "rules updater is already running"; }
    :local old [$RUXReadJSON $statusFile (false)]; :local oldRun "";
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
        :local state [$RUXReadJSON $statusFile (false)];
        :local now [:pick [/container print as-value where name=$workerName] 0];
        :if ([:typeof $state] = "array") do={
            :local newRun ($state->"run_id");
            :if (([:typeof $newRun] = "str") && ($newRun ~ "^[a-f0-9]{16}\$") && ($newRun != $oldRun) && (($now->"running") != true)) do={ :return $state; }
        }
    }
    /container stop $id;
    :error "rules task timed out or did not write a fresh completion record";
}
:global RUXStop do={
    :global RUXContainer;
    :local consumerName $1; :local id [$RUXContainer $consumerName];
    /container stop $id;
    :for wait from=0 to=60 do={
        :local row [:pick [/container print as-value where name=$consumerName] 0];
        :if (($row->"running") != true) do={ :return; }
        :delay 500ms;
    }
    :error "rules consumer did not stop";
}
:global RUXStart do={
    :global RUXContainer;
    :local consumerName $1; /container start [$RUXContainer $consumerName];
    :for wait from=0 to=60 do={
        :local row [:pick [/container print as-value where name=$consumerName] 0];
        :if (($row->"running") = true) do={ :return; }
        :delay 500ms;
    }
    :error "rules consumer did not start";
}
:global RUXSetAsset do={
    :local listName $1; :local present $2; :local assetPath $3;
    :if ([:typeof $present] != "bool") do={ :error "rules asset presence flag must be boolean"; }
    :local ids [/container envs find where list=$listName and key="XRAY_LOCATION_ASSET"];
    :if ([:len $ids] > 1) do={ :error "rules asset environment is ambiguous"; }
    :if (!$present) do={ /container envs remove $ids; :return; }
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
    :local command ("/bin/sh " . ($c->"nginx_helper") . " " . $action);
    :if ($action = "activate") do={
        :if (!($version ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules version is invalid"; }
        :set command ($command . " " . $version);
    }
    :set command ($command . " " . $token);
    /container shell [$RUXContainer ($c->"nginx")] cmd=$command no-sh;
    :local state [$RUXReadJSON ($c->"nginx_state") (true)];
    :local expected "";
    :if ($action = "activate") do={ :set expected "activated"; }
    :if ($action = "restore") do={ :set expected "restored"; }
    :if ($action = "commit") do={ :set expected "committed"; }
    :if ((($state->"run_id") != $token) || (($state->"status") != $expected)) do={ :error "rules Nginx action did not complete"; }
    :return $state;
}
:global RUXCheckSubscription do={
    :local c $1; :local version $2;
    :local result [/tool fetch url=($c->"subscription_manifest_url") check-certificate=yes output=user as-value];
    :if (($result->"status") != "finished") do={ :error "rules subscription request failed"; }
    :local manifest [:deserialize from=json value=($result->"data") options=json.no-string-conversion];
    :if (($manifest->"version") != $version) do={ :error "rules subscription still serves a different version"; }
}
:global RUXValidateJournal do={
    :local journal $1;
    :if ([:typeof $journal] != "array") do={ :error "rules transaction journal is invalid"; }
    :foreach field in={"run_id";"desired_version";"old_applied_version";"old_asset_value";"old_mosdns_data";"old_ack_content"} do={
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
        :if (([:typeof ($oldAck->"version")] != "str") || (($oldAck->"version") != $previous)) do={ :error "rules transaction previous acknowledgement disagrees"; }
    } else={
        :if ((($journal->"old_applied_version") != "") || (($journal->"old_ack_content") != "")) do={ :error "rules bootstrap journal has a fabricated acknowledgement"; }
    }
    :return $journal;
}
:global RUXRestore do={
    :global RUXStop; :global RUXStart; :global RUXSetAsset; :global RUXWriteFile;
    :global RUXProbe; :global RUXNginx; :global RUXCheckSubscription; :global RUXValidateJournal;
    :local c $1; :local journal [$RUXValidateJournal $2];
    $RUXStop ($c->"mosdns"); $RUXStop ($c->"xray");
    $RUXSetAsset ($c->"xray_env_list") ($journal->"old_asset_present") ($journal->"old_asset_value");
    $RUXWriteFile ($c->"mosdns_data") ($journal->"old_mosdns_data");
    $RUXStart ($c->"xray"); $RUXStart ($c->"mosdns");
    :local nginx [$RUXNginx $c "restore" "" ($journal->"run_id")];
    :local health [$RUXProbe $c];
    # Restore the actual prior acknowledgement, not publisher previous/current.
    :local ackPath (($c->"state_root") . "/applied.json");
    :if (($journal->"old_ack_present") = true) do={
        $RUXWriteFile $ackPath ($journal->"old_ack_content");
        $RUXCheckSubscription $c ($journal->"old_applied_version");
    } else={
        /file remove [/file find where name=$ackPath];
        # Bootstrap restored original embedded assets/config and old Nginx
        # include. There is no fabricated prior publication version to assert.
    }
}

# SINGLE HOST OWNER. Multiple scheduler/manual jobs must use this script name.
:if ([:len [/system script job find where script=($settings->"script_name")]] > 1) do={ :error "rules host transaction is already running"; }
:local publish ($settings->"publish_root"); :local config ($settings->"config_root");
:local hostRoot ($settings->"state_root");
:local journalPath ($hostRoot . "/transaction.json"); :local ackPath ($hostRoot . "/applied.json");
:local token [:rndstr from="0123456789abcdef" length=16];
:local success false; :local applying false; :local current "";
:local phase "recover";

:do {
    # Recover a bounded interrupted host transaction before any generation.
    :local interrupted [$RUXReadJSON $journalPath (false)];
    :if ([:typeof $interrupted] = "array") do={
        :set interrupted [$RUXValidateJournal $interrupted];
        :set applying true;
        # The journal was persisted before any mutation. A crash can tear the
        # later ACK write; recover from the valid journal in that case. Outside
        # this recovery branch, malformed ACKs still fail closed.
        :local acknowledged "";
        :do { :set acknowledged [$RUXReadJSON $ackPath (false)]; } on-error={ :set acknowledged ""; }
        :if (([:typeof $acknowledged] = "array") && (($acknowledged->"version") = ($interrupted->"desired_version"))) do={
            :local health [$RUXProbe $settings];
            $RUXCheckSubscription $settings ($interrupted->"desired_version");
            :local committed [$RUXNginx $settings "commit" "" ($interrupted->"run_id")];
        } else={ $RUXRestore $settings $interrupted; }
        /file remove [/file find where name=$journalPath];
        :set applying false;
    }

    :local manifest [$RUXReadCurrent $settings];
    :local applied [$RUXReadJSON $ackPath (false)]; :local oldVersion "";
    :if ([:typeof $applied] = "array") do={
        :local acknowledgedVersion ($applied->"version");
        :if ([:typeof $acknowledgedVersion] != "str") do={ :error "rules previous acknowledgement version is invalid"; }
        :if (!($acknowledgedVersion ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules previous acknowledgement version is invalid"; }
        :set oldVersion $acknowledgedVersion;
    }
    :if ([:typeof $manifest] = "array") do={ :set current ($manifest->"version"); }
    :if (($current = "") || ($current = $oldVersion)) do={
        :set phase "generate";
        :local generated [$RUXRunOneShot $settings "-config /config/config.json" ($publish . "/status.json")];
        :if ((($generated->"status") != "published") && (($generated->"status") != "unchanged")) do={ :error "rules generation was not successful"; }
        :set manifest [$RUXReadCurrent $settings];
        :set current ($manifest->"version");
        :if ($current != ($generated->"version")) do={ :error "rules generation and current manifest disagree"; }
    }
    # Pending current skips generation, even if upstream latest has advanced.
    :if (!($current ~ "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\$")) do={ :error "rules current version is invalid"; }
    :if ($current = $oldVersion) do={
        :set phase "unchanged_health";
        :local health [$RUXProbe $settings];
        $RUXCheckSubscription $settings $current;
        :set success true;
    } else={
        :set phase "verify";
        :local verification [$RUXRunOneShot $settings "-verify-config /config/verify.json" ($publish . "/verification.json")];
        :if ((($verification->"status") != "verified") || (($verification->"version") != $current)) do={ :error "rules target-core verification failed"; }

        :local envIDs [/container envs find where list=($settings->"xray_env_list") and key="XRAY_LOCATION_ASSET"];
        :if ([:len $envIDs] > 1) do={ :error "rules previous Xray environment is ambiguous"; }
        :local oldAsset ""; :local hadAsset false;
        :if ([:len $envIDs] = 1) do={ :set hadAsset true; :set oldAsset [/container envs get [:pick $envIDs 0] value]; }
        :local oldData [/file get ($settings->"mosdns_data") contents];
        :local oldAck ""; :local hadAck false;
        :if ([:typeof $applied] = "array") do={ :set hadAck true; :set oldAck [/file get $ackPath contents]; }
        :local journal {"run_id"=$token;"desired_version"=$current;"old_applied_version"=$oldVersion;"old_asset_present"=$hadAsset;"old_asset_value"=$oldAsset;"old_mosdns_data"=$oldData;"old_ack_present"=$hadAck;"old_ack_content"=$oldAck};
        :set journal [$RUXValidateJournal $journal];
        $RUXWriteFile $journalPath [:serialize to=json value=$journal options=json.no-string-conversion];
        :set applying true;

        :local assets ("/rules/versions/" . $current);
        :local template [/file get ($settings->"mosdns_template") contents];
        :local nextData [$RUXRenderMos $template $assets];
        :set phase "apply_xray";
        $RUXStop ($settings->"xray");
        $RUXSetAsset ($settings->"xray_env_list") (true) $assets;
        $RUXStart ($settings->"xray");
        :set phase "apply_mosdns";
        $RUXStop ($settings->"mosdns");
        $RUXWriteFile ($settings->"mosdns_data") $nextData;
        $RUXStart ($settings->"mosdns");
        :set phase "native_health";
        :local health [$RUXProbe $settings];
        :set phase "activate_nginx";
        :local nginx [$RUXNginx $settings "activate" $current $token];
        $RUXCheckSubscription $settings $current;

        :set phase "acknowledge";
        :local ack {"version"=$current;"run_id"=$token;"verification_run_id"=($verification->"run_id");"health_run_id"=($health->"run_id");"applied_utc"=($nginx->"applied_utc")};
        $RUXWriteFile $ackPath [:serialize to=json value=$ack options=json.no-string-conversion];
        :set phase "commit";
        :local committed [$RUXNginx $settings "commit" "" $token];
        /file remove [/file find where name=$journalPath];
        :set applying false; :set success true;
    }
} on-error={
    :if ($applying) do={
        :do {
            :local journal [$RUXReadJSON $journalPath (true)];
            $RUXRestore $settings $journal;
            /file remove [/file find where name=$journalPath];
        } on-error={ :log error "xray-rules-updater: rollback incomplete; transaction retained"; }
    }
}

# A stopped worker is expected; restore its normal generation command for
# manual use, including the smaller default memory limits. cpu-list is unchanged.
# No service restarts occur for an unchanged applied version.
:do { /container set [$RUXContainer ($settings->"updater")] cmd="-config /config/config.json" memory-high=($settings->"worker_memory_high") memory-max=($settings->"worker_memory_max"); } on-error={}
:local outcome "failed"; :if ($success) do={ :set outcome "complete"; }
:local hostState {"run_id"=$token;"status"=$outcome;"phase"=$phase;"desired_version"=$current};
:do { $RUXWriteFile ($hostRoot . "/host-status.json") [:serialize to=json value=$hostState options=json.no-string-conversion]; } on-error={}
:if (!$success) do={ :error "xray-rules-updater: host update failed; no new application acknowledged"; }
