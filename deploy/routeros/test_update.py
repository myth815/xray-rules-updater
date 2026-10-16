"""Local source contracts and interruption-state matrix; no RouterOS execution.

Native syntax, mount-list values, script permissions and actual lifecycle flags
must additionally be exercised by the isolated target-router fixtures.
"""
from itertools import product
from pathlib import Path
import re
import unittest

SOURCE = Path(__file__).with_name("update.rsc").read_text()


def function(name):
    start = SOURCE.index(":global " + name + " do={")
    begin = SOURCE.index("{", start)
    depth, quoted, escaped, comment = 0, False, False, False
    for index in range(begin, len(SOURCE)):
        char = SOURCE[index]
        if comment:
            if char == "\n":
                comment = False
            continue
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == "#":
            comment = True
        elif char == '"':
            quoted = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError("unclosed function " + name)


class SourceContracts(unittest.TestCase):
    def test_functions_and_file_size(self):
        names = re.findall(r":global (RUX\w+) do=", SOURCE)
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertTrue(function(name).endswith("}"))
        self.assertLess(len(SOURCE.encode()), 60000)

    def test_native_language_pitfalls_do_not_regress(self):
        self.assertNotRegex(SOURCE, r":return\s*;")
        self.assertNotRegex(SOURCE, r":local\s+(?:name|value|list|src|dst|mode|running|stopped)\s")
        self.assertNotRegex(SOURCE, r"\$RUX\w+[^;\n]*\s(?:true|false)(?:\s|;|\])")
        for match in re.finditer(r'~ "((?:\\.|[^"\\])*)"', SOURCE):
            self.assertFalse(match.group(1).endswith("$") and not match.group(1).endswith("\\$"))

    def test_no_critical_routeros_file_writes(self):
        # File API is staging/telemetry only, never a durability fence.
        main = SOURCE[SOURCE.index("# Both installed sources"):]
        calls = [line.strip() for line in main.splitlines() if "$RUXWriteFile" in line]
        self.assertEqual(len(calls), 1)
        self.assertIn('"/host-status.json"', calls[0])
        self.assertNotIn("/file remove", SOURCE)
        for action in ("write_journal", "begin_restore", "apply_mosdns", "restore_mosdns", "write_ack", "restore_ack", "remove_journal", "restore_nginx_offline"):
            self.assertIn('"' + action + '"', SOURCE)

    def test_named_update_and_recovery_share_mutex(self):
        self.assertIn('($settings->"script_name") = ($settings->"recover_script_name")', SOURCE)
        self.assertIn('script=($settings->"script_name")', SOURCE)
        self.assertIn('script=($settings->"recover_script_name")', SOURCE)
        self.assertIn("$ownerJobs != 1", SOURCE)

    def test_role_handoff_cannot_execute_producer_with_host_rw(self):
        role = function("RUXWorkerRole")
        self.assertLess(role.index("-host-request-id invalid"), role.index("mountlists=$desired"))
        self.assertIn('($row->"stopped") != true', role)
        self.assertIn("start-on-boot", role)
        self.assertIn("uncontrolled RW mount", role)
        self.assertIn("controlled destination", role)
        self.assertIn('($expectedSources->"/diagnostics") $diagnosticSource', role)
        self.assertIn('"/diagnostics") "rw"', role)
        self.assertIn("diagnostic RW source overlaps", role)

    def test_consumer_submounts_cannot_override_verified_assets(self):
        topology = function("RUXCheckTopology")
        self.assertIn('"/rules/"', topology)
        self.assertIn('"/etc/mosdns/"', topology)
        self.assertIn("overrides publication assets", topology)
        self.assertIn("overrides configuration data", topology)

    def test_fresh_host_and_nginx_results_are_required(self):
        host = function("RUXHostControl")
        for field in ("request_id", "action", "transaction_id", "status", "completed"):
            self.assertIn('->"' + field + '"', host)
        self.assertIn('($result->"completed") != true', host)
        one_shot = function("RUXRunOneShot")
        self.assertIn("$newRun != $oldRun", one_shot)
        self.assertIn('($now->"stopped") = true', one_shot)
        nginx = function("RUXNginx")
        self.assertIn('($state->"request_id") != $requestID', nginx)
        self.assertIn('($state->"completed") != true', nginx)
        self.assertIn('($state->"version") != $version', nginx)
        self.assertIn(':local childJob [:execute $childSource]', nginx)
        self.assertIn('$childGone &&', nginx)
        self.assertIn('35s', nginx)
        self.assertIn('/system script job get $childJob started', nginx)
        self.assertIn('/system script job remove $childJob', nginx)
        self.assertNotIn('file=', nginx)
        self.assertIn(':foreach listedID in=[/system script job find]', nginx)
        self.assertIn('live Nginx child identity could not be inspected', nginx)
        self.assertIn('!$childGone && $childFingerprint', nginx)

    def test_recovery_requires_actual_consumers_and_durable_decision(self):
        main = SOURCE[SOURCE.index("# Both installed sources"):]
        self.assertIn('$ackDesired && $actualDesired && (($nginxState->"version") = ($interrupted->"desired_version")) && (($interrupted->"phase") != "rolling_back")', main)
        known = function("RUXKnownState")
        self.assertIn("$RUXCheckIdentities", known)
        for field in ("mount_bindings", "env_bindings"):
            self.assertIn(field, function("RUXSnapshotConsumer"))
            self.assertIn(field, function("RUXCheckIdentities"))
            self.assertIn(field, function("RUXValidateJournal"))
        self.assertIn("$asset = $desired", known)
        self.assertIn("$actualData = $nextData", known)
        restore = function("RUXRestore")
        self.assertLess(restore.index('"check_nginx"'), restore.index("$RUXStop"))
        self.assertLess(restore.index('"begin_restore"'), restore.index('    $RUXStop'))
        self.assertLess(restore.index('"restore_nginx_offline"'), restore.index('    $RUXStart'))
        self.assertLess(restore.index("$RUXCheckSubscription $c"), restore.index('"restore_ack"'))
        self.assertLess(restore.index('"restore_ack"'), restore.index('"remove_journal"'))

    def test_unchanged_refuses_asset_drift_before_generation(self):
        main = SOURCE[SOURCE.index("# Both installed sources"):]
        self.assertLess(main.index("$RUXActualVersion $settings $oldVersion"), main.index('phase "generate"'))
        self.assertIn("unchanged publication has drifted consumer bindings", main)
        self.assertIn('"assert_nginx" "" "" $current', main)

    def test_recover_only_skips_generation_and_current_metadata(self):
        begin = SOURCE.index('    :if (($settings->"mode") = "recover-only") do={')
        end = SOURCE.index('    } else={', begin)
        recovery = SOURCE[begin:end]
        self.assertNotIn("$RUXReadCurrent", recovery)
        self.assertNotIn("-config /config/config.json", recovery)
        self.assertIn("$RUXStart", recovery)
        self.assertIn("$RUXCheckSubscription", recovery)

    def test_readiness_is_bounded_and_keeps_tls_validation(self):
        check = function("RUXCheckSubscription")
        for part in ("20s", "duration=2s", "idle-timeout=1s", "check-certificate=yes", "Status 404", "$observed = $version"):
            self.assertIn(part, check)
        self.assertIn(":error $requestError", check)


class InterruptionDecisionMatrix(unittest.TestCase):
    @staticmethod
    def decide(ack, asset, mosdns, nginx, phase):
        # This documents the required safety property, while source-contract
        # assertions above bind every predicate to the actual RouterOS body.
        return "commit" if ack == asset == mosdns == nginx == "desired" and phase != "rolling_back" else "restore"

    def test_every_partial_state_restores(self):
        for ack, asset, mos, nginx, phase in product(("old", "desired"), repeat=5):
            # The fifth position is converted to the two persistent decisions.
            decision_phase = "prepared" if phase == "old" else "rolling_back"
            result = self.decide(ack, asset, mos, nginx, decision_phase)
            expected = "commit" if (ack, asset, mos, nginx, decision_phase) == ("desired", "desired", "desired", "desired", "prepared") else "restore"
            self.assertEqual(result, expected)

    def test_ack_and_http_cannot_commit_restored_core(self):
        self.assertEqual(self.decide("desired", "old", "old", "desired", "prepared"), "restore")
        self.assertEqual(self.decide("desired", "desired", "desired", "desired", "rolling_back"), "restore")


if __name__ == "__main__":
    unittest.main()
