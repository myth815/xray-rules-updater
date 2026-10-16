"""Filesystem/ordering tests with fake nginx/sync; never a running service.

The flock shim uses the real host kernel lock. These tests do not prove NAND
power-loss durability; the production helper invokes the real Linux sync.
"""
import json
import fcntl
import os
from pathlib import Path
import subprocess
import signal
import tempfile
import unittest
import time


HELPER = Path(__file__).with_name("apply.sh")


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.control = self.root / "control"
        self.control.mkdir()
        self.assets = self.root / "rules" / "versions"
        for version in ("release-a", "release-b"):
            directory = self.assets / version
            directory.mkdir(parents=True)
            for name in ("onexray.json", "geoip.dat", "geosite.dat", "manifest.json"):
                (directory / name).write_text("fake fixture")
        stub = self.root / "nginx-stub"
        stub.write_text('#!/bin/sh\nif [ "$1" = "-t" ] && [ -f "$RULES_CONTROL_DIR/reject-next" ] && grep -q release-b "$RULES_CONTROL_DIR/active.inc"; then exit 1; fi\nexit 0\n')
        stub.chmod(0o700)
        self.env = dict(os.environ, RULES_CONTROL_DIR=str(self.control), RULES_PUBLISH_DIR=str(self.root / "rules"), NGINX_BIN=str(stub))
        self.install_test_flock()
        sync = self.root / "bin" / "sync"
        sync.write_text('#!/bin/sh\nn=0; [ ! -f "$RULES_CONTROL_DIR/sync-count" ] || n=$(cat "$RULES_CONTROL_DIR/sync-count"); n=$((n+1)); printf "%s\\n" "$n" > "$RULES_CONTROL_DIR/sync-count"; [ "$n" != "${RULES_FAIL_SYNC_AT:-never}" ]\n')
        sync.chmod(0o700)

    def run_helper(self, *args, ok=True):
        result = subprocess.run(["/bin/sh", str(HELPER), *args], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode == 0, ok, result.stderr + result.stdout)
        state = self.control / "apply-result.json"
        return json.loads(state.read_text()) if state.exists() else None

    def test_activate_commit_next_restore(self):
        (self.control / "active.inc").write_text('set $rules_version "bootstrap";\n')
        self.assertEqual(self.run_helper("activate", "release-a", "token1")["status"], "activated")
        self.assertEqual(self.run_helper("commit", "token1")["status"], "committed")
        self.assertEqual(self.run_helper("activate", "release-b", "token2")["version"], "release-b")
        restored = self.run_helper("restore", "token2")
        self.assertEqual((restored["status"], restored["version"]), ("restored", "release-a"))
        self.assertIn("release-a", (self.control / "active.inc").read_text())

    def test_bootstrap_absence_restored_truthfully(self):
        self.run_helper("activate", "release-a", "first")
        restored = self.run_helper("restore", "first")
        self.assertFalse((self.control / "active.inc").exists())
        self.assertEqual(restored["version"], "")

    def test_failed_nginx_validation_restores_original(self):
        (self.control / "active.inc").write_text('set $rules_version "release-a";\n')
        (self.control / "reject-next").touch()
        state = self.run_helper("activate", "release-b", "broken", ok=False)
        self.assertEqual(state["status"], "failed")
        self.assertEqual(json.loads((self.control / "apply-state.json").read_text())["status"], "failed")
        self.assertIn("release-a", (self.control / "active.inc").read_text())
        self.assertEqual(self.run_helper("restore", "broken")["status"], "restored")

    def test_restore_before_activation_is_noop(self):
        original = 'set $rules_version "bootstrap";\n'
        (self.control / "active.inc").write_text(original)
        self.assertEqual(self.run_helper("restore", "never-started")["status"], "restored")
        self.assertEqual((self.control / "active.inc").read_text(), original)

    def test_second_pending_transaction_is_refused(self):
        self.run_helper("activate", "release-a", "pending")
        state = self.run_helper("activate", "release-b", "different", ok=False)
        self.assertEqual(state["error_code"], "previous_transaction_pending")
        self.assertIn("release-a", (self.control / "active.inc").read_text())

    def test_same_token_does_not_replace_original_backup(self):
        original = 'set $rules_version "bootstrap";\n'
        (self.control / "active.inc").write_text(original)
        self.run_helper("activate", "release-a", "same")
        self.run_helper("activate", "release-a", "same")
        self.run_helper("restore", "same")
        self.assertEqual((self.control / "active.inc").read_text(), original)

    def test_invalid_version_token_and_missing_assets(self):
        self.run_helper("activate", "../escape", "safe", ok=False)
        self.run_helper("activate", "release-a", "bad;token", ok=False)
        self.assertEqual(self.run_helper("activate", "missing", "safe", ok=False)["error_code"], "missing_asset")
        self.assertFalse((self.control / "active.inc").exists())

    def test_receipt_has_fresh_request_and_authoritative_state_stays_separate(self):
        result = self.run_helper("activate", "release-a", "aaaaaaaaaaaaaaaa", "1111111111111111")
        self.assertEqual((result["request_id"], result["action"], result["completed"]), ("1111111111111111", "activate", True))
        self.run_helper("commit", "aaaaaaaaaaaaaaaa", "2222222222222222")
        original = (self.control / "apply-state.json").read_bytes()
        no_op = self.run_helper("restore", "bbbbbbbbbbbbbbbb", "3333333333333333")
        self.assertEqual((no_op["run_id"], no_op["version"], no_op["completed"]), ("bbbbbbbbbbbbbbbb", "release-a", True))
        self.assertEqual((self.control / "apply-state.json").read_bytes(), original)

    def test_failed_foreign_request_cannot_overwrite_pending_authoritative_state(self):
        self.run_helper("activate", "release-a", "pending")
        original = (self.control / "apply-state.json").read_bytes()
        result = self.run_helper("activate", "release-b", "foreign", ok=False)
        self.assertEqual(result["error_code"], "previous_transaction_pending")
        self.assertEqual((self.control / "apply-state.json").read_bytes(), original)

    def test_forged_substring_or_owner_in_previous_state_is_rejected(self):
        for mutation in (lambda s: s.replace('"run_id":"owner"', '"run_id":"foreign"'),
                         lambda s: s[:-2] + ',"extra":"committed"}\n',
                         lambda s: s.replace('"status":"committed"', '"status":"activated","status":"committed"')):
            with self.subTest(mutation=mutation):
                self.run_helper("activate", "release-a", "owner")
                self.run_helper("commit", "owner")
                state = self.control / "apply-state.json"
                state.write_text(mutation(state.read_text()))
                self.run_helper("activate", "release-b", "new", ok=False)
                self.assertIn("release-a", (self.control / "active.inc").read_text())
                # Reuse the same owner to reconstruct its valid state.
                self.run_helper("activate", "release-a", "owner")

    def test_sync_failure_before_backup_rename_does_not_change_active(self):
        original = 'set $rules_version "release-a";\n'
        (self.control / "active.inc").write_text(original)
        self.env["RULES_FAIL_SYNC_AT"] = "1"
        self.run_helper("activate", "release-b", "new", "1111111111111111", ok=False)
        self.assertEqual((self.control / "active.inc").read_text(), original)
        self.assertFalse((self.control / ".active.previous.token").exists())
        self.assertFalse((self.control / "apply-result.json").exists())

    def test_sync_failure_cannot_leave_fresh_completed_receipt(self):
        self.run_helper("activate", "release-a", "owner")
        self.run_helper("commit", "owner")
        self.env["RULES_FAIL_SYNC_AT"] = str(int((self.control / "sync-count").read_text()) + 3)
        result = self.run_helper("commit", "owner", "4444444444444444", ok=False)
        self.assertEqual((result["request_id"], result["completed"]), ("4444444444444444", False))
        self.env.pop("RULES_FAIL_SYNC_AT")
        self.assertTrue(self.run_helper("commit", "owner", "5555555555555555")["completed"])

    def test_go_offline_restored_state_is_accepted(self):
        self.run_helper("activate", "release-a", "owner")
        state_path = self.control / "apply-state.json"
        state = json.loads(state_path.read_text())
        state["status"] = "restored"
        state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
        self.assertEqual(self.run_helper("activate", "release-b", "next")["version"], "release-b")

    def test_symlink_and_nonempty_lock_refused_without_truncation(self):
        target = self.root / "foreign"
        target.write_text("keep")
        (self.control / "active.inc").symlink_to(target)
        self.run_helper("activate", "release-a", "new", ok=False)
        self.assertEqual(target.read_text(), "keep")
        (self.control / "active.inc").unlink()
        (self.control / ".apply.flock").write_text("foreign")
        self.run_helper("activate", "release-a", "new", ok=False)
        self.assertEqual((self.control / ".apply.flock").read_text(), "foreign")

    def test_invalid_request_id_never_creates_a_receipt(self):
        self.run_helper("activate", "release-a", "safe", "not-a-nonce", ok=False)
        self.assertFalse((self.control / "apply-result.json").exists())

    def install_test_flock(self):
        directory = self.root / "bin"
        directory.mkdir(exist_ok=True)
        executable = directory / "flock"
        executable.write_text('#!/usr/bin/env python3\nimport fcntl,sys\ntry: fcntl.flock(int(sys.argv[-1]),fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(1)\n')
        executable.chmod(0o700)
        self.env["PATH"] = str(directory) + os.pathsep + self.env["PATH"]

    def test_flock_refuses_concurrent_helper(self):
        with open(self.control / ".apply.flock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_helper("activate", "release-a", "busy", ok=False)
        self.assertFalse((self.control / "active.inc").exists())
        self.assertEqual(self.run_helper("activate", "release-a", "available")["status"], "activated")

    def test_flock_does_not_survive_helper_kill(self):
        stub = Path(self.env["NGINX_BIN"])
        stub.write_text('#!/bin/sh\ntouch "$RULES_CONTROL_DIR/entered"\nsleep 30\n')
        process = subprocess.Popen(["/bin/sh", str(HELPER), "activate", "release-a", "interrupted"], env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            for _ in range(300):
                if (self.control / "entered").exists():
                    break
                if process.poll() is not None:
                    self.fail("helper exited before entering simulated nginx")
                time.sleep(0.02)
            else:
                self.fail("helper did not enter simulated nginx")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        with open(self.control / ".apply.flock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertFalse((self.control / ".apply.lock").exists())


if __name__ == "__main__":
    unittest.main()
