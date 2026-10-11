"""Offline unit tests for private_agent.

These tests MOCK Ollama entirely: no network access and no model are required.
They run under either `python3 -m unittest` or `python3 -m pytest`.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

# Make the package importable whether run from repo root or this directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import private_agent as pa  # noqa: E402


class _TmpProject(unittest.TestCase):
    """Base class that gives each test a disposable, synthetic project dir."""

    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        (self.root / "src").mkdir()
        self.target = self.root / "src" / "mod.py"
        self.target.write_text("value = 1\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()


class ModelValidationTests(unittest.TestCase):
    def test_accepts_plain_local_names(self):
        for name in ("llama3", "llama3:8b", "library/qwen2.5-coder:7b"):
            self.assertEqual(pa.assert_local_model(name), name)

    def test_rejects_cloud_and_remote_models(self):
        for bad in (
            "gpt-oss:120b-cloud",
            "something-cloud",
            "gpt-4o",
            "claude-3-opus",
            "gemini-1.5",
            "http://host/model",
            "ollama.com/library/x",
            "remote-model",
        ):
            with self.assertRaises(pa.SecurityError):
                pa.assert_local_model(bad)

    def test_rejects_empty_and_garbage(self):
        for bad in ("", "   ", "bad name!", "../x"):
            with self.assertRaises(pa.SecurityError):
                pa.assert_local_model(bad)


class PathSafetyTests(_TmpProject):
    def test_accepts_in_project_file(self):
        resolved = pa.assert_safe_path(self.root, "src/mod.py")
        self.assertEqual(resolved, self.target)

    def test_rejects_path_traversal(self):
        with self.assertRaises(pa.SecurityError):
            pa.assert_safe_path(self.root, "../../etc/passwd")

    def test_rejects_absolute_outside_project(self):
        with self.assertRaises(pa.SecurityError):
            pa.assert_safe_path(self.root, "/etc/hostname")

    def test_rejects_symlink_component(self):
        link = self.root / "src" / "link.py"
        try:
            os.symlink(self.target, link)
        except OSError:
            self.skipTest("symlinks unsupported on this platform")
        with self.assertRaises(pa.SecurityError):
            pa.assert_safe_path(self.root, "src/link.py")

    def test_rejects_symlinked_parent_dir(self):
        real_dir = self.root / "real"
        real_dir.mkdir()
        (real_dir / "f.py").write_text("x = 1\n", encoding="utf-8")
        link_dir = self.root / "linkdir"
        try:
            os.symlink(real_dir, link_dir)
        except OSError:
            self.skipTest("symlinks unsupported on this platform")
        with self.assertRaises(pa.SecurityError):
            pa.assert_safe_path(self.root, "linkdir/f.py")

    def test_rejects_sensitive_files(self):
        for name in ("credentials.txt", ".env", "bank_statement.csv",
                     "id_rsa", "my_password_list.md"):
            (self.root / name).write_text("x\n", encoding="utf-8")
            with self.assertRaises(pa.SecurityError):
                pa.assert_safe_path(self.root, name)

    def test_rejects_missing_file(self):
        with self.assertRaises(pa.SecurityError):
            pa.assert_safe_path(self.root, "src/nope.py")

    def test_rejects_directory(self):
        with self.assertRaises(pa.SecurityError):
            pa.assert_safe_path(self.root, "src")


class FingerprintAndBackupTests(_TmpProject):
    def test_fingerprint_detects_change(self):
        fp1 = pa.fingerprint_file(self.target)
        time.sleep(0.01)
        self.target.write_text("value = 2\n", encoding="utf-8")
        fp2 = pa.fingerprint_file(self.target)
        self.assertFalse(fp1.matches(fp2))

    def test_backup_preserves_original(self):
        backup = pa.backup_file(self.target)
        self.assertTrue(backup.exists())
        self.assertTrue(backup.name.endswith(".bak"))
        self.assertEqual(backup.read_text(), "value = 1\n")


class _Spy:
    """Records whether model output was ever executed (it must not be)."""

    def __init__(self, reply: str):
        self.reply = reply
        self.executed = False

    def generate(self, model: str, prompt: str) -> str:
        # A real backend would never run anything here; a malicious reply must
        # still never be executed by the session.
        return self.reply


class EditSessionTests(_TmpProject):
    def _session(self, reply, approver):
        self.spy = _Spy(reply)
        return pa.EditSession(
            self.root, "llama3", self.spy.generate,
            approver=approver, display=lambda _m: None,
        )

    def test_approved_edit_writes_and_backs_up(self):
        session = self._session("```\nvalue = 99\n```\n", lambda _n: True)
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "change value")
        wrote = session.apply(edit)
        self.assertTrue(wrote)
        self.assertEqual(self.target.read_text(), "value = 99\n")
        backups = list((self.root / "src").glob("mod.py.*.bak"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "value = 1\n")

    def test_declined_edit_is_not_written(self):
        session = self._session("```\nvalue = 99\n```\n", lambda _n: False)
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "change value")
        wrote = session.apply(edit)
        self.assertFalse(wrote)
        self.assertEqual(self.target.read_text(), "value = 1\n")
        self.assertEqual(list((self.root / "src").glob("mod.py.*.bak")), [])

    def test_stale_file_rejected(self):
        session = self._session("```\nvalue = 99\n```\n", lambda _n: True)
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "change value")
        # Out-of-band modification AFTER the read.
        time.sleep(0.01)
        self.target.write_text("value = 123\n", encoding="utf-8")
        with self.assertRaises(pa.SecurityError):
            session.apply(edit)
        # The on-disk file keeps the out-of-band content; no overwrite happened.
        self.assertEqual(self.target.read_text(), "value = 123\n")

    def test_noop_edit_is_skipped(self):
        session = self._session("```\nvalue = 1\n```\n", lambda _n: True)
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "no change")
        self.assertTrue(edit.is_noop)
        self.assertFalse(session.apply(edit))
        self.assertEqual(list((self.root / "src").glob("mod.py.*.bak")), [])

    def test_model_output_is_never_executed(self):
        # A reply that WOULD be destructive if executed as code/commands.
        reply = "```\nimport os\nos.system('touch /tmp/pwned_by_agent')\n```\n"
        session = self._session(reply, lambda _n: True)
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "inject")
        session.apply(edit)
        # The content is written verbatim as a file, never executed.
        self.assertIn("os.system", self.target.read_text())
        self.assertFalse(self.spy.executed)
        self.assertFalse(Path("/tmp/pwned_by_agent").exists())

    def test_only_selected_file_enters_prompt(self):
        # A second, unrelated file must not leak into the prompt.
        (self.root / "src" / "other.py").write_text("SECRET = 42\n", encoding="utf-8")
        captured = {}

        def capture(model, prompt):
            captured["prompt"] = prompt
            return "```\nvalue = 2\n```\n"

        session = pa.EditSession(self.root, "llama3", capture,
                                 approver=lambda _n: True, display=lambda _m: None)
        loaded = session.read_file("src/mod.py")
        session.propose(loaded, "change")
        self.assertIn("value = 1", captured["prompt"])
        self.assertNotIn("SECRET = 42", captured["prompt"])


class HardLinkAndSizeTests(_TmpProject):
    def test_rejects_hard_link(self):
        src = self.root / "src" / "linked.py"
        src.write_text("a = 1\n", encoding="utf-8")
        hard = self.root / "src" / "hardcopy.py"
        try:
            os.link(src, hard)
        except OSError:
            self.skipTest("hard links unsupported on this platform")
        with self.assertRaises(pa.SecurityError):
            pa.assert_safe_path(self.root, "src/hardcopy.py")

    def test_rejects_oversized_file(self):
        big = self.root / "src" / "big.py"
        big.write_text("x\n", encoding="utf-8")
        original_limit = pa.MAX_FILE_BYTES
        pa.MAX_FILE_BYTES = 1  # 1-byte limit for the test
        try:
            with self.assertRaises(pa.SecurityError):
                pa.assert_safe_path(self.root, "src/big.py")
        finally:
            pa.MAX_FILE_BYTES = original_limit


class MalformedAndDuplicateTests(_TmpProject):
    def _session(self, reply, approver=lambda _n: True):
        return pa.EditSession(
            self.root, "llama3", lambda _m, _p: reply,
            approver=approver, display=lambda _m: None,
        )

    def test_malformed_empty_proposal_is_ignored(self):
        # Model returns an empty fenced block; the file must not be wiped.
        session = self._session("```\n\n```\n")
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "do something")
        self.assertTrue(edit.is_malformed)
        self.assertFalse(session.apply(edit))
        self.assertEqual(self.target.read_text(), "value = 1\n")
        self.assertEqual(list((self.root / "src").glob("mod.py.*.bak")), [])

    def test_malformed_whitespace_proposal_is_ignored(self):
        session = self._session("   \n   \n")
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "do something")
        self.assertFalse(session.apply(edit))
        self.assertEqual(self.target.read_text(), "value = 1\n")

    def test_duplicate_apply_is_rejected_as_stale(self):
        # Applying the same edit twice: the second apply must be refused because
        # the file changed (we just wrote it) relative to the captured read.
        session = self._session("```\nvalue = 7\n```\n")
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "change")
        self.assertTrue(session.apply(edit))
        self.assertEqual(self.target.read_text(), "value = 7\n")
        with self.assertRaises(pa.SecurityError):
            session.apply(edit)


class FullWorkflowTests(_TmpProject):
    """Exercise request -> proposal -> diff -> approval with a fake local model."""

    def test_full_workflow_approved(self):
        prompts = []
        diffs = []
        approvals = []

        def fake_model(model, prompt):
            # A fake LOCAL model. No network, no download, deterministic reply.
            self.assertEqual(model, "llama3:8b")
            prompts.append(prompt)
            return "```python\nvalue = 42  # updated\n```\n"

        def approver(name):
            approvals.append(name)
            return True

        session = pa.EditSession(
            self.root, "llama3:8b", fake_model,
            approver=approver, display=diffs.append,
        )

        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "set value to 42")
        # Proposal carries the diff; approval happens only after it is shown.
        wrote = session.apply(edit)

        self.assertTrue(wrote)
        # The prompt contained the selected file and the instruction only.
        self.assertIn("value = 1", prompts[0])
        self.assertIn("set value to 42", prompts[0])
        # A unified diff was displayed before approval.
        self.assertTrue(any("value = 42" in d and "---" in d for d in diffs))
        # Approval was requested for exactly this file.
        self.assertEqual(approvals, ["mod.py"])
        # Final state: file updated, original backed up.
        self.assertEqual(self.target.read_text(), "value = 42  # updated\n")
        backups = list((self.root / "src").glob("mod.py.*.bak"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "value = 1\n")

    def test_full_workflow_rejected(self):
        session = pa.EditSession(
            self.root, "llama3:8b", lambda _m, _p: "```\nvalue = 42\n```\n",
            approver=lambda _n: False, display=lambda _m: None,
        )
        loaded = session.read_file("src/mod.py")
        edit = session.propose(loaded, "set value to 42")
        self.assertFalse(session.apply(edit))
        self.assertEqual(self.target.read_text(), "value = 1\n")


class CodeExtractionTests(unittest.TestCase):
    def test_extracts_fenced_block(self):
        self.assertEqual(pa.extract_code("```python\nx = 1\n```\n"), "x = 1\n")

    def test_falls_back_to_whole_response(self):
        self.assertEqual(pa.extract_code("x = 1\n"), "x = 1\n")


class SelfTestTests(unittest.TestCase):
    def test_self_test_passes_offline(self):
        self.assertTrue(pa.run_self_test(display=lambda _m: None))


class OllamaManagerTests(unittest.TestCase):
    def test_binds_loopback_only(self):
        mgr = pa.OllamaManager(port=12345)
        self.assertTrue(mgr.host.startswith("127.0.0.1"))
        self.assertTrue(mgr.base_url.startswith("http://127.0.0.1"))

    def test_start_sets_no_cloud_env(self):
        # Mock Popen so no real process is launched; assert the env is hardened.
        import unittest.mock as mock

        mgr = pa.OllamaManager(port=12346)
        with mock.patch.object(pa.subprocess, "Popen") as popen, \
                mock.patch.object(mgr, "is_up", return_value=True):
            mgr.start(wait_seconds=1)
            _, kwargs = popen.call_args
            env = kwargs["env"]
            self.assertEqual(env["OLLAMA_NO_CLOUD"], "1")
            self.assertEqual(env["OLLAMA_HOST"], "127.0.0.1:12346")
        # popen args use the local `ollama serve` command.
        args, _ = popen.call_args
        self.assertEqual(args[0], ["ollama", "serve"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
