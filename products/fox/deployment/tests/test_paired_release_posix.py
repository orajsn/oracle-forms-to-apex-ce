"""Actual POSIX file/mode tests with only remote/container IO substituted."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


p, r = load("prepare_project_release"), load("build_project_release")


@unittest.skipUnless(os.name == "posix", "requires actual POSIX permissions")
class PosixStaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fox-paired-builder-")
        self.root = Path(self.temp.name)
        self.before_umask = os.umask(0o077)
        self.parent_patch = patch.object(r, "PARENT", self.root / "stages"); self.parent_patch.start()
        self.guard_patch = patch.object(r, "guarded_host", return_value={"synthetic": True}); self.guard_patch.start()
        self.output = self.root / "prepared"
        self.result = p.materialize(files={"qa/operator/hosted_service.py": b"# synthetic\n",
            "deployment/project-opaf-profile-v2.json": (HERE / "project-opaf-profile-v2.json").read_bytes(),
            "fox/fox/__init__.py": b"", "fox/fox/project_conversion.py": b"# synthetic\n"},
            ui={"index.html": b"<html>synthetic</html>"}, converter={
                "forms2apex/__init__.py": b"", "defusedxml/ElementTree.py": b"# synthetic\n",
                "defusedxml-0.7.1.dist-info/REQUESTED": b"",
                "fox_source_contract/source-manifest.json": b"{}\n"},
            output_root=self.output, build_evidence={"synthetic": True})

    def tearDown(self):
        self.guard_patch.stop(); self.parent_patch.stop(); os.umask(self.before_umask)
        # Only the exact fresh TemporaryDirectory owned by this test is removed.
        self.temp.cleanup()

    def stage(self):
        return r.stage((self.output / "paired-source.tar").read_bytes(), self.result["archive_sha256"])

    def test_real_stage_is_private_complete_and_readonly_inspect_accepts_empty_member(self):
        receipt = self.stage(); target = Path(receipt["target"])
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        for item in target.rglob("*"):
            expected = 0o700 if item.is_dir() else 0o644 if item.relative_to(target).as_posix() == r.PUBLIC_PROFILE else 0o600
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), expected)
        state = r.inspect(self.result["source_bundle_sha256"])
        self.assertEqual(state["status"], "STAGED_NOT_ACTIVATED")
        self.assertEqual(state["builds"], {role: {"intent": False, "complete": False} for role in ("fox", "converter")})
        with self.assertRaisesRegex(r.StageError, "STAGE_ALREADY_EXISTS_USE_INSPECT"):
            self.stage()

    def test_world_readable_file_rejected(self):
        receipt = self.stage(); target = Path(receipt["target"])
        (target / "bundle/fox/fox/__init__.py").chmod(0o644)
        with self.assertRaisesRegex(r.StageError, "PRIVATE_BUILD_PATH_REQUIRED"):
            r.inspect(self.result["source_bundle_sha256"])

    def test_public_profile_has_exact_mode_no_broader_permission(self):
        receipt = self.stage(); target = Path(receipt["target"])
        profile = target / r.PUBLIC_PROFILE
        self.assertEqual(stat.S_IMODE(profile.stat().st_mode), 0o644)
        for mode in (0o600, 0o640, 0o666):
            profile.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(r.StageError):
                r.inspect(self.result["source_bundle_sha256"])
        profile.chmod(0o644)
        self.assertEqual(r.inspect(self.result["source_bundle_sha256"])["status"], "STAGED_NOT_ACTIVATED")

    def test_extra_source_or_context_file_rejected(self):
        receipt = self.stage(); target = Path(receipt["target"])
        (target / "bundle/extra.py").write_bytes(b"# not in B\n")
        with self.assertRaisesRegex(r.StageError, "STAGED_MEMBERSHIP_CHANGED"):
            r.inspect(self.result["source_bundle_sha256"])

    def test_linked_source_rejected(self):
        receipt = self.stage(); target = Path(receipt["target"])
        (target / "bundle/linked.py").symlink_to(target / "bundle/fox/fox/__init__.py")
        with self.assertRaisesRegex(r.StageError, "STAGED_LINK_FORBIDDEN"):
            r.inspect(self.result["source_bundle_sha256"])

    def test_build_creates_intent_exit_and_never_activates_or_replays(self):
        receipt = self.stage(); target = Path(receipt["target"])
        new_image = "sha256:" + "a" * 64
        commands = []
        def observed(argv, **kwargs):
            commands.append(argv)
            image = argv[-1]
            return r.canonical([{"Id": image, "Os": "linux", "Architecture": "amd64",
                "Labels": {"com.oracle.jsn.fox.source-bundle": self.result["source_bundle_sha256"]}}])
        class Process:
            pid = 12345
            def __init__(self, argv, **kwargs):
                commands.append(argv)
                Path(argv[argv.index("--iidfile") + 1]).write_text(new_image + "\n")
            def wait(self, timeout): return 0
        with patch.object(r, "command", side_effect=observed), patch.object(r.subprocess, "Popen", Process):
            result = r.build(self.result["source_bundle_sha256"], "fox", apply=True)
        self.assertEqual(result["image"], new_image)
        self.assertTrue((target / "fox-build-complete.json").is_file())
        build = next(argv for argv in commands if argv[1] == "build")
        self.assertIn("--pull=never", build); self.assertIn("--network=none", build)
        self.assertFalse(any(item in argv for argv in commands for item in ("run", "start", "stop", "rm", "rename")))
        with self.assertRaisesRegex(r.StageError, "EXISTING_BUILD_MUST_NOT_BE_REPLAYED"):
            r.build(self.result["source_bundle_sha256"], "fox", apply=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
