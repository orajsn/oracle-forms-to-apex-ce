"""Pure argument tests and actual POSIX private-wheelhouse validation."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("install_host_python", Path(__file__).resolve().parents[1] / "install_host_python.py")
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)


class PureChecks(unittest.TestCase):
    def test_no_apply_never_contacts_host(self):
        with patch.object(tool, "host_guard", side_effect=AssertionError("must not probe")):
            with self.assertRaisesRegex(tool.InstallError, "EXPLICIT_VENV_INSTALL_REQUIRED"):
                tool.install(Path("unused"), "a" * 64)

    def test_invalid_digest_cannot_select_path(self):
        with patch.object(tool, "host_guard", side_effect=AssertionError("must not probe")):
            for value in ("../escape", "/absolute", "", "g" * 64):
                with self.subTest(value=value), self.assertRaisesRegex(tool.InstallError, "EXACT_REVIEWED_WHEELHOUSE_REQUIRED"):
                    tool.install(Path("unused"), value, apply=True)

    def test_clean_environment_ignores_inherited_pip_and_proxy(self):
        with patch.dict(os.environ, {"PIP_INDEX_URL": "https://invalid", "HTTPS_PROXY": "https://invalid", "PYTHONPATH": "/untrusted"}):
            result = tool.environment(Path("/private/home"))
        self.assertNotIn("PIP_INDEX_URL", result); self.assertNotIn("HTTPS_PROXY", result); self.assertNotIn("PYTHONPATH", result)
        self.assertEqual(result["PIP_CONFIG_FILE"], "/dev/null")
        self.assertEqual(result["HOME"], str(Path("/private/home")))

    def test_probe_does_not_make_cloud_or_database_calls(self):
        self.assertIn("import oci,cryptography,defusedxml", tool.PROBE)
        self.assertIn("import aiohttp,crc32c,pkcs11", tool.PROBE)
        self.assertNotIn("InstancePrincipalsSecurityTokenSigner", tool.PROBE)
        self.assertNotIn("DatabaseClient", tool.PROBE)


@unittest.skipUnless(os.name == "posix", "requires actual POSIX permissions")
class PrivateInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fox-wheelhouse-input-")
        self.root = Path(self.temp.name)
        self.mask = os.umask(0o077)
        (self.root / "wheelhouse").mkdir(mode=0o700)
        rows = []
        for name, version in tool.ROOTS.items():
            filename = name + "-" + version + "-py3-none-any.whl"
            raw = b"synthetic reviewed bytes"
            tool.new(self.root / "wheelhouse" / filename, raw)
            rows.append({"filename": filename, "name": name, "version": version,
                         "bytes": len(raw), "sha256": tool.sha(raw), "record_integrity": "PASS"})
        lock = ("\n".join(f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}" for r in sorted(rows, key=lambda r: r["name"])) + "\n").encode()
        tool.new(self.root / "requirements.lock", lock)
        self.report = {"schema_version": 1, "scope": "fox-host-python-wheelhouse-v1", "status": "VERIFIED_DOWNLOAD",
            "roots": tool.ROOTS, "target_python": "3.11.13", "installed": False, "wheels": rows,
            "requirements_lock_sha256": tool.sha(lock)}
        self.raw = tool.canonical(self.report); self.digest = tool.sha(self.raw)
        tool.new(self.root / "evidence.json", self.raw)

    def tearDown(self):
        os.umask(self.mask); self.temp.cleanup()

    def test_exact_inputs_pass_without_install(self):
        value = tool.wheelhouse(self.root, self.digest)
        self.assertEqual(value["distributions"], tool.ROOTS)

    def test_changed_wheel_is_blocked(self):
        path = next((self.root / "wheelhouse").iterdir()); path.write_bytes(b"changed")
        with self.assertRaisesRegex(tool.InstallError, "WHEELHOUSE_BYTES_CHANGED"):
            tool.wheelhouse(self.root, self.digest)

    def test_extra_wheel_blocks(self):
        tool.new(self.root / "wheelhouse/extra.whl", b"extra")
        with self.assertRaisesRegex(tool.InstallError, "WHEELHOUSE_INVENTORY_CHANGED"):
            tool.wheelhouse(self.root, self.digest)

    def test_changed_lock_blocks(self):
        (self.root / "requirements.lock").write_bytes(b"oci\n")
        with self.assertRaisesRegex(tool.InstallError, "WHEELHOUSE_LOCK_CHANGED"):
            tool.wheelhouse(self.root, self.digest)

    def test_world_readable_input_blocks(self):
        (self.root / "evidence.json").chmod(0o644)
        with self.assertRaisesRegex(tool.InstallError, "PRIVATE_INSTALL_INPUT_REQUIRED"):
            tool.wheelhouse(self.root, self.digest)

    def test_symlink_input_blocks(self):
        original = self.root / "evidence.json"
        saved = self.root / "original.json"
        original.rename(saved); original.symlink_to(saved)
        with self.assertRaisesRegex(tool.InstallError, "LINKED_INSTALL_PATH_FORBIDDEN"):
            tool.wheelhouse(self.root, self.digest)

    def test_existing_attempt_is_preserved(self):
        with patch.object(tool, "PARENT", self.root / "installs"), patch.object(tool, "host_guard", return_value={"synthetic": True}):
            tool.PARENT.mkdir(mode=0o700); existing = tool.PARENT / self.digest; existing.mkdir(mode=0o700)
            tool.new(existing / "sentinel", b"retained partial attempt")
            with patch.object(tool, "phase", side_effect=AssertionError("must not start")):
                with self.assertRaisesRegex(tool.InstallError, "EXISTING_INSTALL_PRESERVED_NO_REPLAY"):
                    tool.install(self.root, self.digest, apply=True)
            self.assertEqual((existing / "sentinel").read_bytes(), b"retained partial attempt")


if __name__ == "__main__": unittest.main(verbosity=2)
