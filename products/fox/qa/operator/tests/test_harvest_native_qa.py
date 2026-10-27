"""No network or filesystem writes: retained read-only harvest contract tests."""
import base64
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch
from qa.operator import harvest_native_qa as harvest
from qa.operator import contracts as C

ROOT = Path(__file__).resolve().parents[3]
SNAPSHOT = ROOT / 'work/beta/qa-v2-harvest-1eed6500'
SOURCE = '1eed6500f2838a3d0560ce32c4b75197436d7ea05edf510645d0a60a29413f1d'


class HarvestTests(unittest.TestCase):
    def fixture(self):
        raw = b'{"fixture":true}\n'
        files = {'qa-result.json': b'{"status":"FAILED"}', 'allocation-receipt.json': b'{}', 'launch-intent.json': b'{}'}
        result = {'status': 'COLLECTED', 'plan_sha256': C.digest(raw), 'source_sha256': SOURCE,
                  'credentials_and_logs_excluded': True, 'files': {name: base64.b64encode(value).decode() for name, value in files.items()},
                  'sha256': {name: C.digest(value) for name, value in files.items()}}
        return raw, files, result

    def test_refuses_wrong_reader_digest_before_any_remote_read(self):
        raw, _, _ = self.fixture()
        with patch.object(harvest.clean, 'read_plan', return_value=(raw, {})), patch.object(harvest.clean, 'ssh_json') as ssh:
            with self.assertRaises(harvest.clean.OperatorError):
                harvest.harvest('unused', SNAPSHOT / 'descriptor.json', SNAPSHOT / 'native_qa_remote.py', 'a' * 64, ROOT / 'work/qa-harvest-test')
        ssh.assert_not_called()

    def test_short_destination_must_be_new_direct_workspace_child(self):
        for name in ('x' * 41, '../escape'):
            with patch.object(Path, 'mkdir') as mkdir, self.assertRaises(harvest.clean.OperatorError):
                harvest.new_private_output(ROOT / 'work' / name)
            mkdir.assert_not_called()

    def test_exact_raw_bytes_survive_with_no_dispatch_or_original_collector(self):
        raw, files, result = self.fixture(); output = ROOT / 'work/qa-harvest-test'; written = {}
        original_read = Path.read_bytes
        def read(path): return written[str(path)] if str(path) in written else original_read(path)
        with patch.object(harvest.clean, 'read_plan', return_value=(raw, {})), patch.object(harvest.clean, 'oci_scope', return_value={}), \
             patch.object(harvest.clean, 'ssh_json', return_value=deepcopy(result)) as ssh, patch.object(harvest, 'new_private_output', return_value=output), \
             patch.object(harvest.clean, 'save_new', side_effect=lambda path, value: written.update({str(path): value})), patch.object(Path, 'read_bytes', read):
            actual = harvest.harvest('unused', SNAPSHOT / 'descriptor.json', SNAPSHOT / 'native_qa_remote.py', SOURCE, output)
        self.assertEqual(actual['remote_writes'], False)
        for name, value in files.items(): self.assertEqual(written[str(output / name)], value)
        program = ssh.call_args.args[0]
        self.assertIn("n['collect'](stage,p)", program)
        self.assertNotIn("n['execute']", program)
        self.assertNotIn('podman run', program)

    def test_rejects_credential_or_tampered_members_before_local_output(self):
        raw, _, result = self.fixture()
        for name in ('runtime-credentials.json', 'qa-result.json'):
            changed = deepcopy(result); changed['files'][name] = base64.b64encode(b'changed').decode()
            with patch.object(harvest.clean, 'read_plan', return_value=(raw, {})), patch.object(harvest.clean, 'oci_scope', return_value={}), \
                 patch.object(harvest.clean, 'ssh_json', return_value=changed), patch.object(harvest, 'new_private_output') as create:
                with self.assertRaises(harvest.clean.OperatorError):
                    harvest.harvest('unused', SNAPSHOT / 'descriptor.json', SNAPSHOT / 'native_qa_remote.py', SOURCE, ROOT / 'work/qa-harvest-test')
                create.assert_not_called()


if __name__ == '__main__': unittest.main()
