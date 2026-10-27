"""Real POSIX configuration and private-state isolation, without live effects.

The child processes validate actual ownership, modes, source hashes and Python
identity. Only OCI/host calls are replaced with authored receipt wire data;
plan, root, create-only collection and journal checks remain production code.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'converter', ROOT / 'fox'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))


def hosted_configuration(base):
    """Fresh synthetic installation; no copied secret or mutable root alias."""
    from forms2apex import target_profile
    from qa.operator import runtime_provider as provider
    base.mkdir(mode=0o700)
    state, secret_dir, converter = (base / name for name in ('state', 'secret', 'converter'))
    for directory in (state, secret_dir, converter):
        directory.mkdir(mode=0o700)
    for name in ('clean-install', 'project-clean-install', 'product-verifier', 'handoffs'):
        (state / name).mkdir(mode=0o700)
    (converter / 'forms2apex').mkdir(mode=0o700)
    names = ('forms2apex/__init__.py', 'forms2apex/config.py',
             'forms2apex/target_profile.py', 'forms2apex/oci_identity.py')
    for name in names:
        shutil.copyfile(ROOT / 'converter' / name, converter / name)
        (converter / name).chmod(0o600)
    profile = deepcopy(target_profile._JSN_PROFILE)
    executable = Path(sys.executable).resolve()
    digest = lambda raw: hashlib.sha256(raw).hexdigest()
    config = {'schema_version': 1, 'scope': 'fox-hosted-operator-runtime-v1',
        'owner_uid': os.geteuid(), 'provider_sha256': digest(Path(provider.__file__).read_bytes()),
        'target_profile': profile, 'target_profile_sha256': target_profile.target_profile_sha256(profile),
        'python': {'path': str(executable), 'sha256': digest(executable.read_bytes()),
                   'version': list(sys.version_info[:3])},
        'converter_root': str(converter),
        'converter_sources': {name: digest((converter / name).read_bytes()) for name in names},
        'state_root': str(state), 'admin_secret_file': str(secret_dir / 'unused-admin-secret'),
        'public_mount_roots': [str(base / 'public-fox-data')]}
    raw = (json.dumps(config, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False) + '\n').encode()
    return raw, digest(raw), state


def exercise(base):
    # Import every consumer before selection. Successful configuration below
    # proves these imports did not seal legacy mode or discover configuration.
    from qa.operator import runtime_provider as provider
    from qa.operator import clean_install as native, project_clean_install as project
    from qa.operator import product_verifier as verifier, project_operator as route
    from qa.operator import native_qa_dispatch as native_qa, project_qa_dispatch as project_qa
    from qa.operator import harvest_native_qa as harvest, harvest_project_qa
    from qa.operator import contracts as c
    from qa.operator.tests.test_remote import fixture as native_fixture
    from qa.operator.tests.test_project_clean_install import fixture as project_fixture
    from qa.operator.tests.test_runtime_provider import external_host_boundary

    raw, digest, state = hosted_configuration(base)
    config = json.loads(raw)
    for path in config['public_mount_roots']:
        Path(path).mkdir(mode=0o700)
    legacy = (native.PRIVATE, project.PRIVATE, verifier.JOURNAL_ROOT)
    assert provider.configure_hosted(raw, expected_sha256=digest) == digest
    assert native.private_root() == state / 'clean-install'
    assert project.private_root() == state / 'project-clean-install'
    assert native.handoff_root() == project.handoff_root() == state / 'handoffs'
    assert (native.PRIVATE, project.PRIVATE, verifier.JOURNAL_ROOT) == legacy
    assert harvest_project_qa.new_private_output is harvest.new_private_output

    def plan(cli, fixture):
        value, _, _ = fixture()
        value['operator_code_sha256'] = cli.code_bundle()[1]
        content = c.canonical_bytes(value)
        directory = cli.private_root() / c.digest(content)
        cli.private_directory(directory)
        cli.save_new(directory / 'plan.json', content)
        assert cli.read_plan(directory / 'plan.json') == (content, value)
        return directory / 'plan.json', content, value

    native_path, native_raw, _ = plan(native, native_fixture)
    project_path, project_raw, _ = plan(project, project_fixture)
    assert verifier.GuardedPhases.plan({'plan_sha256': c.digest(native_raw)}) == native_path

    def wire(names, plan_sha, source_sha):
        files = {name: c.canonical_bytes({'synthetic_receipt': name}) for name in names}
        return {'status': 'COLLECTED', 'plan_sha256': plan_sha, 'source_sha256': source_sha,
            'credentials_and_logs_excluded': True,
            'files': {name: base64.b64encode(content).decode() for name, content in files.items()},
            'sha256': {name: c.digest(content) for name, content in files.items()}}

    native_source = native_qa.bundle()[3]
    native_wire = wire(harvest.ALLOWED, c.digest(native_raw), native_source)
    with patch.object(native, 'oci_scope', return_value={'fixture': 'read-only JSN scope'}), \
         patch.object(native, 'ssh_json', return_value=deepcopy(native_wire)) as external:
        value = verifier.GuardedPhases({'schema_version': 1, 'qa_source_sha256': native_source}).perform(
            'qa_collect', None, {'plan_sha256': c.digest(native_raw)})
    assert external.call_count == 1 and value['status'] == 'COLLECTED'
    native_collection = native_path.parent / ('qa-' + native_source[:16])
    assert set(path.name for path in native_collection.iterdir()) == harvest.ALLOWED | {'collection-manifest.json'}

    project_source = project_qa.bundle()[3]
    project_wire = wire(project_qa.ALLOWED, c.digest(project_raw), project_source)
    assert len(project_wire['files']) == 13
    with patch.object(project, 'oci_scope', return_value={'fixture': 'read-only JSN scope'}), \
         patch.object(project, 'ssh_json', return_value=deepcopy(project_wire)) as external:
        value = route.perform('qa_collect', None,
            {'conversion_profile': route.PROFILE, 'plan_sha256': c.digest(project_raw)},
            {'project': {'qa_source_sha256': project_source}}, None)
    assert external.call_count == 1 and value['status'] == 'COLLECTED'
    project_collection = project_path.parent / ('qa-' + project_source[:16])
    assert set(path.name for path in project_collection.iterdir()) == project_qa.ALLOWED | {'collection-manifest.json'}
    assert all((project_collection / name).read_bytes() == base64.b64decode(content)
               for name, content in project_wire['files'].items())
    with unittest.TestCase().assertRaises(project.OperatorError):
        project_qa.save_collection(project_wire, project_collection, c.digest(project_raw), project_source)
    with unittest.TestCase().assertRaises(project.OperatorError):
        project_qa.save_evidence(project_collection / 'runtime-credentials.json', b'excluded')

    # A genuine owner-private sibling journal must work without widening the
    # native plan root. A retained unresolved session must still block replay.
    journal = verifier.PrivateJournal('f' * 64)
    assert journal.root == state / 'product-verifier' / ('f' * 16)
    # Exercise the real mount guard and host identity code. Only its external
    # IMDS/Podman boundary is synthetic, like the other calls in this harness.
    with external_host_boundary(provider, config) as (events, calls), journal.lock():
        session = journal.new({'max_jobs': 1})
        journal.intent(session, 'p0001-claim')
        with unittest.TestCase().assertRaisesRegex(verifier.ProductVerifierError, 'UNRESOLVED_SESSION'):
            journal.new({'max_jobs': 1})
    assert events == ['imds', 'podman'] and len(calls) == 2

    handoff = harvest.new_private_output(state / 'handoffs' / 'retained-project')
    project_qa.save_evidence(handoff / 'qa-result.json', b'{"synthetic":true}\n')
    assert (handoff / 'qa-result.json').read_bytes() == b'{"synthetic":true}\n'
    with unittest.TestCase().assertRaises(project.OperatorError):
        project_qa.save_evidence(handoff / 'qa-result.json', b'cannot overwrite')

    # No read or write may accidentally fall back to workspace state or another
    # installed root. The foreign files are otherwise valid owner-private plans.
    foreign = base / 'other-installation'
    foreign.mkdir(mode=0o700)
    for cli, content in ((native, native_raw), (project, project_raw)):
        directory = foreign / cli.private_root().name
        directory.mkdir(mode=0o700)
        directory = directory / c.digest(content)
        directory.mkdir(mode=0o700)
        path = directory / 'plan.json'
        path.write_bytes(content); path.chmod(0o600)
        with unittest.TestCase().assertRaises(cli.OperatorError):
            cli.read_plan(path)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('Legacy state must not be read')):
            with unittest.TestCase().assertRaises(cli.OperatorError):
                cli.read_plan(cli.PRIVATE / c.digest(content) / 'plan.json')
    for output in (foreign / 'retained-project', harvest.ROOT / 'work' / 'hosted-path-test'):
        with unittest.TestCase().assertRaises(native.OperatorError):
            harvest.new_private_output(output)
        with unittest.TestCase().assertRaises(project.OperatorError):
            project_qa.save_evidence(output / 'qa-result.json', b'outside')
    with unittest.TestCase().assertRaises(project.OperatorError):
        project_qa.private_collection(native_path.parent / ('qa-' + '0' * 16))
    with unittest.TestCase().assertRaises(native.OperatorError):
        native.private_directory(project.private_root() / ('0' * 64))
    with unittest.TestCase().assertRaises(native.OperatorError):
        native.save_new(project_path.parent / 'native-must-not-write.json', b'outside native root')
    with unittest.TestCase().assertRaises(project.OperatorError):
        project.private_directory(native.private_root() / ('0' * 64))
    assert (native.PRIVATE, project.PRIVATE, verifier.JOURNAL_ROOT) == legacy
    return {'native': str(native.private_root()), 'project': str(project.private_root()),
            'journal': str(journal.journal_root), 'handoff': str(native.handoff_root()),
            'project_receipt_count': len(project_wire['files'])}


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0,
                     'Real hosted ownership checks require an unprivileged POSIX filesystem')
class HostedStateTests(unittest.TestCase):
    def test_two_installed_roots_are_isolated_in_fresh_processes(self):
        observations = []
        with tempfile.TemporaryDirectory(prefix='fox-state-paths-') as directory:
            base = Path(directory).resolve()
            for name in ('install-a', 'install-b'):
                result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()),
                                         '--exercise', str(base / name)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90,
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, cwd=str(ROOT))
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                value = json.loads(result.stdout)
                self.assertEqual(value['project_receipt_count'], 13)
                self.assertTrue(all(Path(value[key]).is_relative_to(base / name)
                                    for key in ('native', 'project', 'journal', 'handoff')))
                observations.append(value)
            for key in ('native', 'project', 'journal', 'handoff'):
                self.assertNotEqual(observations[0][key], observations[1][key])


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--exercise':
        print(json.dumps(exercise(Path(sys.argv[2])), sort_keys=True))
    else:
        unittest.main()
