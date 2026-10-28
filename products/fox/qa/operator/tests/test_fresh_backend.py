"""Real local F tests; no runtime, admission or Oracle evidence.

Positive cases require an actual nonroot POSIX host and Python -I -B. Each
case uses real initializers from a copied source closure. Future unexecuted
runtime modules have explicit inert synthetic placeholders. Only named failure
boundaries are injected; no passing validator is replaced with a mock.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0
QA_SOURCES = ('package.json', 'package-lock.json', 'run-native.mjs', 'prepare-target.mjs',
    'run-jsn-qa.sh', 'run-project.mjs', 'lib/contracts.mjs', 'lib/package-evidence.mjs',
    'lib/assert-jsn-vm.sh', 'lib/project-profile.mjs', 'lib/project-runner-inputs.mjs',
    'lib/project-runtime.mjs', 'lib/project-browser.mjs')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode()


def snapshot(root):
    result = {}
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        result[path.relative_to(root).as_posix()] = (
            info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            os.readlink(path) if path.is_symlink() else
            digest(path.read_bytes()) if path.is_file() else None)
    return result


def base_rows(path):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
        schema = db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name').fetchall()
        names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        rows = {name: db.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall() for name in names}
        return schema, rows


def copy_source_closure(source, destination):
    """Copy sources only: no working data, profiles, credentials or history."""
    destination.mkdir(mode=0o700)
    for relative in ('fox/fox', 'converter/forms2apex', 'converter/fox_source_contract', 'qa/operator'):
        for path in (source / relative).glob('*.py'):
            target = destination / path.relative_to(source)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes()); target.chmod(0o600)
    for name in QA_SOURCES:
        path, target = source / 'qa' / name, destination / 'qa' / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes()); target.chmod(0o600)
    for name in ('fresh_connected.py', 'fresh_remote.py'):
        path = destination / 'qa/operator' / name
        if not path.exists():
            path.write_bytes(b'"""SYNTHETIC unexecuted future runtime placeholder; not installation proof."""\n')
            path.chmod(0o600)
    candidates = (source / 'dependencies/defusedxml', source / 'fox/.venv/Lib/site-packages/defusedxml')
    dependency = next((path for path in candidates if path.is_dir()), None)
    if dependency is None:
        # Public source must not need a private development venv or a copied
        # vendor tree. Use only the already-approved isolated test dependency;
        # this never downloads or installs anything.
        from importlib.metadata import distribution, PackageNotFoundError
        try:
            installed = distribution('defusedxml')
            selected = Path(installed.locate_file('defusedxml')).resolve(strict=True)
            if installed.version == '0.7.1' and selected.is_dir():dependency = selected
        except (PackageNotFoundError, OSError):pass
    if dependency is None:
        raise RuntimeError('EXACT_LOCAL_DEFUSEDXML_SOURCES_REQUIRED')
    target = destination / 'dependencies/defusedxml'
    target.mkdir(mode=0o700, parents=True)
    for path in dependency.glob('*.py'):
        copied = target / path.name
        copied.write_bytes(path.read_bytes()); copied.chmod(0o600)


def import_bundle(root):
    sys.path[:0] = [str(root), str(root / 'fox'), str(root / 'converter'), str(root / 'dependencies')]
    from qa.operator import fresh_backend as backend
    from qa.operator import fresh_storage as storage
    from qa.operator import fresh_contracts as contracts
    from fox import backend_storage, verification_queue
    from forms2apex.target_profile import _PROFILE_JSN_PROJECT_20261025, target_profile_sha256
    return backend, storage, contracts, backend_storage, verification_queue, _PROFILE_JSN_PROJECT_20261025, target_profile_sha256


class Fixture:
    def __init__(self, parent, source):
        self.parent, self.source = parent, source
        (self.backend, self.storage, self.contracts, self.schema, self.queue,
         registered_target, target_digest) = import_bundle(source)
        self.values, self.refs, self.artifacts = {}, {}, {}
        self.private, self.public, self.profiles = (parent / name for name in ('private', 'public', 'profiles'))
        for path in (self.private, self.public, self.profiles):
            path.mkdir(mode=0o700)
        self.plan = self.storage.declaration(**{name: str(parent / name) for name in self.storage.ROLES}, owner_uid=os.geteuid())
        result = self.storage.initialize_storage(self.plan,
            expected_plan_sha256=self.storage.plan_sha256(self.plan), apply=True)
        self.identity = result['installation_id']
        self.roots = {name: Path(value) for name, value in self.plan['roots'].items()}
        self.database = self.roots['fox_data'] / 'fox.sqlite3'
        self.attempt = self.roots['operator_state'] / 'fresh-backend'
        self.output = self.public / 'backend-initialization.json'
        self.put('plan', self.private / 'storage-plan.json', self.plan)
        completion = self.roots['records'] / 'complete.json'
        self.refs['completion'] = {'path': str(completion), 'sha256': digest(completion.read_bytes())}
        self.artifacts[str(completion)] = completion.read_bytes()
        self.values['completion'] = json.loads(completion.read_bytes())
        self.put('projection', self.public / 'projection.json', {
            'schema_version': 1, 'scope': 'fox-fresh-app-projection-v1', 'installation_mode': 'fresh',
            'installation_id': self.identity, 'storage_plan_sha256': self.refs['plan']['sha256'],
            'storage_completion_sha256': self.refs['completion']['sha256'], 'converter_endpoint': 'http://127.0.0.1:8291'})
        target = deepcopy(registered_target)
        self.put('target', self.profiles / 'target.json', target)
        opaf = target['opaf']
        self.put('opaf', self.profiles / 'native.json', {
            'schema_version': 2, 'profile_id': 'native-project-v1', **self.contracts.PROJECT_MAPPING,
            'opaf_base_url': opaf['base_url'], 'certificate_sha256': opaf['certificate_sha256'], **opaf['roles']})
        inventory = {path.relative_to(source).as_posix(): digest(path.read_bytes())
                     for path in sorted(source.rglob('*')) if path.is_file()}
        self.put('inventory', self.private / 'inventory.json', {
            'schema_version': 1, 'scope': 'fox-hosted-source-inventory-v1', 'files': inventory})
        self.layout = {'release_root': str(source), 'inventory': self.refs['inventory']}
        def mount(path, destination, readonly=True):
            return {'source': str(path), 'destination': destination, 'read_only': readonly}
        fox_mounts = [mount(self.roots['fox_data'], '/data', False), mount(self.public, '/run/fox-installation'),
            mount(self.refs['opaf']['path'], '/run/fox-native/profile.json'), mount(parent / 'secrets/opaf', '/run/fox-opaf')]
        converter_mounts = [mount(self.roots['converter_jobs'], '/opt/forms2apex/outputs/jobs', False),
            mount(self.public, '/run/fox-installation'), mount(self.refs['target']['path'], '/run/fox-target/profile.json'),
            mount(parent / 'tools/sqlcl', '/opt/sqlcl'), mount(parent / 'secrets/wallet', '/opt/forms2apex/wallet'),
            mount(parent / 'secrets/connections', '/home/converter/.dbtools', False)]
        images = {name: 'sha256:' + digest(('synthetic image ' + name).encode()) for name in ('fox', 'converter')}
        from qa.operator import clean_install, native_qa_dispatch, project_clean_install, project_qa_dispatch
        native_sources = {
            'clean_operator_code_sha256': clean_install.code_bundle()[1],
            'qa_source_sha256': native_qa_dispatch.bundle(images=images)[3],
            'promotion_transport_sha256': inventory['qa/operator/promote_native.py'],
        }
        project_sources = {
            'clean_operator_code_sha256': project_clean_install.code_bundle()[1],
            'qa_source_sha256': project_qa_dispatch.bundle(images=images)[3],
            'promotion_transport_sha256': inventory['qa/operator/promote_project.py'],
            'operator_code_sha256': inventory['qa/operator/project_operator.py'],
        }
        roles = {
            'fox': {'name': 'fox-fresh-test', 'image': images['fox'], 'user': str(os.geteuid()),
                    'read_only_rootfs': True, 'mounts': fox_mounts},
            'converter': {'name': 'forms2apex-fresh-test', 'image': images['converter'], 'user': '10001',
                          'read_only_rootfs': False, 'mounts': converter_mounts},
            'opaf': {'name': 'opaf-test', 'image': 'sha256:' + 'e' * 64, 'user': '0:0',
                     'read_only_rootfs': False, 'mounts': [mount(parent / 'opaf-volume', '/mount', False)]}}
        executable = Path(sys.executable).resolve()
        self.put('provider', self.private / 'provider.json', {
            'schema_version': 3, 'scope': self.contracts.SCOPES['provider'], 'installation_mode': 'fresh',
            'owner_uid': os.geteuid(), 'provider_sha256': inventory['qa/operator/runtime_provider.py'],
            'target_profile': target, 'target_profile_sha256': target_digest(target),
            'python': {'path': str(executable), 'sha256': digest(executable.read_bytes()), 'version': list(sys.version_info[:3])},
            'converter_root': str(source / 'converter'),
            'converter_sources': {name: inventory['converter/' + name] for name in self.contracts.IDENTITY_SOURCES},
            'state_root': str(self.roots['operator_state']), 'admin_secret_file': str(parent / 'secrets/admin'),
            'public_mount_roots': sorted({item['source'] for item in fox_mounts}), 'images': images,
            'storage': {'installation_id': self.identity, 'plan': self.refs['plan'], 'completion': self.refs['completion']},
            'app_projection': self.refs['projection'],
            'runtime': {'roles': roles, 'converter_endpoint': 'http://127.0.0.1:8291',
                'qa': {'root': str(self.roots['operator_state'] / 'qa'), 'base_image': 'sha256:' + 'f' * 64},
                'public_configuration': {'directory': str(self.public), **self.contracts.PUBLIC_FILENAMES},
                'settings': {'conversion_profile': 'native-project-v1', 'data_mode': 'synthetic_test_only',
                             'fox_origin': 'http://127.0.0.1:8110'},
                'opaf_profile': self.refs['opaf'], 'target_profile': self.refs['target']}})
        self.put('release', self.private / 'release.json', {
            'schema_version': 4, 'scope': self.contracts.SCOPES['release'], 'installation_mode': 'fresh', 'enabled': True,
            'images': images, 'modules': {name: inventory['fox/fox/' + name] for name in self.contracts.MODULES},
            'code': {name: inventory['qa/operator/' + name] for name in self.contracts.CODE},
            **native_sources, 'native_profile_sha256': self.refs['opaf']['sha256'],
            'target': {**target['oci'], 'db_name': target['database']['db_name']},
            'project': {**project_sources,
                'modules': {name: inventory['fox/fox/' + name] for name in self.contracts.PROJECT_MODULES},
                'queue_modules': {name: inventory['fox/fox/' + name] for name in self.contracts.QUEUE_MODULES}},
            'hosted_runtime_configuration_sha256': self.refs['provider']['sha256'],
            'opaf_profile': {**self.refs['opaf'], 'target_profile_sha256': target_digest(target)}})
        self.contracts.validate_release(self.refs['release'], self.artifacts,
            provider_reference=self.refs['provider'], layout=self.layout)

    def put(self, label, path, value):
        raw = canonical(value)
        path.write_bytes(raw); path.chmod(0o600)
        self.values[label] = deepcopy(value); self.artifacts[str(path)] = raw
        self.refs[label] = {'path': str(path), 'sha256': digest(raw)}

    def call(self):
        return self.backend.initialize_backend(self.refs['provider'], self.refs['release'], layout=self.layout, apply=True)

    def reject(self):
        try:
            self.call()
        except self.backend.FreshBackendError as error:
            assert str(error) and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for c in str(error)), str(error)
            return str(error)
        raise AssertionError('INITIALIZATION_SHOULD_HAVE_FAILED')


def no_external_actions():
    def blocked(*args, **kwargs):
        raise AssertionError('EXTERNAL_ACTION_FORBIDDEN')
    from contextlib import ExitStack
    stack = ExitStack()
    for target, name in ((socket, 'create_connection'), (socket.socket, 'connect'),
                         (subprocess, 'run'), (subprocess, 'Popen'), (threading.Thread, 'start')):
        stack.enter_context(patch.object(target, name, side_effect=blocked))
    return stack


def scenario(name, original):
    with tempfile.TemporaryDirectory(prefix='fbt-') as temporary:
        parent = Path(temporary); parent.chmod(0o700)
        source = parent / 'release'
        copy_source_closure(original, source)
        fixture = Fixture(parent, source)
        baseline_records = snapshot(fixture.roots['records'])
        original_database = base_rows(fixture.database)
        if name in {'positive', 'lease_held_during_initialization'}:
            original_queue = fixture.queue.initialize_schema
            lock_checks = []
            def observe_queue(connection):
                if name == 'lease_held_during_initialization':
                    observation = fixture.storage.inspect_storage(fixture.plan,
                        expected_plan_sha256=fixture.refs['plan']['sha256'])
                    assert observation['code'] == 'STORAGE_OPERATION_LOCKED'
                    lock_checks.append(observation)
                return original_queue(connection)
            with patch.object(fixture.queue, 'initialize_schema', side_effect=observe_queue), no_external_actions():
                result = fixture.call()
            assert name != 'lease_held_during_initialization' or lock_checks
            assert result['status'] == 'FRESH_BACKEND_INITIALIZED_NOT_ADMITTED'
            assert result['installation_id'] == fixture.identity
            assert all(result[key] is False for key in ('connected_admission', 'services_started', 'oracle_accessed', 'automatic_replay_permitted'))
            reference = result['backend_initialization']
            assert reference == {'path': str(fixture.output), 'sha256': digest(fixture.output.read_bytes())}
            artifacts = {**fixture.artifacts, str(fixture.output): fixture.output.read_bytes()}
            value = fixture.contracts.validate_backend_initialization(reference, artifacts,
                provider_reference=fixture.refs['provider'], release_reference=fixture.refs['release'], layout=fixture.layout)
            assert value['initial_counts'] == fixture.schema.expected_backend_counts()
            assert fixture.database.read_bytes()[18:20] == b'\x01\x01'
            assert not any(Path(str(fixture.database) + suffix).exists() for suffix in ('-wal', '-shm', '-journal'))
            with closing(sqlite3.connect(fixture.database.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
                observed = fixture.schema.validate_backend_storage(db, installation_id=fixture.identity,
                    plan_sha256=fixture.refs['plan']['sha256'], require_empty=True)
                assert observed['backend_schema_sha256'] == value['backend_schema_sha256']
                assert db.execute('PRAGMA journal_mode').fetchone() == ('delete',)
                assert db.execute('PRAGMA foreign_key_check').fetchall() == []
                assert db.execute('SELECT * FROM events ORDER BY id').fetchall() == original_database[1]['events']
            assert set(path.name for path in fixture.public.iterdir()) == {'projection.json', 'backend-initialization.json'}
            assert snapshot(fixture.roots['records']) == baseline_records
            after = snapshot(parent)
            with no_external_actions():
                fixture.reject()
            assert snapshot(parent) == after, 'Completed attempt was rewritten on replay'
            return {'name': name, 'status': 'PASSED', 'schema_sha256': value['backend_schema_sha256']}
        if name in {'nonempty', 'extra_table', 'wrong_identity'}:
            with closing(sqlite3.connect(fixture.database)) as db, db:
                if name == 'nonempty':
                    db.execute("INSERT INTO projects VALUES('synthetic','owner','customer','name','',1)")
                elif name == 'extra_table':
                    db.execute('CREATE TABLE unexpected_empty_table(value TEXT)')
                else:
                    db.execute('UPDATE fox_storage_identity SET installation_id=?', ('fst-' + 'f' * 32,))
        elif name == 'partial_attempt':
            fixture.attempt.mkdir(mode=0o700)
            (fixture.attempt / 'intent.json').write_bytes(b'partial'); (fixture.attempt / 'intent.json').chmod(0o600)
        elif name == 'existing_f':
            fixture.output.write_bytes(b'partial'); fixture.output.chmod(0o600)
        elif name == 'source_drift':
            with (source / 'fox/fox/verification_queue.py').open('ab') as stream:
                stream.write(b'\n# synthetic source drift\n')
        elif name == 'missing_source':
            (source / 'fox/fox/native_source.py').unlink()
        elif name == 'unlisted_source':
            (source / 'unreviewed.py').write_bytes(b'pass\n')
        elif name == 'cached_bytecode':
            cache = source / 'fox/fox/__pycache__'; cache.mkdir(mode=0o700)
            (cache / 'storage.cpython-314.pyc').write_bytes(b'not an allowed cache')
        elif name == 'module_origin':
            fixture.queue.__file__ = str(parent / 'unreviewed.py')
        elif name == 'python_pin':
            fixture.values['provider']['python']['sha256'] = '0' * 64
            fixture.put('provider', Path(fixture.refs['provider']['path']), fixture.values['provider'])
            fixture.values['release']['hosted_runtime_configuration_sha256'] = fixture.refs['provider']['sha256']
            fixture.put('release', Path(fixture.refs['release']['path']), fixture.values['release'])
        elif name == 'projection_drift':
            path = fixture.public / 'projection.json'; path.write_bytes(path.read_bytes() + b' ')
        elif name.startswith('aggregate_'):
            field = name.removeprefix('aggregate_')
            if field.startswith('project_'):
                fixture.values['release']['project'][field.removeprefix('project_')] = '0' * 64
            else:
                fixture.values['release'][field] = '0' * 64
            fixture.put('release', Path(fixture.refs['release']['path']), fixture.values['release'])
        elif name == 'database_symlink':
            retained = fixture.roots['fox_data'] / 'retained.sqlite3'
            fixture.database.rename(retained); fixture.database.symlink_to(retained)
        elif name == 'database_hardlink':
            os.link(fixture.database, parent / 'database-alias')
        elif name == 'database_mode':
            fixture.database.chmod(0o644)
        elif name == 'public_extra':
            (fixture.public / 'unexpected.json').write_bytes(b'{}\n')
        elif name == 'wal_sidecar':
            Path(str(fixture.database) + '-wal').write_bytes(b'unreconciled synthetic WAL')
        elif name == 'lock_contention':
            program = "import fcntl,sys; f=open(sys.argv[1],'rb'); fcntl.flock(f.fileno(),fcntl.LOCK_EX); print('LOCKED',flush=True); sys.stdin.buffer.read(1)"
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program,
                                      str(fixture.roots['records'] / 'operation.lock')],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                assert child.stdout.readline() == b'LOCKED\n'
                before = snapshot(parent)
                with no_external_actions():
                    error = fixture.reject()
                assert snapshot(parent) == before
            finally:
                child.communicate(b'x', timeout=5)
            assert child.returncode == 0
            return {'name': name, 'status': 'PASSED', 'diagnostic': error}
        elif name in {'sql_failure', 'intent_failure', 'observed_failure', 'observed_drift', 'observed_missing',
                      'checkpoint_failure', 'delete_mode_failure', 'publish_failure',
                      'published_uncertainty', 'source_drift_during_sql'}:
            original_queue = fixture.queue.initialize_schema
            original_write = fixture.storage._write
            original_connect = sqlite3.connect
            class FaultConnection(sqlite3.Connection):
                def execute(self, sql, *args, **kwargs):
                    result = super().execute(sql, *args, **kwargs)
                    if ((name == 'checkpoint_failure' and sql == 'PRAGMA wal_checkpoint(TRUNCATE)')
                            or (name == 'delete_mode_failure' and sql == 'PRAGMA journal_mode=DELETE')):
                        raise OSError('synthetic finalization acknowledgement uncertainty')
                    return result
            def connect_action(*args, **kwargs):
                if args and args[0] == fixture.database.as_uri() + '?mode=rw':
                    kwargs['factory'] = FaultConnection
                return original_connect(*args, **kwargs)
            def queue_action(connection):
                original_queue(connection)
                if name == 'sql_failure':
                    raise OSError('synthetic private failure detail must not escape')
                if name == 'source_drift_during_sql':
                    with (source / 'fox/fox/verification_queue.py').open('ab') as stream:
                        stream.write(b'\n# synthetic late source drift\n')
            def write_action(path, raw):
                path = Path(path)
                if name == 'intent_failure' and path == fixture.attempt / 'intent.json':
                    raise OSError('synthetic failure before intent publication')
                if path == fixture.attempt / 'observed.json':
                    if name == 'observed_failure':
                        raise OSError('synthetic failure before observation publication')
                    if name == 'observed_drift':
                        return original_write(path, b'{}\n')
                    if name == 'observed_missing':
                        return None
                if path == fixture.output and name in {'publish_failure', 'published_uncertainty'}:
                    if name == 'published_uncertainty':
                        original_write(path, raw)
                    raise OSError('synthetic failure around F durable publication')
                return original_write(path, raw)
            with patch.object(fixture.queue, 'initialize_schema', side_effect=queue_action), \
                 patch.object(fixture.storage, '_write', side_effect=write_action), \
                 patch.object(sqlite3, 'connect', side_effect=connect_action), no_external_actions():
                error = fixture.reject()
            assert fixture.attempt.is_dir()
            assert (fixture.attempt / 'failure.json').is_file()
            assert fixture.output.exists() == (name == 'published_uncertainty')
            if name in {'sql_failure', 'intent_failure'}:
                assert base_rows(fixture.database) == original_database
            assert snapshot(fixture.roots['records']) == baseline_records
            after = snapshot(parent)
            with no_external_actions():
                fixture.reject()
            assert snapshot(parent) == after, 'Partial attempt was retried'
            return {'name': name, 'status': 'PASSED', 'diagnostic': error}
        else:
            raise AssertionError('UNKNOWN_TEST_SCENARIO')
        before = snapshot(parent)
        with no_external_actions():
            error = fixture.reject()
        assert snapshot(parent) == before, 'Preflight rejection changed filesystem state'
        assert not fixture.attempt.exists() or name == 'partial_attempt'
        return {'name': name, 'status': 'PASSED', 'diagnostic': error}


class FreshBackendPortableTests(unittest.TestCase):
    def run_program(self, program):
        with tempfile.TemporaryDirectory(prefix='fbt-import-') as temporary:
            source = Path(temporary) / 'release'
            copy_source_closure(ROOT, source)
            env = {key: value for key, value in os.environ.items() if not key.startswith(('FOX_', 'F2A_'))}
            env['FOX_DATA_DIR'] = str(Path(temporary) / 'must-not-exist')
            return subprocess.run([sys.executable, '-I', '-B', '-c', program, str(source)],
                cwd=temporary, env=env, capture_output=True, text=True, timeout=30)

    def test_import_is_inert(self):
        program = r'''
import importlib,os,pathlib,socket,sqlite3,subprocess,sys,threading
root=pathlib.Path(sys.argv[1]);sys.path[:0]=[str(root),str(root/'fox'),str(root/'converter'),str(root/'dependencies')]
def deny(*a,**k):raise AssertionError('IMPORT_SIDE_EFFECT_FORBIDDEN')
def audit(event,args):
 if event=='open' and ((isinstance(args[1],str) and any(c in args[1] for c in 'wax+')) or (isinstance(args[2],int) and args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))):deny()
 if event in {'os.mkdir','os.remove','os.rename','os.rmdir','os.system','subprocess.Popen','sqlite3.connect','socket.connect'}:deny()
sys.addaudithook(audit)
sqlite3.connect=deny;subprocess.Popen=deny;socket.socket.connect=deny;socket.create_connection=deny;threading.Thread.start=deny
import qa.operator.fresh_backend
assert 'fox.app' not in sys.modules and 'fox.worker' not in sys.modules
assert not pathlib.Path(os.environ['FOX_DATA_DIR']).exists()
print('IMPORT_INERT')
'''
        result = self.run_program(program)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'IMPORT_INERT')

    def test_explicit_apply_is_not_truthy_or_implied(self):
        program = r'''
import pathlib,sys
root=pathlib.Path(sys.argv[1]);sys.path[:0]=[str(root),str(root/'fox'),str(root/'converter'),str(root/'dependencies')]
from qa.operator import fresh_backend as m
for flag in (False,None,0,1,'true'):
 try:m.initialize_backend({}, {}, layout={}, apply=flag)
 except m.FreshBackendError:pass
 else:raise AssertionError('APPLY_NOT_EXPLICIT')
print('APPLY_REFUSED')
'''
        result = self.run_program(program)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'APPLY_REFUSED')

    @unittest.skipIf(POSIX, 'Non-POSIX refusal only')
    def test_platform_refusal_creates_nothing(self):
        program = r'''
import pathlib,sys
root=pathlib.Path(sys.argv[1]);sys.path[:0]=[str(root),str(root/'fox'),str(root/'converter'),str(root/'dependencies')]
from qa.operator import fresh_backend as m
before=list(pathlib.Path.cwd().iterdir())
try:m.initialize_backend({}, {}, layout={}, apply=True)
except m.FreshBackendError:pass
else:raise AssertionError('WINDOWS_INIT_ALLOWED')
assert list(pathlib.Path.cwd().iterdir())==before
print('PLATFORM_REFUSED')
'''
        result = self.run_program(program)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'PLATFORM_REFUSED')


@unittest.skipUnless(POSIX, 'Genuine nonroot POSIX execution required')
class FreshBackendPosixTests(unittest.TestCase):
    def run_scenario(self, name):
        result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                 '--scenario', name, str(ROOT)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(json.loads(result.stdout)['status'], 'PASSED')


SCENARIOS = ('positive', 'nonempty', 'extra_table', 'wrong_identity', 'partial_attempt', 'existing_f',
    'source_drift', 'missing_source', 'unlisted_source', 'cached_bytecode', 'module_origin', 'python_pin',
    'projection_drift', 'database_symlink', 'database_hardlink', 'database_mode', 'public_extra',
    'wal_sidecar', 'lock_contention', 'sql_failure', 'intent_failure', 'publish_failure',
    'published_uncertainty', 'source_drift_during_sql', 'lease_held_during_initialization',
    'observed_failure', 'observed_drift', 'observed_missing', 'checkpoint_failure', 'delete_mode_failure',
    *( 'aggregate_' + prefix + field for prefix, fields in (
        ('', ('clean_operator_code_sha256', 'qa_source_sha256', 'promotion_transport_sha256')),
        ('project_', ('clean_operator_code_sha256', 'qa_source_sha256',
                      'promotion_transport_sha256', 'operator_code_sha256')))
       for field in fields))
for _scenario in SCENARIOS:
    def _test(self, name=_scenario):
        self.run_scenario(name)
    setattr(FreshBackendPosixTests, 'test_' + _scenario, _test)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--scenario':
        print(json.dumps(scenario(sys.argv[2], Path(sys.argv[3])), sort_keys=True))
    else:
        unittest.main()
