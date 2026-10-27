"""Offline-only remote journey contracts. All process/network operations mocked."""
import ast
import base64
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from qa.operator import fox_journey_remote as r

NOW = datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc)
RUN = 'FOXJ-20261017T100000-a1b2c3d4'
PASSWORD = 'offline-only-placeholder!'
FIXTURES = REPO / 'work/fox-journey-fixtures-20261017a'


def encode(raw):
    return base64.b64encode(raw).decode('ascii')


def packet(command='stage'):
    paths = {name: REPO / 'qa/run-fox-journey.mjs' if name.startswith('driver/')
             else REPO / 'work/beta/prepare-mini-prerequisite.py' if name.startswith('mini/')
             else FIXTURES / name[len('fixtures/'):] for name in r.PINNED_FILES if name != 'release.json'}
    sources = {name: path.read_bytes() for name, path in paths.items()}
    sources['release.json'] = r.canonical(r.RELEASE)
    remote = Path(r.__file__).read_bytes()
    descriptor = {'schema_version': 1, 'scope': 'fox-prepared-journey-source-v1', 'pin_state': r.PIN_STATE,
                  'files': dict(r.PINNED_FILES), 'remote_sha256': r.digest(remote),
                  'wrapper_sha256': 'a' * 64, 'transport_sha256': 'b' * 64,
                  'credential_reader_sha256': 'c' * 64, 'fixture_generator_sha256': r.FIXTURE_GENERATOR_SHA256,
                  'images': dict(r.IMAGES), 'target': dict(r.TARGET), 'release': deepcopy(r.RELEASE),
                  'launch_key': r.LAUNCH_KEY}
    scope = {key: r.TARGET[key] for key in ('instance_id', 'database_id', 'compartment_id', 'region')}
    scope.update(database_db_name='JSNF2APEX', instance_state='RUNNING', database_state='AVAILABLE', observed_at_utc=NOW.isoformat())
    value = {'command': command, 'apply': True, 'source_sha256': r.digest(r.canonical(descriptor)),
             'descriptor': descriptor, 'files': {key: encode(raw) for key, raw in sources.items()},
             'remote_b64': encode(remote), 'cli_scope': scope}
    if command == 'run':
        value['credentials'] = {'username': 'jason', 'password': PASSWORD}
    return value


def prerequisite():
    value = dict(r.TARGET)
    value.update(schema_version=1, scope='fox-journey-product-table-prerequisite-v1',
                 ddl_sha256=r.PINNED_FILES['fixtures/happy/extraction/journey-happy-v1/ready/mini.sql'],
                 readable_source_hash=r.SOURCES['happy'], metadata_verified=True, initial_row_count=0,
                 checked_at_utc=NOW.isoformat())
    return value


def report(prerequisite_raw):
    job = 'fox-' + 'e' * 20
    alias = 'F2A_' + job.replace('-', '_').upper()
    projects = {}
    for kind, pid in [('blocked', '1' * 32), ('happy', '2' * 32)]:
        projects[kind] = {'project_id': pid, 'name': 'FOX prepared journey ' + RUN + ' ' + kind,
                          'source_hash': r.SOURCES[kind], 'assessment': {
                              'source_hash': r.SOURCES[kind], 'preparation_mode': 'PREPARED_SET_MATCH',
                              'native_state': 'READY' if kind == 'happy' else 'BLOCKED', 'table_name': 'FOX_NATIVE_MINI'}}
    projects['blocked'].update(process_disabled=True, process_post_count=0)
    projects['happy'].update(job_id=job, state='QA_REQUIRED', evidence={
        'job_id': job, 'application_id': 123, 'application_alias': alias,
        'application_url': 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/ords/r/forms2apex_poc/' + alias.lower() + '/',
        'reviewer_execution_verified': True, 'review_receipt_sha256': 'a' * 64, 'response_sha256': 'b' * 64,
        'artifact_binding': {'job_id': job, 'draft_sha256': 'c' * 64, 'reviewed_spec_sha256': 'd' * 64, 'native_review_sha256': 'e' * 64},
        'package_sha256': None})
    paths = [('login', None, '/api/login'), ('create', 'blocked', '/api/projects'),
             ('upload', 'blocked', '/api/projects/' + projects['blocked']['project_id'] + '/sources'),
             ('create', 'happy', '/api/projects'), ('upload', 'happy', '/api/projects/' + projects['happy']['project_id'] + '/sources'),
             ('process', 'happy', '/api/projects/' + projects['happy']['project_id'] + '/runs')]
    assets = {'/': r.RELEASE['html_sha256']}
    assets.update({item['path']: item['sha256'] for item in r.RELEASE['assets']})
    return {'schema_version': 1, 'scope': 'fox-prepared-source-rendered-journey-v1', 'status': 'PASSED', 'run_id': RUN,
            'human_acceptance_recorded': False, 'download_requested': False, 'mutation_retry_performed': False,
            'denied_requests': 0, 'browser_error_count': 0, 'projects': projects,
            'bindings': {'fixtures_sha256': r.PINNED_FILES['fixtures/journey-fixtures.json'],
                         'prerequisite_sha256': r.digest(prerequisite_raw), 'release_sha256': r.PINNED_FILES['release.json'],
                         'operator_reported_fox_image_id': r.IMAGES['fox'], 'operator_reported_qa_image_id': r.IMAGES['qa'],
                         'observed_asset_hashes': assets},
            'post_requests': [{'intent_sequence': i + 1, 'kind': kind, 'case': case, 'endpoint': endpoint,
                               'outcome': 'RESPONSE_VALIDATED', 'response_sha256': 'f' * 64}
                              for i, (kind, case, endpoint) in enumerate(paths)]}


class MemoryFS:
    """No real remote/POSIX files: preserve exclusive creation and call order."""
    def __init__(self):
        self.files, self.dirs, self.events = {}, set(), []

    def directory(self, path, create=False, exclusive=False):
        path = Path(path)
        if exclusive and path in self.dirs:
            raise RuntimeError('STAGE_EXISTS_NO_OVERWRITE')
        if create:
            self.dirs.add(path)
        elif path not in self.dirs:
            raise RuntimeError('PRIVATE_PARENT_MISSING')
        return path

    def create(self, path, raw):
        path = Path(path)
        if path in self.files:
            raise RuntimeError('EXCLUSIVE_FILE_EXISTS')
        self.files[path] = raw
        self.events.append(('create', path))

    def read(self, path, limit=r.LIMIT):
        raw = self.files[Path(path)]
        if len(raw) > limit:
            raise RuntimeError('PRIVATE_FILE_SIZE')
        return raw

    def children(self, path):
        return iter({p for p in set(self.files) | self.dirs if p.parent == path})


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.process = patch.object(r.subprocess, 'run', side_effect=AssertionError('REAL_PROCESS_FORBIDDEN')).start()
        self.network = patch.object(r.urllib.request, 'build_opener', side_effect=AssertionError('REAL_NETWORK_FORBIDDEN')).start()
        patch.object(r, 'utc_now', return_value=NOW).start()
        patch.object(r.os, 'getuid', return_value=1000, create=True).start()
        patch.object(r.os, 'getgid', return_value=1000, create=True).start()
        patch.object(r.os, 'umask').start()
        patch.object(r, 'PINS_READY', True).start()
        patch.object(r, 'PIN_STATE', 'READY_H').start()

    def memory_execution(self):
        fs = MemoryFS()
        patch.object(r, 'private_dir', side_effect=fs.directory).start()
        patch.object(r, 'create', side_effect=fs.create).start()
        patch.object(r, 'read_private', side_effect=fs.read).start()
        patch.object(r, 'absent', side_effect=lambda p: Path(p) not in fs.files).start()
        patch.object(Path, 'iterdir', lambda p: fs.children(p)).start()
        baseline = patch.object(r, 'inspect_baselines', side_effect=lambda p: fs.events.append(('baseline', p['command']))).start()
        return fs, baseline

    def test_import_inert_and_python36_syntax(self):
        raw = Path(r.__file__).read_text(encoding='utf-8')
        ast.parse(raw, feature_version=(3, 6))
        spec = importlib.util.spec_from_file_location('fresh_inert_journey', r.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('IMPORT_READ_FORBIDDEN')), patch.object(r.os, 'open', side_effect=AssertionError('IMPORT_IO_FORBIDDEN')):
            spec.loader.exec_module(module)
        self.process.assert_not_called()
        self.network.assert_not_called()

    def test_all_frozen_file_bytes_and_canonical_release_match(self):
        value = packet()
        self.assertEqual(set(r.source_packet(value)), set(r.PINNED_FILES))
        self.assertEqual(len(r.PINNED_FILES), 10)
        expected = ':'.join([r.SOURCES['happy'], r.MANIFESTS['happy'], r.SOURCES['blocked'], r.MANIFESTS['blocked'], r.IMAGES['fox']])
        self.assertEqual(r.LAUNCH_KEY, r.digest(expected.encode()))
        self.assertTrue(r.canonical(r.RELEASE).endswith(b'\n'))

    def test_pending_candidate_gate_blocks_stage_and_run_before_any_boundary(self):
        with patch.object(r, 'source_packet', side_effect=AssertionError('PACKET_PROCESSING_FORBIDDEN')), \
                patch.object(r, 'inspect_baselines', side_effect=AssertionError('BASELINE_FORBIDDEN')), \
                patch.object(r, 'private_dir', side_effect=AssertionError('FILESYSTEM_FORBIDDEN')):
            for ready, state in [(False, 'PENDING_H_CANDIDATE'), (True, 'PENDING_H_CANDIDATE'), (False, 'READY_H'), (1, 'READY_H')]:
                with patch.object(r, 'PINS_READY', ready), patch.object(r, 'PIN_STATE', state):
                    for mode in ('stage', 'run'):
                        with self.assertRaisesRegex(RuntimeError, '^H_CANDIDATE_PINS_PENDING_NO_DISPATCH$'):
                            r.execute({'command': mode})
        self.process.assert_not_called()
        self.network.assert_not_called()
        r.os.umask.assert_not_called()

    def test_packet_strict_apply_command_and_credentials(self):
        original = packet()
        for mutate in [lambda p: p.update(apply=False), lambda p: p.update(apply=1), lambda p: p.update(command='collect'),
                       lambda p: p.update(credentials={'username': 'jason', 'password': PASSWORD}), lambda p: p.update(extra=True),
                       lambda p: p.update(source_sha256=p['source_sha256'] + '\n')]:
            value = deepcopy(original)
            mutate(value)
            with self.assertRaises(Exception):
                r.source_packet(value)
        for credentials in [{}, {'username': 'other', 'password': PASSWORD}, {'username': 'jason', 'password': ''},
                            {'username': 'jason', 'password': 12}, {'username': 'jason', 'password': 'x' * 1025},
                            {'username': 'jason', 'password': PASSWORD, 'token': 'private'}]:
            value = packet('run')
            value['credentials'] = credentials
            with self.assertRaises(Exception):
                r.source_packet(value)

    def test_no_self_consistent_payload_or_binding_substitution(self):
        for field in ['wrapper_sha256', 'remote_sha256', 'transport_sha256', 'credential_reader_sha256', 'fixture_generator_sha256', 'launch_key']:
            value = packet()
            value['descriptor'][field] += '\n'
            value['source_sha256'] = r.digest(r.canonical(value['descriptor']))
            with self.assertRaises(Exception):
                r.source_packet(value)
        for kind in ('file', 'extra_file', 'image', 'target', 'release', 'generator', 'remote', 'extra_descriptor', 'schema_float'):
            value = packet()
            d = value['descriptor']
            if kind == 'file':
                name = next(iter(value['files']))
                value['files'][name] = encode(b'changed')
                d['files'][name] = r.digest(b'changed')
            elif kind == 'extra_file':
                value['files']['private/input-manifest.json'] = encode(b'{}')
                d['files']['private/input-manifest.json'] = r.digest(b'{}')
            elif kind == 'image': d['images']['fox'] = '0' * 64
            elif kind == 'target': d['target']['parsing_schema'] = 'OTHER'
            elif kind == 'release': d['release']['schema_version'] = True
            elif kind == 'generator': d['fixture_generator_sha256'] = '0' * 64
            elif kind == 'remote': value['remote_b64'] = encode(b'other')
            elif kind == 'extra_descriptor': d['approval'] = True
            else: d['schema_version'] = 1.0
            value['source_sha256'] = r.digest(r.canonical(d))
            with self.subTest(kind=kind), self.assertRaises(Exception):
                r.source_packet(value)

    def test_duplicate_nonfinite_and_bad_base64_rejected(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'\xef\xbb\xbf{}', b'\xff']:
            with self.assertRaises(Exception): r.load(raw)
        for raw in ['', 'Zm9v\n', '%%%', 3]:
            with self.assertRaises(Exception): r.decode(raw)

    def test_stage_only_checks_baselines_and_exclusively_retains_pinned_inputs(self):
        fs, baseline = self.memory_execution()
        value = packet()
        with patch.object(r, 'command', side_effect=AssertionError('STAGE_MUST_NOT_START_PROCESS')):
            result = r.execute(value)
        self.assertEqual(set(result), {'status', 'source_sha256', 'stage', 'launch_key', 'qa_image_id'})
        self.assertEqual(result['status'], 'STAGED')
        stage = Path(result['stage'])
        self.assertEqual({str(p.relative_to(stage)).replace('\\', '/') for p in fs.files}, set(r.PINNED_FILES) | {'descriptor.json', 'remote.py', 'stage.complete.json'})
        self.assertEqual(fs.events[0], ('baseline', 'stage'))
        self.assertFalse(any('credentials' in str(p) or 'prerequisite.json' in str(p) for p in fs.files))
        before = dict(fs.files)
        with self.assertRaisesRegex(RuntimeError, 'NO_OVERWRITE'): r.execute(value)
        self.assertEqual(fs.files, before)
        self.assertEqual(baseline.call_count, 2)

    def completed_process(self, fs, stage, exit_code=0, change_report=None):
        def run(args, timeout=15, allowed=(0,)):
            fs.events.append(('command', list(args)))
            if args[0] == '/usr/bin/python3':
                self.assertEqual(args, ['/usr/bin/python3', '-I', '-B', str(stage / 'mini/prepare-mini-prerequisite.py'), '--check'])
                self.assertEqual(timeout, 280)
                return SimpleNamespace(returncode=0, stdout=r.canonical(prerequisite()), stderr=b'')
            self.assertEqual(timeout, 1100)
            self.assertTrue(any('prepared-journey-launch-h' in str(p) for p in fs.files))
            self.assertIn(stage / 'credentials.json', fs.files)
            prereq_raw = fs.files[stage / 'prerequisite.json']
            value = report(prereq_raw)
            if change_report: change_report(value)
            fs.files[stage / 'results' / RUN / 'fox-journey-result.json'] = r.canonical(value)
            fs.dirs.add(stage / 'results' / RUN)
            dispatch = dict(value['bindings'], observed_asset_hashes={})
            dispatch.update(schema_version=1, scope='fox-prepared-journey-dispatch-intent-v1', run_id=RUN, at_utc=NOW.isoformat())
            fs.files[r.DISPATCH_ROOT / (r.LAUNCH_KEY + '.json')] = r.canonical(dispatch)
            return SimpleNamespace(returncode=exit_code, stdout=r.canonical({'run_id': RUN, 'status': 'PASSED', 'receipt': '/results/' + RUN + '/fox-journey-result.json'}), stderr=b'withheld arbitrary process output')
        return run

    def test_run_late_check_intent_and_exact_success_contract(self):
        fs, _ = self.memory_execution()
        value = packet()
        staged = r.execute(value)
        stage = Path(staged['stage'])
        value = dict(value, command='run', credentials={'username': 'jason', 'password': PASSWORD})
        with patch.object(r, 'command', side_effect=self.completed_process(fs, stage)) as process:
            result = r.execute(value)
        self.assertEqual(process.call_count, 2)
        self.assertEqual(result['status'], 'PASSED')
        self.assertEqual(result['post_count'], 6)
        self.assertEqual(result['result_directory'], str(stage / 'results' / RUN))
        self.assertEqual(result['report_path'], str(stage / 'results' / RUN / 'fox-journey-result.json'))
        self.assertEqual(result['projects']['happy']['state'], 'QA_REQUIRED')
        self.assertFalse(result['automatic_replay_permitted'])
        self.assertNotIn(PASSWORD, r.canonical(result).decode())
        self.assertNotIn('jason', r.canonical(result).decode())
        self.assertNotIn('name', result['projects']['happy'])
        events = fs.events
        check_at = next(i for i, item in enumerate(events) if item[0] == 'command' and item[1][0] == '/usr/bin/python3')
        cred_at = next(i for i, item in enumerate(events) if item == ('create', stage / 'credentials.json'))
        launch_at = next(i for i, item in enumerate(events) if item[0] == 'create' and 'prepared-journey-launch-h' in str(item[1]))
        browser_at = next(i for i, item in enumerate(events) if item[0] == 'command' and item[1][0] == '/usr/bin/timeout')
        self.assertLess(check_at, cred_at)
        self.assertLess(cred_at, launch_at)
        self.assertLess(launch_at, browser_at)

    def test_unknown_browser_outcome_keeps_global_intent_and_cannot_replay_new_stage(self):
        fs, _ = self.memory_execution()
        value = packet()
        stage = Path(r.execute(value)['stage'])
        run = dict(value, command='run', credentials={'username': 'jason', 'password': PASSWORD})
        with patch.object(r, 'command', side_effect=self.completed_process(fs, stage, exit_code=124)):
            with self.assertRaisesRegex(RuntimeError, 'NO_REPLAY'): r.execute(run)
        self.assertIn(r.LAUNCH_ROOT / (r.LAUNCH_KEY + '.json'), fs.files)
        next_packet = deepcopy(value)
        next_packet['descriptor']['wrapper_sha256'] = 'd' * 64
        next_packet['source_sha256'] = r.digest(r.canonical(next_packet['descriptor']))
        r.execute(next_packet)
        next_packet.update(command='run', credentials=run['credentials'])
        with patch.object(r, 'command', side_effect=AssertionError('REPLAY_PROCESS_FORBIDDEN')):
            with self.assertRaisesRegex(RuntimeError, 'GLOBAL_JOURNEY_ALREADY_ATTEMPTED'): r.execute(next_packet)

    def test_dispatch_journal_alone_prevents_new_launch(self):
        fs, _ = self.memory_execution()
        value = packet()
        r.execute(value)
        fs.files[r.DISPATCH_ROOT / (r.LAUNCH_KEY + '.json')] = b'unknown prior attempt'
        value.update(command='run', credentials={'username': 'jason', 'password': PASSWORD})
        with patch.object(r, 'command', side_effect=AssertionError('REPLAY_PROCESS_FORBIDDEN')):
            with self.assertRaisesRegex(RuntimeError, 'GLOBAL_JOURNEY_ALREADY_ATTEMPTED'): r.execute(value)

    def test_changed_stage_bytes_fail_before_mini_and_credentials(self):
        fs, _ = self.memory_execution()
        value = packet()
        stage = Path(r.execute(value)['stage'])
        fs.files[stage / 'driver/run-fox-journey.mjs'] += b'\n'
        value.update(command='run', credentials={'username': 'jason', 'password': PASSWORD})
        with patch.object(r, 'command', side_effect=AssertionError('CHANGED_STAGE_PROCESS_FORBIDDEN')):
            with self.assertRaisesRegex(RuntimeError, 'STAGED_BYTES_CHANGED'): r.execute(value)
        self.assertNotIn(stage / 'credentials.json', fs.files)

    def test_failed_prerequisite_writes_no_credentials_or_launch(self):
        fs, _ = self.memory_execution()
        value = packet()
        stage = Path(r.execute(value)['stage'])
        value.update(command='run', credentials={'username': 'jason', 'password': PASSWORD})
        with patch.object(r, 'prerequisite', side_effect=RuntimeError('EMPTY_TABLE_UNPROVEN')):
            with self.assertRaises(RuntimeError): r.execute(value)
        self.assertNotIn(stage / 'credentials.json', fs.files)
        self.assertFalse(any('prepared-journey-launch-h' in str(path) for path in fs.files))

    def test_unfsynced_launch_never_starts_browser(self):
        fs, _ = self.memory_execution()
        value = packet()
        stage = Path(r.execute(value)['stage'])
        value.update(command='run', credentials={'username': 'jason', 'password': PASSWORD})
        def create(path, raw):
            fs.create(path, raw)
            if 'prepared-journey-launch-h' in str(path): raise OSError('fsync failed')
        with patch.object(r, 'create', side_effect=create), patch.object(r, 'command', side_effect=self.completed_process(fs, stage)) as process:
            with self.assertRaises(OSError): r.execute(value)
        self.assertEqual(process.call_count, 1)
        self.assertTrue(any('prepared-journey-launch-h' in str(path) for path in fs.files))

    def test_prerequisite_exact_fixed_fresh_empty_receipt(self):
        for changes in [{}, {'initial_row_count': True}, {'initial_row_count': 0.0}, {'initial_row_count': 1},
                        {'metadata_verified': False}, {'schema_version': True}, {'table_name': 'OTHER'},
                        {'checked_at_utc': '2026-10-17T08:59:59Z'}, {'checked_at_utc': '2026-10-17T10:01:01Z'},
                        {'checked_at_utc': '2026-10-17T17:00:00+07:00'}, {'approval': True}]:
            value = prerequisite()
            value.update(changes)
            raw = r.canonical(value)
            with patch.object(r, 'command', return_value=SimpleNamespace(stdout=raw)):
                if changes:
                    with self.subTest(changes=changes), self.assertRaises(Exception): r.prerequisite(r.ROOT / 'stage')
                else: self.assertEqual(r.prerequisite(r.ROOT / 'stage'), raw)

    def test_run_podman_is_existing_fixed_readonly_capped_image_with_only_private_mounts(self):
        stage = r.STAGE_ROOT / ('a' * 64)
        args = r.podman_args(stage, r.DISPATCH_ROOT)
        self.assertEqual(args[:4], ['/usr/bin/timeout', '--signal=TERM', '--kill-after=15s', '1080s'])
        for option in ['--remote=false', '--pull=never', '--http-proxy=false', '--read-only', '--cap-drop=all',
                       '--security-opt=no-new-privileges', '--cpus=1', '--memory=1536m', '--pids-limit=256', '--userns=keep-id']:
            self.assertIn(option, args)
        self.assertEqual(args[-4:], ['--entrypoint', 'node', 'sha256:' + r.IMAGES['qa'], '/opt/fox-qa/run-fox-journey.mjs'])
        mounts = [args[i + 1] for i, item in enumerate(args) if item == '--volume']
        self.assertEqual(len(mounts), 7)
        self.assertEqual(sum(m.endswith(':rw,Z') for m in mounts), 2)
        self.assertTrue(all(m.startswith(str(r.ROOT)) for m in mounts))
        self.assertFalse(any(x in args for x in ['build', 'pull', 'tag', 'exec', '-p', '--publish', '--privileged', '--network=host']))
        self.assertFalse(any('password' in item.lower() or PASSWORD in item for item in args))
        env = dict(args[i + 1].split('=', 1) for i, item in enumerate(args) if item == '--env')
        self.assertEqual(env['FOX_QA_IMAGE_ID'], r.IMAGES['qa'])
        self.assertEqual(env['FOX_JOURNEY_DISPATCH_DIR'], '/dispatch')
        self.assertEqual(env['DEBUG'], '')
        self.assertEqual(env['HTTPS_PROXY'], '')

    def test_result_rejects_wrong_post_sources_states_evidence_and_secrets(self):
        pre = r.canonical(prerequisite())
        stage = r.STAGE_ROOT / ('a' * 64)
        p = packet('run')
        mutations = [lambda x: x['post_requests'].pop(), lambda x: x['post_requests'][0].update(kind='create'),
                     lambda x: x['post_requests'][1].update(outcome='REQUEST_STARTED'),
                     lambda x: x['post_requests'][5].update(endpoint='/api/accept'),
                     lambda x: x['projects']['happy'].update(source_hash='a' * 64),
                     lambda x: x['projects']['happy'].update(state='VERIFIED'),
                     lambda x: x['projects']['blocked'].update(process_post_count=1),
                     lambda x: x['projects']['happy']['evidence'].update(application_id=True),
                     lambda x: x['projects']['happy']['evidence'].update(application_url='https://elsewhere.invalid/'),
                     lambda x: x['projects']['happy']['evidence'].update(review_receipt_sha256='wrong'),
                     lambda x: x.update(human_acceptance_recorded=True), lambda x: x.update(download_requested=True),
                     lambda x: x.update(denied_requests=True), lambda x: x['bindings'].update(prerequisite_sha256='0' * 64),
                     lambda x: x.update(secret=PASSWORD), lambda x: x.update(secret='jason')]
        for mutate in mutations:
            value = report(pre)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                r.validate_result(r.canonical(value), p, stage, pre, ['jason', PASSWORD])
        value = report(pre)
        value['projects']['blocked']['assessment']['table_name'] = None
        self.assertEqual(r.validate_result(r.canonical(value), p, stage, pre, ['jason', PASSWORD])['status'], 'PASSED')

    def test_main_withholds_all_exception_text_and_never_prints_credentials(self):
        inp = SimpleNamespace(buffer=io.BytesIO(r.canonical(packet('run'))))
        out = io.StringIO()
        with patch.object(r.sys, 'stdin', inp), patch.object(r.sys, 'stdout', out), patch.object(r, 'execute', side_effect=RuntimeError(PASSWORD)):
            self.assertEqual(r.main(), 2)
        self.assertEqual(json.loads(out.getvalue()), {'status': 'STOPPED', 'code': 'JOURNEY_STOPPED_OUTPUT_WITHHELD_NO_REPLAY', 'automatic_replay_permitted': False})
        self.assertNotIn(PASSWORD, out.getvalue())

    def test_command_uses_sanitized_environment_bounded_timeout_and_no_retry(self):
        self.process.side_effect = subprocess.TimeoutExpired(['private'], 15, output=PASSWORD.encode(), stderr=PASSWORD.encode())
        with self.assertRaisesRegex(RuntimeError, '^JOURNEY_TIMEOUT_UNCERTAIN_NO_REPLAY$'):
            r.command(['/usr/bin/podman', '--remote=false', 'info'])
        self.assertEqual(self.process.call_count, 1)
        opts = self.process.call_args.kwargs
        self.assertEqual(opts['stdin'], subprocess.DEVNULL)
        self.assertEqual(opts['cwd'], '/')
        self.assertNotIn('HTTPS_PROXY', opts['env'])
        self.assertNotIn('CONTAINER_HOST', opts['env'])
        self.assertEqual(opts['timeout'], 15)

    def test_network_has_no_proxy_redirect_or_compression(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.getcode.return_value = 200
        response.geturl.return_value = r.ORIGIN + '/'
        response.headers = {}
        response.read.return_value = b'exact raw bytes'
        opener = Mock()
        opener.open.return_value = response
        self.network.side_effect = None
        self.network.return_value = opener
        self.assertEqual(r.fetch(r.ORIGIN + '/'), b'exact raw bytes')
        handlers = self.network.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], r.NoRedirect)
        req = opener.open.call_args.args[0]
        self.assertEqual(req.get_header('Accept-encoding'), 'identity')
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 10)
        with self.assertRaisesRegex(RuntimeError, 'REDIRECT_PROHIBITED'):
            handlers[1].redirect_request(None, None, 302, '', {}, 'https://evil.invalid')
        response.headers = {'Content-Encoding': 'gzip'}
        with self.assertRaisesRegex(RuntimeError, 'HTTP_RESPONSE_DIFFERS'): r.fetch(r.ORIGIN + '/')

    def test_baselines_bind_fixed_scope_images_and_raw_asset_hashes(self):
        value = packet()
        names = {'fox': 'fox', 'forms2apex-mcp': 'converter', 'oracle-applied-ai-label': 'opaf'}
        containers = [{'name': name, 'running': True, 'image': 'sha256:' + r.IMAGES[key]} for name, key in names.items()]
        imds = {'id': r.TARGET['instance_id'], 'compartmentId': r.TARGET['compartment_id'], 'canonicalRegionName': r.TARGET['region']}
        assets = {r.ORIGIN + '/': b'html'}
        assets.update({r.ORIGIN + item['path']: item['path'].encode() for item in r.RELEASE['assets']})
        hash_map = {b'html': r.RELEASE['html_sha256']}
        hash_map.update({item['path'].encode(): item['sha256'] for item in r.RELEASE['assets']})
        actual_digest = r.digest
        def command(args, **kwargs):
            if 'info' in args: raw = b'true\n'
            elif 'image' in args: raw = ('sha256:' + r.IMAGES['qa']).encode()
            else:
                self.assertIn('--format', args)
                self.assertNotIn('Config', args[args.index('--format') + 1])
                raw = b''.join(r.canonical(item) for item in containers)
            return SimpleNamespace(stdout=raw)
        def fetch(url, metadata=False):
            return r.canonical(imds) if metadata else assets[url]
        with patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwuid=lambda _: SimpleNamespace(pw_name='opc'))}), \
                patch.object(r, 'command', side_effect=command), patch.object(r, 'fetch', side_effect=fetch) as get, \
                patch.object(r, 'digest', side_effect=lambda raw: hash_map.get(raw, actual_digest(raw))):
            r.inspect_baselines(value)
            self.assertEqual(get.call_count, 4)
            for mutate in [lambda: value['cli_scope'].update(observed_at_utc='2026-10-17T09:54:59Z'),
                           lambda: value['cli_scope'].update(database_id='OTHER'),
                           lambda: imds.update(id='OTHER'), lambda: containers[0].update(image='latest')]:
                old_scope, old_imds, old_containers = deepcopy(value['cli_scope']), deepcopy(imds), deepcopy(containers)
                mutate()
                with self.assertRaises(RuntimeError): r.inspect_baselines(value)
                value['cli_scope'] = old_scope
                imds.clear(); imds.update(old_imds)
                containers[:] = old_containers

    def test_create_is_exclusive_nofollow_file_then_directory_fsync(self):
        events = []
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream)
        stream.__exit__ = Mock(return_value=False)
        stream.fileno.return_value = 10
        stream.write.side_effect = lambda raw: events.append('write')
        stream.flush.side_effect = lambda: events.append('flush')
        patch.object(r.os, 'O_NOFOLLOW', 0x1000000, create=True).start()
        with patch.object(r, 'private_dir'), patch.object(r.os, 'open', return_value=10) as opening, \
                patch.object(r.os, 'fdopen', return_value=stream), patch.object(r.os, 'fsync', side_effect=lambda _: events.append('file-fsync')), \
                patch.object(r, 'sync_directory', side_effect=lambda _: events.append('directory-fsync')):
            r.create(r.ROOT / 'fixture.json', b'{}')
        self.assertEqual(events, ['write', 'flush', 'file-fsync', 'directory-fsync'])
        flags = opening.call_args.args[1]
        self.assertTrue(flags & r.os.O_EXCL)
        self.assertTrue(flags & r.os.O_NOFOLLOW)
        self.assertEqual(opening.call_args.args[2], 0o600)

    def test_adopted_existing_private_directories_are_durably_linked(self):
        # Windows test host: mock only path metadata; real fsync is prohibited.
        target = r.LAUNCH_ROOT
        def info(path):
            private = path == r.ROOT or r.ROOT in path.parents
            return SimpleNamespace(st_mode=stat.S_IFDIR | (0o700 if private else 0o755), st_uid=1000)
        with patch.object(Path, 'is_absolute', return_value=True), patch.object(Path, 'lstat', info), \
                patch.object(Path, 'mkdir', side_effect=AssertionError('EXISTING_DIRECTORY_MUST_NOT_MKDIR')), \
                patch.object(r, 'sync_directory') as sync:
            self.assertEqual(r.private_dir(target, create=True), target)
            self.assertEqual(sync.call_args_list, [unittest.mock.call(r.ROOT.parent), unittest.mock.call(target.parent)])
            sync.reset_mock()
            r.private_dir(target)
            sync.assert_not_called()
            sync.side_effect = OSError('parent fsync failed')
            with self.assertRaisesRegex(OSError, 'parent fsync failed'): r.private_dir(target, create=True)
        self.process.assert_not_called()

    def test_adopted_launch_directory_fsync_failure_stops_before_check_or_browser(self):
        fs, _ = self.memory_execution()
        value = packet()
        r.execute(value)
        value.update(command='run', credentials={'username': 'jason', 'password': PASSWORD})
        def directory(path, create=False, exclusive=False):
            if path == r.LAUNCH_ROOT and create: raise OSError('adopted directory fsync failed')
            return fs.directory(path, create=create, exclusive=exclusive)
        with patch.object(r, 'private_dir', side_effect=directory), patch.object(r, 'command', side_effect=AssertionError('PROCESS_AFTER_FSYNC_FAILURE_FORBIDDEN')):
            with self.assertRaisesRegex(OSError, 'adopted directory fsync failed'): r.execute(value)


if __name__ == '__main__':
    unittest.main()
