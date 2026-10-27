"""Real local C/F/G history validation for the retired-operator remote reader.

Packages and receipts are deliberately synthetic. Recovery closure, retry event
chains, source selection, promotion and retained-proof gates are production code.
No OCI, network, subprocess, old journal or credential is read. Windows runs
adapt only POSIX ownership/fsync checks, not technical or recovery validation.
"""
from contextlib import closing
from copy import deepcopy
import builtins
import importlib
import io
import json
import os
import pathlib
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
for _folder in (ROOT, ROOT / 'fox', ROOT / 'fox/tests'):
    if str(_folder) not in sys.path:
        sys.path.insert(0, str(_folder))

from fox import native_verification as gate
from fox import source_history
from fox import verification_queue as queue_module
from fox import verification_recovery as recovery

OLD, RETRY, IDLE, CURRENT = (character * 64 for character in ('a', 'b', 'c', 'd'))
SESSION_C, SESSION_F, SESSION_G = ('session-' + character * 24 for character in ('a', 'b', 'c'))


def _blocked(*args, **kwargs):
    pytest.fail('Retirement backend tests must not perform external actions')


def _load_fixtures(monkeypatch):
    # Shared proof fixtures import test_fox only for fixture declarations. Do
    # not construct the application merely to create synthetic package bytes.
    if 'test_fox' not in sys.modules:
        stub = ModuleType('test_fox')
        stub.client = stub.signed_in = stub.project = _blocked
        monkeypatch.setitem(sys.modules, 'test_fox', stub)
    return importlib.import_module('test_verification_recovery')


def _case(fixture, root, monkeypatch, letter, token):
    root.mkdir()
    with monkeypatch.context() as patch:
        harness = fixture.harness.__wrapped__(root, patch)
        if letter != 'a':
            renamed = harness.job.with_name('fox-' + letter * 20)
            harness.job.rename(renamed)
            harness.job, harness.path = renamed, '/fox/jobs/' + renamed.name
        package = fixture.valid_package.__wrapped__(harness)
        proof = fixture.proof_case.__wrapped__(package, harness)
        policy_fixture = importlib.import_module('test_native_verification_policy')
        return policy_fixture.bind_v2(proof, token=token,
            workspace_id='22042420337195501' if letter == 'a' else '22042420337195502',
            app_id=34567 if letter == 'a' else 34568)


def _seed_schema(database, cases):
    database.parent.mkdir()
    with closing(sqlite3.connect(database)) as db, db:
        db.executescript('''
            CREATE TABLE projects(id TEXT PRIMARY KEY,owner TEXT);
            CREATE TABLE sources(id TEXT PRIMARY KEY,project TEXT,name TEXT,sha256 TEXT,
                bytes INTEGER,text TEXT,created REAL);
            CREATE TABLE events(owner TEXT,action TEXT,object_id TEXT,created REAL);
        ''')
        for index, case in enumerate(cases):
            pid = 'synthetic-recovery' if index == 0 else 'synthetic-idle'
            case['snapshot']['project'] = pid
            db.execute('INSERT INTO projects VALUES(?,?)', (pid, 'synthetic-owner'))
            for number, source in enumerate(case['snapshot']['files']):
                db.execute('INSERT INTO sources VALUES(?,?,?,?,?,?,?)',
                    (pid + '-' + str(number), pid, source['name'], source['sha256'],
                     source['bytes'], source['text'], 1.0))
        db.execute('BEGIN') if not db.in_transaction else None
        source_history.initialize(db)


def _promote(case, root, receipts, *, monkeypatch):
    receipts.mkdir(mode=0o700)
    for name, key in zip(gate.RECEIPT_NAMES, ('clean', 'qa', 'target', 'profile')):
        (receipts / name).write_bytes(json.dumps(case[key], sort_keys=True).encode())
    (receipts / 'verification-profile.json').write_bytes(case['verification_policy'].raw)
    (receipts / 'allocation-receipt.json').write_bytes(case['allocation_raw'])
    for path in receipts.iterdir():
        path.chmod(0o600)
    if os.name != 'posix':
        monkeypatch.setattr(gate, '_private', lambda path, directory=False: gate._safe_path(path))
        monkeypatch.setattr(gate, '_sync_dir', lambda path: None)
    return gate.promote_native_run(root=root, run_id=case['release']['job_id'],
        operator_receipt_dir=receipts, policy=case['verification_policy'],
        now=importlib.import_module('test_native_verification').NOW)


def _seed_normal(case, root, release):
    job_id = case['release']['job_id']
    job = root / 'jobs' / job_id
    (job / 'native-pipeline').mkdir(parents=True)
    for name, value in (('source-snapshot.json', case['snapshot']),
                        ('release-evidence.json', case['release']),
                        ('native-pipeline/download.json', {
                            'source_hash': case['snapshot']['source_hash'],
                            'package_sha256': recovery.digest(case['package'])})):
        (job / name).write_bytes(recovery.canonical_bytes(value))
    (job / 'apex-package.zip').write_bytes(case['package'])
    binding = queue_module.VerificationBinding(job_id, case['snapshot']['source_hash'],
        recovery.digest(case['package']), release)
    with closing(sqlite3.connect(root / 'fox.sqlite3')) as db, db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (job_id,
            case['snapshot']['project'], binding.source_manifest_sha256, 'QA_REQUIRED',
            'Synthetic pending proof', 1.0, 1.0, str(Path('jobs') / job_id / 'apex-package.zip')))
    queue = queue_module.VerificationQueue(root / 'fox.sqlite3', enabled=True,
        verifier_release_sha256=release)
    queue.enqueue(binding)
    return queue, queue.claim_next()


@pytest.fixture
def historical_case(tmp_path, monkeypatch):
    monkeypatch.setattr(socket, 'create_connection', _blocked)
    monkeypatch.setattr(socket.socket, 'connect', _blocked)
    monkeypatch.setattr(subprocess, 'run', _blocked)
    monkeypatch.setattr(subprocess, 'Popen', _blocked)
    fixture = _load_fixtures(monkeypatch)
    fixture.no_external_actions.__wrapped__(monkeypatch)
    monkeypatch.setattr(fixture, 'OLD_RELEASE', OLD)
    case = _case(fixture, tmp_path / 'c', monkeypatch, 'a', '261017_89ABCDEF')
    idle = _case(fixture, tmp_path / 'g', monkeypatch, 'e', '261017_76543210')
    database = tmp_path / 'store' / 'fox.sqlite3'
    _seed_schema(database, [case, idle])
    bundle = fixture.failed_bundle(case)
    database, legacy_queue, claim = fixture.seed(database.parent, bundle)
    store = recovery.VerificationRecovery(database, enabled=True,
        producer_probe=lambda *args: deepcopy(bundle['producer']), approved_retry_releases=[RETRY])
    store.initialize()
    document = recovery.validate_failed_evidence(**fixture.arguments(bundle))
    evidence = {name: bundle[name] for name in
        ('package', 'plan_raw', 'collection_raw', 'files', 'journal_summary')}
    acknowledgement = store.record_failure(claim, recovery.canonical_bytes(document),
        evidence=evidence, now=fixture.NOW)
    request = fixture.request(document, release=RETRY)
    store.reserve_retry(recovery.canonical_bytes(request), now=fixture.NOW)
    retry_claim = store.claim_retry(request['attempt_id'])
    passing = importlib.import_module('test_native_verification_policy').bind_v2(case,
        token='261017_01234567', workspace_id='22042420337195503', app_id=34569)
    assert passing['package'] == bundle['package']
    retry_proof = _promote(passing, database.parent, tmp_path / 'f-receipts', monkeypatch=monkeypatch)
    completed = store.complete_retry(retry_claim, queue_module.TechnicalProofResult(retry_proof['proof_sha256']))
    idle_queue, idle_claim = _seed_normal(idle, database.parent, IDLE)
    assert idle_claim is not None
    idle_proof = _promote(idle, database.parent, tmp_path / 'g-receipts', monkeypatch=monkeypatch)
    idle_queue.complete(idle_claim, queue_module.TechnicalProofResult(idle_proof['proof_sha256']))
    history = {
        'failure': {'release_sha256': OLD, 'session_id': SESSION_C,
            'job_id': claim.binding.job_id, 'disposition_sha256': acknowledgement['disposition_sha256'],
            'disposition': document},
        'retry': {'release_sha256': RETRY, 'session_id': SESSION_F,
            'job_id': claim.binding.job_id, 'attempt_id': request['attempt_id'],
            'proof_sha256': retry_proof['proof_sha256']},
        'idle': {'release_sha256': IDLE, 'session_id': SESSION_G,
            'completed_jobs': [{'binding': idle_claim.binding.payload(), 'proof_sha256': idle_proof['proof_sha256']}]}}
    return SimpleNamespace(database=database, root=database.parent, history=history,
        acknowledgement=acknowledgement, completed=completed, legacy_queue=legacy_queue,
        idle_queue=idle_queue, store=store)


def _read(case, *, startup=True, history=None, current=CURRENT):
    from qa.operator import retirement_remote
    return retirement_remote._backend_snapshot(history or case.history, current, startup,
        queue_module, gate, recovery, root=case.root)


def _snapshot(case):
    with closing(sqlite3.connect(case.database)) as db:
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        rows = {table: list(db.execute('SELECT * FROM ' + table)) for table in tables}
        schema = list(db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'))
    files = {str(path.relative_to(case.root)): path.read_bytes()
        for path in (case.root / 'jobs').rglob('*') if path.is_file()}
    return schema, rows, files


def _waiting(case, *, release=CURRENT, number=1):
    job = 'fox-' + f'{number:020x}'
    binding = queue_module.VerificationBinding(job, '9' * 64, '8' * 64, release)
    with closing(sqlite3.connect(case.database)) as db, db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (job, 'synthetic-waiting',
            binding.source_manifest_sha256, 'QA_REQUIRED', 'Synthetic queued', 1, 1,
            str(Path('jobs') / job / 'apex-package.zip')))
    queue = queue_module.VerificationQueue(case.database, enabled=True, verifier_release_sha256=release)
    queue.enqueue(binding)
    return binding


def _busy(case, *, state='PROCESSING', number=10):
    job = 'fox-' + f'{number:020x}'
    with closing(sqlite3.connect(case.database)) as db, db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (job, 'synthetic-idle',
            '7' * 64, state, 'Synthetic ordinary conversion', 1, 1, None))
    return job


def test_real_closed_c_completed_f_and_g_proofs_remain_distinct_and_read_only(historical_case):
    case = historical_case
    before = _snapshot(case)
    result = _read(case)
    assert result['failure_acknowledgement'] == case.acknowledgement
    assert result['completed_idle_jobs'] == case.history['idle']['completed_jobs']
    for key in ('job_id', 'attempt_id', 'release_sha256', 'proof_sha256'):
        assert result['completed_retry'][key] == case.history['retry'][key]
    assert result['waiting_verification_count'] == 0
    assert result['busy_conversion_count'] == 0 and result['admission_state'] == 'READY'
    assert len(result['backend_snapshot_sha256']) == 64
    assert case.legacy_queue.get(case.history['failure']['job_id'])['state'] == 'attention'
    assert _snapshot(case) == before


def test_current_queued_jobs_are_startup_only_and_no_new_proof_is_created(historical_case):
    case = historical_case
    _waiting(case, number=1)
    _waiting(case, number=2)
    before = _snapshot(case)
    assert _read(case)['waiting_verification_count'] == 2
    with pytest.raises(Exception):
        _read(case, startup=False)
    assert _snapshot(case) == before


@pytest.mark.parametrize('state', ['QUEUED', 'PROCESSING'])
@pytest.mark.parametrize('waiting', [False, True])
def test_normal_conversion_observed_as_wait_without_claim_or_mutation(historical_case, state, waiting):
    case = historical_case
    job = _busy(case, state=state)
    if waiting:
        _waiting(case)
    before = _snapshot(case)
    result = _read(case)
    assert result['admission_state'] == 'WAIT' and result['busy_conversion_count'] == 1
    assert result['waiting_verification_count'] == int(waiting)
    assert _snapshot(case) == before
    with pytest.raises(Exception): _read(case, startup=False)
    assert _snapshot(case) == before
    # Normal completion releases admission; the reader neither completes nor
    # resumes the conversion itself and never manufactures a technical proof.
    with closing(sqlite3.connect(case.database)) as db, db:
        db.execute("UPDATE runs SET state='REVIEW_REQUIRED' WHERE id=?", (job,))
    result = _read(case)
    assert result['admission_state'] == 'READY' and result['busy_conversion_count'] == 0


@pytest.mark.parametrize('mutation', ['artifact', 'missing-project', 'bad-hash', 'bad-id', 'queue', 'unknown-state'])
def test_busy_wait_cannot_hide_unbound_or_verification_work(historical_case, mutation):
    case = historical_case
    job = _busy(case)
    with closing(sqlite3.connect(case.database)) as db, db:
        if mutation == 'artifact': db.execute('UPDATE runs SET artifact=? WHERE id=?', ('retained.zip', job))
        elif mutation == 'missing-project': db.execute('UPDATE runs SET project=? WHERE id=?', ('missing', job))
        elif mutation == 'bad-hash': db.execute('UPDATE runs SET source_hash=? WHERE id=?', ('bad', job))
        elif mutation == 'bad-id': db.execute('UPDATE runs SET id=? WHERE id=?', ('unknown', job))
        elif mutation == 'unknown-state': db.execute("UPDATE runs SET state='UNKNOWN' WHERE id=?", (job,))
        else:
            binding = _waiting(case)
            db.execute("UPDATE runs SET state='PROCESSING',artifact=NULL WHERE id=?", (binding.job_id,))
    before = _snapshot(case)
    with pytest.raises(Exception): _read(case)
    assert _snapshot(case) == before


@pytest.mark.parametrize('kind', ['retry-proof', 'idle-proof', 'failure-disposition', 'retry-release', 'idle-release'])
def test_changed_declared_historical_bindings_fail_closed(historical_case, kind):
    case = historical_case
    history = deepcopy(case.history)
    if kind == 'retry-proof': history['retry']['proof_sha256'] = '0' * 64
    elif kind == 'idle-proof': history['idle']['completed_jobs'][0]['proof_sha256'] = '0' * 64
    elif kind == 'failure-disposition': history['failure']['disposition_sha256'] = '0' * 64
    elif kind == 'retry-release': history['retry']['release_sha256'] = '0' * 64
    else: history['idle']['completed_jobs'][0]['binding']['verifier_release_sha256'] = '0' * 64
    before = _snapshot(case)
    with pytest.raises(Exception):
        _read(case, history=history)
    assert _snapshot(case) == before


@pytest.mark.parametrize('role,member', [
    ('failure', 'apex-package.zip'), ('retry', 'technical-verification/verification.json'),
    ('retry', 'technical-verification/qa-result.json'), ('idle', 'technical-verification/verification.json'),
    ('idle', 'technical-verification/qa-target.json'), ('idle', 'source-snapshot.json')])
def test_actual_retained_package_receipt_and_proof_tamper_is_refused(historical_case, role, member):
    case = historical_case
    job = (case.history[role]['job_id'] if role != 'idle'
        else case.history['idle']['completed_jobs'][0]['binding']['job_id'])
    path = case.root / 'jobs' / job / member
    path.write_bytes(path.read_bytes() + b'\nTAMPER')
    before = _snapshot(case)
    with pytest.raises(Exception):
        _read(case)
    assert _snapshot(case) == before


@pytest.mark.parametrize('mutation', ['wrong-release', 'source', 'artifact', 'queue-hash', 'running', 'attention', 'orphan'])
def test_noncurrent_unbound_or_active_queued_work_blocks(historical_case, mutation):
    case = historical_case
    binding = _waiting(case, release='7' * 64 if mutation == 'wrong-release' else CURRENT)
    with closing(sqlite3.connect(case.database)) as db, db:
        db.row_factory = sqlite3.Row
        if mutation == 'source': db.execute('UPDATE runs SET source_hash=? WHERE id=?', ('1' * 64, binding.job_id))
        elif mutation == 'artifact': db.execute('UPDATE runs SET artifact=? WHERE id=?', ('other.zip', binding.job_id))
        elif mutation == 'queue-hash': db.execute('UPDATE verification_queue SET record_sha256=? WHERE job_id=?', ('1' * 64, binding.job_id))
        elif mutation in {'running', 'attention'}:
            row = dict(db.execute('SELECT * FROM verification_queue WHERE job_id=?', (binding.job_id,)).fetchone())
            row.update(state=mutation, claim_token='2' * 32,
                attention_code='INTERRUPTED_OUTCOME' if mutation == 'attention' else None)
            queue_module.VerificationQueue._save(db, row)
        elif mutation == 'orphan': db.execute('DELETE FROM runs WHERE id=?', (binding.job_id,))
    before = _snapshot(case)
    with pytest.raises(Exception):
        _read(case)
    assert _snapshot(case) == before


@pytest.mark.parametrize('state', ['QUEUED', 'PROCESSING', 'ATTENTION', 'UNKNOWN', 'QA_REQUIRED'])
def test_unbound_union_member_never_disappears_from_admission(historical_case, state):
    case = historical_case
    with closing(sqlite3.connect(case.database)) as db, db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', ('fox-' + '6' * 20, 'unknown',
            '1' * 64, state, 'Synthetic unresolved member', 1, 1, None))
    before = _snapshot(case)
    with pytest.raises(Exception):
        _read(case)
    assert _snapshot(case) == before


def test_backend_reads_use_only_readonly_sql_and_preserve_all_raw_proofs(historical_case, monkeypatch):
    case = historical_case
    before = _snapshot(case)
    calls, statements = [], []
    connect = sqlite3.connect
    def traced(*args, **kwargs):
        calls.append((args, kwargs))
        db = connect(*args, **kwargs)
        db.set_trace_callback(statements.append)
        return db
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, 'connect', traced)
        assert _read(case)['waiting_verification_count'] == 0
    assert len(calls) >= 4  # independent history snapshots and exact native proof reads
    assert all(args[0].endswith('?mode=ro') and kwargs['uri'] is True for args, kwargs in calls)
    assert statements
    assert all(sql.lstrip().upper().startswith(('SELECT ', 'PRAGMA ', 'BEGIN', 'ROLLBACK'))
        for sql in statements)
    assert _snapshot(case) == before


def _remove_immutable_row(db, table, predicate, args=()):
    """Corrupt one synthetic ledger while retaining its exact schema guards."""
    triggers = list(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)))
    for name, _ in triggers:
        db.execute('DROP TRIGGER ' + name)
    db.execute('DELETE FROM ' + table + ' WHERE ' + predicate, args)
    for _, sql in triggers:
        db.execute(sql)


@pytest.mark.parametrize('mutation', ['unfinished-retry', 'missing-retry', 'missing-failure', 'missing-proof', 'proof-digest'])
def test_partial_or_changed_real_history_ledgers_are_not_admitted(historical_case, mutation):
    case = historical_case
    with closing(sqlite3.connect(case.database)) as db, db:
        if mutation == 'unfinished-retry':
            _remove_immutable_row(db, 'verification_retry_events', "state='completed'")
        elif mutation == 'missing-retry':
            _remove_immutable_row(db, 'verification_retry_attempts', 'attempt_id=?',
                (case.history['retry']['attempt_id'],))
        elif mutation == 'missing-failure':
            _remove_immutable_row(db, 'verification_failed_dispositions', 'job_id=?',
                (case.history['failure']['job_id'],))
        elif mutation == 'missing-proof':
            db.execute('DELETE FROM technical_verifications WHERE run=?', (case.history['retry']['job_id'],))
        else:
            db.execute('UPDATE technical_verifications SET proof_sha256=? WHERE run=?',
                ('0' * 64, case.history['retry']['job_id']))
    before = _snapshot(case)
    with pytest.raises(Exception):
        _read(case)
    assert _snapshot(case) == before


def test_waiting_queue_cannot_hide_even_a_partial_recovery_identity(historical_case):
    case = historical_case
    binding = _waiting(case)
    with closing(sqlite3.connect(case.database)) as db, db:
        db.execute('INSERT INTO verification_retry_attempts VALUES(?,?,?,?,?,?,?,?)', (
            'attempt-' + '3' * 32, 'request-' + '3' * 32,
            '4' * 64, binding.job_id,
            b'{}', '1' * 64, '2026-10-17T02:00:00+00:00', '1' * 64))
    before = _snapshot(case)
    with pytest.raises(Exception):
        _read(case)
    assert _snapshot(case) == before


def test_union_change_during_real_proof_read_is_refused(historical_case, monkeypatch):
    case = historical_case
    binding = _waiting(case)
    original = gate.verify_existing_native_run
    reads = []
    def changed_during_read(**kwargs):
        result = original(**kwargs)
        reads.append(kwargs['run_id'])
        if len(reads) == 1:
            with closing(sqlite3.connect(case.database)) as db, db:
                db.row_factory = sqlite3.Row
                row = dict(db.execute('SELECT * FROM verification_queue WHERE job_id=?',
                    (binding.job_id,)).fetchone())
                row['updated_at_utc'] = '2026-10-25T00:00:00+00:00'
                queue_module.VerificationQueue._save(db, row)
        return result
    monkeypatch.setattr(gate, 'verify_existing_native_run', changed_during_read)
    from qa.operator.retirement_remote import RetirementRemoteError
    with pytest.raises(RetirementRemoteError, match='CHANGED_DURING_READ'):
        _read(case)
    assert len(reads) == 2


@pytest.mark.parametrize('mutation', [None, 'busy', 'busy-and-queued', 'configuration', 'provider-configuration', 'manifest-provider-configuration',
    'legacy-v2', 'environment-release', 'source', 'profile'], ids=lambda value: value or 'valid-v3')
def test_actual_generated_container_loads_bound_sources_and_checks_real_history(historical_case, monkeypatch, mutation):
    """Run the emitted loader and proof gate, not a fabricated backend reply.

    Only container filesystem prefixes, effective UID/GID, environment and
    stdio are mapped. All /app/fox source bytes and the native profile are
    unchanged local production files; /data is the synthetic SQLite fixture.
    """
    from qa.operator import retirement_remote as remote
    from qa.operator.tests.test_retirement_remote import configuration
    case = historical_case
    manifest, release, infrastructure, config_hash = configuration()
    if mutation in {'busy', 'busy-and-queued'}:
        _busy(case)
        if mutation == 'busy-and-queued': _waiting(case, release=release)
    before = _snapshot(case)
    assert manifest['schema_version'] == 3
    provider_hash = manifest['hosted_runtime_configuration_sha256']
    admission = {'schema_version': 1, 'scope': 'fox-hosted-admission-v1',
        'provider_configuration_sha256': provider_hash, 'current_release_sha256': release,
        'infrastructure': infrastructure}
    assert config_hash == remote._digest(remote._canonical(admission))
    assert provider_hash != config_hash  # C provider identity and D admission envelope are distinct.
    profile_path = ROOT / manifest['opaf_profile']['path']
    assert profile_path == ROOT / 'deployment/project-opaf-profile-v2.json'
    if mutation == 'legacy-v2':
        manifest.update(schema_version=2, scope=remote.bridge.PROJECT_SCOPE)
        del manifest['opaf_profile']
        del manifest['hosted_runtime_configuration_sha256']
        manifest['code'] = {name: manifest['code'][name] for name in remote.bridge.CODE}
        release = remote.bridge.release_sha256(manifest)
    elif mutation == 'manifest-provider-configuration':
        manifest['hosted_runtime_configuration_sha256'] = '0' * 64
        release = remote.bridge.release_sha256(manifest)
    request = {'operation': 'retired_history_read', 'apply': False, 'manifest': manifest,
        'release_sha256': release, 'configuration_sha256': config_hash,
        'provider_configuration_sha256': provider_hash,
        'history': case.history, 'for_startup': True}
    if mutation == 'configuration':
        request['configuration_sha256'] = '0' * 64
    elif mutation == 'provider-configuration':
        request['provider_configuration_sha256'] = '0' * 64
    program = remote.container_source(release, config_hash)
    mapped = []
    def mapped_path(*parts):
        path = Path(*parts)
        text = str(parts[0]).replace('\\', '/') if len(parts) == 1 else path.as_posix()
        prefixes = {'/app/fox': ROOT / 'fox/fox', '/data': case.root,
            '/run/fox-native/profile.json': profile_path}
        for prefix, destination in prefixes.items():
            if text == prefix or text.startswith(prefix + '/'):
                path = destination / text[len(prefix):].lstrip('/') if text != prefix else destination
                mapped.append((text, path))
                break
        return path
    real_import = builtins.__import__
    def import_mapped(name, globals=None, locals=None, fromlist=(), level=0):
        filename = str((globals or {}).get('__file__', ''))
        if name == 'pathlib' and (filename == '<retirement-generated-fixture>' or filename.startswith('/app/fox/')):
            return SimpleNamespace(**{**vars(pathlib), 'Path': mapped_path})
        return real_import(name, globals, locals, fromlist, level)
    real_open = Path.open
    changed_path = (ROOT / 'fox/fox/verification_recovery.py' if mutation == 'source'
        else profile_path if mutation == 'profile' else None)
    def open_changed(path, *args, **kwargs):
        if path == changed_path:
            assert args == ('rb',) and not kwargs
            with real_open(path, 'rb') as stream:
                return io.BytesIO(stream.read() + b'\n# synthetic hash mismatch')
        return real_open(path, *args, **kwargs)
    modules_before = dict(sys.modules)
    path_before, meta_before = list(sys.path), list(sys.meta_path)
    no_bytecode_before = sys.dont_write_bytecode
    output, exceptions, imported = io.StringIO(), [], set()
    trace_before = sys.gettrace()
    def trace(frame, event, arg):
        filename = frame.f_code.co_filename
        if event == 'call' and filename.startswith('/app/fox/'):
            imported.add(filename.rsplit('/', 1)[-1])
        if event == 'exception' and (filename == '<retirement-generated-fixture>' or filename.startswith('/app/fox/')):
            exceptions.append((filename, frame.f_lineno, type(arg[1]).__name__, str(arg[1])))
        return trace
    try:
        with monkeypatch.context() as patch:
            patch.setattr(builtins, '__import__', import_mapped)
            patch.setattr(Path, 'open', open_changed)
            patch.setattr(os, 'geteuid', lambda: 1000, raising=False)
            patch.setattr(os, 'getegid', lambda: 1000, raising=False)
            patch.setenv('FOX_VERIFICATION_ENABLED', '1')
            patch.setenv('FOX_VERIFIER_RELEASE_SHA256', '0' * 64 if mutation == 'environment-release' else release)
            patch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(remote._canonical(request))))
            patch.setattr(sys, 'stdout', output)
            sys.settrace(trace)
            exec(compile(program, '<retirement-generated-fixture>', 'exec', optimize=2), {
                '__name__': '_retirement_generated_fixture', '__file__': '<retirement-generated-fixture>'})
    finally:
        sys.settrace(trace_before)
        sys.path[:] = path_before
        sys.meta_path[:] = meta_before
        sys.dont_write_bytecode = no_bytecode_before
        for name in list(sys.modules):
            if name not in modules_before:
                sys.modules.pop(name, None)
        sys.modules.update(modules_before)
    result = json.loads(output.getvalue())
    if mutation in {None, 'busy', 'busy-and-queued'}:
        assert result.get('status') == 'RETIRED_HISTORY_OBSERVED', exceptions[-8:]
        assert result['failure_acknowledgement'] == case.acknowledgement
        assert result['completed_retry']['proof_sha256'] == case.history['retry']['proof_sha256']
        assert result['completed_idle_jobs'] == case.history['idle']['completed_jobs']
        assert result['current_release_sha256'] == release
        assert result['configuration_sha256'] == config_hash
        assert result['provider_configuration_sha256'] == provider_hash
        assert result['read_only'] is True and result['automatic_replay_permitted'] is False
        assert result['admission_state'] == ('READY' if mutation is None else 'WAIT')
        assert result['busy_conversion_count'] == (0 if mutation is None else 1)
        assert result['waiting_verification_count'] == (1 if mutation == 'busy-and-queued' else 0)
        assert {'verification_queue.py', 'verification_runtime.py', 'technical_release.py',
            'native_verification.py', 'verification_recovery.py'} <= imported
        assert any(text == '/data' for text, _ in mapped)
        assert any(text == '/run/fox-native/profile.json' for text, _ in mapped)
    else:
        assert result == {'status': 'STOPPED',
            'code': 'QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY', 'automatic_replay_permitted': False}
        assert not imported, 'Rejected container identity/source must fail before importing runtime modules'
    assert set(sys.modules) == set(modules_before)
    assert all(sys.modules[name] is value for name, value in modules_before.items())
    assert sys.path == path_before and sys.meta_path == meta_before
    assert _snapshot(case) == before
