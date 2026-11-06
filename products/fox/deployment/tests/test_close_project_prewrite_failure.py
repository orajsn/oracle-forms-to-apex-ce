"""Controlled local SQLite/OS leases; never hosted closure or Oracle proof."""
import base64
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'fox'), str(ROOT / 'converter'), str(ROOT / 'fox/tests')]
from test_project_prewrite_recovery import prewrite_case, original_stage_case, actual_release, case
from fox import verification_recovery as recovery
from qa.operator import product_verifier as verifier

spec = importlib.util.spec_from_file_location('protected_prewrite_adapter', ROOT / 'deployment/close_project_prewrite_failure.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


def plan():
    return {'schema_version': 1, 'scope': M.SCOPE, 'controller_sha256': 'a' * 64,
        'export': '/home/opc/private/recovery-export',
        **{key: {'path': '/home/opc/private/' + key + '.py', 'sha256': 'b' * 64} for key in M.REFS}}


def test_exact_plan_contains_no_boolean_authority_and_compiles_real_children():
    p = plan(); raw = M.canonical(p)
    assert M.plan_document(raw, M.sha(raw)) == p
    for key in ('BACKEND', 'CLEAN_CAPTURE'):
        compile(getattr(M, key), key, 'exec')
    assert 'runtime-credentials.json' in M.CLEAN_CAPTURE
    assert 'BEGIN IMMEDIATE' not in M.BACKEND  # the production store reserves it
    assert 'close_project_prewrite_failure' in M.BACKEND


def test_protocol_timeout_is_bounded_even_after_partial_message(monkeypatch):
    clock = iter((0, 0, 2))
    monkeypatch.setattr(M.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(M.select, 'select', lambda *args: ([object()], [], []))
    monkeypatch.setattr(M.os, 'read', lambda *args: b'{')
    with pytest.raises(M.ClosureError, match='RESPONSE_TIMEOUT'):
        M.child_message(SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: 1)), seconds=1)


def test_protocol_rejects_oversized_or_extra_messages(monkeypatch):
    monkeypatch.setattr(M.select, 'select', lambda *args: ([object()], [], []))
    for raw in (b'x' * 65537, b'{}\n{}\n', b''):
        monkeypatch.setattr(M.os, 'read', lambda *args: raw)
        with pytest.raises(M.ClosureError, match='RESPONSE_BOUND'):
            M.child_message(SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: 1)))


def test_packet_write_timeout_preserves_blocking_mode_and_never_blocks(monkeypatch):
    modes = []
    monkeypatch.setattr(M.os, 'get_blocking', lambda fd: True)
    monkeypatch.setattr(M.os, 'set_blocking', lambda fd, value: modes.append(value))
    monkeypatch.setattr(M.select, 'select', lambda *args: ([], [], []))
    monkeypatch.setattr(M.os, 'write', lambda *args: pytest.fail('Nonwritable pipe reached write'))
    with pytest.raises(M.ClosureError, match='WRITE_TIMEOUT'):
        M.child_write(SimpleNamespace(stdin=SimpleNamespace(fileno=lambda: 1)), b'x' * 194000, seconds=0.01)
    assert modes == [False, True]


def test_partial_packet_writes_share_one_deadline_and_restore_mode(monkeypatch):
    modes, writes = [], []
    clock = iter((0, 0, 0.5, 2))
    monkeypatch.setattr(M.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(M.os, 'get_blocking', lambda fd: False)
    monkeypatch.setattr(M.os, 'set_blocking', lambda fd, value: modes.append(value))
    monkeypatch.setattr(M.select, 'select', lambda *args: ([], [1], []))
    def partial(fd, raw): writes.append(bytes(raw)); return 1
    monkeypatch.setattr(M.os, 'write', partial)
    with pytest.raises(M.ClosureError, match='WRITE_TIMEOUT'):
        M.child_write(SimpleNamespace(stdin=SimpleNamespace(fileno=lambda: 1)), b'abcdef', seconds=1)
    assert writes == [b'abcdef', b'bcdef'] and modes == [False, False]


@pytest.mark.skipif(os.name != 'posix', reason='Production timed pipe select is POSIX-only')
def test_actual_nonreading_child_cannot_strand_packet_write():
    # The controlled child waits on stdout-independent EOF and never reads stdin.
    # Parent owns its termination; no hosted process or shared state is involved.
    import time
    p = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(10)'], stdin=subprocess.PIPE)
    try:
        started = time.monotonic()
        with pytest.raises(M.ClosureError, match='WRITE_TIMEOUT'):
            M.child_write(p, b'x' * 194000, seconds=0.1)
        assert time.monotonic() - started < 3 and os.get_blocking(p.stdin.fileno()) is True
    finally:
        p.stdin.close(); p.kill(); p.wait(timeout=5)


@pytest.mark.parametrize('fault', ['extra', 'missing', 'bool', 'digest', 'relative', 'traversal', 'ref-extra', 'duplicate', 'noncanonical'])
def test_invalid_plan_never_reaches_host(fault):
    p = plan()
    if fault == 'extra': p['lease_held'] = True
    elif fault == 'missing': del p['recovery']
    elif fault == 'bool': p['schema_version'] = True
    elif fault == 'relative': p['export'] = 'relative'
    elif fault == 'traversal': p['classifier']['path'] = '/home/opc/../other.py'
    elif fault == 'ref-extra': p['helper']['approved'] = True
    raw = M.canonical(p)
    if fault == 'duplicate': raw = raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
    elif fault == 'noncanonical': raw = json.dumps(p).encode()
    with pytest.raises(M.ClosureError):
        M.plan_document(raw, '0' * 64 if fault == 'digest' else M.sha(raw))


def child(item, action, observed=None):
    _, database, _, _, _, a, _ = item
    source = (ROOT / 'fox/fox/verification_recovery.py').read_bytes()
    packet = {'action': action, 'recovery': base64.b64encode(source).decode(), 'recovery_sha256': M.sha(source),
        'assessment': base64.b64encode(M.canonical(a)).decode(), 'assessment_sha256': M.sha(M.canonical(a))}
    program = M.BACKEND.replace("sys.path.insert(0,'/app')", 'sys.path[:0]=' + repr([str(ROOT / 'fox'), str(ROOT / 'converter'), str(ROOT)]))
    program = program.replace("'/data/fox.sqlite3'", repr(str(database)))
    program = program.replace("'file:/data/fox.sqlite3?mode=ro'", repr(database.as_uri() + '?mode=ro'))
    # Windows select accepts sockets only; this local subprocess fixture has
    # a complete pre-supplied line. Production retains POSIX timed pipe reads.
    if os.name == 'nt':
        program = program.replace("select.select([sys.stdin],[],[],remaining)[0]", 'True')
        program = program.replace("os.read(sys.stdin.fileno(),4096)", "os.read(sys.stdin.fileno(),1)")
    input_raw = M.canonical(packet)
    if observed is not None: input_raw += M.canonical(observed)
    return subprocess.run([sys.executable, '-I', '-B', '-c', program], input=input_raw, capture_output=True, timeout=60)


def original_rows(database):
    with sqlite3.connect(database) as db:
        return recovery.VerificationRecovery._precheck_original_rows(db)


def test_actual_child_sqlite_append_preserves_originals_and_is_read_only_on_repeat(prewrite_case):
    _, database, _, _, store, a, _ = prewrite_case
    before = original_rows(database)
    status = child(prewrite_case, 'status')
    assert status.returncode == 0 and json.loads(status.stdout) == {'result': None}
    with sqlite3.connect(database) as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='verification_project_prewrite_failures'").fetchall()
    done = child(prewrite_case, 'apply', a)
    assert done.returncode == 0, done.stderr.decode()
    messages = [json.loads(line) for line in done.stdout.splitlines()]
    assert messages[0] == {'request': 'FRESH_CAPTURE_INSIDE_RESERVED_TRANSACTION'}
    assert messages[1]['result']['action'] == 'RECORDED_ONCE'
    assert original_rows(database) == before
    again = child(prewrite_case, 'apply')
    assert again.returncode == 0 and len(again.stdout.splitlines()) == 1
    assert json.loads(again.stdout)['result']['action'] == 'ALREADY_RECORDED_NO_REPLAY'
    assert store.eligibility(a['binding']['job_id'])['retry_eligible'] is False


def test_real_reserved_transaction_blocks_competing_writer(prewrite_case):
    _, database, _, _, _, a, _ = prewrite_case
    source = (ROOT / 'fox/fox/verification_recovery.py').read_bytes()
    packet = {'action': 'apply', 'recovery': base64.b64encode(source).decode(), 'recovery_sha256': M.sha(source),
        'assessment': base64.b64encode(M.canonical(a)).decode(), 'assessment_sha256': M.sha(M.canonical(a))}
    program = M.BACKEND.replace("sys.path.insert(0,'/app')", 'sys.path[:0]=' + repr([str(ROOT / 'fox'), str(ROOT / 'converter'), str(ROOT)]))
    program = program.replace("'/data/fox.sqlite3'", repr(str(database)))
    if os.name == 'nt':
        program = program.replace("select.select([sys.stdin],[],[],remaining)[0]", 'True')
        program = program.replace("os.read(sys.stdin.fileno(),4096)", "os.read(sys.stdin.fileno(),1)")
    p = subprocess.Popen([sys.executable, '-I', '-B', '-c', program], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        p.stdin.write(M.canonical(packet)); p.stdin.flush()
        assert json.loads(p.stdout.readline()) == {'request': 'FRESH_CAPTURE_INSIDE_RESERVED_TRANSACTION'}
        with sqlite3.connect(database, timeout=0) as competing:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                competing.execute('BEGIN IMMEDIATE')
        p.stdin.write(M.canonical(a)); p.stdin.close()
        assert json.loads(p.stdout.readline())['result']['action'] == 'RECORDED_ONCE'
        assert p.wait(timeout=60) == 0
    finally:
        if p.poll() is None: p.kill(); p.wait()


def test_changed_fresh_observation_rolls_back_append_but_preserves_explicit_initialization(prewrite_case):
    _, database, _, _, store, a, _ = prewrite_case
    changed = deepcopy(a); changed['capture_sha256'] = '0' * 64
    before = original_rows(database)
    done = child(prewrite_case, 'apply', changed)
    assert done.returncode != 0
    with sqlite3.connect(database) as db:
        assert db.execute('SELECT count(*) FROM verification_project_prewrite_failures').fetchone()[0] == 0
    assert original_rows(database) == before
    assert store.eligibility(a['binding']['job_id'])['blocks_admission'] is True


def test_lost_parent_response_rolls_back_and_releases_sqlite_writer(prewrite_case):
    _, database, _, _, _, _, _ = prewrite_case
    before = original_rows(database)
    done = child(prewrite_case, 'apply')  # EOF instead of an observer reply
    assert done.returncode != 0
    with sqlite3.connect(database, timeout=0) as db:
        db.execute('BEGIN IMMEDIATE')
        assert db.execute('SELECT count(*) FROM verification_project_prewrite_failures').fetchone()[0] == 0
    assert original_rows(database) == before


def test_lost_reply_after_actual_append_is_inspected_without_second_append(prewrite_case, monkeypatch, capsys):
    _, database, _, _, _, a, _ = prewrite_case
    before = original_rows(database)
    done = child(prewrite_case, 'apply', a)
    assert done.returncode == 0  # committed reply is deliberately lost here
    def lost(**kwargs): raise RuntimeError('PRIVATE_LOST_REPLY')
    monkeypatch.setattr(M, 'protected_read', lambda *args, **kwargs: M.canonical(plan()))
    monkeypatch.setattr(M, 'Adapter', lambda _: SimpleNamespace(run=lost))
    p = plan(); assert M.main(['--plan', '/home/opc/plan', '--plan-sha256', M.sha(M.canonical(p)), '--apply']) == 1
    attention = json.loads(capsys.readouterr().out)
    assert attention['status'] == 'ATTENTION' and attention['automatic_replay_permitted'] is False
    assert 'PRIVATE_LOST_REPLY' not in json.dumps(attention)
    status = child(prewrite_case, 'status')
    assert status.returncode == 0 and json.loads(status.stdout)['result']['action'] == 'ALREADY_RECORDED_NO_REPLAY'
    assert original_rows(database) == before
    with sqlite3.connect(database) as db:
        assert db.execute('SELECT count(*) FROM verification_project_prewrite_failures').fetchone()[0] == 1


def test_actual_online_sqlite_backup_is_readable_and_keeps_original_rows(prewrite_case, tmp_path):
    _, database, _, _, _, _, _ = prewrite_case
    done = child(prewrite_case, 'backup')
    assert done.returncode == 0, done.stderr.decode()
    raw = base64.b64decode(json.loads(done.stdout)['result']['sqlite_b64'], validate=True)
    target = tmp_path / 'backup.sqlite3'; target.write_bytes(raw)
    assert original_rows(database) == original_rows(target)
    with sqlite3.connect(target) as db: assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)


def test_real_os_lease_contends_and_expires(tmp_path, monkeypatch):
    from qa.operator import clean_install as clean, runtime_provider
    from qa.operator.failed_verification import FailureResolutionError
    private = tmp_path / 'private'; private.mkdir(mode=0o700)
    monkeypatch.setattr(clean, 'private_root', lambda: private)
    monkeypatch.setattr(runtime_provider, 'selected_hosted', lambda: None)
    monkeypatch.setattr(verifier, 'JOURNAL_ROOT', private / 'product-verifier')
    journal = verifier.PrivateJournal('a' * 64)
    with journal.lock() as lease:
        lease.require_active('a' * 64, journal.root)
        with pytest.raises(verifier.ProductVerifierError, match='ANOTHER_PRODUCT_VERIFIER'):
            with journal.lock(create=False): pytest.fail('Contended OS lease was granted')
        with pytest.raises(FailureResolutionError): lease.require_active('b' * 64, journal.root)
    with pytest.raises(FailureResolutionError): lease.require_active('a' * 64, journal.root)


@pytest.mark.skipif(os.name != 'posix', reason='Host owner/mode/no-follow checks require POSIX')
def test_protected_input_rejects_link_and_public_private_file(tmp_path):
    target = tmp_path / 'input.json'; target.write_bytes(b'{}\n'); target.chmod(0o600)
    assert M.protected_read(target, private=True) == b'{}\n'
    target.chmod(0o644)
    with pytest.raises(M.ClosureError, match='PRIVATE_INPUT'): M.protected_read(target, private=True)
    linked = tmp_path / 'linked'; linked.symlink_to(target)
    with pytest.raises(M.ClosureError): M.protected_read(linked)
