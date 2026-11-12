"""Offline modeled journal/clock; execute the actual serialized idle branch only.

No controller import, subprocess, service, provider or real journal is used.
This proves observation contracts, not installed-flow or conversion acceptance.
"""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


CONTROLLER = Path(__file__).resolve().parents[1] / 'current_pair_transition.py'


def idle_branch():
    source = ast.parse(CONTROLLER.read_text(encoding='utf-8'))
    assignments = [node for node in source.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'NEW_PROBE'
                           for target in node.targets)]
    assert len(assignments) == 1, 'Cannot uniquely extract actual NEW_PROBE'
    probe = ast.parse(ast.literal_eval(assignments[0].value))
    matches = [node for node in ast.walk(probe) if isinstance(node, ast.If)
               and ast.unparse(node.test) == "p['mode'] == 'idle'"]
    assert len(matches) == 1, 'Cannot uniquely extract actual idle branch'
    return ast.Module(body=matches[0].body, type_ignores=[])


class Clock:
    def __init__(self):
        self.now = 0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds == 1
        self.sleeps.append(seconds)
        self.now += seconds
        assert self.now <= 181, 'Observer must remain bounded'


class JournalPath:
    """In-memory paths expose authored evidence only, never create a claim."""
    name = 'session-synthetic'

    def __init__(self, journal, member=None):
        self.journal, self.member = journal, member

    def __truediv__(self, member):
        return JournalPath(self.journal, member)

    def exists(self):
        if self.member is None:
            return self.journal.root_exists
        if self.journal.clock.now < self.journal.arrives:
            return False
        return self.member in self.journal.files

    def glob(self, pattern):
        assert pattern == 'session-*'
        return [self]


class Journal:
    def __init__(self, clock, arrives):
        self.clock, self.arrives = clock, arrives
        self.root_exists = True
        self.root = JournalPath(self)
        self.files = {
            'session.json': {'release_sha256': 'a' * 64,
                             'startup_authorized': True, 'bounds': {'max_jobs': 1}},
            'p0001-claim.intent.json': {
                'scope': 'fox-product-verifier-step-v1', 'release_sha256': 'a' * 64,
                'step': 'p0001-claim', 'binding_sha256': None},
        }
        self.files['p0001-claim.complete.json'] = {
            'result': {'status': 'IDLE'},
            'intent_sha256': hashlib.sha256(self.raw(self.root, 'p0001-claim.intent.json')).hexdigest()}
        self.seal_valid = True
        self.seal_checks = []

    def read(self, directory, member):
        assert directory is self.root
        return deepcopy(self.files[member])

    def raw(self, directory, member):
        return json.dumps(self.read(directory, member), sort_keys=True).encode()

    def _check_seal(self, directory, complete):
        assert directory is self.root
        self.seal_checks.append(deepcopy(complete))
        assert self.seal_valid, 'SYNTHETIC_INVALID_NORMAL_SEAL'


def harness(arrives=30):
    clock = Clock()
    journal = Journal(clock, arrives)
    checks = []

    def check():
        checks.append(clock.now)
        return {'status': 'CHECKED_NOT_STARTED'}

    admission = SimpleNamespace(release='a' * 64,
                                document={'bounds': {'max_jobs': 1}}, check=check)

    def private_journal(release):
        assert release == admission.release
        return journal

    namespace = {'time': clock, 'verifier': SimpleNamespace(PrivateJournal=private_journal),
                 'admission': admission, 'json': json, 'hashlib': hashlib}
    return SimpleNamespace(clock=clock, journal=journal, checks=checks, namespace=namespace)


def observe(state):
    before = deepcopy(state.journal.files)
    try:
        exec(compile(idle_branch(), str(CONTROLLER) + ':NEW_PROBE.idle', 'exec'), state.namespace)
    finally:
        assert state.journal.files == before, 'Observer changed original journal evidence'
    return state.namespace['result']


@pytest.mark.parametrize('arrives', [30, 95, 179])
def test_genuine_delayed_idle_accepted_without_batch_success(arrives):
    state = harness(arrives)
    result = observe(state)
    assert state.clock.now == arrives
    assert state.checks == [arrives]
    assert state.journal.seal_checks == []  # First idle need not finish the batch.
    assert result == {
        'status': 'GENUINE_NEW_VERIFIER_IDLE_CLAIM', 'session': 'session-synthetic',
        'claim_complete_sha256': hashlib.sha256(
            state.journal.raw(state.journal.root, 'p0001-claim.complete.json')).hexdigest(),
        'release_sha256': 'a' * 64, 'batch_completion_claimed': False}


@pytest.mark.parametrize('missing', ['late', 'no-root', 'no-claim'])
def test_missing_witness_expires_without_restart_or_synthetic_claim(missing):
    state = harness(181 if missing == 'late' else 0)
    if missing == 'no-root':
        state.journal.root_exists = False
    if missing == 'no-claim':
        del state.journal.files['p0001-claim.complete.json']
    with pytest.raises(AssertionError, match='^NO_NEW_VERIFIER_IDLE_WITNESS$'):
        observe(state)
    assert state.clock.now == 180
    assert state.checks == []
    assert state.namespace['result'] is None


@pytest.mark.parametrize('fault', [
    'attention', 'release', 'startup', 'bounds', 'intent', 'hash', 'nonidle', 'unknown'])
def test_wrong_or_unknown_witness_refused_before_admission(fault):
    state = harness(0)
    files = state.journal.files
    if fault == 'attention':
        files['attention.json'] = {'status': 'ATTENTION'}
    elif fault == 'release':
        files['session.json']['release_sha256'] = 'b' * 64
    elif fault == 'startup':
        files['session.json']['startup_authorized'] = False
    elif fault == 'bounds':
        files['session.json']['bounds'] = {'max_jobs': 2}
    elif fault == 'intent':
        files['p0001-claim.intent.json']['step'] = 'p0002-claim'
        files['p0001-claim.complete.json']['intent_sha256'] = hashlib.sha256(
            state.journal.raw(state.journal.root, 'p0001-claim.intent.json')).hexdigest()
    elif fault == 'hash':
        files['p0001-claim.complete.json']['intent_sha256'] = '0' * 64
    else:
        files['p0001-claim.complete.json']['result'] = {
            'status': 'CLAIMED' if fault == 'nonidle' else 'UNKNOWN'}
    with pytest.raises(AssertionError):
        observe(state)
    assert state.namespace['result'] is None
    assert state.checks == []


@pytest.mark.parametrize('fault', [None, 'seal', 'status', 'jobs'])
def test_completed_session_still_requires_normal_valid_empty_batch_seal(fault):
    state = harness(0)
    complete = {'status': 'SESSION_COMPLETE', 'completed_jobs': []}
    state.journal.files['complete.json'] = complete
    if fault == 'seal':
        state.journal.seal_valid = False
    elif fault == 'status':
        complete['status'] = 'UNKNOWN'
    elif fault == 'jobs':
        complete['completed_jobs'] = ['synthetic-job']
    if fault is None:
        result = observe(state)
        assert state.journal.seal_checks == [complete]
        assert result['batch_completion_claimed'] is False
    else:
        with pytest.raises(AssertionError):
            observe(state)
        assert state.checks == []
        assert state.namespace['result'] is None
        assert len(state.journal.seal_checks) == (1 if fault == 'seal' else 0)


def test_actual_idle_branch_has_only_observation_calls_no_restart_or_claim_writer():
    calls = {ast.unparse(node.func) for node in ast.walk(idle_branch())
             if isinstance(node, ast.Call)}
    assert calls == {
        'verifier.PrivateJournal', 'time.monotonic', 'journal.root.exists',
        'sorted', 'journal.root.glob', "(directory / 'attention.json').exists",
        "(directory / 'p0001-claim.complete.json').exists", 'journal.read',
        'journal.raw', 'json.loads', 'hashlib.sha256',
        'hashlib.sha256(intent).hexdigest', "(directory / 'complete.json').exists",
        'journal._check_seal',
        "hashlib.sha256(journal.raw(directory, 'p0001-claim.complete.json')).hexdigest",
        'time.sleep', 'admission.check'}
