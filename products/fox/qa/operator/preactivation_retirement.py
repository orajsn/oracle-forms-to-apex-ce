"""Explicit G retirement before a distinct release is activated.

This is a new authority, not an I InstalledRuntime and not a G pump. The G
transport measures the still-running G image, mounted profile, environment and
modules. Frozen I supplies only its pure idle parser, recorded Win32 observer
and read-only history/idle source builders. No old driver is executed.

Use in a fresh ``python -I -B`` process. Opening the context reads source only;
``hold()`` acquires existing C/F/G OS leases. ``plan_under_lock()`` reads real
local and remote evidence. Only ``close_idle_under_lock(apply=True,
authorized_plan_sha256=...)`` can add the one new closure file. No queue, QA,
model, import, cloud configuration, process control or deployment is exposed.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.abc
import importlib.machinery
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from types import ModuleType, SimpleNamespace

SCOPE = 'fox-preactivation-retirement-context-v1'
PLAN_SCOPE = 'fox-preactivation-idle-retirement-plan-v1'
CLOSURE_SCOPE = 'fox-preactivation-interrupted-idle-closure-v1'
STATUS = 'INTERRUPTED_IDLE_CLOSED'
SOURCE_CONTEXT = 'preactivation-g-v1'
G_RELEASE = 'acc3bf901d6f221cc5b887afe88a5cd53b9b4a8153e820b1f078b10d679004ba'
G_EVIDENCE = 'e6e90f551064794cf18b0422f61a1ba88fab8d76c12f2612e6596dd415183435'
A1 = {'job_id': 'fox-7957b40cac8d4ed8a558',
      'package_sha256': '6941b7f6224d6571e122104055ba2652696309fdc5b5fa7bd2da5aa5a2683b91',
      'proof_sha256': '7bdf0d32ff2bd3f342f14d726e933cb4add166387ae8b8f8f5fc90fcfd5af232'}
ROLES = ('failure', 'retry', 'idle')
HELPERS = ('idle_recovery.py', 'idle_remote.py', 'recorded_native.py', 'history_executor.py', 'win_process.py')
SHA = re.compile(r'[a-f0-9]{64}\Z')
SESSION = re.compile(r'session-[a-f0-9]{24}\Z')


class PreActivationError(RuntimeError):
    """Bounded public diagnostics only."""


def need(value, code):
    if not value:
        raise PreActivationError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def relative(value):
    need(type(value) is str and value and '\\' not in value and ':' not in value,
         'PREACTIVATION_RELATIVE_SOURCE_REQUIRED')
    path = PurePosixPath(value)
    need(not path.is_absolute() and str(path) == value and all(x not in ('', '.', '..') for x in path.parts),
         'PREACTIVATION_RELATIVE_SOURCE_REQUIRED')
    return value


def read(path, expected=None):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
             'PREACTIVATION_SOURCE_LINK_FORBIDDEN')
    before = path.stat()
    need(path.resolve() == path and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and 0 < before.st_size <= 32_000_000, 'PREACTIVATION_SOURCE_UNSAFE')
    raw = path.read_bytes()
    after = path.stat()
    need((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
         and len(raw) == before.st_size and (expected is None or sha(raw) == expected),
         'PREACTIVATION_SOURCE_CHANGED')
    return raw


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'PREACTIVATION_DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    need(type(value) is dict and canonical(value) == raw, 'PREACTIVATION_CANONICAL_JSON_REQUIRED')
    return value


def private_inputs(paths):
    """New explicit read-only ACL adapter; never changes any ACL.

    The isolated G namespace selects this function instead of the legacy
    Get-Acl autoload-dependent function. Its source is independently included
    in the retirement authority. Frozen source files are never patched.
    """
    need(os.name == 'nt', 'PREACTIVATION_WINDOWS_REQUIRED')
    for path in paths:
        path = Path(path)
        need(path.is_absolute() and path.exists() and path.resolve() == path,
             'PREACTIVATION_PRIVATE_PATH_UNSAFE')
        for part in (path, *path.parents):
            info = part.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                 'PREACTIVATION_PRIVATE_PATH_UNSAFE')
    program = r'''$ErrorActionPreference='Stop'; $v=([Console]::In.ReadToEnd()|ConvertFrom-Json)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach($p in $v.paths) {
 $acl=if([IO.Directory]::Exists($p)){[IO.Directory]::GetAccessControl($p)}else{[IO.File]::GetAccessControl($p)}
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid){throw 'Wrong owner'}
 foreach($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -ne $sid){throw 'Unexpected reader'}
 }
}
Write-Output 'PRIVATE_COLLECTION_VERIFIED'
'''
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', program],
        input=json.dumps({'paths': [str(x) for x in paths]}).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30)
    need(result.returncode == 0 and not result.stderr.strip()
         and result.stdout.strip() == b'PRIVATE_COLLECTION_VERIFIED', 'PREACTIVATION_PRIVATE_ACL_REQUIRED')


def _load(name, path, expected):
    raw = read(path, expected)
    module = ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class _MeasuredSourceLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Compile measured G source bytes; never consult a cached .pyc."""
    def __init__(self, root, sources):
        self.root, self.sources = root, sources

    def find_spec(self, fullname, path=None, target=None):
        prefix = fullname.split('.')[0]
        if prefix not in ('qa', 'fox', 'forms2apex'):
            return None
        outer = {'qa': '', 'fox': 'fox', 'forms2apex': 'converter'}[prefix]
        relative_path = '/'.join(filter(None, (outer, fullname.replace('.', '/'))))
        for name, package in ((relative_path + '/__init__.py', True), (relative_path + '.py', False)):
            if name in self.sources:
                spec = importlib.machinery.ModuleSpec(fullname, self, origin=str(self.root / name), is_package=package)
                spec.loader_state = name
                if package:
                    spec.submodule_search_locations = [str((self.root / name).parent)]
                return spec
        need(fullname in ('qa', 'qa.operator'), 'PREACTIVATION_UNMEASURED_IMPORT_FORBIDDEN')
        spec = importlib.machinery.ModuleSpec(fullname, loader=None, is_package=True)
        spec.submodule_search_locations = [str(self.root / relative_path)]
        return spec

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        name = module.__spec__.loader_state
        path, expected = self.sources[name]
        module.__file__ = str(path)
        exec(compile(read(path, expected), str(path), 'exec'), module.__dict__)


def fresh_observation(value, now=None):
    """Final commit gate, before the first create-only write."""
    now = datetime.now(timezone.utc) if now is None else now
    need(type(value) is dict and set(value) == {'native_before', 'remote', 'native_after'},
         'PREACTIVATION_OBSERVATION_REQUIRED')
    timestamps = {}
    for key in ('native_before', 'remote', 'native_after'):
        stamp = value[key].get('observed_at_utc')
        need(type(stamp) is str and re.fullmatch(
            r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', stamp),
            'PREACTIVATION_OBSERVATION_UTC_REQUIRED')
        observed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        timestamps[key] = observed
        need(-5 <= (now - observed).total_seconds() <= 30, 'PREACTIVATION_OBSERVATION_EXPIRED_BEFORE_WRITE')
    need(0 <= (timestamps['native_after'] - timestamps['native_before']).total_seconds() <= 150
         and 0 <= (now - timestamps['native_after']).total_seconds() <= 30,
         'PREACTIVATION_OBSERVATION_ORDER_INVALID')


class PreActivationIdleReader:
    """Only this new context interprets its separately versioned closure."""
    def __init__(self, context, original):
        self.context, self.original = context, original
        for name in ('native', 'remote', 'journal', 'directory', 'manifest', 'api'):
            setattr(self, name, getattr(original, name))

    def _read_under_lock(self):
        context = self.context
        context.require_active()
        value = context._transcript()
        closure = self.journal.read(self.directory, 'closed-idle.json')
        keys = {'schema_version', 'scope', 'status', 'source_context', 'authorized_plan_sha256',
                'retirement_plan', *value, 'observation', 'successful_native_exit_confirmed',
                'automatic_replay_permitted', 'human_acceptance_recorded', 'closed_at_utc'}
        need(set(closure) == keys and type(closure['schema_version']) is int and closure['schema_version'] == 1
             and closure['scope'] == CLOSURE_SCOPE and closure['status'] == STATUS
             and closure['source_context'] == SOURCE_CONTEXT and all(closure[k] == v for k, v in value.items())
             and all(closure[k] is False for k in ('successful_native_exit_confirmed',
                  'automatic_replay_permitted', 'human_acceptance_recorded')),
             'PREACTIVATION_CLOSURE_CHANGED')
        plan = context._plan_document(value, closure['retirement_plan']['native_retained_identity'])
        need(plan == closure['retirement_plan'] and sha(canonical(plan)) == closure['authorized_plan_sha256'],
             'PREACTIVATION_CLOSURE_PLAN_CHANGED')
        saved = closure['observation']
        need(type(saved) is dict and set(saved) == {'native_before', 'remote', 'native_after'},
             'PREACTIVATION_SAVED_OBSERVATION_CHANGED')
        idle = context.helpers['idle_recovery']
        closed_at = idle.timestamp(closure['closed_at_utc'])
        before, after = (idle.timestamp(saved[key]['observed_at_utc']) for key in ('native_before', 'native_after'))
        need(0 <= (after - before).total_seconds() <= 150 and 0 <= (closed_at - after).total_seconds() <= 30
             and closed_at <= datetime.now(timezone.utc), 'PREACTIVATION_CLOSURE_TIME_CHANGED')
        for item in (saved['native_before'], saved['native_after']):
            need(self.native.retained_identity(item) == plan['native_retained_identity'],
                 'PREACTIVATION_SAVED_NATIVE_CHANGED')
        self.remote.validate(saved['remote'], value['completed_jobs'], require_idle=True, now=after,
                             max_age_seconds=150, historical=False)
        observed = context._observe(value)
        need(self.native.retained_identity(observed['native_after']) == plan['native_retained_identity'],
             'PREACTIVATION_NATIVE_CHANGED')
        return {'status': STATUS, 'release_sha256': context.release, 'ready': True}


class PreActivationRetirementContext:
    """Construct with open_context; no injectable observer/lease/transport seam."""
    def __init__(self, token, *, workspace, source_root, authority_root, authority_raw,
                 configuration_raw, source_files, helpers):
        need(token is _CONSTRUCTION, 'PREACTIVATION_FACTORY_REQUIRED')
        self.workspace, self.source_root, self.authority_root = workspace, source_root, authority_root
        self.authority_manifest_raw, self.authority_release = authority_raw, sha(authority_raw)
        self.authority_configuration_raw = configuration_raw
        self._sources, self.helpers = source_files, helpers
        self.current_raw = read(source_root / 'current-release-manifest.json', G_RELEASE)
        self.release, self.manifest = G_RELEASE, parse(self.current_raw)
        original = parse(configuration_raw)
        need(original.get('schema_version') == 2 and original.get('scope') == 'fox-installed-history-operator-v2'
             and original.get('current_release_sha256') == self.authority_release
             and set(original.get('history', {})) == set(ROLES), 'PREACTIVATION_CONFIGURATION_CHANGED')
        self.history = original['history']
        need(self.history['idle']['release_sha256'] == G_RELEASE
             and self.history['idle']['native_reference'] == 'installed://jsn/g-normal-session'
             and len({entry['release_sha256'] for entry in self.history.values()}) == 3
             and all(SESSION.fullmatch(entry['session_id']) for entry in self.history.values()),
             'PREACTIVATION_HISTORY_CHANGED')
        self.configuration = {'schema_version': 1, 'scope': SCOPE, 'source_context': SOURCE_CONTEXT,
            'current_release_sha256': self.release, 'authority_release_sha256': self.authority_release,
            'authority_configuration_sha256': sha(configuration_raw), 'history': self.history,
            'infrastructure': original['infrastructure'], 'automatic_replay_permitted': False}
        self.configuration_sha256 = sha(canonical(self.configuration))
        self._configuration_raw = canonical(self.configuration)
        self.historical_raw = {role: read(authority_root / 'historical-manifests' / (letter + '.json'),
            self.history[role]['release_sha256']) for role, letter in zip(ROLES, ('c', 'f', 'g'))}
        need(self.historical_raw['idle'] == self.current_raw, 'PREACTIVATION_G_MANIFEST_CHANGED')
        modules = {label: importlib.import_module(name) for label, name in (
            ('product', 'qa.operator.product_verifier'), ('bridge', 'qa.operator.product_queue_transport'),
            ('clean', 'qa.operator.clean_install'), ('failure', 'qa.operator.failed_verification'),
            ('transport', 'qa.operator.failure_recovery_transport'), ('reader', 'qa.operator.closed_failure_reader'),
            ('qa', 'qa.operator.native_qa_dispatch'), ('backend', 'fox.verification_recovery'))}
        self.components = c = SimpleNamespace(**modules)
        # Explicit new adapter selection in this fresh, isolated read namespace.
        c.product.promotion.private_inputs = private_inputs
        self.qa_provider = c.qa  # source-only descriptor selection, no QA executor
        need(c.clean.PRIVATE == workspace / 'work/private/clean-install', 'PREACTIVATION_PRIVATE_ROOT_CHANGED')
        self.journals = {role: c.product.PrivateJournal(entry['release_sha256'])
                         for role, entry in self.history.items()}
        self.current = self.journals['idle']
        self.current._historical = (self.journals['failure'], self.journals['retry'])
        c.current, c.historical, c.previous = self.current, self.journals['failure'], self.journals['retry']
        c.manifest, c.current_raw, c.historical_raw = self.manifest, self.current_raw, self.historical_raw['failure']
        c.source = read(source_root / 'fox/fox/verification_recovery.py', self.manifest['modules']['verification_recovery.py'])
        old = self.history['failure']
        wrapper = read(source_root / 'qa/operator/qa/run-jsn-qa.sh', old['original_wrapper_sha256'])
        marker = b"image='localhost/fox-native-qa:pw1.64.0'"
        need(wrapper.count(marker) == 1, 'PREACTIVATION_WRAPPER_CHANGED')
        wrapper = wrapper.replace(marker, ("image='" + old['qa_image_id'][7:] + "'").encode(), 1)
        need(sha(wrapper) == old['wrapper_sha256'], 'PREACTIVATION_WRAPPER_CHANGED')
        reviewed = c.backend.ReviewedSynchronousLaunch(old['release_sha256'], old['qa_source_sha256'],
            old['wrapper_sha256'], old['original_wrapper_sha256'], old['qa_image_id'])
        c.resolver = c.failure.FailureResolver(manifest=parse(c.historical_raw),
            expected_release_sha256=old['release_sha256'], historical_manifest_raw=c.historical_raw,
            session=c.historical.root / old['session_id'], expected_collection_sha256=old['collection_sha256'],
            allow_apply=False, privacy_check=private_inputs,
            reviewed_synchronous_launch=reviewed, wrapper_raw=wrapper)
        self.bound_container_id = self.configuration['infrastructure']['fox']['id']
        current_pin = c.transport.CurrentRuntimePin(self.current_raw, self.release, self.bound_container_id,
            self.manifest['modules']['verification_recovery.py'])
        retry = {key: self.history['retry'][key] for key in ('attempt_id', 'proof_sha256', 'release_sha256', 'job_id')}
        executor = helpers['history_executor'].HistoryExecutor(self, current_pin, completed_retry=retry)
        wire = c.transport.HistoricalClosedReadTransport(
            c.transport.HistoricalRelease(c.historical_raw, old['release_sha256']), current_pin,
            source=c.source, executor=executor)
        self.failure_reader = c.reader.ClosedFailureReader(enabled=True, resolver=c.resolver,
            store=c.transport.ClosedFailureReadAdapter(c.resolver, wire), job_id=old['job_id'],
            release_sha256=old['release_sha256'], disposition_sha256=old['disposition_sha256'])
        cfg = self.history['idle']
        native = helpers['recorded_native'].RecordedNativeObserver(c.clean.PRIVATE / 'history-managed-pump-20261019a',
            cfg['native_source_sha256'], self.release, profile='recorded-legacy-g-v1',
            script_path=workspace / 'work/product-history-managed-journey-20261019a/pump_session.py',
            native_helper_path=authority_root / 'qa/operator/win_process.py', privacy=private_inputs,
            current_runtime_path=Path(sys._base_executable).absolute())
        remote = helpers['idle_remote'].RemoteIdleObserver(c.product, self.manifest, self.release,
            self.configuration['infrastructure'], qa_provider=self.qa_provider)
        original_reader = helpers['idle_recovery'].IdleClosureReader(c.product, self.current,
            self.current.root / cfg['session_id'], self.manifest, native, remote, admission_journal=self.current)
        self.idle_reader = PreActivationIdleReader(self, original_reader)
        self.read_hashes, self._held, self._closed_once = [], False, False
        self.ready()

    def source_files(self):
        return {name: read(path, expected) for name, (path, expected) in self._sources.items()}

    def ready(self):
        need(type(self) is PreActivationRetirementContext and os.name == 'nt', 'PREACTIVATION_EXACT_WINDOWS_CONTEXT_REQUIRED')
        self.source_files()
        need(canonical(self.configuration) == self._configuration_raw, 'PREACTIVATION_CONFIGURATION_CHANGED')
        self.components.bridge.require_ready(self.manifest, self.release, qa_provider=self.qa_provider)
        need(type(self.idle_reader) is PreActivationIdleReader
             and type(self.idle_reader.original) is self.helpers['idle_recovery'].IdleClosureReader
             and type(self.idle_reader.native) is self.helpers['recorded_native'].RecordedNativeObserver
             and type(self.idle_reader.remote) is self.helpers['idle_remote'].RemoteIdleObserver
             and self.idle_reader.native.profile == 'recorded-legacy-g-v1'
             and self.components.product.promotion.private_inputs is private_inputs
             and self.components.resolver.privacy_check is private_inputs
             and self.idle_reader.native.privacy is private_inputs and self.idle_reader.native._test_open is None,
             'PREACTIVATION_REAL_OBSERVERS_REQUIRED')

    @contextmanager
    def hold(self):
        need(not self._held, 'PREACTIVATION_NESTED_HOLD_FORBIDDEN')
        self.ready()
        self.current._check_history_inventory()
        with ExitStack() as stack:
            for journal in sorted(self.journals.values(), key=lambda item: str(item.root)):
                # existing=True cannot manufacture a release binding or lock.
                stack.enter_context(journal._lock_one(existing=True))
            self._held = True
            try:
                self.require_active()
                yield self
            finally:
                self._held = False

    def _leases(self):
        need(self._held and self.current is self.journals['idle']
             and self.current._historical == (self.journals['failure'], self.journals['retry']),
             'PREACTIVATION_ACTUAL_HOLD_REQUIRED')
        for role, journal in self.journals.items():
            need(type(journal) is self.components.product.PrivateJournal
                 and journal.release == self.history[role]['release_sha256']
                 and journal.root == self.components.product.JOURNAL_ROOT / journal.release[:16]
                 and type(journal._held) is self.components.failure.HeldOperatorLock,
                 'PREACTIVATION_ACTUAL_LEASE_REQUIRED')
            journal._held.require_active(journal.release, journal.root)
        self.current._check_history_inventory()

    def completed_retry_binding(self):
        self._leases()
        cfg, journal = self.history['retry'], self.journals['retry']
        directory = journal.root / cfg['session_id']
        raw = journal.raw(directory, 'reconciled.json')
        terminal = parse(raw)
        expected = {'status': 'PROOF_RECONCILED', 'release_sha256': cfg['release_sha256'],
            'job_id': cfg['job_id'], 'attempt_id': cfg['attempt_id'], 'proof_sha256': cfg['proof_sha256'],
            'automatic_replay_permitted': False, 'retained_sha256': terminal.get('retained_sha256')}
        need(terminal == expected and sha(raw) == cfg['seal_sha256']
             and cfg['job_id'] == self.history['failure']['job_id'], 'PREACTIVATION_RETRY_SEAL_CHANGED')
        journal._check_seal(directory, terminal)
        expected.pop('retained_sha256')
        need(journal.completed_result(directory, 'proof-reconcile') == expected
             and journal.completed_result(directory, 'p0001-continuation-promotion-apply') == {
                 'status': 'VERIFIED', 'job_id': cfg['job_id'], 'human_acceptance_recorded': False,
                 'proof_sha256': cfg['proof_sha256']}, 'PREACTIVATION_RETRY_PROOF_CHANGED')
        return {key: terminal[key] for key in ('attempt_id', 'proof_sha256', 'release_sha256', 'job_id')}

    def require_active(self):
        self.ready()
        self._leases()
        self.completed_retry_binding()

    def _transcript(self):
        self.require_active()
        for role, journal in self.journals.items():
            need({path.name for path in journal.root.iterdir()} ==
                 {'worker.lock', 'release.json', self.history[role]['session_id']},
                 'PREACTIVATION_UNKNOWN_OR_EXTRA_SESSION')
        ack = self.components.resolver._validated_closed_under_lock(self.journals['failure']._held)
        need(ack.get('status') == 'FAILED_QA_RECORDED'
             and ack.get('disposition_sha256') == self.history['failure']['disposition_sha256'],
             'PREACTIVATION_FAILURE_CHANGED')
        value = self.helpers['idle_recovery'].transcript(self.components.product, self.current,
            self.idle_reader.directory, self.manifest, admission_journal=self.current)
        need(len(value['completed_jobs']) == 1 and value['completed_jobs'][0]['proof_sha256'] == A1['proof_sha256']
             and value['completed_jobs'][0]['binding']['job_id'] == A1['job_id']
             and value['completed_jobs'][0]['binding']['package_sha256'] == A1['package_sha256'],
             'PREACTIVATION_ORIGINAL_A1_REQUIRED')
        return value

    def _observe(self, value):
        self.require_active()
        before = self._journal_bytes()
        prefix = 'idle/' + self.history['idle']['session_id'] + '/'
        retained = {name[len(prefix):]: digest for name, digest in before.items()
                    if name.startswith(prefix) and name != prefix + 'closed-idle.json'}
        need(retained == value['retained_sha256'], 'PREACTIVATION_TRANSCRIPT_CHANGED_BEFORE_READ')
        # Original typed C read additionally checks the exact F completed
        # attempt/proof and full job union, without changing either disposition.
        result = self.failure_reader._check_under_lock(self.journals['failure']._held)
        need(result.get('status') == 'CLOSED_FAILURE_READ_READY' and result.get('ready') is True,
             'PREACTIVATION_REMOTE_C_F_UNCONFIRMED')
        observation = self.idle_reader.original._observe(value, require_idle=True)
        # Preserve the already parsed schemas by exact byte equality, rather
        # than launching one ACL subprocess per file again after observation.
        need(self._journal_bytes() == before, 'PREACTIVATION_TRANSCRIPT_CHANGED_DURING_READ')
        fresh_observation(observation)
        return observation

    def _held_lock_bytes(self, journal):
        """Read the locked byte through its owning fd, never another handle.

        Windows byte-range locks deny a new file handle's overlapping read,
        including a second handle in the same process. Preserve the actual
        lease, fd position and file identity rather than temporarily unlocking.
        """
        lease = journal._held
        need(type(lease) is self.components.failure.HeldOperatorLock,
             'PREACTIVATION_ACTUAL_LEASE_REQUIRED')
        lease.require_active(journal.release, journal.root)
        path = journal.root / 'worker.lock'
        stream = lease._stream
        before = os.fstat(stream.fileno())
        current = path.stat()
        # Windows stat(path) and fstat(fd) can expose different ctime values
        # for the same unchanged file. Compare identity across APIs, then keep
        # each API's complete timestamp snapshot stable against itself.
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode, info.st_nlink)
        stable = lambda info: (*identity(info), info.st_ctime_ns)
        need(identity(before) == identity(current) and before.st_size == 1
             and stat.S_ISREG(before.st_mode) and before.st_nlink == current.st_nlink == 1,
             'PREACTIVATION_LOCK_IDENTITY_CHANGED')
        position = stream.tell()
        try:
            stream.seek(0)
            raw = stream.read(2)
        finally:
            stream.seek(position)
        lease.require_active(journal.release, journal.root)
        need(raw == b'0' and stable(os.fstat(stream.fileno())) == stable(before)
             and stable(path.stat()) == stable(current), 'PREACTIVATION_LOCK_BYTES_CHANGED')
        return raw

    def _journal_bytes(self):
        self._leases()
        paths = []
        names = {}
        locks = {}
        for role, journal in self.journals.items():
            paths.append(journal.root)
            session = journal.root / self.history[role]['session_id']
            need({path.name for path in journal.root.iterdir()} == {'worker.lock', 'release.json', session.name}
                 and session.is_dir(), 'PREACTIVATION_JOURNAL_INVENTORY_CHANGED')
            paths.append(session)
            files = [journal.root / 'worker.lock', journal.root / 'release.json', *session.iterdir()]
            need(all(path.is_file() for path in files), 'PREACTIVATION_JOURNAL_DIRECTORY_FORBIDDEN')
            for path in sorted(files):
                paths.append(path)
                names[role + '/' + path.relative_to(journal.root).as_posix()] = path
                if path == journal.root / 'worker.lock':
                    locks[path] = journal
        need(len(paths) <= 4096 and len(names) <= 4096, 'PREACTIVATION_JOURNAL_BOUNDS')
        private_inputs(paths)
        return {name: sha(self._held_lock_bytes(locks[path]) if path in locks else read(path))
                for name, path in names.items()}

    def _plan_document(self, value, native_identity):
        return {'schema_version': 1, 'scope': PLAN_SCOPE, 'source_context': SOURCE_CONTEXT,
            'runtime_release_sha256': self.release, 'runtime_container_id': self.bound_container_id,
            'authority_release_sha256': self.authority_release, 'configuration_sha256': self.configuration_sha256,
            'source_reader_files': {name: sha(raw) for name, raw in self.source_files().items()},
            'history': self.history, 'transcript_sha256': sha(canonical(value)),
            'native_retained_identity': native_identity, 'closure_name': 'closed-idle.json',
            'closure_scope': CLOSURE_SCOPE, 'successful_native_exit_confirmed': False,
            'deployment_authorized': False, 'human_acceptance_recorded': False, 'automatic_replay_permitted': False}

    def plan_under_lock(self):
        value = self._transcript()
        observation = self._observe(value)
        plan = self._plan_document(value, self.idle_reader.native.retained_identity(observation['native_after']))
        return {'plan': plan, 'plan_sha256': sha(canonical(plan)), 'observation': observation, 'transcript': value}

    def close_idle_under_lock(self, *, apply=False, authorized_plan_sha256=None):
        need(apply is True and type(authorized_plan_sha256) is str and SHA.fullmatch(authorized_plan_sha256),
             'PREACTIVATION_EXPLICIT_REVIEWED_PLAN_REQUIRED')
        self.require_active()
        need(not self._closed_once and not (self.idle_reader.directory / 'closed-idle.json').exists(),
             'PREACTIVATION_EXISTING_CLOSURE_READ_ONLY')
        checked = self.plan_under_lock()
        need(checked['plan_sha256'] == authorized_plan_sha256, 'PREACTIVATION_PLAN_NOT_AUTHORIZED')
        value = checked['transcript']
        need(sha(canonical(value)) == checked['plan']['transcript_sha256'], 'PREACTIVATION_TRANSCRIPT_CHANGED')
        closure = {'schema_version': 1, 'scope': CLOSURE_SCOPE, 'status': STATUS,
            'source_context': SOURCE_CONTEXT, 'authorized_plan_sha256': authorized_plan_sha256,
            'retirement_plan': checked['plan'], **value, 'observation': checked['observation'],
            'successful_native_exit_confirmed': False, 'human_acceptance_recorded': False,
            'automatic_replay_permitted': False, 'closed_at_utc': datetime.now(timezone.utc).isoformat()}
        private_inputs([self.idle_reader.directory])
        closed_at = datetime.now(timezone.utc)
        closure['closed_at_utc'] = closed_at.isoformat()
        fresh_observation(checked['observation'], closed_at)
        self._closed_once = True  # unknown write result is never automatically retried
        self.current.write(self.idle_reader.directory, 'closed-idle.json', closure)
        self.idle_reader._read_under_lock()
        return {'status': STATUS, 'release_sha256': self.release, 'session_id': self.idle_reader.directory.name,
            'closure_sha256': sha(self.current.raw(self.idle_reader.directory, 'closed-idle.json')),
            'completed_job_count': len(value['completed_jobs']), 'successful_native_exit_confirmed': False,
            'human_acceptance_recorded': False, 'automatic_replay_permitted': False}

    def history_read_under_lock(self, *, for_startup=False):
        need(for_startup is False, 'PREACTIVATION_STARTUP_FORBIDDEN')
        self.idle_reader._read_under_lock()
        return {'status': 'PREACTIVATION_HISTORY_READY', 'release_sha256': self.release,
            'runtime_release_sha256': self.release, 'source_context': SOURCE_CONTEXT,
            'current_container_id': self.bound_container_id, 'for_startup': False,
            'read_count': len(self.read_hashes), 'automatic_replay_permitted': False}


_CONSTRUCTION = object()


@contextmanager
def open_context(*, workspace, authority_root, expected_authority_sha256,
                 configuration_raw, expected_configuration_sha256, expected_source_sha256):
    """Fresh-process, source-only construction; no private/remote read yet.

    Independent caller approval pins both this new file and the frozen I
    manifest/configuration. The configured G identity is never replaced by I.
    """
    need(os.name == 'nt' and sys.dont_write_bytecode, 'PREACTIVATION_WINDOWS_NO_BYTECODE_REQUIRED')
    need(sha(read(Path(__file__).absolute())) == expected_source_sha256
         and sha(configuration_raw) == expected_configuration_sha256, 'PREACTIVATION_APPROVED_SOURCE_REQUIRED')
    prefixes = ('qa', 'fox', 'forms2apex')
    occupied = {name for name in sys.modules if any(name == x or name.startswith(x + '.') for x in prefixes)}
    # Import this helper by a private alias, not qa.operator, in the fresh runner.
    need(not occupied, 'PREACTIVATION_FRESH_NAMESPACE_REQUIRED')
    workspace, authority_root = Path(workspace).absolute(), Path(authority_root).absolute()
    source_root = workspace / 'work/product-history-transport-bind-20261019a/operator-release'
    authority_raw = read(authority_root / 'current-release-manifest.json', expected_authority_sha256)
    authority = parse(authority_raw)
    evidence = parse(read(source_root / 'binding-evidence.json', G_EVIDENCE))
    sources = {'preactivation/preactivation_retirement.py': (Path(__file__).absolute(), expected_source_sha256),
        'authority/current-release-manifest.json': (authority_root / 'current-release-manifest.json', expected_authority_sha256)}
    for name, entry in evidence['source_hashes'].items():
        path = source_root / relative(name)
        read(path, entry['staged_sha256'])
        sources[name] = (path, entry['staged_sha256'])
    for name, digest in evidence['artifact_sha256'].items():
        sources[relative(name)] = (source_root / name, digest)
    sources['binding-evidence.json'] = (source_root / 'binding-evidence.json', G_EVIDENCE)
    for group, directory in (('code', 'qa/operator'), ('modules', 'fox/fox')):
        for name, digest in authority[group].items():
            path = authority_root / directory / relative(name)
            read(path, digest)
            sources['authority/' + directory + '/' + name] = (path, digest)
    old_path, old_bytecode = list(sys.path), sys.dont_write_bytecode
    loader = _MeasuredSourceLoader(source_root, sources)
    sys.meta_path.insert(0, loader)
    sys.path[:0] = [str(source_root), str(source_root / 'fox'), str(source_root / 'converter')]
    try:
        importlib.import_module('qa.operator')
        # Preserve one exact class identity for the independently reviewed
        # exporter while this isolated namespace is active.
        sys.modules['qa.operator.preactivation_retirement'] = sys.modules[__name__]
        helpers = {}
        for name in HELPERS:
            module_name = 'qa.operator.' + name[:-3]
            helpers[name[:-3]] = _load(module_name, authority_root / 'qa/operator' / name, authority['code'][name])
        context = PreActivationRetirementContext(_CONSTRUCTION, workspace=workspace, source_root=source_root,
            authority_root=authority_root, authority_raw=authority_raw, configuration_raw=configuration_raw,
            source_files=sources, helpers=helpers)
        yield context
    finally:
        for name in tuple(sys.modules):
            if any(name == x or name.startswith(x + '.') for x in prefixes):
                sys.modules.pop(name, None)
        sys.path[:], sys.dont_write_bytecode = old_path, old_bytecode
        sys.meta_path.remove(loader)
