"""Installed, owner-private supervisor for the ordinary finite ProductVerifier.

No service-manager, deployment, secret creation, recovery or replay actions.
The independently pinned installation binds C (provider), R (release), D
(admission), X (retirement) and the exact source tree. Checks never initialize a
journal. Only explicit ``run --apply`` can start normal bounded verification.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import sys
import threading

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
for directory in (ROOT, ROOT / 'fox', ROOT / 'converter'):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
from qa.operator import contracts as C
from qa.operator import product_verifier as product
from qa.operator import product_queue_transport as bridge
from qa.operator import runtime_provider as runtime
from qa.operator import retirement_handoff as retirement
from qa.operator import retirement_remote as remote

SCOPE = 'fox-hosted-product-verifier-installation-v1'
INVENTORY_SCOPE = 'fox-hosted-source-inventory-v1'
SHA = re.compile(r'[a-f0-9]{64}\Z')
MAX_DOCUMENT = 2_000_000


class HostedServiceError(RuntimeError):
    """Closed categories; never provider output or secret contents."""


def need(value, code):
    if not value:
        raise HostedServiceError(code)


def _sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def _path(value):
    # Pure validation is usable for offline declarations on any platform.
    need(type(value) is str and 1 < len(value) <= 1024 and '\\' not in value
         and not any(ord(char) < 32 for char in value), 'INSTALLATION_PATH_INVALID')
    parsed = PurePosixPath(value)
    need(parsed.is_absolute() and parsed.as_posix() == value and '..' not in parsed.parts,
         'INSTALLATION_PATH_INVALID')
    return Path(value)


def _reference(value):
    need(type(value) is dict and set(value) == {'path', 'sha256'} and _sha(value['sha256']),
         'INSTALLATION_REFERENCE_INVALID')
    _path(value['path'])


def installation_document(raw, *, expected_sha256):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_DOCUMENT and _sha(expected_sha256)
         and C.digest(raw) == expected_sha256, 'INSTALLATION_HASH_CHANGED')
    value = runtime._json(raw)
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'provider', 'release',
         'admission', 'retirement', 'layout', 'bounds', 'batch_pause_seconds'}
         and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['scope'] == SCOPE and C.canonical_bytes(value) == raw,
         'INSTALLATION_DOCUMENT_INVALID')
    for key in ('provider', 'release', 'admission'):
        _reference(value[key])
    archive = value['retirement']
    need(type(archive) is dict and set(archive) == {'path', 'attestation_sha256'}
         and _sha(archive['attestation_sha256']), 'INSTALLATION_RETIREMENT_INVALID')
    _path(archive['path'])
    layout = value['layout']
    need(type(layout) is dict and set(layout) == {'release_root', 'inventory'}, 'INSTALLATION_LAYOUT_INVALID')
    root = _path(layout['release_root'])
    _reference(layout['inventory'])
    paths = [_path(value[key]['path']) for key in ('provider', 'release', 'admission')]
    paths += [_path(layout['inventory']['path']), _path(archive['path'])]
    need(len(set(paths)) == len(paths) and runtime._outside(root, paths), 'INSTALLATION_LAYOUT_OVERLAPS')
    bounds = value['bounds']
    limits = {'max_jobs': 5, 'max_polls': 120, 'max_seconds': 7200, 'poll_seconds': 60}
    need(type(bounds) is dict and set(bounds) == set(limits)
         and all(type(bounds[key]) is int and 1 <= bounds[key] <= limit for key, limit in limits.items())
         and bounds['max_jobs'] <= bounds['max_polls']
         and type(value['batch_pause_seconds']) is int and 1 <= value['batch_pause_seconds'] <= 60,
         'INSTALLATION_BOUNDS_INVALID')
    return value


def _private_raw(path, maximum=MAX_DOCUMENT):
    runtime._private_directory(path.parent)
    return runtime._read(path, maximum, private=True)


def _pinned(reference):
    raw = _private_raw(_path(reference['path']))
    need(C.digest(raw) == reference['sha256'], 'INSTALLATION_REFERENCE_CHANGED')
    return raw


def _source_raw(path):
    if path.lstat().st_size:
        return runtime._read(path, 64_000_000)
    # Empty package markers are legitimate SOURCE members, not missing files.
    # Configurations, evidence and secrets retain their nonempty read checks.
    runtime._ancestors(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'INSTALLATION_SOURCE_FILE_INVALID')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        need(stream.read(1) == b'', 'INSTALLATION_SOURCE_BYTES_CHANGED')
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    need(identity(before) == identity(opened) == identity(after) == identity(path.lstat()),
         'INSTALLATION_SOURCE_BYTES_CHANGED')
    return b''


def verify_inventory(root, raw):
    """Exact no-follow source closure; no ignored paths or generated caches."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_DOCUMENT, 'INSTALLATION_INVENTORY_INVALID')
    document = runtime._json(raw)
    need(type(document) is dict and set(document) == {'schema_version', 'scope', 'files'}
         and type(document['schema_version']) is int and document['schema_version'] == 1
         and document['scope'] == INVENTORY_SCOPE and runtime._canonical(document) == raw,
         'INSTALLATION_INVENTORY_INVALID')
    files = document['files']
    need(type(files) is dict and 0 < len(files) <= 10000, 'INSTALLATION_INVENTORY_INVALID')
    expected_dirs = set()
    for name, digest in files.items():
        need(type(name) is str and 0 < len(name) <= 512 and '\\' not in name
             and not any(ord(char) < 32 for char in name), 'INSTALLATION_INVENTORY_PATH_INVALID')
        parsed = PurePosixPath(name)
        need(not parsed.is_absolute() and parsed.as_posix() == name
             and '..' not in parsed.parts and '__pycache__' not in parsed.parts and _sha(digest),
             'INSTALLATION_INVENTORY_PATH_INVALID')
        expected_dirs.update(str(parent) for parent in parsed.parents if str(parent) != '.')
    runtime._ancestors(root)
    need(root.is_dir(), 'INSTALLATION_SOURCE_ROOT_REQUIRED')
    seen, directories, todo, total = set(), set(), [root], 0
    while todo:
        directory = todo.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                name = path.relative_to(root).as_posix()
                need(not entry.is_symlink(), 'INSTALLATION_SOURCE_LINK_FORBIDDEN')
                if entry.is_dir(follow_symlinks=False):
                    need(name in expected_dirs, 'INSTALLATION_SOURCE_DIRECTORY_CHANGED')
                    runtime._ancestors(path)
                    directories.add(name)
                    todo.append(path)
                else:
                    need(name in files, 'INSTALLATION_SOURCE_INVENTORY_CHANGED')
                    content = _source_raw(path)
                    total += len(content)
                    need(total <= 512_000_000 and C.digest(content) == files[name],
                         'INSTALLATION_SOURCE_BYTES_CHANGED')
                    seen.add(name)
    need(seen == set(files) and directories == expected_dirs, 'INSTALLATION_SOURCE_INVENTORY_CHANGED')
    return document


class HostedAdmission:
    """Concrete installation authority, never a boolean/caller-supplied reader."""
    def __init__(self, installation_path, *, expected_sha256):
        need(os.name == 'posix' and os.geteuid() > 0, 'HOSTED_UNPRIVILEGED_POSIX_REQUIRED')
        self.path = _path(str(installation_path))
        self.sha256 = expected_sha256
        self.raw = _private_raw(self.path)
        self.document = installation_document(self.raw, expected_sha256=expected_sha256)
        value = self.document
        self.source_root = _path(value['layout']['release_root'])
        need(self.source_root == ROOT and runtime._outside(self.path, [self.source_root]),
             'INSTALLATION_EXECUTED_SOURCE_ROOT_DIFFERS')
        provider_raw, release_raw, admission_raw = (_pinned(value[name]) for name in ('provider', 'release', 'admission'))
        self.reference_raw = {'provider': provider_raw, 'release': release_raw, 'admission': admission_raw,
                              'inventory': _pinned(value['layout']['inventory'])}
        config = runtime.configuration_document(provider_raw, expected_sha256=value['provider']['sha256'])
        need(config['schema_version'] == 2 and Path(config['converter_root']).parent == self.source_root
             and runtime._outside(self.source_root, [_path(config['state_root']), _path(config['admin_secret_file'])]),
             'INSTALLATION_PROVIDER_LAYOUT_DIFFERS')
        need(Path(sys.executable).resolve() == _path(config['python']['path'])
             and list(sys.version_info[:3]) == config['python']['version'], 'INSTALLATION_PYTHON_DIFFERS')
        self.manifest = bridge.validate_release(C.load_json(release_raw))
        self.release = value['release']['sha256']
        need(self.manifest['schema_version'] == 3 and C.canonical_bytes(self.manifest) == release_raw
             and bridge.release_sha256(self.manifest) == self.release
             and self.manifest['hosted_runtime_configuration_sha256'] == value['provider']['sha256'],
             'INSTALLATION_RELEASE_BINDING_CHANGED')
        admission = C.load_json(admission_raw)
        infrastructure = remote._infrastructure(admission.get('infrastructure'), self.manifest['images'])
        need(admission_raw == C.canonical_bytes(remote.admission_configuration(self.release,
             value['provider']['sha256'], infrastructure)), 'INSTALLATION_ADMISSION_BINDING_CHANGED')
        verify_inventory(self.source_root, self.reference_raw['inventory'])
        runtime.configure_hosted(provider_raw, expected_sha256=value['provider']['sha256'])
        self.provider = runtime.selected_hosted()
        self.reader = remote.RetiredHistoryRemoteReader(self.manifest, self.release,
                                                       infrastructure, value['admission']['sha256'])
        self.archive = retirement.RetirementArchive(_path(value['retirement']['path']),
            attestation_sha256=value['retirement']['attestation_sha256'], release_sha256=self.release,
            configuration_sha256=value['admission']['sha256'])
        need(self.archive.root != self.provider.path('handoff')
             and self.provider.path('handoff') in self.archive.root.parents,
             'INSTALLATION_RETIREMENT_LAYOUT_DIFFERS')

    def preflight(self):
        need(type(self) is HostedAdmission and runtime.selected_hosted() is self.provider
             and _private_raw(self.path) == self.raw, 'INSTALLATION_AUTHORITY_CHANGED')
        for key in ('provider', 'release', 'admission'):
            need(_pinned(self.document[key]) == self.reference_raw[key], 'INSTALLATION_REFERENCE_CHANGED')
        need(_pinned(self.document['layout']['inventory']) == self.reference_raw['inventory'],
             'INSTALLATION_INVENTORY_CHANGED')
        verify_inventory(self.source_root, self.reference_raw['inventory'])
        bridge.require_ready(self.manifest, self.release)
        self.provider.check_public_mounts()

    def require_under_lock(self, lease, current_root):
        self.preflight()
        return self.archive.require_admission_under_lock(lease, current_root=current_root,
            current_release=self.release, reader=self.reader, for_startup=True)

    def check(self):
        self.preflight()
        before = self.archive.read()
        snapshot = self.reader.read(before['history'], for_startup=True)
        need(self.archive.read() == before, 'INSTALLATION_ARCHIVE_CHANGED_DURING_CHECK')
        self.preflight()
        return {'status': 'WAIT' if snapshot['admission_state'] == 'WAIT' else 'CHECKED_NOT_STARTED',
                'release_sha256': self.release, 'read_only': True,
                'startup_authorized': False, 'automatic_replay_permitted': False}


class StopRequest:
    def __init__(self):
        self.event = threading.Event()

    def requested(self):
        return self.event.is_set()

    def request(self, *_):
        self.event.set()

    def wait(self, seconds):
        self.event.wait(seconds)

    @contextmanager
    def signals(self):
        previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
        try:
            for number in previous:
                signal.signal(number, self.request)
            yield self
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)


class HostedSupervisor:
    def __init__(self, admission, *, stop=None):
        need(type(admission) is HostedAdmission, 'CONCRETE_HOSTED_ADMISSION_REQUIRED')
        self.admission = admission
        self.stop = stop or StopRequest()
        self.verifier = product.ProductVerifier(admission.manifest, admission.release,
            hosted_admission=admission, stop_requested=self.stop.requested, sleeper=self.stop.wait)

    def _summary(self, status, **fields):
        return {'status': status, 'release_sha256': self.admission.release,
                'automatic_replay_permitted': False, **fields}

    def status(self):
        self.admission.preflight()
        journal = self.verifier.journal
        if not journal.root.exists():
            return self._summary('NOT_STARTED', read_only=True)
        try:
            with journal.lock(create=False):
                pending = journal.pending()
                return self._summary('ATTENTION' if pending else 'NO_UNCLOSED_SESSION', read_only=True,
                                     unresolved_session_count=len(pending))
        except product.ProductVerifierError as error:
            if str(error) == 'ANOTHER_PRODUCT_VERIFIER_ACTIVE_OR_LOCK_UNAVAILABLE':
                return self._summary('ACTIVE_OR_LOCK_UNAVAILABLE', read_only=True)
            raise

    def _completed_batch(self, result):
        need(type(result) is dict and result.get('status') == 'SESSION_COMPLETE'
             and result.get('release_sha256') == self.admission.release
             and result.get('automatic_replay_permitted') is False, 'BATCH_COMPLETION_UNCONFIRMED')
        journal = self.verifier.journal
        directory = Path(result['private_session'])
        need(directory.parent == journal.root and product._SESSION.fullmatch(directory.name),
             'BATCH_COMPLETION_LOCATION_CHANGED')
        with journal.lock(create=False):
            need(not journal.pending(), 'UNCLOSED_SESSION_REQUIRES_ATTENTION')
            value = journal.read(directory, 'complete.json')
            need(value.get('status') == 'SESSION_COMPLETE'
                 and value.get('release_sha256') == self.admission.release
                 and value.get('completed_jobs') == result['completed_jobs'], 'BATCH_COMPLETION_UNCONFIRMED')
            journal._check_seal(directory, value)

    def run(self, *, apply=False):
        need(apply is True, 'EXPLICIT_HOSTED_START_AUTHORITY_REQUIRED')
        batches = 0
        while not self.stop.requested():
            result = self.verifier.pump(apply=True, **self.admission.document['bounds'])
            if result['status'] == 'SESSION_COMPLETE':
                self._completed_batch(result)
                batches += 1
            elif result['status'] == 'WAIT':
                pass  # Concrete fresh history observation; no new session/claim.
            elif result['status'] == 'STOPPED_NO_SESSION' and self.stop.requested():
                break
            else:
                return self._summary('ATTENTION', completed_batches=batches,
                                     code='UNCLOSED_OR_UNCONFIRMED_BATCH')
            self.stop.wait(self.admission.document['batch_pause_seconds'])
        return self._summary('STOPPED', completed_batches=batches)


def _unit_quote(value):
    need(type(value) is str and not any(char in value for char in ('\n', '\r', '\x00', '%', '$')),
         'UNIT_ARGUMENT_INVALID')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def service_unit(admission, installation_path):
    """Render only. Existing opc user manager is the only installation target."""
    command = ' '.join(_unit_quote(value) for value in (
        admission.provider.configuration['python']['path'], '-I', '-B',
        str(admission.source_root / 'qa/operator/hosted_service.py'), 'run', '--installation',
        str(installation_path), '--installation-sha256', admission.sha256, '--apply'))
    return ('[Unit]\nDescription=FOX protected product verifier\n\n[Service]\nType=simple\n'
        + 'WorkingDirectory=' + _unit_quote(str(admission.source_root)) + '\nExecStart=' + command
        + '\nUMask=0077\nRestart=no\nKillMode=mixed\nTimeoutStopSec=1800\nSendSIGKILL=no\n'
        + '\n[Install]\nWantedBy=default.target\n').encode('utf-8')


def package(admission, output_directory, *, apply=False):
    """Create-only packaging, not installation, activation or service control."""
    need(type(admission) is HostedAdmission and type(apply) is bool, 'PACKAGE_ARGUMENTS_INVALID')
    destination = _path(str(output_directory))
    runtime._private_directory(destination.parent)
    need(not destination.exists() and not destination.is_symlink(), 'PACKAGE_NEW_DESTINATION_REQUIRED')
    roots = [admission.source_root, _path(admission.provider.configuration['state_root']),
             _path(admission.provider.configuration['admin_secret_file'])]
    need(runtime._outside(destination, roots), 'PACKAGE_DESTINATION_OVERLAPS')
    admission.preflight()  # Includes public-mount check before any package write.
    # A package with absent/fabricated retirement references is not usable.
    admission.archive.read()
    files = {'installation.json': admission.raw,
             'fox-product-verifier.service': service_unit(admission, destination / 'installation.json')}
    result = {'status': 'PACKAGED_NOT_INSTALLED' if apply else 'PACKAGE_PLAN_ONLY',
              'installation_sha256': admission.sha256, 'service_activation_performed': False,
              'files': {name: C.digest(raw) for name, raw in files.items()}}
    if apply:
        destination.mkdir(mode=0o700)
        for name, raw in files.items():
            with os.fdopen(os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                   0o600), 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
    return result


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise HostedServiceError('HOSTED_ARGUMENTS_INVALID') from None


def main(argv=None):
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument('operation', choices=('check', 'status', 'report', 'run', 'package'))
        parser.add_argument('--installation', required=True)
        parser.add_argument('--installation-sha256', required=True)
        parser.add_argument('--output-directory')
        parser.add_argument('--apply', action='store_true')
        args = parser.parse_args(argv)
        need((args.operation == 'package') == (args.output_directory is not None)
             and (not args.apply or args.operation in ('run', 'package')), 'HOSTED_ARGUMENTS_INVALID')
        admission = HostedAdmission(args.installation, expected_sha256=args.installation_sha256)
        if args.operation == 'package':
            result = package(admission, args.output_directory, apply=args.apply)
        elif args.operation == 'check':
            result = admission.check()
        else:
            supervisor = HostedSupervisor(admission)
            if args.operation in ('status', 'report'):
                result = supervisor.status()
            else:
                with supervisor.stop.signals():
                    result = supervisor.run(apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 2 if result['status'] == 'ATTENTION' else 0
    except Exception:
        print(json.dumps({'status': 'ATTENTION', 'code': 'HOSTED_GUARD_UNCONFIRMED',
                          'automatic_replay_permitted': False}, sort_keys=True))
        return 2


if __name__ == '__main__':
    # Keep the concrete admission type identical for direct-file systemd
    # startup and ProductVerifier's canonical package import.
    from qa.operator.hosted_service import main as installed_main
    raise SystemExit(installed_main())
