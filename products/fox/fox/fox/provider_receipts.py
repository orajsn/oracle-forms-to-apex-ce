"""Explicit private, create-only OCI response receipts, not execution authority.

The caller supplies a dedicated private root OUTSIDE the sealed job tree. POSIX
permissions are enforced; on Windows the operator must provision a private ACL
on that root (chmod alone cannot establish a Windows confidentiality boundary).
POSIX local filesystems are flushed at the file and directory boundaries. On
Windows, only process-crash recovery is covered: namespace persistence across
OS/power failure is not guaranteed and must not enable automatic live recovery.
Metadata excludes request bodies, authentication material and arbitrary headers.
The private model response body is preserved unchanged, not secret-redacted.
Digests detect corruption, not a malicious writer with access to the store.
There is deliberately no retry, provider client, automatic adoption or cleanup.
"""
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .opaf import OpafError, canonical_hash

MAX_BODY_BYTES = 2_000_000
MAX_RECEIPT_BYTES = 2_100_000


class ProviderReceiptError(OpafError):
    """Safe fixed-message failures; never include paths, bodies or SDK errors."""


def _need(condition):
    if not condition:
        raise ValueError()


def _encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('utf-8')


def _timestamp(value):
    _need(isinstance(value, str) and len(value) <= 64)
    _need(datetime.fromisoformat(value).utcoffset() is not None)


def _safe_metadata(info, *, directory=False):
    _need(not getattr(info, 'st_file_attributes', 0) & 0x400)  # Windows reparse point
    _need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    if not directory:
        _need(info.st_nlink == 1)
    if os.name != 'nt':
        _need(info.st_uid == os.getuid())


def _signature(info):
    return tuple(getattr(info, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns'))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result)
        result[key] = value
    return result


def _sync_directory(path):
    if os.name == 'nt':
        return  # Windows namespace durability is explicitly not guaranteed.
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _metadata(binding, environment):
    """Fixed metadata schemas only; never a catch-all context/header dictionary."""
    from .design_provider import DIRECT, PROMPTS
    from .genai_prompts import prompt_hash
    hashes = {'source_manifest_sha256', 'identity_sha256', 'target_profile_sha256',
              'client_target_sha256', 'role_sha256', 'prompt_sha256',
              'request_sha256', 'wire_request_sha256'}
    _need(type(binding) is dict and set(binding) == hashes |
          {'schema_version', 'provider', 'job_id', 'role', 'model', 'prompt_version'})
    _need(type(binding['schema_version']) is int and binding['schema_version'] == 1)
    _need(binding['provider'] == DIRECT and binding['role'] in PROMPTS)
    _need(all(isinstance(binding[key], str) and re.fullmatch('[0-9a-f]{64}', binding[key]) for key in hashes))
    _need(isinstance(binding['job_id'], str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', binding['job_id']))
    _need(isinstance(binding['model'], str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', binding['model']))
    _need(binding['prompt_version'] == PROMPTS[binding['role']]
          and binding['prompt_sha256'] == prompt_hash(binding['role']))
    expected = {key: binding[key] for key in ('provider', 'job_id', 'role', 'model',
        'source_manifest_sha256', 'target_profile_sha256', 'prompt_version', 'prompt_sha256')}
    expected.update(schema_version=2, scope='fox-design-model-environment-v2',
        trust_boundary='authenticated_fox_executor_not_vendor_attestation',
        authentication='instance_principal', region='us-ashburn-1',
        endpoint='https://inference.generativeai.us-ashburn-1.oci.oraclecloud.com')
    _need(type(environment) is dict and set(environment) == set(expected) |
          {'observed_at_utc', 'sdk_version', 'compartment_id'})
    _need(type(environment['schema_version']) is int)
    _need(all(environment[key] == value for key, value in expected.items()))
    _timestamp(environment['observed_at_utc'])
    _need(isinstance(environment['sdk_version'], str)
          and re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', environment['sdk_version']))
    _need(isinstance(environment['compartment_id'], str)
          and re.fullmatch(r'ocid1\.compartment\.[A-Za-z0-9.]{1,240}', environment['compartment_id']))


class LocalProviderReceiptStore:
    """One immutable intent and response per exact binding, with no replay path.

    Root parent must already exist. Paths are hash-derived, never source/job names.
    Keep the root on a local filesystem with atomic hard-link creation supported.
    Unpublished temporary files can remain after a process crash; they are never
    interpreted as receipts. On supported POSIX local filesystems a response
    commit is fsynced before capture returns, including its directory entry.
    """

    def __init__(self, root, *, sealed_job_root, read_only=False):
        try:
            _need(type(read_only) is bool)
            self._read_only = read_only
            self.root = Path(os.path.abspath(root))
            self.sealed_job_root = Path(os.path.abspath(sealed_job_root))
            _need(not self.root.is_relative_to(self.sealed_job_root)
                  and not self.sealed_job_root.is_relative_to(self.root))
            self._parents(self.sealed_job_root.parent)
            if self.sealed_job_root.exists():
                _safe_metadata(self.sealed_job_root.lstat(), directory=True)
            self._parents(self.root.parent)
            if not self.root.exists():
                _need(not self._read_only)
                self.root.mkdir(mode=0o700)
            self._root_check()
            info = self.root.lstat()
            self._root_identity = info.st_dev, info.st_ino
            # Persist the root's name too, including when the caller just made it.
            if not self._read_only:
                _sync_directory(self.root.parent)
        except Exception:
            raise ProviderReceiptError('Private provider receipt store is unavailable or unsafe.') from None

    @classmethod
    def read_only(cls, root, *, sealed_job_root):
        """Open existing evidence without creation, fsync or write capability."""
        return cls(root, sealed_job_root=sealed_job_root, read_only=True)

    @staticmethod
    def _parents(path):
        for item in (*reversed(path.parents), path):
            info = item.lstat()
            # System ancestors need not be owned by the service account.
            _need(stat.S_ISDIR(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)

    def _root_check(self):
        self._parents(self.root)
        info = self.root.lstat()
        _safe_metadata(info, directory=True)
        if hasattr(self, '_root_identity'):
            _need((info.st_dev, info.st_ino) == self._root_identity)
        if os.name != 'nt':
            _need(self.root.stat().st_mode & 0o077 == 0)

    def _path(self, key, kind):
        _need(isinstance(key, str) and re.fullmatch('[0-9a-f]{64}', key))
        _need(kind in ('intent', 'response'))
        self._root_check()
        return self.root / (key + '.' + kind + '.json')

    def _write(self, key, kind, payload):
        _need(not self._read_only)
        path = self._path(key, kind)
        raw = _encode({'schema_version': 1, 'kind': kind, 'payload': payload,
                       'payload_sha256': canonical_hash(payload)})
        _need(0 < len(raw) <= MAX_RECEIPT_BYTES)
        temporary = self.root / ('.pending-' + uuid.uuid4().hex)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
            with os.fdopen(os.open(temporary, flags, 0o600), 'wb') as stream:
                _safe_metadata(os.fstat(stream.fileno()))
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self._root_check()
            # Unlike rename/replace, link cannot overwrite a prior receipt.
            os.link(temporary, path, follow_symlinks=False)
        finally:
            if temporary.exists():
                temporary.unlink()
        _sync_directory(self.root)

    def _read(self, key, kind):
        path = self._path(key, kind)
        before = path.lstat()
        _safe_metadata(before)
        _need(0 < before.st_size <= MAX_RECEIPT_BYTES)
        if os.name != 'nt':
            _need(before.st_mode & 0o077 == 0)
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            _safe_metadata(opened)
            _need(_signature(before) == _signature(opened))
            raw = stream.read(MAX_RECEIPT_BYTES + 1)
            _need(_signature(opened) == _signature(os.fstat(stream.fileno())))
        _need(_signature(before) == _signature(path.lstat()))
        _need(len(raw) == before.st_size)
        record = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda value: _need(False))
        _need(set(record) == {'schema_version', 'kind', 'payload', 'payload_sha256'})
        _need(type(record['schema_version']) is int and record['schema_version'] == 1 and record['kind'] == kind)
        _need(record['payload_sha256'] == canonical_hash(record['payload']))
        return record['payload']

    def begin(self, binding, *, client_request_id, started_at_utc, environment):
        """Commit before POST. Any existing intent blocks submission, even valid."""
        try:
            _metadata(binding, environment)
            _need(re.fullmatch(r'fox-[0-9a-f]{32}', client_request_id))
            _timestamp(started_at_utc)
            key = canonical_hash(binding)
            try:
                self._path(key, 'response').lstat()
            except FileNotFoundError:
                pass
            else:
                raise ValueError()  # Orphan response still prohibits another POST.
            intent = {'binding': binding, 'client_request_id': client_request_id,
                'started_at_utc': started_at_utc, 'environment': environment}
            self._write(key, 'intent', intent)
            _need(self._read(key, 'intent') == intent)
            return key
        except Exception:
            raise ProviderReceiptError('Provider receipt intent could not be created; existing or uncertain work must reconcile without replay.') from None

    def capture(self, key, *, body, status, request_id, completed_at_utc):
        """Preserve the SDK data dictionary before parsing any model content."""
        try:
            intent = self._read(key, 'intent')
            _timestamp(completed_at_utc)
            _need(type(status) is int and 0 <= status <= 999)
            # Invalid/missing IDs remain evidence; never store arbitrary headers.
            _need(request_id is None or isinstance(request_id, str) and len(request_id) <= 512)
            try:
                _need(len(_encode(body)) <= MAX_BODY_BYTES)
                retained, outcome = body, 'captured'
            except (ValueError, TypeError, UnicodeError):
                retained, outcome = None, 'body_unavailable'
            self._write(key, 'response', {'intent_sha256': canonical_hash(intent),
                'body': retained, 'outcome': outcome, 'status': status, 'request_id': request_id,
                'completed_at_utc': completed_at_utc})
            _need(outcome == 'captured')
        except Exception:
            raise ProviderReceiptError('Provider response capture is unavailable or invalid; reconcile without replay.') from None

    def read(self, binding):
        """Read only: absence, corruption and incomplete capture fail closed."""
        try:
            key = canonical_hash(binding)
            intent = self._read(key, 'intent')
            _need(set(intent) == {'binding', 'client_request_id', 'started_at_utc', 'environment'})
            _need(intent['binding'] == binding)
            _metadata(binding, intent['environment'])
            _need(re.fullmatch(r'fox-[0-9a-f]{32}', intent['client_request_id']))
            _timestamp(intent['started_at_utc'])
            response = self._read(key, 'response')
            _need(set(response) == {'intent_sha256', 'body', 'outcome', 'status', 'request_id', 'completed_at_utc'})
            _need(response['intent_sha256'] == canonical_hash(intent))
            _need(type(response['status']) is int and 0 <= response['status'] <= 999)
            _need(response['request_id'] is None or isinstance(response['request_id'], str)
                  and len(response['request_id']) <= 512)
            _need(response['outcome'] == 'captured' and len(_encode(response['body'])) <= MAX_BODY_BYTES)
            _timestamp(response['completed_at_utc'])
            _need(datetime.fromisoformat(response['completed_at_utc']) >= datetime.fromisoformat(intent['started_at_utc']))
            return intent, response
        except FileNotFoundError:
            raise ProviderReceiptError('Provider receipt is missing or the transport outcome is unknown; reconcile without replay.') from None
        except Exception:
            raise ProviderReceiptError('Provider receipt is invalid or unsafe; reconcile without replay.') from None
