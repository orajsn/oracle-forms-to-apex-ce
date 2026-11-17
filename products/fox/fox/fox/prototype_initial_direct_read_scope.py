"""One saved-candidate read's pure initial-direct reconstruction cache.

This is deliberately separate from epoch authority. The complete original job,
including files outside its pipeline, must remain byte/identity/name identical.
No DB, owner consent, compiler result or model operation is cached here.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import json
from pathlib import Path
import re

from .opaf import OpafError
from .prototype_read_scope import _inventory, _owner

MAX_PROOFS = 4
MAX_VALUE_BYTES = 4 * 1024 * 1024
MAX_CACHE_BYTES = 8 * 1024 * 1024
# Optional pure document material never spends the retained-proof budget.
# These bound serialized values, not Python process RSS.
MAX_DOCUMENT_BUILDS = 4
MAX_DOCUMENT_BUILD_VALUE_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_BUILD_BYTES = 8 * 1024 * 1024
_state = ContextVar('fox_saved_initial_direct_read', default=None)


def _fail():
    raise OpafError('Saved initial-direct proof changed or crossed an execution boundary.') from None


def _ancestors(job):
    # Inventory pins the job itself. Also pin its location: moving an unchanged
    # job under a replaced ancestor cannot preserve this operation's identity.
    # An ancestor's link count can change when an unrelated sibling job starts.
    # Its device/inode/mode pin location without coupling separate job activity.
    return tuple((str(path), info.st_dev, info.st_ino, info.st_mode)
                 for path in job.parents for info in (path.lstat(),))


@contextmanager
def initial_direct_read_scope(job, target):
    """Only saved_candidate opens this scope; nested operations never share it."""
    from .design_provider import is_direct
    from .prototype_direct_container import present
    if _state.get() is not None:
        _fail()
    job = Path(job).absolute()
    root = job / 'prototype-pipeline'
    if (not is_direct(target) or not present(root)
            or (root / 'epochs').exists() or (root / 'epochs').is_symlink()):
        yield
        return
    if any(part in ('.', '..') for part in job.parts):
        _fail()
    before = _inventory(job), _ancestors(job)
    current = {'root': root, 'owner': _owner(), 'proofs': {}, 'bytes': 0, 'active': True,
               'document_builds': {}, 'document_build_bytes': 0}
    token = _state.set(current)
    try:
        yield
    finally:
        try:
            if current['owner'] != _owner() or (_inventory(job), _ancestors(job)) != before:
                _fail()
        finally:
            # A captured Context can outlive its request even on the same task.
            # Revoke that shared state before resetting this ContextVar token.
            current['active'] = False
            current['proofs'].clear()
            current['bytes'] = 0
            current['document_builds'].clear()
            current['document_build_bytes'] = 0
            _state.reset(token)


def current_read_root():
    """Pure helpers may reuse only this active owner/thread/task's job scope."""
    current = _state.get()
    if current is None:
        return None
    if not current['active'] or current['owner'] != _owner():
        _fail()
    return current['root']


def optional_document_build(root, identity, compute):
    """Detached exact-byte packet/chunks, independent of retained proof storage.

    Only capacity declines storage; context, computation and full-job exit fence
    failures still propagate. No selection, consent or authority is cached.
    """
    current = _state.get()
    if current is None:
        return compute()
    if current_read_root() != Path(root).absolute():
        _fail()
    if (type(identity) is not tuple or not 1 <= len(identity) <= 4
            or any(type(row) is not tuple or len(row) != 3 or type(row[0]) is not str
                   or len(row[0]) > 180 or type(row[1]) is not int or row[1] <= 0
                   or type(row[2]) is not str or not re.fullmatch('[a-f0-9]{64}', row[2])
                   for row in identity)):
        _fail()
    builds = current['document_builds']
    if identity in builds:
        return deepcopy(builds[identity])
    if len(builds) >= MAX_DOCUMENT_BUILDS:
        return compute()
    value = compute()
    size = len(json.dumps(value, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8'))
    if size > MAX_DOCUMENT_BUILD_VALUE_BYTES or current['document_build_bytes'] + size > MAX_DOCUMENT_BUILD_BYTES:
        return value
    builds[identity] = deepcopy(value)
    current['document_build_bytes'] += size
    return deepcopy(builds[identity])


def optional_proof(root, identity, compute):
    """Detached pure derive data, bounded independently of all epoch caches."""
    current = _state.get()
    if current is None:
        return compute()
    if (not current['active'] or current['root'] != Path(root).absolute()
            or current['owner'] != _owner()):
        _fail()
    if type(identity) is not str or not re.fullmatch('[a-f0-9]{64}', identity):
        _fail()
    proofs = current['proofs']
    if identity in proofs:
        return deepcopy(proofs[identity])
    if len(proofs) >= MAX_PROOFS:
        return compute()
    value = compute()
    size = len(json.dumps(value, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8'))
    if size > MAX_VALUE_BYTES or current['bytes'] + size > MAX_CACHE_BYTES:
        return value
    proofs[identity] = deepcopy(value)
    current['bytes'] += size
    return deepcopy(proofs[identity])


def forbid_execution():
    if _state.get() is not None:
        _fail()
