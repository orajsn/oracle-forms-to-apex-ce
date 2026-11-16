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
    current = {'root': root, 'owner': _owner(), 'proofs': {}, 'bytes': 0, 'active': True}
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
            _state.reset(token)


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
