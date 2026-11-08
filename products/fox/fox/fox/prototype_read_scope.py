"""Bounded operation-local immutable proof reuse; never cached consent.

Exact names, raw hashes, file identity and modes are fenced at entry/exit.
Current owner/DB/target/stage/result checks still run. No scope crosses a model
operation, credential/configuration load or package HTTP request.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import asyncio
import hashlib
import json
from pathlib import Path
import re
import stat
import threading

from .opaf import OpafError, canonical_hash

MAX_FILES = 4096
MAX_FILE_BYTES = 20_000_000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CACHED_VALUES = 512
MAX_CACHED_VALUE_BYTES = 20_000_000
MAX_CACHE_BYTES = 64 * 1024 * 1024
_state = ContextVar('fox_readonly_technical_scope', default=None)


def _fail():
    raise OpafError('Read-only technical proof scope changed or crossed an execution boundary.') from None


def _owner():
    try:
        task = asyncio.current_task()
    except RuntimeError:
        task = None
    return threading.get_ident(), id(task) if task is not None else None


def _identity(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns


def _file_pin(path):
    from .prototype_mapping_epochs import _safe_path
    _safe_path(path.parent, path.name)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_FILE_BYTES):
        _fail()
    digest, length = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while chunk := stream.read(131072):
            length += len(chunk)
            if length > before.st_size:
                _fail()
            digest.update(chunk)
    if length != before.st_size or _identity(before) != _identity(path.lstat()):
        _fail()
    return (*_identity(before), digest.hexdigest())


def _inventory(root):
    from .prototype_mapping_epochs import _safe_path
    _safe_path(root.parent, root.name)
    if not root.is_dir():
        _fail()
    root_meta = root.lstat()
    names = {'/': (root_meta.st_dev, root_meta.st_ino, root_meta.st_mode, root_meta.st_nlink)}
    pending, total, files = [root], 0, 0
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            relative = path.relative_to(root).as_posix()
            _safe_path(root, relative)
            metadata = path.lstat()
            if len(names) >= MAX_FILES * 2:
                _fail()
            if stat.S_ISDIR(metadata.st_mode):
                names[relative + '/'] = (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink)
                pending.append(path)
                continue
            pin = _file_pin(path)
            total += pin[4]
            files += 1
            if total > MAX_TOTAL_BYTES or files > MAX_FILES:
                _fail()
            names[relative] = pin
    return names


def _fences(root):
    result = {'pipeline': _inventory(root)}
    job = root.parent
    # The converter receiver has only the inert technical pipeline; FOX current
    # authority has the original snapshot, DB and fixed outside-job staging.
    if root.name == 'prototype-pipeline' and (job / 'source-snapshot.json').exists():
        from . import prototype_mapping_epochs as epochs, prototype_clause_epoch as clause
        from . import prototype_container_epoch as container
        from . import prototype_partition_review_epoch as partition
        from . import prototype_context_screen_epoch as screen
        screen_head = ((root / screen.PREFIX).exists() or (root / screen.PREFIX).is_symlink()
            or (job / screen.RECORD).exists() or (job / screen.RECORD).is_symlink())
        partition_head = ((root / partition.PREFIX).exists() or (root / partition.PREFIX).is_symlink()
            or (job / partition.RECORD).exists() or (job / partition.RECORD).is_symlink())
        for name in ('source-snapshot.json', 'mapping-continuation.json', 'prototype-result.json'):
            result[name] = _file_pin(epochs._safe_path(job, name))
        for folder, allowed in (('mapping-epochs', lambda name: name in {
                'epoch-000002.json', 'epoch-000003.json', 'epoch-000004.json'}
                | ({'epoch-000005.json'} if partition_head else set()) | ({'epoch-000006.json'} if screen_head else set())),
                ('prototype-results', lambda name: bool(re.fullmatch('[a-f0-9]{64}\\.json', name)))):
            directory = epochs._safe_path(job, folder)
            if any(not allowed(path.name) for path in directory.iterdir()):
                _fail()
            result[folder] = _inventory(directory)
        result_modules = (container, partition, screen) if screen_head else (container, partition) if partition_head else (container,)
        for result_module in result_modules:
            publications = epochs._safe_path(job, result_module.RESULT_BASE)
            if any(path.name not in ('previous-result.json', 'publication.json') for path in publications.iterdir()):
                _fail()
        parent = publications.parent
        if {path.name for path in parent.iterdir()} != {module.NAME for module in result_modules}:
            _fail()
        result['result-publications'] = _inventory(parent)
        for module in (clause, container, partition) if partition_head else (clause, container):
            stage = module._stage(job)
            for path in (stage.parent, stage, stage / 'json', stage / 'json/review'):
                clause._protected(path, directory=True)
            if module is clause:
                clause._protected(stage / 'json/analysis', directory=True)
            if {path.name for path in stage.iterdir()} != {'descriptor.json', 'json'}:
                _fail()
            clause._protected(stage / 'descriptor.json')
            module._members(stage / 'json', protected=True)  # Fixed JSON names before any walk.
            result[module.STRATEGY] = _inventory(stage)
    return result


@contextmanager
def readonly_proof_scope(root):
    root = Path(root).absolute()
    current = _state.get()
    if current is not None:
        if current['root'] != root or current['owner'] != _owner():
            _fail()
        yield
        return
    before = _fences(root)
    token = _state.set({'root': root, 'owner': _owner(), 'cache': {}, 'bytes': 0})
    try:
        yield
    finally:
        try:
            if _fences(root) != before:
                _fail()
        finally:
            _state.reset(token)


@contextmanager
def epoch_read_scope(root):
    root = Path(root).absolute()
    head = root / 'epochs/epoch-000004'
    if _state.get() is not None or head.exists() or head.is_symlink():
        with readonly_proof_scope(root):
            yield
    else:
        yield  # Preserve the legacy two/three read paths and direct callers.


def cached_read(root, kind, identity, compute):
    current = _state.get()
    if current is None:
        return compute()
    if current['root'] != Path(root).absolute() or current['owner'] != _owner():
        _fail()
    if kind not in ('technical_record', 'active_focus'):
        _fail()
    key = kind, canonical_hash(identity)
    if key not in current['cache']:
        if len(current['cache']) >= MAX_CACHED_VALUES:
            _fail()
        value = compute()
        size = len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                              allow_nan=False).encode('utf-8'))
        if size > MAX_CACHED_VALUE_BYTES or current['bytes'] + size > MAX_CACHE_BYTES:
            _fail()
        current['cache'][key] = deepcopy(value)
        current['bytes'] += size
    return deepcopy(current['cache'][key])


def forbid_execution():
    if _state.get() is not None:
        _fail()
