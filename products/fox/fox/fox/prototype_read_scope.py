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
import math
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
# Optional pure document material never spends mandatory proof-cache capacity.
# These are canonical serialized-value caps, not Python process RSS limits.
MAX_DOCUMENT_BUILDS = 4
MAX_DOCUMENT_BUILD_VALUE_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_BUILD_BYTES = 8 * 1024 * 1024
# Complete retained-container proofs have a separate optional serialized budget.
MAX_CONTAINER_PROOFS = 4
MAX_CONTAINER_PROOF_VALUE_BYTES = 4 * 1024 * 1024
MAX_CONTAINER_PROOF_BYTES = 8 * 1024 * 1024
# Pure context-screen projection data cannot spend any other cache's budget.
MAX_SCREEN_PROJECTIONS = 128
MAX_SCREEN_PROJECTION_VALUE_BYTES = 4 * 1024 * 1024
MAX_SCREEN_PROJECTION_BYTES = 8 * 1024 * 1024
# Pure prefix summaries and final focused contexts share this optional budget.
MAX_CONTEXT_PREFIXES = 128
MAX_CONTEXT_PREFIX_VALUE_BYTES = 4 * 1024 * 1024
MAX_CONTEXT_PREFIX_BYTES = 8 * 1024 * 1024
# Final DSC technical views cannot spend any other optional/mandatory budget.
MAX_DSC_VIEWS = 128
MAX_DSC_VIEW_VALUE_BYTES = 4 * 1024 * 1024
MAX_DSC_VIEW_BYTES = 8 * 1024 * 1024
# Eligibility limits only: unsupported values retain the original deepcopy path.
_JSON_COPY_MAX_DEPTH = 64
_JSON_COPY_MAX_NODES = 600_000
_JSON_COPY_MAX_INT_BITS = 2048  # <=617 decimal digits, below Python's minimum640.
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
        from . import prototype_dsc_identity_repair as dsc
        expected_names={module.NAME for module in result_modules}
        if dsc.present(root):
            expected_names.add(Path(dsc.RESULT_BASE).name)
            revision=epochs._safe_path(job,dsc.RESULT_BASE)
            if any(path.name not in ('previous-result.json','publication.json') for path in revision.iterdir()): _fail()
        if {path.name for path in parent.iterdir()} != expected_names:
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
    root_files = {name for name in before['pipeline'] if not name.endswith('/')}
    job_files = set()
    if root.name == 'prototype-pipeline':
        job_files.update('prototype-pipeline/' + name for name in root_files)
        for name in ('source-snapshot.json', 'mapping-continuation.json', 'prototype-result.json'):
            if name in before: job_files.add(name)
        for key, prefix in (('mapping-epochs', 'mapping-epochs/'), ('prototype-results', 'prototype-results/'),
                            ('result-publications', 'prototype-result-publications/')):
            if key in before:
                job_files.update(prefix + name for name in before[key] if not name.endswith('/'))
    token = _state.set({'root': root, 'owner': _owner(), 'cache': {}, 'bytes': 0,
        'document_builds': {}, 'document_build_bytes': 0,
        'container_proofs': {}, 'container_proof_bytes': 0,
        'screen_projections': {}, 'screen_projection_bytes': 0,
        'context_prefixes': {}, 'context_prefix_bytes': 0,
        'dsc_views': {}, 'dsc_view_bytes': 0,
        'fenced_root_files': frozenset(root_files), 'fenced_job_files': frozenset(job_files)})
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


def current_read_root():
    """Root for pure helpers only; inherited thread/task contexts cannot reuse it."""
    current = _state.get()
    if current is None:
        return None
    if current['owner'] != _owner():
        _fail()
    return current['root']


def baseline_read_root(base, names):
    """Only exact files included in this operation's entry fence may be reused."""
    root = current_read_root()
    if root is None:
        return None
    current = _state.get()
    base = Path(base).absolute()
    if any('prototype-transport' in name.split('/') for name in names):
        return None
    if base == root:
        covered = current['fenced_root_files']
    elif root.name == 'prototype-pipeline' and base == root.parent:
        covered = current['fenced_job_files']
    else:
        return None
    return root if set(names) <= covered else None


def _json_tree_copy_bytes(value):
    """Insertion-order bytes ONLY for bounded strict, alias-free JSON trees.

    Exact types preserve booleans/numbers; global container IDs reject shared
    mutable aliases as well as cycles. Tuples/subclasses/custom hooks fall back.
    Immutable leaf identity is not part of this JSON-data contract.
    """
    if type(value) not in (dict, list):
        return None
    seen, remaining = set(), _JSON_COPY_MAX_NODES
    def visit(node, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > _JSON_COPY_MAX_DEPTH:
            return False
        kind = type(node)
        if kind is dict or kind is list:
            ref = id(node)
            if ref in seen:
                return False
            seen.add(ref)
            if kind is dict:
                for key, child in node.items():
                    if type(key) is not str or not visit(child, depth + 1):
                        return False
            else:
                for child in node:
                    if not visit(child, depth + 1):
                        return False
            return True
        if kind is int:
            return node.bit_length() <= _JSON_COPY_MAX_INT_BITS
        return node is None or kind in (str, bool) or kind is float and math.isfinite(node)
    try:
        if not visit(value, 0):
            return None
        # Never sort here: detached dicts must retain original insertion order.
        return json.dumps(value, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, RecursionError, OverflowError, UnicodeError):
        return None  # Only decline this copy optimization; original copy still runs.


def _copy_cached_value(entry):
    fast, value = entry
    return json.loads(value) if fast else deepcopy(value)


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
        raw = _json_tree_copy_bytes(value)
        # Private tagged representation prevents collisions with arbitrary values
        # returned by custom __deepcopy__ implementations on the fallback path.
        current['cache'][key] = (True, raw) if raw is not None else (False, deepcopy(value))
        current['bytes'] += size
    return _copy_cached_value(current['cache'][key])


def optional_document_build(root, identity, compute):
    """Pure exact-byte document derivation, only in this fenced read operation.

    Capacity alone declines storage; context/fence/compute errors never fall
    through. This independent optional store cannot exhaust mandatory entries.
    """
    current = _state.get()
    if current is None:
        return compute()
    if current['root'] != Path(root).absolute() or current['owner'] != _owner():
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
    size = len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8'))
    if size > MAX_DOCUMENT_BUILD_VALUE_BYTES or current['document_build_bytes'] + size > MAX_DOCUMENT_BUILD_BYTES:
        return value
    builds[identity] = deepcopy(value)
    current['document_build_bytes'] += size
    return deepcopy(builds[identity])


def optional_container_proof(root, identity, compute):
    """Pure complete proof only; no authority, DB, event or consent results.

    Identity is an exact-input digest prepared after fresh module/member guards.
    Capacity declines storage, never validation or the enclosing exit fences.
    """
    current = _state.get()
    if current is None:
        return compute()
    if current['root'] != Path(root).absolute() or current['owner'] != _owner():
        _fail()
    if type(identity) is not str or not re.fullmatch('[a-f0-9]{64}', identity):
        _fail()
    proofs = current['container_proofs']
    if identity in proofs:
        return deepcopy(proofs[identity])
    if len(proofs) >= MAX_CONTAINER_PROOFS:
        return compute()
    value = compute()
    size = len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8'))
    if size > MAX_CONTAINER_PROOF_VALUE_BYTES or current['container_proof_bytes'] + size > MAX_CONTAINER_PROOF_BYTES:
        return value
    proofs[identity] = deepcopy(value)
    current['container_proof_bytes'] += size
    return deepcopy(proofs[identity])


def optional_screen_projection(root, identity, compute):
    """Bounded pure candidate/receipt data; not a cached permission or review.

    Only capacity declines storage. Context, computation and enclosing file-fence
    failures still propagate. Copies protect both first and subsequent results.
    """
    current = _state.get()
    if current is None:
        return compute()
    if current['root'] != Path(root).absolute() or current['owner'] != _owner():
        _fail()
    if type(identity) is not str or not re.fullmatch('[a-f0-9]{64}', identity):
        _fail()
    projections = current['screen_projections']
    if identity in projections:
        return deepcopy(projections[identity])
    if len(projections) >= MAX_SCREEN_PROJECTIONS:
        return compute()
    value = compute()
    size = len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8'))
    if size > MAX_SCREEN_PROJECTION_VALUE_BYTES or current['screen_projection_bytes'] + size > MAX_SCREEN_PROJECTION_BYTES:
        return value
    projections[identity] = deepcopy(value)
    current['screen_projection_bytes'] += size
    return deepcopy(projections[identity])


def optional_context_prefix(root, identity, compute):
    """Pure prefix summaries/focused contexts, never provenance or consent.

    Capacity declines storage, not validation. This store cannot exhaust any
    mandatory/document/container/screen store or suppress the enclosing fences.
    """
    current = _state.get()
    if current is None:
        return compute()
    if current['root'] != Path(root).absolute() or current['owner'] != _owner():
        _fail()
    if type(identity) is not str or not re.fullmatch('[a-f0-9]{64}', identity):
        _fail()
    prefixes = current['context_prefixes']
    if identity in prefixes:
        return deepcopy(prefixes[identity])
    if len(prefixes) >= MAX_CONTEXT_PREFIXES:
        return compute()
    value = compute()
    size = len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8'))
    if size > MAX_CONTEXT_PREFIX_VALUE_BYTES or current['context_prefix_bytes'] + size > MAX_CONTEXT_PREFIX_BYTES:
        return value
    prefixes[identity] = deepcopy(value)
    current['context_prefix_bytes'] += size
    return deepcopy(prefixes[identity])


def optional_dsc_view(root, identity, compute):
    """Final detached technical view only; not current DB/owner/processing grants."""
    current = _state.get()
    if current is None:
        return compute()
    if current['root'] != Path(root).absolute() or current['owner'] != _owner():
        _fail()
    if type(identity) is not str or not re.fullmatch('[a-f0-9]{64}', identity):
        _fail()
    views = current['dsc_views']
    if identity in views:
        return deepcopy(views[identity])
    if len(views) >= MAX_DSC_VIEWS:
        return compute()
    value = compute()
    size = len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8'))
    if size > MAX_DSC_VIEW_VALUE_BYTES or current['dsc_view_bytes'] + size > MAX_DSC_VIEW_BYTES:
        return value
    views[identity] = deepcopy(value)
    current['dsc_view_bytes'] += size
    return deepcopy(views[identity])


def forbid_execution():
    if _state.get() is not None:
        _fail()
