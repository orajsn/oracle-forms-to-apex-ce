"""Single-folder installer adapter for genuine S0, never service admission.

The wizard derives internal roots here instead of asking users to assemble S0
records. Existing producer/inspector, source pins, ownership and replay rules
remain authoritative. No model, Oracle, container or public listener is used.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

from . import fresh_storage as storage

SCOPE = 'fox-installer-storage-step-v1'
MARKER = 'setup-storage-plan.json'
DIRECTORIES = {'fox_data': 'data', 'converter_jobs': 'jobs',
               'operator_state': 'operator', 'records': 'storage-records'}


class InstallerStorageError(RuntimeError):
    """Closed codes; caller-supplied values are not diagnostics."""


def need(value, code):
    if not value:
        raise InstallerStorageError(code)


def digest(value):
    return hashlib.sha256(storage.canonical(value)).hexdigest()


def plan(installation_root, *, owner_uid):
    """Read source pins and derive one S0 plan; write nothing on either OS."""
    need(type(installation_root) is str
         and re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+', installation_root),
         'CANONICAL_INSTALLATION_ROOT_REQUIRED')
    base = PurePosixPath(installation_root)
    need(str(base) == installation_root and '..' not in base.parts
         and len(base.parts) >= 3, 'CANONICAL_INSTALLATION_ROOT_REQUIRED')
    declared = storage.declaration(owner_uid=owner_uid,
        **{role: str(base / name) for role, name in DIRECTORIES.items()})
    return {'schema_version': 1, 'scope': SCOPE,
        'installation_root': installation_root, 'storage_plan': declared,
        'adapter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def _checked(value, expected):
    need(type(value) is dict and set(value) == {'schema_version', 'scope',
         'installation_root', 'storage_plan', 'adapter_sha256'}, 'EXACT_INSTALLER_STORAGE_PLAN_REQUIRED')
    need(type(expected) is str and re.fullmatch(r'[a-f0-9]{64}', expected)
         and digest(value) == expected, 'INSTALLER_STORAGE_PLAN_HASH_CHANGED')
    need(type(value['storage_plan']) is dict and 'owner_uid' in value['storage_plan'],
         'INSTALLER_STORAGE_OWNER_REQUIRED')
    current = plan(value['installation_root'], owner_uid=value['storage_plan']['owner_uid'])
    need(storage.canonical(value) == storage.canonical(current), 'INSTALLER_STORAGE_SOURCE_CHANGED')
    return current


def _create_installation_root(base):
    """Create the private namespace without chmod of an existing home/folder."""
    parent = base.parent
    need(parent.resolve() == parent, 'INSTALLATION_PARENT_LINKED')
    for item in (parent, *parent.parents):
        info = item.lstat()
        sticky = info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX
        need(not stat.S_ISLNK(info.st_mode) and stat.S_ISDIR(info.st_mode)
             and info.st_uid in (0, os.geteuid())
             and (not stat.S_IMODE(info.st_mode) & 0o022 or sticky),
             'INSTALLATION_PARENT_UNSAFE')
    need(parent.stat().st_uid == os.geteuid(), 'INSTALLATION_PARENT_NOT_OWNED')
    source = Path(__file__).resolve().parents[2]
    need(not storage._overlap(base, source), 'INSTALLATION_OVERLAPS_SOURCE')
    for item in base.parents:
        need(not any(os.path.lexists(item / name) for name in
             ('fox.sqlite3', '.native-schema-index.json', '.native-schema')),
             'EXISTING_STORE_ANCESTOR_FORBIDDEN')
    base.mkdir(mode=0o700)  # create only; never adopt or change parent permissions
    storage._sync(parent)
    storage._private_dir(base)


def initialize(value, *, expected_plan_sha256, apply=False):
    """Create once, or inspect the same stage. Never adopt unknown directories."""
    need(apply is True, 'EXPLICIT_INSTALLER_STORAGE_APPLY_REQUIRED')
    value = _checked(value, expected_plan_sha256)
    declared = value['storage_plan']
    storage._runtime(declared)  # Actual nonroot POSIX owner, before any write.
    base = Path(value['installation_root'])
    created = False
    if os.path.lexists(base):
        storage._private_dir(base)
        allowed = {MARKER, *DIRECTORIES.values()}
        for index, path in enumerate(base.iterdir()):
            need(index < len(allowed) and path.name in allowed,
                 'EXISTING_INSTALLATION_CONTENTS_REQUIRE_REVIEW')
        need((base / MARKER).is_file(), 'EXISTING_INSTALLATION_NOT_ADOPTED')
        need(storage._read(base / MARKER) == storage.canonical(value),
             'RETAINED_INSTALLER_STORAGE_PLAN_CHANGED')
    else:
        _create_installation_root(base)
        storage._write(base / MARKER, storage.canonical(value))
        storage._sync(base)
        created = True
    observed = storage.inspect_storage(declared, expected_plan_sha256=storage.plan_sha256(declared))
    if observed['status'] == 'NOT_STARTED':
        # A retained plan with zero S0 roots may continue: the existing S0
        # inspector proved no producer attempt began. Partial roots/intents do
        # not select this branch, and failed writes are never replayed.
        storage.initialize_storage(declared, expected_plan_sha256=storage.plan_sha256(declared), apply=True)
        observed = storage.inspect_storage(declared, expected_plan_sha256=storage.plan_sha256(declared))
        created = True
    need(observed['status'] == 'LOCAL_STORAGE_BASELINE_OBSERVED_NOT_ADMITTED',
         'STORAGE_ATTENTION_NO_REPLAY')
    need(storage._read(base / MARKER) == storage.canonical(value),
         'RETAINED_INSTALLER_STORAGE_PLAN_CHANGED')
    return {'schema_version': 1, 'scope': SCOPE,
        'status': 'STORAGE_INITIALIZED_NOT_INSTALLED' if created else 'STORAGE_REUSED_NOT_INSTALLED',
        'read_only': not created, 'installation_id': observed['installation_id'],
        'storage_completion_sha256': observed['completion_sha256'],
        'conversion_ready': False, 'connected_admission': False,
        'services_started': False, 'automatic_replay_permitted': False}
