"""Exact retained-project copy for isolated delivery QA, never a new proof.

The exporter is read-only. Its caller must first verify the live deployment
identity; this module does not turn self-described JSON into cloud authority.
The isolated seed and audit always call FOX's actual retained-proof reader.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

OWNER = 'synthetic-project-delivery'
NOTES = 'Automated isolated delivery QA only. Not Jason approval, customer review, business equivalence, or live acceptance.'
SCOPE = 'fox-genuine-project-delivery-input-v1'
FILES = (
    'source-snapshot.json', 'release-evidence.json',
    'native-project-pipeline/download.json', 'native-project-pipeline/target-profile.json',
    'project-technical-verification/verification.json',
    'project-technical-verification/verification-profile.json',
    'project-technical-verification/allocation-receipt.json',
    'project-technical-verification/attempt.json',
    'project-technical-verification/clean-install.json',
    'project-technical-verification/qa-result.json',
    'project-technical-verification/qa-target.json',
    'project-technical-verification/qa-profile.json', 'apex-package.zip',
)
MAX_EXPORT = 48_000_000
MAX_PACKAGE = 8_000_000
MAX_JSON = 2_000_000
HASH = re.compile(r'[a-f0-9]{64}\Z')
JOB = re.compile(r'fox-[a-f0-9]{20}\Z')
PROJECT = re.compile(r'[a-f0-9]{32}\Z')
BINDING_FIELDS = {'job_id', 'project_id', 'source_hash', 'package_sha256', 'proof_sha256',
                  'fox_image', 'release_sha256'}
PROJECT_FIELDS = ('id', 'owner', 'customer', 'name', 'description', 'created')
RUN_FIELDS = ('id', 'project', 'source_hash', 'state', 'message', 'created', 'updated', 'artifact')
TECHNICAL_FIELDS = ('run', 'source_hash', 'artifact_sha256', 'proof_sha256', 'proof_json', 'created')


class DeliveryError(RuntimeError):
    """Only bounded categories, never source/credentials/provider messages."""


def need(ok, code):
    if not ok:
        raise DeliveryError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                           allow_nan=False) + '\n').encode()
    except (ValueError, TypeError, UnicodeError):
        raise DeliveryError('INVALID_CANONICAL_JSON') from None


def parsed(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError):
        raise DeliveryError('INVALID_JSON') from None


def binding(value):
    need(type(value) is dict and set(value) == BINDING_FIELDS, 'EXACT_BINDING_REQUIRED')
    need(type(value['job_id']) is str and JOB.fullmatch(value['job_id'])
         and type(value['project_id']) is str and PROJECT.fullmatch(value['project_id']), 'INVALID_RUN_IDENTITY')
    need(all(type(value[key]) is str and HASH.fullmatch(value[key])
             for key in ('source_hash', 'package_sha256', 'proof_sha256', 'release_sha256')),
         'EXACT_DIGEST_BINDING_REQUIRED')
    need(type(value['fox_image']) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', value['fox_image']),
         'IMMUTABLE_FOX_IMAGE_REQUIRED')
    return dict(value)


def read(path, maximum=MAX_JSON):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path and not any(p.is_symlink() for p in (path, *path.parents)),
         'REGULAR_INPUT_PATH_REQUIRED')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum,
         'BOUNDED_REGULAR_INPUT_REQUIRED')
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        need((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), 'INPUT_IDENTITY_CHANGED')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    need((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
         and len(raw) == before.st_size, 'INPUT_CHANGED')
    return raw


def row(connection, sql, parameters):
    cursor = connection.execute(sql, parameters)
    found = cursor.fetchone()
    return dict(zip((item[0] for item in cursor.description), found)) if found is not None else None


def _rows(connection, expected):
    project = row(connection, 'SELECT * FROM projects WHERE id=?', (expected['project_id'],))
    run = row(connection, 'SELECT * FROM runs WHERE id=? AND project=?',
              (expected['job_id'], expected['project_id']))
    technical = row(connection, 'SELECT * FROM technical_verifications WHERE run=?', (expected['job_id'],))
    need(project is not None and run is not None and technical is not None, 'GENUINE_PROJECT_ROWS_REQUIRED')
    need(set(project) == set(PROJECT_FIELDS) and set(run) == set(RUN_FIELDS)
         and set(technical) == set(TECHNICAL_FIELDS), 'UNEXPECTED_DATABASE_ROW_SHAPE')
    need(connection.execute('SELECT COUNT(*) FROM acceptances WHERE run=?', (expected['job_id'],)).fetchone()[0] == 0,
         'LIVE_ACCEPTANCE_MUST_REMAIN_ABSENT')
    return project, run, technical


def export_readonly(root, expected):
    """Run inside the independently pinned live FOX image; no session/login/write."""
    expected = binding(expected)
    root = Path(root).absolute()
    from fox.technical_release import checked_release
    database = root / 'fox.sqlite3'
    need(database.resolve(strict=True) == database and not database.is_symlink(), 'EXACT_DATA_ROOT_REQUIRED')
    job = root / 'jobs' / expected['job_id']
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        connection.execute('PRAGMA query_only=ON'); connection.execute('BEGIN')
        project, run, technical = _rows(connection, expected)
        need(run['state'] == 'VERIFIED', 'GENUINE_UNACCEPTED_VERIFIED_RUN_REQUIRED')
        checked = checked_release(connection, root, run)
        need(type(checked) is dict and sha(checked['package']) == expected['package_sha256']
             and checked['proof']['scope'] == 'fox-project-technical-verification-v1'
             and checked['proof']['human_acceptance_recorded'] is False, 'GENUINE_PROJECT_PROOF_REQUIRED')
        files = {}
        for name in FILES:
            raw = read(job / name, MAX_PACKAGE if name.endswith('.zip') else MAX_JSON)
            files[name] = {'bytes': len(raw), 'sha256': sha(raw), 'base64': base64.b64encode(raw).decode()}
        need(checked['package'] == base64.b64decode(files['apex-package.zip']['base64']), 'PACKAGE_CHANGED_DURING_EXPORT')
        need((project, run, technical) == _rows(connection, expected), 'ROWS_CHANGED_DURING_EXPORT')
    # A repeated read in one WAL transaction sees the same old snapshot. Use
    # an independent final read to observe a concurrent real owner acceptance.
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        connection.execute('PRAGMA query_only=ON'); connection.execute('BEGIN')
        need((project, run, technical) == _rows(connection, expected), 'ROWS_CHANGED_DURING_EXPORT')
        final = checked_release(connection, root, run)
        need(final == checked, 'GENUINE_PROOF_CHANGED_DURING_EXPORT')
        for name, item in files.items():
            need(sha(read(job / name, MAX_PACKAGE if name.endswith('.zip') else MAX_JSON)) == item['sha256'],
                 'FILES_CHANGED_DURING_EXPORT')
    value = {'schema_version': 1, 'scope': SCOPE, 'read_only': True, 'binding': expected,
        'project': project, 'run': run, 'technical_verification': technical, 'files': files,
        'live_acceptance_count': 0, 'source_scope': 'caller-approved-labelled-synthetic-project',
        'authority': 'caller-must-independently-verify-live-deployment',
        'exported_at_utc': datetime.now(timezone.utc).isoformat()}
    raw = canonical(value)
    validate_export(raw, expected_sha256=sha(raw), expected_binding=expected)
    return raw


def validate_export(raw, *, expected_sha256, expected_binding):
    expected_binding = binding(expected_binding)
    need(type(raw) is bytes and 0 < len(raw) <= MAX_EXPORT and type(expected_sha256) is str
         and HASH.fullmatch(expected_sha256) and sha(raw) == expected_sha256, 'EXACT_EXPORT_BYTES_REQUIRED')
    value = parsed(raw)
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'read_only', 'binding',
        'project', 'run', 'technical_verification', 'files', 'live_acceptance_count', 'source_scope',
        'authority', 'exported_at_utc'} and canonical(value) == raw, 'EXPORT_SHAPE_OR_CANONICAL_BYTES_INVALID')
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and value['scope'] == SCOPE
         and value['read_only'] is True and type(value['live_acceptance_count']) is int
         and value['live_acceptance_count'] == 0 and value['binding'] == expected_binding
         and value['source_scope'] == 'caller-approved-labelled-synthetic-project'
         and value['authority'] == 'caller-must-independently-verify-live-deployment', 'EXPORT_BINDING_CHANGED')
    files = value['files']
    need(type(files) is dict and set(files) == set(FILES), 'EXACT_PROJECT_FILE_CLOSURE_REQUIRED')
    decoded = {}
    for name, item in files.items():
        maximum = MAX_PACKAGE if name.endswith('.zip') else MAX_JSON
        need(type(item) is dict and set(item) == {'sha256', 'bytes', 'base64'}
             and type(item['bytes']) is int and 0 < item['bytes'] <= maximum
             and type(item['base64']) is str and len(item['base64']) <= maximum * 2,
             'EXPORTED_FILE_BOUND_INVALID')
        try:
            content = base64.b64decode(item['base64'], validate=True)
        except (ValueError, TypeError):
            raise DeliveryError('EXPORTED_FILE_ENCODING_INVALID') from None
        need(len(content) == item['bytes'] and sha(content) == item['sha256'], 'EXPORTED_FILE_HASH_CHANGED')
        decoded[name] = content
    snapshot = parsed(decoded['source-snapshot.json'])
    proof_raw = decoded['project-technical-verification/verification.json']
    proof = parsed(proof_raw)
    project, run, technical = value['project'], value['run'], value['technical_verification']
    need(type(project) is dict and set(project) == set(PROJECT_FIELDS)
         and type(run) is dict and set(run) == set(RUN_FIELDS)
         and type(technical) is dict and set(technical) == set(TECHNICAL_FIELDS), 'EXPORTED_ROW_FIELDS_CHANGED')
    need(all(type(project[name]) is str for name in ('id', 'owner', 'customer', 'name', 'description'))
         and all(type(run[name]) is str for name in ('id', 'project', 'source_hash', 'state', 'message', 'artifact'))
         and type(technical['proof_json']) is str
         and run['artifact'].replace('\\', '/') == f"jobs/{expected_binding['job_id']}/apex-package.zip",
         'ORIGINAL_ROW_OR_ARTIFACT_IDENTITY_INVALID')
    need(project['id'] == run['project'] == snapshot.get('project') == snapshot.get('project_id') == expected_binding['project_id']
         and project['name'] == snapshot.get('project_name') and run['id'] == technical['run'] == expected_binding['job_id']
         and run['state'] == 'VERIFIED' and snapshot.get('conversion_profile') == 'native-project-v1'
         and snapshot.get('source_hash') == run['source_hash'] == technical['source_hash'] == expected_binding['source_hash'],
         'EXPORTED_PROJECT_OR_SOURCE_CHANGED')
    need(sha(decoded['apex-package.zip']) == technical['artifact_sha256'] == expected_binding['package_sha256']
         and sha(proof_raw) == technical['proof_sha256'] == expected_binding['proof_sha256']
         and technical['proof_json'].encode() == proof_raw and proof.get('human_acceptance_recorded') is False
         and proof.get('scope') == 'fox-project-technical-verification-v1', 'EXPORTED_PROOF_OR_PACKAGE_CHANGED')
    need(all(type(v) in (int, float) and math.isfinite(v) and v >= 0
             for v in (project['created'], run['created'], run['updated'], technical['created'])), 'ORIGINAL_TIME_REQUIRED')
    spec = snapshot.get('native_project', {})
    need(type(spec) is dict and spec.get('profile_id') == 'native-project-v1'
         and spec.get('data_mode') == 'synthetic_test_only' and type(spec.get('forms')) is list
         and 2 <= len(spec['forms']) <= 20, 'MULTI_FORM_SYNTHETIC_PROJECT_REQUIRED')
    return value, decoded, snapshot


def _new(path, raw):
    for parent in path.parents:
        if parent.exists() or parent.is_symlink():
            need(not parent.is_symlink() and parent.resolve(strict=True) == parent, 'LINKED_COPY_PARENT_FORBIDDEN')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(path.parent.resolve(strict=True) == path.parent, 'LINKED_COPY_PARENT_FORBIDDEN')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def seed_isolated(root, raw, *, expected_sha256, expected_binding):
    """The actual app schema must already exist in a fresh isolated data root."""
    from fox import source_history
    from fox.technical_release import checked_release
    from fox.intake import inventory
    root = Path(root).absolute()
    need(root.resolve(strict=True) == root and not root.is_symlink(), 'ISOLATED_ROOT_REQUIRED')
    value, files, snapshot = validate_export(raw, expected_sha256=expected_sha256, expected_binding=expected_binding)
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        need(all(connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] == 0
                 for table in ('projects', 'runs', 'sessions', 'acceptances', 'sources')),
             'FRESH_ISOLATED_DATABASE_REQUIRED')
        # create_app truthfully records its one schema initialization event.
        # It is not a project, conversion, prior acceptance or disposable row.
        need(connection.execute('SELECT owner,action,object_id FROM events').fetchall() ==
             [('system-source-history', 'source_history_initialized', 'schema-v1')],
             'EXACT_FRESH_SCHEMA_EVENT_REQUIRED')
    job = root / 'jobs' / value['run']['id']
    need(not job.exists() and not job.is_symlink(), 'EXISTING_JOB_CANNOT_BE_REPLACED')
    for name, content in files.items():
        _new(job / name, content)
    now = time.time()
    project, run, technical = dict(value['project']), dict(value['run']), value['technical_verification']
    project.update(owner=OWNER, customer='Automated isolated delivery QA only', description=NOTES)
    run['artifact'] = str((job / 'apex-package.zip').relative_to(root))
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        connection.execute('PRAGMA foreign_keys=ON'); connection.execute('BEGIN IMMEDIATE')
        connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', tuple(project[key] for key in PROJECT_FIELDS))
        source_history.create_project_selection(connection, project['id'], now)
        source_history.publish_upload(connection, project['id'], snapshot['files'], now, OWNER)
        need(inventory(source_history.selected_sources(connection, project['id']))['source_hash'] == snapshot['source_hash'],
             'ISOLATED_SOURCE_SELECTION_CHANGED')
        connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', tuple(run[key] for key in RUN_FIELDS))
        connection.execute('CREATE TABLE IF NOT EXISTS technical_verifications('
            'run TEXT PRIMARY KEY REFERENCES runs(id),source_hash TEXT NOT NULL,artifact_sha256 TEXT NOT NULL,'
            'proof_sha256 TEXT NOT NULL,proof_json TEXT NOT NULL,created REAL NOT NULL)')
        connection.execute('INSERT INTO technical_verifications VALUES(?,?,?,?,?,?)',
                           tuple(technical[key] for key in TECHNICAL_FIELDS))
        checked = checked_release(connection, root, run)
        need(checked['package'] == files['apex-package.zip'] and checked['proof']['human_acceptance_recorded'] is False,
             'ACTUAL_RETAINED_PROJECT_CHECK_FAILED')
    return {'project_id': project['id'], 'project_name': project['name'], 'run_id': run['id'],
        'source_hash': run['source_hash'], 'package_sha256': expected_binding['package_sha256'],
        'package_bytes': len(files['apex-package.zip']), 'proof_sha256': expected_binding['proof_sha256'],
        'form_count': len(snapshot['native_project']['forms']), 'notes': NOTES, 'owner': OWNER,
        'input_sha256': expected_sha256, 'producer_files': {name: sha(content) for name, content in files.items()},
        'live_acceptance_recorded': False, 'simulated_oracle_receipts': False}


def audit_isolated(root, raw, *, expected_sha256, expected_binding, accepted):
    from fox.technical_release import checked_release
    root = Path(root).absolute()
    need(type(accepted) is bool and root.resolve(strict=True) == root
         and not any(path.is_symlink() for path in (root, *root.parents)), 'ISOLATED_AUDIT_ROOT_REQUIRED')
    value, files, _ = validate_export(raw, expected_sha256=expected_sha256, expected_binding=expected_binding)
    job = root / 'jobs' / expected_binding['job_id']
    entries = list(job.rglob('*'))
    need(all(not path.is_symlink() and path.resolve(strict=True) == path for path in entries),
         'LINKED_PRODUCER_EVIDENCE_FORBIDDEN')
    need({path.relative_to(job).as_posix() for path in entries if path.is_file()} == set(FILES),
         'PRODUCER_FILE_INVENTORY_CHANGED')
    need(all(read(job / name, MAX_PACKAGE if name.endswith('.zip') else MAX_JSON) == content
             for name, content in files.items()), 'PRODUCER_BYTES_CHANGED')
    database = root / 'fox.sqlite3'
    need(database.resolve(strict=True) == database and not database.is_symlink(), 'ISOLATED_DATABASE_REQUIRED')
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        connection.execute('PRAGMA query_only=ON'); connection.execute('BEGIN')
        projects = connection.execute('SELECT id,owner,name FROM projects').fetchall()
        need(projects == [(expected_binding['project_id'], OWNER, value['project']['name'])], 'ISOLATED_OWNER_CHANGED')
        run = row(connection, 'SELECT * FROM runs WHERE id=?', (expected_binding['job_id'],))
        need(run is not None and run['state'] == ('ACCEPTED' if accepted else 'VERIFIED'), 'ISOLATED_STATE_CHANGED')
        for name in ('id', 'project', 'source_hash', 'created'):
            need(run[name] == value['run'][name], 'ORIGINAL_RUN_BINDING_CHANGED')
        checked = checked_release(connection, root, run)
        need(checked['package'] == files['apex-package.zip'] and checked['proof']['human_acceptance_recorded'] is False,
             'ACTUAL_RETAINED_PROJECT_CHECK_FAILED')
        technical = row(connection, 'SELECT * FROM technical_verifications WHERE run=?', (run['id'],))
        need(technical == value['technical_verification'], 'TECHNICAL_PROOF_ROW_CHANGED')
        approvals = connection.execute('SELECT run,owner,source_hash,artifact_sha256,notes FROM acceptances').fetchall()
        expected = [(run['id'], OWNER, run['source_hash'], expected_binding['package_sha256'], NOTES)] if accepted else []
        need(approvals == expected, 'ISOLATED_ACCEPTANCE_CHANGED')
        events = connection.execute("SELECT owner,object_id FROM events WHERE action='human_accepted'").fetchall()
        need(events == ([(OWNER, run['id'])] if accepted else []), 'EXACT_SYNTHETIC_EVENT_REQUIRED')
    return {'status': 'ISOLATED_ACCEPTANCE_VERIFIED' if accepted else 'GENUINE_COPY_VERIFIED',
        'producer_bytes_unchanged': True, 'technical_proof_unchanged': True,
        'package_sha256': expected_binding['package_sha256'], 'proof_sha256': expected_binding['proof_sha256'],
        'synthetic_acceptance_count': 1 if accepted else 0, 'live_acceptance_recorded': False,
        'oracle_database_contacted': False, 'model_invoked': False, 'isolated_sqlite_used': True}
