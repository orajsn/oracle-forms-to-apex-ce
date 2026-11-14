"""Startup-only retention of unresolved bytes. Never closure or execution authority.

The private maintenance caller must hold its actual exclusion lease, independently
measure current identities/profiles and host quiescence, and recheck afterwards.
A digest or caller-authored packet alone cannot establish that authority.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

BASELINE_SCOPE = 'fox-inert-startup-baseline-v1'
READ_SCOPE = 'fox-inert-startup-paired-read-v1'
PURPOSE = 'maintenance_inert_startup_preservation'
STATE = 'inert_unresolved_history'
RUNTIME_CANDIDATE = 'runtime_intent_candidate'
OPAQUE_BOUNDARY = 'opaque_unresolved'


class PreservationError(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise PreservationError(code)


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def sha(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


def runtime_identity(request, imported, snapshot):
    """Existing browser naming projection ONLY; no import-success assertion.

    Keep byte-compatible with prototype_package.runtime_binding's returned
    identity. This does not call its semantic validators or adopt old receipts.
    """
    return {'schema_version': 1, 'scope': 'fox-native-blueprint-runtime-v1',
        'profile_id': request['rendering_spec']['profile_id'],
        **{key: request[key] for key in ('job_id', 'project_id', 'source_binding', 'plan_sha256', 'rendered_zip_sha256')},
        'artifact_binding_sha256': hashed(snapshot), 'import_receipt_sha256': hashed(imported),
        **{key: imported[key] for key in ('application_id', 'application_alias')}, 'workspace': 'FORMS2APEX_POC'}


def runtime_target(jobs):
    """Unique runtime candidate's saved target, never an opaque row's authority."""
    targets = [item['target_profile_sha256'] for item in jobs.values()
               if item['boundary'] == RUNTIME_CANDIDATE]
    need(targets and all(sha(value) for value in targets) and len(set(targets)) == 1,
         'INERT_RUNTIME_TARGET_UNCONFIRMED')
    return {'target_profile_sha256': targets[0]}


def receiver_job_tree(root, job_id):
    """Full existing tree OR genuine missing child bound to its current parent."""
    import os
    import stat
    from .verification_recovery import preclaim_tree, _need
    root = Path(root).absolute()
    _need(re.fullmatch('fox-[a-f0-9]{20}', job_id) is not None and root.resolve() == root,
          'INERT_RECEIVER_ROOT_UNSAFE')
    for parent in (root, *root.parents):
        _need(not parent.is_symlink(), 'INERT_RECEIVER_ROOT_UNSAFE')
    before = root.lstat()
    _need(stat.S_ISDIR(before.st_mode) and (os.name == 'nt' or
          before.st_uid == os.getuid() and not before.st_mode & 0o022), 'INERT_RECEIVER_ROOT_UNSAFE')
    namespace = lambda info: {'device': info.st_dev, 'inode': info.st_ino,
                             'owner': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}
    path = root / job_id
    _need(not path.is_symlink(), 'INERT_RECEIVER_ROOT_UNSAFE')
    value = preclaim_tree(path) if path.exists() else {'absent': True, 'parent_namespace': namespace(before)}
    _need(namespace(root.lstat()) == namespace(before) and root.resolve() == root,
          'INERT_RECEIVER_NAMESPACE_CHANGED')
    return value


def receiver_collector_source():
    """Fixed stdlib no-follow collector. Runs only at configured private roots."""
    import inspect
    from .verification_recovery import RecoveryError, _need, digest, _load, preclaim_tree
    # Remove only this fixed package import in the standalone stdlib emitter.
    tree_source = inspect.getsource(receiver_job_tree).replace(
        '    from .verification_recovery import preclaim_tree, _need\n', '')
    functions = (RecoveryError, _need, digest, _load, preclaim_tree, hashed, runtime_identity)
    return ('import hashlib,json,pathlib,re,sys\nfrom pathlib import Path\n' +
        '\n'.join(inspect.getsource(function) for function in functions) + '\n' + tree_source + '''
p=json.load(sys.stdin);assert set(p)=={'receiver_jobs','jobs'}
root=Path(p['receiver_jobs']);assert root.is_absolute() and root.resolve()==root
assert 0<len(p['jobs'])<=100 and all(re.fullmatch('fox-[a-f0-9]{20}',j) for j in p['jobs'])
before={j:receiver_job_tree(root,j) for j in p['jobs']}
entries=list(root.iterdir());assert len(entries)<=4096
for job in entries:
 assert not job.is_symlink() and job.is_dir()
 stage=job/'prototype-converter';assert not stage.is_symlink()
 for name in ('runtime-request.json','runtime-claim.json','runtime-result.json','runtime-receipt.json','runtime-evidence'):
  path=stage/name;assert not path.exists() and not path.is_symlink()
identities={};requests={}
for job in p['jobs']:
 if before[job].get('absent') is True:continue
 stage=root/job/'prototype-converter'
 for name in ('verify_runtime.json','export-request.json','export-intent.json','export-attempt.json','export.json','prototype-package.zip'):
  path=stage/name;assert not path.exists() and not path.is_symlink()
 # Earlier unresolved jobs have no runtime envelope to interpret or validate.
 # A partial/present runtime envelope is NEVER downgraded to opaque.
 runtime=[(stage/n).exists() or (stage/n).is_symlink() for n in
  ('verify_runtime-request.json','verify_runtime-intent.json')]
 if not any(runtime):continue
 assert all(runtime)
 documents={n:_load((stage/n).read_bytes(),20000000) for n in
  ('verify_runtime-request.json','verify_runtime-intent.json','import.json','snapshot.json')}
 request=documents['verify_runtime-request.json'];assert request['job_id']==job
 assert documents['verify_runtime-intent.json']=={'request_sha256':hashed(request)}
 assert set(request['prior_receipts'])=={'validate','prepare_schema','import'}
 assert request['prior_receipts']['import']==documents['import.json']
 identities[job]=runtime_identity(request,documents['import.json'],documents['snapshot.json'])
 requests[job]=hashed(request)
assert before=={j:receiver_job_tree(root,j) for j in p['jobs']}
print(json.dumps({'receiver':before,'identities':identities,'requests':requests},sort_keys=True))
''')


def database_projection(db):
    """Exact schema/data digest, including unknown history; no semantic adoption.

    Operator-contact recency is deliberately excluded: it is mutable liveness
    telemetry, never job/queue/consent authority. Everything else is retained.
    """
    schema = [tuple(row) for row in db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
    need(len(schema) <= 512, 'INERT_DATABASE_BOUNDS')
    tables = {}
    for kind, name, _, _ in schema:
        if kind != 'table' or name == 'verification_operator_contact':
            continue
        need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name), 'INERT_DATABASE_TABLE_INVALID')
        cursor = db.execute('SELECT * FROM "' + name + '"')
        columns = [item[0] for item in cursor.description]
        rows = cursor.fetchmany(10001)
        need(len(rows) <= 10000, 'INERT_DATABASE_BOUNDS')
        def atom(value):
            return {'blob': base64.b64encode(value).decode('ascii')} if type(value) is bytes else value
        row_hashes = sorted(hashed([atom(value) for value in row]) for row in rows)
        tables[name] = {'columns': columns, 'rows': len(rows), 'sha256': hashed(row_hashes)}
    return {'schema_sha256': hashed(schema), 'tables': tables}


def observe_fox(database, db):
    """Read every paused identity and full tree; refuse independently runnable work."""
    from .verification_recovery import preclaim_tree, _load
    need(db.execute('PRAGMA query_only').fetchone()[0] == 1, 'INERT_QUERY_ONLY_REQUIRED')
    need(not db.execute("SELECT 1 FROM runs WHERE state IN ('QUEUED','PROCESSING') LIMIT 1").fetchone(),
         'INERT_RUNNABLE_CONVERSION_PRESENT')
    projection = database_projection(db)
    tables = projection['tables']
    if 'verification_queue' in tables:
        need(not db.execute("SELECT 1 FROM verification_queue WHERE state IN ('queued','running') LIMIT 1").fetchone(),
             'INERT_RUNNABLE_VERIFICATION_PRESENT')
    if 'verification_retry_attempts' in tables:
        need('verification_retry_events' in tables, 'INERT_RETRY_HISTORY_UNKNOWN')
        for row in db.execute('SELECT attempt_id FROM verification_retry_attempts'):
            event = db.execute('SELECT state FROM verification_retry_events WHERE attempt_id=? ORDER BY sequence DESC LIMIT 1',
                               (row[0],)).fetchone()
            need(event is not None and event[0] == 'completed', 'INERT_RUNNABLE_OR_UNRESOLVED_RETRY_PRESENT')
    jobs, trees = {}, {}
    rows = list(db.execute("SELECT * FROM runs WHERE state='ATTENTION' AND artifact IS NULL ORDER BY id"))
    need(0 < len(rows) <= 100, 'INERT_PAUSED_JOB_INVENTORY_REQUIRED')
    for row in rows:
        run = dict(row); identity = run['id']
        need(type(identity) is str and re.fullmatch('fox-[a-f0-9]{20}', identity), 'INERT_JOB_INVALID')
        for table, column in (('verification_queue', 'job_id'), ('verification_retry_attempts', 'job_id'),
                              ('technical_verifications', 'run'), ('acceptances', 'run')):
            if table in tables:
                need(db.execute('SELECT 1 FROM ' + table + ' WHERE ' + column + '=?', (identity,)).fetchone() is None,
                     'INERT_PAUSED_JOB_LEDGER_PRESENT')
        job = Path(database).absolute().parent / 'jobs' / identity
        trees[identity] = preclaim_tree(job)
        snapshot = _load((job / 'source-snapshot.json').read_bytes(), 20_000_000)
        owner = db.execute('SELECT owner FROM projects WHERE id=?', (run['project'],)).fetchone()
        selection = db.execute('SELECT current_source_set_id FROM project_source_selection WHERE project=?',
                               (run['project'],)).fetchone()
        need(owner is not None and owner[0] == snapshot['approvals']['owner']
             and selection is not None and selection[0] == snapshot['selected_source_set_id']
             and run['source_hash'] == snapshot['source_hash'] and run['project'] == snapshot['project_id'],
             'INERT_OWNER_OR_SOURCE_CHANGED')
        files = trees[identity]['files']
        nodes = set(files) | set(trees[identity]['directories'])
        need(not any(name in nodes for name in ('prototype-pipeline/verify_runtime.json',
             'prototype-pipeline/export-intent.json', 'prototype-pipeline/export.json',
             'prototype-pipeline/prototype-package.zip', 'prototype-pipeline/runtime-request.json',
             'prototype-pipeline/runtime-claim.json', 'prototype-pipeline/runtime-result.json',
             'prototype-pipeline/runtime-receipt.json', 'prototype-pipeline/runtime-evidence')), 'INERT_UNSUPPORTED_BOUNDARY')
        runtime = 'prototype-pipeline/verify_runtime-intent.json' in nodes
        need(not runtime or 'prototype-pipeline/verify_runtime-intent.json' in files, 'INERT_RUNTIME_INTENT_INVALID')
        request_name = 'prototype-pipeline/verify_runtime-request.json'
        need(request_name not in nodes or runtime and request_name in files, 'INERT_RUNTIME_INTENT_INVALID')
        request_sha = None
        if runtime:
            intent = _load((job / 'prototype-pipeline/verify_runtime-intent.json').read_bytes())
            need(type(intent) is dict and set(intent) == {'request_sha256'} and sha(intent['request_sha256']),
                 'INERT_RUNTIME_INTENT_INVALID')
            request_sha = intent['request_sha256']
        jobs[identity] = {'row': run, 'owner': owner[0], 'source_set_id': selection[0],
                          'target_profile_sha256': snapshot['prototype']['target_profile_sha256'],
                          'boundary': RUNTIME_CANDIDATE if runtime else OPAQUE_BOUNDARY,
                          'runtime_request_sha256': request_sha}
    need(db.total_changes == 0, 'INERT_DATABASE_CHANGED')
    return {'database': projection, 'jobs': jobs, 'fox': trees}


def validate_baseline(value):
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'database', 'jobs', 'fox', 'receiver', 'runtime'}
         and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['scope'] == BASELINE_SCOPE and type(value['jobs']) is dict
         and 0 < len(value['jobs']) <= 100 and set(value['fox']) == set(value['receiver']) == set(value['jobs']),
         'INERT_EXPLICIT_BASELINE_REQUIRED')
    for job, item in value['jobs'].items():
        need(item.get('boundary') in (RUNTIME_CANDIDATE, OPAQUE_BOUNDARY)
             and (sha(item.get('runtime_request_sha256')) if item['boundary'] == RUNTIME_CANDIDATE
                  else item.get('runtime_request_sha256') is None), 'INERT_BOUNDARY_INVALID')
        tree = value['receiver'][job]
        if tree.get('absent') is True:
            need(item['boundary'] == OPAQUE_BOUNDARY and set(tree) == {'absent', 'parent_namespace'}
                 and type(tree['parent_namespace']) is dict
                 and set(tree['parent_namespace']) == {'device','inode','owner','mode'},
                 'INERT_RECEIVER_ABSENCE_INVALID')
    return value


def validate_pair(database, db, job_id, readback, expected, *, now=None):
    """Protected maintenance only. Unknown history stays unknown and blocked."""
    baseline = validate_baseline(expected['baseline'])
    need(type(expected) is dict and set(expected) == {'baseline', 'baseline_sha256', 'identity'}
         and hashed(baseline) == expected['baseline_sha256'], 'INERT_BASELINE_CHANGED')
    need(type(readback) is dict and set(readback) == {'schema_version', 'scope', 'observed_at_utc',
        'expires_at_utc', 'binding', 'fox', 'receiver', 'host', 'identity'}
         and type(readback['schema_version']) is int and readback['schema_version'] == 1
         and readback['scope'] == READ_SCOPE and readback['binding'] == expected['baseline_sha256']
         and readback['identity'] == expected['identity'], 'INERT_PAIRED_BINDING_CHANGED')
    clock = datetime.now(timezone.utc) if now is None else now
    observed, expires = (datetime.fromisoformat(readback[key].replace('Z', '+00:00'))
                         for key in ('observed_at_utc', 'expires_at_utc'))
    need(observed.tzinfo is not None and expires.tzinfo is not None and clock.tzinfo is not None
         and -5 <= (clock-observed).total_seconds() <= 30
         and 0 < (expires-observed).total_seconds() <= 30 and clock <= expires, 'INERT_PAIRED_READ_EXPIRED')
    identity = expected['identity']
    need(type(identity) is dict and set(identity) == {'pair_sha256', 'lease_sha256', 'release_sha256',
        'source_sha256', 'profile_sha256', 'runtime_state', 'stopped_writer_sha256', 'admission'}
         and all(sha(identity[key]) for key in ('pair_sha256', 'lease_sha256', 'release_sha256',
             'source_sha256', 'profile_sha256'))
         and identity['admission'] == {'enabled': True, 'release_sha256': identity['release_sha256']}
         and type(identity['admission']['enabled']) is bool
         and identity['runtime_state'] in ('running', 'stopped')
         and (sha(identity['stopped_writer_sha256']) if identity['runtime_state'] == 'stopped'
              else identity['stopped_writer_sha256'] is None), 'INERT_CURRENT_IDENTITY_REQUIRED')
    actual = observe_fox(database, db)
    need(actual == readback['fox'] == {key: baseline[key] for key in ('database', 'jobs', 'fox')}
         and job_id in actual['jobs'] and readback['receiver'] == baseline['receiver'], 'INERT_RETAINED_FLOOR_CHANGED')
    host = readback['host']
    need(type(host) is dict and set(host) == {'runtime_sha256', 'receiver_sha256', 'observation_sha256', 'blockers'}
         and host['runtime_sha256'] == hashed(baseline['runtime'])
         and host['receiver_sha256'] == hashed(readback['receiver']) and sha(host['observation_sha256'])
         and host['blockers'] == [], 'INERT_HOST_MEASUREMENT_REQUIRED')
    # This deliberately does NOT call _eligibility, validate old stage success,
    # authorize_current, or any model/import/recovery/continuation operation.
    return {'admission': {'blocks_admission': True, 'recovery_state': STATE, 'retry_eligible': False},
            'preservation_allowed': True, 'preservation_state': STATE,
            'preserved': {'baseline_sha256': expected['baseline_sha256'], 'unresolved': True,
                          'boundary': 'runtime_predispatch_unresolved' if baseline['jobs'][job_id]['boundary'] == RUNTIME_CANDIDATE else OPAQUE_BOUNDARY,
                          'closure_claimed': False, 'continuation_authorized': False}}
