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
BASELINE_SCOPE_V2 = 'fox-inert-startup-baseline-v2'
READ_SCOPE_V2 = 'fox-inert-startup-paired-read-v2'
STATE_V2 = 'inert_mixed_completed_history'
COMPLETED = 'completed_native_prototype'
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
    value = {'schema_version': 1, 'scope': 'fox-native-blueprint-runtime-v1',
        'profile_id': request['rendering_spec']['profile_id'],
        **{key: request[key] for key in ('job_id', 'project_id', 'source_binding', 'plan_sha256', 'rendered_zip_sha256')},
        'artifact_binding_sha256': hashed(snapshot), 'import_receipt_sha256': hashed(imported),
        **{key: imported[key] for key in ('application_id', 'application_alias')}, 'workspace': 'FORMS2APEX_POC'}
    if request['rendering_spec']['profile_id'] == 'native-blueprint-prototype-count-guard-v1':
        # Identity projection only. The measured semantic child separately checks
        # the exact fixture recipe/SQL and the original stage's actual outcome.
        prepared = request['prior_receipts']['prepare_schema']
        need(type(prepared.get('count_guard_fixture')) is dict, 'INERT_COUNT_FIXTURE_BINDING_REQUIRED')
        value['count_guard_fixture_sha256'] = hashed(prepared['count_guard_fixture'])
    return value


def runtime_target(jobs):
    """Unique runtime candidate's saved target, never an opaque row's authority."""
    targets = [item['target_profile_sha256'] for item in jobs.values()
               if item['boundary'] in (RUNTIME_CANDIDATE, COMPLETED)]
    need(targets and all(sha(value) for value in targets) and len(set(targets)) == 1,
         'INERT_RUNTIME_TARGET_UNCONFIRMED')
    return {'target_profile_sha256': targets[0]}


def completed_projection(job):
    """Dependency-bounded fingerprint, NOT semantic completion authority.

    The measured technical child separately checks source/publication/SQLcl and
    exact package semantics. The protected queue reader only repeats these
    deterministic bindings and its full-tree/database comparison.
    """
    from .verification_recovery import _load
    job = Path(job)
    root = job / 'prototype-pipeline'
    read = lambda name: _load((root / name).read_bytes(), 20_000_000)
    binding, plan, rendered = (read(name) for name in ('binding.json', 'native-plan.json', 'rendered.json'))
    authority = {'schema_version': 1, 'scope': 'fox-prototype-source-authority-v1',
        'binding_sha256': hashed(binding), 'sources_manifest_sha256': hashed(read('sources-manifest.json')),
        'review_index_sha256': hashed(read('review-index.json'))}
    base = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1',
        'job_id': job.name, 'project_id': binding['project_id'], 'source_binding': binding['source_binding'],
        'plan_sha256': plan['plan_sha256'], 'rendering_spec': plan['rendering_spec'],
        'rendered_zip_sha256': rendered['zip_sha256'], 'source_authority': authority}
    prior = {}
    for stage in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export'):
        request = {**base, 'prior_receipts': dict(prior)}
        receipt = read(stage + '.json')
        need(read(stage + '-intent.json') == {'request_sha256': hashed(request)}
             and receipt.get('status') == 'COMPLETE' and receipt.get('business_behavior_accepted') is False,
             'INERT_COMPLETED_STAGE_UNCONFIRMED')
        if stage == 'verify_runtime':
            runtime_request = request
        prior[stage] = receipt
    result = _load((job / 'prototype-result.json').read_bytes(), 20_000_000)
    need(result.get('status') == 'APEX_GENERATED' and result.get('stage') == 'complete'
         and result.get('job_id') == job.name and result.get('converter_receipts') == prior,
         'INERT_COMPLETED_RESULT_UNCONFIRMED')
    imported, proof = prior['import'], prior['verify_runtime']['runtime_receipt']
    identity = runtime_identity(runtime_request, imported, prior['validate']['artifact_binding'])
    receipt_sha = hashed(proof)
    need(all(proof.get(key) == value for key, value in identity.items())
         and proof.get('business_behavior_accepted') is False
         and prior['verify_runtime']['runtime_receipt_sha256'] == receipt_sha
         and prior['export']['runtime_receipt_sha256'] == receipt_sha
         and sha(prior['export'].get('package_sha256')), 'INERT_COMPLETED_RUNTIME_UNCONFIRMED')
    return {'runtime_identity': identity, 'runtime_receipt_sha256': receipt_sha,
        'runtime_request_sha256': hashed(runtime_request), 'export_request_sha256': hashed(request),
        'package_sha256': prior['export']['package_sha256'], 'trace_sha256': hashed(rendered['trace']),
        'export_receipt_sha256': hashed(prior['export'])}


def completed_receiver(stage, completed, *, producer_sha256, worker_sha256):
    """Read original successful dispatch only; never renew a historical deadline.

    Source hashes MUST come from the retained configured source inventory, not
    from this packet or currently imported producer. Full tree pins and host
    quiescence are separate mandatory gates in the paired maintenance reader.
    """
    from .verification_recovery import _load, preclaim_tree
    stage = Path(stage)
    before = preclaim_tree(stage)
    need({path.name for path in stage.iterdir() if path.name.startswith('runtime-')} == {
         'runtime-request.json', 'runtime-claim.json', 'runtime-result.json', 'runtime-receipt.json', 'runtime-evidence'},
         'INERT_COMPLETED_MARKERS_UNKNOWN')
    read = lambda name: _load((stage / name).read_bytes(), 20_000_000)
    need(sha(producer_sha256) and sha(worker_sha256), 'INERT_ORIGINAL_RUNTIME_SOURCES_REQUIRED')
    packet = read('runtime-request.json')
    need(type(packet) is dict and set(packet) == {'schema_version', 'scope', 'request', 'imported', 'trace',
         'artifact_binding', 'binding', 'producer', 'issued_at_utc', 'deadline_at_utc', 'target'}
         and type(packet['schema_version']) is int and packet['schema_version'] == 1
         and packet['scope'] == 'fox-prototype-runtime-dispatch-v1'
         and packet['producer'] == {'component': 'fox-prototype-runtime-bridge', 'code_sha256': producer_sha256},
         'INERT_COMPLETED_DISPATCH_CHANGED')
    request = packet['request']; prior = dict(request['prior_receipts'])
    need(hashed(request) == completed['runtime_request_sha256']
         and hashed(packet['trace']) == completed['trace_sha256']
         and packet['target'] == {'workspace': 'FORMS2APEX_POC', 'db_name': 'ASZ8EQWFM8UNCA2_JSNF2APEX',
             'ords_origin': 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com'}
         and packet['binding'] == completed['runtime_identity']
         and packet['imported'] == prior['import'] == read('import.json')
         and packet['artifact_binding'] == prior['validate']['artifact_binding'] == read('snapshot.json')
         and packet['binding'] == runtime_identity(request, packet['imported'], packet['artifact_binding'])
         and request == read('verify_runtime-request.json')
         and read('verify_runtime-intent.json') == {'request_sha256': hashed(request)}
         and set(prior) == {'validate', 'prepare_schema', 'import'}, 'INERT_COMPLETED_REQUEST_CHANGED')
    earlier = {}
    for name in ('validate', 'prepare_schema', 'import'):
        historical = {**request, 'prior_receipts': dict(earlier)}
        need(read(name + '.json') == prior[name]
             and read(name + '-request.json') == historical
             and read(name + '-intent.json') == {'request_sha256': hashed(historical)},
             'INERT_COMPLETED_PRIOR_CHANGED')
        earlier[name] = prior[name]
    archive = (stage / 'candidate-apexlang.zip').read_bytes()
    need(0 < len(archive) <= 64 * 1024 * 1024
         and hashlib.sha256(archive).hexdigest() == request['rendered_zip_sha256'],
         'INERT_COMPLETED_ARCHIVE_CHANGED')
    dispatch = hashed(packet)
    need(read('runtime-claim.json') == {'dispatch_sha256': dispatch, 'worker_sha256': worker_sha256,
         'state': 'CLAIMED_NO_AUTOMATIC_REPLAY'}, 'INERT_COMPLETED_CLAIM_CHANGED')
    receipt = read('runtime-receipt.json')
    result = read('runtime-result.json')
    need(hashed(receipt) == completed['runtime_receipt_sha256']
         and type(result.get('schema_version')) is int
         and result == {'schema_version': 1, 'scope': 'fox-prototype-runtime-result-v1',
             'dispatch_sha256': dispatch, 'binding': packet['binding'], 'worker_sha256': worker_sha256,
             'receipt_sha256': hashed(receipt)}, 'INERT_COMPLETED_RESULT_CHANGED')
    def timestamp(value):
        need(type(value) is str and len(value) <= 40, 'INERT_COMPLETED_TIME_INVALID')
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        need(result.tzinfo is not None and result.utcoffset().total_seconds() == 0, 'INERT_COMPLETED_TIME_INVALID')
        return result
    issued, deadline, started, finished = map(timestamp, (packet['issued_at_utc'], packet['deadline_at_utc'],
        receipt['started_at_utc'], receipt['completed_at_utc']))
    need(0 < (deadline-issued).total_seconds() <= 540 and issued <= started <= finished <= deadline,
         'INERT_COMPLETED_TIME_ORDER_INVALID')
    artifacts = receipt['artifacts']; names = set()
    need(type(artifacts) is list and 0 < len(artifacts) <= 100, 'INERT_COMPLETED_ARTIFACTS_INVALID')
    total = 0
    for row in artifacts:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
             and type(row['path']) is str and re.fullmatch(r'runtime-evidence/[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.(?:json|png)', row['path'])
             and row['path'] not in names and type(row['bytes']) is int and 0 < row['bytes'] <= 5_000_000
             and sha(row['sha256']), 'INERT_COMPLETED_ARTIFACTS_INVALID')
        names.add(row['path']); total += row['bytes']
        raw = (stage / row['path']).read_bytes()
        need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
             'INERT_COMPLETED_ARTIFACT_CHANGED')
    need(total <= 20_000_000 and 'runtime-evidence/browser-report.json' in names
         and {str(path.relative_to(stage)).replace('\\', '/') for path in (stage / 'runtime-evidence').iterdir()} == names
         and read('runtime-evidence/browser-report.json') == {key: value for key, value in receipt.items() if key != 'artifacts'},
         'INERT_COMPLETED_REPORT_CHANGED')
    prior['verify_runtime'] = read('verify_runtime.json')
    export_request = {**request, 'prior_receipts': prior}
    need(hashed(export_request) == completed['export_request_sha256']
         and read('export-request.json') == export_request
         and read('export-intent.json') == {'request_sha256': hashed(export_request)}
         and prior['verify_runtime']['runtime_receipt'] == receipt,
         'INERT_COMPLETED_EXPORT_CHANGED')
    attempt = read('export-attempt.json')
    need(type(attempt) is dict and set(attempt) == {'directory', 'binding'}
         and type(attempt['directory']) is str and attempt['binding'] == packet['binding'],
         'INERT_COMPLETED_EXPORT_ATTEMPT_CHANGED')
    package = (stage / 'prototype-package.zip').read_bytes()
    need(0 < len(package) <= 8_000_000 and hashlib.sha256(package).hexdigest() == completed['package_sha256']
         and read('export.json')['package_sha256'] == completed['package_sha256']
         and hashed(read('export.json')) == completed['export_receipt_sha256'], 'INERT_COMPLETED_PACKAGE_CHANGED')
    need(preclaim_tree(stage) == before, 'INERT_COMPLETED_RECEIVER_CHANGED_DURING_READ')
    return packet


def _receiver_parent_metadata(root, owner):
    """Fingerprint only the product's bounded native-schema index, never adopt it.

    schema_bootstrap.INDEX_NAME is create-only0600 and MAX_RECORD_BYTES=1000000.
    Unknown root files, linked/special nodes and directory-shaped indexes reject.
    Payload bytes remain opaque; no registry or operation success is inferred.
    """
    import os
    import stat
    from .verification_recovery import _need
    entries = list(root.iterdir())
    _need(len(entries) <= 4096, 'INERT_RECEIVER_ROOT_BOUNDS')
    result = {}
    fields = ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    # Windows lstat and fstat can expose different ctime meanings. Keep each
    # source's full before/after pin; only that cross-API comparison is omitted.
    # POSIX still requires every field to match across the path and descriptor.
    identity_fields = fields[:-1] if os.name == 'nt' else fields
    for path in entries:
        info = path.lstat()
        _need(not stat.S_ISLNK(info.st_mode)
              and not getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400),
              'INERT_RECEIVER_ROOT_LINKED')
        if path.name != '.native-schema-index.json':
            _need(stat.S_ISDIR(info.st_mode), 'INERT_RECEIVER_ROOT_ENTRY_UNKNOWN')
            continue
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1_000_000
              and (os.name == 'nt' or info.st_uid == owner and not info.st_mode & 0o022),
              'INERT_RECEIVER_METADATA_UNSAFE')
        with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            _need(all(getattr(opened, name) == getattr(info, name) for name in identity_fields),
                  'INERT_RECEIVER_METADATA_CHANGED')
            raw = stream.read(1_000_001)
            after = os.fstat(stream.fileno())
        final = path.lstat()
        _need(len(raw) == info.st_size
              and all(getattr(opened, name) == getattr(after, name) for name in fields)
              and all(getattr(info, name) == getattr(final, name) for name in fields),
              'INERT_RECEIVER_METADATA_CHANGED')
        result[path.name] = {'kind': 'regular', 'device': info.st_dev, 'inode': info.st_ino,
            'owner': info.st_uid, 'group': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'links': info.st_nlink, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
    return result


def completed_tree(root):
    """Full bytes plus every original inode/owner/mode for completed V2 trees."""
    import stat
    from .verification_recovery import preclaim_tree
    root = Path(root)
    tree = preclaim_tree(root)
    def nodes():
        result = {}
        for path in (root, *(root / name for name in sorted(set(tree['files']) | set(tree['directories'])))):
            info = path.lstat()
            need((stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                 and not getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400),
                 'INERT_COMPLETED_TREE_UNSAFE')
            result[path.relative_to(root).as_posix()] = {
                name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
                    'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        return result
    before = nodes()
    need(preclaim_tree(root) == tree and nodes() == before, 'INERT_COMPLETED_TREE_CHANGED')
    return {**tree, 'node_identities': before}


def receiver_job_tree(root, job_id, *, completed=False):
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
    metadata = _receiver_parent_metadata(root, before.st_uid)
    path = root / job_id
    _need(not path.is_symlink(), 'INERT_RECEIVER_ROOT_UNSAFE')
    value = (completed_tree(path) if completed else preclaim_tree(path)) if path.exists() else {'absent': True}
    _need(_receiver_parent_metadata(root, before.st_uid) == metadata
          and namespace(root.lstat()) == namespace(before) and root.resolve() == root,
          'INERT_RECEIVER_NAMESPACE_CHANGED')
    value.update(parent_namespace=namespace(before), parent_metadata=metadata)
    return value


def receiver_collector_source():
    """Fixed stdlib no-follow collector. Runs only at configured private roots."""
    import inspect
    from .verification_recovery import RecoveryError, _need, digest, _load, preclaim_tree
    # Remove only this fixed package import in the standalone stdlib emitter.
    tree_source = inspect.getsource(receiver_job_tree).replace(
        '    from .verification_recovery import preclaim_tree, _need\n', '')
    metadata_source = inspect.getsource(_receiver_parent_metadata).replace(
        '    from .verification_recovery import _need\n', '')
    completed_source = inspect.getsource(completed_receiver).replace(
        '    from .verification_recovery import _load, preclaim_tree\n', '')
    completed_tree_source = inspect.getsource(completed_tree).replace(
        '    from .verification_recovery import preclaim_tree\n', '')
    functions = (PreservationError, need, sha, RecoveryError, _need, digest, _load, preclaim_tree, hashed, runtime_identity)
    return ('import base64,hashlib,json,pathlib,re,sys\nfrom pathlib import Path\nfrom datetime import datetime\n' +
        '\n'.join(inspect.getsource(function) for function in functions) + '\n' + completed_tree_source + '\n' + metadata_source + '\n' + tree_source + '''
''' + completed_source + '''
p=json.load(sys.stdin);assert set(p) in ({'receiver_jobs','jobs'},{'receiver_jobs','jobs','completed','producer_sha256','worker_sha256'})
completed=p.get('completed',{});assert type(completed)is dict and set(completed)<=set(p['jobs'])
root=Path(p['receiver_jobs']);assert root.is_absolute() and root.resolve()==root
assert 0<len(p['jobs'])<=100 and all(re.fullmatch('fox-[a-f0-9]{20}',j) for j in p['jobs'])
before={j:receiver_job_tree(root,j,completed=j in completed) for j in p['jobs']}
assert all(before[j].get('absent') is not True for j in completed)
entries=list(root.iterdir());assert len(entries)<=4096
for job in entries:
 assert not job.is_symlink()
 if job.name=='.native-schema-index.json':
  assert job.is_file() and all(job.name in tree['parent_metadata'] for tree in before.values())
  continue
 assert job.is_dir()
 stage=job/'prototype-converter';assert not stage.is_symlink()
 if job.name in completed:continue
 for name in ('runtime-request.json','runtime-claim.json','runtime-result.json','runtime-receipt.json','runtime-evidence'):
  path=stage/name;assert not path.exists() and not path.is_symlink()
identities={};requests={};packages={};total=0
for job in p['jobs']:
 if before[job].get('absent') is True:continue
 stage=root/job/'prototype-converter'
 if job in completed:
  packet=completed_receiver(stage,completed[job],producer_sha256=p['producer_sha256'],worker_sha256=p['worker_sha256'])
  identities[job]=packet['binding'];requests[job]=hashed(packet['request'])
  raw=(stage/'prototype-package.zip').read_bytes();total+=len(raw);assert total<=20000000
  packages[job]=base64.b64encode(raw).decode('ascii')
  continue
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
assert before=={j:receiver_job_tree(root,j,completed=j in completed) for j in p['jobs']}
output={'receiver':before,'identities':identities,'requests':requests}
if completed:output['completed_packages']=packages
print(json.dumps(output,sort_keys=True))
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
    rows = list(db.execute("SELECT * FROM runs WHERE state IN ('ATTENTION','GENERATED') AND artifact IS NULL ORDER BY id"))
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
        if run['state'] == 'GENERATED':
            trees[identity] = completed_tree(job)
            completed = completed_projection(job)
            jobs[identity] = {'row': run, 'owner': owner[0], 'source_set_id': selection[0],
                'target_profile_sha256': snapshot['prototype']['target_profile_sha256'],
                'boundary': COMPLETED, 'runtime_request_sha256': completed['runtime_request_sha256'],
                'completed': completed}
            continue
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
    v2 = type(value) is dict and value.get('scope') == BASELINE_SCOPE_V2
    fields = {'schema_version', 'scope', 'database', 'jobs', 'fox', 'receiver', 'runtime'}
    need(type(value) is dict and set(value) == fields | ({'completed_host'} if v2 else set())
         and type(value['schema_version']) is int and value['schema_version'] == (2 if v2 else 1)
         and value['scope'] == (BASELINE_SCOPE_V2 if v2 else BASELINE_SCOPE) and type(value['jobs']) is dict
         and 0 < len(value['jobs']) <= 100 and set(value['fox']) == set(value['receiver']) == set(value['jobs']),
         'INERT_EXPLICIT_BASELINE_REQUIRED')
    parent = None
    for job, item in value['jobs'].items():
        need(item.get('boundary') in ((RUNTIME_CANDIDATE, OPAQUE_BOUNDARY, COMPLETED) if v2 else (RUNTIME_CANDIDATE, OPAQUE_BOUNDARY))
             and (sha(item.get('runtime_request_sha256')) if item['boundary'] in (RUNTIME_CANDIDATE, COMPLETED)
                  else item.get('runtime_request_sha256') is None), 'INERT_BOUNDARY_INVALID')
        if item['boundary'] == COMPLETED:
            proof = item.get('completed')
            need(type(proof) is dict and set(proof) == {'runtime_identity', 'runtime_receipt_sha256',
                 'runtime_request_sha256', 'export_request_sha256', 'package_sha256', 'trace_sha256', 'export_receipt_sha256'}
                 and type(proof['runtime_identity']) is dict and proof['runtime_identity'].get('job_id') == job
                 and all(sha(proof[key]) for key in proof if key != 'runtime_identity')
                 and proof['runtime_request_sha256'] == item['runtime_request_sha256']
                 and item['row']['state'] == 'GENERATED' and item['row']['artifact'] is None,
                 'INERT_COMPLETED_BINDING_INVALID')
            for retained in (value['fox'][job], value['receiver'][job]):
                nodes = retained.get('node_identities')
                need(type(nodes) is dict and set(nodes) == {'.'} | set(retained['files']) | set(retained['directories'])
                     and all(type(pin) is dict and set(pin) == {'st_dev', 'st_ino', 'st_uid', 'st_gid',
                         'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'}
                         and all(type(number) is int for number in pin.values()) for pin in nodes.values()),
                     'INERT_COMPLETED_NODE_IDENTITIES_REQUIRED')
        else:
            need('completed' not in item, 'INERT_COMPLETED_BINDING_INVALID')
        tree = value['receiver'][job]
        need(type(tree) is dict and type(tree.get('parent_namespace')) is dict
             and set(tree['parent_namespace']) == {'device','inode','owner','mode'}
             and all(type(number) is int for number in tree['parent_namespace'].values())
             and type(tree.get('parent_metadata')) is dict
             and set(tree['parent_metadata']) <= {'.native-schema-index.json'}, 'INERT_RECEIVER_PARENT_INVALID')
        for pin in tree['parent_metadata'].values():
            need(type(pin) is dict and set(pin) == {'kind','device','inode','owner','group','mode','links','bytes',
                 'sha256','mtime_ns','ctime_ns'} and pin['kind'] == 'regular' and sha(pin['sha256'])
                 and all(type(pin[name]) is int for name in pin if name not in ('kind','sha256'))
                 and pin['owner'] == tree['parent_namespace']['owner']
                 and pin['links'] == 1 and 0 < pin['bytes'] <= 1_000_000, 'INERT_RECEIVER_METADATA_INVALID')
        actual_parent = tree['parent_namespace'], tree['parent_metadata']
        need(parent is None or parent == actual_parent, 'INERT_RECEIVER_PARENT_CHANGED')
        parent = actual_parent
        if tree.get('absent') is True:
            need(item['boundary'] == OPAQUE_BOUNDARY and set(tree) == {'absent', 'parent_namespace','parent_metadata'},
                 'INERT_RECEIVER_ABSENCE_INVALID')
        else:
            need(set(tree) == {'files','directories','namespace','parent_namespace','parent_metadata'}
                 | ({'node_identities'} if item['boundary'] == COMPLETED else set()),
                 'INERT_RECEIVER_TREE_INVALID')
    if v2:
        completed = {job for job, item in value['jobs'].items() if item['boundary'] == COMPLETED}
        need(completed and type(value['completed_host']) is dict and set(value['completed_host']) == completed
             and all(type(trees) is dict and set(trees) == {'staging', 'qa'}
                     and all(type(tree) is dict and set(tree) == {'files', 'directories', 'namespace'}
                             for tree in trees.values()) for trees in value['completed_host'].values()),
             'INERT_COMPLETED_HOST_BASELINE_REQUIRED')
    return value


def validate_pair(database, db, job_id, readback, expected, *, now=None):
    """Protected maintenance only. Unknown history stays unknown and blocked."""
    baseline = validate_baseline(expected['baseline'])
    v2 = baseline['scope'] == BASELINE_SCOPE_V2
    need(type(expected) is dict and set(expected) == {'baseline', 'baseline_sha256', 'identity'}
         and hashed(baseline) == expected['baseline_sha256'], 'INERT_BASELINE_CHANGED')
    need(type(readback) is dict and set(readback) == {'schema_version', 'scope', 'observed_at_utc',
        'expires_at_utc', 'binding', 'fox', 'receiver', 'host', 'identity'}
         and type(readback['schema_version']) is int and readback['schema_version'] == (2 if v2 else 1)
         and readback['scope'] == (READ_SCOPE_V2 if v2 else READ_SCOPE) and readback['binding'] == expected['baseline_sha256']
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
    host_fields = {'runtime_sha256', 'receiver_sha256', 'observation_sha256', 'blockers'}
    need(type(host) is dict and set(host) == host_fields | ({'completed_host_sha256'} if v2 else set())
         and host['runtime_sha256'] == hashed(baseline['runtime'])
         and host['receiver_sha256'] == hashed(readback['receiver']) and sha(host['observation_sha256'])
         and host['blockers'] == [], 'INERT_HOST_MEASUREMENT_REQUIRED')
    if v2:
        need(host['completed_host_sha256'] == hashed(baseline['completed_host']), 'INERT_COMPLETED_HOST_CHANGED')
    # This deliberately does NOT call _eligibility, validate old stage success,
    # authorize_current, or any model/import/recovery/continuation operation.
    boundary = baseline['jobs'][job_id]['boundary']
    state = STATE_V2 if v2 else STATE
    return {'admission': {'blocks_admission': True, 'recovery_state': state, 'retry_eligible': False},
            'preservation_allowed': True, 'preservation_state': state,
            'preserved': {'baseline_sha256': expected['baseline_sha256'], 'unresolved': boundary != COMPLETED,
                          'boundary': 'runtime_predispatch_unresolved' if boundary == RUNTIME_CANDIDATE else boundary,
                          'closure_claimed': False, 'continuation_authorized': False}}
