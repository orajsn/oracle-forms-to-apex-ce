"""Read-only single-gateway protocol observation, not arbitrary-process attestation.

The trusted deployment must run one converter process. A separate manual process
or privileged namespace writer is outside this protocol; this witness cannot grant
execution, retry, closure or acceptance. No archived code is imported or executed.
"""
import hashlib
import math
import os
from pathlib import Path
import re
import stat

from . import blueprint_profiles, runtime_preflight, sqlcl
from .project_reviews import digest, read_object
from .prototype_authority_client import execution_target
from .security import validate_job_id, alias_for_job


def need(value):
    if not value:
        raise RuntimeError('PROTOTYPE_ISOLATION_UNCONFIRMED')


def identity(path, directory=False):
    info = path.lstat()
    need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)
    need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


def namespace(jobs):
    # Inspect every lexical ancestor, not resolve()-then-check which loses links.
    parents = {str(p): identity(p, True) for p in reversed((jobs, *jobs.parents))}
    entries = sorted(p.name for p in jobs.iterdir())
    need(len(entries) <= 10000)
    return {'parents': parents, 'entries': entries}


def tree(root):
    result, total = {}, 0
    def walk(path):
        nonlocal total
        need(len(result) < 4096)
        name = path.relative_to(root).as_posix()
        need('\\' not in name and ':' not in name and not any(ord(c) < 32 for c in name))
        info = path.lstat()
        directory = stat.S_ISDIR(info.st_mode)
        before = identity(path, directory)
        if directory:
            children = sorted(path.iterdir())
            result[name] = {'identity': before, 'children': [p.name for p in children]}
            for child in children:
                walk(child)
        else:
            total += info.st_size
            need(info.st_size <= 64_000_000 and total <= 128_000_000)
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
            with os.fdopen(fd, 'rb') as stream:
                opened = os.fstat(stream.fileno())
                need(opened.st_ino == info.st_ino and opened.st_dev == info.st_dev
                     and stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1)
                raw = stream.read(64_000_001)
            need(len(raw) == info.st_size and identity(path) == before)
            result[name] = {'identity': before, 'sha256': hashlib.sha256(raw).hexdigest()}
        need(identity(path, directory) == before)
    walk(root)
    return result


def import_proof(root, request, binding):
    """Only the local retained half of durable import reconciliation; NO SQLcl."""
    imported = request['prior_receipts']['import']
    alias = alias_for_job(request['job_id'])
    need(imported.get('application_alias') == alias and imported.get('workspace') == 'FORMS2APEX_POC')
    reservation = read_object(root / 'import-reservation.json')
    confirmation = read_object(root / 'import-reservation-receipt.json')
    for record in (reservation, confirmation):
        need(record.get('record_sha256') == digest({k: v for k, v in record.items() if k != 'record_sha256'}))
    need(reservation == {'schema_version': 1, 'kind': 'sqlcl-apexlang-import-reservation',
        'job_id': request['job_id'], 'target_database': sqlcl._TARGET_DATABASE,
        'connection_name': 'F2A_APEX', 'workspace': 'FORMS2APEX_POC',
        'application_id': imported['application_id'], 'application_alias': alias,
        'artifact_binding': binding, 'input': sqlcl._input_members(root / 'candidate-apexlang.zip'),
        'record_sha256': imported['import_intent_sha256']})
    need(confirmation.get('schema_version') == 1 and confirmation.get('kind') == 'sqlcl-apexlang-import-confirmation'
         and confirmation.get('intent_sha256') == reservation['record_sha256']
         and confirmation.get('sqlcl_import_confirmed') is True)
    compiled = confirmation['compiled_metadata']
    snapshot = compiled['snapshot_directory']
    need(type(snapshot) is str and re.fullmatch(r'\.import-capture-[A-Za-z0-9_-]+/' + re.escape(alias.lower()), snapshot)
         and compiled.get('format') == 'APEXLANG' and compiled.get('validated') is True
         and compiled.get('scope') == 'complete_compiled_export_exact_bytes')
    need(sqlcl._input_members(root / snapshot) == {k: compiled[k] for k in ('kind', 'sha256', 'files')}
         and compiled['sha256'] == imported['compiled_metadata_sha256'])
    return snapshot.split('/')[0]


def historical_recovery(root, request, binding, files):
    """Known completed maintenance records only, never permission to resume them."""
    allowed = set()
    for prefix, stage, scope in (
        ('validate-recovery-attempt-', 'validate', 'one-retained-validation-maintenance-attempt-v1'),
        ('schema-continuation-attempt-', 'prepare_schema', 'one-retained-schema-continuation-attempt-v1')):
        markers = [p for p in root.iterdir() if p.name.startswith(prefix)]
        need(len(markers) <= 1)
        for marker in markers:
            need(re.fullmatch(re.escape(prefix) + '[a-f0-9]{20}\\.json', marker.name))
            record = read_object(marker)
            historical = read_object(root / (stage + '-request.json'))
            need(set(record) == {'scope', 'plan_sha256', 'request_sha256', 'operator', 'started_at'}
                 and record['scope'] == scope and record['request_sha256'] == digest(historical)
                 and type(record['plan_sha256']) is str and re.fullmatch('[a-f0-9]{64}', record['plan_sha256'])
                 and marker.name == prefix + record['plan_sha256'][:20] + '.json'
                 and type(record['operator']) is str and 0 < len(record['operator']) <= 512
                 and type(record['started_at']) in (int, float) and math.isfinite(record['started_at'])
                 and record['started_at'] > 0 and request['prior_receipts'][stage]['status'] == 'COMPLETE')
            allowed.add(marker.name)
            if stage == 'validate':
                log = 'validation-recovery-' + record['plan_sha256'][:20] + '.log'
                need(request['prior_receipts'][stage]['validation']['log'] == str(root / log)
                     and 'prototype-converter/' + log in files)
                allowed.add(log)
    imported = request['prior_receipts']['import']
    compiled = read_object(root / 'import-reservation-receipt.json')['compiled_metadata']
    expected = {k: compiled[k] for k in ('kind', 'sha256', 'files')}
    for path in root.iterdir():
        if re.fullmatch(r'\.import-capture-[A-Za-z0-9_-]+', path.name):
            need(path.is_dir() and sqlcl._input_members(path / imported['application_alias'].lower()) == expected
                 and {p.name for p in path.iterdir()} <= {imported['application_alias'].lower(), 'capture.log', 'validation.log'})
            allowed.add(path.name)
        elif re.fullmatch(r'import-readonly-parity-[0-9]{1,24}\.log', path.name):
            proof = read_object(path)
            need(proof == {k: imported[k] for k in ('application_id', 'application_alias', 'workspace',
                'import_intent_sha256', 'compiled_metadata_sha256')} | {'log': str(path), 'reconciled': True,
                'reconciliation_scope': 'exact_identity_and_complete_compiled_metadata', 'target_writes': False})
            allowed.add(path.name)
        elif path.name.startswith('confirmed-import-proof-'):
            need(re.fullmatch('confirmed-import-proof-[a-f0-9]{20}\\.json', path.name))
            record = read_object(path)
            need(set(record) == {'schema_version', 'scope', 'plan_sha256', 'proof', 'request_sha256',
                'artifact_binding', 'converter_additions', 'observed_at_epoch'}
                and record['schema_version'] == 1 and record['scope'] == 'fox-confirmed-import-readonly-proof-v1'
                and type(record['plan_sha256']) is str and re.fullmatch('[a-f0-9]{64}', record['plan_sha256'])
                and path.name == 'confirmed-import-proof-' + record['plan_sha256'][:20] + '.json'
                and record['request_sha256'] == digest(read_object(root / 'import-request.json'))
                and record['artifact_binding'] == binding
                and type(record['observed_at_epoch']) in (int, float) and math.isfinite(record['observed_at_epoch'])
                and record['observed_at_epoch'] > 0)
            proof = record['proof']
            need(proof == {k: imported[k] for k in ('application_id', 'application_alias', 'workspace', 'log',
                'import_intent_sha256', 'compiled_metadata_sha256', 'reconciled', 'reconciliation_scope', 'target_writes')}
                and proof['reconciled'] is True and proof['target_writes'] is False
                and proof['reconciliation_scope'] == 'exact_identity_and_complete_compiled_metadata')
            log = 'confirmed-import-reconcile-' + record['plan_sha256'][:20] + '.log'
            need(proof['log'] == str(root / log) and read_object(root / log) == proof)
            additions = record['converter_additions']
            need(type(additions) is dict and additions and all(
                type(name) is str and (name == 'prototype-converter/' + log or re.fullmatch(
                    r'prototype-converter/\.import-capture-[A-Za-z0-9_-]+/.+', name))
                and name in files and files[name].get('sha256') == sha for name, sha in additions.items()))
            need('prototype-converter/' + log in additions
                 and len({name.split('/')[1] for name in additions if '/.import-capture-' in name}) == 1)
            allowed |= {path.name, log}
    return allowed


def observe(gateway, job_id, challenge):
    from .prototype_gateway import STAGES
    validate_job_id(job_id)
    need(type(challenge) is str and re.fullmatch('[a-f0-9]{64}', challenge))
    jobs = Path(gateway.settings.jobs_root).absolute()
    parent = namespace(jobs)
    job = jobs / job_id
    value = {'schema_version': 1, 'scope': 'fox-prototype-isolation-witness-v1',
        'job_id': job_id, 'challenge': challenge, 'boundary': 'receiver_absent',
        'project_id': None, 'source_binding': None, 'request_sha256': None,
        'execution_target_sha256': None, 'execution_authorized': False,
        'retry_authorized': False, 'closure_claimed': False, 'business_behavior_accepted': False,
        'process_scope': 'single_converter_process'}
    if job_id not in parent['entries']:
        # lstat refuses dangling links rather than treating exists()==False as absence.
        try:
            job.lstat()
        except FileNotFoundError:
            pass
        else:
            need(False)
        need(namespace(jobs) == parent and job_id not in {p.name for p in jobs.iterdir()})
        return {**value, 'retained_sha256': digest({'namespace': parent, 'job_absent': job_id})}
    before = tree(job)
    root = job / 'prototype-converter'
    need(root.is_dir() and {p.name for p in job.iterdir()} <= {'prototype-converter', 'prototype-pipeline'})
    exported = 'prototype-converter/export-request.json' in before
    stage = 'export' if exported else 'verify_runtime'
    request = read_object(root / (stage + '-request.json'))
    need(request.get('job_id') == job_id)
    spec, raw = gateway._request_inputs(stage, request)
    _, binding = gateway._snapshot(root, request, spec, raw, create=False)
    gateway._check_prior(root, request)
    capture = import_proof(root, request, binding)
    allowed = {'authority-manifest.json', 'snapshot.json', 'candidate-apexlang.zip',
        'validation.log', 'synthetic-schema.sql', 'schema-write-intent.json', 'import.log',
        'import-reservation.json', 'import-reservation-receipt.json', capture}
    for prior in STAGES[:STAGES.index(stage) + 1]:
        historical = {**request, 'prior_receipts': {k: request['prior_receipts'][k] for k in STAGES[:STAGES.index(prior)]}}
        need(read_object(root / (prior + '-request.json')) == historical
             and read_object(root / (prior + '-intent.json')) == {'request_sha256': digest(historical)})
        allowed |= {prior + '-request.json', prior + '-intent.json'}
        if prior != stage or exported:
            receipt = read_object(root / (prior + '.json'))
            gateway._check_receipt(prior, historical, receipt)
            need(receipt.get('schema_version') == 1 and receipt.get('scope') == 'fox-prototype-converter-receipt-v1'
                 and receipt.get('status') == 'COMPLETE')
            if prior == 'validate':
                validation = receipt['validation']
                need(validation.get('passed') is True and type(validation.get('return_code')) is int
                     and validation['return_code'] == 0 and receipt.get('artifact_binding') == binding
                     and receipt.get('draft_sha256') == digest({name: hashlib.sha256(text.encode()).hexdigest()
                         for name, text in blueprint_profiles.select(spec).render_native_blueprint(spec).items()}))
            allowed.add(prior + '.json')
    ddl = blueprint_profiles.select(spec).render_prototype_schema(spec).encode()
    tables = [b['table_name'] for b in spec['blocks'] if b['classification'] == 'database']
    schema = request['prior_receipts']['prepare_schema']
    need((root / 'synthetic-schema.sql').read_bytes() == ddl
         and schema['schema_ddl_sha256'] == hashlib.sha256(ddl).hexdigest()
         and schema.get('tables') == tables and schema.get('database_writes') is bool(tables))
    if any(b['classification'] == 'database' for b in spec['blocks']):
        schema_request = read_object(root / 'prepare_schema-request.json')
        need(read_object(root / 'schema-write-intent.json') == {'request_sha256': digest(schema_request),
             'ddl_sha256': hashlib.sha256(ddl).hexdigest()})
    external, packet = None, None
    if exported:
        from .prototype_release import validate_prototype_package
        from .prototype_package import runtime_binding
        allowed |= {'runtime-request.json', 'runtime-claim.json', 'runtime-result.json', 'runtime-receipt.json',
            'runtime-evidence', 'export-attempt.json', 'prototype-package.zip'}
        bridge_names = {'runtime-request.json', 'runtime-claim.json', 'runtime-result.json', 'runtime-receipt.json'}
        if {p.name for p in root.iterdir()} & bridge_names:
            # Any dispatch fragment requires the entire exact terminal envelope.
            packet = read_object(root / 'runtime-request.json')
            claim = read_object(root / 'runtime-claim.json')
            result = read_object(root / 'runtime-result.json')
            runtime = read_object(root / 'runtime-receipt.json')
            historical = read_object(root / 'verify_runtime-request.json')
            identity_binding = runtime_binding(historical, historical['prior_receipts']['import'], binding)
            need(set(packet) == {'schema_version', 'scope', 'request', 'imported', 'trace', 'artifact_binding',
                 'binding', 'producer', 'issued_at_utc', 'deadline_at_utc', 'target'}
                 and packet['schema_version'] == 1 and packet['scope'] == 'fox-prototype-runtime-dispatch-v1'
                 and packet['request'] == historical and packet['imported'] == historical['prior_receipts']['import']
                 and packet['trace'] == blueprint_profiles.select(spec).prototype_trace(spec)
                 and packet['artifact_binding'] == binding and packet['binding'] == identity_binding
                 and runtime == request['prior_receipts']['verify_runtime']['runtime_receipt'])
            worker = claim.get('worker_sha256')
            need(type(worker) is str and re.fullmatch('[a-f0-9]{64}', worker)
                 and claim == {'dispatch_sha256': digest(packet), 'worker_sha256': worker,
                               'state': 'CLAIMED_NO_AUTOMATIC_REPLAY'}
                 and result == {'schema_version': 1, 'scope': 'fox-prototype-runtime-result-v1',
                    'dispatch_sha256': digest(packet), 'binding': identity_binding,
                    'worker_sha256': worker, 'receipt_sha256': digest(runtime)})
        receipt = read_object(root / 'export.json')
        package = (root / 'prototype-package.zip').read_bytes()
        need(hashlib.sha256(package).hexdigest() == receipt['package_sha256'])
        validate_prototype_package(package, request=request, runtime_receipt=request['prior_receipts']['verify_runtime']['runtime_receipt'],
            imported=request['prior_receipts']['import'], artifact_binding=binding, export_receipt=receipt)
        attempt = read_object(root / 'export-attempt.json')
        path = Path(attempt['directory'])
        need(path.is_absolute() and path.parent == jobs and re.fullmatch(r'\.px-[A-Za-z0-9_-]+', path.name)
             and attempt['binding'] == runtime_binding(request, request['prior_receipts']['import'], binding))
        external = (path, tree(path))
        sql = path / ('f' + str(receipt['application_id']) + '.sql')
        need(receipt['native_sql_path'] == str(sql) and sql.stat().st_size == receipt['native_sql_bytes']
             and hashlib.sha256(sql.read_bytes()).hexdigest() == receipt['native_sql_sha256']
             and sqlcl._input_members(path / receipt['application_alias'].lower())['sha256']
                 == request['prior_receipts']['import']['compiled_metadata_sha256'])
    allowed |= historical_recovery(root, request, binding, before)
    need({p.name for p in root.iterdir()} <= allowed)
    for path in root.iterdir():
        if path.name == 'runtime-evidence' or path.name.startswith('.import-capture-'):
            need(path.is_dir())
        else:
            identity(path)  # Every other marker/output must be a regular singleton.
    if (root / 'authority-manifest.json').exists():
        authority = gateway.recover_source_authority(job_id)  # Read-only, no owner callback.
        need(authority is not None and authority['source_binding'] == request['source_binding']
             and authority['source_authority'] == request['source_authority'])
    if exported:
        artifacts = request['prior_receipts']['verify_runtime']['runtime_receipt']['artifacts']
        need({p.relative_to(root).as_posix() for p in (root / 'runtime-evidence').iterdir()}
             == {row['path'] for row in artifacts})
    for log in (request['prior_receipts']['validate']['validation']['log'],
                request['prior_receipts']['import']['log']):
        path = Path(log)
        need(path.parent == root and path.name in allowed
             and before.get('prototype-converter/' + path.name, {}).get('sha256') is not None)
    profile = (gateway.target_profile_loader(gateway.settings) if callable(gateway.target_profile_loader)
               else runtime_preflight.bound_target_profile(gateway.settings))
    if packet is not None:
        from .prototype_release import _timestamp
        producer = packet['producer']
        need(type(producer) is dict and set(producer) == {'component', 'code_sha256'}
             and producer['component'] == 'fox-prototype-runtime-bridge'
             and type(producer['code_sha256']) is str and re.fullmatch('[a-f0-9]{64}', producer['code_sha256'])
             and 0 < (_timestamp(packet['deadline_at_utc']) - _timestamp(packet['issued_at_utc'])).total_seconds() <= 540
             and packet['target'] == {'workspace': profile['apex']['workspace'],
                'db_name': profile['database']['db_name'], 'ords_origin': profile['apex']['ords_origin']})
    target = digest(execution_target(profile))
    need(tree(job) == before and namespace(jobs) == parent)
    if external:
        need(tree(external[0]) == external[1])
    return {**value, 'boundary': 'export_complete' if exported else 'runtime_not_dispatched',
        'project_id': request['project_id'], 'source_binding': request['source_binding'],
        'request_sha256': digest(request), 'execution_target_sha256': target,
        'retained_sha256': digest({'namespace': parent, 'tree': before,
            'export_tree': external[1] if external else None})}
