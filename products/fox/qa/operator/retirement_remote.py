"""Read-only destination-side proof checks for a Windows retirement handoff.

This is an installation-owned, point-in-time reader, not admission authority.
The caller must hold and recheck its actual current operator lease around the
read, and separately validate the SHA-bound retirement archive. No historical
Windows program or path is opened, imported, executed, or adopted here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import inspect
import json
from pathlib import Path
import re

from qa.operator import product_queue_transport as bridge

SCOPE = 'fox-retired-history-remote-read-v1'
MAX_PACKET = 2_000_000

STARTUP_PRECLAIM = r'''
import hashlib,json,os,pathlib,sqlite3,sys
sys.path.insert(0,'/app');sys.dont_write_bytecode=True
from fox import verification_recovery as r
from fox.prototype_job import load_prototype_profile
from fox.prototype_download import configured_download_client
from fox.prototype_transport import PrototypeHttpConverterAdapter
from fox.prototype_preclaim_continuation import check_witness
p=json.load(sys.stdin)
assert hashlib.sha256(pathlib.Path(r.__file__).read_bytes()).hexdigest()==p['reader_sha256']
db=sqlite3.connect('file:/data/fox.sqlite3?mode=ro',uri=True);db.row_factory=sqlite3.Row
db.execute('PRAGMA query_only=ON');db.execute('BEGIN');result={}
for row in db.execute("SELECT * FROM runs WHERE state='ATTENTION' AND artifact IS NULL"):
 job=pathlib.Path('/data/jobs')/row['id']
 if not (job/'prototype-pipeline/candidate-format-continuation.json').exists() or not (job/'prototype-pipeline/validate-intent.json').exists():continue
 value=r.preclaim_fox_lineage('/data/fox.sqlite3',db,dict(row))
 target=load_prototype_profile(pathlib.Path(os.environ['FOX_PROTOTYPE_PROFILE_FILE']))
 assert target['target_profile_sha256']==value['snapshot']['prototype']['target_profile_sha256']
 # Only after maintenance-specific stopped-owner/source/proof checks. This
 # constructs the trusted existing client; it grants no ordinary admission.
 claimed='prototype-pipeline/validate-preclaim-continuation.json' in value['documents']
 if claimed:
  technical=r.preclaim_technical_read('/data/fox.sqlite3',row['id'],target['target_profile'],p['image_sha256'])
  witness=None
 else:
  client=configured_download_client(target['target_profile_sha256'])
  adapter=PrototypeHttpConverterAdapter(job,client)
  first_witness=adapter.validate_preclaim_witness(value['request'])
  technical=r.preclaim_technical_read('/data/fox.sqlite3',row['id'],target['target_profile'],p['image_sha256'])
  witness=adapter.validate_preclaim_witness(value['request'])
  assert first_witness==witness
  intent=value['documents']['prototype-transport/authority-intent.json']
  check_witness(value['request'],witness,intent['manifest_sha256'],target['target_profile'])
  assert adapter._get(adapter.path+'/stages/validate') is None
 assert r.preclaim_tree(job)==value['tree']
 result[row['id']]={'technical':technical,'request':value['request'],'witness':witness,
   'target_profile_sha256':target['target_profile_sha256'],**({'claimed_validation':True} if claimed else {})}
assert db.total_changes==0
print(json.dumps({'jobs':result,'collector':r.preclaim_collector_source()},sort_keys=True))
'''


class RetirementRemoteError(RuntimeError):
    """Only bounded public failure categories escape the reader."""


def _need(value, code):
    if not value:
        raise RetirementRemoteError(code)


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False) + '\n').encode()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RetirementRemoteError('RETIREMENT_REMOTE_JSON_INVALID') from None


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _hash(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


def _identifier(value, prefix, length):
    return type(value) is str and re.fullmatch(re.escape(prefix) + '[a-f0-9]{' + str(length) + '}', value) is not None


def _history_binding(value, release):
    _need(type(value) is dict and set(value) == {'job_id', 'source_manifest_sha256',
          'package_sha256', 'verifier_release_sha256'}
          and _identifier(value['job_id'], 'fox-', 20)
          and all(_hash(value[key]) for key in value if key != 'job_id')
          and value['verifier_release_sha256'] == release, 'RETIREMENT_REMOTE_BINDING_INVALID')
    return value


def validate_history(history, current_release):
    """Validate a detached C/F/G projection; release identities never flatten."""
    _need(type(history) is dict and set(history) == {'failure', 'retry', 'idle'}
          and _hash(current_release), 'RETIREMENT_REMOTE_HISTORY_REQUIRED')
    fields = {'failure': {'release_sha256', 'session_id', 'job_id', 'disposition_sha256', 'disposition'},
              'retry': {'release_sha256', 'session_id', 'job_id', 'attempt_id', 'proof_sha256'},
              'idle': {'release_sha256', 'session_id', 'completed_jobs'}}
    releases = [current_release]
    sessions = []
    for role in fields:
        item = history[role]
        _need(type(item) is dict and set(item) == fields[role]
              and _hash(item['release_sha256']) and _identifier(item['session_id'], 'session-', 24),
              'RETIREMENT_REMOTE_HISTORY_FIELDS')
        releases.append(item['release_sha256']); sessions.append(item['session_id'])
    _need(len(set(releases)) == 4 and len(set(sessions)) == 3, 'RETIREMENT_REMOTE_DISTINCT_HISTORY_REQUIRED')
    old, retry, idle = (history[key] for key in ('failure', 'retry', 'idle'))
    _need(_identifier(old['job_id'], 'fox-', 20) and retry['job_id'] == old['job_id']
          and _identifier(retry['attempt_id'], 'attempt-', 32) and _hash(retry['proof_sha256'])
          and _hash(old['disposition_sha256']), 'RETIREMENT_REMOTE_RETRY_LINK_INVALID')
    document = old['disposition']
    _need(type(document) is dict and _digest(_canonical(document)) == old['disposition_sha256']
          and type(document.get('binding')) is dict
          and document['binding'].get('job_id') == old['job_id']
          and document.get('human_acceptance_recorded') is False
          and document.get('automatic_retry_permitted') is False,
          'RETIREMENT_REMOTE_DISPOSITION_INVALID')
    _history_binding(document['binding'], old['release_sha256'])
    jobs = idle['completed_jobs']
    _need(type(jobs) is list and 0 < len(jobs) <= 5, 'RETIREMENT_REMOTE_IDLE_JOBS_REQUIRED')
    ids = []
    for job in jobs:
        _need(type(job) is dict and set(job) == {'binding', 'proof_sha256'} and _hash(job['proof_sha256']),
              'RETIREMENT_REMOTE_IDLE_JOB_INVALID')
        ids.append(_history_binding(job['binding'], idle['release_sha256'])['job_id'])
    _need(len(set(ids)) == len(ids) and old['job_id'] not in ids, 'RETIREMENT_REMOTE_JOB_IDENTITY_COLLISION')
    raw = _canonical(history)
    _need(0 < len(raw) <= MAX_PACKET // 2, 'RETIREMENT_REMOTE_HISTORY_TOO_LARGE')
    return json.loads(raw)


def _backend_read(history, current_release, for_startup, queue_module, recovery_module, root, paired_preclaim=None):
    """One query-only transaction over every admission-bearing job identity."""
    store = recovery_module.VerificationRecovery(root / 'fox.sqlite3', enabled=True)
    old, retry, idle = (history[key] for key in ('failure', 'retry', 'idle'))
    with store._db(False) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        _need(store._recovery_available(db), 'RETIREMENT_REMOTE_RECOVERY_SCHEMA_REQUIRED')
        closed, document = store._closed(db, old['job_id'])
        _need(closed is not None and closed.disposition_sha256 == old['disposition_sha256']
              and _canonical(document) == _canonical(old['disposition']),
              'RETIREMENT_REMOTE_ORIGINAL_FAILURE_CHANGED')
        attempt = store._attempt(db, retry['attempt_id'])
        _need(type(attempt) is dict and attempt['state'] == 'completed'
              and attempt['proof_sha256'] == retry['proof_sha256']
              and attempt['disposition_sha256'] == old['disposition_sha256']
              and attempt['binding'] == {**document['binding'], 'verifier_release_sha256': retry['release_sha256']},
              'RETIREMENT_REMOTE_COMPLETED_RETRY_CHANGED')
        ids = store._job_ids(db)
        _need(0 < len(ids) <= 10000 and len(set(ids)) == len(ids)
              and {old['job_id'], *(job['binding']['job_id'] for job in idle['completed_jobs'])} <= set(ids),
              'RETIREMENT_REMOTE_JOB_UNION_CHANGED')
        eligibility, preservation = {}, {}
        paired_preclaim = {} if paired_preclaim is None else paired_preclaim
        _need(type(paired_preclaim) is dict and set(paired_preclaim) <= set(ids), 'RETIREMENT_REMOTE_PAIRED_JOB_INVALID')
        waiting, busy = [], []
        for job_id in sorted(ids):
            paired = paired_preclaim.get(job_id)
            protected = (store._protected_read_status(db, job_id, purpose='maintenance_preclaim_preservation',
                paired_readback=paired['readback'],expected_pair=paired['expected']) if paired is not None else
                store._protected_read_status(db, job_id, purpose='maintenance_preservation'))
            value = protected['admission']
            _need(type(value) is dict and set(value) == {'blocks_admission', 'recovery_state', 'retry_eligible'}
                  and type(value['blocks_admission']) is bool and type(value['retry_eligible']) is bool,
                  'RETIREMENT_REMOTE_ELIGIBILITY_INVALID')
            if protected['preservation_allowed']:
                if paired is not None:
                    run = db.execute('SELECT * FROM runs WHERE id=?', (job_id,)).fetchone()
                    state = ('claimed_validation_history' if paired['readback']['scope'] ==
                        recovery_module.CLAIMED_VALIDATION_MAINTENANCE_SCOPE else 'preclaim_validate_history')
                    _need(value['blocks_admission'] is True and value['retry_eligible'] is False
                        and protected['preservation_state'] == state and run is not None,
                        'RETIREMENT_REMOTE_PRECLAIM_UNCONFIRMED')
                    checked = recovery_module.validate_preclaim_pair(root/'fox.sqlite3',db,dict(run),
                        paired['readback'],paired['expected'])
                    _need(checked == protected['preserved'],'RETIREMENT_REMOTE_PRECLAIM_UNCONFIRMED')
                    preservation[job_id] = {'state':state,'preserved':checked}
                    eligibility[job_id] = value
                    continue
                # Independently reopen the sealed lineage; a projected ready
                # flag/label is not authority. Admission remains blocked.
                run = db.execute('SELECT * FROM runs WHERE id=?', (job_id,)).fetchone()
                classifier = getattr(recovery_module, 'terminal_closed_provider_preservation', None)
                _need(value['blocks_admission'] is True and value['retry_eligible'] is False
                      and protected['preservation_state'] == 'closed_provider_history'
                      and run is not None and callable(classifier)
                      and classifier(root / 'fox.sqlite3', db, dict(run)) is True,
                      'RETIREMENT_REMOTE_PRESERVATION_UNCONFIRMED')
                preservation[job_id] = 'closed_provider_history'
            elif value['blocks_admission']:
                _need(for_startup is True, 'RETIREMENT_REMOTE_UNRESOLVED_OR_ACTIVE_WORK')
                if value['recovery_state'] == 'conversion_active':
                    # An ordinary conversion is not a new verification claim.
                    # Observe it as WAIT only, never reinterpret queued/running
                    # verification, retry history or a retained output as busy.
                    run = db.execute('SELECT r.id,r.project,r.source_hash,r.state,r.artifact '
                        'FROM runs r JOIN projects p ON p.id=r.project WHERE r.id=?', (job_id,)).fetchone()
                    _need(run is not None and _identifier(run['id'], 'fox-', 20)
                          and _hash(run['source_hash']) and type(run['project']) is str and run['project']
                          and run['state'] in {'QUEUED', 'PROCESSING'} and run['artifact'] is None
                          and value['retry_eligible'] is False
                          and db.execute('SELECT 1 FROM verification_queue WHERE job_id=?', (job_id,)).fetchone() is None
                          and db.execute('SELECT 1 FROM verification_failed_dispositions WHERE job_id=?', (job_id,)).fetchone() is None
                          and db.execute('SELECT 1 FROM verification_retry_attempts WHERE job_id=?', (job_id,)).fetchone() is None,
                          'RETIREMENT_REMOTE_CONVERSION_WAIT_UNCONFIRMED')
                    busy.append(dict(run))
                    eligibility[job_id] = value
                    continue
                row = queue_module.VerificationQueue._record(db.execute(
                    'SELECT * FROM verification_queue WHERE job_id=?', (job_id,)).fetchone())
                _need(row is not None and row['state'] == 'queued'
                      and row['verifier_release_sha256'] == current_release,
                      'RETIREMENT_REMOTE_UNRESOLVED_OR_ACTIVE_WORK')
                binding = queue_module.VerificationBinding.from_payload({key: row[key]
                    for key in ('job_id', 'source_manifest_sha256', 'package_sha256', 'verifier_release_sha256')})
                # Validate the selected queue/run independently before deciding
                # whether the whole snapshot is READY or only read-only WAIT.
                queue_module.VerificationQueue._run(db, binding, states={'QA_REQUIRED'})
                _need(db.execute('SELECT 1 FROM verification_failed_dispositions WHERE job_id=?', (job_id,)).fetchone() is None
                      and db.execute('SELECT 1 FROM verification_retry_attempts WHERE job_id=?', (job_id,)).fetchone() is None,
                      'RETIREMENT_REMOTE_QUEUED_WORK_NOT_ADMISSIBLE')
                waiting.append({'binding': binding.payload(), 'record_sha256': row['record_sha256']})
            elif value['recovery_state'] in {'prototype_clause_repair_terminal', 'prototype_container_review_terminal',
                                            'prototype_partition_review_terminal', 'prototype_context_screen_terminal',
                                            'prototype_review_scope_terminal', 'prototype_post_correction_review_terminal'}:
                # A label cannot close, replay, export or authorize this run.
                # Independently re-read the exact sealed pre-database failure;
                # missing helpers in an older namespace fail closed as well.
                run = db.execute('SELECT * FROM runs WHERE id=?', (job_id,)).fetchone()
                classifier_name = {'prototype_clause_repair_terminal': 'terminal_prototype_clause_repair',
                    'prototype_container_review_terminal': 'terminal_prototype_container_review',
                    'prototype_partition_review_terminal': 'terminal_prototype_partition_review',
                    'prototype_context_screen_terminal': 'terminal_prototype_context_screen',
                    'prototype_review_scope_terminal': 'terminal_prototype_review_scope',
                    'prototype_post_correction_review_terminal': 'terminal_prototype_post_correction_review'}[value['recovery_state']]
                classifier = getattr(recovery_module, classifier_name, None)
                _need(value == {'blocks_admission': False,
                    'recovery_state': value['recovery_state'], 'retry_eligible': False}
                    and run is not None and callable(classifier)
                    and classifier(root / 'fox.sqlite3', db, dict(run)) is True,
                    'RETIREMENT_REMOTE_CLAUSE_TERMINAL_UNCONFIRMED')
            elif value['recovery_state'] in {'precheck_failed_closed','qa_stage_failed_closed',
                    'project_prewrite_failed_closed', 'prototype_mapping_incomplete',
                    'prototype_mapping_owner_resolution_pending', 'prototype_mapping_analysis_terminal'}:
                # The production recovery reader has revalidated the separate
                # append-only row, original queue/claim and retained package.
                # The prototype family instead rechecks its exact sealed first
                # empty mapper, owner-resolution stop, or sealed pre-epoch2
                # analysis stop and absence of later work. No historical model
                # approval is promoted to source-fact truth. No classification
                # is a technical pass, completed retry or replay grant.
                _need(value == {'blocks_admission': False,
                    'recovery_state': value['recovery_state'], 'retry_eligible': False},
                    'RETIREMENT_REMOTE_PRECHECK_ELIGIBILITY_INVALID')
            else:
                _need(value['recovery_state'] in {'failed_closed', 'no_active_verification', 'retry_completed_verified'},
                      'RETIREMENT_REMOTE_ELIGIBILITY_INVALID')
            eligibility[job_id] = value
        if not busy:
            for item in waiting:
                binding = queue_module.VerificationBinding.from_payload(item['binding'])
                # READY still uses the exact production admission predicate.
                # No global busy bypass reaches a queue claim.
                _need(store.normal_claim_allowed(db, binding), 'RETIREMENT_REMOTE_QUEUED_WORK_NOT_ADMISSIBLE')
        _need(eligibility[old['job_id']] == {'blocks_admission': False,
              'recovery_state': 'retry_completed_verified', 'retry_eligible': False},
              'RETIREMENT_REMOTE_RETRY_PROOF_UNCONFIRMED')
        queue_rows = []
        for job in idle['completed_jobs']:
            binding = queue_module.VerificationBinding.from_payload(job['binding'])
            row = queue_module.VerificationQueue._record(db.execute(
                'SELECT * FROM verification_queue WHERE job_id=?', (binding.job_id,)).fetchone())
            _need(row is not None and row['state'] == 'completed' and row['proof_sha256'] == job['proof_sha256']
                  and all(row[key] == value for key, value in binding.payload().items()),
                  'RETIREMENT_REMOTE_IDLE_QUEUE_CHANGED')
            queue = queue_module.VerificationQueue(root / 'fox.sqlite3', enabled=True,
                                                 verifier_release_sha256=idle['release_sha256'])
            queue._validated_proof(db, binding, queue_module.TechnicalProofResult(job['proof_sha256']))
            queue_rows.append({'binding': binding.payload(), 'record_sha256': row['record_sha256'],
                               'proof_sha256': row['proof_sha256']})
        return {'failure_acknowledgement': {'status': 'FAILED_QA_RECORDED',
                    'disposition_sha256': old['disposition_sha256'], 'disposition': document},
                'completed_retry': {key: retry[key] for key in ('release_sha256', 'job_id', 'attempt_id', 'proof_sha256')},
                'completed_idle_jobs': idle['completed_jobs'], 'waiting_verification_count': len(waiting),
                'busy_conversion_count': len(busy), 'admission_state': 'WAIT' if busy else 'READY',
                'snapshot': {'eligibility': eligibility, 'preservation': preservation,
                             'waiting': waiting, 'busy': busy, 'idle_queue': queue_rows,
                             'retry': attempt}}


def _backend_snapshot(history, current_release, for_startup, queue_module,
                      verification_module, recovery_module, *, root=Path('/data'), paired_preclaim=None):
    """Recheck real retained proofs and compare independent before/after reads."""
    history = validate_history(history, current_release)
    _need(type(for_startup) is bool, 'RETIREMENT_REMOTE_STARTUP_MODE_REQUIRED')
    root = Path(root).absolute()
    before = _backend_read(history, current_release, for_startup, queue_module, recovery_module, root, paired_preclaim)
    proofs = [{'binding': {**history['failure']['disposition']['binding'],
                          'verifier_release_sha256': history['retry']['release_sha256']},
               'proof_sha256': history['retry']['proof_sha256']}, *history['idle']['completed_jobs']]
    for job in proofs:
        checked = verification_module.verify_existing_native_run(root=root, run_id=job['binding']['job_id'])
        _need(type(checked) is dict and checked.get('id') == job['binding']['job_id']
              and checked.get('state') in ('VERIFIED', 'ACCEPTED')
              and checked.get('read_only') is checked.get('idempotent') is True
              and checked.get('active_policy_applied') is False
              and checked.get('proof_sha256') == job['proof_sha256'],
              'RETIREMENT_REMOTE_HISTORICAL_PROOF_CHANGED')
    after = _backend_read(history, current_release, for_startup, queue_module, recovery_module, root, paired_preclaim)
    _need(_canonical(before) == _canonical(after), 'RETIREMENT_REMOTE_CHANGED_DURING_READ')
    result = {key: value for key, value in after.items() if key != 'snapshot'}
    return {**result, 'backend_snapshot_sha256': _digest(_canonical(after['snapshot']))}


def _retirement_validate_request(value):
    _need(type(value) is dict and set(value) in ({'operation', 'apply', 'manifest', 'release_sha256',
          'configuration_sha256', 'provider_configuration_sha256', 'history', 'for_startup'},
          {'operation', 'apply', 'manifest', 'release_sha256', 'configuration_sha256',
          'provider_configuration_sha256', 'history', 'for_startup','paired_preclaim'})
          and value['operation'] == 'retired_history_read' and value['apply'] is False
          and type(value['for_startup']) is bool, 'RETIREMENT_REMOTE_READ_ONLY_REQUEST_REQUIRED')
    manifest = validate_release(value['manifest'])
    _need(manifest['schema_version'] == 3 and manifest['enabled'] is True
          and _digest(_canonical(manifest)) == value['release_sha256'] == EXPECTED_RELEASE
          and value['configuration_sha256'] == EXPECTED_CONFIGURATION
          and value['provider_configuration_sha256'] == manifest['hosted_runtime_configuration_sha256'],
          'RETIREMENT_REMOTE_CURRENT_CONFIGURATION_CHANGED')
    validate_history(value['history'], value['release_sha256'])
    return value


def _container_result(request, queue_module, verification_module, recovery_module):
    result = _backend_snapshot(request['history'], request['release_sha256'], request['for_startup'],
                               queue_module, verification_module, recovery_module,
                               paired_preclaim=request.get('paired_preclaim'))
    return {'schema_version': 1, 'scope': SCOPE, 'status': 'RETIRED_HISTORY_OBSERVED',
            'current_release_sha256': request['release_sha256'],
            'configuration_sha256': request['configuration_sha256'],
            'provider_configuration_sha256': request['provider_configuration_sha256'],
            'images': request['manifest']['images'],
            'history_sha256': _digest(_canonical(request['history'])), 'for_startup': request['for_startup'],
            'read_only': True, 'automatic_replay_permitted': False, **result}


def container_source(current_release, configuration_sha256):
    """Extend the hosted v3 bridge's measured project loader, not old code."""
    _need(_hash(current_release) and _hash(configuration_sha256), 'RETIREMENT_REMOTE_CONFIGURATION_REQUIRED')
    source = bridge.container_source()
    parse = ' request=_validate_request(json.loads(raw))'
    imports = "for name in ('verification_queue','verification_runtime','technical_release'):"
    action = ("result=container_execute(request,sys.modules['fox.verification_queue'],sys.modules['fox.technical_release'],\n"
              "     sys.modules['fox.verification_runtime'])")
    boundary = 'import hashlib,io,os,sys,types\n'
    for marker in (parse, imports, action, boundary):
        _need(source.count(marker) == 1, 'RETIREMENT_REMOTE_CONTAINER_TEMPLATE_CHANGED')
    functions = (RetirementRemoteError, _need, _canonical, _digest, _hash, _identifier, _history_binding,
                 validate_history, _backend_read, _backend_snapshot, _retirement_validate_request, _container_result)
    extra = ('from datetime import timezone\nSCOPE=' + repr(SCOPE) + '\nMAX_PACKET=' + repr(MAX_PACKET)
             + '\nEXPECTED_RELEASE=' + repr(current_release) + '\nEXPECTED_CONFIGURATION=' + repr(configuration_sha256)
             + '\n' + '\n'.join(inspect.getsource(item) for item in functions) + '\n')
    source = source.replace(boundary, extra + boundary, 1).replace(parse,
        ' request=_retirement_validate_request(json.loads(raw))', 1)
    source = source.replace(imports,
        "for name in ('verification_queue','verification_runtime','technical_release','native_verification','verification_recovery'):", 1)
    source = source.replace(action,
        "result=_container_result(request,sys.modules['fox.verification_queue'],sys.modules['fox.native_verification'],\n"
        "     sys.modules['fox.verification_recovery'])", 1)
    _need(source.count('read(65537)') == 2 and source.count('0<len(raw)<=65536') == 1,
          'RETIREMENT_REMOTE_INPUT_BOUND_TEMPLATE_CHANGED')
    source = source.replace('read(65537)', 'read(2000001)', 1).replace('0<len(raw)<=65536', '0<len(raw)<=2000000', 1)
    compile(source, '<retirement-container>', 'exec')
    return source


def _host_inventory():
    response = subprocess.run(['podman', 'ps', '-aq', '--no-trunc'], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=30)
    guard(response.returncode == 0 and not response.stderr.strip() and len(response.stdout) <= 65536)
    ids = response.stdout.decode('ascii').split()
    guard(3 <= len(ids) <= 256 and len(ids) == len(set(ids))
          and all(re.fullmatch('[a-f0-9]{64}', item) for item in ids))
    response = subprocess.run(['podman', 'inspect'] + sorted(ids), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60)
    guard(response.returncode == 0 and not response.stderr.strip() and 0 < len(response.stdout) <= 16_000_000)
    values = json.loads(response.stdout)
    guard(type(values) is list and len(values) == len(ids))
    rows = []
    for item in values:
        state = item['State']
        image = item['Image']
        rows.append({'id': item['Id'], 'name': item['Name'],
            'image': image if image.startswith('sha256:') else 'sha256:' + image,
            'status': state['Status'], 'running': state['Running'], 'pid': state['Pid'],
            'exit_code': state['ExitCode'], 'created_at': item['Created'],
            'started_at': state['StartedAt'], 'finished_at': state['FinishedAt']})
    rows.sort(key=lambda row: row['id'])
    guard([row['id'] for row in rows] == sorted(ids))
    return rows


def _host_preclaim_health():
    import urllib.request
    with urllib.request.urlopen('http://127.0.0.1:8100/api/health',timeout=5) as response:
        raw=response.read(65537)
    guard(0<len(raw)<=65536);value=json.loads(raw)
    guard(value.get('status')=='ok' and value.get('product')=='FOX'
          and value.get('worker',{}).get('healthy') is True and value['worker']['state'] in ('idle','polling'))


def _host_preclaim_collect(code,packet):
    response=subprocess.run(['podman','unshare','/usr/bin/python3','-I','-B','-c',code],
        input=json.dumps(packet).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
    guard(response.returncode==0 and not response.stderr.strip() and 0<len(response.stdout)<=2_000_000)
    return json.loads(response.stdout)


def _host_claimed_provenance(v, infrastructure):
    """Read only the current release's retained transition, never historical code.

    The digest below correlates the actual outer HeldOperatorLock; it does not
    replace RetirementArchive.require_admission_under_lock's before/after checks.
    """
    import os, stat
    h=lambda raw:hashlib.sha256(raw).hexdigest()
    captures={}
    def unique(rows):
        value={}
        for key,item in rows:
            guard(key not in value);value[key]=item
        return value
    def read(path, expected=None, private=True):
        path=Path(path)
        guard(path.is_absolute() and path.resolve(strict=True)==path)
        for parent in (path,*path.parents):guard(not parent.is_symlink())
        info=path.stat()
        guard(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid()
              and not info.st_mode & (0o077 if private else 0o022) and 0<info.st_size<=2_000_000)
        raw=path.read_bytes();after=path.stat()
        guard((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)==
              (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
              and (expected is None or h(raw)==expected))
        captures[str(path)]={'sha256':h(raw),'device':info.st_dev,'inode':info.st_ino}
        return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:guard(False))
    def ref(value):
        guard(type(value)is dict and set(value)=={'path','sha256'}
            and re.fullmatch('[a-f0-9]{64}',value['sha256']))
        return read(value['path'],value['sha256'])
    release=v['release_sha256'];guard(re.fullmatch('[a-f0-9]{64}',release))
    plan=read(Path('/home/opc/.local/share/fox-project-transitions')/release/'plan.json')
    guard(plan['schema_version']==2 and plan['scope']=='fox-current-pair-transition-v2')
    new=ref(plan['new_installation']);old=ref(plan['old_installation'])
    guard(new['release']['sha256']==release and new['admission']['sha256']==v['configuration_sha256']
          and new['provider']['sha256']==v['provider_configuration_sha256'])
    guard(ref(new['release'])==v['manifest'])
    admission=ref(new['admission'])
    guard(admission['infrastructure']==infrastructure)
    provider=ref(new['provider'])
    inventory=ref(new['layout']['inventory'])
    guard(plan['recovery']=={'path':str(Path(new['layout']['release_root'])/'fox/fox/verification_recovery.py'),
        'sha256':v['manifest']['project']['queue_modules']['verification_recovery.py']}
        and inventory['files']['fox/fox/verification_recovery.py']==plan['recovery']['sha256'])
    baseline=ref(plan['preclaim_preservation']);old_admission=ref(old['admission'])
    guard(set(baseline)=={'schema_version','scope','job_id','request_sha256','source_binding',
        'target_profile_sha256','fox_tree_sha256','receiver_tree_sha256','manifest_sha256','original_handler'}
        and type(baseline['schema_version'])is int and baseline['schema_version']==1
        and baseline['scope']=='fox-reviewed-claimed-validation-terminal-baseline-v1')
    terminal=baseline['original_handler'];pin=old_admission['infrastructure']['forms2apex-mcp']
    guard(set(terminal)=={'method','stage','status','container_id','completed_at_utc'}
        and terminal['method']=='POST' and terminal['stage']=='validate' and type(terminal['status'])is int
        and terminal['status']==409 and terminal['container_id']==pin['id'])
    when=datetime.fromisoformat(terminal['completed_at_utc'].replace('Z','+00:00'))
    guard(when.tzinfo is not None and when<=datetime.now(timezone.utc))
    response=subprocess.run(['podman','inspect',pin['id']],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    guard(response.returncode==0 and not response.stderr.strip() and 0<len(response.stdout)<=2_000_000)
    item=json.loads(response.stdout)[0];state=item['State'];image=item['Image']
    guard(item['Id']==pin['id'] and item['Name'].lstrip('/')=='forms2apex-pre-upgrade-'+release[:16]
        and (image if image.startswith('sha256:') else 'sha256:'+image)==pin['image']
        and state['Running'] is False and type(state['Pid'])is int and state['Pid']==0
        and state['Status'] in ('stopped','exited')
        and datetime.fromisoformat(state['FinishedAt'].replace('Z','+00:00'))>=when)
    profile_path=Path(new['layout']['release_root'])/'deployment/target-profile.jsn-project-v2.json'
    profile=read(profile_path,inventory['files']['deployment/target-profile.jsn-project-v2.json'],private=False)
    guard(profile==provider['target_profile'])
    projection=_host_claimed_execution_target(profile)
    response=subprocess.run(['podman','inspect',infrastructure['forms2apex-mcp']['id']],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    guard(response.returncode==0 and not response.stderr.strip() and 0<len(response.stdout)<=2_000_000)
    current=json.loads(response.stdout)[0]
    mounts=[m for m in current['Mounts'] if m['Destination']=='/run/fox-target/profile.json']
    guard(current['Id']==infrastructure['forms2apex-mcp']['id'] and len(mounts)==1
        and mounts[0]['Source']==str(profile_path) and mounts[0]['Type']=='bind' and mounts[0]['RW'] is False
        and 'F2A_TARGET_PROFILE_PATH=/run/fox-target/profile.json' in current['Config']['Env'])
    canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    return {'baseline':baseline,'original_terminal_sha256':plan['preclaim_preservation']['sha256'],
        'captures':captures,'old_converter':item,'current_converter':current,
        'converter_target_sha256':h(canonical(profile)),'execution_target_sha256':h(canonical(projection))}


def _host_claimed_execution_target(profile):
    """Wire projection only; full focused/converter profile pins stay separate."""
    for name,fields in {'oci':{'compartment_id','database_id','instance_id','region'},
        'database':{'db_name','session_user','parsing_schema'},
        'apex':{'workspace','workspace_id','ords_origin','ords_base_path'},
        'sqlcl':{'saved_connection'},'tested_versions':{'apex','sqlcl','apexlang_mmd','opaf'}}.items():
        guard(type(profile[name])is dict and set(profile[name])==fields
            and all(type(value)is str and 0<len(value)<=2048 for value in profile[name].values()))
    scope=profile['scope']
    guard(profile['active']is True and scope['data_mode']=='synthetic_test_only'
        and scope['existing_resources_only']is True and scope['customer_deployment_authorized']is False
        and scope['supported_operations']==['query','insert','update'])
    return {'schema_version':1,'active':True,**{key:profile[key] for key in ('oci','database','apex','sqlcl')},
        'tested_versions':{key:profile['tested_versions'][key] for key in ('apex','sqlcl','apexlang_mmd')},
        'scope':{key:scope[key] for key in ('data_mode','existing_resources_only',
            'customer_deployment_authorized','supported_operations')}}


def _host_preclaim(v,fox,infrastructure,startup_source):
    """NEW startup only; internally collected evidence, never request flags."""
    # Fixed legacy JSN roles, matching activate_project_release's approved
    # candidate contract. This is not a caller-selected/fresh deployment policy.
    legacy_rootfs = {'fox': True, 'forms2apex-mcp': False}
    pins={}
    for name in ('fox','forms2apex-mcp'):
        response=subprocess.run(['podman','inspect',infrastructure[name]['id']],stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=30)
        guard(response.returncode==0 and not response.stderr.strip() and len(response.stdout)<=2_000_000)
        item=json.loads(response.stdout)[0];image=item['Image'];image=image if image.startswith('sha256:') else 'sha256:'+image
        guard(item['Id']==infrastructure[name]['id'] and image==infrastructure[name]['image']
              and item['Name'].lstrip('/')==name and item['State']['Running'] is True and item['State']['Pid']>0
              and item['HostConfig'].get('ReadonlyRootfs') is legacy_rootfs[name])
        pins[name]=item
    response=subprocess.run(['podman','exec','-i',fox['Id'],'/usr/local/bin/python','-I','-B','-c',startup_source],
        input=json.dumps({'reader_sha256':v['manifest']['project']['queue_modules']['verification_recovery.py'],
            'image_sha256':v['manifest']['images']['fox'][7:]}).encode(),
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240)
    guard(response.returncode==0 and not response.stderr.strip() and 0<len(response.stdout)<=2_000_000)
    value=json.loads(response.stdout);guard(set(value)=={'jobs','collector'})
    if not value['jobs']:return {},{},{}
    _host_preclaim_health()
    response=subprocess.run(['podman','top',infrastructure['forms2apex-mcp']['id'],'pid'],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    guard(response.returncode==0 and not response.stderr.strip()
          and len(response.stdout.decode().splitlines())==2 and response.stdout.decode().splitlines()[1].strip()=='1')
    receiver_mounts={m['Destination']:m for m in pins['forms2apex-mcp']['Mounts']}
    mount=receiver_mounts['/opt/forms2apex/outputs/jobs']
    guard(mount['Type']=='bind' and mount['RW'] is True)
    receiver_root=Path(mount['Source'])
    guard(receiver_root.is_absolute() and receiver_root.resolve()==receiver_root
          and receiver_root == Path('/home/opc/forms2apex/outputs/jobs'))
    pair={name:{'id':item['Id'],'image':infrastructure[name]['image'],
        'configuration_sha256':hashlib.sha256(json.dumps({'config':item['Config'],'host':item['HostConfig'],
            'mounts':item['Mounts']},sort_keys=True,separators=(',',':')).encode()).hexdigest()}
        for name,item in pins.items()}
    h=lambda data:hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    paired,captures={},{}
    provenance=(_host_claimed_provenance(v,infrastructure)
        if any(entry.get('claimed_validation') is True for entry in value['jobs'].values()) else None)
    for job,entry in value['jobs'].items():
        guard(re.fullmatch('fox-[a-f0-9]{20}',job))
        packet={'fox_data':'/home/opc/fox/data','receiver_jobs':str(receiver_root),'job_id':job}
        first=_host_preclaim_collect(value['collector'],packet)
        guard(h(first['fox_tree'])==entry['technical']['fox_tree_sha256'])
        claimed=entry.get('claimed_validation') is True
        guard(claimed==('receiver_claims' in first))
        witness=entry['witness'];observed=datetime.now(timezone.utc)
        if claimed:
            baseline=provenance['baseline']
            guard(baseline['job_id']==job and baseline['request_sha256']==entry['technical']['request_sha256']
                and baseline['source_binding']==entry['request']['source_binding']
                and baseline['target_profile_sha256']==entry['target_profile_sha256']
                and baseline['fox_tree_sha256']==h(first['fox_tree'])
                and baseline['receiver_tree_sha256']==h(first['receiver_tree'])
                and baseline['manifest_sha256']==first['receiver_manifest']['manifest_sha256']
                and provenance['execution_target_sha256']==entry['technical']['execution_target_sha256'])
            fields={'schema_version':1,'scope':'fox-claimed-validation-maintenance-witness-v1',
                'fox_tree_sha256':h(first['fox_tree']),'receiver_tree_sha256':h(first['receiver_tree']),
                'request_sha256':entry['technical']['request_sha256'],
                'execution_target_sha256':entry['technical']['execution_target_sha256'],
                'source_review_authorized':False,'maintenance_only':True}
            witness={**fields,'witness_sha256':h(fields)}
        terminal_pin=provenance['original_terminal_sha256'] if claimed else witness['witness_sha256']
        expected={'job_id':job,'request_sha256':entry['technical']['request_sha256'],
            'source_binding':entry['request']['source_binding'],'target_profile_sha256':entry['target_profile_sha256'],
            'pair_sha256':h(pair),'scope_sha256':h(p['cli_scope']),
            'lease_sha256':h({'release':v['release_sha256'],'configuration':v['configuration_sha256']}),
            'original_terminal_sha256':terminal_pin,'technical_source_sha256':v['manifest']['images']['fox'][7:],
            'mode':'startup','runtime_state':'running','stopped_writer_sha256':None}
        paired[job]={'expected':expected,'readback':{'schema_version':1,'scope':
            'fox-paired-claimed-validation-maintenance-read-v1' if claimed else 'fox-paired-preclaim-maintenance-read-v1',
            'observed_at_utc':observed.isoformat(),'expires_at_utc':(observed+timedelta(seconds=30)).isoformat(),
            'binding':expected,**{k:first[k] for k in ('fox_tree','receiver_tree','receiver_manifest')},
            **({'receiver_claims':first['receiver_claims']} if claimed else {}),
            'technical':{**entry['technical'],'receiver_manifest_raw_sha256':first['receiver_manifest_raw_sha256']},
            'producer':{'fox_worker':'terminal_idle','receiver_servers':1,'receiver_operations':0,'unknown_producers':0,
                'original_terminal_sha256':terminal_pin},
            'serialization_barrier':{'kind':'current_serialized_read','observed_at_utc':observed.isoformat(),
                'binding':{'pair_sha256':h(pair),'fox_tree_sha256':h(first['fox_tree']),
                    'receiver_tree_sha256':h(first['receiver_tree'])},
                'result':({'method':'READ_ONLY_PAIRED_TREE','stage':'claimed_validate','job_id':job,
                    'maintenance_only':True,'source_review_authorized':False} if claimed else
                    {'method':'GET','stage':'validate','job_id':job,'status':404})},
            'gateway_witness':witness,'stopped_writer':None}}
        captures[job]=(value['collector'],packet,first,provenance if claimed else None,v)
    _host_preclaim_health()
    return paired,captures,pair


def _host_preclaim_recheck(captures,infrastructure,pair):
    if not captures:return
    _host_preclaim_health()
    for code,packet,first,provenance,v in captures.values():
        guard(_host_preclaim_collect(code,packet)==first)
        if provenance is not None:guard(_host_claimed_provenance(v,infrastructure)==provenance)
    for name,expected in pair.items():
        response=subprocess.run(['podman','inspect',infrastructure[name]['id']],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        guard(response.returncode==0 and not response.stderr.strip());item=json.loads(response.stdout)[0]
        actual={'id':item['Id'],'image':item['Image'] if item['Image'].startswith('sha256:') else 'sha256:'+item['Image'],
            'configuration_sha256':hashlib.sha256(json.dumps({'config':item['Config'],'host':item['HostConfig'],
            'mounts':item['Mounts']},sort_keys=True,separators=(',',':')).encode()).hexdigest()}
        guard(actual==expected and item['State']['Running'] is True)
    response=subprocess.run(['podman','top',infrastructure['forms2apex-mcp']['id'],'pid'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    guard(response.returncode==0 and not response.stderr.strip() and len(response.stdout.decode().splitlines())==2
          and response.stdout.decode().splitlines()[1].strip()=='1')


def host_source(current_release, configuration_sha256, infrastructure):
    source = bridge.host_source()
    original = 'code=' + repr(bridge.container_source())
    before = " r=subprocess.run(['podman','inspect','fox'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)"
    after = " result.update(host_scope_verified=True,fox_image=v['manifest']['images']['fox'])"
    identity = " fox=inspected[0];container=fox['Id']"
    for marker in (original, before, after, identity):
        _need(source.count(marker) == 1, 'RETIREMENT_REMOTE_HOST_TEMPLATE_CHANGED')
    source = source.replace(original, 'code=' + repr(container_source(current_release, configuration_sha256)), 1)
    source = source.replace(before, ' inventory_before=_host_inventory()\n' + before, 1)
    source = source.replace(identity, identity + '\n guard(container==' + repr(infrastructure['fox']['id']) + ')', 1)
    framing=" framed=base64.b64encode(code.encode())+b'\\n'+json.dumps(v).encode()+b'\\n'"
    _need(source.count(framing)==1,'RETIREMENT_REMOTE_PRECLAIM_TEMPLATE_CHANGED')
    source=source.replace(framing,
        ' paired,captures,pair=_host_preclaim(v,fox,'+repr(infrastructure)+','+repr(STARTUP_PRECLAIM)+')\n'
        " v.pop('paired_preclaim',None)\n if paired:v['paired_preclaim']=paired\n"+framing,1)
    source = source.replace(after,
        ' _host_preclaim_recheck(captures,'+repr(infrastructure)+',pair)\n'
        ' inventory_after=_host_inventory()\n guard(inventory_before==inventory_after)\n'
        " result.update(inventory=inventory_after,observed_at_utc=datetime.now(timezone.utc).isoformat())\n" + after, 1)
    source = source.replace('0<len(r.stdout)<=65536', '0<len(r.stdout)<=2000000', 1)
    source = 'from pathlib import Path\nfrom datetime import datetime,timezone,timedelta\n' + '\n'.join(inspect.getsource(item) for item in
        (_host_inventory,_host_preclaim_health,_host_preclaim_collect,_host_claimed_execution_target,
            _host_claimed_provenance,_host_preclaim,_host_preclaim_recheck)) + '\n' + source
    source=source.replace("stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)",
                          "stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240)")
    compile(source, '<retirement-host>', 'exec')
    return source


def _infrastructure(value, images):
    _need(type(value) is dict and set(value) == {'fox', 'forms2apex-mcp', 'oracle-applied-ai-label'},
          'RETIREMENT_REMOTE_INFRASTRUCTURE_REQUIRED')
    for item in value.values():
        _need(type(item) is dict and set(item) == {'id', 'image'} and _hash(item['id'])
              and type(item['image']) is str and re.fullmatch('sha256:[a-f0-9]{64}', item['image']),
              'RETIREMENT_REMOTE_INFRASTRUCTURE_INVALID')
    _need(len({item['id'] for item in value.values()}) == 3
          and value['fox']['image'] == images['fox'] and value['forms2apex-mcp']['image'] == images['converter'],
          'RETIREMENT_REMOTE_INFRASTRUCTURE_BINDING_CHANGED')
    return json.loads(_canonical(value))


def admission_configuration(current_release, provider_configuration_sha256, infrastructure):
    """D binds current R, provider C and exact infrastructure without a cycle.

    R already binds C in its v3 manifest. D is separately installation-owned
    admission data; it is not C and must never be compared to C as an alias.
    """
    _need(_hash(current_release) and _hash(provider_configuration_sha256),
          'RETIREMENT_REMOTE_ADMISSION_CONFIGURATION_INVALID')
    return {'schema_version': 1, 'scope': 'fox-hosted-admission-v1',
            'provider_configuration_sha256': provider_configuration_sha256,
            'current_release_sha256': current_release,
            'infrastructure': json.loads(_canonical(infrastructure))}


def validate_snapshot(value, *, history, current_release, configuration_sha256,
                      provider_configuration_sha256, images,
                      infrastructure, for_startup, now=None):
    """Verify the full protected response; a caller-supplied ready flag is invalid."""
    from fox import verification_recovery
    history = validate_history(history, current_release)
    infrastructure = _infrastructure(infrastructure, images)
    _need(_digest(_canonical(admission_configuration(current_release, provider_configuration_sha256,
          infrastructure))) == configuration_sha256, 'RETIREMENT_REMOTE_ADMISSION_CONFIGURATION_CHANGED')
    keys = {'schema_version', 'scope', 'status', 'current_release_sha256', 'configuration_sha256',
            'provider_configuration_sha256', 'images',
            'history_sha256', 'for_startup', 'read_only', 'automatic_replay_permitted',
            'failure_acknowledgement', 'completed_retry', 'completed_idle_jobs',
            'waiting_verification_count', 'busy_conversion_count', 'admission_state', 'backend_snapshot_sha256', 'inventory',
            'observed_at_utc', 'host_scope_verified', 'fox_image'}
    old, retry = history['failure'], history['retry']
    _need(type(value) is dict and set(value) == keys and type(value['schema_version']) is int
          and value['schema_version'] == 1 and value['scope'] == SCOPE
          and value['status'] == 'RETIRED_HISTORY_OBSERVED' and type(for_startup) is bool
          and value['for_startup'] is for_startup and value['current_release_sha256'] == current_release
          and value['configuration_sha256'] == configuration_sha256 and _hash(configuration_sha256)
          and value['provider_configuration_sha256'] == provider_configuration_sha256
          and value['images'] == images and value['fox_image'] == images['fox']
          and value['history_sha256'] == _digest(_canonical(history))
          and value['read_only'] is value['host_scope_verified'] is True
          and value['automatic_replay_permitted'] is False, 'RETIREMENT_REMOTE_RESPONSE_BINDING_CHANGED')
    acknowledgement = {'status': 'FAILED_QA_RECORDED',
        'disposition_sha256': old['disposition_sha256'], 'disposition': old['disposition']}
    _need(type(value['failure_acknowledgement']) is dict
          and _canonical(value['failure_acknowledgement']) == _canonical(acknowledgement)
          and value['completed_retry'] == {key: retry[key] for key in ('release_sha256', 'job_id', 'attempt_id', 'proof_sha256')}
          and value['completed_idle_jobs'] == history['idle']['completed_jobs']
          and _hash(value['backend_snapshot_sha256']) and type(value['waiting_verification_count']) is int
          and 0 <= value['waiting_verification_count'] <= 10000
          and type(value['busy_conversion_count']) is int and 0 <= value['busy_conversion_count'] <= 10000
          and value['admission_state'] == ('WAIT' if value['busy_conversion_count'] else 'READY')
          and (for_startup or value['waiting_verification_count'] == value['busy_conversion_count'] == 0),
          'RETIREMENT_REMOTE_PROOF_RESPONSE_CHANGED')
    contract = verification_recovery.classification_contract()
    now = datetime.now(timezone.utc) if now is None else now
    observed = contract.timestamp(value['observed_at_utc'])
    _need(-5 <= float(contract.timestamp(now.isoformat()) - observed) <= 30,
          'RETIREMENT_REMOTE_OBSERVATION_EXPIRED')
    rows = value['inventory']
    _need(type(rows) is list and 3 <= len(rows) <= 256
          and all(type(row) is dict and 'id' in row and 'name' in row for row in rows)
          and len({row['id'] for row in rows}) == len(rows)
          and len({row['name'] for row in rows}) == len(rows)
          and [row['id'] for row in rows] == sorted(row['id'] for row in rows),
          'RETIREMENT_REMOTE_INVENTORY_INVALID')
    found = set()
    for row in rows:
        kind = contract.classify_row(row, value['observed_at_utc'])
        expected = infrastructure.get(row['name'])
        if expected is not None:
            _need(row['id'] == expected['id'] and row['image'] == expected['image'] and kind == 'LIVE'
                  and row['running'] is True and row['status'] == 'running' and row['pid'] > 0,
                  'RETIREMENT_REMOTE_INFRASTRUCTURE_CHANGED')
            found.add(row['name'])
        else:
            _need(kind in {'CREATED_NEVER_STARTED', 'STOPPED_NON_LIVE'},
                  'RETIREMENT_REMOTE_LIVE_OR_UNKNOWN_PRODUCER')
    _need(found == set(infrastructure), 'RETIREMENT_REMOTE_INFRASTRUCTURE_MISSING')
    return json.loads(_canonical(value))


class RetiredHistoryRemoteReader:
    """Concrete guarded transport. Construction performs no host operation."""
    def __init__(self, current_manifest, current_release, infrastructure, configuration_sha256):
        checked = bridge.validate_release(current_manifest)
        _need(checked['schema_version'] == 3 and checked['enabled'] is True
              and bridge.release_sha256(checked) == current_release and _hash(configuration_sha256),
              'RETIREMENT_REMOTE_NEW_CURRENT_RELEASE_REQUIRED')
        self.manifest_raw = _canonical(checked)
        self.current_release, self.configuration_sha256 = current_release, configuration_sha256
        self.infrastructure_raw = _canonical(_infrastructure(infrastructure, checked['images']))
        _need(_digest(_canonical(admission_configuration(current_release,
              self.provider_configuration_sha256, self.infrastructure))) == configuration_sha256,
              'RETIREMENT_REMOTE_ADMISSION_CONFIGURATION_CHANGED')
        self.source_sha256 = _digest(Path(__file__).read_bytes())

    @property
    def manifest(self):
        return json.loads(self.manifest_raw)

    @property
    def infrastructure(self):
        return json.loads(self.infrastructure_raw)

    @property
    def provider_configuration_sha256(self):
        return self.manifest['hosted_runtime_configuration_sha256']

    def read(self, history, *, for_startup=True):
        try:
            _need(type(self) is RetiredHistoryRemoteReader and type(for_startup) is bool,
                  'RETIREMENT_REMOTE_TYPED_READER_REQUIRED')
            _need(_digest(Path(__file__).read_bytes()) == self.source_sha256,
                  'RETIREMENT_REMOTE_READER_SOURCE_CHANGED')
            manifest = bridge.require_ready(self.manifest, self.current_release)
            infrastructure = _infrastructure(self.infrastructure, manifest['images'])
            _need(_digest(_canonical(admission_configuration(self.current_release,
                  self.provider_configuration_sha256, infrastructure))) == self.configuration_sha256,
                  'RETIREMENT_REMOTE_ADMISSION_CONFIGURATION_CHANGED')
            history = validate_history(history, self.current_release)
            request = {'operation': 'retired_history_read', 'apply': False, 'manifest': manifest,
                       'release_sha256': self.current_release, 'configuration_sha256': self.configuration_sha256,
                       'provider_configuration_sha256': self.provider_configuration_sha256,
                       'history': history, 'for_startup': for_startup}
            _need(len(_canonical(request)) <= MAX_PACKET, 'RETIREMENT_REMOTE_REQUEST_TOO_LARGE')
            program = host_source(self.current_release, self.configuration_sha256, self.infrastructure)
            scope = bridge.clean.oci_scope(require_database_available=False)
            value = bridge.clean.ssh_json(program, {'cli_scope': scope, 'request': request})
            bridge.require_ready(self.manifest, self.current_release)
            _need(_digest(Path(__file__).read_bytes()) == self.source_sha256,
                  'RETIREMENT_REMOTE_READER_SOURCE_CHANGED')
            return validate_snapshot(value, history=history, current_release=self.current_release,
                configuration_sha256=self.configuration_sha256,
                provider_configuration_sha256=self.provider_configuration_sha256, images=manifest['images'],
                infrastructure=self.infrastructure, for_startup=for_startup)
        except RetirementRemoteError:
            raise
        except Exception:
            raise RetirementRemoteError('RETIREMENT_REMOTE_READ_UNCONFIRMED') from None
