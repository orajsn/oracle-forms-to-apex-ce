"""Pure classification of a project QA handoff failure after clean import.

Unlike the earlier clean-check failure, this case already owns an imported
application. Completed operations must remain intact. A classified capture is
not live authority, a terminal disposition, technical success or permission to
repeat any step. A later guarded operator must independently observe exclusion
and exact state before deciding how to continue.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from . import contracts as c, project_contracts as pc
from . import product_queue_transport as bridge, product_verifier as verifier
from . import project_qa_contracts as preparation
from fox.verification_queue import VerificationQueue, VerificationBinding

CAPTURE_SCOPE = 'fox-project-qa-stage-failure-capture-v1'
SCOPE = 'fox-project-qa-stage-failure-assessment-v1'
PHASES = ('allocate', 'schema', 'import', 'verify')
STEPS = ('prepare', 'clean_check', *PHASES)
CLEAN_FILES = frozenset((*preparation.EVIDENCE, 'plan.json',
    'schema.evidence.json', 'import.evidence.json',
    *(phase + suffix for phase in PHASES for suffix in ('.intent.json', '.complete.json'))))
_HASH = re.compile(r'[a-f0-9]{64}\Z')
_SESSION = re.compile(r'session-[a-f0-9]{24}\Z')


class QaStageEvidenceError(ValueError):
    """Fixed, source-free classification failures only."""


def need(value, code):
    if not value:
        raise QaStageEvidenceError(code)


def _decode(value, maximum):
    need(type(value) is str and 0 < len(value) <= (maximum + 2) // 3 * 4,
         'QA_STAGE_ENCODED_BOUND')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise QaStageEvidenceError('QA_STAGE_ENCODING_INVALID') from None
    need(0 < len(raw) <= maximum, 'QA_STAGE_BYTES_BOUND')
    return raw


def _capture_digest(value):
    # Capture contains encoded package bytes, not just a small operator JSON
    # document. Stream a separately bounded canonical encoding rather than
    # weakening contracts.MAX_JSON_BYTES for every existing plan/receipt.
    encoder=json.JSONEncoder(sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    digest=hashlib.sha256();size=0
    for chunk in encoder.iterencode(value):
        raw=chunk.encode('utf-8');size+=len(raw)
        need(size<=64_000_000,'QA_STAGE_CAPTURE_BOUND')
        digest.update(raw)
    digest.update(b'\n')
    return digest.hexdigest()


def assess_capture(capture, *, expected_release_sha256, expected_installation_sha256,
                   expected_converter_id, expected_converter_image):
    """Check exact captured bytes only; never access files, OCI, SQL or a browser."""
    try:
        return _assess(capture, expected_release_sha256, expected_installation_sha256,
                       expected_converter_id, expected_converter_image)
    except QaStageEvidenceError:
        raise
    except Exception:
        raise QaStageEvidenceError('QA_STAGE_RETAINED_CONTRACT_INVALID') from None


def _assess(capture, release_sha, installation_sha, converter_id, converter_image):
    need(all(type(v) is str and _HASH.fullmatch(v) for v in
             (release_sha, installation_sha, converter_id))
         and type(converter_image) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', converter_image),
         'QA_STAGE_INDEPENDENT_PINS_REQUIRED')
    need(type(capture) is dict and set(capture) == {'scope', 'writes_requested',
         'installation_sha256', 'release', 'session', 'journal', 'product', 'clean',
         'observation', 'dependency_probe'} and capture['scope'] == CAPTURE_SCOPE
         and capture['writes_requested'] is False
         and capture['installation_sha256'] == installation_sha,
         'QA_STAGE_CAPTURE_FIELDS_OR_INSTALLATION')
    manifest = bridge.validate_release(capture['release'])
    need(c.digest(c.canonical_bytes(manifest)) == release_sha
         and manifest['schema_version'] in (2, 3) and manifest['enabled'] is True
         and manifest['images']['converter'] == converter_image, 'QA_STAGE_RELEASE_CHANGED')
    need(type(capture['session']) is str and _SESSION.fullmatch(capture['session']),
         'QA_STAGE_SESSION_INVALID')
    product = capture['product']
    need(type(product) is dict and set(product) == {'queue', 'run',
         'technical_proof_count', 'human_acceptance_count'}
         and all(type(product[k]) is int and product[k] == 0 for k in
                 ('technical_proof_count', 'human_acceptance_count')), 'QA_STAGE_PROOF_OR_ACCEPTANCE_EXISTS')
    queue = VerificationQueue._record(product['queue'])
    need(queue is not None and queue['state'] == 'attention' and queue['proof_sha256'] is None
         and queue['attention_code'] == 'BACKEND_OUTCOME_UNCONFIRMED',
         'QA_STAGE_QUEUE_NOT_ATTENTION')
    binding = VerificationBinding.from_payload({k: queue[k] for k in
        ('job_id', 'source_manifest_sha256', 'package_sha256', 'verifier_release_sha256')})
    need(binding.verifier_release_sha256 == release_sha, 'QA_STAGE_QUEUE_RELEASE_CHANGED')
    run = product['run']
    need(type(run) is dict and set(run) == {'id','state','source_hash','artifact'}
         and run.get('id') == binding.job_id and run.get('state') == 'QA_REQUIRED'
         and run.get('source_hash') == binding.source_manifest_sha256
         and run.get('artifact') == f'jobs/{binding.job_id}/apex-package.zip', 'QA_STAGE_RUN_CHANGED')
    encoded = capture['journal']
    need(type(encoded) is dict and len(encoded) == 17, 'QA_STAGE_EXACT_SINGLE_CLAIM_REQUIRED')
    labels = [k for k in encoded if type(k) is str and re.fullmatch(r'p[0-9]{4}-qa-stage\.intent\.json', k)]
    need(len(labels) == 1, 'QA_STAGE_INTENT_REQUIRED')
    prefix = labels[0].split('-', 1)[0]
    need(prefix == 'p0001', 'QA_STAGE_MISSING_EARLIER_POLL_HISTORY')
    expected = {'session.json', 'attention.json', labels[0],
        *(prefix + '-' + step.replace('_', '-') + suffix for step in ('claim', *STEPS)
          for suffix in ('.intent.json', '.complete.json'))}
    need(set(encoded) == expected, 'QA_STAGE_LATER_OR_UNKNOWN_STEP_PRESENT')
    journal = {name: _decode(raw, 65536) for name, raw in encoded.items()}
    docs = {name: c.load_json(raw) for name, raw in journal.items()}
    header = docs['session.json']
    need(set(header) == {'scope','release_sha256','started_at_utc','bounds','startup_authorized'}
         and header['scope'] == 'fox-product-verifier-session-v1'
         and header['release_sha256'] == release_sha and header['startup_authorized'] is True,
         'QA_STAGE_SESSION_BINDING')
    c._timestamp(header['started_at_utc'])
    bounds = header['bounds']
    need(type(bounds) is dict and set(bounds) == {'max_jobs','max_polls','max_seconds','poll_seconds'}
         and all(type(v) is int for v in bounds.values()) and bounds['max_jobs'] == 1
         and 1 <= bounds['max_polls'] <= 120 and 1 <= bounds['max_seconds'] <= 7200
         and 1 <= bounds['poll_seconds'] <= 60, 'QA_STAGE_SESSION_BOUNDS')
    need(docs['attention.json'] == {'status':'ATTENTION','release_sha256':release_sha,
         'known_claim':True,'code':'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE',
         'automatic_replay_permitted':False}, 'QA_STAGE_ATTENTION_CHANGED')
    binding_sha = c.digest(c.canonical_bytes(binding.payload()))
    results = {}
    for step in ('claim', *STEPS, 'qa_stage'):
        label = prefix + '-' + step.replace('_', '-')
        need(docs[label+'.intent.json'] == {'scope':'fox-product-verifier-step-v1',
             'release_sha256':release_sha,'step':label,
             'binding_sha256':None if step == 'claim' else binding_sha}, 'QA_STAGE_INTENT_CHANGED')
        if step == 'qa_stage':
            continue
        complete = docs[label+'.complete.json']
        need(set(complete) == {'scope','release_sha256','intent_sha256','result'}
             and complete['scope'] == 'fox-product-verifier-step-result-v1'
             and complete['release_sha256'] == release_sha
             and complete['intent_sha256'] == c.digest(journal[label+'.intent.json']),
             'QA_STAGE_COMPLETION_CHANGED')
        results[step] = complete['result']
    need(results['claim'] == {'status':'CLAIMED','claim':{'binding':binding.payload(),
         'attempt_token':queue['claim_token']}}, 'QA_STAGE_ORIGINAL_CLAIM_CHANGED')
    context = {}
    for step in STEPS:
        context.update(verifier.safe_phase(step, results[step], binding, context, manifest))
    need(context['conversion_profile'] == 'native-project-v1', 'QA_STAGE_PROJECT_PROFILE_REQUIRED')
    encoded = capture['clean']
    need(type(encoded) is dict and set(encoded) == CLEAN_FILES, 'QA_STAGE_CLEAN_MEMBERS_OR_CREDENTIALS')
    files = {name: _decode(raw, 8_000_000 if name == 'package.zip' else 2_000_000)
             for name, raw in encoded.items()}
    plan = pc.validate_plan(files['plan.json'],operator_code_sha256=manifest['project']['clean_operator_code_sha256'])
    need(c.digest(files['plan.json']) == context['plan_sha256']
         and all(plan['binding'][k] == v for k,v in binding.payload().items()
                 if k != 'verifier_release_sha256'), 'QA_STAGE_PLAN_BINDING_CHANGED')
    prepared = preparation.prepare_evidence(files['plan.json'],
        {name:files[name] for name in preparation.EVIDENCE},operator_code_sha256=plan['operator_code_sha256'])
    for phase in PHASES:
        intent, complete = (c.load_json(files[phase+suffix]) for suffix in ('.intent.json','.complete.json'))
        need(pc.validate_phase_record(intent,plan,phase) == 'attention' and intent['state'] == 'intent'
             and pc.validate_phase_record(complete,plan,phase) == 'complete'
             and complete['started_at_utc'] == intent['started_at_utc']
             and complete['evidence_sha256'] == results[phase]['evidence_sha256']
             == c.digest(files[phase+'.evidence.json']), 'QA_STAGE_CLEAN_PHASE_CHANGED')
    source = manifest['project']['qa_source_sha256']
    observation = capture['observation']
    stage = '/home/opc/.config/fox-qa/project-v1-stages/'+context['plan_sha256']+'/'+source
    need(type(observation) is dict and set(observation) == {'service','active_sqlcl_pids',
         'active_browser_pids','stage_path','stage_exists','stage_image_tags_present',
         'launch_intent_exists','dispatch_receipt_exists'}
         and observation['service'] == {'LoadState':'loaded','ActiveState':'failed','SubState':'failed','MainPID':'0'}
         and observation['stage_path'] == stage
         and all(type(observation[k]) is list and observation[k] == [] for k in
                 ('active_sqlcl_pids','active_browser_pids','stage_image_tags_present'))
         and all(observation[k] is False for k in ('stage_exists','launch_intent_exists','dispatch_receipt_exists')),
         'QA_STAGE_PRODUCER_OR_STAGE_EFFECT_UNCONFIRMED')
    probe = capture['dependency_probe']
    need(type(probe) is dict and probe == {'module':'fox.native_verification','exit_code':1,
         'error_kind':'ModuleNotFoundError','source_sha256':source,
         'container_id':converter_id,'converter_image':converter_image}
         and type(probe['exit_code']) is int, 'QA_STAGE_POSITIVE_DEPENDENCY_PROBE_REQUIRED')
    return {'schema_version':1,'scope':SCOPE,'status':'CLASSIFIED_QA_STAGE_FAILURE_NOT_CLOSED',
        'binding':binding.payload(),'session':capture['session'],'installation_sha256':installation_sha,
        'legacy_record_sha256':queue['record_sha256'],
        'claim_sha256':c.digest(c.canonical_bytes(results['claim']['claim'])),
        'retained_sha256':{name:c.digest(raw) for name,raw in sorted(journal.items())},
        'clean_sha256':{name:c.digest(raw) for name,raw in sorted(files.items())},
        'capture_sha256':_capture_digest(capture),'plan_sha256':context['plan_sha256'],
        'qa_source_sha256':source,'completed_steps':list(STEPS),'failed_phase':'qa_stage',
        'missing_dependency':'fox.native_verification',
        'target':c.load_json(prepared['target.json'])['target'],
        'expected_versions':plan['expected_versions'],'current_admission_blocks':True,
        'closure_performed':False,'technical_success':False,'human_acceptance_recorded':False,
        'automatic_replay_permitted':False,'recovery_authorized':False}
