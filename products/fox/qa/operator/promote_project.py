"""Protected whole-project receipt promotion; no APEX, OCI or browser work.

``check`` validates supplied exact receipts without copying or changing logical
state. ``apply`` invokes the already checked project gate once and rechecks its
durable proof. An interrupted technical decision may reuse only its exact
retained attempt; no clean-install or browser operation exists in this module.
The paired FOX image and closed application-module hashes are prerequisites,
not a declaration that this local code has been deployed.

Explicit inputs accept only owner-private project-clean-install/<plan-sha256>/
qa-<source-prefix> collections, or a directly named handoff-root/<shortname>
collection (lowercase letter followed by up to 39 lowercase letters, digits or
hyphens). Both require the exact approved manifest hash and all thirteen bound
receipts; neither path is discovered or adopted automatically. A short harvest
does not authorize new clean-install/browser work or bypass source, freshness,
launch or dispatch checks. Historical proof reads remain the separate retained
proof reader; they do not need a current collection or current QA source.
The legacy handoff root remains ROOT/work; the hosted provider selects its
installation-owned private handoff root before any operator work.
"""
from __future__ import annotations

import base64
import inspect
import json
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / 'fox'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import contracts as C
from qa.operator import project_clean_install as transport
from qa.operator.promote_native import FILES, SHA, digest, require
from qa.operator.project_qa_dispatch import private_inputs
from fox.native_verification_policy import BoundVerificationPolicy, validate_allocation_receipt
from fox.native_verification import _json as receipt_json

# The complete FOX-relative import closure used by project verification. Third
# party and standard-library dependencies are bound by the approved image pin.
MODULES = ('intake.py', 'native_source.py', 'opaf.py', 'native_pipeline.py',
           'native_verification_policy.py', 'native_verification.py',
           'native_qa_plan.py', 'project_conversion.py', 'project_qa_plan.py',
           'project_progress.py', 'native_project_pipeline.py', 'source_history.py',
           'project_verification.py', 'project_verification_runtime.py')
COLLECTION_FILES = frozenset(FILES.values()) | {'package.zip', 'native-project-spec.json', 'source-to-apex.json',
    'stage-receipt.json', 'launch-intent.json', 'launch-receipt.json', 'dispatch-receipt.json'}


def module_hashes():
    result = {}
    for name in MODULES:
        path = ROOT / 'fox/fox' / name
        require(path.resolve() == path and path.is_file() and not path.is_symlink()
                and 0 < path.stat().st_size <= 2_000_000, 'LOCAL_PROJECT_MODULE_UNSAFE')
        raw = path.read_bytes()
        require(0 < len(raw) <= 2_000_000, 'LOCAL_PROJECT_MODULE_UNSAFE')
        result[name] = digest(raw)
    return result


def collection_provenance(files, manifest, policy):
    """Require one observed, source-bound browser dispatch before promotion.

    These private records are owner attestations, not signatures. Credentials
    remain excluded; their retained stage hash is checked as an identity only.
    The actual project proof still independently checks every runtime case.
    """
    from qa.operator import project_qa_dispatch as qa
    sources, _, _, source_sha = qa.bundle()
    plan_sha = manifest['plan_sha256']
    require(source_sha == manifest['source_sha256'], 'PROJECT_QA_APPROVED_SOURCE_DIFFERS')
    stage_path = '/home/opc/.config/fox-qa/project-v1-stages/' + plan_sha + '/' + source_sha
    tag = 'localhost/fox-project-qa:v1-' + plan_sha[:16] + '-' + source_sha[:16]
    stage, launch, completed, dispatch, target, result = [receipt_json(files[name]) for name in (
        'stage-receipt.json', 'launch-intent.json', 'launch-receipt.json', 'dispatch-receipt.json',
        'target-receipt.json', 'qa-result.json')]
    image = stage.get('image_id')
    require(type(image) is str and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', image), 'PROJECT_QA_IMAGE_REQUIRED')
    allocation_sha = digest(files['allocation-receipt.json'])
    expected_stage = {'status': 'STAGED', 'plan_sha256': plan_sha, 'source_sha256': source_sha,
        'allocation_receipt_sha256': allocation_sha, 'image_id': image, 'image_tag': tag, 'stage': stage_path}
    require(set(stage) == set(expected_stage) | {'bound_files'}
            and all(stage[key] == value for key, value in expected_stage.items()), 'PROJECT_QA_STAGE_DIFFERS')
    bindings = {'source/' + name: digest(content) for name, content in sources.items()}
    containerfile = ('FROM ' + tag + '-base\nUSER root\nCOPY lib /opt/fox-qa/lib\nCOPY run-project.mjs /opt/fox-qa/\n'
                     'RUN chmod -R a+rX /opt/fox-qa\nUSER pwuser\n').encode()
    bindings['source/Containerfile'] = digest(containerfile)
    mapping = {'inputs/package.zip': 'package.zip', 'inputs/native-project-spec.json': 'native-project-spec.json',
        'inputs/source-to-apex.json': 'source-to-apex.json', 'inputs/allocate.evidence.json': 'allocation-receipt.json',
        'inputs/verification-profile.json': 'verification-profile.json', 'inputs/verify.evidence.json': 'clean-import-receipt.json',
        'prepared/profile.json': 'qa-profile.json', 'prepared/target.json': 'target-receipt.json'}
    bindings.update({name: digest(files[collected]) for name, collected in mapping.items()})
    bound = stage.get('bound_files')
    require(type(bound) is dict and set(bound) == set(bindings) | {'inputs/runtime-credentials.json'}
            and all(type(value) is str and SHA.fullmatch(value) for value in bound.values())
            and all(bound[name] == value for name, value in bindings.items()), 'PROJECT_QA_STAGE_BYTES_DIFFER')
    require(launch == {'scope': 'fox-project-qa-launch-v1', 'allocation_receipt_sha256': allocation_sha,
        'plan_sha256': plan_sha, 'source_sha256': source_sha, 'image_id': image,
        'state': 'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY'}, 'PROJECT_QA_LAUNCH_INTENT_DIFFERS')
    require(completed == {'status': 'PASSED', 'exit_code': 0, 'plan_sha256': plan_sha,
        'source_sha256': source_sha, 'image_id': image, 'result_directory': stage_path + '/results',
        'automatic_replay_permitted': False} and type(completed['exit_code']) is int,
        'PROJECT_QA_LAUNCH_COMPLETION_UNPROVEN')
    run_id = result.get('run_id')
    require(type(run_id) is str and re.fullmatch(r'FPQ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}', run_id)
            and result.get('status') == 'PASSED' and result.get('runtime_image_id') == image
            and result.get('dispatch_state') == 'ATTEMPT_COMPLETED'
            and type(result.get('write_attempts')) is list and bool(result['write_attempts'])
            and manifest.get('report_path') == stage_path + '/results/' + run_id + '/qa-result.json',
            'PROJECT_QA_RESULT_DISPATCH_UNPROVEN')
    require(target.get('target') == policy.target
            and all(target.get(key) == value for key, value in policy.binding.items())
            and target.get('verification_profile_sha256') == policy.sha256
            and target.get('profile_sha256') == digest(files['qa-profile.json'])
            and target.get('import_receipt_sha256') == digest(files['clean-import-receipt.json'])
            and target.get('package_sha256') == digest(files['package.zip'])
            and target.get('project_spec_sha256') == digest(files['native-project-spec.json'])
            and target.get('source_to_apex_sha256') == digest(files['source-to-apex.json'])
            and result.get('target') == target
            and result.get('target_receipt_sha256') == digest(files['target-receipt.json']),
            'PROJECT_QA_COLLECTED_INPUT_BINDING_DIFFERS')
    expected_dispatch = {'schema_version': 1, 'scope': 'fox-project-qa-dispatch-v1', 'run_id': run_id,
        'job_id': policy.binding['job_id'], 'allocation_receipt_sha256': allocation_sha,
        'verification_profile_sha256': policy.sha256, 'target_receipt_sha256': digest(files['target-receipt.json']),
        'test_plan_sha256': result.get('test_plan_sha256'), 'package_sha256': policy.binding['package_sha256'],
        'image_id': image, 'state': 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'}
    require(type(dispatch.get('schema_version')) is int and set(dispatch) == set(expected_dispatch) | {'started_at'}
            and all(dispatch[key] == value for key, value in expected_dispatch.items())
            and type(expected_dispatch['test_plan_sha256']) is str and SHA.fullmatch(expected_dispatch['test_plan_sha256'])
            and target.get('test_plan_sha256') == expected_dispatch['test_plan_sha256']
            and C._timestamp(result.get('started_at')) <= C._timestamp(dispatch.get('started_at'))
                <= C._timestamp(result.get('finished_at')), 'PROJECT_QA_DISPATCH_RECEIPT_DIFFERS')


def payload(command, evidence_dir, *, collection_sha256, expected_image, module_sha256, apply=False):
    require(command in ('check', 'apply') and apply is (command == 'apply'), 'EXPLICIT_ACTION_REQUIRED')
    require(type(expected_image) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', expected_image)
            and type(module_sha256) is dict and set(module_sha256) == set(MODULES)
            and all(type(value) is str and SHA.fullmatch(value) for value in module_sha256.values())
            and type(collection_sha256) is str and SHA.fullmatch(collection_sha256),
            'EXACT_APPROVED_IMAGE_MODULE_AND_COLLECTION_HASHES_REQUIRED')
    directory = Path(evidence_dir).absolute()
    private_root = transport.private_root()
    handoff_root = transport.handoff_root(legacy_root=ROOT / 'work')
    plan_collection = (directory.parent.parent == private_root
        and SHA.fullmatch(directory.parent.name) is not None
        and re.fullmatch(r'qa-[a-f0-9]{16}', directory.name) is not None)
    short_collection = (directory.parent == handoff_root
        and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', directory.name) is not None)
    require(plan_collection or short_collection, 'EXACT_PRIVATE_PROJECT_COLLECTION_REQUIRED')
    paths = [directory, directory / 'collection-manifest.json', *[directory / name for name in sorted(COLLECTION_FILES)]]
    boundary = private_root if plan_collection else handoff_root
    path_guards = [*paths, directory.parent, boundary]
    require(all(path.exists() and path.resolve() == path and not path.is_symlink()
                and not getattr(path.lstat(), 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
                for path in path_guards), 'PROJECT_COLLECTION_LINK_OR_REPARSE_FORBIDDEN')
    private_inputs(paths)
    require(directory.is_dir() and all(path.is_file() and path.stat().st_nlink == 1 for path in paths[1:]),
            'COLLECTION_FILES_REQUIRED')
    require({path.name for path in directory.iterdir()} == COLLECTION_FILES | {'collection-manifest.json'},
            'EXACT_PROJECT_COLLECTION_MEMBERS_REQUIRED')
    require(0 < paths[1].stat().st_size <= 65_536, 'COLLECTION_MANIFEST_SIZE_INVALID')
    manifest_raw = paths[1].read_bytes()
    require(digest(manifest_raw) == collection_sha256, 'COLLECTION_MANIFEST_CHANGED')
    manifest = C.load_json(manifest_raw)
    source_sha = manifest.get('source_sha256')
    require(manifest.get('status') == 'COLLECTED' and manifest.get('credentials_and_logs_excluded') is True
            and type(source_sha) is str and SHA.fullmatch(source_sha)
            and type(manifest.get('plan_sha256')) is str and SHA.fullmatch(manifest['plan_sha256'])
            and (short_collection or directory.parent.name == manifest['plan_sha256']
                 and directory.name == 'qa-' + source_sha[:16]), 'COLLECTION_IDENTITY_DIFFERS')
    require(type(manifest.get('sha256')) is dict and set(manifest['sha256']) == COLLECTION_FILES,
            'EXACT_PROJECT_COLLECTION_HASHES_REQUIRED')
    collected_files = {}
    for collected in COLLECTION_FILES:
        path = directory / collected
        maximum = (8_000_000 if collected == 'package.zip' else 16_384
                   if collected in ('verification-profile.json', 'allocation-receipt.json') else 2_000_000)
        require(0 < path.stat().st_size <= maximum, 'COLLECTED_RECEIPT_SIZE_INVALID')
        raw = path.read_bytes()
        require(0 < len(raw) <= maximum and digest(raw) == manifest.get('sha256', {}).get(collected),
                'COLLECTED_RECEIPT_CHANGED')
        collected_files[collected] = raw
    require(sum(len(raw) for raw in collected_files.values()) <= 12_000_000, 'PROJECT_COLLECTION_TOO_LARGE')
    receipts = {name: collected_files[collected] for name, collected in FILES.items()}
    policy = BoundVerificationPolicy(receipts['verification-profile.json'], historical=True)
    allocation = validate_allocation_receipt(receipts['allocation-receipt.json'], policy)
    clean = receipt_json(receipts['clean-install.json'])
    require(allocation['plan_sha256'] == manifest['plan_sha256']
            and clean.get('scope') == 'fox-project-clean-package-install-v1'
            and clean.get('profile_id') == 'native-project-v1', 'PROJECT_COLLECTION_ALLOCATION_DIFFERS')
    collection_provenance(collected_files, manifest, policy)
    return {'command': command, 'apply': apply, 'expected_image': expected_image,
            'module_sha256': dict(module_sha256), 'collection_manifest_sha256': collection_sha256,
            'binding': policy.binding, 'receipt_sha256': {name: digest(raw) for name, raw in receipts.items()},
            'receipts': {name: base64.b64encode(raw).decode() for name, raw in receipts.items()}}


def container_execute(value, gate, root='/data', operator_root='/tmp', now=None):
    """Injectable local roots are test seams; dispatch always uses fixed roots."""
    import base64
    from contextlib import redirect_stderr, redirect_stdout
    from datetime import datetime, timezone
    import hashlib
    import io
    import json
    from pathlib import Path
    import sqlite3
    from fox.native_verification_policy import BoundVerificationPolicy, validate_allocation_receipt

    def need(ok, code):
        if not ok:
            raise RuntimeError(code)
    def sha(raw):
        return hashlib.sha256(raw).hexdigest()

    need(type(value) is dict and set(value) == {'command', 'apply', 'expected_image', 'module_sha256',
         'collection_manifest_sha256', 'binding', 'receipt_sha256', 'receipts'}, 'PROJECT_PACKET_INVALID')
    need(value['command'] in ('check', 'apply') and value['apply'] is (value['command'] == 'apply'),
         'EXPLICIT_ACTION_REQUIRED')
    receipts = {name: base64.b64decode(raw, validate=True) for name, raw in value['receipts'].items()}
    names = set(gate.RECEIPT_NAMES) | {'verification-profile.json', 'allocation-receipt.json'}
    need(set(receipts) == set(value['receipt_sha256']) == names
         and all(0 < len(raw) <= (16_384 if name in {'verification-profile.json', 'allocation-receipt.json'} else 2_000_000)
                 and sha(raw) == value['receipt_sha256'][name] for name, raw in receipts.items()),
         'EXACT_PROJECT_RECEIPT_BYTES_REQUIRED')
    policy = BoundVerificationPolicy(receipts['verification-profile.json'], historical=True)
    allocation_raw = receipts['allocation-receipt.json']
    validate_allocation_receipt(allocation_raw, policy)
    need(policy.binding == value['binding'], 'EXACT_PROJECT_PROFILE_BINDING_REQUIRED')
    job_id = policy.binding['job_id']
    native = gate.native_io
    root = native._safe_path(Path(root))
    database = native._safe_path(root / 'fox.sqlite3')
    receipt_hashes = {name: value['receipt_sha256'][name] for name in gate.RECEIPT_NAMES}

    def state():
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
            need(connection.execute("SELECT COUNT(*) FROM runs WHERE state IN ('QUEUED','PROCESSING')").fetchone()[0] == 0,
                 'ACTIVE_FOX_JOB_PREVENTS_PROMOTION')
            row = gate._one(connection, 'SELECT * FROM runs WHERE id=?', (job_id,))
            need(row is not None and row['state'] in ('QA_REQUIRED', 'VERIFIED'), 'PROJECT_RUN_NOT_ELIGIBLE')
            need(connection.execute('SELECT COUNT(*) FROM acceptances WHERE run=?', (job_id,)).fetchone()[0] == 0,
                 'HUMAN_ACCEPTANCE_MUST_REMAIN_ABSENT')
            events = connection.execute("SELECT COUNT(*) FROM events WHERE object_id=? AND action='project_technical_verified'",
                                        (job_id,)).fetchone()[0]
            exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
            proofs = connection.execute('SELECT COUNT(*) FROM technical_verifications WHERE run=?', (job_id,)).fetchone()[0] if exists else 0
            return row, events, proofs

    def retained(row):
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
            checked = gate.checked_project_release(connection, root, row)
        proof = checked['proof']
        need(sha(checked['package']) == policy.binding['package_sha256']
             and proof['receipt_sha256'] == receipt_hashes
             and proof.get('verification_profile_sha256') == policy.sha256
             and proof.get('allocation_receipt_sha256') == policy.binding['allocation_receipt_sha256']
             and proof.get('human_acceptance_recorded') is False, 'RETAINED_PROJECT_PROOF_DIFFERS')
        existing = gate.verify_existing_project_run(root=root, run_id=job_id)
        need(existing['state'] == 'VERIFIED', 'RETAINED_PROJECT_STATE_DIFFERS')
        return existing['proof_sha256']

    row, events, proofs = state()
    material = gate._material(root, job_id)
    gate._row_binding(row, material, root)
    need(row['source_hash'] == policy.binding['source_manifest_sha256']
         and sha(material['package']) == policy.binding['package_sha256'], 'RETAINED_PROJECT_BINDING_DIFFERS')
    if row['state'] == 'VERIFIED':
        need(events == proofs == 1, 'EXISTING_PROJECT_DECISION_INCONSISTENT')
        proof_sha = retained(row)
        return {'status': 'VERIFIED', 'job_id': job_id, 'state': 'VERIFIED', 'idempotent': True,
                'read_only': True, 'human_acceptance_recorded': False, 'event_count': events,
                'proof_count': proofs, 'proof_sha256': proof_sha}
    need(events == proofs == 0, 'UNEXPECTED_PROJECT_DECISION_EXISTS')
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        gate._selection(connection, row, material['objects']['source_snapshot'])
    current = now or datetime.now(timezone.utc)
    need(isinstance(current, datetime) and current.tzinfo is not None, 'PROJECT_DECISION_TIME_INVALID')
    receipt_raws = [receipts[name] for name in gate.RECEIPT_NAMES]
    attempt_path = material['job'] / gate._RETAINED / 'attempt.json'
    resume = attempt_path.exists() or attempt_path.is_symlink()
    decision_time = current
    if resume:
        saved = native._private(attempt_path.parent, directory=True)
        need(native._read(native._private(saved / 'verification-profile.json'), 16_384) == policy.raw
             and native._read(native._private(saved / 'allocation-receipt.json'), 16_384) == allocation_raw,
             'DURABLE_PROJECT_PROFILE_OR_ALLOCATION_DIFFERS')
        attempt = native._json(native._read(native._private(attempt_path)))
        identity = gate._attempt_identity(job_id, material, policy, allocation_raw, receipt_raws, row['created'])
        need(set(attempt) == set(identity) | {'verified_at_utc'}
             and gate._raw({key: attempt[key] for key in identity}) == gate._raw(identity),
             'DURABLE_PROJECT_ATTEMPT_IDENTITY_DIFFERS')
        decision_time = datetime.fromtimestamp(native._time(attempt['verified_at_utc']), timezone.utc)
        need(decision_time.timestamp() <= current.timestamp() + 300, 'DURABLE_PROJECT_ATTEMPT_TIME_INVALID')
        gate._verify(**gate._arguments(material, receipt_raws, policy, allocation_raw, decision_time, row['created']),
                     _historical=True)
    else:
        policy = BoundVerificationPolicy(policy.raw)
        gate.verify_project_detached_proof(**gate._arguments(material, receipt_raws, policy, allocation_raw,
                                                           decision_time, row['created']))
    if value['command'] == 'check':
        return {'status': 'READY_NOT_APPLIED', 'job_id': job_id, 'state': 'QA_REQUIRED', 'read_only': True,
                'resume_retained_attempt': resume, 'event_count': 0, 'proof_count': 0,
                'human_acceptance_recorded': False}
    identity = sha(json.dumps(value['receipt_sha256'], sort_keys=True, separators=(',', ':')).encode())
    operator = Path(operator_root) / ('fox-project-promotion-v1-' + identity)
    need(operator.absolute() == operator and root != operator and root not in operator.parents,
         'PRIVATE_RECEIPTS_MUST_REMAIN_OUTSIDE_FOX_DATA')
    if operator.exists() or operator.is_symlink():
        native._private(operator, directory=True)
        need({path.name for path in operator.iterdir()} <= names, 'PRIVATE_PROJECT_RECEIPT_MEMBERS_DIFFER')
    else:
        operator.mkdir(mode=0o700)
        native._private(operator, directory=True)
    for name, raw in receipts.items():
        native._save_once(operator / name, raw)
    # No subprocess or reimport: this gate and its entire FOX import closure
    # have already been loaded from the exact reviewed, checked source bytes.
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        result = gate.promote_project_run(root=root, run_id=job_id, operator_receipt_dir=operator,
                                          policy=policy, now=current)
    need(result.get('id') == job_id and result.get('state') == 'VERIFIED', 'PROJECT_GATE_OUTCOME_UNCONFIRMED')
    after, events, proofs = state()
    need(after['state'] == 'VERIFIED' and events == proofs == 1, 'PROJECT_TECHNICAL_POSTCHECK_FAILED')
    proof_sha = retained(after)
    need(proof_sha == result.get('proof_sha256'), 'PROJECT_POSTCHECK_PROOF_DIFFERS')
    return {'status': 'VERIFIED', 'job_id': job_id, 'state': 'VERIFIED', 'idempotent': result['idempotent'],
            'read_only': False, 'event_count': events, 'proof_count': proofs, 'human_acceptance_recorded': False,
            'proof_sha256': proof_sha}


def container_source():
    return inspect.getsource(container_execute) + '\nMODULES = ' + repr(MODULES) + r'''
import hashlib,importlib.abc,importlib.util,json,os,sys,types
from pathlib import Path
try:
 value=json.loads(sys.stdin.buffer.read(16000001))
 if not (os.geteuid()==1000 and os.getegid()==1000 and type(value['module_sha256']) is dict
         and set(value['module_sha256'])==set(MODULES)):
  raise RuntimeError('PROJECT_DEPENDENCY_IDENTITIES_REQUIRED')
 checked={}
 for name in MODULES:
  path=Path('/app/fox')/name
  if not (path.resolve()==path and path.is_file() and not path.is_symlink()
          and path.stat().st_nlink==1 and 0<path.stat().st_size<=2000000):
   raise RuntimeError('DEPLOYED_PROJECT_MODULE_UNSAFE')
  raw=path.read_bytes()
  if not (0<len(raw)<=2000000 and hashlib.sha256(raw).hexdigest()==value['module_sha256'][name]):
   raise RuntimeError('DEPLOYED_PROJECT_MODULE_IDENTITY_DIFFERS')
  checked['fox.'+name[:-3]]=(str(path),raw)
 # Deny unchecked fox imports, including package initializers. Execute exactly
 # the checked snapshots rather than asking a loader to read the path again.
 class CheckedLoader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
  def find_spec(self,fullname,path=None,target=None):
   if fullname.startswith('fox.'):
    if fullname not in checked:raise ImportError('UNCHECKED_PROJECT_DEPENDENCY')
    return importlib.util.spec_from_loader(fullname,self)
  def create_module(self,spec):return None
  def exec_module(self,module):
   filename,raw=checked[module.__name__]
   module.__file__=filename
   exec(compile(raw,filename,'exec'),module.__dict__)
 for name in list(sys.modules):
  if name=='fox' or name.startswith('fox.'):del sys.modules[name]
 package=types.ModuleType('fox');package.__path__=[];sys.modules['fox']=package
 sys.meta_path.insert(0,CheckedLoader())
 from fox import project_verification_runtime as gate
 result=container_execute(value,gate)
except Exception:
 result={'status':'BLOCKED','code':'PROJECT_PROMOTION_GUARD_OR_GATE_FAILED_INSPECT_STATE','automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
'''


def host_source():
    # Keep the same fixed JSN host/container guard as the established operator;
    # only the embedded checked program and loader diagnostic name differ.
    from qa.operator import promote_native
    source = promote_native.host_source()
    old = repr(promote_native.container_source())
    require(source.count(old) == 1, 'NATIVE_HOST_TEMPLATE_CHANGED')
    return source.replace(old, repr(container_source())).replace('<native-v2-promotion>', '<project-v1-promotion>')


def dispatch(command, evidence_dir, **options):
    value = payload(command, evidence_dir, **options)
    encoded = json.dumps(value).encode() + b'\n'
    program = host_source()
    require(len(base64.b64encode(program.encode())) + 1 + len(encoded) <= transport.MAX_WIRE,
            'PROTECTED_PROJECT_REQUEST_TOO_LARGE')
    loader = "python3 -B -c 'import base64,sys;exec(base64.b64decode(sys.stdin.buffer.readline()))'"
    result = C.load_json(transport.execute_host(program, encoded, timeout=180, legacy_loader=loader))
    require(result.get('status') in ('READY_NOT_APPLIED', 'VERIFIED') and result.get('host_scope_verified') is True
            and result.get('expected_image') == value['expected_image']
            and result.get('module_sha256') == value['module_sha256']
            and result.get('job_id') == value['binding']['job_id']
            and result.get('human_acceptance_recorded') is False,
            'PROJECT_PROMOTION_BLOCKED_OR_UNCONFIRMED_NO_AUTOMATIC_RETRY')
    return result
