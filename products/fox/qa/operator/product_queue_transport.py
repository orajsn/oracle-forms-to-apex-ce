"""Protected, fixed-JSN queue bridge; no public endpoint or credential handling.

The current H image is deliberately not executable through this bridge. A new
reviewed deployment, matching clean-operator pins and enabled release manifest
are prerequisites for *every* operation, including status. Importing is inert.
Only claim responses contain a private claim token. Callers must journal those
privately and must never print raw transport results or retry uncertain writes.
"""
from __future__ import annotations

import base64
from datetime import datetime
import inspect
import json
from pathlib import Path, PurePosixPath
import re
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / 'fox'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import clean_install as clean
from qa.operator import contracts as C
from qa.operator import native_qa_dispatch as native_qa
from qa.operator import runtime_provider
from fox.verification_queue import Claim, VerificationBinding

H_FOX_IMAGE = 'sha256:d69b0e8a39dfe3fabf6c703dbd4ec42513e5a19bad75988096db3f22c7584bec'
SCOPE = 'fox-product-verifier-release-v1'
PROJECT_SCOPE = 'fox-product-verifier-release-v2'
HOSTED_SCOPE = 'fox-product-verifier-release-v3'
TARGET = dict(C.FIXED_TARGET)
MODULES = ('verification_queue.py', 'verification_runtime.py', 'native_verification.py',
           'native_verification_policy.py')
CODE = ('product_verifier.py', 'product_queue_transport.py', 'runtime_provider.py')
HOSTED_CODE = (*CODE, 'retirement_handoff.py', 'retirement_remote.py', 'preactivation_retirement.py',
               'hosted_service.py', 'failed_verification.py')
PROJECT_MODULES = ('intake.py', 'native_source.py', 'opaf.py', 'native_pipeline.py',
    'native_verification_policy.py', 'native_verification.py', 'native_qa_plan.py',
    'project_conversion.py', 'project_qa_plan.py', 'project_progress.py',
    'native_project_pipeline.py', 'source_history.py', 'project_verification.py',
    'project_verification_runtime.py')
PROJECT_QUEUE_MODULES = ('technical_release.py', 'verification_recovery.py')
PROJECT_HASHES = ('clean_operator_code_sha256', 'qa_source_sha256',
                  'promotion_transport_sha256', 'operator_code_sha256')
ATTENTION = frozenset({'BACKEND_OUTCOME_UNCONFIRMED', 'PROOF_UNCONFIRMED', 'INTERRUPTED_OUTCOME'})
OPERATIONS = frozenset({'heartbeat', 'claim', 'status', 'attention', 'complete', 'reconcile'})
BINDING_KEYS = ('job_id', 'source_manifest_sha256', 'package_sha256', 'verifier_release_sha256')
QUEUE_KEYS = (*BINDING_KEYS, 'state', 'proof_sha256', 'attention_code', 'created_at_utc', 'updated_at_utc')


class QueueTransportError(RuntimeError):
    """Fixed diagnostics only; captured remote output never becomes a message."""


def _require(ok, code):
    if not ok:
        raise QueueTransportError(code)


def _sha(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def _profile_reference(value, *, with_host_path=False):
    fields = {'path', 'sha256', 'target_profile_sha256'} | ({'host_path'} if with_host_path else set())
    _require(type(value) is dict and set(value) == fields
             and type(value['path']) is str
             and re.fullmatch(r'deployment/[a-z0-9][a-z0-9-]{0,63}\.json', value['path'])
             and _sha(value['sha256']) and _sha(value['target_profile_sha256']),
             'REVIEWED_OPAF_PROFILE_REFERENCE_INVALID')
    if with_host_path:
        host = value['host_path']
        _require(type(host) is str and len(host) <= 1024 and '\\' not in host and '\x00' not in host,
                 'REVIEWED_OPAF_PROFILE_HOST_PATH_INVALID')
        parsed = PurePosixPath(host)
        _require(parsed.is_absolute() and str(parsed) == host and '..' not in parsed.parts
                 and host.endswith('/' + value['path']), 'REVIEWED_OPAF_PROFILE_HOST_PATH_INVALID')
    return dict(value)


def validate_release(manifest):
    """Pure exact-field validation; this grants neither readiness nor execution."""
    fields = {'schema_version', 'scope', 'enabled', 'images', 'modules', 'code',
              'clean_operator_code_sha256', 'qa_source_sha256', 'promotion_transport_sha256',
              'native_profile_sha256', 'target'}
    _require(type(manifest) is dict, 'RELEASE_FIELDS_INVALID')
    version = manifest.get('schema_version')
    _require(type(version) is int and version in (1, 2, 3)
             and manifest.get('scope') == {1: SCOPE, 2: PROJECT_SCOPE, 3: HOSTED_SCOPE}.get(version)
             and type(manifest.get('enabled')) is bool, 'RELEASE_HEADER_INVALID')
    extra = {'project'} if version in (2, 3) else set()
    if version == 3:
        extra |= {'hosted_runtime_configuration_sha256', 'opaf_profile'}
    _require(set(manifest) == fields | extra, 'RELEASE_FIELDS_INVALID')
    _require(type(manifest['images']) is dict and set(manifest['images']) == {'fox', 'converter'}
             and all(type(v) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', v)
                     for v in manifest['images'].values()), 'RELEASE_IMAGES_INVALID')
    for name, keys in (('modules', MODULES), ('code', HOSTED_CODE if version == 3 else CODE)):
        _require(type(manifest[name]) is dict and set(manifest[name]) == set(keys)
                 and all(_sha(v) for v in manifest[name].values()), 'RELEASE_CODE_FIELDS_INVALID')
    _require(all(_sha(manifest[key]) for key in ('clean_operator_code_sha256', 'qa_source_sha256',
                                               'promotion_transport_sha256', 'native_profile_sha256')),
             'RELEASE_DIGEST_INVALID')
    _require(type(manifest['target']) is dict and manifest['target'] == TARGET, 'EXACT_JSN_TARGET_REQUIRED')
    result = {**manifest, **{key: dict(manifest[key]) for key in ('images', 'modules', 'code', 'target')}}
    if version == 3:
        result['opaf_profile'] = _profile_reference(manifest['opaf_profile'], with_host_path=True)
        _require(_sha(manifest['hosted_runtime_configuration_sha256'])
                 and result['opaf_profile']['sha256'] == manifest['native_profile_sha256'],
                 'HOSTED_RELEASE_BINDING_INVALID')
    if version in (2, 3):
        project = manifest['project']
        _require(type(project) is dict and set(project) == set(PROJECT_HASHES) | {'modules', 'queue_modules'}
                 and all(_sha(project[key]) for key in PROJECT_HASHES), 'PROJECT_RELEASE_FIELDS_INVALID')
        for name, keys in (('modules', PROJECT_MODULES), ('queue_modules', PROJECT_QUEUE_MODULES)):
            _require(type(project[name]) is dict and set(project[name]) == set(keys)
                     and all(_sha(value) for value in project[name].values()), 'PROJECT_RELEASE_MODULES_INVALID')
        _require(all(project['modules'][key] == manifest['modules'][key]
                     for key in set(PROJECT_MODULES) & set(MODULES)), 'PROJECT_RELEASE_SHARED_MODULE_DIFFERS')
        result['project'] = {**project, 'modules': dict(project['modules']), 'queue_modules': dict(project['queue_modules'])}
    return result


def release_sha256(manifest):
    return C.digest(C.canonical_bytes(validate_release(manifest)))


def _file_sha(path):
    _require(path.is_file() and not path.is_symlink() and path.resolve() == path
             and 0 < path.stat().st_size <= 2_000_000, 'RELEASE_LOCAL_FILE_UNSAFE')
    raw = path.read_bytes()
    _require(0 < len(raw) <= 2_000_000, 'RELEASE_LOCAL_FILE_UNSAFE')
    return C.digest(raw)


def project_manifest(*, images=None):
    """Local source declaration only; does not enable or deploy anything."""
    from qa.operator import project_clean_install, project_qa_dispatch, promote_project
    _require(tuple(promote_project.MODULES) == PROJECT_MODULES, 'PROJECT_PROMOTION_CLOSURE_CHANGED')
    return {'clean_operator_code_sha256': project_clean_install.code_bundle()[1],
            'qa_source_sha256': (project_qa_dispatch.bundle() if images is None
                                 else project_qa_dispatch.bundle(images=images))[3],
            'promotion_transport_sha256': _file_sha(Path(__file__).with_name('promote_project.py')),
            'operator_code_sha256': _file_sha(Path(__file__).with_name('project_operator.py')),
            'modules': promote_project.module_hashes(),
            'queue_modules': {name: _file_sha(ROOT / 'fox/fox' / name) for name in PROJECT_QUEUE_MODULES}}


def reviewed_profile(reference, configuration, *, with_host_path=False):
    """Bind reviewed role bytes to the exact configured target, offline only."""
    reference = _profile_reference(reference, with_host_path=with_host_path)
    _require(type(configuration) is dict and configuration.get('schema_version') == 2
             and reference['target_profile_sha256'] == configuration['target_profile_sha256'],
             'HOSTED_PROFILE_TARGET_DIFFERS')
    root = PurePosixPath(configuration['converter_root'])
    _require(root.is_absolute() and str(root) == configuration['converter_root']
             and '..' not in root.parts and root.name == 'converter', 'HOSTED_RELEASE_LAYOUT_INVALID')
    host_path = str(root.parent / reference['path'])
    _require(not with_host_path or reference['host_path'] == host_path, 'HOSTED_PROFILE_HOST_PATH_DIFFERS')
    path = ROOT / reference['path']
    _require(_file_sha(path) == reference['sha256'], 'NATIVE_PROFILE_SOURCE_CHANGED')
    profile = C.load_json(path.read_bytes())
    target = configuration['target_profile']
    opaf = target['opaf']
    expected = {'schema_version': 1, 'profile_id': 'native-table-form-v1',
        'opaf_base_url': opaf['base_url'], 'certificate_sha256': opaf['certificate_sha256'],
        'mapper': dict(opaf['roles']['mapper']), 'reviewer': dict(opaf['roles']['reviewer'])}
    if 'project_mapping' in target['scope']:
        expected.update(schema_version=2, profile_id='native-project-v1', **target['scope']['project_mapping'])
    _require(type(profile) is dict and C.canonical_bytes(profile) == C.canonical_bytes(expected)
             and _file_sha(path) == reference['sha256'], 'HOSTED_PROFILE_TARGET_DIFFERS')
    return {**reference, 'host_path': host_path}


def require_ready(manifest, expected_sha):
    """Offline guard; disabled/H releases fail before OCI, SSH or subprocess."""
    checked = validate_release(manifest)
    _require(checked['enabled'], 'VERIFIER_RELEASE_DISABLED')
    _require(checked['images']['fox'] != H_FOX_IMAGE, 'LIVE_H_QUEUE_UNAVAILABLE')
    _require(_sha(expected_sha) and release_sha256(checked) == expected_sha, 'EXACT_VERIFIER_RELEASE_REQUIRED')
    provider = runtime_provider.hosted()
    if checked['schema_version'] == 3:
        _require(provider is not None and provider.configuration['schema_version'] == 2
                 and provider.sha256 == checked['hosted_runtime_configuration_sha256'],
                 'HOSTED_RELEASE_CONFIGURATION_REQUIRED')
        reviewed_profile(checked['opaf_profile'], provider.configuration, with_host_path=True)
    else:
        _require(provider is None or provider.configuration['schema_version'] == 1,
                 'HOSTED_VERSIONED_RELEASE_REQUIRED')
    _require(checked['images'] == clean.image_pins(),
             'CLEAN_DEPLOYMENT_PINS_DIFFER')
    _require(checked['modules'] == {name: _file_sha(ROOT / 'fox/fox' / name) for name in MODULES},
             'VERIFIER_INSTALLED_SOURCE_CHANGED')
    code_names = HOSTED_CODE if checked['schema_version'] == 3 else CODE
    _require(checked['code'] == {name: _file_sha(Path(__file__).parent / name) for name in code_names},
             'VERIFIER_ADAPTER_SOURCE_CHANGED')
    _require(checked['clean_operator_code_sha256'] == clean.code_bundle()[1], 'CLEAN_OPERATOR_SOURCE_CHANGED')
    _require(checked['qa_source_sha256'] == native_qa.bundle()[3], 'NATIVE_QA_SOURCE_CHANGED')
    _require(checked['promotion_transport_sha256'] == _file_sha(Path(__file__).with_name('promote_native.py')),
             'PROMOTION_TRANSPORT_SOURCE_CHANGED')
    profile_path = checked['opaf_profile']['path'] if checked['schema_version'] == 3 else 'deployment/native-beta-profile.json'
    _require(checked['native_profile_sha256'] == _file_sha(ROOT / profile_path),
             'NATIVE_PROFILE_SOURCE_CHANGED')
    if checked['schema_version'] in (2, 3):
        from qa.operator import project_clean_install
        _require(project_clean_install.image_pins() == checked['images'], 'PROJECT_DEPLOYMENT_PINS_DIFFER')
        _require(checked['project'] == project_manifest(), 'PROJECT_RELEASE_SOURCE_CHANGED')
    return checked


def _binding(value, release):
    _require(type(value) is dict and set(value) == set(BINDING_KEYS), 'QUEUE_REQUEST_BINDING_INVALID')
    _require(type(value['job_id']) is str and re.fullmatch(r'fox-[a-f0-9]{20}', value['job_id'])
             and all(_sha(value[key]) for key in BINDING_KEYS[1:])
             and value['verifier_release_sha256'] == release, 'QUEUE_REQUEST_BINDING_INVALID')
    return dict(value)


def _validate_request(value, *, release_validator=validate_release):
    _require(type(value) is dict and set(value) == {'operation', 'apply', 'manifest', 'release_sha256',
                                                  'binding', 'claim', 'code', 'proof_sha256'},
             'QUEUE_REQUEST_FIELDS_INVALID')
    op = value['operation']
    _require(type(op) is str and op in OPERATIONS and type(value['apply']) is bool
             and value['apply'] is (op != 'status'), 'EXPLICIT_QUEUE_ACTION_REQUIRED')
    manifest = release_validator(value['manifest'])
    # Canonical encoding exactly matches contracts.canonical_bytes, without
    # importing workstation modules in the protected FOX interpreter.
    import hashlib
    raw = (json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False) + '\n').encode('utf-8')
    release = value['release_sha256']
    _require(manifest['enabled'] and manifest['images']['fox'] != H_FOX_IMAGE
             and _sha(release) and hashlib.sha256(raw).hexdigest() == release,
             'QUEUE_REQUEST_RELEASE_INVALID')
    bound, claim, code, proof = (value[key] for key in ('binding', 'claim', 'code', 'proof_sha256'))
    if op in {'heartbeat', 'claim'}:
        _require(bound is claim is code is proof is None, 'QUEUE_REQUEST_ARGUMENTS_INVALID')
    else:
        _binding(bound, release)
        if claim is not None:
            _require(type(claim) is dict and set(claim) == {'binding', 'attempt_token'}
                     and type(claim['attempt_token']) is str
                     and re.fullmatch(r'[a-f0-9]{32}', claim['attempt_token'])
                     and _binding(claim['binding'], release) == bound, 'QUEUE_REQUEST_CLAIM_INVALID')
        _require((claim is not None if op in {'attention', 'complete'} else True)
                 and (claim is None if op == 'status' else True), 'QUEUE_REQUEST_CLAIM_REQUIRED')
        _require((type(code) is str and code in ATTENTION) if op == 'attention' else code is None,
                 'QUEUE_REQUEST_ATTENTION_INVALID')
        _require(_sha(proof) if op == 'complete' else (proof is None or (op == 'reconcile' and _sha(proof))),
                 'QUEUE_REQUEST_PROOF_INVALID')
    return value


def _queue_projection(value, release, binding=None):
    """Drop unknown fields, then validate every returned public value."""
    if value is None:
        return None
    _require(type(value) is dict and set(QUEUE_KEYS) <= set(value), 'QUEUE_RESPONSE_INVALID')
    projected = {key: value[key] for key in QUEUE_KEYS}
    bound = _binding({key: projected[key] for key in BINDING_KEYS}, release)
    _require(binding is None or bound == binding, 'QUEUE_RESPONSE_BINDING_CHANGED')
    state, proof, code = (projected[key] for key in ('state', 'proof_sha256', 'attention_code'))
    _require(type(state) is str and state in {'queued', 'running', 'attention', 'completed'}, 'QUEUE_RESPONSE_INVALID')
    _require((state in {'queued', 'running'} and proof is code is None)
             or (state == 'attention' and proof is None and type(code) is str and code in ATTENTION)
             or (state == 'completed' and _sha(proof) and code is None), 'QUEUE_RESPONSE_INVALID')
    for key in ('created_at_utc', 'updated_at_utc'):
        at = projected[key]
        _require(type(at) is str and re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)', at),
            'QUEUE_RESPONSE_INVALID')
        try:
            datetime.fromisoformat(at.replace('Z', '+00:00'))
        except ValueError:
            raise QueueTransportError('QUEUE_RESPONSE_INVALID') from None
    return projected


def _project_result(value, request):
    _require(type(value) is dict, 'QUEUE_RESPONSE_INVALID')
    release, op = request['release_sha256'], request['operation']
    _require(value.get('verifier_release_sha256') == release, 'QUEUE_RESPONSE_RELEASE_CHANGED')
    status = value.get('status')
    allowed = {'heartbeat': {'CONTACT_RECORDED'}, 'claim': {'CLAIMED', 'IDLE'}, 'status': {'STATUS'},
               'attention': {'ATTENTION'}, 'complete': {'COMPLETED'}, 'reconcile': {'COMPLETED'}}
    _require(type(status) is str and status in allowed[op], 'QUEUE_OPERATION_UNCONFIRMED_NO_REPLAY')
    result = {'status': status, 'verifier_release_sha256': release, 'automatic_replay_permitted': False}
    if status == 'CLAIMED':
        claim = value.get('claim')
        _require(type(claim) is dict and set(claim) == {'binding', 'attempt_token'}
                 and type(claim['attempt_token']) is str and re.fullmatch(r'[a-f0-9]{32}', claim['attempt_token']),
                 'QUEUE_RESPONSE_CLAIM_INVALID')
        result['claim'] = {'binding': _binding(claim['binding'], release), 'attempt_token': claim['attempt_token']}
    elif status in {'STATUS', 'ATTENTION', 'COMPLETED'}:
        _require('queue' in value, 'QUEUE_RESPONSE_INVALID')
        row = _queue_projection(value['queue'], release, request['binding'])
        _require(status == 'STATUS' or (row is not None and row['state'] ==
                 ('attention' if status == 'ATTENTION' else 'completed')), 'QUEUE_RESPONSE_INVALID')
        if status == 'COMPLETED' and request['proof_sha256'] is not None:
            _require(row['proof_sha256'] == request['proof_sha256'], 'QUEUE_RESPONSE_PROOF_CHANGED')
        result['queue'] = row
    return result


def _checked_retained_proof(root, bound, verification_module):
    """Read the profile dispatcher and stored decision without current policy."""
    import hashlib
    import sqlite3
    from contextlib import closing
    database = root / 'fox.sqlite3'
    _require(database.is_file() and not database.is_symlink() and database.resolve() == database,
             'RETAINED_DATABASE_UNSAFE')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=30)) as db:
        db.row_factory = sqlite3.Row
        row = db.execute('SELECT * FROM runs WHERE id=?', (bound.job_id,)).fetchone()
        _require(row is not None, 'RETAINED_RUN_UNAVAILABLE')
        run = dict(row)
        _require(run.get('state') in {'VERIFIED', 'ACCEPTED'}
                 and run.get('source_hash') == bound.source_manifest_sha256
                 and run.get('artifact') == str(Path('jobs') / bound.job_id / 'apex-package.zip'),
                 'RETAINED_RUN_BINDING_CHANGED')
        checked = verification_module.checked_release(db, root, run)
        stored = db.execute('SELECT proof_sha256,artifact_sha256 FROM technical_verifications WHERE run=?',
                            (bound.job_id,)).fetchone()
        _require(type(checked) is dict and set(checked) == {'proof', 'package'}
                 and type(checked['package']) is bytes and type(checked['proof']) is dict
                 and stored is not None and _sha(stored['proof_sha256'])
                 and stored['artifact_sha256'] == bound.package_sha256
                 and hashlib.sha256(checked['package']).hexdigest() == bound.package_sha256
                 and all(checked['proof'].get(key) == value for key, value in {
                     'job_id': bound.job_id, 'source_manifest_sha256': bound.source_manifest_sha256,
                     'package_sha256': bound.package_sha256}.items())
                 and checked['proof'].get('human_acceptance_recorded') is False,
                 'RETAINED_TECHNICAL_PROOF_REQUIRED')
        return {'id': bound.job_id, 'state': run['state'], 'read_only': True, 'idempotent': True,
                'active_policy_applied': False, 'proof_sha256': stored['proof_sha256']}


def container_execute(value, queue_module, verification_module, runtime_module, *, root=None,
                      request_validator=_validate_request):
    """Fixed dispatch in production; injectable modules/root only for offline tests."""
    # This is FOX container data, not the installed operator's private state.
    root = Path('/data') if root is None else root
    request = request_validator(value)
    release, op = request['release_sha256'], request['operation']
    queue = queue_module.VerificationQueue(root / 'fox.sqlite3', enabled=True, verifier_release_sha256=release)
    bound = queue_module.VerificationBinding.from_payload(request['binding']) if request['binding'] else None
    claim = (queue_module.Claim(bound, request['claim']['attempt_token']) if request['claim'] else None)
    result = {'verifier_release_sha256': release}
    if op == 'heartbeat':
        runtime_module.operator_heartbeat(root, release)
        result['status'] = 'CONTACT_RECORDED'
    elif op == 'claim':
        claimed = queue.claim_next()
        result['status'] = 'IDLE' if claimed is None else 'CLAIMED'
        if claimed is not None:
            result['claim'] = {'binding': claimed.binding.payload(), 'attempt_token': claimed.attempt_token}
    elif op == 'status':
        result.update(status='STATUS', queue=queue.get(bound.job_id))
    elif op == 'attention':
        result.update(status='ATTENTION', queue=queue.attention(claim, request['code']))
    elif op == 'complete':
        proof = queue_module.TechnicalProofResult(request['proof_sha256'])
        result.update(status='COMPLETED', queue=queue.complete(claim, proof))
    else:
        row = _queue_projection(queue.get(bound.job_id), release, bound.payload())
        _require(row is not None and row['state'] in {'attention', 'running', 'completed'},
                 'QUEUE_RECONCILIATION_STATE_INVALID')
        _require(row['state'] == 'attention' or claim is not None, 'RETAINED_PRIVATE_CLAIM_REQUIRED')
        checked = (_checked_retained_proof(root, bound, verification_module) if request['manifest']['schema_version'] in (2, 3, 4)
                   else verification_module.verify_existing_native_run(root=root, run_id=bound.job_id))
        _require(type(checked) is dict and checked.get('id') == bound.job_id
                 and checked.get('state') in {'VERIFIED', 'ACCEPTED'}
                 and checked.get('read_only') is True and checked.get('idempotent') is True
                 and checked.get('active_policy_applied') is False and _sha(checked.get('proof_sha256')),
                 'RETAINED_TECHNICAL_PROOF_REQUIRED')
        _require(request['proof_sha256'] is None or request['proof_sha256'] == checked['proof_sha256'],
                 'RETAINED_TECHNICAL_PROOF_CHANGED')
        proof = queue_module.TechnicalProofResult(checked['proof_sha256'])
        completed = (queue.reconcile_completed(bound, proof) if row['state'] == 'attention'
                     else queue.complete(claim, proof))
        result.update(status='COMPLETED', queue=completed)
    return _project_result(result, request)


def _helper_source():
    constants = {'H_FOX_IMAGE': H_FOX_IMAGE, 'SCOPE': SCOPE, 'PROJECT_SCOPE': PROJECT_SCOPE,
                 'HOSTED_SCOPE': HOSTED_SCOPE, 'HOSTED_CODE': HOSTED_CODE,
                 'PROJECT_MODULES': PROJECT_MODULES, 'PROJECT_QUEUE_MODULES': PROJECT_QUEUE_MODULES,
                 'PROJECT_HASHES': PROJECT_HASHES, 'TARGET': TARGET, 'MODULES': MODULES,
                 'CODE': CODE, 'ATTENTION': ATTENTION, 'OPERATIONS': OPERATIONS,
                 'BINDING_KEYS': BINDING_KEYS, 'QUEUE_KEYS': QUEUE_KEYS}
    header = ('import json,re\nfrom pathlib import Path,PurePosixPath\nfrom datetime import datetime\n'
              + '\n'.join(name + '=' + repr(value) for name, value in constants.items()) + '\n')
    return header + '\n'.join(inspect.getsource(item) for item in
        (QueueTransportError, _require, _sha, _profile_reference, validate_release, _binding, _validate_request,
         _queue_projection, _project_result, _checked_retained_proof, container_execute))


def container_source():
    return _helper_source() + r'''
import hashlib,io,os,sys,types
from contextlib import redirect_stdout,redirect_stderr
try:
 raw=sys.stdin.buffer.read(65537)
 _require(0<len(raw)<=65536,'QUEUE_REQUEST_TOO_LARGE')
 request=_validate_request(json.loads(raw))
 _require(os.geteuid()==1000 and os.getegid()==1000,'FOX_EFFECTIVE_USER_INVALID')
 _require(os.environ.get('FOX_VERIFICATION_ENABLED')=='1'
  and os.environ.get('FOX_VERIFIER_RELEASE_SHA256')==request['release_sha256'],'FOX_QUEUE_CONFIG_MISMATCH')
 # A single-file bind can retain an old inode after replacement on the
 # host. Check the actual mounted bytes as well as the guarded host source.
 profile=Path('/run/fox-native/profile.json')
 _require(profile.is_file() and not profile.is_symlink() and profile.resolve(strict=True)==profile
  and 0<profile.stat().st_size<=65536,'FOX_NATIVE_PROFILE_UNSAFE')
 with profile.open('rb') as stream:profile_raw=stream.read(65537)
 _require(0<len(profile_raw)<=65536 and hashlib.sha256(profile_raw).hexdigest()==request['manifest']['native_profile_sha256'],
  'FOX_NATIVE_PROFILE_CHANGED')
 sources={}
 expected=dict(request['manifest']['modules'])
 if request['manifest']['schema_version'] in (2,3):
  expected.update(request['manifest']['project']['modules'])
  expected.update(request['manifest']['project']['queue_modules'])
 for filename in expected:
  path=Path('/app/fox')/filename
  _require(path.resolve()==path and path.is_file() and not path.is_symlink()
   and 0<path.stat().st_size<=2000000,'FOX_INSTALLED_MODULE_UNSAFE')
  with path.open('rb') as stream:source=stream.read(2000001)
  _require(0<len(source)<=2000000 and hashlib.sha256(source).hexdigest()==expected[filename],
   'FOX_INSTALLED_MODULE_CHANGED')
  sources[filename]=source
 # Compile the checked bytes, bypassing package initializers and .pyc for
 # the four attested modules. Other dependencies belong to the pinned image.
 sys.dont_write_bytecode=True
 sys.path.insert(0,'/app')
 if request['manifest']['schema_version'] in (2,3):
  for name in tuple(sys.modules):
   if name=='fox' or name.startswith('fox.'):del sys.modules[name]
 package=types.ModuleType('fox');package.__path__=['/app/fox'];sys.modules['fox']=package
 with redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
  if request['manifest']['schema_version'] in (2,3):
   import importlib.abc,importlib.util,importlib
   class CheckedFinder(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def find_spec(self,fullname,path=None,target=None):
     if not fullname.startswith('fox.'):return None
     _require(fullname.count('.')==1 and fullname[4:]+'.py' in sources,'FOX_UNBOUND_DEPENDENCY')
     return importlib.util.spec_from_loader(fullname,self)
    def create_module(self,spec):return None
    def exec_module(self,module):
     filename=module.__name__[4:]+'.py';module.__file__='/app/fox/'+filename
     exec(compile(sources[filename],module.__file__,'exec'),module.__dict__)
   finder=CheckedFinder();sys.meta_path.insert(0,finder)
   try:
    for name in ('verification_queue','verification_runtime','technical_release'):importlib.import_module('fox.'+name)
    result=container_execute(request,sys.modules['fox.verification_queue'],sys.modules['fox.technical_release'],
     sys.modules['fox.verification_runtime'])
   finally:sys.meta_path.remove(finder)
  else:
   for filename in ('native_verification_policy.py','verification_queue.py','native_verification.py','verification_runtime.py'):
    name='fox.'+filename[:-3];module=types.ModuleType(name);module.__package__='fox';module.__file__='/app/fox/'+filename
    sys.modules[name]=module
    exec(compile(sources[filename],module.__file__,'exec'),module.__dict__)
   result=container_execute(request,sys.modules['fox.verification_queue'],sys.modules['fox.native_verification'],
    sys.modules['fox.verification_runtime'])
except Exception:
 result={'status':'STOPPED','code':'QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY','automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
'''


def host_source():
    body = clean.HOST_PREFIX + r'''
v=p['request'];guard(v['manifest']['images']['fox']!=''' + repr(H_FOX_IMAGE) + r''')
profile_source=(v['manifest']['opaf_profile']['host_path'] if v['manifest']['schema_version']==3
 else '/home/opc/fox/releases/native-beta-20261017h/deployment/native-beta-profile.json')
r=subprocess.run(['podman','inspect','fox'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
guard(r.returncode==0 and not r.stderr.strip() and len(r.stdout)<=1000000)
inspected=json.loads(r.stdout);guard(type(inspected) is list and len(inspected)==1)
fox=inspected[0];container=fox['Id']
guard(isinstance(container,str) and re.fullmatch(r'[a-f0-9]{64}',container))
actual=fox['Image'];guard(isinstance(actual,str) and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}',actual))
guard(fox['State']['Running'] is True and (actual[7:] if actual.startswith('sha256:') else actual)==v['manifest']['images']['fox'][7:]
 and fox['Config']['User']=='1000:1000' and not fox['HostConfig'].get('UsernsMode')
 and fox['HostConfig'].get('ReadonlyRootfs') is True)
mounts=fox['Mounts'];guard(type(mounts) is list)
seen=set()
for mount in mounts:
 dest=mount['Destination']
 guard(isinstance(dest,str) and dest not in seen);seen.add(dest)
 guard((dest=='/data' and mount['Type']=='bind' and mount['Source']=='/home/opc/fox/data' and mount['RW'] is True)
  or (dest=='/run/fox-opaf' and mount['Type']=='bind' and mount['Source']=='/home/opc/fox/secure/opaf-client' and mount['RW'] is False)
  or (dest=='/run/fox-native/profile.json' and mount['Type']=='bind'
   and mount['Source']==profile_source and mount['RW'] is False)
  or (dest=='/tmp' and mount['Type']=='tmpfs'))
guard({'/data','/run/fox-native/profile.json'}<=seen)
from pathlib import Path
native_profile=Path(profile_source)
guard(native_profile.is_file() and not native_profile.is_symlink() and native_profile.resolve(strict=True)==native_profile
 and 0<native_profile.stat().st_size<=65536)
with native_profile.open('rb') as stream:native_profile_raw=stream.read(65537)
guard(0<len(native_profile_raw)<=65536 and hashlib.sha256(native_profile_raw).hexdigest()==v['manifest']['native_profile_sha256'])
tmpfs=fox['HostConfig'].get('Tmpfs',{});guard(type(tmpfs) is dict and set(tmpfs)<= {'/tmp'})
environment=fox['Config']['Env'];guard(type(environment) is list)
guard(not any(x.split('=',1)[0].startswith('LD_') for x in environment))
code=''' + repr(container_source()) + r'''
loader='import base64,sys;exec(compile(base64.b64decode(sys.stdin.buffer.readline()),"<protected-queue>","exec"))'
framed=base64.b64encode(code.encode())+b'\n'+json.dumps(v).encode()+b'\n'
r=subprocess.run(['podman','exec','-i',container,'/usr/local/bin/python','-I','-B','-c',loader],input=framed,
 stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
guard(r.returncode==0 and not r.stderr.strip() and 0<len(r.stdout)<=65536)
result=json.loads(r.stdout);guard(type(result) is dict)
result.update(host_scope_verified=True,fox_image=v['manifest']['images']['fox'])
'''
    return ('import re,sys\nsys.dont_write_bytecode=True\ntry:\n' + textwrap.indent(body, ' ') + r'''
except Exception:
 result={'status':'STOPPED','code':'QUEUE_HOST_OUTCOME_UNCONFIRMED_NO_REPLAY','automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
''')


def dispatch(operation, manifest, *, expected_release_sha256, apply=False, claim=None, binding=None,
             code=None, proof_sha256=None):
    """One protected operation only. Never automatically replay an uncertain call."""
    checked = require_ready(manifest, expected_release_sha256)
    _require(claim is None or type(claim) is Claim, 'QUEUE_REQUEST_CLAIM_INVALID')
    _require(binding is None or type(binding) is VerificationBinding, 'QUEUE_REQUEST_BINDING_INVALID')
    if claim is not None:
        _require(binding is None or binding == claim.binding, 'QUEUE_REQUEST_BINDING_INVALID')
        binding = claim.binding
    value = _validate_request({'operation': operation, 'apply': apply, 'manifest': checked,
        'release_sha256': expected_release_sha256, 'binding': binding.payload() if binding else None,
        'claim': {'binding': claim.binding.payload(), 'attempt_token': claim.attempt_token} if claim else None,
        'code': code, 'proof_sha256': proof_sha256})
    try:
        scope = clean.oci_scope(require_database_available=False)
        result = clean.ssh_json(host_source(), {'cli_scope': scope, 'request': value})
        _require(type(result) is dict and result.get('host_scope_verified') is True
                 and result.get('fox_image') == checked['images']['fox'], 'QUEUE_HOST_ATTESTATION_UNCONFIRMED')
        return _project_result(result, value)
    except Exception:
        raise QueueTransportError('QUEUE_TRANSPORT_OUTCOME_UNCONFIRMED_NO_REPLAY') from None
