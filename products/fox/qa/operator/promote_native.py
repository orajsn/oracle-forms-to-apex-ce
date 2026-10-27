"""Per-job v2 technical promotion; prepare locally, dispatch only on approval.

check has no logical DB/app mutation, local output, receipt/proof copy or
bytecode. SQLite's normal read-only WAL/shared-memory bookkeeping can occur.
apply requires --apply and uses the deployed atomic gate, never acceptance.
Only six hash-bound non-secret collection files cross protected transport stdin.
No OCI CLI, database application, model, install, pull or deployment call exists.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / 'fox'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import clean_install as transport
from qa.operator import contracts as C
from fox.native_verification_policy import BoundVerificationPolicy, validate_allocation_receipt

FILES = {
    'verification-profile.json': 'verification-profile.json',
    'allocation-receipt.json': 'allocation-receipt.json',
    'clean-install.json': 'clean-import-receipt.json',
    'qa-result.json': 'qa-result.json',
    'qa-target.json': 'target-receipt.json',
    'qa-profile.json': 'qa-profile.json',
}
SHA = re.compile(r'[a-f0-9]{64}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_inputs(paths):
    """Read-only ownership/ACL checks, including the collection directory."""
    for path in paths:
        require(path.exists() and path.resolve() == path and not path.is_symlink(), 'PRIVATE_COLLECTION_PATH_UNSAFE')
    if os.name != 'nt':
        require(all(path.stat().st_uid == os.getuid() and not stat.S_IMODE(path.stat().st_mode) & 0o077
                    for path in paths), 'PRIVATE_COLLECTION_PERMISSIONS_REQUIRED')
        return
    program = r'''$ErrorActionPreference='Stop'; $v=([Console]::In.ReadToEnd()|ConvertFrom-Json)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach($p in $v.paths) {
 $acl=if([IO.Directory]::Exists($p)){[IO.Directory]::GetAccessControl($p)}else{[IO.File]::GetAccessControl($p)}
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid){throw 'Wrong owner'}
 foreach($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -ne $sid){throw 'Unexpected reader'}
 }
}
Write-Output 'PRIVATE_COLLECTION_VERIFIED'
'''
    output = transport.run_process(['powershell', '-NoProfile', '-Command', program],
        data=json.dumps({'paths': [str(path) for path in paths]}).encode(), timeout=30)
    require(output.strip() == b'PRIVATE_COLLECTION_VERIFIED', 'PRIVATE_COLLECTION_PERMISSIONS_REQUIRED')


def payload(command, evidence_dir, *, collection_sha256, expected_image, module_sha256, apply=False):
    require(command in ('check', 'apply') and apply is (command == 'apply'), 'EXPLICIT_ACTION_REQUIRED')
    require(isinstance(expected_image, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', expected_image)
            and isinstance(module_sha256, str) and SHA.fullmatch(module_sha256)
            and isinstance(collection_sha256, str) and SHA.fullmatch(collection_sha256),
            'EXACT_APPROVED_IMAGE_MODULE_AND_COLLECTION_HASHES_REQUIRED')
    directory = Path(evidence_dir).absolute()
    require(directory.parent.parent == transport.private_root(), 'EXACT_PRIVATE_COLLECTION_DIRECTORY_REQUIRED')
    paths = [directory, directory / 'collection-manifest.json', *[directory / name for name in FILES.values()]]
    private_inputs(paths)
    require(directory.is_dir() and all(path.is_file() for path in paths[1:]), 'COLLECTION_FILES_REQUIRED')
    require(paths[1].stat().st_size <= 65_536, 'COLLECTION_MANIFEST_TOO_LARGE')
    manifest_raw = paths[1].read_bytes()
    require(digest(manifest_raw) == collection_sha256, 'COLLECTION_MANIFEST_CHANGED')
    manifest = C.load_json(manifest_raw)
    source_sha = manifest.get('source_sha256')
    require(manifest.get('status') == 'COLLECTED' and manifest.get('credentials_and_logs_excluded') is True
            and isinstance(source_sha, str) and SHA.fullmatch(source_sha)
            and directory.parent.name == manifest.get('plan_sha256')
            and directory.name == 'qa-' + source_sha[:16], 'COLLECTION_IDENTITY_DIFFERS')
    receipts = {}
    for name, collected in FILES.items():
        path = directory / collected
        maximum = 16_384 if name in ('verification-profile.json', 'allocation-receipt.json') else 2_000_000
        require(0 < path.stat().st_size <= maximum, 'COLLECTED_RECEIPT_SIZE_INVALID')
        raw = path.read_bytes()
        require(0 < len(raw) <= maximum and digest(raw) == manifest.get('sha256', {}).get(collected), 'COLLECTED_RECEIPT_CHANGED')
        receipts[name] = raw
    policy = BoundVerificationPolicy(receipts['verification-profile.json'], historical=True)
    allocation = validate_allocation_receipt(receipts['allocation-receipt.json'], policy)
    require(allocation['plan_sha256'] == manifest['plan_sha256'], 'COLLECTION_ALLOCATION_PLAN_DIFFERS')
    return {'command': command, 'apply': apply, 'expected_image': expected_image, 'module_sha256': module_sha256,
            'collection_manifest_sha256': collection_sha256, 'binding': policy.binding,
            'receipt_sha256': {name: digest(raw) for name, raw in receipts.items()},
            'receipts': {name: base64.b64encode(raw).decode() for name, raw in receipts.items()}}


def container_execute(value, gate, root='/data', operator_root='/tmp', now=None):
    """Default roots are fixed by dispatch; injectable roots/clock are offline test seams."""
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

    need(value['command'] in ('check', 'apply') and value['apply'] is (value['command'] == 'apply'), 'EXPLICIT_ACTION_REQUIRED')
    receipts = {name: base64.b64decode(raw, validate=True) for name, raw in value['receipts'].items()}
    names = set(gate.RECEIPT_NAMES) | {'verification-profile.json', 'allocation-receipt.json'}
    need(set(receipts) == set(value['receipt_sha256']) == names
         and all(0 < len(raw) <= (16_384 if name in {'verification-profile.json', 'allocation-receipt.json'} else 2_000_000)
                 and sha(raw) == value['receipt_sha256'][name] for name, raw in receipts.items()), 'EXACT_RECEIPT_BYTES_REQUIRED')
    policy = BoundVerificationPolicy(receipts['verification-profile.json'], historical=True)
    validate_allocation_receipt(receipts['allocation-receipt.json'], policy)
    need(policy.binding == value['binding'], 'EXACT_PROFILE_BINDING_REQUIRED')
    job_id = policy.binding['job_id']
    root = gate._safe_path(Path(root))
    job = gate._safe_path(root / 'jobs' / job_id)
    database = gate._safe_path(root / 'fox.sqlite3')
    receipt_hashes = {name: value['receipt_sha256'][name] for name in gate.RECEIPT_NAMES}

    def state():
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
            connection.row_factory = sqlite3.Row
            need(connection.execute("SELECT COUNT(*) FROM runs WHERE state IN ('QUEUED','PROCESSING')").fetchone()[0] == 0,
                 'ACTIVE_FOX_JOB_PREVENTS_PROMOTION')
            row = connection.execute('SELECT * FROM runs WHERE id=?', (job_id,)).fetchone()
            need(row is not None and row['state'] in ('QA_REQUIRED', 'VERIFIED')
                 and row['source_hash'] == policy.binding['source_manifest_sha256']
                 and row['artifact'] == str((job / 'apex-package.zip').relative_to(root)), 'RETAINED_RUN_IDENTITY_DIFFERS')
            need(connection.execute('SELECT COUNT(*) FROM acceptances WHERE run=?', (job_id,)).fetchone()[0] == 0,
                 'HUMAN_ACCEPTANCE_MUST_REMAIN_ABSENT')
            events = connection.execute("SELECT COUNT(*) FROM events WHERE object_id=? AND action='native_technical_verified'", (job_id,)).fetchone()[0]
            exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
            proofs = connection.execute('SELECT COUNT(*) FROM technical_verifications WHERE run=?', (job_id,)).fetchone()[0] if exists else 0
            return dict(row), events, proofs

    def retained(row):
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
            connection.row_factory = sqlite3.Row
            checked = gate.checked_native_release(connection, root, row)
        need(checked is not None and sha(checked['package']) == policy.binding['package_sha256']
             and checked['proof']['receipt_sha256'] == receipt_hashes
             and checked['proof'].get('verification_profile_sha256') == policy.sha256
             and checked['proof'].get('allocation_receipt_sha256') == policy.binding['allocation_receipt_sha256']
             and checked['proof'].get('human_acceptance_recorded') is False, 'RETAINED_TECHNICAL_PROOF_DIFFERS')
        return checked['proof']

    row, events, proofs = state()
    if row['state'] == 'VERIFIED':
        need(events == proofs == 1, 'EXISTING_TECHNICAL_DECISION_INCONSISTENT')
        retained(row)
        return {'status': 'VERIFIED', 'job_id': job_id, 'state': 'VERIFIED', 'idempotent': True,
                'read_only': True, 'human_acceptance_recorded': False, 'event_count': events, 'proof_count': proofs}
    need(events == proofs == 0, 'UNEXPECTED_TECHNICAL_DECISION_EXISTS')
    current = now or datetime.now(timezone.utc)
    verified_at = current
    attempt_path = job / 'technical-verification' / 'attempt.json'
    resume = attempt_path.exists() or attempt_path.is_symlink()
    if resume:
        # Match the existing gate's durable attempt identity before using its
        # original freshness decision. The CLI independently rechecks this.
        saved = gate._private(attempt_path.parent, directory=True)
        need(gate._read(gate._private(saved / 'verification-profile.json'), 16_384) == policy.raw
             and gate._read(gate._private(saved / 'allocation-receipt.json'), 16_384) == receipts['allocation-receipt.json'],
             'DURABLE_ATTEMPT_PROFILE_OR_ALLOCATION_DIFFERS')
        attempt = gate._json(gate._read(gate._private(attempt_path)))
        expected = {'schema_version': 2, 'job_id': job_id, 'source_manifest_sha256': policy.binding['source_manifest_sha256'],
                    'package_sha256': policy.binding['package_sha256'], 'policy_id': 'jsn-clean-native-v2',
                    'observed_versions': policy.versions, 'receipt_sha256': receipt_hashes,
                    'verification_profile_sha256': policy.sha256,
                    'allocation_receipt_sha256': policy.binding['allocation_receipt_sha256']}
        need(set(attempt) == set(expected) | {'verified_at_utc'} and all(attempt[key] == item for key, item in expected.items()),
             'DURABLE_ATTEMPT_IDENTITY_DIFFERS')
        verified_at = datetime.fromtimestamp(gate._time(attempt['verified_at_utc']), timezone.utc)
        need(verified_at.timestamp() <= current.timestamp() + 300, 'DURABLE_ATTEMPT_TIME_INVALID')
    else:
        policy = BoundVerificationPolicy(policy.raw)
    package = gate._read(job / 'apex-package.zip', 8_000_000)
    snapshot = gate._json(gate._read(job / 'source-snapshot.json'))
    release = gate._json(gate._read(job / 'release-evidence.json'))
    download = gate._json(gate._read(job / 'native-pipeline' / 'download.json'))
    need(snapshot.get('project') == row['project'] and download == {
        'package_sha256': policy.binding['package_sha256'], 'source_hash': policy.binding['source_manifest_sha256']},
        'FROZEN_JOB_CHECKPOINT_BINDING_DIFFERS')
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        connection.row_factory = sqlite3.Row
        sources = [dict(item) for item in connection.execute(
            'SELECT s.* FROM sources s WHERE project=? AND rowid=(SELECT MAX(rowid) FROM sources newer '
            'WHERE newer.project=s.project AND newer.name=s.name) ORDER BY name', (row['project'],))]
    need(gate.inventory(sources)['source_hash'] == policy.binding['source_manifest_sha256'], 'CURRENT_PROJECT_SOURCE_DIFFERS')
    gate.verify_detached_proof(package=package, snapshot=snapshot, release=release,
        clean_install_raw=receipts['clean-install.json'], qa_result_raw=receipts['qa-result.json'],
        qa_target_raw=receipts['qa-target.json'], qa_profile_raw=receipts['qa-profile.json'],
        policy=policy, now=verified_at, run_created=row['created'], allocation_receipt_raw=receipts['allocation-receipt.json'])
    if value['command'] == 'check':
        return {'status': 'READY_NOT_APPLIED', 'job_id': job_id, 'state': 'QA_REQUIRED', 'read_only': True,
                'resume_retained_attempt': resume, 'event_count': 0, 'proof_count': 0, 'human_acceptance_recorded': False}
    identity = sha(json.dumps(value['receipt_sha256'], sort_keys=True, separators=(',', ':')).encode())
    operator = Path(operator_root) / ('fox-native-promotion-v2-' + identity)
    need(operator.absolute() == operator and root != operator and root not in operator.parents, 'PRIVATE_RECEIPTS_MUST_REMAIN_OUTSIDE_FOX_DATA')
    if operator.exists() or operator.is_symlink():
        gate._private(operator, directory=True)
        need({path.name for path in operator.iterdir()} <= names, 'PRIVATE_RECEIPT_DIRECTORY_HAS_UNEXPECTED_FILES')
    else:
        operator.mkdir(mode=0o700)
        gate._private(operator, directory=True)
    for name, raw in receipts.items():
        gate._save_once(operator / name, raw)
    command = ['--data-dir', str(root), '--run-id', job_id,
               '--receipt-dir', str(operator), '--policy-file', str(operator / 'verification-profile.json'), '--apply']
    if resume:
        command.append('--resume-retained')
    # Invoke the existing CLI parser/main from the already hash-checked module.
    # A new "-m" process would reimport unchecked bytes/package initializers.
    output, diagnostics = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(diagnostics):
        code = gate.main(command)
    encoded = output.getvalue().encode()
    need(code == 0 and len(encoded) <= 16_384, 'GATE_OUTCOME_UNCONFIRMED_INSPECT_RETAINED_STATE_NO_AUTOMATIC_RETRY')
    result = gate._json(encoded)
    need(result.get('id') == job_id and result.get('state') == 'VERIFIED', 'UNEXPECTED_ATOMIC_GATE_RESULT')
    after, events, proofs = state()
    need(after['state'] == 'VERIFIED' and events == proofs == 1, 'TECHNICAL_POSTCHECK_FAILED')
    retained(after)
    return {'status': 'VERIFIED', 'job_id': job_id, 'state': 'VERIFIED', 'idempotent': result['idempotent'],
            'read_only': False, 'event_count': events, 'proof_count': proofs, 'human_acceptance_recorded': False,
            'operator_directory': str(operator), 'proof_sha256': result['proof_sha256']}


def container_source():
    return inspect.getsource(container_execute) + r'''
import hashlib,json,os,sys,types
from pathlib import Path
try:
 value=json.loads(sys.stdin.buffer.read(16000001))
 path=Path('/app/fox/native_verification.py')
 module_raw=path.read_bytes()
 if not (os.geteuid()==1000 and os.getegid()==1000 and path.resolve()==Path('/app/fox/native_verification.py')
         and not path.is_symlink() and hashlib.sha256(module_raw).hexdigest()==value['module_sha256']):
  raise RuntimeError('DEPLOYED_MODULE_IDENTITY_DIFFERS')
 # Execute exactly the checked bytes, not a subsequent path read, and avoid
 # importing an unverified/shadowed fox package initializer.
 sys.path.insert(0,'/app')
 package=types.ModuleType('fox');package.__path__=['/app/fox'];sys.modules['fox']=package
 gate=types.ModuleType('fox.native_verification');gate.__package__='fox';gate.__file__=str(path)
 sys.modules['fox.native_verification']=gate
 exec(compile(module_raw,str(path),'exec'),gate.__dict__)
 result=container_execute(value,gate)
except Exception:
 result={'status':'BLOCKED','code':'PROMOTION_GUARD_OR_GATE_FAILED_INSPECT_STATE','automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
'''


def host_source():
    return r'''
import sys
sys.dont_write_bytecode=True
import base64,json,re,subprocess,urllib.request
def need(ok):
 if not ok:raise RuntimeError('PINNED_HOST_OR_IMAGE_GUARD_FAILED')
def image_id(value):
 need(isinstance(value,str) and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}',value) is not None)
 return value[7:] if value.startswith('sha256:') else value
try:
 value=json.loads(sys.stdin.buffer.read(16000001))
 request=urllib.request.Request('http://169.254.169.254/opc/v2/instance/',headers={'Authorization':'Bearer Oracle'})
 with urllib.request.urlopen(request,timeout=5) as response:metadata=json.loads(response.read(100000))
 need(metadata['id']=='ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
  and metadata['compartmentId']=='ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
  and metadata['canonicalRegionName']=='us-ashburn-1')
 result=subprocess.run(['podman','inspect','fox'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 need(result.returncode==0)
 fox=json.loads(result.stdout)[0]
 container_id=fox['Id']
 need(isinstance(container_id,str) and len(container_id)==64 and all(c in '0123456789abcdef' for c in container_id))
 need(fox['State']['Running'] is True and image_id(fox['Image'])==image_id(value['expected_image']) and fox['Config']['User']=='1000:1000'
  and not fox['HostConfig'].get('UsernsMode') and not any(m['Destination']=='/app' or m['Destination'].startswith('/app/') for m in fox.get('Mounts',[])))
 code=''' + repr(container_source()) + r'''
 loader='import base64,sys;exec(compile(base64.b64decode(sys.stdin.buffer.readline()),"<native-v2-promotion>","exec"))'
 framed=base64.b64encode(code.encode())+bytes([10])+json.dumps(value).encode()+bytes([10])
 result=subprocess.run(['podman','exec','-i',container_id,'python','-I','-B','-c',loader],input=framed,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
 need(result.returncode==0 and len(result.stdout)<=65536)
 outcome=json.loads(result.stdout)
 outcome.update(host_scope_verified=True,expected_image=value['expected_image'],module_sha256=value['module_sha256'])
except Exception:
 outcome={'status':'BLOCKED','code':'PINNED_TRANSPORT_OUTCOME_UNCONFIRMED_INSPECT_STATE','automatic_replay_permitted':False}
print(json.dumps(outcome,sort_keys=True))
'''


def dispatch(command, evidence_dir, **options):
    value = payload(command, evidence_dir, **options)
    # The installed provider chooses local stdin or the unchanged legacy SSH
    # argv. The source-bound host/container guards remain exactly the same.
    # Never call the clean operator's OCI or SQL helpers from promotion.
    encoded = json.dumps(value).encode() + b'\n'
    program = host_source()
    require(len(base64.b64encode(program.encode())) + 1 + len(encoded) <= transport.MAX_WIRE,
            'PROTECTED_REQUEST_TOO_LARGE')
    loader = "python3 -B -c 'import base64,sys;exec(base64.b64decode(sys.stdin.buffer.readline()))'"
    result = C.load_json(transport.execute_host(program, encoded, timeout=180, legacy_loader=loader))
    require(result.get('status') in ('READY_NOT_APPLIED', 'VERIFIED') and result.get('host_scope_verified') is True
            and result.get('expected_image') == value['expected_image'] and result.get('module_sha256') == value['module_sha256']
            and result.get('job_id') == value['binding']['job_id'] and result.get('human_acceptance_recorded') is False,
            'PROMOTION_BLOCKED_OR_UNCONFIRMED_INSPECT_STATE_NO_AUTOMATIC_RETRY')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('check', 'apply'))
    parser.add_argument('--evidence-dir', required=True)
    parser.add_argument('--collection-sha256', required=True)
    parser.add_argument('--expected-image', required=True)
    parser.add_argument('--module-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = dispatch(args.command, args.evidence_dir, collection_sha256=args.collection_sha256,
                          expected_image=args.expected_image, module_sha256=args.module_sha256, apply=args.apply)
    except Exception:
        print(json.dumps({'status': 'BLOCKED', 'code': 'PROMOTION_BLOCKED_OR_UNCONFIRMED_INSPECT_STATE',
                          'automatic_replay_permitted': False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
