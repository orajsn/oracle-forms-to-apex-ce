"""Parent-dispatched, JSN-only staging/run wrapper; importing this module does no I/O.

manifest is local/read-only. stage and run each require --apply and exact clean
plan/source hashes. They reuse the existing clean operator's private plan,
read-only clean check, OCI scope and protected SSH transport. No installs/pulls,
service deployment, target creation, secret provisioning or automatic retry.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT)) if str(ROOT) not in sys.path else None
from qa.operator import clean_install as clean
from qa.operator import contracts as C

HERE = Path(__file__).resolve().parent
FILES = ('package.json', 'package-lock.json', 'run-native.mjs', 'prepare-target.mjs',
         'run-jsn-qa.sh', 'lib/contracts.mjs', 'lib/package-evidence.mjs', 'lib/assert-jsn-vm.sh')
BASE_QA_IMAGE = 'sha256:e3f7b9648271a741cf320b7ad928a17e0e1591ba66835e7420864905524eb571'
BASE_DIGEST = 'mcr.microsoft.com/playwright@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f'


def bundle(*, images=None):
    pins = clean.image_pins() if images is None else clean.runtime_provider.validated_image_pins(images)
    files = {}
    for name in FILES:
        path = ROOT / 'qa' / name
        clean.require(path.is_file() and not path.is_symlink() and path.resolve() == path,
                      'QA_SOURCE_FILE_UNSAFE')
        files[name] = path.read_bytes()
        clean.require(0 < len(files[name]) <= 2_000_000, 'QA_SOURCE_SIZE_INVALID')
    remote = (HERE / 'native_qa_remote.py').read_bytes()
    clean_sources, clean_hash = clean.code_bundle()
    descriptor = {'schema_version': 1, 'scope': 'fox-native-qa-stage-source-v1',
                  'files': {name: C.digest(raw) for name, raw in files.items()},
                  'remote_sha256': C.digest(remote), 'wrapper_sha256': C.digest(Path(__file__).read_bytes()),
                  'clean_operator_code_sha256': clean_hash,
                  'clean_operator_manifest': {name: C.digest(raw) for name, raw in clean_sources.items()},
                  'base_qa_image': BASE_QA_IMAGE, 'base_digest': BASE_DIGEST,
                  'converter_image': pins['converter'], 'fox_image': pins['fox']}
    return files, remote, descriptor, C.digest(C.canonical_bytes(descriptor))


def dispatch(command, plan_path, plan_sha, source_sha, *, apply=False):
    clean.require(command in ('stage', 'run', 'collect') and apply is (command != 'collect'), 'EXPLICIT_QA_ACTION_REQUIRED')
    raw, plan = clean.read_plan(plan_path)
    clean.require(C.digest(raw) == plan_sha, 'EXACT_CLEAN_PLAN_SHA_REQUIRED')
    files, remote, descriptor, actual = bundle()
    clean.require(actual == source_sha, 'EXACT_QA_SOURCE_SHA_REQUIRED')
    clean.require(plan['operator_code_sha256'] == descriptor['clean_operator_code_sha256'],
                  'CLEAN_OPERATOR_CHANGED_REPREPARE_REQUIRED')
    # Reuse canonical package/retained-proof/live empty-table checks. This is
    # read-only, does not allocate or import, and intentionally fails after QA.
    checked = clean.dispatch('check', plan_path, expected_sha=plan_sha) if command != 'collect' else None
    expected_handoff = {key: '/opt/forms2apex/outputs/jobs/.operator-clean/' + plan_sha + '/' + name
                        for key, name in {'package': 'package.zip', 'native_spec': 'native-form-spec.json',
                        'allocation_receipt': 'allocate.evidence.json', 'verification_profile': 'verification-profile.json',
                        'import_receipt': 'verify.evidence.json', 'runtime_credentials': 'runtime-credentials.json'}.items()}
    clean.require(command == 'collect' or (checked.get('state') == 'QA_READY' and checked.get('plan_sha256') == plan_sha
                  and checked.get('qa_handoff') == expected_handoff), 'ACTUAL_CLEAN_READY_HANDOFF_REQUIRED')
    packet = {'command': command, 'apply': apply, 'cli_scope': clean.oci_scope(require_database_available=command != 'collect'),
              'plan_sha256': plan_sha, 'plan_b64': base64.b64encode(raw).decode(),
              'source_sha256': actual, 'descriptor': descriptor,
              'files': {name: base64.b64encode(value).decode() for name, value in files.items()},
              'remote_b64': base64.b64encode(remote).decode(),
              'contracts_b64': base64.b64encode(clean.code_bundle()[0]['contracts.py']).decode()}
    host = clean.HOST_PREFIX + r'''
remote=base64.b64decode(p['remote_b64'],validate=True)
guard(hashlib.sha256(remote).hexdigest()==p['descriptor']['remote_sha256'])
namespace={'__name__':'fox_native_qa_dispatch_remote'}
exec(compile(remote,'native_qa_remote.py','exec'),namespace)
try: result=namespace['execute'](p)
except Exception: result={'status':'STOPPED','code':'QA_ACTION_FAILED_PRESERVE_PRIVATE_STATE','automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
'''
    result = clean.ssh_json(host, packet)
    if command == 'collect' and result.get('status') == 'COLLECTED':
        # Keep Windows member paths below MAX_PATH. The complete source digest
        # remains in the verified manifest; prefix collisions still fail closed.
        destination = Path(plan_path).absolute().parent / ('qa-' + source_sha[:16])
        clean.private_directory(destination)
        allowed = {'package.zip', 'native-form-spec.json', 'allocation-receipt.json', 'verification-profile.json',
                   'clean-import-receipt.json', 'qa-profile.json', 'target-receipt.json', 'qa-result.json',
                   'stage-receipt.json', 'launch-receipt.json', 'launch-intent.json', 'dispatch-receipt.json'}
        clean.require(set(result['files']) <= allowed and {'allocation-receipt.json', 'qa-result.json', 'launch-intent.json'} <= set(result['files']), 'EVIDENCE_MEMBERS_INVALID')
        for name, encoded in result.pop('files').items():
            value = base64.b64decode(encoded, validate=True)
            clean.require(C.digest(value) == result['sha256'][name], 'EVIDENCE_TRANSFER_DIGEST_DIFFERS')
            clean.save_new(destination / name, value)
        clean.save_new(destination / 'collection-manifest.json', C.canonical_bytes(result))
        result['local_directory'] = str(destination)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('manifest', 'stage', 'run', 'collect'))
    parser.add_argument('--plan'); parser.add_argument('--plan-sha256'); parser.add_argument('--source-sha256')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'manifest':
        clean.require(not any((args.plan, args.plan_sha256, args.source_sha256, args.apply)), 'MANIFEST_IS_READ_ONLY')
        _, _, descriptor, digest = bundle()
        result = {'status': 'LOCAL_MANIFEST', 'qa_source_sha256': digest, 'descriptor': descriptor}
    else:
        result = dispatch(args.command, args.plan, args.plan_sha256, args.source_sha256, apply=args.apply)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status') in ('LOCAL_MANIFEST', 'STAGED', 'PASSED', 'COLLECTED') else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps({'status': 'STOPPED', 'code': 'QA_LOCAL_GUARD_OR_TRANSPORT_FAILED',
                          'automatic_replay_permitted': False}))
        raise SystemExit(2)
