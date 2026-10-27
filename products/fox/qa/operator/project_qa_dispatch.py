"""Local project-only QA dispatch. No external work occurs on import or bundle.

An enabled, paired product release is required by the product operator. This
transport separately requires explicit stage/run authority, exact plan/source
bytes and the fixed JSN guard. It does not install a background service.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
import re
import stat
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for location in (ROOT, ROOT / 'converter', ROOT / 'fox'):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))
from qa.operator import contracts as c
from qa.operator import project_clean_install as clean
from qa.operator import native_qa_dispatch as native

HERE = Path(__file__).resolve().parent
FILES = ('package.json', 'package-lock.json', 'run-project.mjs', 'lib/contracts.mjs',
         'lib/package-evidence.mjs', 'lib/project-profile.mjs', 'lib/project-runner-inputs.mjs',
         'lib/project-runtime.mjs', 'lib/project-browser.mjs')
HELPERS = ('native_qa_remote.py', 'project_qa_contracts.py')
BASE_QA_IMAGE, BASE_DIGEST = native.BASE_QA_IMAGE, native.BASE_DIGEST
ALLOWED = frozenset({'package.zip', 'native-project-spec.json', 'source-to-apex.json',
    'allocation-receipt.json', 'verification-profile.json', 'clean-import-receipt.json',
    'qa-profile.json', 'target-receipt.json', 'qa-result.json', 'stage-receipt.json',
    'launch-intent.json', 'launch-receipt.json', 'dispatch-receipt.json'})
REQUIRED = ALLOWED - {'launch-receipt.json', 'dispatch-receipt.json'}


def private_inputs(paths):
    """Owner-only evidence checks without PowerShell module auto-loading."""
    clean.require(all(path.is_absolute() and path.exists() and path.resolve() == path
        and not path.is_symlink()
        and not getattr(path.lstat(), 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
        for path in paths), 'PRIVATE_PROJECT_EVIDENCE_PATH_UNSAFE')
    if os.name != 'nt':
        clean.require(all(path.stat().st_uid == os.getuid() and not stat.S_IMODE(path.stat().st_mode) & 0o077
                          for path in paths), 'PRIVATE_PROJECT_EVIDENCE_PERMISSIONS_REQUIRED')
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
Write-Output 'PRIVATE_PROJECT_EVIDENCE_VERIFIED'
'''
    output = clean.run_process(['powershell', '-NoProfile', '-Command', program],
        data=json.dumps({'paths': [str(path) for path in paths]}).encode(), timeout=30)
    clean.require(output.strip() == b'PRIVATE_PROJECT_EVIDENCE_VERIFIED', 'PRIVATE_PROJECT_EVIDENCE_PERMISSIONS_REQUIRED')


def private_collection(path):
    """Only a new QA child of an exact project-plan directory is writable."""
    clean.require(path.is_absolute() and path.parent.parent == clean.private_root()
        and c._HASH.fullmatch(path.parent.name) and len(path.name) == 19 and path.name.startswith('qa-')
        and all(char in '0123456789abcdef' for char in path.name[3:])
        and path.parent.resolve() == path.parent and not path.exists() and not path.is_symlink(),
        'NEW_EXACT_PROJECT_COLLECTION_REQUIRED')
    private_inputs([path.parent])
    path.mkdir(mode=0o700)
    if os.name == 'nt':
        program = r'''$ErrorActionPreference='Stop'; $p=([Console]::In.ReadToEnd()|ConvertFrom-Json).path
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.SetAccessRule($rule); [IO.Directory]::SetAccessControl($p,$acl)
Write-Output 'PRIVATE_DIRECTORY_PROTECTED'
'''
        clean.require(clean.run_process(['powershell', '-NoProfile', '-Command', program],
            data=json.dumps({'path': str(path)}).encode()).strip() == b'PRIVATE_DIRECTORY_PROTECTED',
            'PROJECT_COLLECTION_PROTECTION_FAILED')


def save_evidence(path, raw):
    """Write one approved receipt in an already owner-private output directory."""
    project_child = (path.parent.parent.parent == clean.private_root()
        and c._HASH.fullmatch(path.parent.parent.name) and re.fullmatch(r'qa-[a-f0-9]{16}', path.parent.name))
    harvest_child = (path.parent.parent == clean.handoff_root(legacy_root=ROOT / 'work')
        and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', path.parent.name))
    clean.require(path.is_absolute() and (project_child or harvest_child) and path.name in ALLOWED | {'collection-manifest.json'}
        and path.parent.resolve() == path.parent and not path.exists() and not path.is_symlink()
        and type(raw) is bytes and 0 < len(raw) <= 8_000_000, 'NEW_PROJECT_EVIDENCE_FILE_REQUIRED')
    private_inputs([path.parent])
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags, 0o600), 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    private_inputs([path.parent, path])


def _source(path):
    clean.require(path.is_file() and not path.is_symlink() and path.resolve() == path
                  and 0 < path.stat().st_size <= 2_000_000, 'PROJECT_QA_SOURCE_UNSAFE')
    return path.read_bytes()


def bundle(*, images=None):
    pins = clean.image_pins() if images is None else clean.runtime_provider.validated_image_pins(images)
    files = {name: _source(ROOT / 'qa' / name) for name in FILES}
    remote = _source(HERE / 'project_qa_remote.py')
    helpers = {name: _source(HERE / name) for name in HELPERS}
    code, code_hash = clean.code_bundle()
    descriptor = {'schema_version': 1, 'scope': 'fox-project-qa-stage-source-v1',
        'files': {name: c.digest(raw) for name, raw in files.items()},
        'helpers': {name: c.digest(raw) for name, raw in helpers.items()},
        'remote_sha256': c.digest(remote), 'wrapper_sha256': c.digest(_source(Path(__file__))),
        'clean_operator_code_sha256': code_hash,
        'clean_operator_manifest': {name: c.digest(raw) for name, raw in code.items()},
        'base_qa_image': BASE_QA_IMAGE, 'base_digest': BASE_DIGEST,
        'converter_image': pins['converter'], 'fox_image': pins['fox']}
    return files, remote, descriptor, c.digest(c.canonical_bytes(descriptor))


HOST = clean.HOST_PREFIX + r'''
import types
sources={name:base64.b64decode(raw,validate=True) for name,raw in p['helpers'].items()}
guard(set(sources)=={'native_qa_remote.py','project_qa_contracts.py'})
guard(all(hashlib.sha256(raw).hexdigest()==p['descriptor']['helpers'][name] for name,raw in sources.items()))
remote=base64.b64decode(p['remote_b64'],validate=True)
guard(hashlib.sha256(remote).hexdigest()==p['descriptor']['remote_sha256'])
for name in ('qa','qa.operator'):
 module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
module=types.ModuleType('qa.operator.native_qa_remote');module.__package__='qa.operator'
sys.modules[module.__name__]=module
exec(compile(sources['native_qa_remote.py'],'native_qa_remote.py','exec'),module.__dict__)
namespace={'__name__':'qa.operator.project_qa_remote','__package__':'qa.operator'}
exec(compile(remote,'project_qa_remote.py','exec'),namespace)
try:result=namespace['execute'](p)
except Exception:result={'status':'STOPPED','code':'PROJECT_QA_ACTION_UNCONFIRMED_PRESERVE_STATE','automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
'''


def save_collection(result, destination, plan_sha, source_sha):
    clean.require(type(result) is dict and result.get('status') == 'COLLECTED'
        and result.get('plan_sha256') == plan_sha and result.get('source_sha256') == source_sha
        and result.get('credentials_and_logs_excluded') is True, 'PROJECT_COLLECTION_IDENTITY_DIFFERS')
    encoded = result.get('files')
    clean.require(type(encoded) is dict and REQUIRED <= set(encoded) <= ALLOWED
        and type(result.get('sha256')) is dict and set(encoded) == set(result['sha256']), 'PROJECT_COLLECTION_MEMBERS_DIFFER')
    files = {name: base64.b64decode(raw, validate=True) for name, raw in encoded.items()}
    clean.require(sum(len(raw) for raw in files.values()) <= 12_000_000
        and all(0 < len(raw) <= 8_000_000 and c.digest(raw) == result['sha256'][name]
                for name, raw in files.items()), 'PROJECT_COLLECTION_BYTES_DIFFER')
    # Validate the entire transport before the first create-only local write.
    private_collection(destination)
    for name, raw in files.items():
        save_evidence(destination / name, raw)
        clean.require(c.digest((destination / name).read_bytes()) == result['sha256'][name],
                      'PROJECT_COLLECTION_READBACK_DIFFERS')
    saved = {key: value for key, value in result.items() if key != 'files'}
    save_evidence(destination / 'collection-manifest.json', c.canonical_bytes(saved))
    return {**saved, 'local_directory': str(destination)}


def dispatch(command, plan_path, plan_sha, source_sha, *, apply=False):
    clean.require(command in ('stage', 'run', 'collect') and apply is (command != 'collect'),
                  'EXPLICIT_PROJECT_QA_ACTION_REQUIRED')
    raw, plan = clean.read_plan(plan_path)
    clean.require(c.digest(raw) == plan_sha, 'EXACT_PROJECT_PLAN_SHA_REQUIRED')
    files, remote, descriptor, actual = bundle()
    clean.require(actual == source_sha and plan['operator_code_sha256'] == descriptor['clean_operator_code_sha256'],
                  'EXACT_PROJECT_QA_SOURCE_REQUIRED')
    expected = {key: '/opt/forms2apex/outputs/jobs/.operator-project-clean/' + plan_sha + '/' + name
        for key, name in {'package': 'package.zip', 'project_spec': 'native-project-spec.json',
            'project_trace': 'source-to-apex.json', 'allocation_receipt': 'allocate.evidence.json',
            'verification_profile': 'verification-profile.json', 'import_receipt': 'verify.evidence.json',
            'runtime_credentials': 'runtime-credentials.json'}.items()}
    if command != 'collect':
        checked = clean.dispatch('check', plan_path, expected_sha=plan_sha)
        clean.require(checked.get('state') == 'QA_READY' and checked.get('plan_sha256') == plan_sha
                      and checked.get('qa_handoff') == expected, 'ACTUAL_PROJECT_CLEAN_HANDOFF_REQUIRED')
    code, _ = clean.code_bundle()
    packet = {'command': command, 'apply': apply, 'plan_sha256': plan_sha,
        'plan_b64': base64.b64encode(raw).decode(), 'source_sha256': actual, 'descriptor': descriptor,
        'files': {name: base64.b64encode(raw).decode() for name, raw in files.items()},
        'remote_b64': base64.b64encode(remote).decode(),
        'helpers': {name: base64.b64encode(_source(HERE / name)).decode() for name in HELPERS},
        'clean_code': {name: base64.b64encode(raw).decode() for name, raw in code.items()},
        'cli_scope': clean.oci_scope(require_database_available=command != 'collect')}
    result = clean.ssh_json(HOST, packet)
    if command == 'collect' and result.get('status') == 'COLLECTED':
        return save_collection(result, Path(plan_path).absolute().parent / ('qa-' + source_sha[:16]), plan_sha, source_sha)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('manifest', 'stage', 'run', 'collect'))
    for name in ('plan', 'plan-sha256', 'source-sha256'):
        parser.add_argument('--' + name)
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
    try:raise SystemExit(main())
    except Exception:
        print(json.dumps({'status': 'STOPPED', 'code': 'PROJECT_QA_LOCAL_GUARD_OR_TRANSPORT_FAILED',
                          'automatic_replay_permitted': False}))
        raise SystemExit(2)
