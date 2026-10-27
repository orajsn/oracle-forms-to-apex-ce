"""Read-only remote harvest of a retained approved QA stage into a short new local directory.

The original stage, source bundle, runtime report and journals are never changed.
The supplied retained descriptor and remote reader are hash-checked; current QA
source changes do not reinterpret the historical attempt. No browser or SQL runs.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT)) if str(ROOT) not in sys.path else None
from qa.operator import clean_install as clean
from qa.operator import contracts as C

ALLOWED = {'package.zip', 'native-form-spec.json', 'allocation-receipt.json', 'verification-profile.json',
           'clean-import-receipt.json', 'qa-profile.json', 'target-receipt.json', 'qa-result.json',
           'stage-receipt.json', 'launch-intent.json', 'launch-receipt.json', 'dispatch-receipt.json'}


def read_local(path, limit):
    path = Path(path).absolute()
    clean.require(path.is_file() and not path.is_symlink() and path.resolve() == path and path.stat().st_size <= limit,
                  'RETAINED_SOURCE_FILE_UNSAFE')
    return path.read_bytes()


def new_private_output(path):
    path = Path(path).absolute()
    clean.require(path.parent == clean.handoff_root(legacy_root=ROOT / 'work')
                  and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', path.name)
                  and path.parent.resolve() == path.parent and not path.exists() and not path.is_symlink()
                  and len(str(path)) + 64 < 240, 'NEW_SHORT_WORKSPACE_OUTPUT_REQUIRED')
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
                      'LOCAL_OUTPUT_PROTECTION_FAILED')
    return path


def harvest(plan_path, descriptor_path, remote_path, source_sha, output):
    raw, _ = clean.read_plan(plan_path)
    plan_sha = C.digest(raw)
    descriptor = C.load_json(read_local(descriptor_path, 65_536))
    remote = read_local(remote_path, 2_000_000)
    clean.require(re.fullmatch(r'[a-f0-9]{64}', source_sha or '') and C.digest(C.canonical_bytes(descriptor)) == source_sha
                  and C.digest(remote) == descriptor['remote_sha256'], 'EXACT_RETAINED_READER_BINDING_REQUIRED')
    program = clean.HOST_PREFIX + r'''
from pathlib import Path
remote=base64.b64decode(p['remote_b64'],validate=True)
guard(hashlib.sha256(remote).hexdigest()==p['descriptor']['remote_sha256'])
n={'__name__':'retained_qa_readonly_harvest'};exec(compile(remote,'retained_native_qa_remote.py','exec'),n)
n['inspect_baselines'](p)
stage=n['ROOT']/'v2-stages'/p['plan_sha256']/p['source_sha256']
receipt=n['load'](n['read_private'](stage/'stage.complete.json'))
guard(receipt['plan_sha256']==p['plan_sha256'] and receipt['source_sha256']==p['source_sha256'])
for name,expected in receipt['bound_files'].items():
 guard(not Path(name).is_absolute() and '..' not in Path(name).parts)
 guard(hashlib.sha256(n['read_private'](stage/name)).hexdigest()==expected)
result=n['collect'](stage,p)
print(json.dumps(result,sort_keys=True))
'''
    result = clean.ssh_json(program, {'cli_scope': clean.oci_scope(require_database_available=False),
        'descriptor': descriptor, 'remote_b64': base64.b64encode(remote).decode(),
        'plan_sha256': plan_sha, 'source_sha256': source_sha})
    clean.require(result.get('status') == 'COLLECTED' and result.get('plan_sha256') == plan_sha
                  and result.get('source_sha256') == source_sha and result.get('credentials_and_logs_excluded') is True,
                  'RETAINED_EVIDENCE_IDENTITY_REQUIRED')
    encoded = result.pop('files')
    clean.require(set(encoded) <= ALLOWED and {'qa-result.json', 'allocation-receipt.json', 'launch-intent.json'} <= set(encoded)
                  and set(encoded) == set(result['sha256']), 'EVIDENCE_ALLOWLIST_REQUIRED')
    files = {name: base64.b64decode(value, validate=True) for name, value in encoded.items()}
    clean.require(all(C.digest(value) == result['sha256'][name] for name, value in files.items()), 'RAW_EVIDENCE_HASH_MISMATCH')
    destination = new_private_output(output)
    for name, value in files.items():
        clean.save_new(destination / name, value)
        clean.require(C.digest((destination / name).read_bytes()) == result['sha256'][name], 'LOCAL_EVIDENCE_READBACK_DIFFERS')
    clean.save_new(destination / 'collection-manifest.json', C.canonical_bytes(result))
    return {**result, 'local_directory': str(destination), 'remote_writes': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'descriptor', 'remote-code', 'source-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(harvest(args.plan, args.descriptor, args.remote_code, args.source_sha256, args.output), sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        import traceback
        print(json.dumps({'status': 'STOPPED', 'exception_type': type(exc).__name__, 'winerror': getattr(exc, 'winerror', None),
            'frames': [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                       for frame in traceback.extract_tb(exc.__traceback__)]}))
        raise SystemExit(2)
