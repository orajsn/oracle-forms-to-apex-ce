"""Explicit read-only harvest using an exact retained project reader and helper.

No current runner/source reinterpretation, clean check, SQL, browser launch or
proof promotion. Old evidence remains in place; local output is create-only.

Run explicitly with ``python -m qa.operator.harvest_project_qa``. A complete
harvest under workspace ``work/<shortname>`` can be supplied separately to the
project promoter with its exact collection hash. Harvest itself never adopts
the collection, edits an operator journal, or reconciles the queue.
"""
from __future__ import annotations
import base64
import argparse
import json
from pathlib import Path
from . import contracts as c
from . import project_clean_install as clean
from . import project_qa_dispatch as dispatch
from .harvest_native_qa import read_local, new_private_output


def harvest(plan_path, descriptor_path, remote_path, helper_path, source_sha, output):
    plan_raw, _ = clean.read_plan(plan_path)
    descriptor = c.load_json(read_local(descriptor_path, 65_536))
    remote, helper = read_local(remote_path, 2_000_000), read_local(helper_path, 2_000_000)
    clean.require(c._HASH.fullmatch(source_sha or '')
        and descriptor.get('scope') == 'fox-project-qa-stage-source-v1'
        and c.digest(c.canonical_bytes(descriptor)) == source_sha
        and c.digest(remote) == descriptor.get('remote_sha256')
        and c.digest(helper) == descriptor.get('helpers', {}).get('native_qa_remote.py'),
        'EXACT_RETAINED_PROJECT_READER_REQUIRED')
    program = clean.HOST_PREFIX + r'''
import types
remote=base64.b64decode(p['remote_b64'],validate=True);helper=base64.b64decode(p['helper_b64'],validate=True)
guard(hashlib.sha256(remote).hexdigest()==p['descriptor']['remote_sha256'])
guard(hashlib.sha256(helper).hexdigest()==p['descriptor']['helpers']['native_qa_remote.py'])
for name in ('qa','qa.operator'):
 module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
module=types.ModuleType('qa.operator.native_qa_remote');module.__package__='qa.operator';sys.modules[module.__name__]=module
exec(compile(helper,'retained_native_qa_remote.py','exec'),module.__dict__)
n={'__name__':'qa.operator.project_qa_remote','__package__':'qa.operator'}
exec(compile(remote,'retained_project_qa_remote.py','exec'),n)
n['inspect_baselines'](p)
stage=n['ROOT']/'project-v1-stages'/p['plan_sha256']/p['source_sha256']
result=n['collect'](stage,p)
print(json.dumps(result,sort_keys=True))
'''
    result = clean.ssh_json(program, {'cli_scope': clean.oci_scope(require_database_available=False),
        'plan_sha256': c.digest(plan_raw), 'source_sha256': source_sha, 'descriptor': descriptor,
        'remote_b64': base64.b64encode(remote).decode(), 'helper_b64': base64.b64encode(helper).decode()})
    # Validate bytes before creating output; save_collection's private_directory
    # is project-plan-specific, so use the shared explicit new work-dir guard.
    clean.require(result.get('status') == 'COLLECTED' and result.get('plan_sha256') == c.digest(plan_raw)
        and result.get('source_sha256') == source_sha and result.get('credentials_and_logs_excluded') is True,
        'RETAINED_PROJECT_EVIDENCE_IDENTITY_REQUIRED')
    encoded = result.get('files')
    clean.require(type(encoded) is dict and dispatch.REQUIRED <= set(encoded) <= dispatch.ALLOWED
        and set(encoded) == set(result.get('sha256', {})), 'RETAINED_PROJECT_EVIDENCE_MEMBERS_DIFFER')
    files = {name: base64.b64decode(raw, validate=True) for name, raw in encoded.items()}
    clean.require(sum(len(raw) for raw in files.values()) <= 12_000_000
        and all(0 < len(raw) <= 8_000_000 and c.digest(raw) == result['sha256'][name]
                for name, raw in files.items()), 'RETAINED_PROJECT_EVIDENCE_BYTES_DIFFER')
    destination = new_private_output(output)
    for name, raw in files.items():
        dispatch.save_evidence(destination / name, raw)
        clean.require((destination / name).read_bytes() == raw, 'RETAINED_PROJECT_READBACK_DIFFERS')
    saved = {key: value for key, value in result.items() if key != 'files'}
    dispatch.save_evidence(destination / 'collection-manifest.json', c.canonical_bytes(saved))
    return {**saved, 'local_directory': str(destination), 'remote_writes': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'descriptor', 'remote-code', 'helper-code', 'source-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    result = harvest(args.plan, args.descriptor, args.remote_code, args.helper_code, args.source_sha256, args.output)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:raise SystemExit(main())
    except Exception:
        print(json.dumps({'status': 'STOPPED', 'code': 'PROJECT_HARVEST_UNCONFIRMED_PRESERVE_STATE',
                          'automatic_replay_permitted': False}))
        raise SystemExit(2)
