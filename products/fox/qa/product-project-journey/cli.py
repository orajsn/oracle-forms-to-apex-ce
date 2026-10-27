"""Prepare, inspect or explicitly run a bounded synthetic project UI journey.

No database credentials are accepted. Normal FOX login credentials enter Node
through stdin after fresh installed-service checks. Unknown UI writes are never
replayed by this command; the same attempt directory cannot be reused.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import journey_contracts as contract
import private_io
import preflight
from process_owner import OwnedJob, inspect_identity

HARNESS = ('cli.py', 'journey_contracts.py', 'preflight.py', 'private_io.py', 'process_owner.py', 'live.mjs')


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # An accidentally supplied credential must not be echoed by argparse.
        raise contract.JourneyError('JOURNEY_ARGUMENTS_INVALID') from None


def verify_bundle(deployment):
    contract.deployment(deployment)
    root = Path(deployment['bundle_root'])
    expected = deployment['inventory']['files']
    actual = {}
    directories = {str(parent) for name in expected for parent in PurePosixPath(name).parents if str(parent) != '.'}
    for path in root.rglob('*'):
        contract.need(not path.is_symlink(), 'SOURCE_LINK_FORBIDDEN')
        name = path.relative_to(root).as_posix()
        if path.is_file():
            contract.need(name in expected, 'SOURCE_MEMBER_NOT_IN_FROZEN_INVENTORY')
            actual[name] = contract.sha(contract.read(path, maximum=8_000_000, empty=True))
        else:
            contract.need(path.is_dir() and name in directories, 'SOURCE_DIRECTORY_CHANGED')
    contract.need(actual == expected, 'FROZEN_SOURCE_BUNDLE_CHANGED')
    return root


def production_deployment(deployment):
    """Use actual packaged production validators; no provider gets selected."""
    root = verify_bundle(deployment)
    contract.need(not any(name == 'qa' or name.startswith('qa.') or name == 'fox' or name.startswith('fox.')
                         or name == 'forms2apex' or name.startswith('forms2apex.') for name in sys.modules),
                  'FRESH_PACKAGED_VALIDATOR_PROCESS_REQUIRED')
    sys.path[:0] = [str(root), str(root / 'fox'), str(root / 'converter')]
    runtime = importlib.import_module('qa.operator.runtime_provider')
    bridge = importlib.import_module('qa.operator.product_queue_transport')
    verifier = importlib.import_module('qa.operator.product_verifier')
    remote = importlib.import_module('qa.operator.retirement_remote')
    raw = contract.canonical(deployment['provider'])
    runtime.configuration_document(raw, expected_sha256=deployment['provider_sha256'])
    release = bridge.validate_release(deployment['release'])
    config = {'schema_version': 3, 'scope': 'fox-product-verifier-operator-config-v3',
        'enabled': release['enabled'], 'images': release['images'],
        'hosted_runtime_configuration_sha256': deployment['provider_sha256'],
        'opaf_profile': {key: release['opaf_profile'][key] for key in ('path', 'sha256', 'target_profile_sha256')}}
    contract.need(verifier.build_manifest(config, hosted_configuration=raw) == release,
                  'PACKAGED_RELEASE_SOURCE_DIFFERS')
    infrastructure = remote._infrastructure(deployment['admission']['infrastructure'], release['images'])
    contract.need(remote.admission_configuration(deployment['release_sha256'], deployment['provider_sha256'], infrastructure)
                  == deployment['admission'] and runtime._selected is runtime._UNSELECTED,
                  'PURE_DEPLOYMENT_DECLARATION_REQUIRED')
    return deployment


def prepare(args):
    deployment = {'source_bundle_sha256': args.bundle_sha256, 'bundle_root': str(Path(args.bundle_root).resolve(strict=True)),
                  'inventory': contract.object_bytes(contract.read(args.inventory))}
    for name in ('provider', 'release', 'admission'):
        raw = contract.read(getattr(args, name))
        value = contract.object_bytes(raw)
        contract.need(raw == contract.canonical(value) and contract.sha(raw) == getattr(args, name + '_sha256'),
                      'CANONICAL_REVIEWED_DEPLOYMENT_REQUIRED')
        deployment[name], deployment[name + '_sha256'] = value, contract.sha(raw)
    deployment['ui_assets'] = {name.removeprefix('fox/dist/'): sha for name, sha in deployment['inventory']['files'].items()
                               if name.startswith('fox/dist/')}
    production_deployment(deployment)
    module = Path(args.playwright_module).resolve(strict=True)
    metadata = contract.object_bytes(contract.read(module.parent / 'package.json'))
    contract.need(metadata.get('name') == 'playwright', 'INSTALLED_PLAYWRIGHT_REQUIRED')
    node = Path(args.node).resolve(strict=True)
    attempt = 'live-' + uuid.uuid4().hex[:24]
    plan = {'schema_version': 1, 'scope': contract.SCOPE, 'attempt_id': attempt, 'origin': contract.ORIGIN,
        'project': {'customer': 'Synthetic FOX internal QA', 'name': 'Synthetic FOX ' + attempt,
                    'description': 'Synthetic automated conversion proof. No customer data or human acceptance.'},
        'files': contract.source_files(args.sources), 'source_manifest_sha256': contract.SOURCE_HASH,
        'expected_forms': ['ALPHA', 'BETA'], 'deployment': deployment,
        'browser': {'playwright_module': str(module), 'index_sha256': contract.sha(contract.read(module)),
                    'version': metadata['version'], 'channel': args.browser_channel},
        'node': {'path': str(node), 'sha256': contract.sha(contract.read(node, maximum=150_000_000))},
        'harness': {name: contract.sha(contract.read(HERE / name)) for name in HARNESS},
        'max_wait_seconds': args.max_wait_seconds, 'poll_seconds': args.poll_seconds,
        'plan_directory': str(Path(args.output).absolute())}
    contract.validate_plan(plan)
    target = private_io.new_directory(args.output)
    private_io.save(target / 'plan.json', plan)
    result = {'status': 'PREPARED_NOT_PREFLIGHTED', 'plan_sha256': contract.sha(contract.canonical(plan)),
              'attempt_id': attempt, 'project_name': plan['project']['name'], 'plan': str(target / 'plan.json'),
              'live_requests_made': False, 'acceptance_permitted': False}
    private_io.save(target / 'prepared.json', result)
    return result


def load_plan(args, *, code=True):
    raw = contract.read(args.plan)
    contract.need(contract.sha(raw) == args.plan_sha256, 'EXACT_REVIEWED_PLAN_REQUIRED')
    plan = contract.validate_plan(contract.object_bytes(raw))
    contract.need(raw == contract.canonical(plan), 'CANONICAL_PLAN_REQUIRED')
    contract.need(Path(args.plan).absolute() == Path(plan['plan_directory']) / 'plan.json', 'PLAN_LOCATION_CHANGED')
    if code:
        contract.need(plan['harness'] == {name: contract.sha(contract.read(HERE / name)) for name in HARNESS},
                      'HARNESS_CHANGED_NEW_REVIEW_REQUIRED')
    return plan


def inspect(args):
    plan = load_plan(args, code=False)
    if args.attempt_output:
        directory = private_io.private(args.attempt_output)
        contract.need(contract.read(directory / 'plan.json') == contract.canonical(plan), 'ATTEMPT_PLAN_BINDING_CHANGED')
        claim_path = Path(plan['plan_directory']) / 'live-dispatch.json'
        if claim_path.exists() or (directory / 'dispatch.json').exists():
            claim = contract.object_bytes(contract.read(claim_path))
            contract.need(claim['attempt_id'] == plan['attempt_id'] and claim['plan_sha256'] == args.plan_sha256
                          and Path(claim['output_directory']) == directory, 'ATTEMPT_OUTPUT_BINDING_CHANGED')
        result = {'status': 'RETAINED_ATTEMPT_ONLY', 'attempt_id': plan['attempt_id'], 'read_only': True,
                  'automatic_replay_permitted': False, 'process_liveness_observed': False, 'files': {}}
        for name in ('dispatch.json', 'process.json', 'result.json', 'browser/result.json'):
            path = directory / name
            if path.exists():
                raw = contract.read(path)
                value = contract.object_bytes(raw)
                contract.need(value.get('attempt_id') == plan['attempt_id'], 'ATTEMPT_IDENTITY_CHANGED')
                if name == 'dispatch.json':
                    observed = contract.object_bytes(contract.read(directory / 'preflight.json'))
                    contract.need(value['plan_sha256'] == args.plan_sha256
                        and value['preflight_sha256'] == observed['receipt_sha256'], 'ATTEMPT_DISPATCH_BINDING_CHANGED')
                if name == 'browser/result.json':
                    contract.need(value['release_sha256'] == plan['deployment']['release_sha256']
                        and value['source_bundle_sha256'] == plan['deployment']['source_bundle_sha256']
                        and value['source_manifest_sha256'] == plan['source_manifest_sha256'], 'BROWSER_RESULT_BINDING_CHANGED')
                result['files'][name] = {'sha256': contract.sha(raw), 'value': value}
        # Recorded process metadata is not a current OS liveness observation.
        if os.name == 'nt' and 'process.json' in result['files']:
            record = result['files']['process.json']['value']
            contract.need(record['attempt_id'] == plan['attempt_id'] and record['node_sha256'] == plan['node']['sha256']
                          and record['identity']['pid'] == record['pid']
                          and Path(record['identity']['executable']) == Path(plan['node']['path']), 'RECORDED_PROCESS_BINDING_CHANGED')
            result['process'] = inspect_identity(record['identity'])
            result['process_liveness_observed'] = result['process']['state'] != 'unconfirmed'
        if args.remote:
            result['saved_state'] = preflight.inspect_journey(plan, args.ssh_key)
        return result
    production_deployment(plan['deployment'])
    value = preflight.observe(plan, args.ssh_key)
    return {'status': 'PREFLIGHTED_NOT_STARTED', 'preflight': value, 'acceptance_permitted': False}


def run(args):
    contract.need(args.apply is True and os.name == 'nt', 'EXPLICIT_WINDOWS_LIVE_RUN_REQUIRED')
    plan = load_plan(args)
    plan_root = private_io.private(plan['plan_directory'])
    contract.need(not (plan_root / 'live-dispatch.json').exists(), 'PRIOR_LIVE_ATTEMPT_RETAINED_INSPECT_ONLY')
    production_deployment(plan['deployment'])
    contract.need(contract.sha(contract.read(plan['node']['path'], maximum=150_000_000)) == plan['node']['sha256'],
                  'NODE_EXECUTABLE_CHANGED')
    module = Path(plan['browser']['playwright_module'])
    contract.need(contract.sha(contract.read(module)) == plan['browser']['index_sha256']
                  and contract.object_bytes(contract.read(module.parent / 'package.json'))['version'] == plan['browser']['version'],
                  'INSTALLED_BROWSER_CHANGED')
    output = private_io.new_directory(args.output)
    private_io.save(output / 'plan.json', plan)
    observed = preflight.observe(plan, args.ssh_key)
    private_io.save(output / 'preflight.json', observed)
    if getattr(args,'credentials_dpapi',None):
        contract.need(bool(args.username),'DPAPI_LOGIN_USERNAME_REQUIRED')
        login = private_io.dpapi_credentials(args.credentials_dpapi,args.username)
    else:
        contract.need(not getattr(args,'username',None),'USERNAME_ONLY_WITH_DPAPI')
        login = private_io.credentials(args.credentials)
    contract.validate_preflight(observed, plan)
    data = {'schema_version': 1, 'scope': 'fox-live-project-journey-input-v1', 'mode': 'live', 'apply': True,
        'origin': plan['origin'], 'attempt_id': plan['attempt_id'], 'output_dir': str(output / 'browser'),
        'credentials': login, 'project': plan['project'], 'files': plan['files'],
        'source_manifest_sha256': plan['source_manifest_sha256'], 'expected_forms': plan['expected_forms'],
        'preflight': observed, 'ui_assets': plan['deployment']['ui_assets'], 'browser': plan['browser'],
        'max_wait_seconds': plan['max_wait_seconds'], 'poll_seconds': plan['poll_seconds']}
    # Atomic plan-level claim prevents the same plan/attempt from being run
    # again merely by choosing another output directory. It is never removed.
    private_io.save(plan_root / 'live-dispatch.json', {'scope': 'fox-live-project-plan-claim-v1',
        'attempt_id': plan['attempt_id'], 'plan_sha256': args.plan_sha256, 'output_directory': str(output),
        'started_at_utc': datetime.now(timezone.utc).isoformat(), 'automatic_replay_permitted': False})
    private_io.save(output / 'dispatch.json', {'scope': 'fox-live-project-browser-dispatch-v1',
        'attempt_id': plan['attempt_id'], 'plan_sha256': args.plan_sha256,
        'preflight_sha256': observed['receipt_sha256'], 'started_at_utc': datetime.now(timezone.utc).isoformat(),
        'automatic_replay_permitted': False, 'acceptance_permitted': False})
    environment = {key: value for key, value in os.environ.items() if key.upper() in {
        'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'COMSPEC', 'PROGRAMFILES', 'PROGRAMFILES(X86)'}}
    process = None; job = OwnedJob(); outcome = None; forced = False
    deadline = time.monotonic() + plan['max_wait_seconds'] + 180
    try:
        with (output / 'browser.stdout').open('xb') as stdout, (output / 'browser.stderr').open('xb') as stderr:
            process = subprocess.Popen([plan['node']['path'], str(HERE / 'live.mjs'), '--apply'],
                stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, env=environment, cwd=HERE,
                creationflags=subprocess.CREATE_NO_WINDOW)
            job.assign(process)
            identity = job.identity(process)
            contract.need(Path(identity['executable']) == Path(plan['node']['path']), 'OWNED_NODE_EXECUTABLE_DIFFERS')
            private_io.save(output / 'process.json', {'pid': process.pid, 'attempt_id': plan['attempt_id'],
                'node_sha256': plan['node']['sha256'], 'owned_windows_job': True, 'identity': identity,
                'started_at_utc': datetime.now(timezone.utc).isoformat()})
            # No credential or source body is persisted in launch metadata.
            deliver_stdin(process, job, canonical_input(data), deadline=deadline)
            login.clear(); data['credentials'].clear()
            try:
                code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                forced = True; job.stop(); process.wait(timeout=15)
                raise contract.JourneyError('BROWSER_TIMEOUT_OUTCOME_UNCONFIRMED') from None
            if job.active():
                forced = True; job.stop()
            report_path = output / 'browser/result.json'
            report = contract.object_bytes(contract.read(report_path)) if report_path.exists() else None
            passed = (code == 0 and not forced and report is not None
                and report.get('status') == 'LIVE_VERIFIED_NOT_ACCEPTED' and report.get('evidence_mode') == 'live_http'
                and report.get('browser_close_returned') is True and report.get('accepted') is False
                and report.get('downloaded') is False and report.get('acceptance_requests') == 0
                and report.get('download_requests') == 0
                and report.get('completed_actions') == ['login', 'create', 'upload', 'process'])
            outcome = {'status': 'LIVE_VERIFIED_NO_ACCEPTANCE' if passed else 'ATTENTION_NO_REPLAY',
                'attempt_id': plan['attempt_id'], 'exit_code': code, 'forced_owned_cleanup': forced,
                'owned_processes_stopped': job.active() == 0, 'automatic_replay_permitted': False,
                'acceptance_recorded_by_harness': False, 'browser_result_sha256': contract.sha(contract.read(report_path)) if report else None}
            if passed:
                outcome['output'] = report['output']
    finally:
        login.clear()
        cleanup_ok = True
        try:
            if process is not None and process.poll() is None:
                # Assignment failure occurs before stdin delivery; still target
                # only this Popen handle, never a guessed or enumerated PID.
                if job.assigned:
                    job.stop()
                else:
                    process.terminate()
                process.wait(timeout=15)
            if process is not None and process.stdin is not None and not process.stdin.closed:
                try:
                    process.stdin.close()
                except OSError:
                    cleanup_ok = False
        except Exception:
            cleanup_ok = False
        finally:
            # KILL_ON_JOB_CLOSE applies only to this assigned child tree,
            # including when a pipe close or an observation failed.
            job.close()
        if outcome is None:
            outcome = {'status': 'ATTENTION_NO_REPLAY', 'attempt_id': plan['attempt_id'],
                'automatic_replay_permitted': False, 'acceptance_recorded_by_harness': False,
                'outcome_unconfirmed': True}
        if not cleanup_ok:
            outcome.update(status='ATTENTION_NO_REPLAY', cleanup_unconfirmed=True)
        private_io.save(output / 'result.json', outcome)
    return outcome


def canonical_input(value):
    # Separate name makes secret transport easy to audit: only the returned
    # bytes go into child stdin, never a file, argument or environment value.
    return contract.canonical(value)


def deliver_stdin(process, job, payload, *, deadline, write_timeout=30):
    """Anonymous-pipe writes can block on Windows before wait(timeout)."""
    done = threading.Event(); failed = []
    def send():
        try:
            process.stdin.write(payload)
        except Exception:
            failed.append(True)
        finally:
            try:
                process.stdin.close()
            except Exception:
                failed.append(True)
            done.set()
    writer = threading.Thread(target=send, name='fox-proof-private-stdin', daemon=True)
    writer.start()
    if not done.wait(max(0.01, min(write_timeout, deadline - time.monotonic()))):
        job.stop(); process.wait(timeout=15); writer.join(timeout=5)
        raise contract.JourneyError('STDIN_DELIVERY_TIMEOUT_OUTCOME_UNCONFIRMED')
    contract.need(not failed, 'STDIN_DELIVERY_UNCONFIRMED')


def main(argv=None):
    parser = SafeParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    make = sub.add_parser('prepare')
    for name in ('provider', 'release', 'admission'):
        make.add_argument('--' + name, required=True)
        make.add_argument('--' + name + '-sha256', required=True)
    for name in ('bundle-root', 'bundle-sha256', 'inventory', 'sources', 'node', 'playwright-module', 'output'):
        make.add_argument('--' + name, required=True)
    make.add_argument('--browser-channel', choices=('msedge', 'chromium'), default='msedge')
    make.add_argument('--max-wait-seconds', type=int, default=1800)
    make.add_argument('--poll-seconds', type=int, default=5)
    check = sub.add_parser('inspect'); execute = sub.add_parser('run')
    for child in (check, execute):
        child.add_argument('--plan', required=True); child.add_argument('--plan-sha256', required=True)
        child.add_argument('--ssh-key')
    check.add_argument('--attempt-output'); check.add_argument('--remote', action='store_true')
    execute.add_argument('--output', required=True)
    credential_mode=execute.add_mutually_exclusive_group(required=True)
    credential_mode.add_argument('--credentials')
    credential_mode.add_argument('--credentials-dpapi')
    execute.add_argument('--username')
    execute.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.mode in ('run', 'inspect') and (not getattr(args, 'attempt_output', None) or getattr(args, 'remote', False)):
        contract.need(bool(args.ssh_key), 'EXPLICIT_SSH_REFERENCE_REQUIRED')
    result = {'prepare': prepare, 'inspect': inspect, 'run': run}[args.mode](args)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] not in ('ATTENTION_NO_REPLAY',) else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        code = str(error) if isinstance(error, contract.JourneyError) else type(error).__name__
        print(json.dumps({'status': 'NOT_CONFIRMED', 'code': code, 'automatic_replay_permitted': False}))
        raise SystemExit(1)
