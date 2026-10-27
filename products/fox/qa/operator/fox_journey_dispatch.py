"""Local manifest and separately authorized stage/run for the fixed journey.

Import and manifest perform local reads only. No target/URL/image overrides,
builds, installs, deployment, new ports, acceptance or download are implemented.
Only run decrypts the existing FOX DPAPI secret, captures it in memory, and
sends it through the existing protected SSH stdin transport without printing it.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from qa.operator import clean_install as clean
from qa.operator import fox_journey_remote as remote

HERE = Path(__file__).resolve().parent
FIXTURE_ROOT = ROOT / 'work/fox-journey-fixtures-20261017a'
SECRET_FILE = ROOT / 'fox/work/private/fox-web-admin.dpapi'
SECRET_READER = ROOT / 'scripts/Get-JsnSecret.ps1'
GENERATOR = ROOT / 'qa/prepare-fox-journey.py'
GENERATOR_SHA = '4a217e39e1852ef952886ceac935c7f11ad2ae23f3663693c6402b4988658378'
HASH = re.compile(r'[a-f0-9]{64}\Z')
STOPPED = {'status': 'STOPPED', 'code': 'JOURNEY_STOPPED_OUTPUT_WITHHELD_NO_REPLAY',
           'automatic_replay_permitted': False}


def require(value, code='JOURNEY_LOCAL_GUARD_FAILED'):
    if not value:
        raise RuntimeError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def local_bytes(file, limit=2_000_000):
    file = Path(file).absolute()
    require(file.resolve() == file and file.is_relative_to(ROOT), 'LOCAL_SOURCE_PATH_UNSAFE')
    info = file.lstat()
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_nlink == 1 and 0 < info.st_size <= limit, 'LOCAL_SOURCE_FILE_UNSAFE')
    raw = file.read_bytes()
    require(len(raw) == info.st_size, 'LOCAL_SOURCE_CHANGED_DURING_READ')
    return raw


def bundle():
    """Read only the frozen public fixture handoff and parent-reviewed code."""
    files = {}
    for name, expected in remote.PINNED_FILES.items():
        if name == 'release.json':
            raw = remote.canonical(remote.RELEASE)
        elif name == 'driver/run-fox-journey.mjs':
            raw = local_bytes(ROOT / 'qa/run-fox-journey.mjs', 100_000)
        elif name == 'mini/prepare-mini-prerequisite.py':
            raw = local_bytes(ROOT / 'work/beta/prepare-mini-prerequisite.py', 100_000)
        else:
            require(name.startswith('fixtures/'), 'UNEXPECTED_PUBLIC_FIXTURE_MEMBER')
            raw = local_bytes(FIXTURE_ROOT / name[len('fixtures/'):], 32_768)
        require(digest(raw) == expected, 'FROZEN_JOURNEY_BYTES_CHANGED')
        files[name] = raw
    require(digest(local_bytes(GENERATOR, 100_000)) == GENERATOR_SHA, 'FIXTURE_GENERATOR_CHANGED')
    require(digest(local_bytes(ROOT / 'fox/dist/index.html')) == remote.RELEASE['html_sha256'],
            'LOCAL_G_HTML_DIFFERS')
    for asset in remote.RELEASE['assets']:
        require(digest(local_bytes(ROOT / 'fox/dist' / asset['path'].lstrip('/'))) == asset['sha256'],
                'LOCAL_G_ASSET_DIFFERS')
    remote_raw = local_bytes(HERE / 'fox_journey_remote.py', 150_000)
    transport = {name: digest(local_bytes(HERE / name)) for name in ('clean_install.py', 'contracts.py')}
    descriptor = {
        'schema_version': 1, 'scope': 'fox-prepared-journey-source-v1',
        'pin_state': remote.PIN_STATE,
        'files': {name: digest(raw) for name, raw in files.items()},
        'remote_sha256': digest(remote_raw),
        'wrapper_sha256': digest(local_bytes(Path(__file__))),
        'transport_sha256': digest(remote.canonical(transport)),
        'credential_reader_sha256': digest(local_bytes(SECRET_READER)),
        'fixture_generator_sha256': GENERATOR_SHA,
        'images': remote.IMAGES, 'target': remote.TARGET,
        'release': remote.RELEASE, 'launch_key': remote.LAUNCH_KEY,
    }
    return files, remote_raw, descriptor, digest(remote.canonical(descriptor))


def fox_credentials():
    """No clipboard, plaintext file, command-line password, or credential echo."""
    # The existing DPAPI reader is deliberately reused, never invoked by manifest
    # or staging. Its stdout is captured by Python and never forwarded directly.
    require(SECRET_FILE.is_file() and not SECRET_FILE.is_symlink()
            and SECRET_FILE.resolve() == SECRET_FILE, 'PROTECTED_FOX_SECRET_UNAVAILABLE')
    raw = clean.run_process(['powershell', '-NoProfile', '-NonInteractive', '-File', str(SECRET_READER),
                             '-SecretFile', str(SECRET_FILE)], timeout=30)
    require(type(raw) is bytes and 0 < len(raw) <= 4096, 'PROTECTED_FOX_SECRET_INVALID')
    password = raw.decode('utf-8', 'strict').rstrip('\r\n')
    require(1 <= len(password) <= 1024 and not any(char in password for char in '\r\n\0'),
            'PROTECTED_FOX_SECRET_INVALID')
    return {'username': 'jason', 'password': password}


def validate_result(value, command, source_sha):
    require(type(value) is dict, 'JOURNEY_RESPONSE_INVALID')
    if value == STOPPED:
        return dict(STOPPED)
    base = {'status', 'source_sha256', 'stage', 'launch_key', 'qa_image_id'}
    stage = remote.STAGE_ROOT.as_posix() + '/' + source_sha
    require(value.get('source_sha256') == source_sha and value.get('stage') == stage
            and value.get('launch_key') == remote.LAUNCH_KEY and value.get('qa_image_id') == remote.IMAGES['qa'],
            'JOURNEY_RESPONSE_BINDING_INVALID')
    if command == 'stage':
        require(set(value) == base and value['status'] == 'STAGED', 'STAGE_RESPONSE_INVALID')
        return value
    require(set(value) == base | {'exit_code', 'result_directory', 'report_path', 'projects', 'post_count',
                                  'automatic_replay_permitted'}
            and value['status'] == 'PASSED' and type(value['exit_code']) is int and value['exit_code'] == 0
            and type(value['post_count']) is int and value['post_count'] == 6
            and value['automatic_replay_permitted'] is False, 'RUN_RESPONSE_INVALID')
    result_directory = value['result_directory']
    require(type(result_directory) is str and re.fullmatch(
        re.escape(stage) + r'/results/FOXJ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}', result_directory)
            and str(PurePosixPath(result_directory)) == result_directory
            and value['report_path'] == result_directory + '/fox-journey-result.json', 'RUN_REPORT_PATH_INVALID')
    projects = value['projects']
    require(type(projects) is dict and set(projects) == {'happy', 'blocked'}, 'RUN_PROJECTS_INVALID')
    for kind, source_hash in (
        ('happy', 'b7ba121603d8ebb046ec2d889b33a0b1e7a97a946f1aaf92c107f6767e9f09d7'),
        ('blocked', 'ed4ad70b2bad380d9172a8ef3219d9a2d055373e43f2926b1da4b00bdbc9476e'),
    ):
        item = projects[kind]
        require(type(item) is dict and type(item.get('project_id')) is str
                and re.fullmatch(r'[a-f0-9]{32}', item['project_id']) and item.get('source_hash') == source_hash,
                'RUN_PROJECT_IDENTITY_INVALID')
        if kind == 'happy':
            require(set(item) == {'project_id', 'job_id', 'source_hash', 'state', 'application_id'}
                    and type(item['job_id']) is str and re.fullmatch(r'fox-[a-f0-9]{20}', item['job_id'])
                    and item['state'] == 'QA_REQUIRED' and type(item['application_id']) is int
                    and item['application_id'] > 0, 'RUN_HAPPY_RESULT_INVALID')
        else:
            require(set(item) == {'project_id', 'source_hash', 'process_post_count'}
                    and type(item['process_post_count']) is int and item['process_post_count'] == 0,
                    'RUN_BLOCKED_RESULT_INVALID')
    require(projects['happy']['project_id'] != projects['blocked']['project_id'], 'PROJECTS_NOT_DISTINCT')
    return value


def dispatch(command, source_sha, *, apply=False):
    require(command in ('stage', 'run') and apply is True, 'EXPLICIT_PARENT_ACTION_REQUIRED')
    require(remote.PINS_READY is True and remote.PIN_STATE == 'READY_H', 'H_CANDIDATE_PINS_PENDING_NO_DISPATCH')
    require(type(source_sha) is str and HASH.fullmatch(source_sha), 'EXACT_SOURCE_SHA_REQUIRED')
    files, remote_raw, descriptor, actual = bundle()
    require(source_sha == actual, 'REVIEWED_JOURNEY_SOURCE_SHA_DIFFERS')
    # Only cloud identity reads: do not invoke clean.dispatch/check, SQLcl,
    # allocation, native QA, or any database query from this local wrapper.
    packet = {
        'command': command, 'apply': True, 'source_sha256': actual, 'descriptor': descriptor,
        'files': {name: base64.b64encode(raw).decode('ascii') for name, raw in files.items()},
        'remote_b64': base64.b64encode(remote_raw).decode('ascii'),
        'cli_scope': clean.oci_scope(require_database_available=True),
    }
    credentials = fox_credentials() if command == 'run' else None
    if credentials is not None:
        packet['credentials'] = credentials
    host = clean.HOST_PREFIX + r'''
remote=base64.b64decode(p['remote_b64'],validate=True)
guard(hashlib.sha256(remote).hexdigest()==p['descriptor']['remote_sha256'])
namespace={'__name__':'fox_prepared_journey_remote'}
try:
 exec(compile(remote,'fox_journey_remote.py','exec'),namespace)
 result=namespace['execute'](p)
except Exception:
 result={'status':'STOPPED','code':'JOURNEY_STOPPED_OUTPUT_WITHHELD_NO_REPLAY','automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
'''
    value = clean.ssh_json(host, packet)
    # Remote failures and unexpected strings can never echo the DPAPI value.
    encoded = json.dumps(value, sort_keys=True)
    require(len(encoded) <= 16_384 and (credentials is None or credentials['password'] not in encoded),
            'REMOTE_RESPONSE_WITHHELD')
    return validate_result(value, command, source_sha)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise RuntimeError('COMMAND_INVALID')


def main(argv=None):
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument('command', choices=('manifest', 'stage', 'run'))
        parser.add_argument('--source-sha256')
        parser.add_argument('--apply', action='store_true')
        args = parser.parse_args(argv)
        if args.command == 'manifest':
            require(args.source_sha256 is None and not args.apply, 'MANIFEST_IS_LOCAL_READ_ONLY')
            _, _, descriptor, source_sha = bundle()
            value = {'status': 'LOCAL_MANIFEST', 'candidate_pins_complete': remote.PINS_READY is True,
                     'live_activation_verified': False, 'parent_dispatch_required': True,
                     'pin_state': remote.PIN_STATE, 'journey_source_sha256': source_sha, 'descriptor': descriptor}
        else:
            value = dispatch(args.command, args.source_sha256, apply=args.apply)
        print(json.dumps(value, sort_keys=True))
        return 0 if value['status'] in ('LOCAL_MANIFEST', 'STAGED', 'PASSED') else 2
    except Exception:
        print(json.dumps(STOPPED, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
