"""Fixed prepared-source journey stage/run protocol; inert on import, Python 3.6.

Only an explicitly dispatched run calls the frozen MINI read-only check and the
existing browser image. Never build, pull, install, provision, accept or retry.
All failures withhold process output and retain exclusive no-replay journals.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.request

ROOT = Path('/home/opc/.config/fox-qa')
STAGE_ROOT = ROOT / 'prepared-journey-h'
LAUNCH_ROOT = ROOT / 'prepared-journey-launch-h'
DISPATCH_ROOT = ROOT / 'prepared-journey-dispatch-h'
# Actual H candidate identities supplied by the parent. This is not activation
# or dispatch approval: each action still checks the exact running services.
PIN_STATE = 'READY_H'
PINS_READY = True
ORIGIN = 'https://fox.129.213.189.48.sslip.io'
IMAGES = {
    'fox': 'd69b0e8a39dfe3fabf6c703dbd4ec42513e5a19bad75988096db3f22c7584bec',
    'converter': 'c7fdb53bc04450e297cbbbc89fb834be714e106d5a164b1c80dc77d544db5a1b',
    'opaf': '7c7ebc1f3da055ab3887a520e25552142f0a37f6d05dd116c16a87cac59fee8f',
    'qa': '142e37662816c276b33ca8b1be3da0d5afcc5e075667809be4f11898a34685f3',
}
TARGET = {
    'compartment_id': 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',
    'instance_id': 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
    'database_id': 'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq',
    'region': 'us-ashburn-1', 'db_name': 'ASZ8EQWFM8UNCA2_JSNF2APEX',
    'parsing_schema': 'FORMS2APEX_POC', 'table_name': 'FOX_NATIVE_MINI',
}
RELEASE = {
    'schema_version': 1, 'scope': 'fox-journey-release-binding-v1',
    'fox_image_id': IMAGES['fox'], 'qa_image_id': IMAGES['qa'],
    'html_sha256': '4cf8635e98c740a96c2e1f2bf8d67dd64b4c9193b9f4f2489da099173a6de6c8',
    'assets': [
        {'path': '/assets/index-B1MsZfAd.js', 'sha256': 'c6b28daa9d0b571ea40a070597f1fc4be2bef67a7ddd5af5ce59529e6757b0f7'},
        {'path': '/assets/index-7JXG_oaM.css', 'sha256': '9776c2b71fc626803a40411f7b4893ca9edc464979a1f3b476c31aad30637ac6'},
    ],
}
SOURCES = {
    'happy': 'b7ba121603d8ebb046ec2d889b33a0b1e7a97a946f1aaf92c107f6767e9f09d7',
    'blocked': 'ed4ad70b2bad380d9172a8ef3219d9a2d055373e43f2926b1da4b00bdbc9476e',
}
MANIFESTS = {
    'happy': '097e3e085f92fcb64f181e5c18517e0cc902fd550ca350d34c718ac767ca487c',
    'blocked': 'e736bf38d0ad941de9e333ad2fe591632ecfe4f4ca26d1a5dd71b8a9645a6b65',
}
FIXTURE_GENERATOR_SHA256 = '4a217e39e1852ef952886ceac935c7f11ad2ae23f3663693c6402b4988658378'
LIMIT = 2_000_000
PODMAN = ['/usr/bin/podman', '--remote=false']


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


PINNED_FILES = {
    'driver/run-fox-journey.mjs': '1af6739fc117bb815af3bad0e12db338f1eb10a5a0710ca5f6c62f04c0a5e6aa',
    'mini/prepare-mini-prerequisite.py': 'be0bfa442123ec4f9504677ef91b419470c6ccffd3a32e8ffb197e724e8714a2',
    'fixtures/journey-fixtures.json': '5576843cf487c3b892276dafdedddf952ad4a48b593ad29026b5c04702658d6d',
    'fixtures/happy/extraction/journey-happy-v1/ready/mini.xml': '4e9416890275043aac6061330d44c5bef713ea13d3d01e8251679ac941231197',
    'fixtures/happy/extraction/journey-happy-v1/ready/mini.sql': '8e66edefe2dfd5b6fb3614dfba179b997e4151b962dd9761bd7909abf87adc7e',
    'fixtures/happy/extraction/journey-happy-v1/ready/fox-readable-upload.json': MANIFESTS['happy'],
    'fixtures/blocked/extraction/journey-blocked-v1/ready/blocked.xml': 'a687cff597ce10257d410a34529c32cf8f65a80a00be126fd99a630d414974a0',
    'fixtures/blocked/extraction/journey-blocked-v1/ready/blocked.sql': '8e66edefe2dfd5b6fb3614dfba179b997e4151b962dd9761bd7909abf87adc7e',
    'fixtures/blocked/extraction/journey-blocked-v1/ready/fox-readable-upload.json': MANIFESTS['blocked'],
    'release.json': digest(canonical(RELEASE)),
}
LAUNCH_KEY = digest(':'.join([SOURCES['happy'], MANIFESTS['happy'], SOURCES['blocked'], MANIFESTS['blocked'], IMAGES['fox']]).encode('ascii'))


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def exact(value, keys):
    return type(value) is dict and set(value) == set(keys)


def is_hash(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


def load(raw):
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, 'JSON_BOUND_REQUIRED')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'NONFINITE_JSON'))


def decode(value):
    require(type(value) is str and 0 < len(value) <= LIMIT, 'BASE64_BOUND_REQUIRED')
    raw = base64.b64decode(value, validate=True)
    require(0 < len(raw) <= LIMIT, 'SOURCE_BOUND_REQUIRED')
    return raw


def utc_now():
    return datetime.now(timezone.utc)


def fresh(value, seconds):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value), 'UTC_TIME_REQUIRED')
    clean = value.replace('+00:00', 'Z')
    parsed = datetime.strptime(clean, '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in clean else '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    require(-60 <= (utc_now() - parsed).total_seconds() <= seconds, 'FRESH_OBSERVATION_REQUIRED')


def source_packet(packet):
    keys = {'command', 'apply', 'source_sha256', 'descriptor', 'files', 'remote_b64', 'cli_scope'}
    require(type(packet) is dict and packet.get('command') in ('stage', 'run'), 'EXPLICIT_STAGE_OR_RUN_REQUIRED')
    require(exact(packet, keys | ({'credentials'} if packet['command'] == 'run' else set()))
            and packet['apply'] is True and is_hash(packet['source_sha256']), 'EXPLICIT_EXACT_PACKET_REQUIRED')
    descriptor = packet['descriptor']
    require(exact(descriptor, ['schema_version', 'scope', 'pin_state', 'files', 'remote_sha256', 'wrapper_sha256',
                               'transport_sha256', 'credential_reader_sha256', 'fixture_generator_sha256',
                               'images', 'target', 'release', 'launch_key']), 'DESCRIPTOR_FIELDS_DIFFER')
    require(type(descriptor['schema_version']) is int and descriptor['schema_version'] == 1
            and descriptor['scope'] == 'fox-prepared-journey-source-v1'
            and descriptor['pin_state'] == PIN_STATE, 'DESCRIPTOR_SCHEMA_DIFFERS')
    require(all(is_hash(descriptor[key]) for key in ('remote_sha256', 'wrapper_sha256', 'transport_sha256',
                                                    'credential_reader_sha256', 'fixture_generator_sha256', 'launch_key')),
            'EXACT_DIGEST_REQUIRED')
    require(descriptor['images'] == IMAGES and descriptor['target'] == TARGET
            and canonical(descriptor['release']) == canonical(RELEASE) and descriptor['launch_key'] == LAUNCH_KEY
            and descriptor['fixture_generator_sha256'] == FIXTURE_GENERATOR_SHA256, 'FIXED_BINDING_DIFFERS')
    require(descriptor['files'] == PINNED_FILES and exact(packet['files'], PINNED_FILES)
            and digest(canonical(descriptor)) == packet['source_sha256'], 'SOURCE_MANIFEST_DIFFERS')
    sources = {name: decode(value) for name, value in packet['files'].items()}
    require(all(digest(raw) == PINNED_FILES[name] for name, raw in sources.items()), 'SOURCE_BYTES_DIFFER')
    require(digest(decode(packet['remote_b64'])) == descriptor['remote_sha256'], 'REMOTE_BYTES_DIFFER')
    if packet['command'] == 'run':
        credentials = packet['credentials']
        require(exact(credentials, ['username', 'password']) and credentials['username'] == 'jason'
                and type(credentials['password']) is str and 0 < len(credentials['password']) <= 1024,
                'PROTECTED_CREDENTIAL_SHAPE_DIFFERS')
    return sources


def safe_environment():
    return {'HOME': '/home/opc', 'USER': 'opc', 'LOGNAME': 'opc', 'PATH': '/usr/bin:/bin',
            'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()), 'LANG': 'C.UTF-8', 'PYTHONNOUSERSITE': '1'}


def command(args, timeout=15, allowed=(0,)):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=safe_environment(), cwd='/', timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('JOURNEY_TIMEOUT_UNCERTAIN_NO_REPLAY') from None
    require(result.returncode in allowed and type(result.stdout) is bytes and type(result.stderr) is bytes
            and len(result.stdout) <= LIMIT and len(result.stderr) <= LIMIT, 'COMMAND_FAILED_OUTPUT_WITHHELD')
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('REDIRECT_PROHIBITED')


def fetch(url, metadata=False):
    # No ambient proxy, auth, redirect, gzip transformation, cookies or retry.
    headers = {'Accept-Encoding': 'identity'}
    if metadata:
        headers['Authorization'] = 'Bearer Oracle'
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=10) as response:
        require(response.getcode() == 200 and response.geturl() == url
                and response.headers.get('Content-Encoding', 'identity') == 'identity', 'HTTP_RESPONSE_DIFFERS')
        raw = response.read(1_048_577)
    require(0 < len(raw) <= 1_048_576, 'HTTP_BYTES_OUT_OF_BOUNDS')
    return raw


def inspect_baselines(packet):
    import pwd
    require(os.getuid() != 0 and pwd.getpwuid(os.getuid()).pw_name == 'opc', 'OPC_ROOTLESS_REQUIRED')
    scope = packet['cli_scope']
    expected = {key: TARGET[key] for key in ('instance_id', 'database_id', 'compartment_id', 'region')}
    expected.update(database_db_name='JSNF2APEX', instance_state='RUNNING', database_state='AVAILABLE')
    require(exact(scope, set(expected) | {'observed_at_utc'})
            and all(scope[key] == value for key, value in expected.items()), 'CLI_JSN_SCOPE_DIFFERS')
    fresh(scope['observed_at_utc'], 300)
    identity = load(fetch('http://169.254.169.254/opc/v2/instance/', metadata=True))
    require(identity.get('id') == TARGET['instance_id'] and identity.get('compartmentId') == TARGET['compartment_id']
            and identity.get('canonicalRegionName') == TARGET['region'], 'IMDS_JSN_SCOPE_DIFFERS')
    require(command(PODMAN + ['info', '--format', '{{.Host.Security.Rootless}}']).stdout.strip() == b'true', 'ROOTLESS_REQUIRED')
    names = {'fox': 'fox', 'forms2apex-mcp': 'converter', 'oracle-applied-ai-label': 'opaf'}
    projection = '{"name":{{json .Name}},"image":{{json .Image}},"running":{{json .State.Running}}}'
    raw = command(PODMAN + ['inspect', '--format', projection] + sorted(names)).stdout
    containers = [load(line) for line in raw.splitlines()]
    require(len(containers) == 3, 'SERVICE_BASELINE_CHANGED')
    seen = set()
    for item in containers:
        require(exact(item, ['name', 'image', 'running']) and type(item['name']) is str, 'SERVICE_BASELINE_CHANGED')
        name = item['name'][1:] if item['name'].startswith('/') else item['name']
        require(name in names and name not in seen and item['running'] is True
                and item['image'] in (IMAGES[names[name]], 'sha256:' + IMAGES[names[name]]), 'SERVICE_BASELINE_CHANGED')
        seen.add(name)
    image = command(PODMAN + ['image', 'inspect', 'sha256:' + IMAGES['qa'], '--format', '{{.Id}}']).stdout.decode('ascii').strip()
    require(image in (IMAGES['qa'], 'sha256:' + IMAGES['qa']), 'CACHED_QA_IMAGE_CHANGED')
    assets = {'/': RELEASE['html_sha256']}
    assets.update({item['path']: item['sha256'] for item in RELEASE['assets']})
    for path, expected_hash in sorted(assets.items()):
        require(digest(fetch(ORIGIN + path)) == expected_hash, 'SERVED_RELEASE_BYTES_CHANGED')


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_dir(path, create=False, exclusive=False):
    path = Path(path)
    require(path.is_absolute() and (path == ROOT or ROOT in path.parents), 'FIXED_PRIVATE_ROOT_REQUIRED')
    current = Path('/')
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            require(create and (current == ROOT or ROOT in current.parents), 'PRIVATE_PARENT_MISSING')
            current.mkdir(mode=0o700)
            info = current.lstat()
        else:
            require(not (current == path and exclusive), 'STAGE_EXISTS_NO_OVERWRITE')
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'PRIVATE_DIRECTORY_LINK')
        require(not (stat.S_IMODE(info.st_mode) & 0o022), 'WRITABLE_ANCESTOR_FORBIDDEN')
        if current == ROOT or ROOT in current.parents:
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_DIRECTORY_OWNER_MODE')
            if create:
                # Adopted entries may have been mkdir'ed by a concurrent
                # claimant before its parent fsync. Adopt them durably too.
                sync_directory(current.parent)
    return path


def read_private(path, limit=LIMIT):
    private_dir(Path(path).parent)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= limit, 'PRIVATE_FILE_OWNER_MODE')
        raw = stream.read(limit + 1)
    require(len(raw) == info.st_size, 'PRIVATE_FILE_CHANGED')
    return raw


def create(path, raw):
    private_dir(Path(path).parent)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(Path(path).parent)


def absent(path):
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return True
    return False


def prerequisite(stage):
    raw = command(['/usr/bin/python3', '-I', '-B', str(stage / 'mini/prepare-mini-prerequisite.py'), '--check'], timeout=280).stdout
    value = load(raw)
    require(exact(value, set(TARGET) | {'schema_version', 'scope', 'ddl_sha256', 'readable_source_hash',
                                       'metadata_verified', 'initial_row_count', 'checked_at_utc'}), 'PREREQUISITE_FIELDS_DIFFER')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['scope'] == 'fox-journey-product-table-prerequisite-v1'
            and all(value[key] == expected for key, expected in TARGET.items())
            and value['ddl_sha256'] == PINNED_FILES['fixtures/happy/extraction/journey-happy-v1/ready/mini.sql']
            and value['readable_source_hash'] == SOURCES['happy'] and value['metadata_verified'] is True
            and type(value['initial_row_count']) is int and value['initial_row_count'] == 0, 'PREREQUISITE_UNPROVEN')
    fresh(value['checked_at_utc'], 3600)
    return raw


def podman_args(stage, dispatch):
    args = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=15s', '1080s'] + PODMAN + [
        'run', '--rm', '--init', '--pull=never', '--http-proxy=false',
        '--name', 'fox-prepared-journey-' + LAUNCH_KEY[:24],
        '--userns=keep-id', '--user', str(os.getuid()) + ':' + str(os.getgid()),
        '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges',
        '--ipc=private', '--shm-size=256m', '--cpus=1', '--memory=1536m', '--pids-limit=256',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777', '--workdir', '/opt/fox-qa',
    ]
    environment = {
        'FOX_JOURNEY_DISPATCH': 'approved-synthetic-prepared-journey-v1',
        'FOX_JOURNEY_FIXTURES': '/inputs/fixtures/journey-fixtures.json',
        'FOX_JOURNEY_PREREQUISITE': '/inputs/prerequisite.json', 'FOX_JOURNEY_RELEASE': '/inputs/release.json',
        'FOX_QA_CREDENTIAL_FILE': '/run/secrets/fox.json', 'FOX_QA_OUTPUT_DIR': '/results',
        'FOX_JOURNEY_DISPATCH_DIR': '/dispatch', 'FOX_QA_IMAGE_ID': IMAGES['qa'],
    }
    environment.update({key: '' for key in ('DEBUG', 'PWDEBUG', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                                          'http_proxy', 'https_proxy', 'all_proxy')})
    for key, value in sorted(environment.items()):
        args += ['--env', key + '=' + value]
    volumes = [(stage / 'driver/run-fox-journey.mjs', '/opt/fox-qa/run-fox-journey.mjs', 'ro'),
               (stage / 'fixtures', '/inputs/fixtures', 'ro'), (stage / 'release.json', '/inputs/release.json', 'ro'),
               (stage / 'prerequisite.json', '/inputs/prerequisite.json', 'ro'),
               (stage / 'credentials.json', '/run/secrets/fox.json', 'ro'),
               (stage / 'results', '/results', 'rw'), (dispatch, '/dispatch', 'rw')]
    for source, target, mode in volumes:
        args += ['--volume', str(source) + ':' + target + ':' + mode + ',Z']
    return args + ['--entrypoint', 'node', 'sha256:' + IMAGES['qa'], '/opt/fox-qa/run-fox-journey.mjs']


def stage_result(packet, stage):
    return {'status': 'STAGED', 'source_sha256': packet['source_sha256'], 'stage': str(stage),
            'launch_key': LAUNCH_KEY, 'qa_image_id': IMAGES['qa']}


def validate_result(raw, packet, stage, prerequisite_raw, secrets):
    require(not any(secret.encode('utf-8') in raw for secret in secrets), 'SECRET_IN_RESULT_WITHHELD')
    result = load(raw)
    require(result.get('schema_version') == 1 and type(result['schema_version']) is int
            and result.get('scope') == 'fox-prepared-source-rendered-journey-v1'
            and result.get('status') == 'PASSED', 'JOURNEY_NOT_PASSED_NO_REPLAY')
    run_id = result.get('run_id')
    require(type(run_id) is str and re.fullmatch(r'FOXJ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}', run_id), 'RESULT_IDENTITY_DIFFERS')
    for field in ('human_acceptance_recorded', 'download_requested', 'mutation_retry_performed'):
        require(result.get(field) is False, 'PROHIBITED_JOURNEY_ACTION')
    for field in ('denied_requests', 'browser_error_count'):
        require(type(result.get(field)) is int and result[field] == 0, 'JOURNEY_GUARD_FAILED')
    expected_assets = {'/': RELEASE['html_sha256']}
    expected_assets.update({item['path']: item['sha256'] for item in RELEASE['assets']})
    require(result.get('bindings') == {
        'fixtures_sha256': PINNED_FILES['fixtures/journey-fixtures.json'],
        'prerequisite_sha256': digest(prerequisite_raw), 'release_sha256': PINNED_FILES['release.json'],
        'operator_reported_fox_image_id': IMAGES['fox'], 'operator_reported_qa_image_id': IMAGES['qa'],
        'observed_asset_hashes': expected_assets}, 'RESULT_BINDINGS_DIFFER')
    projects = result.get('projects')
    require(exact(projects, ['happy', 'blocked']), 'RESULT_PROJECTS_DIFFER')
    safe_projects = {}
    for kind in ('happy', 'blocked'):
        item = projects[kind]
        pid = item.get('project_id')
        require(type(pid) is str and re.fullmatch('[a-f0-9]{32}', pid) and item.get('source_hash') == SOURCES[kind]
                and item.get('name') == 'FOX prepared journey ' + run_id + ' ' + kind, 'RESULT_SOURCE_IDENTITY_DIFFERS')
        assessment = {'source_hash': SOURCES[kind], 'preparation_mode': 'PREPARED_SET_MATCH',
                      'native_state': 'READY' if kind == 'happy' else 'BLOCKED',
                      'table_name': 'FOX_NATIVE_MINI'}
        actual_assessment = item.get('assessment')
        if kind == 'blocked' and type(actual_assessment) is dict and actual_assessment.get('table_name') is None:
            assessment['table_name'] = None
        require(actual_assessment == assessment, 'RESULT_ASSESSMENT_DIFFERS')
        safe_projects[kind] = {'project_id': pid, 'source_hash': SOURCES[kind]}
    happy, blocked = projects['happy'], projects['blocked']
    require(happy['project_id'] != blocked['project_id'] and blocked.get('process_disabled') is True
            and type(blocked.get('process_post_count')) is int and blocked['process_post_count'] == 0
            and 'job_id' not in blocked and happy.get('state') == 'QA_REQUIRED', 'RESULT_STATE_DIFFERS')
    job = happy.get('job_id')
    require(type(job) is str and re.fullmatch('fox-[a-f0-9]{20}', job), 'RESULT_JOB_DIFFERS')
    evidence = happy.get('evidence', {})
    alias = 'F2A_' + job.replace('-', '_').upper()
    url = 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/ords/r/forms2apex_poc/' + alias.lower() + '/'
    require(evidence.get('job_id') == job and type(evidence.get('application_id')) is int
            and 0 < evidence['application_id'] <= 9007199254740991 and evidence.get('application_alias') == alias
            and evidence.get('application_url') == url and evidence.get('reviewer_execution_verified') is True
            and is_hash(evidence.get('review_receipt_sha256')) and is_hash(evidence.get('response_sha256'))
            and evidence.get('package_sha256') is None, 'RESULT_APPLICATION_EVIDENCE_DIFFERS')
    artifacts = evidence.get('artifact_binding', {})
    require(exact(artifacts, ['job_id', 'draft_sha256', 'reviewed_spec_sha256', 'native_review_sha256'])
            and artifacts['job_id'] == job and all(is_hash(artifacts[key]) for key in artifacts if key != 'job_id'),
            'RESULT_REVIEW_BINDING_DIFFERS')
    posts = result.get('post_requests')
    expected = [('login', None, '/api/login'), ('create', 'blocked', '/api/projects'),
                ('upload', 'blocked', '/api/projects/' + blocked['project_id'] + '/sources'),
                ('create', 'happy', '/api/projects'), ('upload', 'happy', '/api/projects/' + happy['project_id'] + '/sources'),
                ('process', 'happy', '/api/projects/' + happy['project_id'] + '/runs')]
    require(type(posts) is list and len(posts) == 6, 'RESULT_POST_BUDGET_DIFFERS')
    prior = 0
    for item, (kind, case, endpoint) in zip(posts, expected):
        require(exact(item, ['intent_sequence', 'kind', 'case', 'endpoint', 'outcome', 'response_sha256'])
                and type(item['intent_sequence']) is int and item['intent_sequence'] > prior
                and (item['kind'], item['case'], item['endpoint']) == (kind, case, endpoint)
                and item['outcome'] == 'RESPONSE_VALIDATED' and is_hash(item['response_sha256']), 'RESULT_POST_SEQUENCE_DIFFERS')
        prior = item['intent_sequence']
    safe_projects['happy'].update(job_id=job, state='QA_REQUIRED', application_id=evidence['application_id'])
    safe_projects['blocked']['process_post_count'] = 0
    safe = stage_result(packet, stage)
    safe.update(status='PASSED', exit_code=0, result_directory=str(stage / 'results' / run_id),
                report_path=str(stage / 'results' / run_id / 'fox-journey-result.json'),
                projects=safe_projects, post_count=6, automatic_replay_permitted=False)
    require(not any(secret.encode('utf-8') in canonical(safe) for secret in secrets), 'SECRET_IN_SUMMARY_WITHHELD')
    return safe


def execute(packet):
    require(PINS_READY is True and PIN_STATE == 'READY_H', 'H_CANDIDATE_PINS_PENDING_NO_DISPATCH')
    sources = source_packet(packet)
    os.umask(0o077)
    inspect_baselines(packet)
    stage = STAGE_ROOT / packet['source_sha256']
    if packet['command'] == 'stage':
        private_dir(stage.parent, create=True)
        private_dir(stage, create=True, exclusive=True)
        for name, raw in sorted(sources.items()):
            private_dir((stage / name).parent, create=True)
            create(stage / name, raw)
        create(stage / 'descriptor.json', canonical(packet['descriptor']))
        create(stage / 'remote.py', decode(packet['remote_b64']))
        private_dir(stage / 'results', create=True, exclusive=True)
        receipt = stage_result(packet, stage)
        create(stage / 'stage.complete.json', canonical(receipt))
        return receipt
    private_dir(stage)
    require(read_private(stage / 'stage.complete.json') == canonical(stage_result(packet, stage))
            and read_private(stage / 'descriptor.json') == canonical(packet['descriptor'])
            and read_private(stage / 'remote.py') == decode(packet['remote_b64']), 'STAGED_BINDING_DIFFERS')
    for name, raw in sources.items():
        require(read_private(stage / name) == raw, 'STAGED_BYTES_CHANGED')
    results = private_dir(stage / 'results')
    require(not list(results.iterdir()), 'STAGED_RESULTS_NOT_EMPTY_NO_REPLAY')
    launch = private_dir(LAUNCH_ROOT, create=True)
    dispatch = private_dir(DISPATCH_ROOT, create=True)
    require(absent(launch / (LAUNCH_KEY + '.json')) and absent(dispatch / (LAUNCH_KEY + '.json')),
            'GLOBAL_JOURNEY_ALREADY_ATTEMPTED_NO_REPLAY')
    # This fixed host-side script is the ONLY database-related operation here.
    # In particular, stage never calls it, and run can never request --apply.
    prerequisite_raw = prerequisite(stage)
    create(stage / 'prerequisite.json', prerequisite_raw)
    create(stage / 'credentials.json', canonical(packet['credentials']))
    intent = {'schema_version': 1, 'scope': 'fox-prepared-journey-launch-intent-v1',
              'state': 'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY', 'source_sha256': packet['source_sha256'],
              'launch_key': LAUNCH_KEY, 'qa_image_id': IMAGES['qa'], 'fox_image_id': IMAGES['fox'],
              'prerequisite_sha256': digest(prerequisite_raw), 'at_utc': utc_now().isoformat()}
    # Global immutable key, independent of source descriptor changes; fsync
    # failure is fatal before process start. Never remove it to retry.
    create(launch / (LAUNCH_KEY + '.json'), canonical(intent))
    completed = command(podman_args(stage, dispatch), timeout=1100, allowed=(0, 2, 124, 137))
    require(completed.returncode == 0, 'JOURNEY_INCOMPLETE_NO_REPLAY')
    output = load(completed.stdout)
    require(exact(output, ['run_id', 'status', 'receipt']) and output['status'] == 'PASSED'
            and type(output['run_id']) is str and re.fullmatch(r'FOXJ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}', output['run_id'])
            and output['receipt'] == '/results/' + output['run_id'] + '/fox-journey-result.json', 'DRIVER_SUMMARY_DIFFERS')
    report_path = results / output['run_id'] / 'fox-journey-result.json'
    raw = read_private(report_path, limit=131072)
    summary = validate_result(raw, packet, stage, prerequisite_raw, packet['credentials'].values())
    require(summary['report_path'] == str(report_path), 'REPORT_PATH_DIFFERS')
    dispatch_raw = read_private(dispatch / (LAUNCH_KEY + '.json'), limit=16384)
    receipt = load(dispatch_raw)
    # The driver journals BEFORE browser launch, so asset observations are
    # intentionally empty here; final observed hashes are checked above.
    dispatch_bindings = dict(load(raw)['bindings'], observed_asset_hashes={})
    require(receipt.get('scope') == 'fox-prepared-journey-dispatch-intent-v1'
            and type(receipt.get('schema_version')) is int and receipt['schema_version'] == 1
            and receipt.get('run_id') == output['run_id']
            and all(receipt.get(key) == value for key, value in dispatch_bindings.items()),
            'DRIVER_DISPATCH_BINDING_DIFFERS')
    create(stage / 'launch.complete.json', canonical(summary))
    return summary


def main():
    try:
        packet = load(sys.stdin.buffer.read(LIMIT + 1))
        result = execute(packet)
        print(canonical(result).decode('utf-8'), end='')
        return 0
    except Exception:
        # Never print caught exceptions, process stderr, reports, credentials,
        # project titles, browser logs, screenshots or unverified identities.
        print(canonical({'status': 'STOPPED', 'code': 'JOURNEY_STOPPED_OUTPUT_WITHHELD_NO_REPLAY',
                         'automatic_replay_permitted': False}).decode('utf-8'), end='')
        return 2


if __name__ == '__main__':
    sys.exit(main())
