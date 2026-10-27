"""Measured fresh host/backend facts, never admission or a write transport.

Import is inert. Public APIs require the process's concrete selected C3/R4/F
provider. Only fixed GET/inspect operations and coherent query-only SQLite
reads are used. No service/container/schema/app is created, changed or replayed.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess

from . import runtime_provider as runtime


MAX_WIRE = 16_000_000
MAX_ROWS = 4096
RUN_STATES = frozenset(('QUEUED', 'PROCESSING', 'ATTENTION', 'QA_REQUIRED',
                        'REVIEW_REQUIRED', 'VERIFIED', 'ACCEPTED'))


class FreshRemoteError(RuntimeError):
    """Bounded codes only; raw rows, credentials and subprocess text stay private."""


def need(value, code):
    if not value:
        raise FreshRemoteError(code)


def closed(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except FreshRemoteError:
            raise
        except Exception:
            raise FreshRemoteError('FRESH_HOST_OBSERVATION_UNCONFIRMED') from None
    return call


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'FRESH_OBSERVATION_DUPLICATE_KEY')
            result[key] = value
        return result
    need(type(raw) is bytes and 0 < len(raw) <= MAX_WIRE, 'FRESH_OBSERVATION_BYTE_BOUND')
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(FreshRemoteError('FRESH_OBSERVATION_NONFINITE')))


def context(provider):
    need(type(provider) is runtime.FreshHostedProvider and runtime.selected_hosted() is provider,
         'CONCRETE_SELECTED_FRESH_PROVIDER_REQUIRED')
    config = provider.configuration
    need(os.name == 'posix' and os.geteuid() == config['owner_uid'] > 0,
         'FRESH_HOST_OWNER_REQUIRED')
    references = dict(provider.references_raw)
    plan = parse(references[config['storage']['plan']['path']])
    release_ref = parse(provider.release_reference_raw)
    backend_ref = parse(provider.backend_reference_raw)
    backend = parse(references[backend_ref['path']])
    return config, plan, release_ref, backend_ref, backend


def podman(provider, args):
    listing = args == ['ps', '-aq', '--no-trunc']
    inspecting = (type(args) is list and 3 <= len(args) <= 258 and args[:2] == ['inspect', '--']
                  and all(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) for value in args[2:]))
    need(listing or inspecting, 'READ_ONLY_LOCAL_INVENTORY_OPERATION_REQUIRED')
    result = subprocess.run(['/usr/bin/podman', '--remote=false', *args], cwd='/',
        env=provider._environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    need(result.returncode == 0 and not result.stderr.strip() and 0 <= len(result.stdout) <= MAX_WIRE,
         'FRESH_CONTAINER_INVENTORY_UNAVAILABLE')
    return result.stdout


def inventory(provider):
    from fox import producer_inventory_contract as producers
    raw = podman(provider, ['ps', '-aq', '--no-trunc'])
    ids = raw.decode('ascii').split()
    need(3 <= len(ids) <= producers.MAX_ROOTLESS and len(ids) == len(set(ids))
         and all(re.fullmatch('[a-f0-9]{64}', value) for value in ids), 'FRESH_CONTAINER_IDS_INVALID')
    values = parse(podman(provider, ['inspect', '--', *sorted(ids)]))
    need(type(values) is list and len(values) == len(ids), 'FRESH_CONTAINER_INVENTORY_INCOMPLETE')
    observed = datetime.now(timezone.utc).isoformat()
    rows, indexed = [], {}
    for item in values:
        need(type(item) is dict and item.get('Id') in ids and item['Id'] not in indexed,
             'FRESH_CONTAINER_INVENTORY_REBOUND')
        state = item['State']; image = item['Image']; name = item['Name']
        need(type(image) is str and type(name) is str, 'FRESH_CONTAINER_METADATA_INVALID')
        row = {'id': item['Id'], 'name': name.removeprefix('/'),
            'image': image if image.startswith('sha256:') else 'sha256:' + image,
            'status': state['Status'], 'running': state['Running'], 'pid': state['Pid'],
            'exit_code': state['ExitCode'], 'created_at': item['Created'],
            'started_at': state['StartedAt'], 'finished_at': state['FinishedAt']}
        producers.classify_row(row, observed)  # Validate every row, even infrastructure.
        rows.append(row); indexed[item['Id']] = item
    rows.sort(key=lambda row: row['id'])
    need([row['id'] for row in rows] == sorted(ids) and len({row['name'] for row in rows}) == len(rows),
         'FRESH_CONTAINER_INVENTORY_REBOUND')
    return rows, indexed, observed


def filesystem_identity(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'FRESH_MOUNT_PATH_ALIAS_INVALID')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'FRESH_MOUNT_PATH_TYPE_INVALID')
    return info.st_dev, info.st_ino


def private_alias(source, private):
    """Reject canonical paths that cover protected storage through bind aliases."""
    source, private = Path(source), Path(private)
    source_id = filesystem_identity(source)
    for ancestor in private.parents:
        if source_id == filesystem_identity(ancestor):
            return True
    if os.path.lexists(private):
        private_id = filesystem_identity(private)
        if source_id == private_id or any(private_id == filesystem_identity(parent) for parent in source.parents):
            return True
    return False


def fox_environment(config, release_ref, backend_ref):
    return {'FOX_INSTALLATION_MODE': 'fresh', 'FOX_DATA_DIR': '/data',
        'FOX_FRESH_PUBLIC_CONFIG_DIR': '/run/fox-installation',
        'FOX_FRESH_PROJECTION_SHA256': config['app_projection']['sha256'],
        'FOX_FRESH_PROVIDER_SHA256': digest(canonical(config)),
        'FOX_VERIFIER_RELEASE_SHA256': release_ref['sha256'],
        'FOX_FRESH_BACKEND_SHA256': backend_ref['sha256'],
        'FOX_VERIFICATION_ENABLED': '1', 'FOX_CONVERSION_PROFILE': 'native-project-v1',
        'FOX_RUN_ADAPTER': 'embedded-opaf', 'FOX_CONVERTER_URL': config['runtime']['converter_endpoint'],
        'FOX_PUBLIC_ORIGIN': config['runtime']['settings']['fox_origin'],
        'FOX_NATIVE_PROFILE_FILE': '/run/fox-native/profile.json'}


def role_measurements(provider, config, plan, release_ref, backend_ref, rows, indexed, *, staged):
    from fox import producer_inventory_contract as producers
    names = {row['name']: row for row in rows}
    need(len(names) == len(rows), 'FRESH_ROLE_NAMES_DUPLICATE')
    private = [config['admin_secret_file'], config['state_root'], plan['roots']['records']]
    result = {}
    backend = parse(dict(provider.references_raw)[backend_ref['path']])
    for role, expected in config['runtime']['roles'].items():
        need(expected['name'] in names, 'FRESH_DECLARED_ROLE_MISSING')
        row = names[expected['name']]; item = indexed[row['id']]
        need(row['image'] == expected['image'] and type(item.get('Config')) is dict
             and type(item.get('HostConfig')) is dict and item['Config'].get('User') == expected['user']
             and item['HostConfig'].get('ReadonlyRootfs') is expected['read_only_rootfs'],
             'FRESH_ROLE_CONFIGURATION_CHANGED')
        if staged and role != 'opaf':
            need(row['running'] is False and row['pid'] == row['exit_code'] == 0
                 and row['status'] in ('created', 'configured')
                 and producers.timestamp(row['started_at']) == producers.timestamp(producers.ZERO)
                 and producers.timestamp(row['finished_at']) == producers.timestamp(producers.ZERO)
                 and producers.timestamp(row['created_at']) >= producers.timestamp(backend['completed_at_utc']),
                 'FRESH_NEW_STOPPED_ROLE_REQUIRED')
        else:
            need(row['running'] is True and row['status'] == 'running' and row['pid'] > 0,
                 'FRESH_RUNNING_ROLE_REQUIRED')
        env = item['Config'].get('Env')
        need(type(env) is list and len(env) <= 256 and all(type(v) is str and 0 < len(v) <= 8192 and '=' in v for v in env),
             'FRESH_ROLE_ENVIRONMENT_INVALID')
        pairs = [value.split('=', 1) for value in env]
        environment = dict(pairs)
        need(len(environment) == len(pairs) and all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', key) for key in environment),
             'FRESH_ROLE_ENVIRONMENT_INVALID')
        if role == 'fox':
            need(not any(key.startswith('LD_') for key in environment), 'FRESH_FOX_LOADER_ENVIRONMENT_INVALID')
            need(all(environment.get(key) == value for key, value in fox_environment(config, release_ref, backend_ref).items()),
                 'FRESH_FENCED_ENVIRONMENT_REQUIRED')
            need(type(environment.get('FOX_PASSWORD_HASH')) is str
                 and re.fullmatch('[a-f0-9]{32}:[a-f0-9]{128}', environment['FOX_PASSWORD_HASH'])
                 and type(environment.get('FOX_ADMIN_USERNAME')) is str and 0 < len(environment['FOX_ADMIN_USERNAME']) <= 100,
                 'FRESH_LOGIN_CONFIGURATION_REQUIRED')
        mounts = runtime.persistent_mounts(role, item['HostConfig'], item.get('Mounts'))
        expected_mounts = {mount['destination']: mount for mount in expected['mounts']}
        need(len(mounts) == len(expected_mounts), 'FRESH_ROLE_MOUNTS_CHANGED')
        seen = set()
        for mount in mounts:
            destination = mount.get('Destination'); source = mount.get('Source')
            need(type(destination) is str and destination in expected_mounts and destination not in seen,
                 'FRESH_ROLE_MOUNTS_CHANGED')
            wanted = expected_mounts[destination]; seen.add(destination)
            need(mount.get('Type') in ('bind', 'volume') and source == wanted['source']
                 and type(mount.get('RW')) is bool and mount['RW'] is not wanted['read_only'],
                 'FRESH_ROLE_MOUNTS_CHANGED')
            need(not any(private_alias(source, path) for path in private), 'FRESH_PRIVATE_STORAGE_MOUNT_ALIAS')
        static = {'schema_version': 1, 'scope': 'fox-fresh-static-container-v1', 'name': row['name'],
                  'image': row['image'], 'config': item['Config'], 'host_config': item['HostConfig'],
                  'mounts': sorted(item['Mounts'], key=lambda mount: mount['Destination'])}
        raw = canonical(static)
        need(len(raw) <= 2_000_000, 'FRESH_STATIC_CONFIGURATION_BOUND')
        result[role] = {'id': row['id'], 'static_runtime_sha256': digest(raw)}
    return result


def bootstrap_snapshot(provider, config, plan, backend_ref, backend):
    from . import fresh_storage as storage
    from fox import backend_storage
    roots = {key: Path(value) for key, value in plan['roots'].items()}
    files = storage._retained_records(roots['records'])
    need(set(files) == storage.RECORDS - {'failure.json'}, 'FRESH_BOOTSTRAP_RECEIPT_INVENTORY_CHANGED')
    need(files['operation.lock'] == b'0' and all(canonical(parse(raw)) == raw
         for name, raw in files.items() if name != 'operation.lock'), 'FRESH_BOOTSTRAP_RECEIPTS_NOT_CANONICAL')
    complete = parse(files['complete.json']); intent = parse(files['intent.json'])
    rooted = parse(files['roots.json']); initialized = parse(files['database-initialized.json'])
    need(digest(files['complete.json']) == config['storage']['completion']['sha256']
         and complete['intent_sha256'] == digest(files['intent.json'])
         and complete['roots_sha256'] == digest(files['roots.json'])
         and complete['schema_observation_sha256'] == digest(files['database-initialized.json'])
         and intent['plan'] == plan and intent['installation_id'] == config['storage']['installation_id'],
         'FRESH_BOOTSTRAP_RECEIPT_BINDING_CHANGED')
    need(rooted['identities'] == {key: storage._root_identity(path) for key, path in roots.items()}
         and initialized['schema'] == storage._prerequisite_schema(plan), 'FRESH_BOOTSTRAP_ROOT_OR_SCHEMA_CHANGED')
    need(parse(files['schema-started.json']) == {'scope': 'fox-fresh-storage-schema-intent-v1',
        'installation_id': config['storage']['installation_id'], 'plan_sha256': config['storage']['plan']['sha256']},
        'FRESH_BOOTSTRAP_SCHEMA_INTENT_CHANGED')
    attempt = roots['operator_state'] / 'fresh-backend'
    storage._private_dir(attempt)
    need({path.name for path in attempt.iterdir()} == {'intent.json', 'observed.json'}, 'FRESH_BACKEND_ATTEMPT_CHANGED')
    intent_raw = storage._read(attempt / 'intent.json'); observed_raw = storage._read(attempt / 'observed.json')
    f_intent, observed = parse(intent_raw), parse(observed_raw)
    need(canonical(f_intent) == intent_raw and canonical(observed) == observed_raw,
         'FRESH_BACKEND_RECEIPTS_NOT_CANONICAL')
    keys = ('installation_id', 'storage_plan_sha256', 'storage_completion_sha256', 'app_projection_sha256',
            'provider_configuration_sha256', 'release_sha256')
    need(set(f_intent) == {'schema_version', 'scope', *keys, 'source_inventory', 'executing_sources',
                          'automatic_replay_permitted', 'created_at_utc'}
         and set(observed) == {'scope', *keys, 'intent_sha256', 'schema', 'backend_schema_sha256',
             'initial_counts', 'sqlite_version', 'journal_mode', 'sqlite_header_read_version', 'sqlite_header_write_version'},
         'FRESH_BACKEND_RECEIPT_FIELDS_CHANGED')
    layout = parse(provider.layout_raw)
    inventory = parse(dict(provider.references_raw)[layout['inventory']['path']])['files']
    executing = f_intent.get('executing_sources')
    need(type(executing) is dict and {'qa.operator.fresh_backend', 'fox.storage'} <= set(executing)
         and all(type(item) is dict and set(item) == {'path', 'sha256'}
             and inventory.get(item['path']) == item['sha256'] for item in executing.values()),
         'FRESH_BACKEND_EXECUTING_SOURCE_BINDING_CHANGED')
    need(digest(intent_raw) == backend['intent_sha256'] and f_intent['scope'] == 'fox-fresh-backend-intent-v1'
         and type(f_intent['schema_version']) is int and f_intent['schema_version'] == 1
         and f_intent['source_inventory'] == layout['inventory']
         and f_intent['automatic_replay_permitted'] is False
         and all(f_intent[key] == observed[key] == backend[key] for key in keys)
         and observed['scope'] == 'fox-fresh-backend-observation-v1'
         and observed['intent_sha256'] == backend['intent_sha256']
         and observed['schema'] == backend_storage.expected_backend_schema()
         and canonical(observed['initial_counts']) == canonical(backend_storage.expected_backend_counts())
         and observed['backend_schema_sha256'] == backend['backend_schema_sha256']
         and observed['journal_mode'] == 'delete'
         and observed['sqlite_header_read_version'] == observed['sqlite_header_write_version'] == 1,
         'FRESH_BACKEND_OBSERVATION_CHANGED')
    return digest(canonical({'S0': {name: digest(raw) for name, raw in files.items()},
        'F_intent': digest(intent_raw), 'F_observed': digest(observed_raw), 'F': backend_ref['sha256']}))


def scheduling_digest(runs, ledger):
    """Fingerprint bounded scheduling data; never serialize private BLOB values."""
    used = len(canonical(runs))
    safe = {}
    for table, rows in ledger.items():
        need(type(table) is str and type(rows) is list and len(rows) <= MAX_ROWS, 'FRESH_SCHEDULING_LEDGER_BOUND')
        safe[table] = []
        for row in rows:
            value = {}
            for key, item in row.items():
                if type(item) in (bytes, str):
                    used += len(item) if type(item) is bytes else len(item.encode('utf-8'))
                    need(used <= MAX_WIRE, 'FRESH_SCHEDULING_LEDGER_BOUND')
                value[key] = {'blob_bytes': len(item), 'sha256': digest(item)} if type(item) is bytes else item
            safe[table].append(value)
    raw = canonical({'runs': runs, 'ledger': safe})
    need(len(raw) <= MAX_WIRE, 'FRESH_SCHEDULING_LEDGER_BOUND')
    return digest(raw)


def backend_snapshot(provider, config, plan, release_ref, backend_ref, backend, deployment_sha=None):
    from fox import backend_storage, fresh_startup, verification_recovery
    env = {'FOX_INSTALLATION_MODE': 'fresh', 'FOX_FRESH_PUBLIC_CONFIG_DIR': config['runtime']['public_configuration']['directory'],
        'FOX_FRESH_PROJECTION_SHA256': config['app_projection']['sha256'], 'FOX_FRESH_PROVIDER_SHA256': provider.sha256,
        'FOX_VERIFIER_RELEASE_SHA256': release_ref['sha256'], 'FOX_FRESH_BACKEND_SHA256': backend_ref['sha256']}
    fence = fresh_startup.FreshStartupFence(plan['roots']['fox_data'], env)
    projection, _, admitted, admission_digest = fence._documents()
    if admitted and deployment_sha is not None:
        admission = parse(fresh_startup._read(fence.public / 'live-admission.json'))
        need(admission['admission_sha256'] == deployment_sha, 'FRESH_LIVE_ADMISSION_DEPLOYMENT_CHANGED')
    fence._sqlite_files(admitted=admitted)
    with closing(sqlite3.connect(fence.database.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        remaining = [2000]
        def bounded_sql():
            remaining[0] -= 1
            return remaining[0] < 0
        db.set_progress_handler(bounded_sql, 1000)
        backend_storage.validate_backend_storage(db, installation_id=projection['installation_id'],
            plan_sha256=projection['storage_plan_sha256'], require_empty=not admitted)
        if admitted:
            fence._normal_records(db)
        runs = [dict(row) for row in db.execute(
            'SELECT id,project,source_hash,state,artifact,created,updated FROM runs ORDER BY id LIMIT 4097')]
        need(len(runs) <= MAX_ROWS and all(type(row['id']) is str and re.fullmatch('fox-[a-f0-9]{20}', row['id'])
             and type(row['source_hash']) is str and re.fullmatch('[a-f0-9]{64}', row['source_hash'])
             and type(row['project']) is str and 0 < len(row['project']) <= 128
             and (row['artifact'] is None or row['artifact'] == 'jobs/' + row['id'] + '/apex-package.zip')
             and row['state'] in RUN_STATES and all(type(row[key]) in (int, float) and math.isfinite(row[key]) and row[key] >= 0
             for key in ('created', 'updated')) for row in runs), 'FRESH_RUN_SCHEDULING_STATE_INVALID')
        tables = ('verification_queue', *sorted(verification_recovery.VerificationRecovery._TABLES))
        ledger = {name: [dict(row) for row in db.execute('SELECT * FROM ' + name + ' ORDER BY rowid LIMIT 4097')]
                  for name in tables}
        need(all(len(rows) <= MAX_ROWS for rows in ledger.values()), 'FRESH_SCHEDULING_LEDGER_BOUND')
        scheduling_sha256 = scheduling_digest(runs, ledger)
        db.rollback()
    fence._sqlite_files(admitted=admitted)
    need(fence.refresh() is admitted, 'FRESH_ADMISSION_CHANGED_DURING_READ')
    return {'installation_id': projection['installation_id'], 'mode': 'NORMAL' if admitted else 'FENCED',
        'admission_sha256': admission_digest, 'scheduling_snapshot_sha256': scheduling_sha256, 'run_count': len(runs),
        'busy_conversion_count': sum(row['state'] in ('QUEUED', 'PROCESSING') for row in runs),
        'waiting_verification_count': sum(row['state'] == 'QA_REQUIRED' for row in runs),
        'running_verification_count': sum(row['state'] == 'running' for row in ledger['verification_queue'])}


def producer_snapshot(rows, infrastructure, observed):
    from fox import producer_inventory_contract as producers
    ids = {value['id'] for value in infrastructure.values()}
    extra = [{**row, 'classification': producers.classify_row(row, observed)} for row in rows if row['id'] not in ids]
    snapshot = {'observed_at_utc': observed, 'rootless_container_count': len(rows),
                'rootless_inventory_sha256': digest(canonical(rows)), 'producers': extra}
    return snapshot, producers.validate_snapshot(snapshot)


def observation(provider, *, staged, deployment_reference=None):
    from . import fresh_contracts as contracts, fresh_storage as storage
    from fox import producer_inventory_contract as producers
    config, plan, release_ref, backend_ref, backend = context(provider)
    declaration = None
    if deployment_reference is not None:
        reference = contracts._ref(deployment_reference)
        contracts._private_reference(reference, config)
        secret_paths = [config['admin_secret_file']] + [mount['source']
            for role in config['runtime']['roles'].values() for mount in role['mounts']
            if mount['destination'] in ('/run/fox-opaf', '/opt/forms2apex/wallet', '/home/converter/.dbtools')]
        need(contracts._outside(reference['path'], secret_paths)
             and not any(private_alias(reference['path'], secret) for secret in secret_paths),
             'FRESH_DEPLOYMENT_REFERENCE_IS_SECRET')
        raw = runtime._read(Path(reference['path']), 2_000_000, private=True)
        need(digest(raw) == reference['sha256'], 'FRESH_DEPLOYMENT_REFERENCE_CHANGED')
        artifacts = {**dict(provider.references_raw), reference['path']: raw}
        declaration = contracts.validate_admission(reference, artifacts,
            provider_reference=parse(provider.provider_reference_raw), release_reference=release_ref,
            layout=parse(provider.layout_raw))
    scope = provider.oci_scope(require_database_available=False)
    with storage._lock(Path(plan['roots']['records']), False):
        bootstrap_before = bootstrap_snapshot(provider, config, plan, backend_ref, backend)
        before, indexed, first_time = inventory(provider)
        measured = role_measurements(provider, config, plan, release_ref, backend_ref, before, indexed, staged=staged)
        if declaration is not None:
            need(measured == declaration['containers'], 'FRESH_DEPLOYMENT_CONTAINER_CHANGED')
        first_backend = backend_snapshot(provider, config, plan, release_ref, backend_ref, backend,
            deployment_reference['sha256'] if declaration else None)
        image_measurements = None
        if not staged:
            from .fresh_image import measure_runtime_payload
            image_measurements = measure_runtime_payload(provider, measured)
        after, after_indexed, last_time = inventory(provider)
        need(before == after and measured == role_measurements(provider, config, plan, release_ref, backend_ref,
             after, after_indexed, staged=staged), 'FRESH_INVENTORY_CHANGED_DURING_READ')
        last_backend = backend_snapshot(provider, config, plan, release_ref, backend_ref, backend,
            deployment_reference['sha256'] if declaration else None)
        need(first_backend == last_backend and bootstrap_before == bootstrap_snapshot(provider, config, plan, backend_ref, backend),
             'FRESH_BACKEND_CHANGED_DURING_OBSERVATION')
    need(provider.configuration == config, 'FRESH_PROVIDER_CHANGED_DURING_OBSERVATION')
    producer_before, counts = producer_snapshot(before, measured, first_time)
    producer_after, after_counts = producer_snapshot(after, measured, last_time)
    need(counts == after_counts, 'FRESH_PRODUCER_CLASSIFICATION_CHANGED')
    observed = datetime.now(timezone.utc).isoformat()
    witness = {'schema_version': 1, 'scope': producers.SCOPE, 'before': producer_before, 'after': producer_after}
    need(len(canonical(witness)) <= producers.MAX_WITNESS_BYTES
         and 0 <= producers.timestamp(last_time) - producers.timestamp(first_time) <= 120
         and producers.timestamp(observed) - producers.timestamp(first_time) <= 150,
         'FRESH_OBSERVATION_INTERVAL_OR_BYTE_BOUND')
    return {'schema_version': 1, 'scope': 'fox-fresh-host-observation-v1', 'status': 'OBSERVED_NOT_ADMITTED',
        'installation_id': config['storage']['installation_id'], 'provider_configuration_sha256': provider.sha256,
        'release_sha256': release_ref['sha256'], 'backend_initialization_sha256': backend_ref['sha256'],
        'bootstrap_receipts_sha256': bootstrap_before, 'containers': measured, 'backend': last_backend,
        'producer_witness': witness,
        'producer_counts': counts, 'oci_identity': scope, 'observed_at_utc': observed,
        'staged': staged, 'read_only': True, 'connected_admission': False,
        'image_contents_checked': image_measurements is not None,
        'image_contents_scope': 'fox-converter-application-payload-v1' if image_measurements is not None else None,
        'image_measurements': image_measurements, 'image_runtime_dependencies_checked': False,
        'opaf_image_files_checked': False,
        'full_installation_chain_checked': False, 'operator_admission_lease_checked': False,
        'automatic_replay_permitted': False}


@closed
def measure_deployment(provider):
    """Observe new stopped FOX/converter roles and running OPAF; publish nothing."""
    result = observation(provider, staged=True)
    need(result['backend']['mode'] == 'FENCED' and result['backend']['run_count'] == 0,
         'FRESH_INITIAL_DEPLOYMENT_REQUIRES_EMPTY_FENCED_STORE')
    backend_ref = parse(provider.backend_reference_raw)
    declaration = {'schema_version': 2, 'scope': 'fox-fresh-deployment-v2', 'installation_mode': 'fresh',
        'installation_id': result['installation_id'], 'provider_configuration_sha256': provider.sha256,
        'release_sha256': result['release_sha256'], 'backend_initialization': backend_ref,
        'containers': result['containers'], 'observed_at_utc': result['observed_at_utc']}
    return {**result, 'status': 'MEASURED_NOT_PUBLISHED', 'deployment_document': declaration}


@closed
def observe_host_state(provider, deployment_reference):
    """Compare live roles with real private D2 and return facts, never READY/A."""
    need(deployment_reference is not None, 'FRESH_DEPLOYMENT_REFERENCE_REQUIRED')
    return observation(provider, staged=False, deployment_reference=deployment_reference)
