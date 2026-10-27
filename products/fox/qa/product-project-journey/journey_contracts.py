"""Bounded synthetic FOX product-journey declarations; no external effects."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

ORIGIN = 'https://fox.129.213.189.48.sslip.io'
INSTANCE = 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
COMPARTMENT = 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
DATABASE = 'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq'
REGION = 'us-ashburn-1'
SOURCE_HASH = '00cd6353d749d21236aa5e62f1440018a24819c50d1570939ef3b7bef9714218'
SOURCES = {
    'alpha.sql': '5a259b6d39e189180a16bcdcc5b59ea1f7ce18bb22cfd876a9b0572c3ca1e6bd',
    'alpha.xml': '446a73cf6c83c0b3584fadf37ab3c67978796f87f21f27f3a991d142c00aa5f0',
    'beta.sql': '4499836da0994f2314e569b3ff43c3a076d43d7f6a5c81c5ab9fc11af8ddc838',
    'beta.xml': '4b62238f1eada83b21de4726445db389ac103993e16092ae2492b76021cfb557',
}
HASH = re.compile(r'[a-f0-9]{64}\Z')
SCOPE = 'fox-live-project-journey-plan-v1'


class JourneyError(ValueError):
    """Fixed public categories, never credentials or provider output."""


def need(value, code):
    if not value:
        raise JourneyError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                           allow_nan=False) + '\n').encode('utf-8')
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise JourneyError('CANONICAL_JSON_REQUIRED') from None


def object_bytes(raw, *, maximum=2_000_000):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, 'BOUNDED_JSON_REQUIRED')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(JourneyError('FINITE_JSON_REQUIRED')))
    except JourneyError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise JourneyError('JSON_OBJECT_REQUIRED') from None
    need(type(result) is dict, 'JSON_OBJECT_REQUIRED')
    return result


def read(path, *, maximum=2_000_000, empty=False):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
             'LINKED_INPUT_FORBIDDEN')
    before = path.stat()
    need(path.resolve() == path and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and int(not empty) <= before.st_size <= maximum, 'REGULAR_BOUNDED_INPUT_REQUIRED')
    raw = path.read_bytes()
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
         and len(raw) == before.st_size, 'INPUT_CHANGED_DURING_READ')
    return raw


def hash_value(value):
    return type(value) is str and HASH.fullmatch(value) is not None


def source_files(directory):
    directory = Path(directory).absolute()
    if directory.is_file():
        fixture = object_bytes(read(directory, maximum=300_000))
        need(set(fixture) == {'schema_version', 'scope', 'files'} and type(fixture['schema_version']) is int
             and fixture['schema_version'] == 1 and fixture['scope'] == 'fox-synthetic-project-sources-v1'
             and type(fixture['files']) is dict and set(fixture['files']) == set(SOURCES)
             and all(type(text) is str for text in fixture['files'].values()), 'BUNDLED_SYNTHETIC_FIXTURE_REQUIRED')
        raw_files = {name: text.encode('utf-8') for name, text in fixture['files'].items()}
    else:
        need({path.name for path in directory.iterdir()} == set(SOURCES), 'EXACT_SYNTHETIC_SOURCE_SET_REQUIRED')
        raw_files = {name: read(directory / name, maximum=300_000) for name in SOURCES}
    result = []
    for name, expected in sorted(SOURCES.items()):
        raw = raw_files[name]
        need(sha(raw) == expected, 'SYNTHETIC_SOURCE_BYTES_CHANGED')
        result.append({'name': name, 'sha256': expected, 'base64': base64.b64encode(raw).decode('ascii')})
    validate_sources(result)
    return result


def validate_sources(files):
    need(type(files) is list and len(files) == 4, 'EXACT_SYNTHETIC_SOURCE_SET_REQUIRED')
    seen = {}
    for row in files:
        need(type(row) is dict and set(row) == {'name', 'sha256', 'base64'} and row.get('name') in SOURCES,
             'SYNTHETIC_SOURCE_FIELDS_INVALID')
        need(row['name'] not in seen and row['sha256'] == SOURCES[row['name']]
             and type(row['base64']) is str and len(row['base64']) <= 400_000, 'SYNTHETIC_SOURCE_FIELDS_INVALID')
        try:
            raw = base64.b64decode(row['base64'], validate=True)
        except (ValueError, TypeError):
            raise JourneyError('SOURCE_ENCODING_INVALID') from None
        need(0 < len(raw) <= 300_000 and sha(raw) == row['sha256'], 'SYNTHETIC_SOURCE_BYTES_CHANGED')
        seen[row['name']] = row['sha256']
    need(seen == SOURCES and sha('\n'.join(name + ':' + digest for name, digest in sorted(seen.items())).encode()) == SOURCE_HASH,
         'SYNTHETIC_SOURCE_MANIFEST_CHANGED')
    return files


def deployment(value):
    fields = {'provider', 'provider_sha256', 'release', 'release_sha256', 'admission', 'admission_sha256',
              'source_bundle_sha256', 'inventory', 'bundle_root', 'ui_assets'}
    need(type(value) is dict and set(value) == fields, 'DEPLOYMENT_FIELDS_INVALID')
    for name in ('provider', 'release', 'admission'):
        need(type(value[name]) is dict and hash_value(value[name + '_sha256'])
             and sha(canonical(value[name])) == value[name + '_sha256'], 'DEPLOYMENT_BINDING_CHANGED')
    provider, release, admission = (value[name] for name in ('provider', 'release', 'admission'))
    need(provider.get('schema_version') == 2 and provider.get('scope') == 'fox-hosted-operator-runtime-v2'
         and provider.get('owner_uid') == 1000 and release.get('schema_version') == 3
         and release.get('scope') == 'fox-product-verifier-release-v3' and release.get('enabled') is True,
         'DEPLOYED_PROJECT_RELEASE_REQUIRED')
    # The packaged production validators additionally check the entire C/R/D.
    target = provider.get('target_profile', {}).get('oci', {})
    need(all(target.get(key) == item for key, item in {'instance_id': INSTANCE, 'compartment_id': COMPARTMENT,
         'database_id': DATABASE, 'region': REGION}.items()), 'EXACT_JSN_TARGET_REQUIRED')
    need(release.get('hosted_runtime_configuration_sha256') == value['provider_sha256']
         and release.get('images') == provider.get('images')
         and type(admission.get('schema_version')) is int and admission.get('schema_version') == 1 and admission.get('scope') == 'fox-hosted-admission-v1'
         and admission.get('provider_configuration_sha256') == value['provider_sha256']
         and admission.get('current_release_sha256') == value['release_sha256'], 'DEPLOYMENT_BINDING_CHANGED')
    infrastructure = admission.get('infrastructure')
    need(type(infrastructure) is dict and set(infrastructure) == {'fox', 'forms2apex-mcp', 'oracle-applied-ai-label'},
         'EXACT_CONTAINER_BINDING_REQUIRED')
    for row in infrastructure.values():
        need(type(row) is dict and set(row) == {'id', 'image'} and hash_value(row['id'])
             and type(row['image']) is str and re.fullmatch('sha256:[a-f0-9]{64}', row['image']), 'EXACT_CONTAINER_BINDING_REQUIRED')
    need(len({row['id'] for row in infrastructure.values()}) == 3
         and infrastructure['fox']['image'] == release['images']['fox']
         and infrastructure['forms2apex-mcp']['image'] == release['images']['converter'], 'EXACT_CONTAINER_BINDING_REQUIRED')
    inventory = value['inventory']
    need(type(inventory) is dict and set(inventory) == {'schema_version', 'scope', 'files'}
         and inventory['schema_version'] == 1 and inventory['scope'] == 'fox-hosted-source-inventory-v1'
         and hash_value(value['source_bundle_sha256']) and sha(canonical(inventory)) == value['source_bundle_sha256'],
         'SOURCE_BUNDLE_CHANGED')
    need(type(inventory['files']) is dict and 1 <= len(inventory['files']) <= 10000, 'SOURCE_INVENTORY_INVALID')
    for name, digest in inventory['files'].items():
        need(type(name) is str and 0 < len(name) <= 512 and hash_value(digest)
             and '\\' not in name and ':' not in name and '__pycache__' not in name.split('/')
             and not PurePosixPath(name).is_absolute() and str(PurePosixPath(name)) == name
             and all(part not in ('', '.', '..') for part in name.split('/')), 'SOURCE_INVENTORY_INVALID')
    need(provider['converter_root'] == '/home/opc/.local/share/fox-project-builds/' + value['source_bundle_sha256'] + '/bundle/converter',
         'EXACT_HOST_SOURCE_BUNDLE_REQUIRED')
    ui = {name.removeprefix('fox/dist/'): digest for name, digest in inventory['files'].items() if name.startswith('fox/dist/')}
    need(type(value['bundle_root']) is str and Path(value['bundle_root']).is_absolute()
         and value['ui_assets'] == ui and 'index.html' in ui and len(ui) >= 3, 'EXACT_BUILT_UI_REQUIRED')
    return value


def validate_plan(value):
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'attempt_id', 'origin', 'project',
         'files', 'source_manifest_sha256', 'expected_forms', 'deployment', 'browser', 'node', 'harness',
         'max_wait_seconds', 'poll_seconds', 'plan_directory'}, 'PLAN_FIELDS_INVALID')
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and value['scope'] == SCOPE
         and value['origin'] == ORIGIN and type(value['attempt_id']) is str
         and re.fullmatch('live-[a-f0-9]{24}', value['attempt_id']), 'PLAN_IDENTITY_INVALID')
    need(type(value['plan_directory']) is str and Path(value['plan_directory']).is_absolute(), 'BOUND_PLAN_DIRECTORY_REQUIRED')
    project = value['project']
    need(type(project) is dict and set(project) == {'customer', 'name', 'description'}
         and project['customer'] == 'Synthetic FOX internal QA'
         and project['name'] == 'Synthetic FOX ' + value['attempt_id']
         and project['description'] == 'Synthetic automated conversion proof. No customer data or human acceptance.',
         'SYNTHETIC_PROJECT_REQUIRED')
    validate_sources(value['files'])
    need(value['source_manifest_sha256'] == SOURCE_HASH and value['expected_forms'] == ['ALPHA', 'BETA'], 'SOURCE_PLAN_CHANGED')
    deployment(value['deployment'])
    browser = value['browser']
    need(type(browser) is dict and set(browser) == {'playwright_module', 'index_sha256', 'version', 'channel'}
         and type(browser['playwright_module']) is str and Path(browser['playwright_module']).is_absolute()
         and hash_value(browser['index_sha256']) and type(browser['version']) is str
         and re.fullmatch(r'1\.\d+\.\d+', browser['version']) and browser['channel'] in ('msedge', 'chromium'),
         'PINNED_BROWSER_REQUIRED')
    node = value['node']
    need(type(node) is dict and set(node) == {'path', 'sha256'} and type(node['path']) is str
         and Path(node['path']).is_absolute() and hash_value(node['sha256']), 'PINNED_NODE_REQUIRED')
    need(type(value['harness']) is dict and set(value['harness']) == {'cli.py', 'journey_contracts.py', 'preflight.py', 'private_io.py', 'process_owner.py', 'live.mjs'}
         and all(hash_value(digest) for digest in value['harness'].values()), 'EXACT_HARNESS_REQUIRED')
    need(type(value['max_wait_seconds']) is int and 30 <= value['max_wait_seconds'] <= 3600
         and type(value['poll_seconds']) is int and 2 <= value['poll_seconds'] <= 10, 'BOUNDED_WAIT_REQUIRED')
    return value


def validate_preflight(value, plan, *, now=None):
    fields = {'schema_version', 'scope', 'observed_at_utc', 'source_bundle_sha256', 'release_sha256',
        'provider_sha256', 'admission_sha256', 'images', 'containers', 'instance', 'database',
        'operator_service', 'active_conversion_count', 'application_profile', 'receipt_sha256'}
    need(type(value) is dict and set(value) == fields and hash_value(value.get('receipt_sha256'))
         and sha(canonical({key: item for key, item in value.items() if key != 'receipt_sha256'})) == value['receipt_sha256'],
         'PREFLIGHT_RECEIPT_CHANGED')
    expected = plan['deployment']
    need(value.get('scope') == 'fox-live-project-preflight-v1' and type(value.get('schema_version')) is int and value.get('schema_version') == 1
         and all(value.get(key) == expected[key] for key in ('source_bundle_sha256', 'release_sha256', 'provider_sha256', 'admission_sha256'))
         and value.get('images') == expected['release']['images']
         and value.get('containers') == expected['admission']['infrastructure']
         and value.get('instance') == {'id': INSTANCE, 'compartment_id': COMPARTMENT, 'region': REGION}
         and value.get('database') == {'id': DATABASE, 'compartment_id': COMPARTMENT, 'lifecycle_state': 'AVAILABLE', 'db_name': 'JSNF2APEX'}
         and value.get('active_conversion_count') == 0 and type(value.get('active_conversion_count')) is int
         and value.get('application_profile') == 'native-project-v1', 'PREFLIGHT_DEPLOYMENT_DIFFERS')
    service = value.get('operator_service')
    need(type(service) is dict and set(service) == {'unit', 'pid', 'start_ticks', 'state'}
         and service['unit'] == 'fox-product-verifier.service' and service['state'] == 'running'
         and type(service['pid']) is int and service['pid'] > 1
         and type(service['start_ticks']) is str and re.fullmatch('[0-9]+', service['start_ticks']), 'LIVE_OPERATOR_REQUIRED')
    try:
        need(type(value['observed_at_utc']) is str and re.fullmatch(
            r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', value['observed_at_utc']),
            'UTC_PREFLIGHT_REQUIRED')
        stamp = datetime.fromisoformat(value['observed_at_utc'].replace('Z', '+00:00'))
        need(stamp.tzinfo is not None, 'UTC_PREFLIGHT_REQUIRED')
        age = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
    except (KeyError, ValueError, TypeError, AttributeError):
        raise JourneyError('UTC_PREFLIGHT_REQUIRED') from None
    need(-5 <= age <= 120, 'FRESH_PREFLIGHT_REQUIRED')
    return value
