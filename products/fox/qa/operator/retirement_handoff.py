"""Versioned Windows retirement evidence for a distinct hosted installation.

Export runs only in the already installed Windows I namespace, after its
explicit idle closure, while its actual leases remain held. It returns bytes;
it never closes a session, copies files, deploys, kills a process or grants
acceptance. Hosted reads never load or execute archived Windows code. The
installation must independently pin the returned attestation SHA. A self hash
or a JSON ``ready`` flag is not authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import SimpleNamespace


SCOPE = 'fox-windows-hosted-retirement-v1'
PLAN_SCOPE = 'fox-windows-hosted-retirement-plan-v1'
MAX_FILE = 32_000_000
MAX_TOTAL = 128_000_000
ROLES = ('failure', 'retry', 'idle')
NATIVE_RECORDS = frozenset(('source.json', 'intent.json', 'worker-launch.json',
    'worker-ready.json', 'watchdog-launch.json', 'watchdog-ready.json', 'watchdog-armed.json'))
SHA = re.compile(r'[a-f0-9]{64}\Z')
SESSION = re.compile(r'session-[a-f0-9]{24}\Z')


class RetirementError(RuntimeError):
    """Only fixed diagnostics; no private source contents in errors."""


def need(ok, code):
    if not ok:
        raise RetirementError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_FILE, 'RETIREMENT_JSON_BOUNDS')
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'RETIREMENT_DUPLICATE_KEY')
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs)
        need(type(value) is dict and canonical(value) == raw, 'RETIREMENT_CANONICAL_JSON_REQUIRED')
        return value
    except RetirementError:
        raise
    except Exception:
        raise RetirementError('RETIREMENT_JSON_INVALID') from None


def relative(value):
    need(type(value) is str and 0 < len(value) <= 500 and '\\' not in value
         and ':' not in value and '\x00' not in value, 'RETIREMENT_RELATIVE_PATH_REQUIRED')
    path = PurePosixPath(value)
    need(not path.is_absolute() and str(path) == value and all(
        part not in ('', '.', '..') for part in path.parts), 'RETIREMENT_RELATIVE_PATH_REQUIRED')
    return value


def utc(value):
    need(type(value) is str and re.fullmatch(
        r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', value),
        'RETIREMENT_UTC_REQUIRED')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise RetirementError('RETIREMENT_UTC_REQUIRED') from None


def _safe_source(path, *, directory=False):
    path = Path(path).absolute()
    need(path.resolve() == path, 'RETIREMENT_SOURCE_LINK_FORBIDDEN')
    for member in (path, *path.parents):
        info = member.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
             'RETIREMENT_SOURCE_LINK_FORBIDDEN')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) if directory else
         stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_FILE,
         'RETIREMENT_SOURCE_UNSAFE')
    return path


def _source_read(path):
    path = _safe_source(path)
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
         == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
         and len(raw) == before.st_size, 'RETIREMENT_SOURCE_CHANGED_DURING_READ')
    return raw


def _held_journal_lock_read(journal):
    """Copy the single lock byte through the genuine lease's owning handle."""
    from qa.operator.failed_verification import HeldOperatorLock
    lease = journal._held
    need(type(lease) is HeldOperatorLock, 'RETIREMENT_ACTUAL_SOURCE_LEASE_REQUIRED')
    lease.require_active(journal.release, journal.root)
    path = _safe_source(journal.root / 'worker.lock')
    stream = lease._stream
    before, current = os.fstat(stream.fileno()), path.stat()
    # Preserve each API's own ctime: Windows path/fd ctime representations
    # need not match even though both refer to the same unchanged lock file.
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode, info.st_nlink)
    stable = lambda info: (*identity(info), info.st_ctime_ns)
    need(identity(before) == identity(current) and before.st_size == 1
         and stat.S_ISREG(before.st_mode) and before.st_nlink == current.st_nlink == 1,
         'RETIREMENT_SOURCE_LOCK_IDENTITY_CHANGED')
    position = stream.tell()
    try:
        stream.seek(0)
        raw = stream.read(2)
    finally:
        stream.seek(position)
    lease.require_active(journal.release, journal.root)
    need(raw == b'0' and stable(os.fstat(stream.fileno())) == stable(before)
         and stable(path.stat()) == stable(current), 'RETIREMENT_SOURCE_LOCK_BYTES_CHANGED')
    return raw


def _reader_sources():
    return {name: sha(_source_read(Path(__file__).with_name(name))) for name in
            ('retirement_handoff.py', 'retirement_remote.py', 'preactivation_retirement.py')}


def _destination_manifest(manifest):
    """Run the genuine new bridge's pure validator in either source namespace.

    Windows export intentionally has the original G package selected. Importing
    ``qa.operator.product_queue_transport`` there would choose the old validator,
    while replacing that module would corrupt the live read-only context. Load
    only the exact measured new validator definitions and their declared pure
    constants, without imports, dispatch, or any old namespace modification.
    The already-approved JSN target contract is identical on both sides and the
    destination is additionally compared to every original manifest below.
    """
    from qa.operator import contracts
    need(type(manifest) is dict, 'RETIREMENT_DESTINATION_MANIFEST_INVALID')
    def plain(value, depth=0):
        need(depth <= 40, 'RETIREMENT_DESTINATION_MANIFEST_INVALID')
        if type(value) is dict:
            need(all(type(key) is str for key in value), 'RETIREMENT_DESTINATION_MANIFEST_INVALID')
            for item in value.values():
                plain(item, depth + 1)
        elif type(value) is list:
            for item in value:
                plain(item, depth + 1)
        else:
            need(type(value) in (str, int, bool, type(None)), 'RETIREMENT_DESTINATION_MANIFEST_INVALID')
    plain(manifest)
    target = contracts.FIXED_TARGET
    need(type(target) is dict and set(target) == {'compartment_id', 'database_id', 'region', 'db_name', 'instance_id'}
         and all(type(value) is str for value in target.values()), 'RETIREMENT_DESTINATION_TARGET_CONTRACT_INVALID')
    raw = _source_read(Path(__file__).with_name('product_queue_transport.py'))
    need(type(manifest.get('code')) is dict
         and manifest['code'].get('product_queue_transport.py') == sha(raw),
         'RETIREMENT_DESTINATION_VALIDATOR_SOURCE_CHANGED')
    constants = {'SCOPE', 'PROJECT_SCOPE', 'HOSTED_SCOPE', 'TARGET', 'MODULES', 'CODE',
                 'HOSTED_CODE', 'PROJECT_MODULES', 'PROJECT_QUEUE_MODULES', 'PROJECT_HASHES'}
    definitions = {'QueueTransportError', '_require', '_sha', '_profile_reference', 'validate_release'}
    nodes, selected = [], []
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in constants:
                nodes.append(node)
                selected.append(name)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in definitions:
            nodes.append(node)
            selected.append(node.name)
    need(len(selected) == len(constants | definitions) and set(selected) == constants | definitions,
         'RETIREMENT_DESTINATION_VALIDATOR_SHAPE_CHANGED')
    allowed_calls = {'PurePosixPath', 'QueueTransportError', '_profile_reference', '_require', '_sha',
        'all', 'dict', 'len', 'set', 'str', 'type', 're.fullmatch', 'host.endswith', 'manifest.get',
        "manifest['images'].values", 'manifest[name].values', 'parsed.is_absolute', 'project[name].values',
        '{1: SCOPE, 2: PROJECT_SCOPE, 3: HOSTED_SCOPE}.get'}
    signatures = {'_require': ('ok', 'code'), '_sha': ('value',),
                  '_profile_reference': ('value',), 'validate_release': ('manifest',)}
    for node in nodes:
        need(not isinstance(node, (ast.FunctionDef, ast.ClassDef)) or not node.decorator_list,
             'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
        if isinstance(node, ast.FunctionDef):
            args = node.args
            need(tuple(arg.arg for arg in args.args) == signatures[node.name]
                 and not args.posonlyargs and not args.defaults and args.vararg is args.kwarg is None
                 and all(arg.annotation is None for arg in (*args.args, *args.kwonlyargs))
                 and node.returns is None, 'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
            need((node.name == '_profile_reference' and len(args.kwonlyargs) == len(args.kw_defaults) == 1
                  and args.kwonlyargs[0].arg == 'with_host_path' and isinstance(args.kw_defaults[0], ast.Constant)
                  and args.kw_defaults[0].value is False)
                 or (node.name != '_profile_reference' and not args.kwonlyargs and not args.kw_defaults),
                 'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
        if isinstance(node, ast.ClassDef):
            need(node.name == 'QueueTransportError' and not node.keywords
                 and len(node.bases) == 1 and isinstance(node.bases[0], ast.Name)
                 and node.bases[0].id == 'RuntimeError'
                 and all(isinstance(item, ast.Pass) or isinstance(item, ast.Expr)
                     and isinstance(item.value, ast.Constant) and type(item.value.value) is str
                     for item in node.body), 'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
        for child in ast.walk(node):
            need(not isinstance(child, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
                ast.AsyncFunctionDef, ast.Await, ast.Yield, ast.YieldFrom, ast.Lambda, ast.NamedExpr)),
                'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
            need(not isinstance(child, ast.Attribute) or not isinstance(child.ctx, (ast.Store, ast.Del)),
                 'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
            if isinstance(child, ast.Subscript) and isinstance(child.ctx, (ast.Store, ast.Del)):
                need(isinstance(child.ctx, ast.Store) and isinstance(child.value, ast.Name)
                     and child.value.id == 'result' and isinstance(child.slice, ast.Constant)
                     and child.slice.value in ('opaf_profile', 'project'),
                     'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
            need(not isinstance(child, ast.Name) or not child.id.startswith('__'),
                 'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
            need(not isinstance(child, ast.Attribute) or not child.attr.startswith('__'),
                 'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
            need(child is node or not isinstance(child, (ast.FunctionDef, ast.ClassDef)),
                 'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
            if isinstance(child, ast.Call):
                need(ast.unparse(child.func) in allowed_calls, 'RETIREMENT_DESTINATION_VALIDATOR_BOUNDARY_CHANGED')
    namespace = {'re': SimpleNamespace(fullmatch=re.fullmatch), 'PurePosixPath': PurePosixPath,
                 'C': SimpleNamespace(FIXED_TARGET=dict(target))}
    try:
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<measured-destination-validator>', 'exec'), namespace)
        checked = namespace['validate_release'](manifest)
    except Exception:
        raise RetirementError('RETIREMENT_DESTINATION_MANIFEST_INVALID') from None
    need(checked['schema_version'] == 3 and checked['scope'] == 'fox-product-verifier-release-v3',
         'RETIREMENT_HOSTED_V3_REQUIRED')
    return checked


def _destination(manifest_raw, configuration_raw, historical):
    manifest, configuration = _destination_manifest(parse(manifest_raw)), parse(configuration_raw)
    need(manifest.get('enabled') is True and set(manifest.get('images', {})) == {'fox', 'converter'}
         and all(type(x) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', x)
                 for x in manifest['images'].values()), 'RETIREMENT_DESTINATION_INVALID')
    need(set(configuration) == {'schema_version', 'scope', 'provider_configuration_sha256',
         'current_release_sha256', 'infrastructure'}
         and configuration.get('scope') == 'fox-hosted-admission-v1'
         and configuration.get('schema_version') == 1
         and type(configuration['schema_version']) is int
         and type(configuration['provider_configuration_sha256']) is str
         and SHA.fullmatch(configuration['provider_configuration_sha256'])
         and configuration['provider_configuration_sha256'] == manifest['hosted_runtime_configuration_sha256']
         and configuration['current_release_sha256'] == sha(manifest_raw),
         'RETIREMENT_HOSTED_CONFIGURATION_REQUIRED')
    infrastructure = configuration['infrastructure']
    need(type(infrastructure) is dict and set(infrastructure) ==
         {'fox', 'forms2apex-mcp', 'oracle-applied-ai-label'}, 'RETIREMENT_DESTINATION_INFRASTRUCTURE_REQUIRED')
    for row in infrastructure.values():
        need(type(row) is dict and set(row) == {'id', 'image'}
             and type(row['id']) is str and SHA.fullmatch(row['id'])
             and type(row['image']) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', row['image']),
             'RETIREMENT_DESTINATION_INFRASTRUCTURE_INVALID')
    need(len({row['id'] for row in infrastructure.values()}) == 3
         and infrastructure['fox']['image'] == manifest['images']['fox']
         and infrastructure['forms2apex-mcp']['image'] == manifest['images']['converter'],
         'RETIREMENT_DESTINATION_INFRASTRUCTURE_INVALID')
    sources = _reader_sources()
    need(all(manifest.get('code', {}).get(name) == digest for name, digest in sources.items()),
         'RETIREMENT_DESTINATION_READER_SOURCE_UNBOUND')
    for old_raw in historical:
        old = parse(old_raw)
        need(sha(manifest_raw) != sha(old_raw) and old.get('target') == manifest.get('target')
             and all(manifest['images'][name] != old['images'][name] for name in ('fox', 'converter')),
             'RETIREMENT_DISTINCT_PAIRED_RELEASE_REQUIRED')
    return {'release_sha256': sha(manifest_raw), 'configuration_sha256': sha(configuration_raw),
            'provider_configuration_sha256': configuration['provider_configuration_sha256'],
            'infrastructure': infrastructure, 'images': manifest['images'], 'reader_sources': sources}


def _runtime(runtime):
    # The exporter is imported *inside* the approved I environment. Importing
    # this new module on the hosted machine never imports the old package.
    try:
        from qa.operator.preactivation_retirement import PreActivationRetirementContext
    except ImportError:
        PreActivationRetirementContext = None
    if PreActivationRetirementContext is not None and type(runtime) is PreActivationRetirementContext:
        need(os.name == 'nt', 'RETIREMENT_INSTALLED_WINDOWS_RUNTIME_REQUIRED')
        runtime.require_active()
        need(runtime.idle_reader is not None and runtime.idle_reader.native._test_open is None,
             'RETIREMENT_REAL_WINDOWS_OBSERVER_REQUIRED')
        return 'preactivation-g-v1'
    try:
        from qa.operator.installed_runtime import InstalledRuntime
        from qa.operator.recorded_native import RecordedNativeObserver
    except ImportError:
        raise RetirementError('RETIREMENT_INSTALLED_WINDOWS_RUNTIME_REQUIRED') from None
    need(os.name == 'nt' and type(runtime) is InstalledRuntime,
         'RETIREMENT_INSTALLED_WINDOWS_RUNTIME_REQUIRED')
    need(runtime.idle_reader is not None and type(runtime.idle_reader.native) is RecordedNativeObserver
         and runtime.idle_reader.native._test_open is None
         and runtime.idle_reader.native.profile == 'recorded-legacy-g-v1',
         'RETIREMENT_REAL_WINDOWS_OBSERVER_REQUIRED')
    runtime.require_active()
    return 'installed-i-v1'


def _source_files(runtime, context):
    if context == 'preactivation-g-v1':
        files = runtime.source_files()
        need(type(files) is dict and 0 < len(files) <= 4096, 'RETIREMENT_SOURCE_INVENTORY_REQUIRED')
        for name, raw in files.items():
            relative(name)
            need(type(raw) is bytes and 0 < len(raw) <= MAX_FILE, 'RETIREMENT_SOURCE_FILE_INVALID')
        return files
    root = Path(inspect.getfile(type(runtime))).resolve().parents[2]
    paths = [*('qa/operator/' + name for name in runtime.manifest['code']),
             *('fox/fox/' + name for name in runtime.manifest['modules'])]
    return {name: _source_read(root / name) for name in paths}


def retirement_plan(runtime, *, destination_manifest_raw, destination_configuration_raw):
    """Read-only review document. Caller must independently authorize its SHA.

    The same actual I leases are required for review and export. This function
    does not close an open idle session or infer permission to do so.
    """
    context = _runtime(runtime)
    authority_raw = runtime.authority_manifest_raw if context == 'preactivation-g-v1' else runtime.current_raw
    old = [runtime.current_raw, authority_raw, *(runtime.historical_raw[role] for role in ROLES)]
    destination = _destination(destination_manifest_raw, destination_configuration_raw, old)
    files = _source_files(runtime, context)
    sources = {name: sha(raw) for name, raw in files.items()}
    required = {**{'qa/operator/' + name: digest for name, digest in runtime.manifest['code'].items()},
                **{'fox/fox/' + name: digest for name, digest in runtime.manifest['modules'].items()}}
    need(all(sources.get(name) == digest for name, digest in required.items()), 'RETIREMENT_SOURCE_CHANGED')
    return {'schema_version': 1, 'scope': PLAN_SCOPE, 'source_release_sha256': runtime.release,
        'source_context': context, 'source_authority_release_sha256': sha(authority_raw),
        'source_configuration_sha256': runtime.configuration_sha256,
        'source_reader_files': sources, 'history': runtime.history, 'destination': destination,
        'source_provenance': {**{role: str(runtime.journals[role].root) for role in ROLES},
                              'native': str(runtime.idle_reader.native.state_root)},
        'deployment_authorized': False, 'human_acceptance_recorded': False,
        'automatic_replay_permitted': False}


@dataclass(frozen=True)
class RetirementBundle:
    """Detached export bytes; callers save create-only outside original roots."""
    attestation_raw: bytes
    members: tuple[tuple[str, bytes], ...]

    @property
    def attestation_sha256(self):
        return sha(self.attestation_raw)


def export_retirement_under_lock(runtime, *, destination_manifest_raw,
                                 destination_configuration_raw, authorized_plan_sha256):
    """Validate the real original closure/history and return an immutable copy.

    Root must first execute the existing ``close_idle_under_lock`` explicitly.
    No synthetic observation, callback, alternate PID probe, or closure shortcut
    is accepted here. Source changes demand a separately approved new plan/hash.
    """
    plan = retirement_plan(runtime, destination_manifest_raw=destination_manifest_raw,
                           destination_configuration_raw=destination_configuration_raw)
    need(type(authorized_plan_sha256) is str and SHA.fullmatch(authorized_plan_sha256)
         and sha(canonical(plan)) == authorized_plan_sha256, 'RETIREMENT_PLAN_NOT_AUTHORIZED')
    result = runtime.history_read_under_lock(for_startup=False)
    expected_status = 'PREACTIVATION_HISTORY_READY' if plan['source_context'] == 'preactivation-g-v1' else 'INSTALLED_HISTORY_READY'
    need(result.get('status') == expected_status and result.get('release_sha256') == runtime.release,
         'RETIREMENT_ORIGINAL_TYPED_HISTORY_NOT_READY')
    resolver = runtime.components.resolver
    acknowledgement = resolver._validated_closed_under_lock(runtime.journals['failure']._held)
    _, evidence = resolver._local()
    retry = runtime.completed_retry_binding()
    members = {}
    def put(name, raw):
        relative(name)
        need(name not in members and type(raw) is bytes and 0 < len(raw) <= MAX_FILE,
             'RETIREMENT_ARCHIVE_MEMBER_INVALID')
        members[name] = raw
    def private_tree(root, prefix, journal=None):
        root = _safe_source(root, directory=True)
        need(journal is None or journal.root == root, 'RETIREMENT_JOURNAL_ROOT_CHANGED')
        for path in sorted(root.rglob('*')):
            _safe_source(path, directory=path.is_dir())
            runtime.components.product.promotion.private_inputs([path])
            if path.is_file():
                raw = (_held_journal_lock_read(journal) if journal is not None
                       and path == journal.root / 'worker.lock' else _source_read(path))
                put(prefix + '/' + path.relative_to(root).as_posix(), raw)
    for role in ROLES:
        journal = runtime.journals[role]
        need({path.name for path in journal.root.iterdir()} ==
             {'worker.lock', 'release.json', runtime.history[role]['session_id']},
             'RETIREMENT_UNKNOWN_OR_EXTRA_SOURCE_SESSION')
        private_tree(journal.root, 'journals/' + role, journal=journal)
        put('manifests/' + role + '.json', runtime.historical_raw[role])
    native = runtime.idle_reader.native
    need({path.name for path in native.state_root.iterdir()} == NATIVE_RECORDS,
         'RETIREMENT_NATIVE_UNFINISHED_OR_UNKNOWN')
    private_tree(native.state_root, 'native')
    put('failure-evidence/plan.json', evidence['plan_raw'])
    put('failure-evidence/apex-package.zip', evidence['package'])
    put('failure-evidence/collection-manifest.json', evidence['collection_raw'])
    put('failure-evidence/journal-summary.json', canonical(evidence['journal_summary']))
    for name, raw in evidence['files'].items():
        put('failure-evidence/collection/' + name, raw)
    put('failure-evidence/reviewed-wrapper.sh', evidence['wrapper_raw'])
    for name, raw in _source_files(runtime, plan['source_context']).items():
        put('source/' + name, raw)
    put('source/manifest.json', runtime.current_raw)
    put('source/authority-manifest.json', runtime.authority_manifest_raw
        if plan['source_context'] == 'preactivation-g-v1' else runtime.current_raw)
    if plan['source_context'] == 'preactivation-g-v1':
        put('source/authority-configuration.json', runtime.authority_configuration_raw)
    put('source/configuration.json', canonical(runtime.configuration))
    put('destination/manifest.json', destination_manifest_raw)
    put('destination/configuration.json', destination_configuration_raw)
    idle_path = 'journals/idle/' + runtime.history['idle']['session_id'] + '/closed-idle.json'
    closure = parse(members[idle_path])
    history = {
        'failure': {key: runtime.history['failure'][key] for key in
                    ('release_sha256', 'session_id', 'job_id', 'disposition_sha256')},
        'retry': {**retry, 'session_id': runtime.history['retry']['session_id']},
        'idle': {'release_sha256': runtime.history['idle']['release_sha256'],
                 'session_id': runtime.history['idle']['session_id'],
                 'completed_jobs': closure['completed_jobs']}}
    history['failure']['disposition'] = acknowledgement['disposition']
    need(retirement_plan(runtime, destination_manifest_raw=destination_manifest_raw,
                         destination_configuration_raw=destination_configuration_raw) == plan,
         'RETIREMENT_SOURCE_PLAN_CHANGED')
    # Re-run genuine typed history checks after capturing every byte. They
    # include original Windows absence and exact remote proof/inventory reads.
    runtime.history_read_under_lock(for_startup=False)
    attestation = {'schema_version': 1, 'scope': SCOPE, 'plan': plan,
        'authorized_plan_sha256': authorized_plan_sha256,
        'issued_at_utc': datetime.now(timezone.utc).isoformat(),
        'history': history, 'original_typed_checks': result,
        'inventory': {name: {'sha256': sha(raw), 'bytes': len(raw)}
                      for name, raw in sorted(members.items())},
        'windows_successful_exit_confirmed': False, 'deployment_authorized': False,
        'human_acceptance_recorded': False, 'automatic_replay_permitted': False}
    raw = canonical(attestation)
    validate_bundle(raw, members, expected_attestation_sha256=sha(raw),
                    expected_release_sha256=plan['destination']['release_sha256'],
                    expected_configuration_sha256=plan['destination']['configuration_sha256'])
    return RetirementBundle(raw, tuple(sorted(members.items())))


def _seal(members, prefix, name):
    seal = parse(members[prefix + '/' + name])
    retained = {key[len(prefix) + 1:]: sha(raw) for key, raw in members.items()
                if key.startswith(prefix + '/') and key != prefix + '/' + name}
    need(all('/' not in name for name in retained) and seal.get('retained_sha256') == retained
         and 'session.json' in retained, 'RETIREMENT_RETAINED_SEAL_CHANGED')
    return seal


def validate_bundle(attestation_raw, members, *, expected_attestation_sha256,
                    expected_release_sha256, expected_configuration_sha256):
    """Pure byte checks. Does not grant admission or assert live process state."""
    need(type(expected_attestation_sha256) is str and SHA.fullmatch(expected_attestation_sha256)
         and sha(attestation_raw) == expected_attestation_sha256, 'RETIREMENT_ATTESTATION_NOT_PINNED')
    value = parse(attestation_raw)
    need(set(value) == {'schema_version', 'scope', 'plan', 'authorized_plan_sha256',
        'issued_at_utc', 'history', 'original_typed_checks', 'inventory',
        'windows_successful_exit_confirmed', 'deployment_authorized',
        'human_acceptance_recorded', 'automatic_replay_permitted'}
        and type(value['schema_version']) is int and value['schema_version'] == 1 and value['scope'] == SCOPE,
        'RETIREMENT_ATTESTATION_SCHEMA_INVALID')
    need(all(value[key] is False for key in ('windows_successful_exit_confirmed', 'deployment_authorized',
         'human_acceptance_recorded', 'automatic_replay_permitted')), 'RETIREMENT_AUTHORITY_EXPANSION')
    need(utc(value['issued_at_utc']) <= datetime.now(timezone.utc), 'RETIREMENT_ATTESTATION_FUTURE')
    plan = value['plan']
    need(type(plan) is dict and plan.get('scope') == PLAN_SCOPE
         and sha(canonical(plan)) == value['authorized_plan_sha256'], 'RETIREMENT_PLAN_CHANGED')
    inventory = value['inventory']
    need(type(members) is dict and 0 < len(members) <= 4096 and type(inventory) is dict
         and set(inventory) == set(members) and sum(len(raw) for raw in members.values()) <= MAX_TOTAL,
         'RETIREMENT_ARCHIVE_INVENTORY_CHANGED')
    for name, raw in members.items():
        relative(name)
        need(type(raw) is bytes and 0 < len(raw) <= MAX_FILE
             and inventory[name] == {'sha256': sha(raw), 'bytes': len(raw)}, 'RETIREMENT_ARCHIVE_BYTES_CHANGED')
    destination = _destination(members['destination/manifest.json'], members['destination/configuration.json'],
        [members['source/manifest.json'], members['source/authority-manifest.json'],
         *(members['manifests/' + role + '.json'] for role in ROLES)])
    need(destination == plan['destination'] and destination['release_sha256'] == expected_release_sha256
         and destination['configuration_sha256'] == expected_configuration_sha256,
         'RETIREMENT_WRONG_DESTINATION')
    need(sha(members['source/manifest.json']) == plan['source_release_sha256']
         and sha(members['source/authority-manifest.json']) == plan['source_authority_release_sha256']
         and sha(members['source/configuration.json']) == plan['source_configuration_sha256'],
         'RETIREMENT_SOURCE_CONFIGURATION_CHANGED')
    source = parse(members['source/manifest.json'])
    required_sources = {
             **{'qa/operator/' + name: digest for name, digest in source['code'].items()},
             **{'fox/fox/' + name: digest for name, digest in source['modules'].items()}}
    need(plan['source_context'] in ('preactivation-g-v1', 'installed-i-v1'), 'RETIREMENT_SOURCE_CONTEXT_INVALID')
    if plan['source_context'] == 'preactivation-g-v1':
        authority = parse(members['source/authority-manifest.json'])
        required_sources.update({
            **{'authority/qa/operator/' + name: digest for name, digest in authority['code'].items()},
            **{'authority/fox/fox/' + name: digest for name, digest in authority['modules'].items()}})
        # Old Windows helper bytes are opaque retained evidence here. Their
        # installation-authorized attestation hash, not importing them into a
        # Linux namespace, is the source authority on this side of the handoff.
        helper = 'preactivation/preactivation_retirement.py'
        need(helper in plan['source_reader_files'], 'RETIREMENT_PREACTIVATION_SOURCE_MISSING')
    need(all(sha(members['source/' + name]) == digest for name, digest in plan['source_reader_files'].items())
         and all(plan['source_reader_files'].get(name) == digest for name, digest in required_sources.items()),
         'RETIREMENT_SOURCE_CLOSURE_CHANGED')
    config = parse(members['source/configuration.json'])
    need(config['history'] == plan['history'], 'RETIREMENT_SOURCE_HISTORY_CHANGED')
    if plan['source_context'] == 'preactivation-g-v1':
        authority_configuration_raw = members['source/authority-configuration.json']
        authority_configuration = parse(authority_configuration_raw)
        need(sha(authority_configuration_raw) == config['authority_configuration_sha256']
             and config['authority_release_sha256'] == plan['source_authority_release_sha256']
             and authority_configuration['current_release_sha256'] == plan['source_authority_release_sha256']
             and authority_configuration['history'] == config['history']
             and authority_configuration['infrastructure'] == config['infrastructure'],
             'RETIREMENT_SOURCE_AUTHORITY_CONFIGURATION_CHANGED')
    history = value['history']
    need(type(history) is dict and set(history) == set(ROLES), 'RETIREMENT_HISTORY_ROLES_REQUIRED')
    for role in ROLES:
        entry = history[role]
        need(type(entry) is dict and SESSION.fullmatch(entry.get('session_id', ''))
             and entry['session_id'] == plan['history'][role]['session_id']
             and entry['release_sha256'] == plan['history'][role]['release_sha256']
             and sha(members['manifests/' + role + '.json']) == entry['release_sha256'],
             'RETIREMENT_HISTORY_RELEASE_CHANGED')
        prefix = 'journals/' + role + '/'
        paths = {name[len(prefix):].split('/')[0] for name in members if name.startswith(prefix)}
        need(paths == {'release.json', 'worker.lock', entry['session_id']}, 'RETIREMENT_UNKNOWN_SOURCE_SESSION')
        session = prefix + entry['session_id']
        header = parse(members[session + '/session.json'])
        need(header.get('release_sha256') == entry['release_sha256']
             and header.get('startup_authorized') is True, 'RETIREMENT_SESSION_HEADER_CHANGED')
    failed, retry, idle = (history[role] for role in ROLES)
    failure_prefix = 'journals/failure/' + failed['session_id']
    closed = _seal(members, failure_prefix, 'closed-failed.json')
    intent_raw = members[failure_prefix + '/failed-resolution.intent.json']
    intent = parse(intent_raw)
    completion = parse(members[failure_prefix + '/failed-resolution.complete.json'])
    expected_ack = {'status': 'FAILED_QA_RECORDED', 'disposition_sha256': failed['disposition_sha256'],
                    'disposition': failed['disposition']}
    need(closed['status'] == 'FAILED_QA_CLOSED' and closed['technical_verification_passed'] is False
         and closed['human_acceptance_recorded'] is closed['automatic_replay_permitted'] is False
         and closed['disposition_sha256'] == failed['disposition_sha256']
         and completion['intent_sha256'] == sha(intent_raw) and completion['acknowledgement'] == expected_ack
         and intent['disposition'] == failed['disposition'] and sha(canonical(failed['disposition'])) == failed['disposition_sha256']
         and failed['disposition']['binding']['verifier_release_sha256'] == failed['release_sha256']
         and failed['disposition']['binding']['job_id'] == failed['job_id'] == retry['job_id'],
         'RETIREMENT_FAILED_CLOSURE_CHANGED')
    _failure_evidence(members, failed, plan['history']['failure'])
    retry_prefix = 'journals/retry/' + retry['session_id']
    terminal = _seal(members, retry_prefix, 'reconciled.json')
    need(sha(members[retry_prefix + '/reconciled.json']) == plan['history']['retry']['seal_sha256']
         and terminal['status'] == 'PROOF_RECONCILED' and terminal['automatic_replay_permitted'] is False
         and all(terminal[key] == retry[key] for key in ('release_sha256', 'attempt_id', 'job_id', 'proof_sha256')),
         'RETIREMENT_RETRY_PROOF_CHANGED')
    for label, expected in (
        ('proof-reconcile', {key: terminal[key] for key in terminal if key != 'retained_sha256'}),
        ('p0001-continuation-promotion-apply', {'status': 'VERIFIED', 'job_id': retry['job_id'],
            'human_acceptance_recorded': False, 'proof_sha256': retry['proof_sha256']})):
        step_intent = members[retry_prefix + '/' + label + '.intent.json']
        step = parse(members[retry_prefix + '/' + label + '.complete.json'])
        need(step.get('release_sha256') == retry['release_sha256']
             and step.get('intent_sha256') == sha(step_intent) and step.get('result') == expected,
             'RETIREMENT_RETRY_COMPLETION_CHANGED')
    idle_prefix = 'journals/idle/' + idle['session_id']
    closure = _seal(members, idle_prefix, 'closed-idle.json')
    expected_scope = ('fox-preactivation-interrupted-idle-closure-v1' if plan['source_context'] == 'preactivation-g-v1'
                      else 'fox-interrupted-idle-closure-v1')
    need(closure['scope'] == expected_scope and closure['schema_version'] == 1
         and closure['status'] == 'INTERRUPTED_IDLE_CLOSED' and closure['release_sha256'] == idle['release_sha256']
         and closure['session_id'] == idle['session_id'] and closure['completed_jobs'] == idle['completed_jobs']
         and closure['successful_native_exit_confirmed'] is closure['automatic_replay_permitted']
         is closure['human_acceptance_recorded'] is False, 'RETIREMENT_IDLE_CLOSURE_CHANGED')
    if plan['source_context'] == 'preactivation-g-v1':
        original_plan = closure.get('retirement_plan')
        transcript = {key: closure[key] for key in ('session_id', 'release_sha256',
                      'claim_count', 'completed_jobs', 'retained_sha256')}
        need(type(original_plan) is dict and closure.get('source_context') == 'preactivation-g-v1'
             and sha(canonical(original_plan)) == closure.get('authorized_plan_sha256')
             and original_plan.get('scope') == 'fox-preactivation-idle-retirement-plan-v1'
             and original_plan.get('source_context') == 'preactivation-g-v1'
             and original_plan.get('runtime_release_sha256') == idle['release_sha256'] == plan['source_release_sha256']
             and original_plan.get('authority_release_sha256') == plan['source_authority_release_sha256']
             and original_plan.get('configuration_sha256') == plan['source_configuration_sha256']
             and original_plan.get('source_reader_files') == plan['source_reader_files']
             and original_plan.get('history') == plan['history']
             and original_plan.get('transcript_sha256') == sha(canonical(transcript))
             and original_plan.get('runtime_container_id') == value['original_typed_checks'].get('current_container_id')
             and original_plan.get('closure_name') == 'closed-idle.json'
             and original_plan.get('closure_scope') == expected_scope
             and all(original_plan.get(key) is False for key in ('successful_native_exit_confirmed',
                 'deployment_authorized', 'human_acceptance_recorded', 'automatic_replay_permitted')),
             'RETIREMENT_PREACTIVATION_PLAN_CHANGED')
    _idle_transcript(members, idle_prefix, closure)
    native = {name[7:]: sha(raw) for name, raw in members.items() if name.startswith('native/')}
    need(set(native) == NATIVE_RECORDS and native['source.json'] == plan['history']['idle']['native_source_sha256'],
         'RETIREMENT_NATIVE_ARCHIVE_CHANGED')
    observations = closure['observation']
    before, after = (observations[key] for key in ('native_before', 'native_after'))
    for observed in (before, after):
        need(observed['retained_sha256'] == native
             and observed['source_sha256'] == native['source.json']
             and observed['verifier_release_sha256'] == idle['release_sha256']
             and observed['successful_exit_confirmed'] is False
             and set(observed['processes']) == {'worker', 'watchdog'}
             and all(x in ('ABSENT_UNCONFIRMED', 'ORIGINAL_ABSENT_PID_REUSED') for x in observed['processes'].values()),
             'RETIREMENT_ORIGINAL_ABSENCE_CHECK_CHANGED')
    need(0 <= (utc(after['observed_at_utc']) - utc(before['observed_at_utc'])).total_seconds() <= 150
         and 0 <= (utc(closure['closed_at_utc']) - utc(after['observed_at_utc'])).total_seconds() <= 30,
         'RETIREMENT_ORIGINAL_CLOSURE_TIME_CHANGED')
    need(observations['remote']['completed_jobs'] == idle['completed_jobs']
         and observations['remote']['require_idle'] is True and observations['remote']['read_only'] is True,
         'RETIREMENT_ORIGINAL_REMOTE_CHECK_CHANGED')
    expected_status = 'PREACTIVATION_HISTORY_READY' if plan['source_context'] == 'preactivation-g-v1' else 'INSTALLED_HISTORY_READY'
    need(value['original_typed_checks'].get('status') == expected_status
         and value['original_typed_checks'].get('release_sha256') == plan['source_release_sha256']
         and value['original_typed_checks'].get('for_startup') is False,
         'RETIREMENT_ORIGINAL_TYPED_CHECKS_CHANGED')
    return json.loads(canonical(value))


def _idle_transcript(members, prefix, closure):
    """The v1 IDLE closure never waives an unmatched original operation."""
    names = closure['retained_sha256']
    claims = sorted(name for name in names if re.fullmatch(r'p[0-9]{4}-claim.intent.json', name))
    need(bool(claims) and len(claims) == closure['claim_count'], 'RETIREMENT_IDLE_CLAIMS_CHANGED')
    for name in names:
        if name == 'session.json':
            continue
        need(re.fullmatch(r'p[0-9]{4}-[a-z-]+\.(?:intent|complete)\.json', name),
             'RETIREMENT_IDLE_UNKNOWN_OPERATION')
        if name.endswith('.intent.json'):
            complete_name = name[:-12] + '.complete.json'
            need(complete_name in names, 'RETIREMENT_IDLE_UNMATCHED_OPERATION')
            raw = members[prefix + '/' + name]
            intent = parse(raw)
            complete = parse(members[prefix + '/' + complete_name])
            need(intent.get('release_sha256') == complete.get('release_sha256') == closure['release_sha256']
                 and complete.get('intent_sha256') == sha(raw), 'RETIREMENT_IDLE_STEP_CHANGED')
        else:
            need(name[:-14] + '.intent.json' in names, 'RETIREMENT_IDLE_UNMATCHED_OPERATION')
    need(claims == ['p' + str(i).zfill(4) + '-claim.intent.json' for i in range(1, len(claims) + 1)]
         and parse(members[prefix + '/' + claims[-1][:-12] + '.complete.json'])['result'] == {'status': 'IDLE'},
         'RETIREMENT_LAST_CLAIM_NOT_IDLE')
    # Reuse the current normal pump's pure claim/phase validators. No source
    # code is imported from the archived Windows artifact.
    from qa.operator import product_verifier as api
    manifest = parse(members['manifests/idle.json'])
    expected_names, jobs = {'session.json'}, []
    def step(label, binding):
        expected_names.update((label + '.intent.json', label + '.complete.json'))
        intent = parse(members[prefix + '/' + label + '.intent.json'])
        need(intent == {'scope': 'fox-product-verifier-step-v1', 'release_sha256': closure['release_sha256'],
            'step': label, 'binding_sha256': sha(canonical(binding.payload())) if binding else None},
            'RETIREMENT_IDLE_INTENT_CHANGED')
        return parse(members[prefix + '/' + label + '.complete.json'])['result']
    for index in range(1, len(claims) + 1):
        label = 'p' + str(index).zfill(4)
        result = step(label + '-claim', None)
        if result == {'status': 'IDLE'}:
            continue
        need(type(result) is dict and set(result) == {'status', 'claim'} and result['status'] == 'CLAIMED'
             and index != len(claims), 'RETIREMENT_IDLE_CLAIM_CHANGED')
        claim = api._claim(result['claim'], closure['release_sha256'])
        context = {}
        for phase in api.STEPS:
            result = step(label + '-' + phase.replace('_', '-'), claim.binding)
            if phase == 'queue_complete':
                need(result == {'status': 'COMPLETED', 'job_id': claim.binding.job_id,
                    'proof_sha256': context['proof_sha256']}, 'RETIREMENT_IDLE_PROOF_CHANGED')
            else:
                context.update(api.safe_phase(phase, result, claim.binding, context, manifest))
                if phase == 'qa_run':
                    need(result['status'] == 'PASSED' and result['exit_code'] == 0, 'RETIREMENT_IDLE_FAILED_QA')
        jobs.append({'binding': claim.binding.payload(), 'proof_sha256': context['proof_sha256']})
    header = parse(members[prefix + '/session.json'])
    bounds = header['bounds']
    need(set(names) == expected_names and jobs == closure['completed_jobs']
         and len({item['binding']['job_id'] for item in jobs}) == len(jobs)
         and len(jobs) < bounds['max_jobs'] and len(claims) <= bounds['max_polls'],
         'RETIREMENT_IDLE_TRANSCRIPT_CHANGED')


def _failure_evidence(members, failed, config):
    """Revalidate raw copied C evidence with the genuine current backend gate.

    Plan path strings are never resolved. The full summary was derived by the
    typed Windows resolver before export and is separately disposition-bound.
    """
    from fox import verification_recovery as recovery
    from fox.verification_queue import VerificationBinding
    collection_raw = members['failure-evidence/collection-manifest.json']
    collection = parse(collection_raw)
    files = {name[len('failure-evidence/collection/'):]: raw for name, raw in members.items()
             if name.startswith('failure-evidence/collection/')}
    need(sha(collection_raw) == config['collection_sha256']
         and collection.get('credentials_and_logs_excluded') is True
         and collection.get('sha256') == {name: sha(raw) for name, raw in files.items()}
         and files.get('package.zip') == members['failure-evidence/apex-package.zip']
         and collection.get('plan_sha256') == sha(members['failure-evidence/plan.json'])
         and sha(members['failure-evidence/reviewed-wrapper.sh']) == config['wrapper_sha256'],
         'RETIREMENT_FAILURE_EVIDENCE_BYTES_CHANGED')
    document = failed['disposition']
    summary = parse(members['failure-evidence/journal-summary.json'])
    prefix = 'journals/failure/' + failed['session_id'] + '/'
    resolution = {'closed-failed.json', 'failed-resolution.intent.json', 'failed-resolution.complete.json'}
    original = {name[len(prefix):]: raw for name, raw in members.items()
                if name.startswith(prefix) and name[len(prefix):] not in resolution}
    need(document['session_id'] == summary['session_id'] == failed['session_id']
         and summary['release_sha256'] == failed['release_sha256']
         and summary['retained_sha256'] == {name: sha(raw) for name, raw in original.items()},
         'RETIREMENT_FAILED_JOURNAL_SUMMARY_UNBOUND')
    claims = sorted(name for name in original if re.fullmatch(r'p[0-9]{4}-claim.intent.json', name))
    need(bool(claims), 'RETIREMENT_FAILED_CLAIM_MISSING')
    final_claim = parse(original[claims[-1][:-12] + '.complete.json'])['result']['claim']
    need(final_claim['binding'] == document['binding']
         and sha(canonical(final_claim)) == summary['claim_sha256'], 'RETIREMENT_FAILED_CLAIM_CHANGED')
    phase_prefix = claims[-1][:5]
    for phase, recorded in summary['phases'].items():
        label = phase_prefix + '-' + phase.replace('_', '-')
        intent_raw = original[label + '.intent.json']
        completed_raw = original[label + '.complete.json']
        completed = parse(completed_raw)
        need(recorded['intent_sha256'] == sha(intent_raw) == completed['intent_sha256']
             and recorded['completion_sha256'] == sha(completed_raw)
             and canonical(recorded['result']) == canonical(completed['result']),
             'RETIREMENT_FAILED_PHASE_BYTES_CHANGED')
    reviewed = recovery.ReviewedSynchronousLaunch(failed['release_sha256'], config['qa_source_sha256'],
        config['wrapper_sha256'], config['original_wrapper_sha256'], config['qa_image_id'])
    actual = recovery.validate_failed_evidence(
        binding=VerificationBinding.from_payload(document['binding']),
        package=members['failure-evidence/apex-package.zip'],
        plan_raw=members['failure-evidence/plan.json'], collection_raw=collection_raw, files=files,
        journal_summary=summary,
        producer=document['producer'], now=utc(document['producer']['observed_at_utc']),
        wrapper_raw=members['failure-evidence/reviewed-wrapper.sh'], reviewed_synchronous_launch=reviewed)
    need(actual == document, 'RETIREMENT_FAILED_EVIDENCE_REVALIDATION_CHANGED')


class RetirementArchive:
    """Owner-private immutable copied tree, anchored by installer-owned SHA."""
    def __init__(self, root, *, attestation_sha256, release_sha256, configuration_sha256):
        self.root = Path(root).absolute()
        self.attestation_sha256 = attestation_sha256
        self.release_sha256, self.configuration_sha256 = release_sha256, configuration_sha256

    def read(self):
        from qa.operator import runtime_provider as provider
        need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'RETIREMENT_HOSTED_POSIX_REQUIRED')
        provider._private_directory(self.root)
        raw = provider._read(self.root / 'attestation.json', MAX_FILE, private=True)
        need(sha(raw) == self.attestation_sha256, 'RETIREMENT_ATTESTATION_NOT_PINNED')
        inventory = parse(raw).get('inventory')
        need(type(inventory) is dict and 0 < len(inventory) <= 4096
             and 'attestation.json' not in inventory, 'RETIREMENT_ARCHIVE_INVENTORY_INVALID')
        total = 0
        for name, item in inventory.items():
            relative(name)
            need(type(item) is dict and set(item) == {'sha256', 'bytes'}
                 and type(item['bytes']) is int and 0 < item['bytes'] <= MAX_FILE
                 and type(item['sha256']) is str and SHA.fullmatch(item['sha256']),
                 'RETIREMENT_ARCHIVE_INVENTORY_INVALID')
            total += item['bytes']
            need(total <= MAX_TOTAL, 'RETIREMENT_ARCHIVE_SIZE_EXCEEDED')
        expected_dirs = {str(parent) for name in inventory for parent in PurePosixPath(name).parents
                         if str(parent) != '.'}
        need(len(expected_dirs) <= 8192, 'RETIREMENT_ARCHIVE_DIRECTORY_BOUNDS')
        members, directories, pending = {}, set(), [self.root]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    name = relative(path.relative_to(self.root).as_posix())
                    need(not entry.is_symlink(), 'RETIREMENT_ARCHIVE_LINK_FORBIDDEN')
                    if entry.is_dir(follow_symlinks=False):
                        need(name in expected_dirs, 'RETIREMENT_ARCHIVE_DIRECTORY_INVENTORY_CHANGED')
                        provider._private_directory(path)
                        directories.add(name)
                        pending.append(path)
                    elif name != 'attestation.json':
                        # Reject unpinned extras before opening/allocating them.
                        need(name in inventory, 'RETIREMENT_ARCHIVE_INVENTORY_CHANGED')
                        members[name] = provider._read(path, inventory[name]['bytes'], private=True)
        need(directories == expected_dirs, 'RETIREMENT_ARCHIVE_DIRECTORY_INVENTORY_CHANGED')
        need(provider._read(self.root / 'attestation.json', MAX_FILE, private=True) == raw,
             'RETIREMENT_ATTESTATION_CHANGED_DURING_READ')
        return validate_bundle(raw, members, expected_attestation_sha256=self.attestation_sha256,
            expected_release_sha256=self.release_sha256,
            expected_configuration_sha256=self.configuration_sha256)

    def require_admission_under_lock(self, lease, *, current_root, current_release, reader,
                                     for_startup=True):
        """Supervisor seam: real current lease + concrete fresh proof reader.

        Invoke inside the normal ProductVerifier's *own* lock before creating
        its fresh session. Never acquire another nested pump lock or interpret
        the returned receipt as permission to deploy, replay or accept.
        """
        from qa.operator.failed_verification import HeldOperatorLock
        from qa.operator.retirement_remote import RetiredHistoryRemoteReader
        from qa.operator import runtime_provider
        need(type(lease) is HeldOperatorLock and current_release == self.release_sha256
             and type(for_startup) is bool, 'RETIREMENT_ACTUAL_CURRENT_LEASE_REQUIRED')
        lease.require_active(current_release, current_root)
        provider = runtime_provider.hosted()
        need(type(provider) is runtime_provider.HostedProvider,
             'RETIREMENT_INSTALLED_HOSTED_PROVIDER_REQUIRED')
        need(Path(current_root).absolute() == provider.path('journal') / current_release[:16],
             'RETIREMENT_CURRENT_JOURNAL_ROOT_CHANGED')
        private = provider.path('handoff')
        need(self.root != private and private in self.root.parents,
             'RETIREMENT_ARCHIVE_OUTSIDE_INSTALLED_HANDOFF_ROOT')
        need(type(reader) is RetiredHistoryRemoteReader, 'RETIREMENT_CONCRETE_REMOTE_READER_REQUIRED')
        before = self.read()
        need(reader.current_release == current_release
             and reader.configuration_sha256 == self.configuration_sha256
             and provider.sha256 == before['plan']['destination']['provider_configuration_sha256']
             and canonical(reader.infrastructure) == canonical(before['plan']['destination']['infrastructure']),
             'RETIREMENT_READER_DESTINATION_CHANGED')
        snapshot = reader.read(before['history'], for_startup=for_startup)
        lease.require_active(current_release, current_root)
        need(self.read() == before, 'RETIREMENT_ARCHIVE_CHANGED_DURING_ADMISSION')
        need(-5 <= (datetime.now(timezone.utc) - utc(snapshot['observed_at_utc'])).total_seconds() <= 30,
             'RETIREMENT_REMOTE_SNAPSHOT_EXPIRED')
        return {'scope': 'fox-retired-history-admission-v1', 'attestation_sha256': self.attestation_sha256,
            'current_release_sha256': current_release, 'snapshot_sha256': sha(canonical(snapshot)),
            'observed_at_utc': snapshot['observed_at_utc'], 'for_startup': for_startup,
            'admission_state': snapshot['admission_state'],
            'busy_conversion_count': snapshot['busy_conversion_count'],
            'waiting_verification_count': snapshot['waiting_verification_count'],
            'automatic_replay_permitted': False, 'human_acceptance_recorded': False,
            'deployment_authorized': False}
