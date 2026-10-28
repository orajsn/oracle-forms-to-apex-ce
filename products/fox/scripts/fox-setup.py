#!/usr/bin/env python3
"""Local-only FOX discovery, declaration checker and create-only packager.

No installation, application startup, credential resolution, target activation,
cloud/DB/model access, image pull, network request, or configuration command is
performed. A FROZEN declaration is an input integrity claim, not authorization.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / 'deployment/fox-installation.schema.json'
MAX_JSON = 256_000
MAX_MEMBER = 16_000_000
MAX_TOTAL = 32_000_000
MAX_MEMBERS = 200
STATIC_FILES = frozenset({
    'fox/requirements-lock.txt', 'fox/dist/index.html', 'fox/scripts/start-local.ps1',
    'fox/fox/native/FoxPllExtract.java', 'fox/README.md', 'docs/fox-user-guide.md',
    'docs/fox-installation.md', 'docs/fox-local-user-guide.md',
    'deployment/fox-installation.schema.json', 'scripts/fox-setup.py',
})
REQUIRED = frozenset({
    'fox/fox/__init__.py', 'fox/fox/app.py', 'fox/fox/local_assessment.py',
    'fox/fox/local_preparation.py', 'fox/fox/local_security.py',
    'fox/requirements-lock.txt', 'fox/dist/index.html', 'fox/scripts/start-local.ps1',
    'scripts/fox-setup.py', 'deployment/fox-installation.schema.json', 'docs/fox-installation.md',
})
MODULE_PATH = re.compile(r'fox/fox/[a-z][a-z0-9_]*\.py\Z|fox/fox/__init__\.py\Z')
ASSET_PATH = re.compile(r'fox/dist/assets/[A-Za-z0-9_-]{1,100}-[A-Za-z0-9_-]{6,80}\.(?:js|css)\Z')
DEVICE = re.compile(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z', re.I)
SHA = re.compile(r'[a-f0-9]{64}\Z')
# High-confidence material only; this is not a universal secret/data detector.
SENSITIVE = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|'
                       rb'\bjdbc:' + rb'oracle:(?:thin|oci):[^/\s"\x27]+/[^@\s"\x27]+@|'
                       rb'\bBearer\s+[A-Za-z0-9._~-]{24,}', re.I)


class SetupError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # Unknown argument values can themselves contain a pasted secret.
        raise SetupError('INVALID_COMMAND_LINE')


def require(value, code):
    if not value:
        raise SetupError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def _unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'DUPLICATE_JSON_FIELD')
        value[key] = item
    return value


def json_object(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_JSON, 'MANIFEST_SIZE_INVALID')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(SetupError('NONFINITE_JSON')))
    except SetupError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise SetupError('MANIFEST_JSON_INVALID') from None
    require(type(value) is dict, 'MANIFEST_OBJECT_REQUIRED')
    return value


def safe_path(path):
    path = Path(os.path.abspath(path))
    require(not str(path).startswith(('\\\\', '//')), 'NETWORK_PATH_PROHIBITED')
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'LINKED_PATH_PROHIBITED')
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, 'HARDLINK_PROHIBITED')
    return path


def regular_bytes(path, limit=MAX_MEMBER):
    path = safe_path(path)
    try:
        before = path.stat()
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'SOURCE_FILE_INVALID')
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                    and (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), 'SOURCE_CHANGED_DURING_OPEN')
            raw = stream.read(limit + 1)
        require(len(raw) == before.st_size and len(raw) <= limit, 'SOURCE_CHANGED_DURING_READ')
        return raw
    except SetupError:
        raise
    except OSError:
        raise SetupError('SOURCE_FILE_UNAVAILABLE') from None


def structure(value, rule):
    actual = {dict: 'object', list: 'array', str: 'string', int: 'integer', bool: 'boolean', type(None): 'null'}.get(type(value))
    kinds = rule.get('type', [])
    kinds = [kinds] if type(kinds) is str else kinds
    require(actual in kinds, 'MANIFEST_TYPE_INVALID')
    if 'const' in rule:
        require(type(value) is type(rule['const']) and value == rule['const'], 'FIXED_MANIFEST_VALUE_CHANGED')
    if 'enum' in rule:
        require(any(type(value) is type(item) and value == item for item in rule['enum']), 'MANIFEST_ENUM_INVALID')
    if actual == 'object':
        properties = rule['properties']
        require(set(rule.get('required', [])) <= set(value), 'MANIFEST_REQUIRED_FIELD_MISSING')
        require(not rule.get('additionalProperties') and set(value) <= set(properties), 'MANIFEST_UNKNOWN_FIELD')
        for key, item in value.items():
            structure(item, properties[key])
    elif actual == 'array':
        require(rule.get('minItems', 0) <= len(value) <= rule.get('maxItems', MAX_MEMBERS), 'MANIFEST_LIST_SIZE_INVALID')
        for item in value:
            structure(item, rule['items'])
    elif actual == 'string':
        require(rule.get('minLength', 0) <= len(value) <= rule.get('maxLength', 10000), 'MANIFEST_STRING_SIZE_INVALID')
        require(not any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value), 'MANIFEST_STRING_INVALID')
        if 'pattern' in rule:
            require(re.fullmatch(rule['pattern'], value, re.ASCII) is not None, 'MANIFEST_STRING_FORMAT_INVALID')
    elif actual == 'integer':
        require(rule.get('minimum', value) <= value <= rule.get('maximum', value), 'MANIFEST_INTEGER_RANGE_INVALID')


def allowed_member(name):
    require(type(name) is str and '\\' not in name and ':' not in name, 'MEMBER_PATH_INVALID')
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(part not in ('', '.', '..') and not DEVICE.fullmatch(part) for part in path.parts), 'MEMBER_PATH_INVALID')
    require(name in STATIC_FILES or MODULE_PATH.fullmatch(name) or ASSET_PATH.fullmatch(name), 'MEMBER_NOT_ALLOWLISTED')
    return name


def validate_manifest(raw, schema=None):
    value = json_object(raw)
    schema = schema if schema is not None else json_object(regular_bytes(SCHEMA_PATH, MAX_JSON))
    structure(value, schema)
    require(value['activation'] == {'conversion_enabled': False, 'customer_deployment_authorized': False}
            and all(type(flag) is bool for flag in value['activation'].values())
            and value['host']['bind_address'] == '127.0.0.1', 'HOST_SETUP_CANNOT_AUTHORIZE_CONVERSION')
    seen = set()
    for entry in value['release']['files']:
        name = allowed_member(entry['path'])
        require(name.casefold() not in seen, 'DUPLICATE_OR_CASE_COLLIDING_MEMBER')
        seen.add(name.casefold())
        if value['release']['state'] == 'FROZEN':
            require(type(entry['sha256']) is str and SHA.fullmatch(entry['sha256']), 'FROZEN_HASH_REQUIRED')
    tools = value['optional_tools']
    require((tools['oracle_home_reference'] is None) == (tools['java_reference'] is None), 'TOOL_REFERENCES_MUST_BE_PAIRED')
    return value


class AssetReader(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.assets = set()
        self.scripts = 0
        self.styles = 0
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'script':
            self.in_script = True
            require(values.get('type') == 'module' and values.get('src'), 'UNSUPPORTED_UI_SCRIPT')
            self._add(values['src']); self.scripts += 1
        elif tag == 'link' and values.get('rel') in ('stylesheet', 'modulepreload'):
            self._add(values.get('href', ''))
            if values['rel'] == 'stylesheet':
                self.styles += 1

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False

    def handle_data(self, data):
        require(not self.in_script or not data.strip(), 'INLINE_UI_SCRIPT_PROHIBITED')

    def _add(self, value):
        require(type(value) is str and value.startswith('/assets/') and '?' not in value and '#' not in value,
                'EXTERNAL_OR_UNSUPPORTED_UI_ASSET')
        name = 'fox/dist' + value
        require(ASSET_PATH.fullmatch(name), 'UI_ASSET_NAME_INVALID')
        self.assets.add(name)


def ui_assets(raw):
    try:
        parser = AssetReader(); parser.feed(raw.decode('utf-8')); parser.close()
    except SetupError:
        raise
    except (UnicodeError, ValueError):
        raise SetupError('UI_ENTRY_INVALID') from None
    require(parser.scripts >= 1 and parser.styles >= 1, 'UI_ENTRY_ASSETS_MISSING')
    return parser.assets


def relative_dependencies(name, raw):
    if not MODULE_PATH.fullmatch(name):
        return set()
    try:
        code = ast.parse(raw.decode('utf-8'), filename=name)
    except (UnicodeError, SyntaxError):
        raise SetupError('PYTHON_SOURCE_SYNTAX_INVALID') from None
    needed = set()
    for node in ast.walk(code):
        if isinstance(node, ast.ImportFrom) and node.level:
            require(node.level == 1, 'UNSUPPORTED_PACKAGE_RELATIVE_IMPORT')
            if node.module:
                require(re.fullmatch(r'[a-z][a-z0-9_]*', node.module), 'UNSUPPORTED_PACKAGE_MODULE')
                needed.add('fox/fox/' + node.module + '.py')
            else:
                needed.update('fox/fox/' + alias.name + '.py' for alias in node.names)
    if name == 'fox/fox/extractor.py':
        needed.add('fox/fox/native/FoxPllExtract.java')
    return needed


def inspect_release(manifest, source_root):
    root = safe_path(source_root)
    require(root.is_dir(), 'SOURCE_ROOT_MUST_EXIST')
    files = {}; issues = []; observed = []; missing = set(REQUIRED)
    for entry in manifest['release']['files']:
        name = entry['path']
        try:
            raw = regular_bytes(root / name)
            require(not SENSITIVE.search(raw), 'CREDENTIAL_MATERIAL_IN_RELEASE_MEMBER')
            files[name] = raw
            actual = digest(raw)
            observed.append({'path': name, 'sha256': actual, 'bytes': len(raw)})
            if entry['sha256'] is None:
                issues.append({'code': 'UNFROZEN_MEMBER_HASH', 'path': name})
            elif entry['sha256'] != actual:
                issues.append({'code': 'MEMBER_HASH_MISMATCH', 'path': name})
            missing.discard(name)
        except SetupError as error:
            issues.append({'code': error.code, 'path': name})
    require(sum(len(raw) for raw in files.values()) <= MAX_TOTAL, 'RELEASE_TOTAL_SIZE_EXCEEDED')
    dependencies = set()
    for name, raw in files.items():
        dependencies.update(relative_dependencies(name, raw))
    if manifest['release']['ui_entry'] in files:
        dependencies.update(ui_assets(files[manifest['release']['ui_entry']]))
    missing.update(dependencies - set(files))
    for name in sorted(missing):
        allowed_member(name)
        issues.append({'code': 'REQUIRED_MEMBER_NOT_LISTED_OR_AVAILABLE', 'path': name})
    if manifest['release']['state'] != 'FROZEN':
        issues.append({'code': 'RELEASE_NOT_FROZEN'})
    return {'complete': not issues, 'issues': issues, 'freeze_inputs_observed': observed,
            'required_additional_members': sorted(missing)}, files


def locked_dependencies(raw):
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise SetupError('DEPENDENCY_LOCK_INVALID') from None
    dependencies = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]*)==([0-9][A-Za-z0-9.!+_-]*)', line)
        require(match is not None, 'DEPENDENCY_LOCK_MUST_USE_EXACT_EXISTING_PINS')
        name, version = match.groups(); normalized = re.sub('[-_.]+', '-', name).lower()
        require(normalized not in dependencies, 'DUPLICATE_DEPENDENCY_LOCK_ENTRY')
        dependencies[normalized] = version
    require(0 < len(dependencies) <= 100, 'DEPENDENCY_LOCK_SIZE_INVALID')
    return dependencies


def listener_ports():
    """Read the OS listener table only; never bind/connect/open a network port."""
    if os.name == 'nt':
        import ctypes
        directory = ctypes.create_unicode_buffer(32768)
        count = ctypes.windll.kernel32.GetSystemDirectoryW(directory, len(directory))
        require(0 < count < len(directory), 'SYSTEM_DIRECTORY_UNAVAILABLE')
        dll = ctypes.WinDLL(str(Path(directory.value) / 'iphlpapi.dll'), use_last_error=True)
        dll.GetExtendedTcpTable.restype = ctypes.c_ulong
        dll.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
                                           ctypes.c_int, ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        ports = set()
        for family, row_size, port_offset in ((2, 24, 8), (23, 56, 20)):
            size = ctypes.c_ulong(0)
            result = dll.GetExtendedTcpTable(None, ctypes.byref(size), False, family, 3, 0)
            require(result in (0, 122) and 4 <= size.value <= 4_000_000, 'LISTENER_TABLE_UNAVAILABLE')
            buffer = ctypes.create_string_buffer(size.value)
            require(dll.GetExtendedTcpTable(buffer, ctypes.byref(size), False, family, 3, 0) == 0, 'LISTENER_TABLE_UNAVAILABLE')
            raw = buffer.raw[:size.value]; count = struct.unpack_from('<I', raw, 0)[0]
            require(count <= 20000 and 4 + row_size * count <= len(raw), 'LISTENER_TABLE_INVALID')
            for index in range(count):
                encoded = struct.unpack_from('<I', raw, 4 + index * row_size + port_offset)[0] & 0xffff
                ports.add(((encoded & 0xff) << 8) | (encoded >> 8))
        return ports
    if sys.platform.startswith('linux'):
        ports = set(); observed = False
        for file in (Path('/proc/net/tcp'), Path('/proc/net/tcp6')):
            try:
                lines = file.read_text(encoding='ascii').splitlines()[1:]
            except FileNotFoundError:
                continue
            observed = True
            require(len(lines) <= 20000, 'LISTENER_TABLE_TOO_LARGE')
            for line in lines:
                columns = line.split()
                if len(columns) > 3 and columns[3] == '0A':
                    ports.add(int(columns[1].rsplit(':', 1)[1], 16))
        require(observed, 'LISTENER_TABLE_UNAVAILABLE')
        return ports
    raise SetupError('LISTENER_OBSERVATION_UNSUPPORTED')


def actual_capabilities(manifest, source_root, files):
    """Read installed metadata only; do not import FOX or dependency bodies."""
    lock = files.get(manifest['release']['python_lock'])
    dependencies = []
    if lock is not None:
        for name, wanted in locked_dependencies(lock).items():
            try:
                observed = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                observed = None
            dependencies.append({'name': name, 'declared': wanted, 'observed': observed,
                                 'status': 'MATCH' if observed == wanted else 'MISSING' if observed is None else 'DIFFERENT'})
    system = {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'macos'}.get(platform.system(), 'unsupported')
    storage = safe_path(Path(source_root) / manifest['storage']['session_relative_path'])
    nearest = storage
    while not nearest.exists():
        nearest = nearest.parent
    require(nearest.is_dir(), 'STORAGE_PARENT_NOT_DIRECTORY')
    writable = os.access(nearest, os.R_OK | os.W_OK)
    try:
        occupied = manifest['host']['port'] in listener_ports()
        port_status = 'IN_USE' if occupied else 'NOT_LISTENING_AT_CHECK_TIME'
    except (OSError, ValueError, SetupError):
        port_status = 'UNOBSERVED'
    powershell_present = system == 'windows' and shutil.which('powershell') is not None
    launcher_python = safe_path(Path(source_root) / 'fox/.venv/Scripts/python.exe')
    interpreter_matches = (launcher_python.is_file()
                           and os.path.normcase(str(launcher_python.resolve())) == os.path.normcase(str(Path(sys.executable).resolve())))
    return {'platform': system, 'architecture': platform.machine(),
            'python': {'implementation': platform.python_implementation(), 'major': sys.version_info.major,
                       'minor': sys.version_info.minor, 'release': platform.python_version()},
            'dependencies': dependencies, 'dependency_lock_observed': lock is not None,
            'launcher_interpreter_present': launcher_python.is_file(),
            'dependency_metadata_from_launcher_interpreter': interpreter_matches,
            'powershell_present': powershell_present, 'port': port_status,
            'storage': {'path': manifest['storage']['session_relative_path'], 'parent_accessible': writable,
                        'exists': storage.exists(), 'contents_read': False, 'created': False},
            'oracle_tools': 'REFERENCE_ONLY_NOT_RESOLVED', 'health': 'NOT_STARTED_OR_CONTACTED'}


def check(manifest_raw, source_root, *, observer=None):
    manifest = validate_manifest(manifest_raw)
    release, files = inspect_release(manifest, source_root)
    observed = (observer or actual_capabilities)(manifest, source_root, files)
    wanted = manifest['host']; python = observed['python']
    readiness = {'release_complete': release['complete'], 'localhost_route': manifest['route'] == 'localhost-assessment',
                 'windows_launcher_supported': wanted['platform'] == observed['platform'] == 'windows',
                 'python_matches_declaration': python['implementation'] == wanted['python_implementation']
                  and python['major'] == wanted['python_major'] and python['minor'] == wanted['python_minor'],
                 'dependency_lock_matches': observed['dependency_lock_observed'] and bool(observed['dependencies'])
                  and all(row['status'] == 'MATCH' for row in observed['dependencies']),
                 'launcher_interpreter_present': observed['launcher_interpreter_present'],
                 'dependency_metadata_from_launcher_interpreter': observed['dependency_metadata_from_launcher_interpreter'],
                 'powershell_present': observed['powershell_present'],
                 'storage_parent_accessible': observed['storage']['parent_accessible'],
                 'port_not_listening_at_check_time': observed['port'] == 'NOT_LISTENING_AT_CHECK_TIME'}
    ready = all(readiness.values())
    result = {'schema_version': 1, 'scope': 'fox-host-setup-readonly-v1',
              'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'manifest_sha256': digest(manifest_raw),
              'status': 'ASSESSMENT_PREREQUISITES_READY' if ready else 'NOT_READY',
              'assessment_ready': ready, 'conversion_configured': False, 'conversion_authorized': False,
              'conversion_configuration_status': 'NOT_INSPECTED_BY_HOST_SETUP',
              'customer_deployment_authorized': False, 'changes_performed': False,
              'readiness_checks': readiness, 'observed': observed, 'release': release,
              'health_request_performed': False, 'secret_references_resolved': False,
              'route': manifest['route'], 'limitations': [
                  'Readiness is a point-in-time prerequisite check, not a started service or Oracle compatibility certificate.',
                  'Secret/tool/backup/rollback references are inert. No referenced content is read.',
                  'Existing JSN hosted conversion uses its separate guarded operator route.']}
    return result


def _zip_bytes(files):
    output = io.BytesIO()
    # Stored entries avoid compressor-version differences in byte reproduction.
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3; info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, raw)
    return output.getvalue()


def _new_file(path, raw):
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def prepare(manifest_raw, source_root, output):
    manifest = validate_manifest(manifest_raw)
    release, files = inspect_release(manifest, source_root)
    require(release['complete'], 'FROZEN_COMPLETE_RELEASE_REQUIRED')
    # Packaging is allowed on a different build host; it is not host readiness.
    locked_dependencies(files[manifest['release']['python_lock']])
    root = safe_path(source_root)
    destination = safe_path(output)
    require(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir(), 'OUTPUT_MUST_BE_NEW_DIRECTORY')
    storage = root / manifest['storage']['session_relative_path']
    require(destination != root and not root.is_relative_to(destination)
            and not destination.is_relative_to(storage), 'OUTPUT_OVERLAPS_SOURCE_OR_PERSISTENT_STORAGE')
    prepared = dict(files)
    prepared['fox-installation.json'] = canonical(manifest)
    file_hashes = {name: digest(raw) for name, raw in sorted(prepared.items())}
    bundle_manifest = {'schema_version': 1, 'scope': 'fox-local-assessment-bundle-v1',
                       'release_id': manifest['release']['release_id'], 'files': file_hashes,
                       'manifest_input_sha256': digest(manifest_raw),
                       'assessment_ready': False, 'conversion_configured': False, 'conversion_authorized': False,
                       'customer_deployment_authorized': False,
                       'persistent_storage': {'relative_path': manifest['storage']['session_relative_path'],
                                              'included': False, 'modified': False},
                       'oracle_binaries_included': False, 'credential_files_included': False,
                       'inline_sensitive_scan': 'bounded_high_confidence_only_not_secret_certification',
                       'activation_performed': False}
    prepared['bundle-manifest.json'] = canonical(bundle_manifest)
    archive = _zip_bytes(prepared)
    # Recheck every original source immediately before the first output write.
    for name, raw in files.items():
        require(regular_bytes(root / name) == raw, 'SOURCE_CHANGED_BEFORE_PREPARE')
    destination.mkdir(mode=0o700)
    # Partial output is retained on error; never clean up or overwrite it.
    _new_file(destination / 'fox-bundle.zip', archive)
    _new_file(destination / 'bundle-manifest.json', canonical(bundle_manifest))
    result = {'schema_version': 1, 'scope': 'fox-create-only-bundle-preparation-v1', 'status': 'PREPARED_NOT_INSTALLED',
              'bundle_sha256': digest(archive), 'bundle_bytes': len(archive), 'member_count': len(prepared),
              'release_id': manifest['release']['release_id'], 'output_directory': str(destination),
              'source_files_modified': False, 'persistent_storage_modified': False,
              'assessment_ready': False, 'conversion_configured': False, 'conversion_authorized': False,
              'customer_deployment_authorized': False, 'software_installed': False,
              'network_calls_performed': False, 'secret_references_resolved': False}
    _new_file(destination / 'preparation-receipt.json', canonical(result))
    return result


def inspect_installation(installation_root):
    """Bounded read-only discovery for setup/skill callers, never admission.

    Only known metadata is read; database, credential and uploaded-source files
    are never opened. The actual installer must recheck ownership and readiness
    through its existing storage/runtime contracts before reuse or mutation.
    """
    root = safe_path(installation_root)
    result = {'schema_version': 1, 'scope': 'fox-installation-discovery-v1',
              'inspection_scope': 'selected_directory_only',
              'read_only': True, 'changes_performed': False,
              'runtime_checked': False, 'release_integrity_verified': False,
              'conversion_ready': False, 'installation_verified': False,
              'automatic_install_authorized': False,
              'secret_references_resolved': False, 'network_calls_performed': False}

    def observed(status, action):
        return {**result, 'status': status, 'next_action': action}

    try:
        before = root.stat()
    except FileNotFoundError:
        return observed('NOT_INSTALLED', 'SELECT_REVIEWED_FULL_RELEASE')
    require(stat.S_ISDIR(before.st_mode), 'INSTALLATION_ROOT_NOT_DIRECTORY')
    # A root may contain arbitrary user files. Do not print their names, descend
    # into them, or read unrecognized content to identify the installation.
    names = set()
    with os.scandir(root) as entries:
        for entry in entries:
            require(len(names) < 256, 'INSTALLATION_ROOT_INVENTORY_BOUND')
            names.add(entry.name)
    if not names:
        status, action = 'EMPTY_DIRECTORY_NOT_INSTALLED', 'SELECT_REVIEWED_FULL_RELEASE'
    elif '.fox-local-session.json' in names:
        require(not names & {'projection.json', 'live-admission.json', 'installation.json'},
                'CONFLICTING_INSTALLATION_MARKERS')
        status, action = 'ASSESSMENT_SESSION_UNVERIFIED', 'USE_SELECTED_SESSION_RESUME_CHECKS'
    elif names & {'fox.sqlite3', 'intent.json', 'roots.json', 'complete.json',
                  'projection.json', 'backend-initialization.json',
                  'live-admission.json', 'installation.json', 'setup-storage-plan.json'}:
        status, action = 'EXISTING_STATE_UNVERIFIED', 'VERIFY_EXISTING_ATTEMPT_AND_RUNTIME'
    elif 'fox-installation.json' in names:
        manifest = validate_manifest(regular_bytes(root / 'fox-installation.json', MAX_JSON))
        if manifest['route'] == 'localhost-assessment':
            status, action = 'ASSESSMENT_BUNDLE_UNVERIFIED', 'CHECK_SELECTED_ASSESSMENT_BUNDLE'
        else:
            status, action = 'HOSTED_REFERENCE_NOT_INSTALLER', 'SELECT_REVIEWED_FULL_RELEASE'
    else:
        def files_exist(required):
            for name in required:
                path = safe_path(root / name)
                try:
                    info = path.stat()
                except FileNotFoundError:
                    return False
                require(stat.S_ISREG(info.st_mode), 'INSTALLATION_SENTINEL_NOT_FILE')
            return True
        product = ('fox/requirements-lock.txt', 'converter/forms2apex/target_profile.py',
                   'qa/operator/hosted_service.py', 'scripts/fox-setup.py')
        runtime = ('requirements-lock.txt', 'package.json', 'scripts/start-local.ps1',
                   'fox/local_assessment.py')
        ce_skill = ('install.py', 'oracle-forms-to-apex-ce/SKILL.md')
        if files_exist(product):
            status, action = 'PRODUCT_SOURCE_NOT_INSTALLATION', 'SELECT_REVIEWED_FULL_RELEASE'
        elif files_exist(runtime):
            status, action = 'RUNTIME_SOURCE_NOT_INSTALLATION', 'SELECT_REQUESTED_SETUP_ROUTE'
        elif files_exist(ce_skill):
            status, action = 'CE_SKILL_NOT_FOX_INSTALLATION', 'SELECT_FOX_PRODUCT_ROOT'
        else:
            status, action = 'UNRECOGNIZED_NONEMPTY_DIRECTORY', 'CHOOSE_NEW_ROOT_OR_INSPECT_EXISTING_STATE'
    after = root.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, key) == getattr(after, key) for key in fields)
            and safe_path(root) == root, 'INSTALLATION_ROOT_CHANGED_DURING_INSPECTION')
    return observed(status, action)


def installer_storage_step(args):
    """Use the real nonroot storage producer behind the same setup entrypoint."""
    require(os.name == 'posix' and os.geteuid() > 0, 'POSIX_SETUP_OWNER_REQUIRED')
    require(all(safe_path(ROOT / name).is_file() for name in
                ('qa/operator/installer_storage.py', 'qa/operator/fresh_storage.py',
                 'fox/fox/storage.py')), 'STORAGE_STEP_COMPONENTS_MISSING')
    # Explicit product roots, never a caller-provided import path or app import.
    for directory in (ROOT, ROOT / 'fox'):
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
    from qa.operator import installer_storage as step
    require(Path(step.__file__).resolve() == ROOT / 'qa/operator/installer_storage.py',
            'EXPECTED_INSTALLER_STORAGE_MODULE_REQUIRED')
    try:
        value = step.plan(args.installation_root, owner_uid=os.geteuid())
        if args.command == 'storage-plan':
            return {'status': 'STORAGE_PLAN_NOT_INSTALLED', 'plan': value,
                    'plan_sha256': step.digest(value), 'changes_performed': False,
                    'conversion_ready': False, 'services_started': False}
        return step.initialize(value, expected_plan_sha256=args.expected_plan_sha256, apply=args.apply)
    except (step.InstallerStorageError, step.storage.FreshStorageError) as error:
        code = str(error)
        raise SetupError(code if re.fullmatch(r'[A-Z][A-Z0-9_]{1,95}', code)
                         else 'INSTALLER_STORAGE_FAILED') from None


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('command', choices=('inspect', 'storage-plan', 'storage-initialize', 'check', 'prepare'))
    parser.add_argument('manifest', nargs='?')
    parser.add_argument('--source-root')
    parser.add_argument('--installation-root')
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    if args.command in ('storage-plan', 'storage-initialize'):
        require(args.installation_root is not None and args.manifest is None
                and args.source_root is None and args.output is None, 'STORAGE_STEP_ARGUMENTS_INVALID')
        if args.command == 'storage-plan':
            require(not args.apply and args.expected_plan_sha256 is None, 'PLAN_MUST_BE_READ_ONLY')
        else:
            require(args.apply and type(args.expected_plan_sha256) is str
                    and SHA.fullmatch(args.expected_plan_sha256), 'EXACT_APPROVED_STORAGE_PLAN_REQUIRED')
        print(json.dumps(installer_storage_step(args), sort_keys=True))
        return 0
    if args.command == 'inspect':
        require(args.installation_root is not None and args.manifest is None
                and args.source_root is None and args.output is None
                and args.expected_plan_sha256 is None and not args.apply, 'INSPECT_ARGUMENTS_INVALID')
        print(json.dumps(inspect_installation(args.installation_root), sort_keys=True))
        return 0  # Successful observation, not installation or readiness.
    require(args.manifest is not None and args.source_root is not None
            and args.installation_root is None and args.expected_plan_sha256 is None
            and not args.apply, 'SETUP_ARGUMENTS_INVALID')
    require((args.command == 'prepare') == (args.output is not None), 'OUTPUT_ONLY_FOR_CREATE_ONLY_PREPARE')
    raw = regular_bytes(args.manifest, MAX_JSON)
    result = prepare(raw, args.source_root, args.output) if args.command == 'prepare' else check(raw, args.source_root)
    print(json.dumps(result, sort_keys=True))
    return 0 if args.command == 'prepare' or result['assessment_ready'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SetupError as error:
        print(json.dumps({'status': 'INVALID', 'code': error.code, 'changes_performed': False,
                          'conversion_authorized': False, 'customer_deployment_authorized': False}))
        raise SystemExit(2)
    except Exception:
        print(json.dumps({'status': 'STOPPED', 'code': 'SETUP_FAILED_DETAILS_WITHHELD',
                          'conversion_authorized': False, 'customer_deployment_authorized': False,
                          'partial_output_may_be_retained': True}))
        raise SystemExit(2)
