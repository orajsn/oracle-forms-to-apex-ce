"""Local-only, deterministic extraction. Oracle runtimes are never distributed.

The backend contract returns readable artifacts; preparation owns validation,
hashing and publication. No backend may upload sources or connect to a database.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from defusedxml import ElementTree as ET
from .intake import ALLOWED, MAX_PROJECT_BYTES, checked_source, inventory
from .prepared_source import (MAX_MANIFEST_BYTES, UPLOAD_MANIFEST_NAME,
                              PreparedSourceError, encode_upload_manifest,
                              make_upload_manifest, verify_upload_manifest)

BINARY = {'.fmb', '.mmb', '.olb', '.pll'}
MAX_RAW_BYTES = 20 * 1024 * 1024
MAX_INPUT_BYTES = 100 * 1024 * 1024
WINDOWS_PATH_BUDGET = 240  # Conservative FOX policy, not native compatibility certification.
PATH_BUDGET_MESSAGE = ('Local preparation paths exceed this installation\u2019s limit. '
    'Start a new session from a shorter installation folder; keep the original files unchanged.')
_EXTRACT_TEMP_PREFIX = 'fox-extract-'
_PLL_TEMP_PREFIX = 'fox-jdapi-build-'
# Reserve more than tempfile's generated suffix, then recheck actual tool paths.
_TEMP_BUDGET_SUFFIX = 'x' * 32
MODULE_TYPES = {'.fmb': 'FormModule', '.mmb': 'MenuModule', '.olb': 'ObjectLibrary'}
NS = '{http://xmlns.oracle.com/Forms}'
PLL_NS = '{urn:fox:forms-library:v1}'


def validate_pll_xml(raw: bytes) -> None:
    """Validate our JDAPI envelope, retaining spec/body units separately."""
    try:
        root = ET.fromstring(raw)
        if (root.tag != PLL_NS + 'Module' or root.get('Format') != 'FOX-JDAPI-LIBRARY-1'
                or root.get('DatabaseConnected') != 'false' or len(root) != 1
                or root[0].tag != PLL_NS + 'LibraryModule'):
            raise ValueError()
        library = root[0]
        units = library.findall(PLL_NS + 'ProgramUnit')
        attached = library.findall(PLL_NS + 'AttachedLibrary')
        if (not units or len(units) != int(library.get('ProgramUnitCount', '-1'))
                or len(attached) != int(library.get('AttachedLibraryCount', '-1'))
                or len(library) != len(units) + len(attached)):
            raise ValueError()
        keys = set()
        for unit in units:
            key = (unit.get('Name'), unit.get('ProgramUnitType'))
            texts = unit.findall(PLL_NS + 'ProgramUnitText')
            if not key[0] or key in keys or len(texts) != 1 or not texts[0].text:
                raise ValueError()
            keys.add(key)
            if digest(texts[0].text.encode('utf-8')) != unit.get('TextSHA256'):
                raise ValueError()
    except Exception:
        raise ExtractionError('PLL output failed program-unit count or source-integrity validation.') from None


class ExtractionError(ValueError):
    """Safe diagnostic: never include tool output or source content."""


class PathBudgetError(ExtractionError):
    def __init__(self):
        super().__init__(PATH_BUDGET_MESSAGE)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def safe_name(name: str) -> None:
    if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. -]{0,119}', name)
            or '..' in name or name.endswith((' ', '.'))
            or name.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL',
                *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}):
        raise ExtractionError('Unsafe filename. Use letters, digits, spaces, dots, hyphens or underscores.')


def _output_name(name):
    source = Path(name)
    output = source.stem + '_' + source.suffix.lower()[1:] + '.xml' if source.suffix.lower() in BINARY else source.name
    try:
        safe_name(output)
    except ExtractionError:
        # Native suffixes add four characters; reject before any native tool.
        raise PathBudgetError() from None
    return output


def _validate_windows_paths(paths):
    if os.name == 'nt' and any(len(os.path.abspath(path).encode('utf-16-le')) // 2 > WINDOWS_PATH_BUDGET
                               for path in paths):
        raise PathBudgetError()


def _native_budget_paths(source, destination, native):
    paths = [source, source.parent, destination, destination / _output_name(source.name)]
    configured_paths = getattr(native, 'path_budget_paths', None)
    if configured_paths is not None:
        paths.extend(configured_paths(source.suffix.lower()))
    return paths


def validate_path_budget(source_root, output_root, names, job_id, native=None, *, private_paths=()):
    """Check known paths before mkdir/copy/tools; no rename or directory repair.

    Names are already-validated source-relative paths. No public ID, filename or
    manifest contract is shortened. Each classpath entry is checked separately.
    """
    source_root, output_root = Path(source_root), Path(output_root)
    job = output_root / job_id
    paths = [source_root, output_root, job, job / 'ready', job / 'manifest.json',
             job / 'inventory.json', job / 'status.json', job / 'ready' / UPLOAD_MANIFEST_NAME, *private_paths]
    scratch = Path(tempfile.gettempdir()) / (_EXTRACT_TEMP_PREFIX + _TEMP_BUDGET_SUFFIX)
    paths.extend([scratch, scratch / 'sources'])
    for index, name in enumerate(names):
        name = Path(name)
        output_name = _output_name(name.name)
        staged = scratch / 'sources' / name.name
        destination = scratch / f'output-{index}'
        paths.extend([source_root / name, staged, destination, destination / output_name, job / 'ready' / output_name])
        if name.suffix.lower() in BINARY:
            paths.extend(_native_budget_paths(staged, destination, native))
    _validate_windows_paths(paths)


def assert_local_path(path: Path) -> Path:
    # Check BEFORE resolve: resolve would hide junctions and symbolic links.
    path = Path(os.path.abspath(path))
    if str(path).startswith(('\\\\', '//')):
        raise ExtractionError('Use a local directory, not a network share.')
    for part in [path, *path.parents]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & 0x400
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise ExtractionError('Symlinks, junctions, reparse points and hard links are not accepted.')
    return path


def source_files(root: Path) -> list[Path]:
    root = assert_local_path(root)
    if not root.is_dir() or root == root.parent:
        raise ExtractionError('Select a dedicated local source directory.')
    result, names, size = [], set(), 0
    def walk(folder: Path, depth: int) -> None:
        nonlocal size
        if depth > 8:
            raise ExtractionError('Source directories may be at most eight levels deep.')
        for p in sorted(folder.iterdir()):
            assert_local_path(p)
            safe_name(p.name)
            if p.is_dir():
                walk(p, depth + 1)
                continue
            if not p.is_file() or p.suffix.lower() not in ALLOWED | BINARY:
                raise ExtractionError('Unsupported source type; archives and executable assets are not accepted.')
            if p.name.casefold() in names:
                raise ExtractionError('Duplicate basenames. Separate ambiguous modules into different jobs.')
            names.add(p.name.casefold())
            n = p.stat().st_size
            size += n
            if n == 0 or n > MAX_RAW_BYTES or size > MAX_INPUT_BYTES or len(result) >= 50:
                raise ExtractionError('Source limit: 50 files, 20 MB each, 100 MB total; empty files rejected.')
            result.append(p)
    walk(root, 0)
    if not result:
        raise ExtractionError('No source files found.')
    return result


class Backend(Protocol):
    name: str
    def extract(self, source: Path, destination: Path) -> Path: ...


class ReadableBackend:
    name = 'readable-v1'

    def extract(self, source: Path, destination: Path) -> Path:
        output = destination / source.name
        output.write_bytes(source.read_bytes())
        return output


class OracleFormsBackend:
    """Windows Forms 14c installed tool adapter, no shell or DB credentials."""
    name = 'oracle-forms-installed-v1'

    def __init__(self, home: Path, java: Path, timeout: int = 120):
        self.home, self.java, self.timeout = Path(home), Path(java), timeout
        self.jars = [self.home / p for p in ('jlib/frmxmltools.jar', 'jlib/frmjdapi.jar',
            'oracle_common/modules/oracle.xdk/xmlparserv2.jar')]
        self.javac = self.home / 'oracle_common/jdk/bin/javac.exe'
        self.pll_helper = Path(__file__).parent / 'native/FoxPllExtract.java'

    def path_budget_paths(self, suffix):
        """Pure path declaration for preflight; does not inspect or run tools."""
        paths = [self.home, self.java, *self.jars]
        if suffix == '.pll':
            build = Path(tempfile.gettempdir()) / (_PLL_TEMP_PREFIX + _TEMP_BUDGET_SUFFIX)
            paths.extend([self.javac, self.pll_helper, build,
                          *(build / name for name in ('FoxPllExtract.class', 'FoxPllExtract$Unit.class', 'FoxPllExtract$Library.class'))])
        return paths

    def check(self) -> dict:
        if os.name != 'nt':
            raise ExtractionError('This native backend is validated on Windows only. Readable intake is portable.')
        paths = [self.java, *self.jars]
        if not all(p.is_file() for p in paths):
            raise ExtractionError('Installed Forms Home or Java executable not found; no Oracle installer is bundled.')
        return {'backend': self.name, 'tool_files_present': True,
                'native_conversion_tested': False,
                'formats': sorted(BINARY if self.javac.is_file() else MODULE_TYPES),
                'pll_output': 'FOX JDAPI library XML; not Oracle PLD or Forms2XML schema',
                'blocked_formats': {} if self.javac.is_file() else {'.pll': 'Installed JDK compiler required for the JDAPI helper.'},
                'note': 'Presence check only; run a representative extraction to prove compatibility.'}

    def run(self, args: list[str], cwd: Path, forms_path: Path) -> None:
        # No inherited connection strings, JVM injection options or Forms paths.
        keep = {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA',
                'LOCALAPPDATA', 'COMSPEC', 'PATHEXT'}
        env = {k: v for k, v in os.environ.items() if k.upper() in keep}
        env.update(ORACLE_HOME=str(self.home), FORMS_PATH=str(forms_path),
                   NLS_LANG='AMERICAN_AMERICA.AL32UTF8',
                   PATH=str(self.home / 'bin') + os.pathsep + str(self.java.parent)
                        + os.pathsep + str(Path(env.get('SystemRoot', env.get('SYSTEMROOT', 'C:/Windows'))) / 'System32'))
        kwargs = {}
        if os.name == 'nt':
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            kwargs = {'startupinfo': si, 'creationflags': subprocess.CREATE_NO_WINDOW}
        try:
            # Tool diagnostics can contain unredacted source; never persist or print them.
            proc = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=self.timeout, shell=False, **kwargs)
        except subprocess.TimeoutExpired:
            raise ExtractionError('Oracle extraction timed out; no package released.') from None
        except OSError:
            raise ExtractionError('Oracle tool could not start. Check local runtime prerequisites.') from None
        if proc.returncode or re.search(rb'(?i)\b(error|exception|warning)\b|FRM-\d+', proc.stdout):
            raise ExtractionError('Oracle extraction reported an error or warning; inspect the module locally in Forms Builder.')

    def extract(self, source: Path, destination: Path) -> Path:
        _validate_windows_paths(_native_budget_paths(source, destination, self))
        self.check()
        ext = source.suffix.lower()
        if ext == '.pll':
            if not self.javac.is_file() or not self.pll_helper.is_file():
                raise ExtractionError('PLL extraction requires the local JDK compiler and FOX JDAPI helper.')
            output = destination / (source.stem + '_pll.xml')
            if output.exists():
                raise ExtractionError('Refusing to overwrite a PLL extraction artifact.')
            with tempfile.TemporaryDirectory(prefix=_PLL_TEMP_PREFIX) as build:
                _validate_windows_paths([Path(build) / name for name in
                    ('FoxPllExtract.class', 'FoxPllExtract$Unit.class', 'FoxPllExtract$Library.class')])
                self.run([str(self.javac), '-encoding', 'UTF-8', '--release', '17',
                    '-cp', str(self.jars[1]), '-d', build, str(self.pll_helper)], Path(build), source.parent)
                self.run([str(self.java), '-cp', build + os.pathsep + str(self.jars[1]),
                    'FoxPllExtract', str(source), str(output)], destination, source.parent)
            if not output.is_file() or output.stat().st_size > 5 * 1024 * 1024:
                raise ExtractionError('PLL readable output is missing or exceeds intake limits.')
            validate_pll_xml(output.read_bytes())
        else:
            output = destination / (source.stem + '_' + ext[1:] + '.xml')
            args = [str(self.java), '-cp', os.pathsep.join(map(str, self.jars)),
                'oracle.forms.util.xmltools.Forms2XML', 'DUMP=OVERRIDDEN',
                'USE_PROPERTY_IDS=NO', 'OVERWRITE=NO', 'OUTPUTDIR=' + str(destination), str(source)]
            self.run(args, destination, source.parent)
        if not output.is_file() or not output.stat().st_size:
            raise ExtractionError('Oracle did not produce the expected readable artifact.')
        if ext in MODULE_TYPES:
            try:
                root = ET.fromstring(output.read_bytes())
                if root.tag != NS + 'Module' or len(root) != 1 or root[0].tag != NS + MODULE_TYPES[ext]:
                    raise ValueError()
            except Exception:
                raise ExtractionError('Oracle output did not contain the expected Forms module type.') from None
        return output


def prepare(source: Path, output_root: Path, native: Backend | None = None, job_id: str | None = None) -> Path:
    source, output_root = assert_local_path(source), assert_local_path(output_root)
    if output_root == source or output_root.is_relative_to(source) or source.is_relative_to(output_root):
        raise ExtractionError('Source and output directories must be separate, non-nested directories.')
    files = source_files(source)
    if any(p.suffix.lower() in BINARY for p in files) and native is None:
        raise ExtractionError('Binary input requires the installed Oracle Forms backend.')
    job_id = job_id or ('extract-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}', job_id):
        raise ExtractionError('Invalid job ID.')
    validate_path_budget(source, output_root, [p.relative_to(source) for p in files], job_id, native)
    output_root.mkdir(parents=True, exist_ok=True)
    job = output_root / job_id
    job.mkdir(exist_ok=False)  # Never replace an existing extraction.
    report = {'schema_version': 1, 'job_id': job_id, 'status': 'BLOCKED',
              'raw_files_uploaded': False, 'network_calls_by_adapter': False}
    try:
        inputs, accepted, extras, output_names = [], [], [], set()
        # Scratch stays on this workstation, removed after the run. Native files
        # are never opened in place by Oracle and never put in ready/.
        with tempfile.TemporaryDirectory(prefix=_EXTRACT_TEMP_PREFIX) as scratch:
            staging = Path(scratch) / 'sources'
            _validate_windows_paths([staging, *(staging / p.name for p in files),
                *(Path(scratch) / f'output-{i}' / _output_name(p.name) for i, p in enumerate(files))])
            staging.mkdir()
            for p in files:
                assert_local_path(p)
                raw = p.read_bytes()
                if len(raw) != p.stat().st_size or len(raw) > MAX_RAW_BYTES:
                    raise ExtractionError('Input changed while staging. Retry from a frozen source directory.')
                inputs.append({'name': p.relative_to(source).as_posix(), 'sha256': digest(raw), 'bytes': len(raw)})
                (staging / p.name).write_bytes(raw)
            for i, p in enumerate(files):
                tool_out = Path(scratch) / f'output-{i}'
                tool_out.mkdir()
                backend = native if p.suffix.lower() in BINARY else ReadableBackend()
                result = backend.extract(staging / p.name, tool_out)
                if result.parent != tool_out or not result.is_file():
                    raise ExtractionError('Backend returned an artifact outside its output directory.')
                assert_local_path(result)
                safe_name(result.name)
                if result.name.casefold() in output_names:
                    raise ExtractionError('Output filename collision. Supply either binary or exported text, not both.')
                output_names.add(result.name.casefold())
                if result.stat().st_size > 5 * 1024 * 1024:
                    raise ExtractionError('Extracted file exceeds the 5 MB readable intake limit.')
                entry = checked_source(result.name, result.read_bytes())
                entry.update(source=inputs[i]['name'], backend=backend.name)
                accepted.append(entry)
                if sum(e['bytes'] for e in accepted) > MAX_PROJECT_BYTES:
                    raise ExtractionError('Readable output exceeds the 25 MB project limit.')
                # Oracle may export images. Keep them out of the upload package
                # and explicitly report the omission, never silently discard it.
                for extra in tool_out.iterdir():
                    if extra != result:
                        extras.append({'source': inputs[i]['name'], 'type': extra.suffix.lower(),
                            'action': 'Additional Oracle-generated asset excluded. Review graphics or diagnostics locally.'})
            for p, expected in zip(files, inputs):
                assert_local_path(p)
                if digest(p.read_bytes()) != expected['sha256']:
                    raise ExtractionError('Source changed during extraction; no package released.')
        source_hash = digest(json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode())
        normalized = inventory(accepted)
        public_manifest = encode_upload_manifest(make_upload_manifest(job_id, accepted))
        manifest = {'schema_version': 1, 'job_id': job_id, 'source_manifest_hash': source_hash,
            'inputs': inputs, 'files': [{k: v for k, v in f.items() if k != 'text'} for f in accepted],
            'readable_source_hash': normalized['source_hash'], 'excluded_assets': extras,
            'upload_manifest_name': UPLOAD_MANIFEST_NAME,
            'requires_human_redaction_approval': True,
            'limits': ['Static references are not complete dependency discovery.',
                'Regex checks cannot prove absence of secrets, personal identifiers or production data.',
                'Forms2XML does not preserve persistent client information; overridden properties only.',
                'Extraction is not APEX conversion or behavioral equivalence.']}
        ready = job / 'ready'
        ready.mkdir()
        for entry in accepted:
            # Preserve exact bytes including optional UTF-8 BOM for hash identity.
            raw = entry['text'].encode('utf-8')
            if digest(raw) != entry['sha256']:
                raw = b'\xef\xbb\xbf' + raw
            if digest(raw) != entry['sha256']:
                raise ExtractionError('Readable byte identity check failed.')
            (ready / entry['name']).write_bytes(raw)
        # Only this bounded, metadata-only sidecar accompanies readable sources.
        # The private manifest above retains backend/raw-input details locally.
        (ready / UPLOAD_MANIFEST_NAME).write_bytes(public_manifest)
        (job / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        (job / 'inventory.json').write_text(json.dumps(normalized, indent=2), encoding='utf-8')
        report.update(status='PREPARED_REVIEW_REQUIRED', files=len(accepted),
                      source_manifest_hash=source_hash, missing_dependencies=normalized['missing_count'])
    except (ValueError, OSError) as exc:
        # Only explicit safe validation messages can leave the process.
        report['reason'] = str(exc) if isinstance(exc, ValueError) else 'Local file operation failed.'
        raise ExtractionError(report['reason']) from None
    finally:
        (job / 'status.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return job


def verify(job: Path) -> dict:
    job = assert_local_path(job)
    for path in (job / 'status.json', job / 'manifest.json', job / 'ready'):
        assert_local_path(path)
    status = json.loads((job / 'status.json').read_text(encoding='utf-8'))
    manifest = json.loads((job / 'manifest.json').read_text(encoding='utf-8'))
    if status.get('status') != 'PREPARED_REVIEW_REQUIRED':
        raise ExtractionError('Job is not prepared.')
    items = manifest['files']
    if not items or len(items) > 50:
        raise ExtractionError('Manifest file count is invalid.')
    expected = [f['name'] for f in items]
    if len(set(n.casefold() for n in expected)) != len(expected):
        raise ExtractionError('Manifest contains duplicate names.')
    has_public_manifest = 'upload_manifest_name' in manifest
    if has_public_manifest:
        if manifest['upload_manifest_name'] != UPLOAD_MANIFEST_NAME:
            raise ExtractionError('Prepared upload manifest marker is invalid.')
        expected.append(UPLOAD_MANIFEST_NAME)
    actual = list((job / 'ready').iterdir())
    if sorted(p.name for p in actual) != sorted(expected):
        raise ExtractionError('Prepared files differ from the manifest.')
    accepted = []
    for item in items:
        safe_name(item['name'])
        p = assert_local_path(job / 'ready' / item['name'])
        if p.stat().st_size > 5 * 1024 * 1024:
            raise ExtractionError('Readable file exceeds intake limits.')
        entry = checked_source(p.name, p.read_bytes())
        if entry['sha256'] != item['sha256'] or entry['bytes'] != item['bytes']:
            raise ExtractionError('Prepared file changed; regenerate and repeat approval.')
        accepted.append(entry)
    if sum(f['bytes'] for f in accepted) > MAX_PROJECT_BYTES:
        raise ExtractionError('Readable package exceeds intake limits.')
    calculated = digest(json.dumps(manifest['inputs'], sort_keys=True, separators=(',', ':')).encode())
    if calculated != manifest['source_manifest_hash'] or calculated != status['source_manifest_hash']:
        raise ExtractionError('Source manifest changed; regenerate the job.')
    if inventory(accepted)['source_hash'] != manifest['readable_source_hash']:
        raise ExtractionError('Readable manifest changed; regenerate the job.')
    if has_public_manifest:
        public_path = assert_local_path(job / 'ready' / UPLOAD_MANIFEST_NAME)
        if not public_path.is_file():
            raise ExtractionError('Prepared upload manifest is invalid.')
        with public_path.open('rb') as public_file:
            public_raw = public_file.read(MAX_MANIFEST_BYTES + 1)
        try:
            public_manifest = verify_upload_manifest(public_raw, accepted)
        except PreparedSourceError:
            raise ExtractionError('Prepared upload manifest changed; regenerate the job.') from None
        if public_manifest['extraction_job_id'] != manifest['job_id']:
            raise ExtractionError('Prepared upload manifest changed; regenerate the job.')
    return {'status': 'VERIFIED_REVIEW_REQUIRED', 'files': len(items),
            'source_manifest_hash': calculated, 'approved_for_upload': False,
            'note': 'Integrity is not authorization or proof of redaction. Review before uploading.'}


def main() -> int:
    cli = argparse.ArgumentParser(description='FOX local extractor. No upload, AI call or database connection.')
    cli.add_argument('command', choices=['check', 'prepare', 'verify'])
    cli.add_argument('--source', type=Path)
    cli.add_argument('--output', type=Path, default=Path('work/extractions'))
    cli.add_argument('--job', type=Path)
    cli.add_argument('--job-id')
    cli.add_argument('--oracle-home', type=Path)
    cli.add_argument('--java', type=Path)
    args = cli.parse_args()
    native = OracleFormsBackend(args.oracle_home, args.java) if args.oracle_home and args.java else None
    try:
        if args.command == 'check':
            result = native.check() if native else {'backend': 'readable-v1', 'formats': sorted(ALLOWED)}
        elif args.command == 'verify':
            if not args.job:
                cli.error('--job is required')
            result = verify(args.job)
        else:
            if not args.source:
                cli.error('--source is required')
            job = prepare(args.source, args.output, native, args.job_id)
            result = {'job_directory': str(job), **verify(job)}
        print(json.dumps(result, indent=2))
        return 0
    except ExtractionError as exc:
        print(json.dumps({'status': 'BLOCKED', 'reason': str(exc)}))
        return 1
    except (ValueError, OSError, KeyError, TypeError):
        # Details available in local status.json for preparation, never echo
        # arbitrary JSON, filesystem errors or raw Oracle diagnostics to a UI.
        print(json.dumps({'status': 'BLOCKED', 'reason': 'Extraction or verification failed. Check the local job status and source prerequisites.'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
