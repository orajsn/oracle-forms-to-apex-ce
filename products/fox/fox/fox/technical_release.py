"""Read-only release routing; a project must never downgrade to legacy None.

``checked_release(connection, root, run)`` returns the unchanged checked
``{'proof': dict, 'package': bytes}`` from the appropriate retained reader.
Only an established historical HTML prototype returns None, preserving that
caller's existing accepted-artifact check. Unknown, missing, contradictory or
malformed identity evidence fails closed. Classification is not verification:
all native/project integrity checks remain owned by their versioned readers.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import re
import sqlite3
import stat
import zipfile

from . import native_verification as native


# Keep existing API/recovery consumers' exception boundary compatible.
VerificationError = native.VerificationError


_PROFILES = {
    'native-table-form-v1': 'native', 'native-project-v1': 'project',
    'legacy-html-prototype-v1': 'legacy', 'read-only-html-prototype': 'legacy',
}
_TEMPLATES = {
    'sqlcl-26.1.2-fox-native-v1': 'native',
    'sqlcl-26.1.2-fox-project-v1': 'project',
    'sqlcl-26.1.2-fox-v1': 'legacy',
}
_PROOF_SCOPES = {
    'fox-native-technical-verification-v1': 'native',
    'fox-native-technical-verification-v2': 'native',
    'fox-project-technical-verification-v1': 'project',
}
_PROJECT_MEMBERS = {'native-project-spec.json', 'source-to-apex.json', 'evidence/project-review.json'}
_NATIVE_MEMBERS = {'native-form-spec.json', 'evidence/native-review.json'}
_METADATA_MEMBERS = {
    'native-project-spec.json', 'native-form-spec.json', 'source-to-apex.json',
    'evidence/release-evidence.json', 'evidence/migration-spec.json',
}
_LEGACY_PAGES = {
    'apexlang/pages/p00000-global-page.apx': 0,
    'apexlang/pages/p00001-home.apx': 1,
    'apexlang/pages/p09999-login.apx': 9999,
}


def _require(condition, message):
    if not condition:
        raise native.VerificationError(message)


def _optional_document(path):
    # Broken links must not be treated as missing evidence.
    if not path.exists() and not path.is_symlink():
        return None
    return native._json(native._read(path))


def _identify(document, kinds, *, proof=False):
    _require(isinstance(document, dict), 'Release identity metadata is malformed.')
    for name, supported in (('conversion_profile', _PROFILES), ('template_id', _TEMPLATES)):
        if name in document:
            value = document[name]
            _require(isinstance(value, str) and value in supported,
                     'Release identity uses an unsupported conversion profile or template.')
            kinds.add(supported[value])
    for name, kind in (('native_project', 'project'), ('native_form', 'native')):
        if name in document:
            _require(isinstance(document[name], dict), 'Release native identity is malformed.')
            kinds.add(kind)
    if proof:
        scope = document.get('scope')
        _require(isinstance(scope, str) and scope in _PROOF_SCOPES,
                 'The retained technical proof scope is unsupported.')
        kinds.add(_PROOF_SCOPES[scope])


def _outside_fences(text):
    """Read APEXlang structure without mistaking static HTML for components."""
    result, fenced = [], False
    for line in text.splitlines():
        if line.strip().startswith('```'):
            fenced = not fenced
        elif not fenced:
            result.append(line)
    _require(not fenced, 'Legacy APEXlang contains an unfinished source block.')
    return '\n'.join(result)


def _legacy_inventory(archive, names):
    _require({name for name in names if name.startswith('apexlang/pages/')} == set(_LEGACY_PAGES),
             'Legacy HTML package has missing, additional or renamed pages.')
    for name in names:
        if not name.startswith('apexlang/') or not name.endswith('.apx'):
            continue
        structure = _outside_fences(archive.read(name).decode('utf-8'))
        ids = [int(value) for value in re.findall(r'^\s*page\s+([0-9]+)\s*\(', structure, re.MULTILINE)]
        _require(ids == ([_LEGACY_PAGES[name]] if name in _LEGACY_PAGES else []),
                 'Legacy APEXlang embeds an unexpected page identity.')
        _require(not re.search(r'^\s*type\s*:\s*(?:form|interactiveReport|interactiveGrid|formInitialization|formAutoRowProcessing)\b',
                               structure, re.MULTILINE), 'Legacy HTML package contains native table-form components.')
    sql_name = next(name for name in names if re.fullmatch(r'sql/f[1-9][0-9]*\.sql', name))
    sql = archive.read(sql_name).decode('utf-8')
    ids = [int(value) for value in re.findall(
        r'\bwwv_flow_(?:imp_page|api)\.create_page\s*\(\s*p_id\s*=>\s*([0-9]+)\s*[,)]', sql, re.IGNORECASE)]
    _require(sorted(ids) == [0, 1, 9999]
             and not re.search(r"\bp_(?:plug_source|process)_type\s*=>\s*'(?:NATIVE_FORM(?:_[A-Z_]+)?|NATIVE_IR|NATIVE_IG)'", sql, re.IGNORECASE),
             'Legacy conventional SQL does not match the known HTML page/component inventory.')


def _package_identity(raw, kinds):
    """Inspect bounded exact ZIP metadata, without extracting or executing it.

    The native/project reader owns package validation. For a historical legacy
    fallback there is no such reader, so require an intact manifest and the
    known HTML template plus package release metadata before returning None.
    """
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        _require(len(names) == len(set(names)) and 0 < len(names) <= 500
                 and sum(entry.file_size for entry in entries) <= 20_000_000,
                 'Release package member inventory is invalid or oversized.')
        for entry in entries:
            name = entry.filename
            _require(name and not name.startswith('/') and '\\' not in name and ':' not in name
                     and not any(part in {'', '.', '..'} for part in name.split('/'))
                     and not entry.is_dir() and not entry.flag_bits & 1
                     and not stat.S_ISLNK(entry.external_attr >> 16), 'Release package contains an unsafe member.')
        _require(archive.getinfo('manifest.json').file_size <= 2_000_000, 'Release package manifest is oversized.')
        manifest = native._json(archive.read('manifest.json'))
        # Inspect both actual names and manifest claims. A missing project
        # member must not make the remaining archive look like a legacy app.
        claimed = set(names) | set(manifest)
        if claimed & _PROJECT_MEMBERS or any(name.startswith('evidence/form-reviews/') for name in claimed):
            kinds.add('project')
        if claimed & _NATIVE_MEMBERS:
            kinds.add('native')
        documents = {}
        for name in sorted(set(names) & _METADATA_MEMBERS):
            _require(archive.getinfo(name).file_size <= 2_000_000, 'Release package metadata is oversized.')
            value = native._json(archive.read(name))
            documents[name] = value
            _identify(value, kinds)
            if name in {'native-project-spec.json', 'native-form-spec.json'}:
                profile = value.get('profile_id')
                expected = 'native-project-v1' if name == 'native-project-spec.json' else 'native-table-form-v1'
                _require(profile == expected, 'Packaged native profile differs from its identity member.')
            if name == 'source-to-apex.json':
                version = value.get('schema_version')
                _require(type(version) is int and version in (1, 2)
                         and value.get('scope') == 'fox-native-project-render-trace-v' + str(version),
                         'Packaged project trace scope is unsupported.')
        spec, release = documents.get('evidence/migration-spec.json', {}), documents.get('evidence/release-evidence.json', {})
        legacy = (spec.get('template_id') == 'sqlcl-26.1.2-fox-v1'
                  and release.get('conversion_profile') == 'read-only-html-prototype')
        if legacy:
            _require(set(names) == set(manifest) | {'manifest.json'}, 'Legacy package manifest membership differs.')
            for name, digest in manifest.items():
                _require(isinstance(digest, str) and re.fullmatch(r'[a-f0-9]{64}', digest)
                         and hashlib.sha256(archive.read(name)).hexdigest() == digest,
                         'Legacy package manifest bytes differ.')
            _require('apexlang/application.apx' in names
                     and len([name for name in names if re.fullmatch(r'sql/f[1-9][0-9]*\.sql', name)]) == 1
                     and not any(name.startswith(('schema/', 'native-')) for name in names),
                     'Legacy package member inventory is not the supported HTML prototype.')
            _legacy_inventory(archive, names)
        return legacy


def _checked_release(connection, root, run):
    _require(isinstance(run, dict) and isinstance(run.get('id'), str)
             and re.fullmatch(r'fox-[a-f0-9]{20}', run['id']), 'Invalid release run identity.')
    root = native._safe_path(Path(root))
    job = root / 'jobs' / run['id']
    kinds = set()
    _identify(run, kinds)
    for name in ('source-snapshot.json', 'release-evidence.json'):
        document = _optional_document(job / name)
        if document is not None:
            _identify(document, kinds)
            if name == 'source-snapshot.json' and 'inventory' in document:
                _identify(document['inventory'], kinds)
    retained = _optional_document(job / 'technical-verification' / 'verification.json')
    if retained is not None:
        _identify(retained, kinds, proof=True)
    project_pipeline = job / 'native-project-pipeline'
    if project_pipeline.exists() or project_pipeline.is_symlink():
        # Even an incomplete conversion cache establishes project identity.
        # Deleted metadata must not expose a legacy/native fallback route.
        kinds.add('project')
        _require(project_pipeline.is_dir() and not project_pipeline.is_symlink(),
                 'Project pipeline evidence directory is unsafe.')
    project_retention = job / 'project-technical-verification'
    if project_retention.exists() or project_retention.is_symlink():
        # A partially retained attempt is already a project marker. It cannot
        # disappear from routing merely because verification.json is absent.
        kinds.add('project')
        _require(project_retention.is_dir() and not project_retention.is_symlink(),
                 'Project retained evidence directory is unsafe.')
        project_proof = _optional_document(project_retention / 'verification.json')
        if project_proof is not None:
            _identify(project_proof, kinds, proof=True)
    table = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
    if table:
        stored = connection.execute('SELECT proof_json FROM technical_verifications WHERE run=?', (run['id'],)).fetchone()
        if stored is not None:
            _require(isinstance(stored[0], str), 'The stored technical proof is malformed.')
            _identify(native._json(stored[0].encode('utf-8')), kinds, proof=True)
    artifact = run.get('artifact')
    if artifact is not None:
        _require(isinstance(artifact, str) and artifact.replace('\\', '/') == f"jobs/{run['id']}/apex-package.zip",
                 'The run points outside its exact release package.')
    package = job / 'apex-package.zip'
    legacy_package = False
    if package.exists() or package.is_symlink():
        legacy_package = _package_identity(native._read(package, 8_000_000), kinds)
    elif artifact is not None:
        _require(False, 'The declared release package is unavailable.')
    _require(len(kinds) == 1, 'Release identity is missing or contradictory; no legacy fallback is permitted.')
    kind = next(iter(kinds))
    if kind == 'legacy':
        retention = job / 'technical-verification'
        _require(legacy_package and retained is None and not retention.exists() and not retention.is_symlink(),
                 'A historical HTML package must be established before the legacy path is used.')
        # The old reader remains the final authority for an established legacy
        # path as well; any retained row unknown to this classifier still fails.
        checked = native.checked_native_release(connection, root, run)
        _require(checked is None, 'A historical HTML package has unexpected native verification evidence.')
        return None
    if kind == 'project':
        from .project_verification_runtime import checked_project_release
        checked = checked_project_release(connection, root, run)
    else:
        checked = native.checked_native_release(connection, root, run)
    _require(isinstance(checked, dict) and set(checked) == {'proof', 'package'}
             and isinstance(checked['proof'], dict) and isinstance(checked['package'], bytes)
             and bool(checked['package']), 'Native or project verification did not return a checked package.')
    return checked


def checked_release(connection: sqlite3.Connection, root: Path, run: dict):
    """Compatible read-only retained reader; never writes state or acceptance.

    Native v1/v2 are delegated unchanged. Projects are always delegated to the
    project retained reader and can never return None. Missing identity blocks,
    including when an unverified project was incorrectly marked REVIEW_REQUIRED
    or ACCEPTED by an older worker.
    """
    try:
        return _checked_release(connection, root, run)
    except native.VerificationError:
        raise
    except (OSError, TypeError, ValueError, KeyError, AttributeError, RecursionError,
            sqlite3.Error, zipfile.BadZipFile, RuntimeError, ImportError):
        raise native.VerificationError('Release identity or retained technical evidence is unavailable or malformed.') from None
