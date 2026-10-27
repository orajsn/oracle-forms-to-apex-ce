"""Read-only, whitelisted business status for an exact multi-form run.

Advisory progress can explain activity, never establish completion. Generation
requires restored source/review-bound receipts or the actual verified package;
technical verification and human acceptance remain separate authorities.
No source, provider response, configuration, credential, or exception is returned.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit
import zipfile

from . import native_verification as safe_io
from .native_project_pipeline import _restore_progress, verify_project_package
from .opaf import OpafError, canonical_hash, validate_model_environment
from .project_conversion import PROFILE_ID, assess_project_conversion, module_execution_binding
from .project_progress import read_project_progress
from .technical_release import checked_release, _identify, _package_identity


_PROJECT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z')
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_STATES = {'QUEUED', 'PROCESSING', 'ATTENTION', 'FAILED', 'QA_REQUIRED', 'REVIEW_REQUIRED', 'VERIFIED', 'ACCEPTED'}
# Historical JSN product target, also recorded by forms2apex.target_profile.
# This is NOT the independent FOX_QA workspace or authority for a new deploy.
_PRODUCT_WORKSPACE = 'FORMS2APEX_POC'
_ERROR = {'message': 'The retained run evidence needs a check before this result can be used.',
          'action': 'Check run status. If this continues, contact the FOX support team with the run ID.', 'owner': 'OPERATOR'}
_STOPPED = {'message': 'Conversion stopped before all required checks were completed.',
            'action': 'Check run status and ask the FOX support team to inspect the retained work before continuing.', 'owner': 'OPERATOR'}


def _need(condition):
    if not condition:
        raise ValueError('Unbound project presentation evidence')


def _exists(path):
    """Broken links count as evidence, so they fail instead of disappearing."""
    return path.exists() or path.is_symlink()


class _Retained:
    """Bounded, duplicate-key-free, frozen documents for one status read."""
    def __init__(self):
        self.documents = {}

    def read(self, path):
        if path not in self.documents:
            self.documents[path] = safe_io._json(safe_io._read(path))
        return self.documents[path]

    def role(self, checkpoints, name, client, role, request):
        # This is ONLY the completed branch of native_pipeline._role. There
        # is deliberately no client, target loader, intent, writer or replay.
        _need(client is None and name in {'mapper', 'reviewer'})
        saved = self.read(checkpoints / (name + '.json'))
        digest = canonical_hash(request)
        _need(saved.get('request_sha256') == digest and saved.get('role') == role
              and saved.get('output_sha256') == canonical_hash(saved.get('output'))
              and saved.get('invocation', {}).get('request_sha256') == digest
              and isinstance(saved.get('model_environment'), dict)
              and saved.get('model_environment_sha256') == canonical_hash(saved['model_environment']))
        target = self.read(checkpoints / 'target-profile.json')['target_profile']
        validate_model_environment(saved['model_environment'], target, name, request, saved['invocation'])
        return saved['output'], saved['invocation']


class _Milestones:
    """Pure sink for the existing checkpoint validator; never publishes."""
    def __init__(self, ids):
        self.forms = {module: 'pending' for module in ids}
        self.active_module = None

    def form(self, module, stage):
        _need(module in self.forms and stage in {'mapped', 'reviewed'})
        self.forms[module] = stage

    def generated(self):
        self.forms = dict.fromkeys(self.forms, 'generated')


def _generation(job, snapshot, plan, retained, milestones):
    checkpoints = job / 'native-project-pipeline'
    if not _exists(checkpoints):
        return False
    safe_io._safe_path(checkpoints)
    # Check expected optional paths before the executor's exists() branches,
    # including broken links; unrelated files are neither read nor displayed.
    expected = [checkpoints / name for name in
                ('binding.json', 'inspection.json', 'target-profile.json', 'review-receipt.json', 'generated.json')]
    for module in milestones.forms:
        child = checkpoints / module
        if _exists(child):
            safe_io._safe_path(child)
        expected.extend(child / name for name in
                        ('binding.json', 'target-profile.json', 'mapper.json', 'reviewer.json', 'review-receipt.json'))
    for path in expected:
        if _exists(path):
            retained.read(path)
    binding = retained.read(checkpoints / 'binding.json')
    version = snapshot['native_project']['schema_version']
    _need(type(version) is int and version in (1, 2)
          and type(binding.get('schema_version')) is int and binding['schema_version'] == version)
    generated = _restore_progress(job, snapshot, plan, milestones, read=retained.read, restore_role=retained.role)
    if not generated:
        return False
    # The executor's compact child receipts are references, not complete
    # seals. Bind each reference to the sealed parent's complete module set.
    parent = retained.read(checkpoints / 'review-receipt.json')
    _need(type(parent.get('schema_version')) is int and parent['schema_version'] == version
          and parent.get('scope') == 'fox-native-project-review-v' + str(version)
          and parent.get('trust_boundary') == 'authenticated_fox_executor_not_vendor_attestation'
          and parent.get('job_id') == job.name and parent.get('source_hash') == snapshot['source_hash']
          and parent.get('receipt_sha256') == canonical_hash({key: value for key, value in parent.items() if key != 'receipt_sha256'}))
    if version == 2:
        _need(parent.get('project_id') == plan['project_id'] and parent.get('plan_sha256') == plan['plan_sha256'])
    references = []
    for module in sorted(milestones.forms):
        child = checkpoints / module
        receipt = retained.read(child / 'review-receipt.json')
        candidate = retained.read(child / 'mapper.json')['output']
        binding = module_execution_binding(plan, parent_job_id=job.name, module_id=module)
        references.append({'module_id': module, 'child_job_id': binding['child_job_id'],
                           'candidate_sha256': canonical_hash(candidate), 'receipt_sha256': receipt['receipt_sha256'],
                           **({'execution_binding': binding} if version == 2 else {})})
    _need(parent.get('form_reviews') == references)
    parent_bytes = json.dumps(parent, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode() + b'\n'
    generated = retained.read(checkpoints / 'generated.json')
    _need(type(generated.get('schema_version')) is int and generated['schema_version'] == version
          and generated['artifact_binding'].get('project_review_sha256') == hashlib.sha256(parent_bytes).hexdigest())
    return True


def _package(job, snapshot, retained, run):
    raw = safe_io._read(job / 'apex-package.zip', 8_000_000)
    release = retained.read(job / 'release-evidence.json')
    envelope = retained.read(job / 'native-project-pipeline' / 'target-profile.json')
    _need(set(envelope) == {'target_profile', 'target_profile_sha256'}
          and isinstance(envelope['target_profile'], dict)
          and envelope['target_profile_sha256'] == canonical_hash(envelope['target_profile'])
          and release.get('job_id') == run['id'])
    artifact = run.get('artifact')
    _need(artifact is None or isinstance(artifact, str)
          and artifact.replace('\\', '/') == f"jobs/{run['id']}/apex-package.zip")
    digest = verify_project_package(raw, release, snapshot['native_project'], envelope['target_profile'])
    return raw, digest, release, envelope['target_profile']


def _preview(release, target=None):
    """Return an existing bound product URL, never the detached QA target.

    Project callers first validate their sealed target profile and package.
    Historical native v1 predates target profiles: its proof/package-bound
    release URL must match the known JSN product workspace. Missing evidence
    never creates a URL. This is a preview link, not live-export attestation.
    """
    try:
        workspace, alias = _PRODUCT_WORKSPACE, release['application_alias']
        if target is not None:
            apex = target['apex']
            _need(apex['workspace'] == workspace
                  and apex['ords_origin'] + apex['ords_base_path'] == safe_io.ORDS)
        _need(all(isinstance(value, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}', value)
                  for value in (workspace, alias)))
        expected = safe_io.ORDS + '/r/' + workspace.lower() + '/' + alias.lower() + '/'
        actual = release.get('application_url')
        _need(isinstance(actual, str))
        parsed, canonical = urlsplit(actual), urlsplit(expected)
        # ASCII host case is harmless. Preserve every other character: reject
        # ports, credentials, query/fragment, encoded paths and URL whitespace.
        return expected if (actual == 'https://' + parsed.netloc + canonical.path
                            and parsed.netloc.isascii()
                            and parsed.netloc.lower() == canonical.netloc) else None
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _historical_preview(package, proof):
    """Read the original release from the exact already-checked package bytes."""
    try:
        with zipfile.ZipFile(io.BytesIO(package)) as archive:
            release = safe_io._json(archive.read('evidence/release-evidence.json'))
        _need(canonical_hash(release) == proof['release_evidence_sha256']
              and release.get('job_id') == proof['job_id']
              and release.get('source_manifest_sha256') == proof['source_manifest_sha256'])
        return _preview(release)
    except (safe_io.VerificationError, OpafError, OSError, ValueError, KeyError,
            TypeError, AttributeError, zipfile.BadZipFile):
        return None


def _steps(state, generated, technical, accepted, error):
    return [
        {'id': 'sources', 'label': 'Check source files', 'state': 'complete'},
        {'id': 'generation', 'label': 'Generate application', 'state': 'complete' if generated else
         'blocked' if error else 'running' if state == 'PROCESSING' else 'pending'},
        {'id': 'technical', 'label': 'Run technical checks', 'state': 'complete' if technical else
         'blocked' if error and generated else 'running' if state == 'QA_REQUIRED' and generated else 'pending'},
        {'id': 'acceptance', 'label': 'Review and accept', 'state': 'complete' if accepted else 'pending'},
    ]


def is_project_run(root: Path, run: dict):
    """Conservative presentation routing, not a release authorization check.

Only explicit, consistent legacy/single-form identities keep their old UI.
Unknown, malformed or contradictory evidence uses the closed project DTO;
a deleted snapshot can never erase retained project/package markers.
"""
    try:
        _need(isinstance(run.get('id'), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}', run['id']))
        root = safe_io._safe_path(Path(root))
        job = safe_io._safe_path(root / 'jobs' / run['id'])
        if any(_exists(job / name) for name in ('native-project-pipeline', 'project-technical-verification')):
            return True
        kinds = set()
        _identify(run, kinds)
        retained = _Retained()
        for name in ('source-snapshot.json', 'release-evidence.json', 'technical-verification/verification.json'):
            path = job / name
            if not _exists(path):
                continue
            document = retained.read(path)
            _identify(document, kinds, proof=name.startswith('technical-verification/'))
            if name == 'source-snapshot.json' and 'inventory' in document:
                _identify(document['inventory'], kinds)
        package = job / 'apex-package.zip'
        if _exists(package):
            _package_identity(safe_io._read(package, 8_000_000), kinds)
        return kinds not in ({'native'}, {'legacy'})
    except (safe_io.VerificationError, OpafError, OSError, ValueError, KeyError, TypeError,
            AttributeError, RecursionError, RuntimeError, zipfile.BadZipFile):
        return True


def project_run_status(connection: sqlite3.Connection, root: Path, run: dict, current_source_hash):
    """Return only business presentation fields; never mutate or perform I/O remotely.

The caller supplies an authorized run row and the current selected source
hash. Historical acceptance may enable download; review is current-source only.
The caller must not use this DTO as a mutation or download authorization gate.
"""
    project = run.get('project')
    result = {'project_id': project if isinstance(project, str) and _PROJECT.fullmatch(project) else '',
              'artifact_generated': False, 'technical_verified': False,
              'human_accepted': False, 'downloadable': False, 'preview_available': False, 'review_available': False,
              'steps': [], 'forms': [], 'recovery': {'kind': 'check_status', 'enabled': True,
                                                   'safety': 'read_only', 'label': 'Check run status'}}
    try:
        _need(isinstance(run.get('id'), str) and re.fullmatch(r'fox-[a-f0-9]{20}', run['id'])
              and isinstance(run.get('project'), str) and _PROJECT.fullmatch(run['project'])
              and isinstance(run.get('source_hash'), str) and _SHA.fullmatch(run['source_hash'])
              and run.get('state') in _STATES)
        root = safe_io._safe_path(Path(root))
        job = safe_io._safe_path(root / 'jobs' / run['id'])
        retained = _Retained()
        snapshot = retained.read(job / 'source-snapshot.json')
        _need(snapshot.get('conversion_profile') == PROFILE_ID and snapshot.get('project_id') == run['project']
              and snapshot.get('project', run['project']) == run['project'] and snapshot.get('source_hash') == run['source_hash'])
        plan = assess_project_conversion(snapshot['files'], project_id=snapshot['project_id'],
                                        project_name=snapshot['project_name'], source_hash=snapshot['source_hash'])
        _need(plan['state'] == 'READY' and plan['can_generate'] is True and plan['assessment_complete'] is True
              and plan['rendering_spec'] == snapshot.get('native_project') and plan['plan_sha256'] == snapshot.get('plan_sha256'))
        ids = sorted(form['module_id'] for form in plan['forms'])
        milestones = _Milestones(ids)
        advisory = read_project_progress(job, job_id=run['id'], source_hash=run['source_hash'],
                                         plan_sha256=plan['plan_sha256'], module_ids=ids)
        activities = {row['module_id']: row['stage'] for row in advisory.get('forms', [])}
        stopped = run['state'] in {'ATTENTION', 'FAILED'}
        error = dict(_STOPPED) if stopped else None
        try:
            package = digest = None
            package_marked = any(_exists(job / name) for name in ('apex-package.zip', 'release-evidence.json'))
            package_marked = package_marked or run.get('artifact') is not None
            if package_marked:
                package, digest, release, target = _package(job, snapshot, retained, run)
                result['artifact_generated'] = True
                milestones.generated()
                preview = _preview(release, target)
                if preview:
                    result.update(preview_available=True, application_url=preview)
            else:
                result['artifact_generated'] = _generation(job, snapshot, plan, retained, milestones)
            if run['state'] in {'VERIFIED', 'ACCEPTED'}:
                checked = checked_release(connection, root, run)
                _need(result['artifact_generated'] and isinstance(checked, dict)
                      and checked['proof'].get('scope') == 'fox-project-technical-verification-v1'
                      and checked['package'] == package)
                result['technical_verified'] = True
                # Retain the original package/profile-bound product preview.
                # The clean app is detached technical proof, not business access.
                accepted = connection.execute(
                    'SELECT a.owner,a.source_hash,a.artifact_sha256,p.owner FROM acceptances a JOIN projects p ON p.id=? '
                    'WHERE a.run=?', (run['project'], run['id'])).fetchone()
                acceptance_bound = (accepted is not None and accepted[0] == accepted[3]
                                    and accepted[1] == run['source_hash'] and accepted[2] == digest)
                result['human_accepted'] = run['state'] == 'ACCEPTED' and acceptance_bound
                result['downloadable'] = result['human_accepted']
                result['review_available'] = (run['state'] == 'VERIFIED' and accepted is None
                                              and run['source_hash'] == current_source_hash)
                if (accepted is not None and not acceptance_bound
                        or run['state'] == 'ACCEPTED' and not result['human_accepted']):
                    error = dict(_ERROR)
        except (safe_io.VerificationError, OpafError, OSError, sqlite3.Error, ValueError, KeyError,
                TypeError, AttributeError, RecursionError, RuntimeError):
            error = dict(_ERROR)
            # A failed restore can have called the in-memory generated sink
            # before its final binding check. Never publish that partial fact.
            if not result['artifact_generated']:
                milestones = _Milestones(ids)
        result['forms'] = []
        for module in ids:
            milestone, activity = milestones.forms[module], activities.get(module)
            form_state = ('generated' if result['artifact_generated'] else
                          'failed' if run['state'] == 'FAILED' and activity == 'attention' else
                          'blocked' if error and activity == 'attention' else
                          'running' if run['state'] == 'PROCESSING' and activity in {'mapping', 'reviewing'} else 'queued')
            message = ('Included in the generated application; technical checks and acceptance are separate.' if form_state == 'generated' else
                       'Processing needs the FOX support team to check the retained work.' if form_state in {'failed', 'blocked'} else
                       'Independent review completed; application generation is pending.' if milestone == 'reviewed' else
                       'Mapping completed; independent review is pending.' if milestone == 'mapped' else
                       'Processing this form.' if form_state == 'running' else 'Waiting for processing.')
            result['forms'].append({'module_id': module, 'state': form_state, 'message': message})
        result['steps'] = _steps(run['state'], result['artifact_generated'], result['technical_verified'], result['human_accepted'], error)
        if error:
            result['error'] = error
        return result
    except (safe_io.VerificationError, OpafError, OSError, sqlite3.Error, ValueError, KeyError,
            TypeError, AttributeError, RecursionError, RuntimeError):
        result['error'] = dict(_ERROR)
        return result


def historical_native_run_status(connection: sqlite3.Connection, root: Path, run: dict, current_source_hash):
    """Present an established native v1/v2 release without upgrading its proof.

Return None ONLY when the shared read-only dispatcher establishes a genuine
historical HTML package. Unknown or unproved native evidence returns closed
flags, never an invented technical success or a legacy fallback. Historical
single-form releases do not acquire made-up multi-form module identities.
"""
    project = run.get('project')
    result = {'project_id': project if isinstance(project, str) and _PROJECT.fullmatch(project) else '',
              'artifact_generated': False, 'technical_verified': False, 'human_accepted': False,
              'downloadable': False, 'preview_available': False, 'review_available': False,
              'steps': [], 'forms': [], 'recovery': {'kind': 'check_status', 'enabled': True,
                                                   'safety': 'read_only', 'label': 'Check run status'}}
    try:
        _need(isinstance(run.get('id'), str) and re.fullmatch(r'fox-[a-f0-9]{20}', run['id'])
              and isinstance(project, str) and _PROJECT.fullmatch(project)
              and isinstance(run.get('source_hash'), str) and _SHA.fullmatch(run['source_hash'])
              and run.get('state') in _STATES)
        checked = checked_release(connection, root, run)
        if checked is None:
            return None
        proof, package = checked['proof'], checked['package']
        version = proof.get('schema_version')
        _need(type(version) is int and version in (1, 2)
              and proof.get('scope') == f'fox-native-technical-verification-v{version}'
              and proof.get('conversion_profile') == 'native-table-form-v1'
              and proof.get('job_id') == run['id'] and proof.get('source_manifest_sha256') == run['source_hash']
              and run['state'] in {'VERIFIED', 'ACCEPTED'} and isinstance(package, bytes) and bool(package))
        digest = hashlib.sha256(package).hexdigest()
        _need(digest == proof.get('package_sha256'))
        root = safe_io._safe_path(Path(root))
        job = safe_io._safe_path(root / 'jobs' / run['id'])
        retained = _Retained()
        snapshot = retained.read(job / 'source-snapshot.json')
        _need(snapshot.get('conversion_profile') == 'native-table-form-v1'
              and snapshot.get('project') == project and snapshot.get('source_hash') == run['source_hash'])
        target = proof['target']
        workspace, alias = target['workspace'], proof['clean_application_alias']
        _need(isinstance(workspace, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}', workspace)
              and isinstance(alias, str) and re.fullmatch(r'F2A_[A-Z0-9_]{1,60}', alias)
              and (version != 1 or workspace == safe_io.WORKSPACE))
        preview = safe_io.ORDS + '/r/' + workspace.lower() + '/' + alias.lower() + '/'
        qa_target = retained.read(job / 'technical-verification' / 'qa-target.json')
        target_url = qa_target.get('url')
        # Cross-check the retained URL receipt too, without changing the old
        # reader/schema or applying today's policy to a historical decision.
        _need(proof.get('clean_application_url') == preview and isinstance(target_url, str) and target_url.lower() == preview
              and qa_target.get('workspace') == workspace and qa_target.get('alias') == alias
              and type(proof.get('clean_application_id')) is int and proof['clean_application_id'] > 0
              and qa_target.get('application_id') == proof['clean_application_id'])
        result.update(artifact_generated=True, technical_verified=True)
        product_preview = _historical_preview(package, proof)
        if product_preview:
            result.update(preview_available=True, application_url=product_preview)
        accepted = connection.execute(
            'SELECT a.owner,a.source_hash,a.artifact_sha256,p.owner FROM acceptances a JOIN projects p ON p.id=? '
            'WHERE a.run=?', (project, run['id'])).fetchone()
        acceptance_bound = (accepted is not None and accepted[0] == accepted[3]
                            and accepted[1] == run['source_hash'] and accepted[2] == digest)
        result['human_accepted'] = run['state'] == 'ACCEPTED' and acceptance_bound
        result['downloadable'] = result['human_accepted']
        result['review_available'] = run['state'] == 'VERIFIED' and accepted is None and run['source_hash'] == current_source_hash
        error = None
        if (accepted is not None and (not acceptance_bound or run['state'] != 'ACCEPTED')
                or run['state'] == 'ACCEPTED' and not result['human_accepted']):
            error = dict(_ERROR)
        result['steps'] = _steps(run['state'], True, True, result['human_accepted'], error)
        if error:
            result['error'] = error
        return result
    except (safe_io.VerificationError, OpafError, OSError, sqlite3.Error, ValueError, KeyError,
            TypeError, AttributeError, RecursionError, RuntimeError):
        result['error'] = dict(_ERROR)
        return result
