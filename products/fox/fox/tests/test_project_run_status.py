"""Business DTO reads actual package/proof bytes without changing retained work.

Package-positive cases use the real converter release fixture. The checkpoint
case isolates only external transports, not the status/checkpoint validators.
"""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import zipfile

import pytest

from fox import project_run_status as status
from fox.opaf import OpafError
from fox.project_progress import ProjectProgress
from project_generation_test_support import GeneratedProject
from test_project_verification_runtime import actual_release, case, promote, row, change_sources, put, observations, raw, sha


FIELDS = {'project_id', 'artifact_generated', 'technical_verified', 'human_accepted', 'downloadable',
          'preview_available', 'review_available', 'application_url', 'steps', 'forms', 'recovery', 'error'}


def present(case, source_hash=None):
    with sqlite3.connect(case.root / 'fox.sqlite3') as db:
        return status.project_run_status(db, case.root, row(case), source_hash or case.snapshot['source_hash'])


def files(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob('*') if path.is_file()}


def accept_fixture(case):
    """Projection-only synthetic DB setup, not a claim of live human acceptance."""
    with sqlite3.connect(case.root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)', (case.run_id, 'synthetic-owner',
            case.snapshot['source_hash'], hashlib.sha256(case.built.package).hexdigest(), 'Synthetic projection fixture only', 1))
        db.execute("UPDATE runs SET state='ACCEPTED' WHERE id=?", (case.run_id,))


def test_actual_package_is_generated_not_verified_or_accepted(case):
    before = files(case.root)
    result = present(case)
    assert result['artifact_generated'] is True
    assert result['technical_verified'] is result['human_accepted'] is result['downloadable'] is result['review_available'] is False
    assert result['preview_available'] is True and result['application_url'] == case.built.evidence['application_url']
    assert len(result['forms']) == 2 and {item['state'] for item in result['forms']} == {'generated'}
    assert result['steps'][1]['state'] == 'complete' and result['steps'][2]['state'] == 'running'
    assert result['recovery'] == {'kind': 'check_status', 'enabled': True, 'safety': 'read_only', 'label': 'Check run status'}
    assert set(result) <= FIELDS and 'error' not in result
    assert files(case.root) == before


def test_actual_checked_proof_enables_review_but_not_acceptance(case):
    promote(case)
    before = files(case.root)
    result = present(case)
    assert result['technical_verified'] is result['review_available'] is True
    assert result['human_accepted'] is result['downloadable'] is False
    assert result['application_url'] == case.built.evidence['application_url']
    assert result['application_url'] != json.loads((case.retained / 'verification.json').read_bytes())['clean_application_url']
    assert files(case.root) == before
    change_sources(case)
    historical = present(case, 'e' * 64)
    assert historical['technical_verified'] is True and historical['review_available'] is False
    assert historical['application_url'] == case.built.evidence['application_url']


def test_acceptance_is_bound_to_owner_source_package_and_remains_historical(case):
    promote(case)
    accept_fixture(case)
    change_sources(case)
    result = present(case, 'e' * 64)
    assert result['human_accepted'] is result['downloadable'] is True
    assert result['review_available'] is False
    assert result['application_url'] == case.built.evidence['application_url']


@pytest.mark.parametrize('column,value', [('owner', 'different-owner'), ('source_hash', '0' * 64), ('artifact_sha256', '0' * 64)])
def test_acceptance_without_exact_binding_cannot_enable_download(case, column, value):
    promote(case)
    accept_fixture(case)
    with sqlite3.connect(case.root / 'fox.sqlite3') as db:
        db.execute(f'UPDATE acceptances SET {column}=? WHERE run=?', (value, case.run_id))
    result = present(case)
    assert result['artifact_generated'] is result['technical_verified'] is True
    assert result['human_accepted'] is result['downloadable'] is False
    assert result['error']['owner'] == 'OPERATOR'


@pytest.mark.parametrize('state', ['VERIFIED', 'ACCEPTED'])
def test_database_state_alone_never_establishes_verification_or_acceptance(case, state):
    with sqlite3.connect(case.root / 'fox.sqlite3') as db:
        db.execute('UPDATE runs SET state=?,message=? WHERE id=?', (state, 'PRIVATE PROVIDER RESPONSE', case.run_id))
    result = present(case)
    assert result['artifact_generated'] is True
    assert result['technical_verified'] is result['human_accepted'] is result['downloadable'] is result['review_available'] is False
    assert 'PRIVATE PROVIDER RESPONSE' not in json.dumps(result)
    assert result['error'] == status._ERROR


@pytest.mark.parametrize('relative', ['apex-package.zip', 'release-evidence.json', 'native-project-pipeline/target-profile.json'])
def test_corrupt_package_or_binding_is_not_generated_and_has_no_preview(case, relative):
    (case.job / relative).write_bytes(b'PRIVATE MALFORMED PROVIDER CONTENT')
    result = present(case)
    assert not any(result[name] for name in ('artifact_generated', 'technical_verified', 'human_accepted', 'downloadable', 'preview_available', 'review_available'))
    assert 'application_url' not in result
    assert 'PRIVATE MALFORMED' not in json.dumps(result)
    assert {item['module_id'] for item in result['forms']} == {form['module_id'] for form in case.built.project['forms']}


@pytest.mark.parametrize('change', ['source', 'form', 'plan', 'project', 'profile', 'duplicate_json', 'oversized'])
def test_snapshot_is_replanned_before_exposing_any_form_identity(case, change):
    snapshot = deepcopy(case.snapshot)
    if change == 'source': snapshot['files'][0]['text'] += '\n'
    elif change == 'form': snapshot['native_project']['forms'][0]['module_id'] = 'form-' + '0' * 20
    elif change == 'plan': snapshot['plan_sha256'] = '0' * 64
    elif change == 'project': snapshot['project_id'] = 'other-project'
    elif change == 'profile': snapshot['conversion_profile'] = 'legacy-html-prototype-v1'
    path = case.job / 'source-snapshot.json'
    if change == 'duplicate_json': path.write_bytes(b'{"conversion_profile":"native-project-v1","conversion_profile":"legacy-html-prototype-v1"}')
    elif change == 'oversized': path.write_bytes(b' ' * 2_000_001)
    else: put(path, snapshot)
    result = present(case)
    assert result['forms'] == result['steps'] == []
    assert result['artifact_generated'] is result['technical_verified'] is False
    assert result['error'] == status._ERROR


def test_advisory_generated_and_verified_flags_cannot_create_completion(case):
    (case.job / 'apex-package.zip').unlink()
    (case.job / 'release-evidence.json').unlink()
    # A real fresh job before any immutable pipeline checkpoint exists.
    (case.job / 'native-project-pipeline/download.json').unlink()
    (case.job / 'native-project-pipeline/target-profile.json').unlink()
    (case.job / 'native-project-pipeline').rmdir()
    with sqlite3.connect(case.root / 'fox.sqlite3') as db:
        db.execute("UPDATE runs SET artifact=NULL,state='PROCESSING' WHERE id=?", (case.run_id,))
    plan = status.assess_project_conversion(case.snapshot['files'], project_id=case.snapshot['project_id'],
        project_name=case.snapshot['project_name'], source_hash=case.snapshot['source_hash'])
    advisory = ProjectProgress(case.job, plan)
    advisory.generated()
    before = files(case.root)
    result = present(case)
    assert result['artifact_generated'] is result['technical_verified'] is result['human_accepted'] is False
    assert {form['state'] for form in result['forms']} == {'queued'}
    assert files(case.root) == before


@pytest.fixture(params=[1, 2], ids=['native-v1', 'mapped-v2'])
def generated(tmp_path, monkeypatch, request):
    root = tmp_path / 'data'; jobs = root / 'jobs'; jobs.mkdir(parents=True)
    # Same explicit temporary OS boundary as the real-package fixture. Do not
    # require sandbox access to protected Windows ancestors above this test.
    def confined(path):
        path = Path(path).absolute()
        resolved = path.resolve(strict=True)
        if path != resolved or not path.is_relative_to(tmp_path):
            raise status.safe_io.VerificationError('Synthetic fixture escaped its temporary root')
        for parent in (path, *path.parents):
            if parent == tmp_path:
                break
            if parent.is_symlink():
                raise status.safe_io.VerificationError('Synthetic fixture is linked')
        return path
    monkeypatch.setattr(status.safe_io, '_safe_path', confined)
    harness = GeneratedProject(tmp_path, jobs, monkeypatch, request.param)
    with pytest.raises(OpafError, match='Synthetic disconnected'):
        harness.run()
    assert status._generation(harness.job, harness.snapshot, harness.plan, status._Retained(),
                              status._Milestones(form['module_id'] for form in harness.plan['forms'])) is True
    assert not (harness.job / 'apex-package.zip').exists()
    assert not (harness.converter_root / 'apex-package.zip').exists()
    assert not (harness.converter_root / 'import-intent.json').exists()
    assert not (harness.converter_root / 'schema-preparation.json').exists()
    assert [role for role, _ in harness.model_calls] == ['mapper', 'reviewer'] * len(harness.plan['forms'])
    run = {'id': harness.job.name, 'project': harness.snapshot['project_id'], 'source_hash': harness.snapshot['source_hash'],
           'state': 'ATTENTION', 'artifact': None}
    return root, harness, run


def test_completed_generation_receipt_is_read_offline_without_writes(generated, monkeypatch):
    root, harness, run = generated
    parent = json.loads((harness.checkpoints / 'review-receipt.json').read_bytes())
    version = harness.snapshot['native_project']['schema_version']
    assert parent['schema_version'] == version
    assert parent['scope'] == 'fox-native-project-review-v' + str(version)
    assert (harness.converter_root / 'apexlang/application.apx').is_file()
    assert parent == json.loads((harness.converter_root / 'project-review.json').read_bytes())
    for role, request in harness.model_calls:
        module = request['inventory']['project_module']['module_id']
        checkpoint = json.loads((harness.checkpoints / module / (role + '.json')).read_bytes())
        assert checkpoint['request_sha256'] == status.canonical_hash(request)
        assert checkpoint['invocation']['request_sha256'] == status.canonical_hash(request)
        if version == 2:
            binding = status.module_execution_binding(harness.plan, parent_job_id=harness.job.name, module_id=module)
            assert request['module_execution_binding'] == binding
            assert request['storage_mapping']['source_table_name'] in {'CUSTOMERS', 'ORDERS'}
            assert request['native_form']['table_name'] == request['storage_mapping']['target_table_name']
            assert next(ref for ref in parent['form_reviews'] if ref['module_id'] == module)['execution_binding'] == binding
    before = files(root)
    def forbidden(*args, **kwargs):
        raise AssertionError('Status must not write or invoke a provider')
    monkeypatch.setattr(status, 'checked_release', forbidden)
    for method in ('write_bytes', 'write_text', 'mkdir', 'unlink', 'replace'):
        monkeypatch.setattr(Path, method, forbidden)
    with sqlite3.connect(':memory:') as db:
        result = status.project_run_status(db, root, run, run['source_hash'])
    assert result['artifact_generated'] is True
    assert {form['state'] for form in result['forms']} == {'generated'}
    assert result['technical_verified'] is result['human_accepted'] is result['preview_available'] is False
    assert result['error'] == status._STOPPED
    assert files(root) == before


def assert_checkpoint_rejected(generated):
    root, harness, run = generated
    before = files(root)
    with sqlite3.connect(':memory:') as db:
        result = status.project_run_status(db, root, run, run['source_hash'])
    assert not any(result[name] for name in ('artifact_generated', 'technical_verified', 'human_accepted',
                                             'downloadable', 'preview_available', 'review_available'))
    assert all(form['state'] != 'generated' for form in result['forms'])
    assert result['error'] == status._ERROR
    assert not (harness.job / 'project-technical-verification').exists()
    assert files(root) == before


def reseal_parent(harness, parent):
    """Keep generic hashes consistent so semantic-binding checks are exercised."""
    parent['receipt_sha256'] = status.canonical_hash({key: value for key, value in parent.items() if key != 'receipt_sha256'})
    put(harness.checkpoints / 'review-receipt.json', parent)
    generated_path = harness.checkpoints / 'generated.json'
    generation = json.loads(generated_path.read_bytes())
    encoded = json.dumps(parent, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode() + b'\n'
    generation['artifact_binding']['project_review_sha256'] = hashlib.sha256(encoded).hexdigest()
    put(generated_path, generation)


@pytest.mark.parametrize('change', ['checkpoint_boolean', 'checkpoint_crossed', 'generation_crossed',
                                  'parent_boolean', 'parent_crossed', 'parent_scope', 'role_request', 'role_invocation'])
def test_exact_schema_and_completed_role_requests_are_required(generated, change):
    _, harness, _ = generated
    version = harness.snapshot['native_project']['schema_version']
    if change.startswith('parent_'):
        path = harness.checkpoints / 'review-receipt.json'
        value = json.loads(path.read_bytes())
        if change == 'parent_scope': value['scope'] = 'fox-native-project-review-v' + str(3 - version)
        else: value['schema_version'] = True if change == 'parent_boolean' else 3 - version
        reseal_parent(harness, value)
    else:
        path = harness.checkpoints / ('generated.json' if change == 'generation_crossed' else 'binding.json')
        if change.startswith('role_'):
            path = harness.checkpoints / harness.plan['forms'][0]['module_id'] / 'mapper.json'
        value = json.loads(path.read_bytes())
        if change == 'role_request': value['request_sha256'] = '0' * 64
        elif change == 'role_invocation': value['invocation']['request_sha256'] = '0' * 64
        else: value['schema_version'] = True if change == 'checkpoint_boolean' else 3 - version
        put(path, value)
    assert_checkpoint_rejected(generated)


@pytest.mark.parametrize('generated', [2], indirect=True, ids=['mapped-v2'])
@pytest.mark.parametrize('change', ['project', 'plan', 'execution_missing', 'execution_source',
                                  'execution_child', 'execution_scope', 'child_binding', 'inventory_mapping'])
def test_mapped_generation_requires_the_exact_parent_and_source_bindings(generated, change):
    _, harness, _ = generated
    module = harness.plan['forms'][0]['module_id']
    if change == 'child_binding':
        path = harness.checkpoints / module / 'binding.json'
        value = json.loads(path.read_bytes())
        value['execution_binding']['source_hash'] = '0' * 64
        put(path, value)
    elif change == 'inventory_mapping':
        path = harness.checkpoints / 'inspection.json'
        value = json.loads(path.read_bytes())
        value['forms'][0]['inventory']['storage_mapping']['source_table_name'] = 'OTHER_SOURCE'
        put(path, value)
    else:
        value = json.loads((harness.checkpoints / 'review-receipt.json').read_bytes())
        if change == 'project': value['project_id'] = 'other-project'
        elif change == 'plan': value['plan_sha256'] = '0' * 64
        elif change == 'execution_missing': del value['form_reviews'][0]['execution_binding']
        else:
            field = {'execution_source': 'source_hash', 'execution_child': 'child_job_id', 'execution_scope': 'scope'}[change]
            value['form_reviews'][0]['execution_binding'][field] = '0' * 64
        reseal_parent(harness, value)
    assert_checkpoint_rejected(generated)


@pytest.mark.parametrize('change', ['generation', 'schema_boolean', 'review_hash', 'parent_refs', 'parent_seal', 'role_hash', 'duplicate', 'oversized'])
def test_altered_local_generation_receipt_never_establishes_generated(generated, change):
    root, harness, run = generated
    path = harness.checkpoints / 'generated.json'
    if change == 'generation':
        value = json.loads(path.read_bytes()); value['candidate_sha256'] = '0' * 64
    elif change == 'schema_boolean':
        value = json.loads(path.read_bytes()); value['schema_version'] = True
    elif change == 'review_hash':
        value = json.loads(path.read_bytes()); value['artifact_binding']['project_review_sha256'] = '0' * 64
    elif change in {'parent_refs', 'parent_seal'}:
        path = harness.checkpoints / 'review-receipt.json'; value = json.loads(path.read_bytes())
        if change == 'parent_refs':
            value['form_reviews'][0]['module_id'] = 'form-' + '0' * 20
            value['receipt_sha256'] = status.canonical_hash({key: item for key, item in value.items() if key != 'receipt_sha256'})
        else:
            value['receipt_sha256'] = '0' * 64
    elif change == 'role_hash':
        path = harness.checkpoints / harness.plan['forms'][0]['module_id'] / 'mapper.json'
        value = json.loads(path.read_bytes()); value['output_sha256'] = '0' * 64
    if change == 'duplicate': path.write_bytes(b'{"schema_version":1,"schema_version":1}')
    elif change == 'oversized': path.write_bytes(b' ' * 2_000_001)
    else: put(path, value)
    before = files(root)
    with sqlite3.connect(':memory:') as db:
        result = status.project_run_status(db, root, run, run['source_hash'])
    assert result['artifact_generated'] is result['technical_verified'] is result['human_accepted'] is result['preview_available'] is False
    assert all(form['state'] != 'generated' for form in result['forms'])
    assert result['error'] == status._ERROR
    assert files(root) == before


@pytest.mark.parametrize('url', ['https://attacker.invalid/', 'javascript:alert(1)', status.safe_io.ORDS + '/r/wrong/app/',
                               None, '', status.safe_io.ORDS + '/r/forms2apex_poc/wrong_alias/'])
def test_preview_only_accepts_exact_profile_application_url(case, url):
    release = deepcopy(case.built.evidence)
    release['application_url'] = url
    assert status._preview(release, case.built.profile) is None


@pytest.mark.parametrize('suffix', ['?x=1', '?', '#x', '#', '/extra', ' ', '\n'])
def test_product_preview_rejects_url_suffixes(case, suffix):
    release = deepcopy(case.built.evidence)
    release['application_url'] += suffix
    assert status._preview(release, case.built.profile) is None


def test_product_preview_accepts_only_hostname_case_variation(case):
    release = deepcopy(case.built.evidence)
    origin, path = release['application_url'].split('/ords/', 1)
    release['application_url'] = 'https://' + origin[len('https://'):].upper() + '/ords/' + path
    assert status._preview(release, case.built.profile) == case.built.evidence['application_url']


@pytest.mark.parametrize('change', ['qa_workspace', 'unknown_workspace', 'port', 'userinfo', 'encoded_path'])
def test_product_preview_cannot_substitute_a_matching_but_unapproved_target(case, change):
    release, target = deepcopy(case.built.evidence), deepcopy(case.built.profile)
    if change in {'qa_workspace', 'unknown_workspace'}:
        target['apex']['workspace'] = 'FOX_QA_261025_ABCDEF12' if change == 'qa_workspace' else 'OTHER_WORKSPACE'
        release['application_url'] = release['application_url'].replace('/forms2apex_poc/', '/' + target['apex']['workspace'].lower() + '/')
    elif change == 'port':
        release['application_url'] = release['application_url'].replace('/ords/', ':443/ords/')
    elif change == 'userinfo':
        release['application_url'] = release['application_url'].replace('https://', 'https://private@')
    else:
        release['application_url'] = release['application_url'].replace('/ords/', '/%6frds/')
    assert status._preview(release, target) is None


@pytest.mark.parametrize('url', [None, 'https://attacker.invalid/',
    status.safe_io.ORDS + '/r/fox_qa_261025_abcdef12/f2a_qa_261025_abcdef12/'])
def test_verified_project_with_unusable_original_url_never_uses_clean_qa(case, url):
    # Author a synthetic release variant BEFORE its first technical decision.
    # Keep every package hash/reference coherent; actual package/proof readers
    # must pass, rather than a positive validator being replaced by a stub.
    assert not case.retained.exists()
    built = deepcopy(case.built)
    with zipfile.ZipFile(io.BytesIO(built.package)) as archive:
        members = {name: archive.read(name) for name in archive.namelist() if name != 'manifest.json'}
    imported = json.loads(members['evidence/imported-application.json'])
    for document in (built.evidence, imported):
        if url is None:
            document.pop('application_url', None)
        else:
            document['application_url'] = url
    members['evidence/imported-application.json'] = raw(imported)
    imported_hash = sha(members['evidence/imported-application.json'])
    completion = json.loads(members['evidence/export-completion.json'])
    completion['imported_application_sha256'] = imported_hash
    members['evidence/export-completion.json'] = raw(completion)
    built.evidence.update(imported_application_sha256=imported_hash,
                          export_completion_sha256=sha(members['evidence/export-completion.json']))
    members['evidence/release-evidence.json'] = raw(built.evidence)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, content in members.items():
            archive.writestr(name, content)
        archive.writestr('manifest.json', raw({name: sha(content) for name, content in members.items()}))
    built.package = output.getvalue()
    assert status.verify_project_package(built.package, built.evidence, built.project, built.profile) == sha(built.package)
    case.built, case.observed = built, observations(built)
    case.policy = case.observed.policy
    for name, content in case.observed.receipts.items():
        put(case.operator / name, content)
    put(case.job / 'release-evidence.json', built.evidence)
    put(case.job / 'apex-package.zip', built.package)
    put(case.job / 'native-project-pipeline/download.json',
        {'package_sha256': sha(built.package), 'source_hash': case.snapshot['source_hash']})
    promote(case)
    before = files(case.root)
    result = present(case)
    assert result['artifact_generated'] is result['technical_verified'] is result['review_available'] is True
    assert result['preview_available'] is False and 'application_url' not in result
    assert files(case.root) == before
    accept_fixture(case)
    change_sources(case)
    accepted = present(case, 'e' * 64)
    assert accepted['human_accepted'] is accepted['downloadable'] is True
    assert accepted['preview_available'] is accepted['review_available'] is False
    assert 'application_url' not in accepted


def test_tampered_technical_receipt_disables_review_and_download(case):
    promote(case)
    accept_fixture(case)
    (case.retained / 'qa-result.json').write_bytes(b'{}')
    result = present(case)
    assert result['artifact_generated'] is True
    assert result['technical_verified'] is result['human_accepted'] is result['downloadable'] is result['review_available'] is False
    assert result['error'] == status._ERROR


def test_expected_file_symlink_cannot_be_used_as_a_package(case):
    path = case.job / 'apex-package.zip'
    original = case.job / 'original-package.zip'
    path.rename(original)
    try:
        path.symlink_to(original)
    except OSError:
        pytest.skip('This Windows account cannot create local test symlinks')
    result = present(case)
    assert result['artifact_generated'] is result['preview_available'] is False
    assert result['error'] == status._ERROR


def test_project_routing_never_downgrades_retained_package_markers(case):
    assert status.is_project_run(case.root, row(case)) is True
    put(case.job / 'source-snapshot.json', {'conversion_profile': 'legacy-html-prototype-v1'})
    # Missing snapshot and package must not erase the retained project marker.
    assert status.is_project_run(case.root, row(case)) is True
    (case.job / 'source-snapshot.json').unlink()
    assert status.is_project_run(case.root, row(case)) is True


@pytest.mark.parametrize('profile', ['legacy-html-prototype-v1', 'native-table-form-v1'])
def test_explicit_old_profile_keeps_existing_presentation(case, profile):
    legacy_job = case.root / 'jobs' / 'legacy-fixture'
    legacy_job.mkdir()
    put(legacy_job / 'source-snapshot.json', {'conversion_profile': profile})
    assert status.is_project_run(case.root, {'id': legacy_job.name}) is False
    (legacy_job / 'source-snapshot.json').write_bytes(b'{}')
    assert status.is_project_run(case.root, {'id': legacy_job.name}) is True


def test_project_package_cannot_be_relabelled_as_legacy_for_presentation(case):
    legacy_job = case.root / 'jobs' / 'relabeled-fixture'
    legacy_job.mkdir()
    put(legacy_job / 'source-snapshot.json', {'conversion_profile': 'legacy-html-prototype-v1'})
    (legacy_job / 'apex-package.zip').write_bytes(case.built.package)
    assert status.is_project_run(case.root, {'id': legacy_job.name}) is True
