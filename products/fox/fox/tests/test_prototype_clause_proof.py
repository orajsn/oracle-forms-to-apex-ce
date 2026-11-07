"""Synthetic retained-file acceptance only; no model, Oracle or live-flow proof."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from fox import prototype_clause_analysis as assembler
from fox import prototype_clause_proof as proof
from fox.forms_design_review import validate_design_review
from fox.opaf import canonical_hash
from test_prototype_clause_analysis import example


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, sort_keys=True, ensure_ascii=False).encode())


def manifest(root):
    return {name: {'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest(),
                   'bytes': (root / name).stat().st_size} for name in sorted(proof.FILES)}


def load(root, name):
    return json.loads((root / name).read_bytes())


def sealed_role(root, folder, name, target, request, output, identity):
    role = target['opaf']['roles'][name]
    binding = {'role': role, 'request_sha256': canonical_hash(request), **identity}
    invocation = {**role, 'room_id': 'synthetic-' + name + '-room',
                  'request_sha256': canonical_hash(request), 'response_sha256': 'd' * 64,
                  'started_at_utc': '2026-11-08T00:00:01Z',
                  'completed_at_utc': '2026-11-08T00:00:02Z'}
    environment = {'schema_version': 1, 'scope': 'opaf-model-environment-v1',
                   'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
                   'job_id': identity['job_id'], 'role': name,
                   'source_manifest_sha256': identity['source_hash'],
                   'target_profile_sha256': canonical_hash(target),
                   'observed_at_utc': '2026-11-08T00:00:00Z',
                   'opaf': {key: target['opaf'][key] for key in ('base_url', 'certificate_sha256',
                            'model_authentication', 'version_number', 'build_id')},
                   'workflow': {**role, 'published': True}, 'opaf_version': target['tested_versions']['opaf']}
    checkpoint = {'binding': binding, 'output': output, 'output_sha256': canonical_hash(output),
                  'invocation': invocation, 'model_environment': environment,
                  'model_environment_sha256': canonical_hash(environment)}
    write(root, folder + '/' + name + '-intent.json', binding)
    write(root, folder + '/' + name + '-target.json', target)
    write(root, folder + '/' + name + '.json', checkpoint)
    return invocation


def independent_review_envelope(focus, original, compact, analysis, candidate, assembly, binding):
    return {'request': focus, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate),
            'review_context': {'schema_version': 1, 'scope': 'fox-dedicated-clause-derived-review-v1',
                'trusted_requirements': {
                    'compare_each_literal_clause_with_its_intent_and_limitations': True,
                    'reject_missing_conditions_ordering_or_invented_external_meaning': True,
                    'original_false_facts_are_historical_not_authority': True,
                    'require_both_clauses_and_action_references': True,
                    'assembly_is_derived_not_a_raw_blueprint_model_response': True,
                    'do_not_execute_or_accept_business_behavior': True},
                'original_candidate': original, 'clause_request': compact, 'raw_clause_analyses': analysis,
                'assembly': assembly, 'assembly_binding': binding}}


def make_case(tmp_path, *, unresolved=False):
    packet, focus, original, analysis = example()
    if unresolved:
        analysis['analyses'][0]['status'] = 'unresolved'
    target = {'opaf': {'base_url': 'https://localhost:8080/agentFactory',
                      'certificate_sha256': 'e' * 64, 'model_authentication': 'oci_instance_principal',
                      'version_number': 'synthetic-26.4', 'build_id': 'synthetic', 'roles': {
                          'mapper': {'workflow_id': 'A' * 32, 'model': 'synthetic-model', 'graph_sha256': 'a' * 64},
                          'reviewer': {'workflow_id': 'B' * 32, 'model': 'synthetic-reviewer', 'graph_sha256': 'b' * 64}}},
              'tested_versions': {'opaf': 'synthetic-26.4'}}
    analysis_role = {'workflow_id': 'C' * 32, 'model': 'synthetic-model', 'graph_sha256': 'c' * 64}
    stage = deepcopy(target)
    stage['opaf']['roles']['mapper'] = analysis_role
    identity = {'job_id': 'fox-' + '1' * 20, 'source_hash': packet['source_binding']}
    root = tmp_path / 'retained'
    root.mkdir()
    (root / 'prototype_clause_analysis.py').write_bytes(Path(assembler.__file__).read_bytes())
    compact = assembler.build_request(packet, focus, original)
    analysis_invocation = sealed_role(root, 'analysis', 'mapper', stage, compact, analysis, identity)
    candidate, assembly = assembler.assemble_candidate(packet, focus, original, analysis)
    for name, value in (('clause-request.json', compact), ('derived-candidate.json', candidate),
                        ('derived-assembly.json', assembly)):
        write(root, name, value)
    binding = {'schema_version': 1, 'scope': 'fox-clause-diagnostic-invocation-assembly-v1',
               'analysis_checkpoint_sha256': hashlib.sha256((root / 'analysis/mapper.json').read_bytes()).hexdigest(),
               'analysis_invocation_sha256': canonical_hash(analysis_invocation), 'assembly_sha256': canonical_hash(assembly),
               'candidate_sha256': canonical_hash(candidate), 'analysis_request_sha256': canonical_hash(compact),
               'source_binding': identity['source_hash'], 'raw_model_output': False}
    write(root, 'assembly-binding.json', binding)
    payload = independent_review_envelope(focus, original, compact, analysis, candidate, assembly, binding)
    review = {'source_binding': focus['source_binding'], 'focus_binding': focus['focus_binding'],
              'candidate_sha256': canonical_hash(candidate), 'verdict': 'APPROVED', 'findings': []}
    review_invocation = sealed_role(root, 'review', 'reviewer', target, payload, review, identity)
    write(root, 'review-receipt.json', validate_design_review(focus, candidate, review))
    summary = {'scope': 'one-source-bound-clause-analysis-diagnostic-not-conversion',
               'job_id': identity['job_id'], 'maximum_analysis_calls': 1, 'maximum_review_calls': 1,
               'automatic_retry': False, 'source_binding': identity['source_hash'],
               'focus_request_sha256': canonical_hash(focus), 'original_candidate_sha256': canonical_hash(original),
               'analysis_request_sha256': canonical_hash(compact), 'module_sha256': proof.ASSEMBLER_SHA256,
               'original_target_sha256': canonical_hash(target), 'analysis_target_sha256': canonical_hash(stage),
               'clause_count': 2, 'whole_clause_bytes': [row['unit']['bytes'] for row in compact['clauses']],
               'production_profile_activated': False, 'production_run_resumed': False, 'apex_imported': False,
               'approval_basis': 'Synthetic fixture only. This text is not an authorization grant.'}
    write(root, 'diagnostic-intent.json', summary)
    write(root, 'result.json', {**summary, 'status': 'CLAUSE_DIAGNOSTIC_COMPLETED',
        'analysis_room_id': analysis_invocation['room_id'], 'analysis_output_sha256': canonical_hash(analysis),
        'derived_candidate_sha256': canonical_hash(candidate),
        'analysis_statuses': {row['source_attribute']: row['status'] for row in analysis['analyses']},
        'review_room_id': review_invocation['room_id'], 'review_verdict': 'APPROVED',
        'approved_structured_design': True, 'finding_count': 0, 'finding_codes': [],
        'original_job_files_unchanged': 1, 'business_behavior_accepted': False,
        'diagnostic_not_production_continuation': True})
    kwargs = {'approved_manifest': manifest(root), 'packet': packet, 'focus_request': focus,
              'original_candidate': original, 'original_target': target, 'analysis_role': analysis_role,
              'identity': identity}
    return root, kwargs


@pytest.fixture
def case(tmp_path):
    return make_case(tmp_path)


def reject(root, kwargs):
    with pytest.raises(ValueError, match='Invalid retained source-bound clause diagnostic proof'):
        proof.read_clause_proof(root, **kwargs)


def test_positive_exact_chain_returns_derived_only_and_does_not_write(case, monkeypatch):
    root, kwargs = case
    original_kwargs = deepcopy(kwargs)
    before = manifest(root)
    original_open = Path.open

    def readonly_open(path, mode='r', *args, **options):
        assert mode in ('r', 'rb'), 'Proof reader must never open for writes.'
        return original_open(path, mode, *args, **options)

    monkeypatch.setattr(Path, 'open', readonly_open)
    candidate, checked, provenance = proof.read_clause_proof(root, **kwargs)
    assert candidate == load(root, 'derived-candidate.json')
    assert checked == load(root, 'review-receipt.json')
    assert checked['verdict'] == 'APPROVED'
    assert provenance['file_manifest'] == before
    assert provenance['file_manifest_sha256'] == canonical_hash(before)
    assert provenance['clause_analyses'] == load(root, 'analysis/mapper.json')['output']['analyses']
    assert provenance['review_request_sha256'] == load(root, 'review/reviewer-intent.json')['request_sha256']
    for key in ('raw_full_blueprint_model_output', 'approval_basis_is_authority', 'epoch_adoption_authorized',
                'original_job_unchanged_independently_verified', 'generation_ready', 'native_apex_generated',
                'native_apex_validity_verified', 'import_verified', 'business_behavior_accepted'):
        assert provenance[key] is False
    assert provenance['derived_diagnostic'] is True
    assert kwargs == original_kwargs and manifest(root) == before
    candidate['blueprint']['screens'].clear()
    provenance['file_manifest'].clear()
    assert kwargs == original_kwargs and manifest(root) == before


def test_json_only_receiver_matches_reader_without_transferring_python(case):
    root, kwargs = case
    members = {name: (root / name).read_bytes() for name in proof.JSON_FILES}
    before = deepcopy((members, kwargs))
    full = proof.read_clause_proof(root, **kwargs)
    received = proof.validate_clause_proof_members(members, assembler_sha256=proof.ASSEMBLER_SHA256, **kwargs)
    assert full[:2] == received[:2]
    assert full[2]['retained_module_bytes_checked'] is True
    assert received[2]['retained_module_bytes_checked'] is False
    expected = deepcopy(full[2])
    expected['retained_module_bytes_checked'] = False
    assert received[2] == expected
    assert (members, kwargs) == before


@pytest.mark.parametrize('mutation', ['missing', 'python-source', 'extra-path', 'nonbytes', 'changed',
                                     'bad-module-pin', 'bad-module-manifest', 'bad-module-size'])
def test_json_receiver_requires_exact_json_bytes_and_separate_frozen_assembler_pin(case, mutation):
    root, kwargs = case
    members = {name: (root / name).read_bytes() for name in proof.JSON_FILES}
    module_sha = proof.ASSEMBLER_SHA256
    if mutation == 'missing': del members['result.json']
    elif mutation == 'python-source': members['prototype_clause_analysis.py'] = (root / 'prototype_clause_analysis.py').read_bytes()
    elif mutation == 'extra-path': members['../result.json'] = members['result.json']
    elif mutation == 'nonbytes': members['result.json'] = bytearray(members['result.json'])
    elif mutation == 'changed': members['result.json'] += b' '
    elif mutation == 'bad-module-pin': module_sha = '0' * 64
    elif mutation == 'bad-module-manifest': kwargs['approved_manifest']['prototype_clause_analysis.py']['sha256'] = '0' * 64
    else: kwargs['approved_manifest']['prototype_clause_analysis.py']['bytes'] += 1
    with pytest.raises(ValueError):
        proof.validate_clause_proof_members(members, assembler_sha256=module_sha, **kwargs)


def test_unresolved_analysis_keeps_its_exact_intent_and_limitations(tmp_path):
    root, kwargs = make_case(tmp_path, unresolved=True)
    candidate, checked, provenance = proof.read_clause_proof(root, **kwargs)
    actual = load(root, 'analysis/mapper.json')['output']['analyses'][0]
    assert actual['status'] == 'unresolved' and actual['limitations']
    assert provenance['clause_analyses'][0] == actual
    claim = next(row for row in candidate['blueprint']['claims'] if row['id'] == 'bad-WhereClause')
    assert claim['value'] == actual['intent'] and claim['status'] == 'unresolved'
    assert checked['generation_ready'] is False and provenance['business_behavior_accepted'] is False


@pytest.mark.parametrize('argument', ['packet', 'focus_request', 'original_candidate', 'original_target',
                                     'analysis_role', 'identity'])
def test_fresh_caller_binding_is_mandatory(case, argument):
    root, kwargs = case
    if argument == 'packet': kwargs[argument]['source_binding'] = '0' * 64
    elif argument == 'focus_request': kwargs[argument]['chunks'][0]['text'] += ' changed source'
    elif argument == 'original_candidate': kwargs[argument]['blueprint']['screens'][0]['title'] = 'Changed original'
    elif argument == 'original_target': kwargs[argument]['tested_versions']['opaf'] = 'changed-target'
    elif argument == 'analysis_role': kwargs[argument]['graph_sha256'] = '0' * 64
    else: kwargs[argument]['job_id'] = 'fox-' + '2' * 20
    reject(root, kwargs)


@pytest.mark.parametrize('name', sorted(proof.FILES))
def test_raw_byte_manifest_rejects_every_changed_file(case, name):
    root, kwargs = case
    with (root / name).open('ab') as handle:
        handle.write(b' ')
    reject(root, kwargs)


@pytest.mark.parametrize('name', sorted(proof.FILES))
def test_missing_files_and_pending_only_results_are_not_replayed(case, name):
    root, kwargs = case
    (root / name).unlink()
    reject(root, kwargs)


@pytest.mark.parametrize('mutation', ['none', 'empty', 'extra-path', 'missing', 'bad-sha', 'bool-bytes',
                                    'zero-bytes', 'oversized', 'extra-field', 'list'])
def test_manifest_is_exact_bounded_and_external(case, mutation):
    root, kwargs = case
    pin = kwargs['approved_manifest']['result.json']
    if mutation == 'none': kwargs['approved_manifest'] = None
    elif mutation == 'empty': kwargs['approved_manifest'] = {}
    elif mutation == 'extra-path': kwargs['approved_manifest']['../outside.json'] = deepcopy(pin)
    elif mutation == 'missing': del kwargs['approved_manifest']['result.json']
    elif mutation == 'bad-sha': pin['sha256'] = 'invalid'
    elif mutation == 'bool-bytes': pin['bytes'] = True
    elif mutation == 'zero-bytes': pin['bytes'] = 0
    elif mutation == 'oversized': pin['bytes'] = proof.MAX_FILE_BYTES + 1
    elif mutation == 'extra-field': pin['approved'] = True
    else: kwargs['approved_manifest'] = list(kwargs['approved_manifest'])
    reject(root, kwargs)


@pytest.mark.parametrize('folder,name', [('analysis', 'mapper'), ('review', 'reviewer')])
@pytest.mark.parametrize('mutation', ['intent', 'request', 'output', 'output-hash', 'environment',
    'environment-hash', 'graph', 'model', 'workflow', 'response-hash', 'room', 'time', 'extra'])
def test_role_chain_not_result_booleans_is_rechecked_even_with_new_manifest(case, folder, name, mutation):
    root, kwargs = case
    path = folder + '/' + name + '.json'
    value = load(root, path)
    if mutation == 'intent':
        path = folder + '/' + name + '-intent.json'
        value = load(root, path)
        value['request_sha256'] = '0' * 64
    elif mutation == 'request': value['binding']['request_sha256'] = '0' * 64
    elif mutation == 'output': value['output'] = {'success': True}
    elif mutation == 'output-hash': value['output_sha256'] = '0' * 64
    elif mutation == 'environment':
        value['model_environment']['source_manifest_sha256'] = '0' * 64
        value['model_environment_sha256'] = canonical_hash(value['model_environment'])
    elif mutation == 'environment-hash': value['model_environment_sha256'] = '0' * 64
    elif mutation == 'graph': value['invocation']['graph_sha256'] = '0' * 64
    elif mutation == 'model': value['invocation']['model'] = 'other-model'
    elif mutation == 'workflow': value['invocation']['workflow_id'] = 'D' * 32
    elif mutation == 'response-hash': value['invocation']['response_sha256'] = 'invalid'
    elif mutation == 'room': value['invocation']['room_id'] = '../unsafe'
    elif mutation == 'time': value['invocation']['completed_at_utc'] = '2026-11-07T00:00:00Z'
    else: value['success'] = True
    write(root, path, value)
    kwargs['approved_manifest'] = manifest(root)
    reject(root, kwargs)


@pytest.mark.parametrize('path', ['analysis/mapper-target.json', 'review/reviewer-target.json'])
@pytest.mark.parametrize('mutation', ['reviewer', 'mapper', 'non-role'])
def test_only_caller_approved_analysis_mapper_target_may_differ(case, path, mutation):
    root, kwargs = case
    value = load(root, path)
    if mutation == 'non-role': value['opaf']['base_url'] = 'https://different.invalid/agentFactory'
    else: value['opaf']['roles'][mutation]['workflow_id'] = 'D' * 32
    write(root, path, value)
    kwargs['approved_manifest'] = manifest(root)
    reject(root, kwargs)


@pytest.mark.parametrize('path,mutation', [
    ('derived-candidate.json', 'candidate'), ('derived-assembly.json', 'assembly'),
    ('assembly-binding.json', 'invocation'), ('assembly-binding.json', 'checkpoint'),
    ('review-receipt.json', 'receipt'), ('result.json', 'result'),
    ('diagnostic-intent.json', 'intent'), ('clause-request.json', 'compact')])
def test_derived_artifacts_must_be_reconstructed_not_merely_hash_pinned(case, path, mutation):
    root, kwargs = case
    value = load(root, path)
    if mutation == 'candidate': value['blueprint']['claims'][1]['value'] = 'Invented synthetic business meaning.'
    elif mutation == 'assembly': value['changes'][0]['analysis']['intent'] = 'Changed original intent.'
    elif mutation == 'invocation': value['analysis_invocation_sha256'] = '0' * 64
    elif mutation == 'checkpoint': value['analysis_checkpoint_sha256'] = '0' * 64
    elif mutation == 'receipt': value['candidate_sha256'] = '0' * 64
    elif mutation == 'result': value['business_behavior_accepted'] = True
    elif mutation == 'intent': value['maximum_review_calls'] = True
    else: value['clauses'][0]['text'] += ' altered source'
    write(root, path, value)
    kwargs['approved_manifest'] = manifest(root)
    reject(root, kwargs)


def test_reviewer_request_is_exact_extended_envelope_not_normal_review(case):
    root, kwargs = case
    path = 'review/reviewer.json'
    value = load(root, path)
    plain = {'request': kwargs['focus_request'], 'candidate': load(root, 'derived-candidate.json'),
             'candidate_sha256': canonical_hash(load(root, 'derived-candidate.json'))}
    value['binding']['request_sha256'] = canonical_hash(plain)
    value['invocation']['request_sha256'] = canonical_hash(plain)
    write(root, path, value)
    write(root, 'review/reviewer-intent.json', value['binding'])
    kwargs['approved_manifest'] = manifest(root)
    reject(root, kwargs)


def test_nonapproved_actual_review_cannot_be_overridden_by_approved_result(case):
    root, kwargs = case
    value = load(root, 'review/reviewer.json')
    value['output'].update(verdict='CHANGES_REQUIRED', findings=[{
        'source_object_id': None, 'code': 'SYNTHETIC_REJECTION', 'detail': 'Requires source review.'}])
    value['output_sha256'] = canonical_hash(value['output'])
    write(root, 'review/reviewer.json', value)
    kwargs['approved_manifest'] = manifest(root)
    reject(root, kwargs)


@pytest.mark.parametrize('mutation', ['same-workflow', 'original-workflow', 'different-model', 'same-room'])
def test_separation_and_analysis_role_pins_are_mandatory(case, mutation):
    root, kwargs = case
    if mutation == 'same-workflow':
        kwargs['analysis_role']['workflow_id'] = kwargs['original_target']['opaf']['roles']['reviewer']['workflow_id']
    elif mutation == 'original-workflow':
        kwargs['analysis_role']['workflow_id'] = kwargs['original_target']['opaf']['roles']['mapper']['workflow_id']
    elif mutation == 'different-model': kwargs['analysis_role']['model'] = 'not-the-original-model'
    else:
        value = load(root, 'review/reviewer.json')
        value['invocation']['room_id'] = load(root, 'analysis/mapper.json')['invocation']['room_id']
        write(root, 'review/reviewer.json', value)
        kwargs['approved_manifest'] = manifest(root)
    reject(root, kwargs)


@pytest.mark.parametrize('mutation', ['extra-file', 'extra-directory', 'traversal-root', 'relative-root',
                                    'duplicate-json', 'nonfinite-json', 'module'])
def test_unsafe_or_unexpected_layout_and_json_are_rejected(case, mutation):
    root, kwargs = case
    if mutation == 'extra-file': write(root, 'authority.json', {'approved': True})
    elif mutation == 'extra-directory': (root / 'extra').mkdir()
    elif mutation == 'traversal-root': root = root / 'review' / '..'
    elif mutation == 'relative-root': root = Path('relative/retained')
    elif mutation == 'module':
        (root / 'prototype_clause_analysis.py').write_bytes(b'raise RuntimeError("must never execute")')
        kwargs['approved_manifest'] = manifest(root)
    else:
        (root / 'result.json').write_bytes(b'{"status":true,"status":true}' if mutation == 'duplicate-json'
                                          else b'{"status":NaN}')
        kwargs['approved_manifest'] = manifest(root)
    reject(root, kwargs)


def test_hardlinked_artifact_rejected(case):
    root, kwargs = case
    outside = root.parent / 'outside-result.json'
    os.link(root / 'result.json', outside)
    reject(root, kwargs)


@pytest.mark.parametrize('ancestor', [False, True])
def test_symlink_artifact_or_ancestor_rejected_when_host_permits(case, ancestor):
    root, kwargs = case
    link = root.parent / 'linked-root' if ancestor else root / 'result.json'
    target = root if ancestor else root.parent / 'outside-result.json'
    if not ancestor:
        link.rename(target)
    try:
        link.symlink_to(target, target_is_directory=ancestor)
    except OSError:
        pytest.skip('Host lacks symlink creation privilege; reparse protection separately tested.')
    reject(link if ancestor else root, kwargs)


def test_windows_reparse_directory_rejected_without_following_it(case, monkeypatch):
    root, kwargs = case
    original = Path.lstat

    def reparse(path):
        value = original(path)
        if path == root.parent:
            return SimpleNamespace(st_mode=value.st_mode,
                                   st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return value

    monkeypatch.setattr(Path, 'lstat', reparse)
    reject(root, kwargs)


def test_bundle_change_during_check_is_detected(case, monkeypatch):
    root, kwargs = case
    original = proof._checked_role

    def changed(*args):
        result = original(*args)
        with (root / 'result.json').open('ab') as handle:
            handle.write(b' ')
        return result

    monkeypatch.setattr(proof, '_checked_role', changed)
    reject(root, kwargs)


def test_unexpected_directory_listing_is_bounded(case, monkeypatch):
    root, kwargs = case
    original = Path.iterdir
    consumed = []

    def many_entries(path):
        if path != root:
            yield from original(path)
            return
        for index in range(1000):
            consumed.append(index)
            yield path / ('unexpected-' + str(index))

    monkeypatch.setattr(Path, 'iterdir', many_entries)
    reject(root, kwargs)
    assert len(consumed) == len({name for name in proof.FILES if '/' not in name}) + 3
