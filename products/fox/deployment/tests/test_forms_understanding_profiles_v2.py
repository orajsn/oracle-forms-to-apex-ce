"""Offline additive resource construction; these are not model quality tests."""
from copy import deepcopy
import hashlib
from pathlib import Path
import shutil

import pytest

from deployment import forms_understanding_profiles as v1
from deployment import forms_understanding_profiles_v2 as v2
from deployment.forms_understanding_registration import canonical_hash
from deployment.tests.test_forms_understanding_profiles import normalized_graph


ROOT = Path(__file__).resolve().parents[1]
V1_CANDIDATES_SHA256 = '6cdc8f21e43ff27a6f7e02e1a424e9c8981d74efc9b01ba1dafb9d2503b68b55'


def test_v1_resources_and_canonical_outputs_are_unchanged():
    expected = {
        'forms_understanding_profiles.py': '99489e950e2ed564ee671e5255848cda31f8eca540d228cd47bbbb1eeb0c8014',
        'prompts/forms-understanding-v1.txt': 'c5241d11dc174bafa6f2edf20dccb991b5987c74dd71b0a434422b05b933db1e',
        'prompts/forms-understanding-review-v1.txt': '3d4e2e2705683b26e12318cdea5f282c20124168ef39d1de9d6fd66779899d1d',
    }
    for name, digest in expected.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    before = v1.build_candidates()
    assert canonical_hash(before) == V1_CANDIDATES_SHA256
    v2.build_candidates()
    assert v1.build_candidates() == before
    assert canonical_hash(v1.build_candidates()) == V1_CANDIDATES_SHA256


def test_build_has_distinct_names_ids_and_inactive_metadata():
    old, result = v1.build_candidates(), v2.build_candidates()
    assert result == v2.build_candidates()
    assert set(result) == set(old)
    assert type(result['schema_version']) is int and result['schema_version'] == 1
    assert result['scope'] == 'fox-forms-understanding-candidates-v2'
    assert result['profile_activation'] is False and result['model_invocation'] is False
    assert set(result['candidates']) == set(old['candidates'])
    expected = {
        'baseline43': ('JSNFOXG2Understandingv2Baseline43', 'JSN Forms Converter 4.3'),
        'candidate47': ('JSNFOXG2Understandingv2Candidate47', 'JSN FOX Understanding 4.7 Candidate 20261105'),
        'reviewer43': ('JSNFOXG2Understandingv2IndependentReview43', 'JSN Forms Reviewer'),
    }
    identities = {row['id'] for candidate in old['candidates'].values()
                  for kind in ('nodes', 'edges') for row in candidate['graph'][kind]}
    for role, candidate in result['candidates'].items():
        previous = old['candidates'][role]
        assert set(candidate) == set(previous)
        assert set(candidate['header']) == set(previous['header'])
        assert (candidate['header']['name'], candidate['connection_name']) == expected[role]
        assert candidate['header']['name'] != previous['header']['name']
        graph = candidate['graph']
        v1._check_graph(graph)
        assert len(graph['nodes']) == 4 and len(graph['edges']) == 3
        assert tuple(node['data']['type'] for node in graph['nodes']) == v1._TYPES
        for kind in ('nodes', 'edges'):
            for row in graph[kind]:
                assert row['id'] not in identities
                identities.add(row['id'])
        llm = graph['nodes'][2]['data']['template']
        assert set(llm) == {'llmToUse', 'prompt', 'temperature'}
        assert llm['llmToUse']['value'] == candidate['connection_name']
        assert type(llm['temperature']['value']) is int and llm['temperature']['value'] == 0
        for description in [candidate['header']['description'],
                            *(node['data']['description'] for node in graph['nodes'])]:
            assert 'Product activation controlled separately.' in description
            assert not any(term in description.lower() for term in
                           ('undeployed', 'inactive', 'no registration', 'no inference'))


def test_understanding_roles_have_identical_normalized_graphs_and_v2_prompt_bytes():
    candidates = v2.build_candidates()['candidates']
    assert normalized_graph(candidates['baseline43']['graph']) == normalized_graph(candidates['candidate47']['graph'])
    for role, candidate in candidates.items():
        filename = 'forms-understanding-review-v2.txt' if role == 'reviewer43' else 'forms-understanding-v2.txt'
        prompt = candidate['graph']['nodes'][1]['data']['template']['prompt']['value']
        assert prompt.encode('utf-8') == (ROOT / 'prompts' / filename).read_bytes()
        assert prompt.count('{{request}}') == 1
        assert candidate['prompt_sha256'] != v1.build_candidates()['candidates'][role]['prompt_sha256']


def test_metadata_digests_describe_actual_prompt_header_graph_and_pinned_template():
    for role, candidate in v2.build_candidates()['candidates'].items():
        kind = 'review' if role == 'reviewer43' else 'understanding'
        template_name, template_sha = v1._TEMPLATES[kind]
        assert candidate['source_template_sha256'] == template_sha
        assert template_sha == hashlib.sha256((ROOT / template_name).read_bytes()).hexdigest()
        assert candidate['header_sha256'] == canonical_hash(candidate['header'])
        assert candidate['graph_sha256'] == canonical_hash(candidate['graph'])
        prompt = candidate['graph']['nodes'][1]['data']['template']['prompt']['value']
        assert candidate['prompt_sha256'] == hashlib.sha256(prompt.encode('utf-8')).hexdigest()


def test_builder_isolated_from_prior_result_mutation_and_does_not_write_resources():
    paths = [ROOT / name for name, _ in v1._TEMPLATES.values()]
    paths += list((ROOT / 'prompts').glob('*'))
    paths += [ROOT / name for name in ('native-opaf-mapper.json', 'native-opaf-reviewer.json',
                                      'project-opaf-profile-v2.json')]
    before = {path: path.read_bytes() for path in paths}
    old = v1.build_candidates()
    result = v2.build_candidates()
    original = deepcopy(result)
    result['candidates']['baseline43']['graph']['nodes'][0]['data']['title'] = 'caller mutation'
    assert v2.build_candidates() == original
    assert v1.build_candidates() == old
    assert before == {path: path.read_bytes() for path in paths}


@pytest.fixture
def resources(tmp_path, monkeypatch):
    for name, _ in v1._TEMPLATES.values():
        shutil.copyfile(ROOT / name, tmp_path / name)
    shutil.copytree(ROOT / 'prompts', tmp_path / 'prompts')
    monkeypatch.setattr(v1, '_ROOT', tmp_path)
    monkeypatch.setattr(v2, '_ROOT', tmp_path)
    return tmp_path


@pytest.mark.parametrize('missing', ['project-opaf-mapper-v2.json', 'project-opaf-reviewer-v2.json',
                                    'prompts/forms-understanding-v2.txt', 'prompts/forms-understanding-review-v2.txt'])
def test_missing_resources_fail_closed(resources, missing):
    (resources / missing).unlink()
    with pytest.raises(FileNotFoundError):
        v2.build_candidates()


@pytest.mark.parametrize('name', ['project-opaf-mapper-v2.json', 'project-opaf-reviewer-v2.json'])
def test_changed_pinned_template_is_rejected(resources, name):
    path = resources / name
    path.write_bytes(path.read_bytes() + b'\n')
    with pytest.raises(ValueError, match='template bytes changed'):
        v2.build_candidates()


@pytest.mark.parametrize('kind', ['understanding', 'review'])
@pytest.mark.parametrize('prompt', ['', 'no request slot', '{{request}} {{request}}'])
def test_prompt_requires_exactly_one_slot(resources, kind, prompt):
    filename = 'forms-understanding-review-v2.txt' if kind == 'review' else 'forms-understanding-v2.txt'
    (resources / 'prompts' / filename).write_text(prompt, encoding='utf-8')
    with pytest.raises(ValueError, match='exactly one request slot'):
        v2.build_candidates()


def test_v2_does_not_read_v1_prompts(resources):
    before = v2.build_candidates()
    for name in ('forms-understanding-v1.txt', 'forms-understanding-review-v1.txt'):
        (resources / 'prompts' / name).unlink()
    assert v2.build_candidates() == before


@pytest.mark.parametrize('kwargs', [{'version': 1}, {'prompt': '{{request}}'}, {'builder': v1.build_candidates},
                                  {'connection_name': 'different'}, {'template': 'arbitrary.json'}])
def test_builder_accepts_no_caller_selected_resources(kwargs):
    with pytest.raises(TypeError):
        v2.build_candidates(**kwargs)


def test_prompt_role_is_explicit():
    with pytest.raises(ValueError, match='Unknown bundled prompt role'):
        v2._prompt('other')
