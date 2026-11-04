"""Actual isolated API/storage; no model, worker, database or external network."""
from test_dependency_guidance import form, spec, body, ddl, package
from test_source_history_api import client, settings, no_external_actions, upload


def test_normal_api_adds_missing_body_in_same_project_and_retains_prior_version(client, monkeypatch):
    c, root, pid = client
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    files = [form(), ddl(), spec()]
    upload(c, pid, [(s['name'], s['text'].encode()) for s in files])
    first = c.get(f'/api/projects/{pid}/conversion-plan').json()
    missing = package(first['forms'][0])
    assert missing['missing_parts'] == ['package_body']
    assert missing['source_location']['button'] == 'Approve order'
    upload(c, pid, [(body()['name'], body()['text'].encode())])
    current = c.get(f'/api/projects/{pid}/conversion-plan').json()
    supplied = package(current['forms'][0])
    assert supplied['status'] == 'SOURCE_PRESENT' and supplied['routine_check'] == 'DECLARATIONS_FOUND'
    assert current['source_hash'] != first['source_hash']
    assert current['selected_source_set_id'] != first['selected_source_set_id']
    assert not any(f['code'] == 'MISSING_DEPENDENCY' for f in current['forms'][0]['findings'])
    assert current['can_generate'] is False  # Available source is not translated behavior.
    saved = c.get(f'/api/projects/{pid}').json()
    assert saved['id'] == pid and saved['runs'] == []
    assert c.get(f'/api/projects/{pid}/source-sets').status_code == 200
