"""Source-bound project planning through real isolated API/storage handlers."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from fox.app import create_app, history_assessment_summary
from fox.intake import inventory
from test_project_conversion import pair, source, xml, module
from test_source_history_api import (ORIGIN, client, settings, no_external_actions,
                                     new_project, upload)


def wire(files):
    # Authored fixtures here have no BOM; specific BOM/CRLF cases are separate.
    return [(item['name'], item['text'].encode('utf-8')) for item in files]


def test_plan_requires_login(tmp_path, settings):
    with TestClient(create_app(tmp_path / 'data', enable_worker=False), base_url=ORIGIN) as c:
        assert c.get('/api/projects/unknown/conversion-plan').status_code == 401


def test_two_forms_have_one_source_bound_public_plan(client):
    c, root, pid = client
    uploaded = upload(c, pid, wire(pair() + pair('BETA', 'FOX_NATIVE_BETA')))
    response = c.get(f'/api/projects/{pid}/conversion-plan')
    assert response.status_code == 200, response.text
    plan = response.json()
    assert plan['project_id'] == pid and plan['source_hash'] == uploaded['source_hash']
    assert plan['selected_source_set_id'] == uploaded['selected_source_set_id']
    assert plan['state'] == 'READY' and plan['summary']['form_count'] == 2
    assert 'rendering_spec' not in plan
    assert all('native_form' not in form for form in plan['forms'])
    assert len({page for form in plan['forms'] for page in form['planned_pages'].values()}) == 4
    detail = c.get(f'/api/projects/{pid}').json()
    assert detail['project_plan'] == plan and detail['project_plan_error'] is None
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


def test_source_selection_changes_plan_but_retains_versions(client):
    c, _, pid = client
    first = upload(c, pid, wire(pair()))
    old = c.get(f'/api/projects/{pid}/conversion-plan').json()
    changed = upload(c, pid, wire(pair(prompt='Updated title')))
    new = c.get(f'/api/projects/{pid}/conversion-plan').json()
    assert old['source_hash'] != new['source_hash']
    assert old['plan_sha256'] != new['plan_sha256']
    selected = c.post(f'/api/projects/{pid}/source-sets/{first["selected_source_set_id"]}/select',
                      json={'expected_current_source_set_id': changed['selected_source_set_id']})
    assert selected.status_code == 200
    assert c.get(f'/api/projects/{pid}/conversion-plan').json() == old


def test_independent_project_plans_do_not_share_module_identity(client):
    c, _, first = client
    second = new_project(c)
    for pid in (first, second):
        upload(c, pid, wire(pair()))
    left = c.get(f'/api/projects/{first}/conversion-plan').json()
    right = c.get(f'/api/projects/{second}/conversion-plan').json()
    assert left['source_hash'] == right['source_hash']
    assert left['plan_sha256'] != right['plan_sha256']
    assert left['forms'][0]['module_id'] != right['forms'][0]['module_id']


def test_unknown_project_cannot_be_read(client):
    c, root, _ = client
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                   ('other-owner', 'someone-else', 'Synthetic', 'Private', '', 1))
    assert c.get('/api/projects/other-owner/conversion-plan').status_code == 404
    assert c.get('/api/projects/missing/conversion-plan').status_code == 404


def test_missing_ddl_is_actionable_not_partial_ready(client):
    c, _, pid = client
    upload(c, pid, wire(pair() + [source('beta.xml', xml(module('BETA', 'FOX_NATIVE_BETA')))]))
    plan = c.get(f'/api/projects/{pid}/conversion-plan').json()
    assert plan['state'] == 'BLOCKED' and plan['can_generate'] is False
    assert plan['summary']['form_count'] == 2
    assert plan['summary']['missing_input_forms'] == 1
    assert any(finding['required_action'] for form in plan['forms'] for finding in form['findings'])


def test_empty_project_plan_is_not_convertible(client):
    c, _, pid = client
    plan = c.get(f'/api/projects/{pid}/conversion-plan').json()
    assert plan['state'] == 'EMPTY' and plan['can_generate'] is False
    assert plan['forms'] == [] and plan['selected_source_set_id'] is None


def test_existing_long_project_name_remains_readable(client):
    c, root, pid = client
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE projects SET name=? WHERE id=?', ('L' * 100, pid))
    detail = c.get(f'/api/projects/{pid}')
    assert detail.status_code == 200
    assert detail.json()['project_plan'] is None
    assert detail.json()['project_plan_error']['code'] == 'PROJECT_NAME_INVALID'
    assert c.get(f'/api/projects/{pid}/conversion-plan').status_code == 422


def test_history_summary_uses_whole_project_profile(monkeypatch):
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    files = pair() + pair('BETA', 'FOX_NATIVE_BETA')
    summary = history_assessment_summary(files)
    assert summary['source_hash'] == inventory(files)['source_hash']
    assert summary['conversion_profile'] == 'native-project-v1'
    assert summary['native_state'] == 'READY' and summary['source_checks_passed'] is True
    assert summary['conversion_blocker_count'] == 0
    blocked = history_assessment_summary(files[:-1])
    assert blocked['source_checks_passed'] is False and blocked['native_state'] == 'BLOCKED'
    assert blocked['conversion_blocker_count'] > 0


def test_planning_never_asserts_execution_readiness(client):
    c, _, pid = client
    upload(c, pid, wire(pair()))
    plan = c.get(f'/api/projects/{pid}/conversion-plan').json()
    assert 'Planning only' in plan['scope_note']
    assert all(item['status'] == 'PLANNED_NOT_GENERATED' for form in plan['forms'] for item in form['mapping'])
    assert 'artifact_generated' not in plan and 'human_accepted' not in plan
