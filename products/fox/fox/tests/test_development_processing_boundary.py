"""Real local HTTP admissions must not reinterpret legacy processing consent."""
import sqlite3

import pytest

from test_development_intake_routes import settings, prepare
from test_source_history_api import client, no_external_actions, settings as base_settings, upload
from test_prototype_project_routes import configured


@pytest.mark.parametrize('delivery_mode', [None, 'apexlang_package'])
def test_preserved_sources_block_both_admissions_even_with_old_approvals(client, configured, delivery_mode, monkeypatch):
    monkeypatch.setattr('fox.app.package_conversion_configuration', lambda: {'conversion_configured': True})
    c, root, pid = client
    _, _, url = prepare(c, root, pid, code='BEGIN NULL; END;')
    assert c.post(url + '/adopt').status_code == 200
    project = c.get(f'/api/projects/{pid}')
    assert project.status_code == 200, project.text
    value = project.json()
    inv = value['inventory']
    assert inv['source_processing_allowed'] is False
    assert value['project_capabilities']['process']['enabled'] is False
    assert value['project_capabilities']['package_delivery']['enabled'] is True
    assessment = c.get(f'/api/projects/{pid}/prototype-assessment')
    assert assessment.status_code == 200, assessment.text
    # The explicit new contract is available; these old approvals still cannot
    # authorize preserved development source processing.
    assert assessment.json()['source_processing_allowed'] is True
    assert assessment.json()['processing_mode'] == 'development'
    common = dict(source_hash=inv['source_hash'], approved_redacted_source=True,
                  approved_external_ai=True, approved_prototype_scope=True)
    standard = c.post(f'/api/projects/{pid}/runs', json=common)
    prototype = c.post(f'/api/projects/{pid}/prototype-runs', json=dict(common,
        source_binding=assessment.json()['source_binding'],
        expected_current_source_set_id=inv['selected_source_set_id'],
        target_profile_sha256='a'*64, approved_chunk_hashes={}, delivery_mode=delivery_mode))
    for response in (standard, prototype):
        assert response.status_code == 409, response.text
        assert any(text in response.text for text in ('development', 'Development'))
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM events WHERE action IN ('approved_conversion','approved_prototype_conversion')").fetchone()[0] == 0
    assert not list((root/'jobs').glob('*/source-snapshot.json'))


def test_ordinary_intake_retains_prior_policy(client):
    c, root, pid = client
    upload(c, pid, [('ordinary.xml', b'<FormModule Name="SYNTHETIC"/>')])
    value = c.get(f'/api/projects/{pid}').json()
    assert value['inventory']['source_processing_allowed'] is True
    assert value['inventory']['source_processing_reason'] is None
    assessment = c.get(f'/api/projects/{pid}/prototype-assessment')
    assert assessment.status_code == 200, assessment.text
    assert assessment.json()['source_processing_allowed'] is True
