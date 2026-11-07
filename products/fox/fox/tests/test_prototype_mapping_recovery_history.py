"""Bounded history projection of real local SQLite recovery lineage only."""
import sqlite3

import pytest

from fox import source_history as history
from fox.intake import checked_source
from fox.prototype_mapping_recovery import retry_run_id
from fox.storage import initialize_schema


@pytest.fixture
def pair(tmp_path):
    c = sqlite3.connect(tmp_path / 'history.sqlite3')
    c.row_factory = sqlite3.Row
    initialize_schema(c)
    c.commit()
    with c:
        c.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p', 'owner', 'Synthetic', 'History', '', 1))
        history.create_project_selection(c, 'p', 1)
        source = checked_source('synthetic.xml', b'<FormModule Name="SYNTHETIC"/>')
        head = history.publish_upload(c, 'p', [source], 2, 'owner')['source_set']
        parent = 'fox-' + '1' * 20
        child = retry_run_id(parent)
        # Opposite creation ordering proves the metadata returns lineage order,
        # not a date-based guess or a silently chosen single latest run.
        for rid, created, state in [(parent, 5, 'ATTENTION'), (child, 4, 'QUEUED')]:
            c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                      (rid, 'p', head['source_hash'], state, 'Synthetic', created, created, None))
        c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                  ('owner', 'approved_prototype_conversion', parent, 3))
        c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                  ('owner', 'approved_prototype_mapping_retry', child, 4))
    yield c, head, parent, child
    c.close()


def test_pair_is_complete_ordered_and_readonly_in_every_history_projection(pair):
    c, head, parent, child = pair
    before = c.total_changes
    assert history.source_set_metadata(c, 'p', head['id'])['run_ids'] == [parent, child]
    assert history.source_set_detail(c, 'p', head['id'])['run_ids'] == [parent, child]
    assert history.source_set_page(c, 'p', head['id'])['source_set']['run_ids'] == [parent, child]
    assert history.list_source_sets(c, 'p')['source_sets'][0]['run_ids'] == [parent, child]
    assert c.total_changes == before


@pytest.mark.parametrize('change', ['missing-event', 'wrong-owner', 'project-owner', 'wrong-parent',
                                  'duplicate-event', 'third-run', 'chain-event', 'cross-source'])
def test_only_exact_pair_with_original_server_events_is_displayed(pair, change):
    c, head, parent, child = pair
    with c:
        if change == 'missing-event': c.execute('DELETE FROM events WHERE object_id=?', (child,))
        elif change == 'wrong-owner': c.execute("UPDATE events SET owner='foreign' WHERE object_id=?", (child,))
        elif change == 'project-owner': c.execute("UPDATE projects SET owner='foreign' WHERE id='p'")
        elif change == 'wrong-parent': c.execute('UPDATE runs SET id=? WHERE id=?', ('fox-' + '2' * 20, parent))
        elif change == 'duplicate-event':
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                      ('owner', 'approved_prototype_mapping_retry', child, 6))
        elif change == 'chain-event':
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                      ('owner', 'approved_prototype_mapping_retry', parent, 6))
        elif change == 'third-run':
            c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                      ('fox-' + '3' * 20, 'p', head['source_hash'], 'QUEUED', 'Unknown', 6, 6, None))
        else:
            # A child for another source does not contaminate this source's
            # ordinary single parent; it cannot be presented as a valid pair.
            c.execute('UPDATE runs SET source_hash=? WHERE id=?', ('0' * 64, child))
    if change == 'cross-source':
        assert history.source_set_metadata(c, 'p', head['id'])['run_ids'] == [parent]
    else:
        with pytest.raises(history.SourceHistoryError):
            history.source_set_metadata(c, 'p', head['id'])
