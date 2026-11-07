"""Real isolated SQLite compatibility tests; no operator or Oracle state."""
import sqlite3

import pytest

from fox.storage import BASE_SCHEMA_SQL, initialize_schema, migrate_mapping_recovery_runs


def legacy(connection):
    connection.executescript(BASE_SCHEMA_SQL.replace('artifact TEXT);', 'artifact TEXT,UNIQUE(project,source_hash));'))
    connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p', 'owner', 'Synthetic', 'Project', '', 1))
    connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                       ('parent', 'p', 'a' * 64, 'ATTENTION', 'Retained', 2.25, 3.5, None))
    connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                       ('other', 'p', 'b' * 64, 'ACCEPTED', 'Historical', 3, 4, 'jobs/other.zip'))
    connection.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)',
                       ('other', 'owner', 'b' * 64, 'c' * 64, 'Human-authored synthetic fixture', 5))
    connection.commit()


@pytest.mark.parametrize('foreign_keys', [0, 1])
def test_migration_preserves_exact_rows_foreign_keys_and_allows_distinct_child(tmp_path, foreign_keys):
    with sqlite3.connect(tmp_path / 'legacy.sqlite3') as c:
        c.execute('PRAGMA foreign_keys=' + str(foreign_keys))
        legacy(c)
        before = c.execute('SELECT * FROM runs ORDER BY id').fetchall()
        acceptance = c.execute('SELECT * FROM acceptances').fetchall()
        columns = c.execute('PRAGMA table_info(runs)').fetchall()
        migrate_mapping_recovery_runs(c)
        assert c.execute('SELECT * FROM runs ORDER BY id').fetchall() == before
        assert c.execute('SELECT * FROM acceptances').fetchall() == acceptance
        assert c.execute('PRAGMA table_info(runs)').fetchall() == columns
        assert c.execute('PRAGMA foreign_keys').fetchone()[0] == foreign_keys
        assert c.execute('PRAGMA foreign_key_check').fetchall() == []
        migrate_mapping_recovery_runs(c)  # Explicit idempotence.
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                  ('child', 'p', 'a' * 64, 'QUEUED', 'Explicit retry', 6, 6, None))
        c.commit()
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('INSERT INTO runs SELECT * FROM runs WHERE id=?', ('parent',))


def test_initialize_migrates_legacy_then_restarts_without_row_loss(tmp_path):
    with sqlite3.connect(tmp_path / 'legacy.sqlite3') as c:
        legacy(c)
        before = c.execute('SELECT * FROM runs ORDER BY id').fetchall()
        initialize_schema(c)
        c.commit()
        initialize_schema(c)
        c.commit()
        assert c.execute('SELECT * FROM runs ORDER BY id').fetchall() == before


def test_failure_after_drop_rolls_back_table_rows_and_foreign_key_setting(tmp_path):
    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('ALTER TABLE runs_mapping_recovery_v1'):
                raise sqlite3.OperationalError('Synthetic failure after DROP, before rename')
            return super().execute(sql, parameters)
    with sqlite3.connect(tmp_path / 'rollback.sqlite3', factory=FailingConnection) as c:
        c.execute('PRAGMA foreign_keys=ON')
        legacy(c)
        schema = c.execute("SELECT sql FROM sqlite_master WHERE name='runs'").fetchone()[0]
        rows = c.execute('SELECT * FROM runs ORDER BY id').fetchall()
        with pytest.raises(sqlite3.OperationalError, match='Synthetic failure'):
            migrate_mapping_recovery_runs(c)
        assert c.execute("SELECT sql FROM sqlite_master WHERE name='runs'").fetchone()[0] == schema
        assert c.execute('SELECT * FROM runs ORDER BY id').fetchall() == rows
        assert c.execute('PRAGMA foreign_keys').fetchone()[0] == 1
        assert c.execute('PRAGMA foreign_key_check').fetchall() == []
        assert c.execute("SELECT 1 FROM sqlite_master WHERE name='runs_mapping_recovery_v1'").fetchone() is None


@pytest.mark.parametrize('custom', ['index', 'trigger', 'column', 'orphan-table'])
def test_unexpected_schema_is_preserved_and_refused(tmp_path, custom):
    with sqlite3.connect(tmp_path / 'custom.sqlite3') as c:
        legacy(c)
        if custom == 'index':
            c.execute('CREATE INDEX custom_runs_state ON runs(state)')
        elif custom == 'trigger':
            c.execute('CREATE TRIGGER custom_runs AFTER INSERT ON runs BEGIN SELECT 1; END')
        elif custom == 'column':
            c.execute('ALTER TABLE runs ADD COLUMN unknown TEXT')
        else:
            c.execute('CREATE TABLE runs_mapping_recovery_v1(retained TEXT)')
        c.commit()
        schema = c.execute('SELECT type,name,sql FROM sqlite_master ORDER BY name').fetchall()
        rows = c.execute('SELECT * FROM runs ORDER BY id').fetchall()
        with pytest.raises(ValueError):
            migrate_mapping_recovery_runs(c)
        assert c.execute('SELECT type,name,sql FROM sqlite_master ORDER BY name').fetchall() == schema
        assert c.execute('SELECT * FROM runs ORDER BY id').fetchall() == rows


def test_foreign_key_failure_rolls_back_migration(tmp_path):
    with sqlite3.connect(tmp_path / 'fk.sqlite3') as c:
        legacy(c)
        c.execute("UPDATE runs SET project='missing' WHERE id='parent'")
        c.commit()
        before = c.execute("SELECT sql FROM sqlite_master WHERE name='runs'").fetchone()[0]
        with pytest.raises(ValueError, match='foreign-key'):
            migrate_mapping_recovery_runs(c)
        assert c.execute("SELECT sql FROM sqlite_master WHERE name='runs'").fetchone()[0] == before


def test_fresh_schema_has_same_eight_columns_and_no_source_unique(tmp_path):
    with sqlite3.connect(tmp_path / 'fresh.sqlite3') as c:
        initialize_schema(c)
        c.commit()
        assert len(c.execute('PRAGMA table_info(runs)').fetchall()) == 8
        indexes = c.execute('PRAGMA index_list(runs)').fetchall()
        assert [row[3] for row in indexes].count('u') == 0
        assert any(row[1] == 'runs_project_source_hash_idx' and row[2] == 0 for row in indexes)
