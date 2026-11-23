"""Bounded emitted-SQL/UI structure tests, not Oracle/APEX runtime proof."""
from copy import deepcopy
import hashlib
import re
import sqlite3

import pytest

from fox import forms_checkbox_workspace as native


@pytest.fixture
def group():
    def field(name, checked='Y', unchecked='N'):
        return {'source_item_id': 'item-' + name, 'source_name': name,
                'source_column': name, 'column': name, 'data_type': 'VARCHAR2',
                'maximum_length': 1, 'length_semantics': 'BYTE', 'label': name.title(),
                'checked_value': checked, 'unchecked_value': unchecked,
                'source_enabled': True, 'source_update_allowed': True}
    return {'project_id': 'synthetic-accounts', 'source_binding': 'synthetic-binding',
            'source_unit_id': 'unit-1', 'source_unit_sha256': 'a' * 64,
            'source_event': 'WHEN-CHECKBOX-CHANGED', 'source_block_id': 'account-block',
            'table_name': 'FOX_NATIVE_' + 'A' * 19, 'report_page_id': 12,
            'report_file': 'pages/p00012-accounts.apx', 'controller': field('ACTIVE'),
            'dependents': [field('MONDAY'), field('TUESDAY', '1', '0')],
            'when_checked': {'enabled': True, 'update_allowed': True},
            'otherwise': {'clear_to_unchecked': True, 'enabled': False},
            'input_policy': {'allowed_values': 'exact_checked_or_unchecked_only',
                             'null_values': 'reject', 'other_values': 'reject',
                             'source_other_values_policy_proven': False}}


def database():
    db = sqlite3.connect(':memory:')
    db.create_function('UNISTR', 1, lambda value: re.sub(r'\\([A-Fa-f0-9]{4})', lambda m: chr(int(m[1], 16)), value))
    db.create_function('RAWTOHEX', 1, lambda value: value.hex().upper())
    db.create_function('STANDARD_HASH', 2, lambda value, _: hashlib.sha256(str(value).encode()).digest())
    db.create_function('TO_CHAR', 1, lambda value: value)
    db.create_function('TO_CHAR', 3, lambda value, *_: str(value))
    db.create_function('CAST_TO_RAW', 1, lambda value: value.encode() if value is not None else None)
    db.create_function('DECODE', 4, lambda left, right, yes, no: yes if left == right else no)
    return db


def test_pure_separate_native_page_keeps_source_links_and_no_rate_dependency(group):
    before = deepcopy(group)
    result = native.render_checkbox_workspace(group, 8100)
    assert result == native.render_checkbox_workspace(group, 8100)
    assert group == before
    page, = result['pages']
    text = page['text'].decode()
    assert page['page_file'] == 'pages/p08100-fox_checkbox_8100.apx'
    assert 'alias: FOX_CHECKBOX_8100\n' in text
    assert 'authentication: required' in text and 'pageAccessProtection: argumentsMustHaveChecksum' in text
    assert 'page: 12' in text and 'redirectThisApp' in text
    assert result['entry_fragment'].count('link {') == 1
    assert 'region checkbox-entry-8100 (' in result['entry_fragment']
    assert 'P8100_ID0: "#FOX_SELECTED_ROW#"' in result['entry_fragment']
    assert 'P8100_TOKEN: "#FOX_SOURCE_TOKEN#"' in result['entry_fragment']
    assert all('FOX_RATE' not in value for value in (text, result['entry_fragment']))
    assert result['metadata']['draft_row_key'] == ['APP_ID', 'SESSION_ID', 'OWNER_NAME', 'SOURCE_ROW_ID', 'SOURCE_TOKEN']
    for key in ('business_table_writes', 'durable_synthetic_save', 'runtime_verified', 'oracle_compiled', 'business_accepted'):
        assert result['metadata'][key] is False
    assert 'original POST/COMMIT' in text and 'record entry' in text


def test_every_identity_is_request_scoped_and_signed(group):
    text = native.render_checkbox_workspace(group, 8100)['pages'][0]['text'].decode()
    for suffix in ('ID0', 'TOKEN', 'DRAFT', 'REV'):
        item = re.search(r'pageItem P8100_' + suffix + r' \((.*?)\n    \)', text, re.S)[1]
        assert 'storage: request' in item and 'checksumRequiredSessionLevel' in item
    for suffix in ('C0', 'C1', 'C2'):
        item = re.search(r'pageItem P8100_' + suffix + r' \((.*?)\n    \)', text, re.S)[1]
        assert 'type: checkbox' in item and 'sessionStateProtection: unrestricted' in item


@pytest.mark.parametrize('action', native.REQUESTS)
def test_transactions_touch_only_owned_disposable_drafts(group, action):
    sql = native.action_code(group, 8100, action)
    table = native.render_checkbox_workspace(group, 8100)['metadata']['draft_table']
    targets = re.findall(r'\b(?:update|insert into|delete from)\s+(FOX_[A-Z0-9_]+)', sql, re.I)
    assert targets and set(targets) == {table}
    assert "APP_ID=to_number(v('APP_ID'))" in sql
    assert "SESSION_ID=v('APP_SESSION')" in sql and "OWNER_NAME=v('APP_USER')" in sql
    assert 'SOURCE_ROW_ID=to_number(:P8100_ID0)' in sql and 'SOURCE_TOKEN=:P8100_TOKEN' in sql
    assert 'rollback to fox_checkbox_draft' in sql
    assert not re.search(r'\b(commit|execute immediate|apex_web_service)\b', sql, re.I)
    assert len(sql.encode()) <= 32767
    if action != native.DISCARD:
        assert 'for update nowait' in sql and 'l_token<>:P8100_TOKEN' in sql
    if action != native.START:
        assert 'DRAFT_UUID=:P8100_DRAFT' in sql and 'REVISION=to_number(:P8100_REV)' in sql
        assert 'sql%rowcount<>1' in sql


def test_off_never_accepts_forged_disabled_values_and_on_checks_every_literal(group):
    sql = native.action_code(group, 8100, native.KEEP)
    branch = sql.split('l_f0:=:P8100_C0;', 1)[1]
    enabled, disabled = branch.split('elsif ', 1)
    disabled, preserved = disabled.split('else\n', 1)
    preserved = preserved.split('end if;', 1)[0]
    assert 'l_f1:=:P8100_C1' in enabled and 'l_f2:=:P8100_C2' in enabled
    assert enabled.count('Only the source checked and unchecked values') == 3
    assert 'l_f1:=' + native._value('N') in disabled
    assert 'l_f2:=' + native._value('0') in disabled
    assert ':P8100_C1' not in disabled and ':P8100_C2' not in disabled
    assert 'l_f1:=l_prior_f1' in preserved and 'l_f2:=l_prior_f2' in preserved
    assert ':P8100_C1' not in preserved and ':P8100_C2' not in preserved
    assert 'select REVISION,C000,C001,C002 into l_revision,l_prior_f0,l_prior_f1,l_prior_f2' in sql
    assert 'l_revision<>to_number(:P8100_REV)' in sql
    assert 'REVISION=REVISION+1' in sql


def test_initial_copy_rejects_unknown_null_or_other_states(group):
    sql = native.action_code(group, 8100, native.START)
    assert sql.count('Only the source checked and unchecked values') == 3
    assert sql.index('Only the source checked and unchecked values') < sql.index('insert into')
    assert 'dup_val_on_index' in sql and 'nothing was replaced' in sql
    assert 'EXPIRES_AT<=sysdate' in sql


def test_ui_change_resets_each_actual_unchecked_value_without_restoring_history(group):
    script = native.client_code(group, 8100)
    assert '"item": "P8100_C1", "unchecked": "N"' in script
    assert '"item": "P8100_C2", "unchecked": "0"' in script
    assert 'changed && !on' in script and 'item.setValue(f.unchecked, null, true)' in script
    assert "if (active && changed && !on) apex.item(cfg.offChanged).setValue('Y', null, true);" in script
    assert '"offChanged": "P8100_OFF_CHANGED"' in script
    assert "setValue('N'" not in script  # OFF stays recorded through a local ON.
    assert 'if (active && on) item.enable(); else item.disable();' in script
    assert 'update(false)' in script and 'update(true)' in script
    assert 'localStorage' not in script and 'sessionStorage' not in script


def draft_values_from_emitted_branch(group, prior, submitted, off_changed):
    """Evaluate actual emitted SQL expressions; PL/SQL control stays modelled."""
    db = database()
    sql = native.action_code(group, 8100, native.KEEP)
    body = sql.split('l_f0:=:P8100_C0;\n', 1)[1]
    body = body[body.index('\nif (l_f0 is not null') + 1:]
    on_guard, body = body.removeprefix('if ').split(' then\n', 1)
    on_body, body = body.split('elsif ', 1)
    off_guard, body = body.split(' then\n', 1)
    off_body, unchanged_body = body.split('else\n', 1)
    unchanged_body = unchanged_body.split('end if;', 1)[0]
    bindings = {'l_f0': submitted[0], 'P8100_OFF_CHANGED': off_changed}
    bindings.update({f'l_prior_f{i}': value for i, value in enumerate(prior)})
    bindings.update({f'P8100_C{i}': value for i, value in enumerate(submitted)})

    def evaluate(expression):
        expression = expression.replace('utl_raw.cast_to_raw', 'CAST_TO_RAW')
        expression = re.sub(r'(?<!:)\b(l_f\d+|l_prior_f\d+)\b', r':\1', expression)
        return db.execute('select ' + expression, bindings).fetchone()[0]

    chosen = on_body if evaluate(on_guard) else off_body if evaluate(off_guard) else unchanged_body
    result = [submitted[0]]
    for i in range(1, len(prior)):
        expression = re.search(r'l_f' + str(i) + r':=(.*?);', chosen)[1]
        result.append(evaluate(expression))
    return tuple(result)


@pytest.mark.parametrize('prior,submitted,off_changed,expected', [
    (('N', 'Y', '1'), ('N', None, None), 'N', ('N', 'Y', '1')),
    (('N', 'Y', '1'), ('N', 'N', '0'), 'N', ('N', 'Y', '1')),
    (('N', 'Y', '1'), ('Y', 'Y', '1'), 'N', ('Y', 'Y', '1')),
    (('Y', 'Y', '1'), ('N', 'Y', '1'), 'N', ('N', 'N', '0')),
    (('N', 'Y', '1'), ('N', None, None), 'Y', ('N', 'N', '0')),
    (('N', 'Y', '1'), ('Y', 'N', '1'), 'Y', ('Y', 'N', '1')),
])
def test_prior_state_and_actual_off_event_determine_reset(group, prior, submitted, off_changed, expected):
    assert draft_values_from_emitted_branch(group, prior, submitted, off_changed) == expected


def test_get_checks_source_and_stored_values_before_binding_native_checkboxes(group):
    sql = native.load_code(group, 8100)
    first_assignment = sql.index(':P8100_C0:=')
    assert sql[:first_assignment].count('Only the source checked and unchecked values') == 6
    assert 'for d in (select DRAFT_UUID,REVISION,C000,C001,C002' in sql
    assert ":P8100_OFF_CHANGED:='N'" in sql
    text = native.render_checkbox_workspace(group, 8100)['pages'][0]['text'].decode()
    item = re.search(r'pageItem P8100_OFF_CHANGED \((.*?)\n    \)', text, re.S)[1]
    assert 'valueProtected: false' in item
    assert text.count('valueProtected: false') == 1
    assert 'type: hidden' in item and 'storage: request' in item
    assert 'sessionStateProtection: unrestricted' in item


def test_entry_labels_null_and_other_source_values_unavailable(group):
    result = native.render_checkbox_workspace(group, 8100)
    query = result['metadata']['source_snapshot_sql']
    db = database()
    db.execute(f"create table {group['table_name']}(FOX_ROW_ID integer primary key, ACTIVE text, MONDAY text, TUESDAY text)")
    db.executemany(f"insert into {group['table_name']} values(?,?,?,?)", [(1, 'N', 'Y', '1'), (2, None, 'Y', '0'), (3, 'Y', 'X', '0')])
    rows = db.execute(query).fetchall()
    assert rows[0][2] == 'Available'
    assert rows[1][2] == 'Unavailable: Active: blank (Forms setting unconfirmed)'
    assert rows[2][2] == 'Unavailable: Monday: other code (Forms setting unconfirmed)'
    assert 'Checkbox draft availability' in result['entry_fragment']


def test_exact_snapshot_sql_covers_identity_and_checkbox_values_only(group):
    result = native.render_checkbox_workspace(group, 8100)
    query = result['metadata']['source_snapshot_sql']
    db = database()
    db.execute(f"create table {group['table_name']}(FOX_ROW_ID integer primary key, ACTIVE text, MONDAY text, TUESDAY text, UNRELATED text)")
    db.executemany(f"insert into {group['table_name']} values(?,?,?,?,?)", [(1, 'Y', 'Y', '0', 'first'), (2, 'N', 'N', '1', 'second')])
    before = db.execute(query).fetchall()
    assert before[0][1] != before[1][1]
    db.execute(f"update {group['table_name']} set UNRELATED='changed' where FOX_ROW_ID=1")
    assert db.execute(query).fetchall() == before
    db.execute(f"update {group['table_name']} set MONDAY='N' where FOX_ROW_ID=1")
    after = db.execute(query).fetchall()
    assert after[0][1] != before[0][1] and after[1] == before[1]
    changed = deepcopy(group)
    changed['project_id'] = 'another-project'
    assert native.render_checkbox_workspace(changed, 8100)['metadata']['draft_table'] != result['metadata']['draft_table']
    assert db.execute(native.render_checkbox_workspace(changed, 8100)['metadata']['source_snapshot_sql']).fetchall()[0][1] != after[0][1]


def test_emitted_sidecar_schema_preserves_other_rows_users_sessions_and_source_snapshots(group):
    result = native.render_checkbox_workspace(group, 8100)
    db = database()
    # Only Oracle type/date spelling is adapted; the owned key and UPDATE are
    # emitted SQL. This is intentionally not an Oracle compilation claim.
    ddl = result['supporting_sql'].decode().replace('default sysdate+1', 'default 2').replace(' byte)', ')')
    db.executescript(ddl)
    table = result['metadata']['draft_table']
    rows = [(1, 'session-a', 'user-a', 1, 'A', 'D1', 0, 2, 'Y', 'Y', '1'),
            (1, 'session-a', 'user-a', 2, 'B', 'D2', 0, 2, 'N', 'N', '0'),
            (1, 'session-b', 'user-a', 1, 'A', 'D3', 0, 2, 'Y', 'N', '0'),
            (1, 'session-a', 'user-b', 1, 'A', 'D4', 0, 2, 'N', 'N', '0'),
            (1, 'session-a', 'user-a', 1, 'CHANGED', 'D5', 0, 2, 'N', 'N', '0')]
    db.executemany(f'insert into {table} values(?,?,?,?,?,?,?,?,?,?,?)', rows)
    sql = native.action_code(group, 8100, native.KEEP)
    update, = re.findall(r'update ' + table + r' set .*?;', sql)
    update = update.replace('sysdate+1', '3').replace('sysdate', '1')
    for i in range(3):
        update = re.sub(r'\bl_f' + str(i) + r'\b', ':f' + str(i), update)
    db.create_function('V', 1, lambda key: {'APP_ID': '1', 'APP_SESSION': 'session-a', 'APP_USER': 'user-a'}[key])
    db.create_function('TO_NUMBER', 1, int)
    binds = {'P8100_ID0': '1', 'P8100_TOKEN': 'A', 'P8100_DRAFT': 'D1', 'P8100_REV': '0', 'f0': 'N', 'f1': 'N', 'f2': '0'}
    assert db.execute(update, binds).rowcount == 1
    assert db.execute(update, binds).rowcount == 0  # stale/replayed revision
    after = db.execute(f'select * from {table}').fetchall()
    assert after[0][6:] == (1, 3, 'N', 'N', '0')
    assert after[1:] == rows[1:]


@pytest.mark.parametrize('bad_page', [12, 0, 10000, True, '8100'])
def test_page_allocation_cannot_collide_with_source(group, bad_page):
    with pytest.raises(ValueError, match='CHECKBOX_WORKSPACE_PAGE'):
        native.render_checkbox_workspace(group, bad_page)


@pytest.mark.parametrize('mutation', ['table', 'policy', 'unchecked', 'field', 'disabled-update'])
def test_unproved_or_unsafe_contracts_fail_closed(group, mutation):
    if mutation == 'table':
        group['table_name'] = 'ORIGINAL_CUSTOMER'
    elif mutation == 'policy':
        group['input_policy']['null_values'] = 'unchecked'
    elif mutation == 'unchecked':
        group['dependents'][0]['unchecked_value'] = 'Y'
    elif mutation == 'field':
        group['dependents'][0]['column'] = 'MONDAY;DROP TABLE X'
    else:
        group['when_checked']['update_allowed'] = False
    with pytest.raises(ValueError):
        native.render_checkbox_workspace(group, 8100)


def test_checkbox_comparison_uses_database_character_set_and_procedural_equality():
    predicate = native._same('l_f0', native._value('1'))
    assert "to_char(unistr(" in predicate
    assert ' is not null and ' in predicate
    assert 'decode(' not in predicate.lower()


def _policy(field, setting, state):
    field.update(other_values=setting, source_null_other_policy_proven=True,
                 source_other_values_policy={'source_property': 'CheckBoxOtherValues',
                                             'source_value': setting, 'display_state': state})


def _status(group, row, *, padding=0):
    db = database()
    fields = [group['controller'], *group['dependents']]
    db.execute('create table source(' + ','.join(f['column'] + ' text' for f in fields) + ')')
    db.execute('insert into source values(' + ','.join('?' for _ in fields) + ')', row)
    query = native._status_query(group, 's', 'select ' + ' ' * padding, ' from source s')
    return db.execute(query).fetchone()[0], len(query.encode())


def test_report_lists_all_affected_fields_and_only_proved_source_settings(group):
    fields = [group['controller'], *group['dependents']]
    for f, policy, state in zip(fields, ['Checked','Unchecked','Not Allowed'], ['checked','unchecked','reject']):
        _policy(f, policy, state)
    fields[1]['label'] = "L'été"
    result, _ = _status(group, [None, 'private raw value', 'other raw value'])
    assert result == ("Unavailable: Active: blank (Forms displays checked); "
                      "L'été: other code (Forms displays unchecked); "
                      "Tuesday: other code (Forms disallows this value)")
    # Different storage representations are compared exactly; lowercase and
    # trailing whitespace cannot silently enter the ordinary editable path.
    result, _ = _status(group, ['y', 'Y ', '0'])
    assert 'Active: other code' in result and "L'été: other code" in result and 'Tuesday' not in result
    fields[0]['source_other_values_policy']['display_state'] = 'unchecked'
    result, _ = _status(group, [None, 'Y', '0'])
    assert result == 'Unavailable: Active: blank (Forms setting unconfirmed)'
    assert _status(group, ['N','Y','1'])[0] == 'Available'


def test_duplicate_or_long_multibyte_captions_fall_back_to_source_names(group):
    fields = [group['controller'], *group['dependents']]
    fields[0]['label'] = fields[1]['label'] = 'Day'
    fields[2]['label'] = '日' * 40
    v, _ = _status(group, [None, None, None])
    for f in fields:
        assert f['source_name'] + ': blank' in v
    assert 'Day:' not in v and '日' not in v


def test_query_capacity_preserves_the_first_cause_then_compact_availability(group):
    row = ['N',None,'new raw code']
    msg, full = _status(group,row)
    assert 'Monday' in msg and 'Tuesday' in msg
    padding = 32768 - full
    msg, compacted = _status(group,row,padding=padding)
    assert msg.startswith('Unavailable (first field): Monday: blank') and 'Tuesday' not in msg
    assert compacted <= 32767
    padding += 32768 - compacted
    msg, smallest = _status(group,row,padding=padding)
    assert msg == 'Unavailable: check stored checkbox codes' and smallest <= 32767
    with pytest.raises(ValueError, match='RECORD_QUERY_CAPACITY'):
        _status(group,row,padding=padding + 32768 - smallest)
