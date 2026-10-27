"""Offline project driver tests; SQLcl/VM boundaries are explicitly synthetic.

The package is emitted by the real project release builder and checked by its
real validator. No parser, plan validator, SQL builder or phase method is mocked.
Authored SQLcl export observations are NOT proof of an Oracle installation.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT, ROOT / 'converter', ROOT / 'converter/tests', ROOT / 'fox'):
    sys.path.insert(0, str(path))

from forms2apex import native_project, project_release
from test_project_release import project_job, finish
from qa.operator import contracts as c, project_contracts as p, project_remote as r
from qa.operator import remote as legacy

TIME = '2026-10-25T01:00:00Z'
LATER = '2026-10-25T01:01:00Z'
NAME = 'FOX_QA_261025_ABCD1234'
CODE = 'b' * 64
ADMIN = 'OnlySyntheticSecret9!'


def vendor_sql(project, schema='FORMS2APEX_POC', workspace='1234', app=123, alias=None, offset=0):
    """Authored boundary output, not an Oracle-generated export."""
    alias = alias or 'F2A_FOX_' + 'C' * 20
    text = f",p_default_workspace_id=>{workspace}\n,p_default_application_id=>{app}\n,p_default_owner=>'{schema}'\n"
    text += f"wwv_imp_workspace.create_flow(\n,p_owner=>nvl(wwv_flow_application_install.get_schema,'{schema}')\n,p_alias=>nvl(wwv_flow_application_install.get_application_alias,'{alias}')\n"
    text += '\n'.join(',' + name + (f'=>wwv_flow_imp.id({9000 + offset})' if name == 'p_navigation_list_id' else '=>null')
                      for name in legacy.FLOW_FIELDS) + '\n);\n'
    trace = native_project.project_trace(project)
    text += f'wwv_flow_imp_shared.create_list(\np_id=>wwv_flow_imp.id({9000 + offset})\n);\n'
    for form in trace['forms']:
        text += f"wwv_flow_imp_shared.create_list_item(\np_id=>wwv_flow_imp.id({9000 + form['report_page_id'] + offset})\n,p_list_item_link_target=>'f?p=&APP_ID.:{form['report_page_id']}:&SESSION.::&DEBUG.:::'\n);\n"
    text += 'wwv_flow_imp_page.create_page(\np_id=>0\n);\n'
    for form in trace['forms']:
        for page, kind in ((form['report_page_id'], 'NATIVE_IR'), (form['form_page_id'], 'NATIVE_FORM')):
            text += f'wwv_flow_imp_page.create_page(\np_id=>{page}\n);\n'
            text += f"wwv_flow_imp_page.create_page_plug(\np_id=>wwv_flow_imp.id({8000 + page + offset})\n,p_query_type=>'TABLE'\n,p_query_table=>'{form['table_name']}'\n,p_plug_source_type=>'{kind}'\n);\n"
        for index, item in enumerate(form['items']):
            text += f"wwv_flow_imp_page.create_page_item(\np_id=>wwv_flow_imp.id({form['form_page_id'] * 100 + index + offset})\n,p_name=>'{item['item']}'\n,p_source=>'{item['column']}'\n,p_item_plug_id=>wwv_flow_imp.id({8000 + form['form_page_id'] + offset})\n,p_item_source_plug_id=>wwv_flow_imp.id({8000 + form['form_page_id'] + offset})\n);\n"
    text += 'wwv_flow_imp_page.create_page(\np_id=>9999\n);\n'
    # Ensure ID relationships and shared call coverage are exercised too.
    for index in range(30):
        text += f'wwv_flow_imp_shared.create_list(\np_id=>wwv_flow_imp.id({10000 + index + offset})\n);\n'
    return text.encode()


@pytest.fixture
def case(project_job, monkeypatch):
    job = project_job
    underlying = job.sqlcl
    def transport(path, args, commands, cwd, **kwargs):
        result = underlying(path, args, commands, cwd, **kwargs)
        if 'apex export ' in '\n'.join(commands):
            (cwd / 'f123.sql').write_bytes(vendor_sql(job.project))
        return result
    monkeypatch.setattr(project_release, '_run_script', transport)
    finish(job)
    raw = (job.root / 'apex-package.zip').read_bytes()
    package = p.load_package(raw, c.digest(raw))
    source = {'schema_version': 1, 'scope': c.SOURCE_SCOPE, 'observed_at_utc': TIME,
        'instance_id': c.INSTANCE, 'compartment_id': c.COMPARTMENT, 'region': c.REGION,
        'job_id': package['binding']['job_id'], 'run_state': 'QA_REQUIRED', 'package_sha256': c.digest(raw),
        'package_bytes': len(raw), 'source_manifest_sha256': package['binding']['source_manifest_sha256']}
    plan = p.make_plan(source, package, NAME, TIME, operator_code_sha256=CODE)
    monkeypatch.setattr(r, 'utc_now', lambda: LATER)
    return plan, package, raw


class MemoryStore:
    def __init__(self):
        self.files, self.path, self.locked = {}, '/synthetic/private/project-only', False
    def read(self, name):
        return self.files.get(name)
    def create(self, name, raw):
        assert name not in self.files
        self.files[name] = raw
    def acquire(self):
        self.locked = True


class SQLclBoundary:
    """Fake only external driver IO; execute actual SQL construction/methods."""
    def __init__(self, case, store):
        self.plan, self.package, self.raw = case
        self.store, self.level, self.scripts, self.fail = store, 0, [], None
        self.ids = {'workspace_id': '90071992547409930001', 'application_id': 444}
    def sql(self, username, password, body, *, timeout=120):
        self.scripts.append(body)
        script = body.decode()
        assert legacy._guard_sql(username, username, self.ids['workspace_id']).decode() in script if username != 'ADMIN' else legacy._guard_sql('ADMIN').decode() in script
        if 'FOX_OPERATOR_ALLOCATE_RETURNED' in script:
            assert 'allocate.intent.json' in self.store.files
            self.level = 1
            return [('ALLOCATE_RETURNED', 'TRUE')]
        if 'generate_application_id;' in script:
            return [('APPLICATION_ID', str(self.ids['application_id']))]
        if 'FOX_OPERATOR_SCHEMA_RETURNED' in script:
            assert 'schema.intent.json' in self.store.files
            assert script.count('CREATE TABLE ') == len(r.table_specs(self.package))
            if self.fail == 'schema':
                raise legacy.RemoteError('SQL_TIMEOUT_UNCERTAIN_NO_REPLAY')
            self.level = 2
            return [('SCHEMA_RETURNED', 'TRUE')]
        if 'FOX_OPERATOR_IMPORT_RETURNED' in script:
            assert 'import.intent.json' in self.store.files
            assert 'set_auto_install_sup_obj(false)' in script and 'set_application_id(444)' in script
            self.level = 3
            return [('IMPORT_RETURNED', 'TRUE')]
        if 'FOX_OPERATOR_PHYSICAL_TABLE=' in script:
            return [('IDENTITY', 'VERIFIED')] + table_markers(self.package)
        if 'apex_export.get_application' in script:
            import base64
            raw = vendor_sql(self.package['project'], NAME, self.ids['workspace_id'], 444,
                             self.plan['target']['application_alias'], 50000)
            return [('EXPORT_DONE', 'TRUE'), ('EXPORT_LENGTH', str(len(raw))), ('EXPORT_CHUNK', base64.b64encode(raw).decode())]
        if 'FOX_OPERATOR_SCHEMA_COUNT' in script:
            app = self.ids['application_id'] if 'FOX_OPERATOR_ID_COUNT' in script else None
            state = {key: 0 for key in legacy._counts_sql(self.plan, app)[1]}
            if self.level:
                state.update(SCHEMA_COUNT=1, WORKSPACE_COUNT=1, MAPPING_COUNT=1, CORRECT_MAPPING_COUNT=1,
                    PRIVILEGE_COUNT=3, QUOTA_COUNT=1, CORRECT_QUOTA_COUNT=1, ACCOUNT_COUNT=1, USER_COUNT=2, RUNTIME_USER_COUNT=2)
            if self.level >= 2:
                state['OBJECT_COUNT'] = len(r.table_specs(self.package)) * 3
            if self.level >= 3:
                state.update(APPLICATION_COUNT=1, ALIAS_COUNT=1, ID_COUNT=1, EXACT_APP_COUNT=1)
            return [('IDENTITY', 'VERIFIED'), *[(key, str(value)) for key, value in state.items()],
                    *([('WORKSPACE_ID', self.ids['workspace_id'])] if self.level else [])]
        raise AssertionError('Unexpected SQLcl boundary')


def table_markers(package):
    specs = r.table_specs(package)
    markers = [('PHYSICAL_TABLE', spec['table_name']) for spec in specs]
    for spec in specs:
        name = spec['table_name']
        markers += [('TABLE_ROW', name + '|0'), ('TABLE_PK_COUNT', name + '|1'), ('UNEXPECTED_DEFAULT_COUNT', name + '|0')]
        markers += [('TABLE_COLUMN', '|'.join((name, col['name'], col['data_type'], 'Y' if col['nullable'] else 'N',
                     str(col.get('length', 0)), 'YES' if col['identity'] else 'NO', 'NULL', 'NULL'))) for col in spec['columns']]
        markers += [('TABLE_PK', name + '|' + next(col['name'] for col in spec['columns'] if col['primary_key']) + '|1|ENABLED|VALIDATED')]
    return markers + [(key, '0') for key in ('TRIGGER_COUNT', 'SYNONYM_COUNT', 'DB_LINK_COUNT', 'INVALID_OBJECT_COUNT',
                                           'UNEXPECTED_OBJECT_COUNT', 'UNEXPECTED_SCHEMA_DEPENDENCY_COUNT')]


def setup_boundary(case, monkeypatch):
    store = MemoryStore()
    boundary, driver = SQLclBoundary(case, store), r.SqlclDriver()
    monkeypatch.setattr(driver, 'sql', boundary.sql)
    # External IMDS/tool-version reads only; SQL builders and phase methods real.
    monkeypatch.setattr(driver, 'scope', lambda plan: None)
    monkeypatch.setattr(driver, 'versions', lambda admin: dict(c.VERSIONS))
    def run(command='apply', phase='allocate', **changes):
        plan, package, raw = case
        options = dict(expected_plan_sha256=p.plan_sha256(plan), phase=phase, apply=command == 'apply',
                       operator_code_sha256=CODE, admin_password=ADMIN, driver=driver, store=store)
        options.update(changes)
        return r.execute(command, c.canonical_bytes(plan), raw, **options)
    return store, boundary, run


def test_real_package_full_clean_driver_receipt_matches_project_validator(case, monkeypatch):
    from fox.native_verification_policy import BoundVerificationPolicy, validate_allocation_receipt
    from fox.project_qa_plan import derive_project_qa_plan
    from fox.project_verification import _validate_clean
    store, boundary, run = setup_boundary(case, monkeypatch)
    for phase in r.ORDER:
        result = run(phase=phase)
    assert result['state'] == 'QA_READY'
    assert sum(b'FOX_OPERATOR_IMPORT_RETURNED' in sql for sql in boundary.scripts) == 1
    assert sum(b'FOX_OPERATOR_SCHEMA_RETURNED' in sql for sql in boundary.scripts) == 1
    plan, package, raw = case
    clean = c.load_json(store.files['verify.evidence.json'])
    policy = BoundVerificationPolicy(store.files['verification-profile.json'])
    validate_allocation_receipt(store.files['allocate.evidence.json'], policy)
    qa_plan = derive_project_qa_plan(package['project'], package['binding']['project_spec_sha256'],
                                   package['trace'], package['binding']['source_to_apex_sha256'])
    binding = {key: clean[key] for key in ('job_id', *p.HASH_KEYS, 'verification_profile_sha256', 'allocation_receipt_sha256')}
    _validate_clean(clean, package['project'], qa_plan, binding, policy, package['binding']['original_parsing_schema'])
    assert len(clean['table_metadata']) == 2 and clean['human_acceptance_recorded'] is False
    before = list(boundary.scripts)
    assert run(phase='import')['action'] == 'ALREADY_COMPLETE_NO_REPLAY'
    assert all(b'FOX_OPERATOR_IMPORT_RETURNED' not in sql for sql in boundary.scripts[len(before):])
    before = list(boundary.scripts)
    assert run('status', None)['state'] == 'QA_READY_HISTORICAL'
    assert boundary.scripts == before


def test_uncertain_schema_is_never_replayed_or_inferred_complete(case, monkeypatch):
    store, boundary, run = setup_boundary(case, monkeypatch)
    run(); boundary.fail = 'schema'
    with pytest.raises(legacy.RemoteError, match='PHASE_UNCONFIRMED_NO_REPLAY'):
        run(phase='schema')
    assert 'schema.intent.json' in store.files and 'schema.attention.json' in store.files
    before = len(boundary.scripts)
    with pytest.raises(legacy.RemoteError, match='PHASE_NOT_STARTABLE_NO_REPLAY'):
        run(phase='schema')
    assert not any(b'FOX_OPERATOR_SCHEMA_RETURNED' in sql for sql in boundary.scripts[before:])
    assert run('status', None)['state'] == 'ATTENTION'


@pytest.mark.parametrize('change', [lambda m: m.pop(), lambda m: m.append(('PHYSICAL_TABLE', 'FOX_NATIVE_ORPHAN')),
    lambda m: m.append(('TABLE_ROW', 'FOX_NATIVE_EXTRA|1')),
    lambda m: m.__setitem__(next(i for i, row in enumerate(m) if row[0] == 'TABLE_COLUMN'), ('TABLE_COLUMN', 'bad'))])
def test_all_table_metadata_fails_closed(case, change):
    markers = table_markers(case[1]); change(markers)
    with pytest.raises(legacy.RemoteError):
        r.verify_tables(markers, case[1], NAME)


def test_compiled_inventory_catches_orphan_pages_items_and_navigation(case):
    plan, package, raw = case
    allocation = r._allocation(plan, {'workspace_id': '12345', 'application_id': 444}, dict(c.VERSIONS))
    actual = vendor_sql(package['project'], NAME, '12345', 444, plan['target']['application_alias'], 100000)
    result = r.verify_compiled(package, actual, allocation)
    assert result['component_counts']['wwv_flow_imp_shared.create_list_item'] == 2
    for altered in (actual.replace(b':3:&SESSION.', b':1:&SESSION.'), actual.replace(b'create_page_item(', b'create_other_item(', 1),
                    actual + b'wwv_flow_imp_page.create_page(\np_id=>88\n);\n', actual + b'-- FORMS2APEX_POC'):
        with pytest.raises(legacy.RemoteError):
            r.verify_compiled(package, altered, allocation)


@pytest.mark.parametrize('corruption', ['wrong_page', 'wrong_column', 'wrong_table', 'wrong_region', 'hidden_navigation'])
def test_matching_export_bytes_cannot_fabricate_page_table_item_or_navigation_mapping(case, corruption):
    plan, package, raw = case
    allocation = r._allocation(plan, {'workspace_id': '12345', 'application_id': 444}, dict(c.VERSIONS))
    actual = vendor_sql(package['project'], NAME, '12345', 444, plan['target']['application_alias'], 100000)
    def corrupt(sql, offset):
        if corruption == 'wrong_page':
            pattern = rb'wwv_flow_imp_page\.create_page_item\([\s\S]*?\);\n'
            items = re.findall(pattern, sql)
            return re.sub(pattern, b'', sql) + b''.join(items)
        if corruption == 'wrong_column':
            return re.sub(rb",p_source=>'[^']+'", b",p_source=>'OTHER_COLUMN'", sql, count=1)
        if corruption == 'wrong_table':
            return re.sub(rb",p_query_table=>'[^']+'", b",p_query_table=>'FOX_NATIVE_OTHER'", sql, count=1)
        if corruption == 'wrong_region':
            return re.sub(rb',p_item_source_plug_id=>wwv_flow_imp.id\([0-9]+\)',
                          f',p_item_source_plug_id=>wwv_flow_imp.id({88888 + offset})'.encode(), sql, count=1)
        return sql.replace(f'p_navigation_list_id=>wwv_flow_imp.id({9000 + offset})'.encode(),
                           f'p_navigation_list_id=>wwv_flow_imp.id({10000 + offset})'.encode())
    changed = deepcopy(package)
    changed['application_sql'] = corrupt(package['application_sql'], 0)
    with pytest.raises(legacy.RemoteError):
        r.verify_compiled(changed, corrupt(actual, 100000), allocation)


def test_ddl_deduplicates_shared_tables_and_ignores_injected_packaged_sql(case):
    plan, package, raw = case
    changed = deepcopy(package)
    changed['project']['forms'][1]['native_form'] = deepcopy(changed['project']['forms'][0]['native_form'])
    changed['schema_sql'] = b'DROP USER SHOULD_NEVER_RUN CASCADE;'
    generated = native_project.render_project_schema(changed['project']).encode()
    changed['binding']['schema_script_sha256'] = c.digest(generated)
    changed['binding']['tables'] = [changed['project']['forms'][0]['native_form']['table_name']]
    new_plan = deepcopy(plan); new_plan['binding'] = changed['binding']
    allocation = r._allocation(new_plan, {'workspace_id': '12345', 'application_id': 444}, dict(c.VERSIONS))
    sql = r.schema_sql(new_plan, allocation, changed)
    assert sql.count(b'CREATE TABLE ') == 1 and b'DROP USER' not in sql


def test_old_plan_crossfeed_and_code_drift_fail_before_external_io(case, monkeypatch):
    store, boundary, run = setup_boundary(case, monkeypatch)
    with pytest.raises(legacy.RemoteError):
        run(operator_code_sha256='0' * 64)
    assert not store.files and not boundary.scripts
    old = deepcopy(case[0]); old['scope'] = c.PLAN_SCOPE
    with pytest.raises(c.ContractError):
        p.validate_plan(old)
    for phase, approved in (('all', True), ('allocate', False), ('allocate', 'true')):
        with pytest.raises(legacy.RemoteError):
            run(phase=phase, apply=approved)
    assert not store.files and not boundary.scripts


def test_retained_receipt_mutation_not_accepted_as_historical_complete(case, monkeypatch):
    store, boundary, run = setup_boundary(case, monkeypatch)
    for phase in r.ORDER:
        run(phase=phase)
    store.files['source-to-apex.json'] += b' '
    with pytest.raises(legacy.RemoteError):
        run('status', None)
