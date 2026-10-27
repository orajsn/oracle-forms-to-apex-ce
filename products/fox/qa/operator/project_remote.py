"""Guarded JSN project clean installer, never an arbitrary SQL executor.

This entrypoint is inert until explicitly called with one apply phase and exact
plan/code/package bytes. It uses the old operator's pinned SQLcl transport and
guards, not its single-form contracts or journal. Uncertain writes never replay.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat

from . import contracts as c, project_contracts as p, remote as r
from forms2apex import native_project

ORDER = r.ORDER
PRIVATE_ROOT = Path('/opt/forms2apex/outputs/jobs/.operator-project-clean')
require = r.require
RemoteError = r.RemoteError
utc_now = r.utc_now


class PrivateStore(r.PrivateStore):
    """Use the audited descriptor methods with an isolated project journal root."""

    def __init__(self, plan_hash, *, create=False):
        require(type(plan_hash) is str and re.fullmatch(r'[a-f0-9]{64}', plan_hash), 'INVALID_PLAN_DIGEST')
        self.fd, self.lock_fd, self.path = None, None, str(PRIVATE_ROOT / plan_hash)
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            components = PRIVATE_ROOT.parts[1:] + (plan_hash,)
            for index, component in enumerate(components):
                private = index >= len(components) - 2
                try:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create or not private:
                        if not create and private:
                            os.close(descriptor)
                            return
                        raise
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                if private:
                    info = os.fstat(descriptor)
                    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                            'PRIVATE_DIRECTORY_PERMISSIONS')
            self.fd = descriptor
        except Exception:
            os.close(descriptor)
            raise RemoteError('PRIVATE_DIRECTORY_UNSAFE') from None


def table_specs(package):
    project = native_project.validate_project_spec(package['project'])
    tables = {form['native_form']['table_name']: form['native_form'] for form in project['forms']}
    return [tables[name] for name in sorted(tables)]


def schema_sql(plan, allocation, package):
    p.validate_plan(plan, package=package)
    p.validate_allocation(allocation, plan)
    generated = native_project.render_project_schema(package['project']).encode('utf-8')
    require(c.digest(generated) == plan['binding']['schema_script_sha256'], 'CANONICAL_SCHEMA_BINDING_CHANGED')
    # The old fixed emptiness/identity preamble is reusable, but the SQL bytes
    # are generated here, never selected from an archive or supplied by a caller.
    return r.schema_sql(plan, allocation, {'schema_sql': generated})


def tables_sql(package):
    sql = "select 'FOX_OPERATOR_PHYSICAL_TABLE='||table_name from user_tables order by table_name;\n"
    for spec in table_specs(package):
        name = spec['table_name']
        sql += f"""
select 'FOX_OPERATOR_TABLE_ROW='||'{name}|'||count(*) from {name};
select 'FOX_OPERATOR_TABLE_COLUMN='||'{name}|'||column_name||'|'||data_type||'|'||nullable||'|'||nvl(char_length,0)||'|'||identity_column||'|'||nvl(to_char(data_precision),'NULL')||'|'||nvl(to_char(data_scale),'NULL')
 from user_tab_columns where table_name='{name}' order by column_id;
select 'FOX_OPERATOR_TABLE_PK='||'{name}|'||cc.column_name||'|'||cc.position||'|'||c.status||'|'||c.validated
 from user_constraints c join user_cons_columns cc on cc.constraint_name=c.constraint_name and cc.table_name=c.table_name
 where c.table_name='{name}' and c.constraint_type='P' order by cc.position;
select 'FOX_OPERATOR_TABLE_PK_COUNT='||'{name}|'||count(*) from user_constraints where table_name='{name}' and constraint_type='P';
select 'FOX_OPERATOR_UNEXPECTED_DEFAULT_COUNT='||'{name}|'||count(*) from user_tab_columns where table_name='{name}' and identity_column='NO' and default_length is not null;
"""
    forbidden = {'TRIGGER_COUNT': 'user_triggers', 'SYNONYM_COUNT': 'user_synonyms', 'DB_LINK_COUNT': 'user_db_links',
        'INVALID_OBJECT_COUNT': "user_objects where status<>'VALID'",
        'UNEXPECTED_OBJECT_COUNT': "user_objects where object_type not in ('TABLE','INDEX','SEQUENCE')",
        'UNEXPECTED_SCHEMA_DEPENDENCY_COUNT': "user_dependencies where referenced_owner not in (user,'SYS','PUBLIC')"}
    sql += ''.join(f"select 'FOX_OPERATOR_{key}='||count(*) from {value};\n" for key, value in forbidden.items())
    return sql.encode('ascii')


def expected_tables(package, schema):
    result = []
    for spec in table_specs(package):
        primary = next(column['name'] for column in spec['columns'] if column['primary_key'])
        result.append({'schema': schema, 'table_name': spec['table_name'], 'row_count': 0, 'primary_keys': [],
            'unexpected_schema_dependency_count': 0,
            'columns': [{'name': col['name'], 'data_type': col['data_type'], 'nullable': col['nullable'],
                         'char_length': col.get('length', 0), 'identity': col['identity']} for col in spec['columns']],
            'primary_key': {'columns': [primary], 'status': 'ENABLED', 'validated': 'VALIDATED'}})
    return result


def verify_tables(markers, package, schema):
    def values(key):
        return [value for name, value in markers if name == key]
    specs = table_specs(package)
    names = [spec['table_name'] for spec in specs]
    require(values('PHYSICAL_TABLE') == names, 'PROJECT_PHYSICAL_TABLE_SET_MISMATCH')
    columns, keys = [], []
    for spec in specs:
        name = spec['table_name']
        for col in spec['columns']:
            columns.append('|'.join((name, col['name'], col['data_type'], 'Y' if col['nullable'] else 'N',
                str(col.get('length', 0)), 'YES' if col['identity'] else 'NO', 'NULL', 'NULL')))
        keys.append(name + '|' + next(col['name'] for col in spec['columns'] if col['primary_key']) + '|1|ENABLED|VALIDATED')
    require(values('TABLE_COLUMN') == columns and values('TABLE_PK') == keys
            and values('TABLE_PK_COUNT') == [name + '|1' for name in names], 'PROJECT_TABLE_METADATA_MISMATCH')
    require(values('TABLE_ROW') == [name + '|0' for name in names]
            and values('UNEXPECTED_DEFAULT_COUNT') == [name + '|0' for name in names], 'PROJECT_TABLE_NOT_EMPTY_OR_DEFAULTED')
    for key in ('TRIGGER_COUNT', 'SYNONYM_COUNT', 'DB_LINK_COUNT', 'INVALID_OBJECT_COUNT',
                'UNEXPECTED_OBJECT_COUNT', 'UNEXPECTED_SCHEMA_DEPENDENCY_COUNT'):
        require(r.number(markers, key) == 0, 'PROJECT_SCHEMA_NOT_CLEAN')
    return expected_tables(package, schema)


# Include ALL shared component creation calls, notably list/menu navigation,
# rather than silently losing the mapping when comparing single-form exports.
CALL = re.compile(r'\b(wwv_imp_workspace\.create_flow|wwv_flow_imp_page\.create_[a-z0-9_]+|wwv_flow_imp_shared\.create_[a-z0-9_]+)\s*\(', re.I)


def project_calls(raw):
    text, calls, offset = raw.decode('utf-8').replace('\r\n', '\n'), [], 0
    while (match := CALL.search(text, offset)) is not None:
        cursor, depth, quoted = match.end(), 1, False
        while cursor < len(text) and depth:
            char = text[cursor]
            if char == "'":
                if quoted and text[cursor:cursor + 2] == "''":
                    cursor += 2
                    continue
                quoted = not quoted
            elif not quoted:
                depth += (char == '(') - (char == ')')
            cursor += 1
        require(depth == 0 and not quoted and text[cursor:cursor + 1] == ';', 'PROJECT_EXPORT_PARSE_FAILED')
        call = text[match.start():cursor + 1]
        if match.group(1).lower() == 'wwv_imp_workspace.create_flow':
            fields = []
            for name in r.FLOW_FIELDS:
                values = re.findall(r'^\s*,?' + name + r'=>([^\n]+)$', call, re.M)
                require(len(values) == 1, 'APPLICATION_SECURITY_FIELD_MISSING')
                fields.append(name + '=>' + values[0])
            call = 'wwv_imp_workspace.create_flow(\n' + '\n,'.join(fields) + '\n);'
        calls.append(call)
        offset = cursor + 1
    require(len(calls) >= 30, 'PROJECT_COMPONENT_SET_INCOMPLETE')
    identities = {}
    def normalize(match):
        identities.setdefault(match[1], str(len(identities) + 1))
        return 'wwv_flow_imp.id(@' + identities[match[1]] + ')'
    return [re.sub(r'wwv_flow_imp\.id\((\d+)\)', normalize, call) for call in calls]


def verify_compiled(package, actual, allocation):
    expected, observed = project_calls(package['application_sql']), project_calls(actual)
    require(expected == observed, 'COMPILED_PROJECT_COMPONENT_MISMATCH')
    original = package['binding']['original_parsing_schema']
    text, target = actual.decode('utf-8'), allocation['target']
    require(original not in text.upper(), 'ORIGINAL_SCHEMA_REFERENCE_REMAINS')
    patterns = {'workspace_id': r',p_default_workspace_id=>([0-9]+)',
        'application_id': r',p_default_application_id=>([0-9]+)',
        'parsing_schema': r",p_owner=>nvl\(wwv_flow_application_install.get_schema,'([A-Z0-9_]+)'\)",
        'default_owner': r",p_default_owner=>'([A-Z0-9_]+)'",
        'application_alias': r",p_alias=>nvl\(wwv_flow_application_install.get_application_alias,'([A-Z0-9_]+)'\)"}
    for key, pattern in patterns.items():
        require(re.findall(pattern, text) == [target['parsing_schema'] if key == 'default_owner' else str(target[key])],
                'COMPILED_CURRENT_IDENTITY_MISMATCH')
    trace = package['trace']
    def field(call, name, *, optional=False):
        values = re.findall(r'^\s*,?' + re.escape(name) + r'=>([^\n]+)$', call, re.M)
        require(len(values) == 1 or optional and not values, 'PROJECT_COMPONENT_FIELD_UNPROVEN')
        return values[0] if values else None
    flows = [call for call in observed if CALL.match(call)[1].lower() == 'wwv_imp_workspace.create_flow']
    require(len(flows) == 1, 'PROJECT_APPLICATION_COUNT_MISMATCH')
    navigation_id = field(flows[0], 'p_navigation_list_id')
    require(re.fullmatch(r'wwv_flow_imp\.id\(@[1-9][0-9]*\)', navigation_id), 'PROJECT_NAVIGATION_LIST_UNPROVEN')
    pages, items, regions, navigation = [], [], [], []
    current_page, current_list, navigation_lists = None, None, 0
    for call in observed:
        kind = CALL.match(call)[1].lower()
        if kind == 'wwv_flow_imp_page.create_page':
            page_id = field(call, 'p_id')
            require(re.fullmatch(r'0|[1-9][0-9]*', page_id), 'PROJECT_PAGE_ID_UNPROVEN')
            current_page = int(page_id)
            pages.append(current_page)
        elif kind == 'wwv_flow_imp_page.create_page_plug':
            source_type = field(call, 'p_plug_source_type', optional=True)
            if source_type in ("'NATIVE_IR'", "'NATIVE_FORM'"):
                require(current_page is not None and field(call, 'p_query_type') == "'TABLE'"
                        and field(call, 'p_query_owner', optional=True) in (None, 'null', "'" + target['parsing_schema'] + "'"),
                        'PROJECT_NATIVE_REGION_SOURCE_UNPROVEN')
                regions.append({'page': current_page, 'id': field(call, 'p_id'),
                                'kind': source_type, 'table': field(call, 'p_query_table')})
        elif kind == 'wwv_flow_imp_page.create_page_item':
            name = field(call, 'p_name')
            require(current_page is not None and field(call, 'p_flow_step_id', optional=True) in (None, str(current_page)),
                    'PROJECT_ITEM_PAGE_CONTEXT_UNPROVEN')
            items.append({'page': current_page, 'name': name, 'source': field(call, 'p_source', optional=True),
                          'region': field(call, 'p_item_plug_id', optional=True),
                          'source_region': field(call, 'p_item_source_plug_id', optional=True)})
        elif kind == 'wwv_flow_imp_shared.create_list':
            current_list = field(call, 'p_id')
            navigation_lists += current_list == navigation_id
        elif kind == 'wwv_flow_imp_shared.create_list_item':
            if current_list == navigation_id:
                navigation.extend(int(value) for value in re.findall(r"p_list_item_link_target=>'f\?p=&APP_ID\.:([0-9]+):", call))
    expected_pages = [0, *range(1, len(trace['forms']) * 2 + 1), 9999]
    require(sorted(pages) == expected_pages, 'PROJECT_PAGE_SET_MISMATCH')
    form_pages = {form['form_page_id'] for form in trace['forms']}
    expected_regions = sorted((form[key], kind, "'" + form['table_name'] + "'") for form in trace['forms']
                              for key, kind in (('report_page_id', "'NATIVE_IR'"), ('form_page_id', "'NATIVE_FORM'")))
    require(sorted((row['page'], row['kind'], row['table']) for row in regions) == expected_regions,
            'PROJECT_REGION_TABLE_MAPPING_MISMATCH')
    measured_modules = []
    for form in trace['forms']:
        page = form['form_page_id']
        region = next(row['id'] for row in regions if row['page'] == page and row['kind'] == "'NATIVE_FORM'")
        mapped = [item for item in items if item['page'] == page]
        require(len(mapped) == len(form['items']), 'PROJECT_ITEM_MAPPING_MISMATCH')
        for expected_item in form['items']:
            candidates = [item for item in mapped if item['name'] == "'" + expected_item['item'] + "'"]
            require(len(candidates) == 1 and candidates[0]['source'] == "'" + expected_item['column'] + "'"
                    and candidates[0]['region'] == candidates[0]['source_region'] == region,
                    'PROJECT_ITEM_MAPPING_MISMATCH')
        measured_modules.append({key: form[key] for key in ('module_id', 'table_name', 'report_page_id', 'form_page_id', 'items')})
    # A correctly named item on a login/report/other form page cannot prove its
    # expected page merely because its P<n>_ prefix happens to look right.
    required_names = {"'" + item['item'] + "'" for form in trace['forms'] for item in form['items']}
    require(all(item['page'] in form_pages for item in items if item['name'] in required_names), 'PROJECT_ITEM_PAGE_MAPPING_MISMATCH')
    require(navigation_lists == 1 and sorted(navigation) == [form['report_page_id'] for form in trace['forms']],
            'PROJECT_NAVIGATION_MAPPING_MISMATCH')
    digest = c.digest(json.dumps(observed, separators=(',', ':'), ensure_ascii=False).encode())
    return {'passed': True, 'scope': 'native_project_pages_all_shared_components_navigation_and_security',
        'call_count': len(observed), 'component_counts': dict(sorted(Counter(CALL.match(call)[1].lower() for call in observed).items())),
        'expected_components_sha256': digest, 'actual_components_sha256': digest, 'actual_export_sha256': c.digest(actual),
        'page_ids': expected_pages, 'module_metadata': measured_modules,
        'navigation': [{key: form[key] for key in ('module_id', 'report_page_id')} for form in trace['forms']],
        'original_parsing_schema': original, 'original_schema_reference_count': 0}


class SqlclDriver(r.SqlclDriver):
    def schema(self, plan, allocation, package, password):
        markers = self.sql(plan['target']['parsing_schema'], password, schema_sql(plan, allocation, package))
        require(r.one(markers, 'SCHEMA_RETURNED') == 'TRUE', 'SCHEMA_RETURN_UNPROVEN')

    def tables(self, plan, allocation, package, password):
        name, ws = plan['target']['parsing_schema'], allocation['target']['workspace_id']
        markers = self.sql(name, password, r._guard_sql(name, name, ws) + tables_sql(package))
        require(r.one(markers, 'IDENTITY') == 'VERIFIED', 'SCHEMA_IDENTITY_UNPROVEN')
        return verify_tables(markers, package, name)


def _phase_record(plan, phase, state, started, evidence=None):
    value = {'schema_version': 1, 'scope': p.PHASE_SCOPE, 'plan_sha256': p.plan_sha256(plan),
        'phase': phase, 'state': state, 'started_at_utc': started,
        'finished_at_utc': None if state == 'intent' else utc_now(),
        'evidence_sha256': c.digest(evidence) if evidence is not None else None}
    p.validate_phase_record(value, plan, phase)
    return value


def phase_state(store, plan, phase):
    intent, complete, attention, evidence = [store.read(phase + suffix) for suffix in
        ('.intent.json', '.complete.json', '.attention.json', '.evidence.json')]
    if intent is None:
        require(complete is attention is evidence is None, 'ORPHAN_PHASE_EVIDENCE')
        return 'unattempted'
    require(p.validate_phase_record(intent, plan, phase) == 'attention' and c.load_json(intent)['state'] == 'intent', 'PHASE_INTENT_INVALID')
    if attention is not None:
        require(p.validate_phase_record(attention, plan, phase) == 'attention', 'PHASE_ATTENTION_INVALID')
    if complete is not None:
        require(attention is None and p.validate_phase_record(complete, plan, phase) == 'complete'
            and evidence is not None and c.load_json(complete)['evidence_sha256'] == c.digest(evidence)
            and c.load_json(complete)['started_at_utc'] == c.load_json(intent)['started_at_utc'], 'PHASE_COMPLETION_INVALID')
        return 'complete'
    return 'attention'


def _allocation(plan, ids, versions):
    return p.validate_allocation({'schema_version': 1, 'scope': c.ALLOCATION_SCOPE, 'passed': True,
        'plan_sha256': p.plan_sha256(plan), 'allocated_at_utc': utc_now(),
        'binding': {key: plan['binding'][key] for key in ('job_id', 'source_manifest_sha256', 'package_sha256')},
        'target': {**plan['target'], **ids}, 'observed_versions': versions,
        'fresh_namespace': {'workspace_created_fresh': True, 'schema_created_fresh': True,
                            'application_count': 0, 'user_object_count': 0}}, plan)


def clean_receipt(plan, allocation, allocation_raw, profile_raw, tables, compiled, started):
    require(compiled['passed'] is True, 'PROJECT_COMPILE_PROOF_REQUIRED')
    target = {key: value for key, value in allocation['target'].items() if key != 'instance_id'}
    return {'schema_version': 1, 'scope': 'fox-project-clean-package-install-v1', 'profile_id': p.PROFILE_ID,
        **{key: plan['binding'][key] for key in ('job_id', *p.HASH_KEYS)},
        'verification_profile_sha256': c.digest(profile_raw), 'allocation_receipt_sha256': c.digest(allocation_raw),
        'target': target, 'observed_versions': allocation['observed_versions'],
        'started_at_utc': started, 'finished_at_utc': utc_now(),
        'before_install': {'application_ids': [], 'user_object_count': 0},
        'after_install': {'application_ids': [target['application_id']], 'physical_tables': plan['binding']['tables'],
                          'unexpected_schema_dependency_count': 0},
        'table_metadata': tables, **{key: compiled[key] for key in ('module_metadata', 'page_ids', 'navigation',
            'original_parsing_schema', 'original_schema_reference_count')},
        'compiled_project_components': compiled, 'authenticated_runtime_passed': False,
        'human_acceptance_recorded': False}


def qa_handoff(store):
    return {key: store.path + '/' + filename for key, filename in {
        'package': 'package.zip', 'project_spec': 'native-project-spec.json', 'project_trace': 'source-to-apex.json',
        'allocation_receipt': 'allocate.evidence.json', 'verification_profile': 'verification-profile.json',
        'import_receipt': 'verify.evidence.json', 'runtime_credentials': 'runtime-credentials.json'}.items()}


def _phase_evidence(plan, allocation, package, phase):
    if phase == 'schema':
        return {'passed': True, 'table_metadata': expected_tables(package, plan['target']['parsing_schema']),
                'plan_sha256': p.plan_sha256(plan), 'schema_script_sha256': plan['binding']['schema_script_sha256']}
    return {'passed': True, 'plan_sha256': p.plan_sha256(plan), 'application_id': allocation['target']['application_id'],
            'application_alias': plan['target']['application_alias'], 'sql_sha256': plan['binding']['sql_sha256']}


def verify_retained(store, plan, plan_raw, package, package_raw, states, allocation, allocation_raw):
    if not any(value == 'complete' for value in states.values()):
        return
    for name, raw in (('plan.json', plan_raw), ('package.zip', package_raw),
                      ('native-project-spec.json', package['project_raw']), ('source-to-apex.json', package['trace_raw'])):
        require(store.read(name) == raw, 'RETAINED_PROJECT_INPUTS_CHANGED')
    for phase in ('schema', 'import'):
        if states[phase] == 'complete':
            require(store.read(phase + '.evidence.json') == c.canonical_bytes(_phase_evidence(plan, allocation, package, phase)),
                    'RETAINED_PROJECT_PHASE_EVIDENCE_CHANGED')
    if states['verify'] == 'complete':
        profile_raw = c.canonical_bytes(p.make_verification_profile(plan, allocation_raw))
        require(store.read('verification-profile.json') == profile_raw, 'RETAINED_PROFILE_CHANGED')
        actual = store.read('compiled-application.sql')
        require(actual is not None, 'RETAINED_COMPILED_EXPORT_MISSING')
        compiled = verify_compiled(package, actual, allocation)
        receipt = c.load_json(store.read('verify.evidence.json'))
        journal = c.load_json(store.read('verify.complete.json'))
        require(receipt['started_at_utc'] == journal['started_at_utc']
                and c._timestamp(journal['started_at_utc']) <= c._timestamp(receipt['finished_at_utc'])
                <= c._timestamp(journal['finished_at_utc']), 'RETAINED_PROJECT_TIMING_CHANGED')
        expected = clean_receipt(plan, allocation, allocation_raw, profile_raw,
            expected_tables(package, plan['target']['parsing_schema']), compiled, journal['started_at_utc'])
        expected['finished_at_utc'] = receipt['finished_at_utc']
        require(store.read('verify.evidence.json') == c.canonical_bytes(expected), 'RETAINED_PROJECT_CLEAN_PROOF_CHANGED')


def verify_completed_live(plan, allocation, states, observation, package, driver, store):
    if 'attention' in states.values():
        return
    if allocation is None:
        r.assert_absent(observation)
        return
    r.assert_isolated(observation, allocation)
    require(all(observation[key] == (1 if states['import'] == 'complete' else 0) for key in
                ('APPLICATION_COUNT', 'ALIAS_COUNT', 'ID_COUNT', 'EXACT_APP_COUNT')), 'COMPLETED_PROJECT_APP_CHANGED')
    if states['schema'] == 'complete':
        password = r._credentials(store, plan['target']['workspace'])['schema_password']
        require(driver.tables(plan, allocation, package, password) == expected_tables(package, plan['target']['parsing_schema']),
                'COMPLETED_PROJECT_SCHEMA_CHANGED')
        if states['verify'] == 'complete':
            verify_compiled(package, driver.export(plan, allocation, password), allocation)
    else:
        require(observation['OBJECT_COUNT'] == 0, 'COMPLETED_ALLOCATION_OBJECT_STATE_CHANGED')


def execute(command, plan_raw, package_raw, *, expected_plan_sha256, phase=None, apply=False,
            admin_password=None, operator_code_sha256=None, driver=None, store=None):
    """One explicit phase or a read-only inspection; no ambiguous reconciliation.

    A complete phase is revalidated and skipped, never replayed. A dangling
    intent/attention is inspectable but requires independent human reconciliation;
    neither an object existence check nor an application ID promotes it complete.
    """
    own_store = store is None
    try:
        require(command in ('check', 'status', 'apply') and type(apply) is bool
                and ((command == 'apply' and apply is True and phase in ORDER)
                     or (command != 'apply' and apply is False and phase is None)), 'EXPLICIT_PHASE_APPROVAL_REQUIRED')
        require(type(plan_raw) is bytes and type(package_raw) is bytes and type(operator_code_sha256) is str,
                'EXACT_INPUT_BYTES_AND_CODE_DIGEST_REQUIRED')
        plan = p.validate_plan(plan_raw, operator_code_sha256=operator_code_sha256 if command != 'status' else None)
        plan_hash = p.plan_sha256(plan)
        require(expected_plan_sha256 == plan_hash, 'APPROVED_PLAN_DIGEST_MISMATCH')
        package = p.load_package(package_raw, plan['binding']['package_sha256'])
        p.validate_plan(plan, package=package)
        driver = driver or SqlclDriver()
        driver.scope(plan)
        versions = None if command == 'status' else driver.versions(admin_password)
        require(command == 'status' or versions == plan['expected_versions'], 'TESTED_VERSION_PROFILE_MISMATCH')
        store = store or PrivateStore(plan_hash, create=command == 'apply')
        if command == 'apply':
            store.acquire()
        require(store.read('plan.json') in (None, plan_raw), 'RETAINED_PLAN_MISMATCH')
        states = {item: phase_state(store, plan, item) for item in ORDER}
        for index, item in enumerate(ORDER):
            if states[item] != 'unattempted':
                require(all(states[earlier] == 'complete' for earlier in ORDER[:index]), 'PHASE_ORDER_INVALID')
        allocation_raw = store.read('allocate.evidence.json') if states['allocate'] == 'complete' else None
        allocation = p.validate_allocation(allocation_raw, plan) if allocation_raw else None
        verify_retained(store, plan, plan_raw, package, package_raw, states, allocation, allocation_raw)
        result = {'schema_version': 1, 'scope': 'fox-project-clean-operator-status-v1', 'plan_sha256': plan_hash,
                  'phases': states, 'private_evidence_directory': store.path, 'automatic_replay_permitted': False,
                  'state': 'ATTENTION' if 'attention' in states.values() else 'PREPARED'}
        if command == 'status':
            return {**result, 'state': 'QA_READY_HISTORICAL' if states['verify'] == 'complete' else result['state'],
                    'database_checked': False, 'historical_evidence_only': True,
                    'operator_code_matches': operator_code_sha256 == plan['operator_code_sha256']}
        observation = driver.observe(plan, admin_password, allocation)
        result.update(observed_versions=versions, observation=observation)
        if command == 'check' or states[phase] == 'complete':
            verify_completed_live(plan, allocation, states, observation, package, driver, store)
            if states['verify'] == 'complete':
                result.update(state='QA_READY', qa_handoff=qa_handoff(store))
            if command == 'check':
                return result
            return {**result, 'action': 'ALREADY_COMPLETE_NO_REPLAY'}
        require(states[phase] == 'unattempted' and 'attention' not in states.values()
                and all(states[item] == 'complete' for item in ORDER[:ORDER.index(phase)]), 'PHASE_NOT_STARTABLE_NO_REPLAY')
        if phase == 'allocate':
            r.assert_absent(observation)
        else:
            r.assert_isolated(observation, allocation)
        for name, raw in (('plan.json', plan_raw), ('package.zip', package_raw),
                          ('native-project-spec.json', package['project_raw']), ('source-to-apex.json', package['trace_raw'])):
            r._retain(store, name, raw)
        credentials = r._credentials(store, plan['target']['workspace'], create=phase == 'allocate')
        started = utc_now()
        store.create(phase + '.intent.json', c.canonical_bytes(_phase_record(plan, phase, 'intent', started)))
        try:
            driver.scope(plan)
            require(driver.versions(admin_password) == versions, 'PRE_DISPATCH_VERSION_CHANGED')
            fresh = driver.observe(plan, admin_password, allocation)
            if phase == 'allocate':
                r.assert_absent(fresh)
                evidence = _allocation(plan, driver.allocate(plan, admin_password, credentials), versions)
                post = driver.observe(plan, admin_password, evidence)
                r.assert_isolated(post, evidence)
                require(post['OBJECT_COUNT'] == post['APPLICATION_COUNT'] == post['ALIAS_COUNT'] == post['ID_COUNT'] == 0,
                        'ALLOCATED_TARGET_NOT_EMPTY')
            else:
                r.assert_isolated(fresh, allocation)
                password = credentials['schema_password']
                if phase in ('schema', 'import'):
                    require(fresh['APPLICATION_COUNT'] == fresh['ALIAS_COUNT'] == fresh['ID_COUNT'] == 0,
                            'IMPORT_PRE_DISPATCH_ID_OCCUPIED')
                if phase == 'schema':
                    require(fresh['OBJECT_COUNT'] == 0, 'SCHEMA_PRE_DISPATCH_NOT_EMPTY')
                    driver.schema(plan, allocation, package, password)
                    require(driver.tables(plan, allocation, package, password) == expected_tables(package, plan['target']['parsing_schema']),
                            'PROJECT_SCHEMA_POSTCONDITION_FAILED')
                    evidence = _phase_evidence(plan, allocation, package, phase)
                elif phase == 'import':
                    driver.tables(plan, allocation, package, password)
                    driver.import_application(plan, allocation, package, password)
                    post = driver.observe(plan, admin_password, allocation)
                    r.assert_isolated(post, allocation)
                    require(all(post[key] == 1 for key in ('APPLICATION_COUNT', 'ALIAS_COUNT', 'ID_COUNT', 'EXACT_APP_COUNT')),
                            'IMPORT_POSTCONDITION_FAILED')
                    evidence = _phase_evidence(plan, allocation, package, phase)
                else:
                    require(all(fresh[key] == 1 for key in ('APPLICATION_COUNT', 'ALIAS_COUNT', 'ID_COUNT', 'EXACT_APP_COUNT')),
                            'VERIFY_APPLICATION_IDENTITY_MISMATCH')
                    tables = driver.tables(plan, allocation, package, password)
                    actual = driver.export(plan, allocation, password)
                    compiled = verify_compiled(package, actual, allocation)
                    profile_raw = c.canonical_bytes(p.make_verification_profile(plan, allocation_raw))
                    r._retain(store, 'verification-profile.json', profile_raw)
                    r._retain(store, 'compiled-application.sql', actual)
                    evidence = clean_receipt(plan, allocation, allocation_raw, profile_raw, tables, compiled, started)
            evidence_raw = c.canonical_bytes(evidence)
            store.create(phase + '.evidence.json', evidence_raw)
            store.create(phase + '.complete.json', c.canonical_bytes(_phase_record(plan, phase, 'complete', started, evidence_raw)))
        except Exception as exc:
            try:
                store.create(phase + '.attention.json', c.canonical_bytes(_phase_record(plan, phase, 'attention', started)))
            except Exception:
                pass
            raise RemoteError('PHASE_UNCONFIRMED_NO_REPLAY', diagnostics=exc.diagnostics if type(exc) is RemoteError else None) from None
        result['phases'][phase] = 'complete'
        result.update(state='QA_READY' if phase == 'verify' else 'PHASE_COMPLETE', action='COMPLETED_ONCE',
                      evidence_sha256=c.digest(evidence_raw), evidence_file=store.path + '/' + phase + '.evidence.json')
        if phase == 'verify':
            result['qa_handoff'] = qa_handoff(store)
        return result
    except RemoteError:
        raise
    except Exception:
        raise RemoteError('OPERATOR_GUARD_FAILED_OUTPUT_WITHHELD') from None
    finally:
        if own_store and store is not None:
            store.close()
