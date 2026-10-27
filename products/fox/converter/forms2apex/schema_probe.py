"""Strict metadata observations and canonical create-only SQL for JSN stubs.

This module does not decide table ownership, retry or creation authority. The
caller must hold its durable table lease, validate source/review/SQLcl evidence,
and run the existing fresh OCI/target action preflight before executing the SQL
returned by create_commands. observe executes dictionary reads only. No table
records, trigger bodies, defaults or arbitrary SQL text are returned.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

from .native_contract import validate_native_spec
from .native_schema import render_native_schema
from .runtime_preflight import bound_target_profile
from .sqlcl import _run_script, _target_guard
from .target_profile import target_profile_sha256


class ProbeError(RuntimeError):
    """Fixed codes only; provider output is never an exception message."""


def need(ok, code):
    if not ok:
        raise ProbeError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def schema_contract(spec):
    value = validate_native_spec(spec)
    return {key: value[key] for key in ('profile_id', 'data_mode', 'table_name')} | {
        'varchar_semantics': 'BYTE',
        'columns': [{key: item[key] for key in ('name', 'data_type', 'nullable',
                     'primary_key', 'identity', 'length') if key in item}
                    for item in value['columns']]}


def schema_sha256(spec):
    return digest(schema_contract(spec))


def target(settings):
    profile = bound_target_profile(settings)
    return {'profile_sha256': target_profile_sha256(profile),
            **profile['oci'], **profile['database'],
            'workspace': profile['apex']['workspace'],
            'workspace_id': profile['apex']['workspace_id'],
            'apex_version': profile['tested_versions']['apex'],
            'saved_connection': profile['sqlcl']['saved_connection'],
            'nls_length_semantics': 'BYTE'}


def _identity_sql(expected):
    # Values come from the exact, allowlisted target-profile validator, not a
    # caller's connection string, model output or uploaded SQL.
    return """
 select version_no into apex_version from apex_release;
 select value into length_semantics from nls_session_parameters where parameter='NLS_LENGTH_SEMANTICS';
 select count(*) into mapping_count from apex_workspace_schemas
  where workspace_name='{workspace}' and schema='{parsing_schema}' and workspace_id={workspace_id};
 select count(*) into mapping_total from apex_workspace_schemas where workspace_name='{workspace}';
 exact(sys_context('USERENV','DB_NAME')='{db_name}' and user='{session_user}'
  and sys_context('USERENV','SESSION_USER')='{session_user}'
  and sys_context('USERENV','CURRENT_SCHEMA')='{parsing_schema}'
  and apex_version='{apex_version}' and mapping_count=1 and mapping_total=1 and length_semantics='BYTE');
 select count(*) into table_priv from session_privs where privilege='CREATE TABLE';
 select count(*) into sequence_priv from session_privs where privilege='CREATE SEQUENCE';
 select count(*) into unlimited_priv from session_privs where privilege='UNLIMITED TABLESPACE';
 select default_tablespace into default_space from user_users;
 select count(*),max(bytes),max(max_bytes) into quota_count,quota_used,quota_limit
  from user_ts_quotas where tablespace_name=default_space;
 exact(quota_count between 0 and 1);
""".format(**expected)


def _identity_marker(expected):
    return (" dbms_output.put_line('D|'||sys_context('USERENV','DB_NAME')||'|'||user||'|'"
            "||sys_context('USERENV','SESSION_USER')||'|'||sys_context('USERENV','CURRENT_SCHEMA')"
            "||'|'||apex_version||'|" + expected['workspace_id'] + "|'||num(mapping_count)||'|'||length_semantics);\n")


_DECLARATIONS = """declare
 n number; t number; regular_count number; ext_count number; trig_count number;
 identity_count number; constraint_count number; column_count number; index_count number;
 grant_count number; public_count number; child_count number; oid number;
 created_value date; ddl_value date; ordinal number; cols varchar2(4000);
 def varchar2(32767); seq varchar2(128); dk varchar2(30); ck varchar2(30); nn varchar2(128);
 apex_version varchar2(100); length_semantics varchar2(10); mapping_count number; mapping_total number;
 table_priv number; sequence_priv number; unlimited_priv number;
 default_space varchar2(128); quota_count number; quota_used number; quota_limit number;
 function num(x number) return varchar2 is begin
  if x is null then return '-'; end if;
  return to_char(x,'FM99999999999999999999999999999999999990');
 end;
 procedure exact(ok boolean) is begin
  if ok is null or not ok then raise_application_error(-20091,'FOX_SCHEMA_GUARD'); end if;
 end;
"""

_PREFIX = ["set sqlformat default", "set pagesize 0", "set linesize 32767",
           "set trimout on", "set define off", "set serveroutput on size unlimited",
           "whenever oserror exit failure rollback"]


def observation_commands(settings, spec):
    value = validate_native_spec(spec)
    expected, name = target(settings), value['table_name']
    query = _DECLARATIONS + "begin\n" + _identity_sql(expected)
    query += " dbms_output.put_line('FOX_SCHEMA_BEGIN=1');\n" + _identity_marker(expected)
    query += _capability_markers()
    query += """
 select count(*) into n from user_objects where object_name='{name}';
 select count(*) into t from user_tables where table_name='{name}';
 select count(*) into public_count from all_synonyms where owner='PUBLIC' and synonym_name='{name}';
 exact(public_count=0);
 if n=0 and t=0 then
  dbms_output.put_line('T|{name}|ABSENT');
 else
  exact(n=1 and t=1);
  select object_id,created,last_ddl_time into oid,created_value,ddl_value
   from user_objects where object_name='{name}' and object_type='TABLE' and status='VALID';
  select count(*) into regular_count from user_tables where table_name='{name}'
   and temporary='N' and secondary='N' and nested='NO' and partitioned='NO'
   and iot_type is null and cluster_name is null;
  select count(*) into ext_count from user_external_tables where table_name='{name}';
  select count(*) into trig_count from user_triggers where table_name='{name}';
  select count(*) into identity_count from user_tab_identity_cols where table_name='{name}';
  select count(*) into constraint_count from user_constraints where table_name='{name}';
  select count(*) into column_count from user_tab_cols where table_name='{name}';
  select count(*) into index_count from user_indexes where table_name='{name}';
  select (select count(*) from user_tab_privs_made where table_name='{name}')
   +(select count(*) from user_col_privs_made where table_name='{name}') into grant_count from dual;
  select count(*) into child_count from user_constraints where constraint_type='R' and r_owner=user
   and r_constraint_name in (select constraint_name from user_constraints
    where table_name='{name}' and constraint_type='P');
  exact(regular_count=1 and ext_count=0 and column_count between 2 and 20
   and constraint_count between 1 and 21 and identity_count between 0 and 20 and index_count between 0 and 20);
  dbms_output.put_line('T|{name}|PRESENT|'||num(oid)||'|'||to_char(created_value,'YYYY-MM-DD"T"HH24:MI:SS')
   ||'|'||to_char(ddl_value,'YYYY-MM-DD"T"HH24:MI:SS')||'|'||num(trig_count)||'|'||num(identity_count)
   ||'|'||num(constraint_count)||'|'||num(column_count)||'|'||num(index_count)||'|'||num(grant_count)||'|'||num(child_count));
  for c in (select column_id,internal_column_id,column_name,data_type,data_length,char_length,char_used,
    nullable,identity_column,default_on_null,hidden_column,virtual_column,user_generated,
    data_type_owner,data_precision,data_scale,data_default from user_tab_cols
    where table_name='{name}' order by internal_column_id) loop
   def:=c.data_default; dk:='OTHER'; seq:=null;
   if def is null then dk:='NONE';
   elsif c.identity_column='YES' then
    select count(*) into n from user_tab_identity_cols where table_name='{name}' and column_name=c.column_name;
    if n=1 then
     select sequence_name into seq from user_tab_identity_cols where table_name='{name}' and column_name=c.column_name;
     if regexp_like(seq,'^ISEQ[$][$]_[0-9]+$') and upper(trim(def))='"{schema}"."'||seq||'".NEXTVAL' then dk:='IDENTITY_NEXTVAL'; end if;
    end if;
   end if;
   dbms_output.put_line('C|'||num(c.column_id)||'|'||num(c.internal_column_id)||'|'||c.column_name||'|'
    ||c.data_type||'|'||num(c.data_length)||'|'||num(c.char_length)||'|'||nvl(c.char_used,'-')||'|'
    ||c.nullable||'|'||c.identity_column||'|'||c.default_on_null||'|'||c.hidden_column||'|'
    ||c.virtual_column||'|'||c.user_generated||'|'||case when c.data_type_owner is null then 'NONE' else 'SET' end
    ||'|'||num(c.data_precision)||'|'||num(c.data_scale)||'|'||dk);
  end loop;
  for i in (select column_name,generation_type,sequence_name from user_tab_identity_cols where table_name='{name}' order by column_name) loop
   dbms_output.put_line('I|'||i.column_name||'|'||i.generation_type||'|'
    ||case when regexp_like(i.sequence_name,'^ISEQ[$][$]_[0-9]+$') then 'SYSTEM' else 'OTHER' end);
  end loop;
  ordinal:=0;
  for k in (select constraint_name,constraint_type,status,validated,deferrable,deferred,rely,search_condition_vc
    from user_constraints where table_name='{name}' order by constraint_name) loop
   ordinal:=ordinal+1;
   select count(*) into n from user_cons_columns where table_name='{name}' and constraint_name=k.constraint_name;
   exact(n between 1 and 20);
   select listagg(column_name,',') within group(order by position) into cols from user_cons_columns
    where table_name='{name}' and constraint_name=k.constraint_name;
   ck:='OTHER'; nn:='-';
   if k.constraint_type='C' and n=1 and trim(k.search_condition_vc)='"'||cols||'" IS NOT NULL' then ck:='NOT_NULL'; nn:=cols; end if;
   dbms_output.put_line('K|'||num(ordinal)||'|'||k.constraint_type||'|'||k.status||'|'||k.validated||'|'
    ||k.deferrable||'|'||k.deferred||'|'||nvl(k.rely,'-')||'|'||cols||'|'||ck||'|'||nn);
  end loop;
  for i in (select index_name,index_type,uniqueness,status,partitioned from user_indexes where table_name='{name}' order by index_name) loop
   select count(*) into n from user_constraints where table_name='{name}' and constraint_type='P' and index_name=i.index_name;
   select listagg(column_name,',') within group(order by column_position) into cols
    from user_ind_columns where index_name=i.index_name and table_name='{name}';
   select count(*) into t from user_ind_columns where index_name=i.index_name and table_name='{name}' and descend<>'ASC';
   dbms_output.put_line('X|'||i.index_type||'|'||i.uniqueness||'|'||i.status||'|'||i.partitioned||'|'||num(n)||'|'||cols||'|'||num(t));
  end loop;
 end if;
 -- End the coherent metadata snapshot, then ensure the sampled object was not
 -- replaced before completion. This is still only a point-in-time observation;
 -- the preparation/import owner must recheck immediately before its action.
 rollback;
 if oid is null then
  select (select count(*) from user_objects where object_name='{name}')
   +(select count(*) from user_tables where table_name='{name}')
   +(select count(*) from all_synonyms where owner='PUBLIC' and synonym_name='{name}') into n from dual;
  exact(n=0);
 else
  select count(*) into n from user_objects where object_name='{name}' and object_type='TABLE'
   and status='VALID' and object_id=oid and created=created_value and last_ddl_time=ddl_value;
  exact(n=1);
 end if;
 dbms_output.put_line('FOX_SCHEMA_END=1');
end;
/""".format(name=name, schema=expected['parsing_schema'])
    return [*_PREFIX, 'set transaction read only;', _target_guard(expected['parsing_schema']), query, 'rollback;']


def _lines(output, begin, end):
    need(type(output) is str and 0 < len(output) <= 100_000 and output.isascii(), 'SCHEMA_PROTOCOL_INVALID')
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    need(len(lines) >= 3 and lines[0] == begin and lines[-1] == end, 'SCHEMA_PROTOCOL_INCOMPLETE')
    return lines


def _uint(value, *, positive=False):
    need(type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}', value), 'SCHEMA_PROTOCOL_INVALID')
    number = int(value)
    need(not positive or number > 0, 'SCHEMA_PROTOCOL_INVALID')
    return number


def _date(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d', value), 'SCHEMA_PROTOCOL_INVALID')
    try:
        datetime.strptime(value, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        raise ProbeError('SCHEMA_PROTOCOL_INVALID') from None
    return value


def _identity(line, expected):
    need(line.split('|') == ['D', expected['db_name'], expected['session_user'], expected['session_user'],
         expected['parsing_schema'], expected['apex_version'], expected['workspace_id'], '1', 'BYTE'],
         'SCHEMA_TARGET_IDENTITY_MISMATCH')


def _capability_markers():
    return (" dbms_output.put_line('P|'||num(table_priv)||'|'||num(sequence_priv)||'|'||num(unlimited_priv));\n"
            " dbms_output.put_line('Q|'||default_space||'|'||num(quota_count)||'|'||num(quota_used)||'|'||num(quota_limit));\n")


def _capability_values(privilege_line, quota_line):
    privileges = privilege_line.split('|')
    quota = quota_line.split('|')
    need(len(privileges) == 4 and privileges[0] == 'P'
         and all(value in ('0', '1') for value in privileges[1:]), 'SCHEMA_PROTOCOL_INVALID')
    need(len(quota) == 5 and quota[0] == 'Q'
         and re.fullmatch(r'[A-Z][A-Z0-9_$#]{0,127}', quota[1])
         and quota[2] in ('0', '1'), 'SCHEMA_PROTOCOL_INVALID')
    if quota[2] == '0':
        need(quota[3:] == ['-', '-'], 'SCHEMA_PROTOCOL_INVALID')
        used = maximum = None
    else:
        used = _uint(quota[3])
        maximum = -1 if quota[4] == '-1' else _uint(quota[4])
    available = privileges[3] == '1' or (quota[2] == '1' and (maximum == -1 or maximum > used))
    result = {'create_table': privileges[1] == '1', 'create_sequence': privileges[2] == '1',
              'unlimited_tablespace': privileges[3] == '1', 'default_tablespace': quota[1],
              'quota_record_present': quota[2] == '1', 'quota_used_bytes': used,
              'quota_max_bytes': maximum, 'quota_available': available,
              'creation_ready': privileges[1:3] == ['1', '1'] and quota[1] == 'DATA' and available,
              'allocation_guaranteed': False}
    return result


def capability_commands(settings):
    expected = target(settings)
    body = (_DECLARATIONS + 'begin\n' + _identity_sql(expected)
            + " dbms_output.put_line('FOX_SCHEMA_CAPABILITIES_BEGIN=1');\n"
            + _identity_marker(expected) + _capability_markers()
            + " dbms_output.put_line('FOX_SCHEMA_CAPABILITIES_END=1');\nend;\n/")
    return [*_PREFIX, 'set transaction read only;', _target_guard(expected['parsing_schema']), body, 'rollback;']


def capabilities(settings, job_root):
    root = _job_root(settings, job_root)
    expected = target(settings)
    output = _readonly_output(settings, expected, capability_commands(settings), root,
                              'SCHEMA_CAPABILITIES_UNCONFIRMED')
    lines = _lines(output, 'FOX_SCHEMA_CAPABILITIES_BEGIN=1', 'FOX_SCHEMA_CAPABILITIES_END=1')
    need(len(lines) == 5, 'SCHEMA_PROTOCOL_INVALID')
    _identity(lines[1], expected)
    return {'schema_version': 1, 'scope': 'fox-native-schema-capabilities-v1', 'target': expected,
            'capabilities': _capability_values(lines[2], lines[3]), 'read_only': True,
            'data_rows_read': False, 'write_authorized': False}


def parse_observation(output, spec, expected):
    value = validate_native_spec(spec)
    lines = _lines(output, 'FOX_SCHEMA_BEGIN=1', 'FOX_SCHEMA_END=1')
    need(len(lines) >= 6, 'SCHEMA_PROTOCOL_INCOMPLETE')
    _identity(lines[1], expected)
    capability = _capability_values(lines[2], lines[3])
    head = lines[4].split('|')
    name = value['table_name']
    base = {'schema_version': 1, 'scope': 'fox-native-schema-observation-v1',
            'target': dict(expected), 'table_name': name, 'schema_sha256': schema_sha256(value),
            'capabilities': capability,
            'data_rows_read': False, 'business_behavior_verified': False}
    if head == ['T', name, 'ABSENT']:
        need(len(lines) == 6, 'SCHEMA_PROTOCOL_INVALID')
        return {**base, 'state': 'ABSENT', 'object_identity': None, 'metadata_sha256': None}
    need(len(head) == 13 and head[:3] == ['T', name, 'PRESENT'], 'SCHEMA_PROTOCOL_INVALID')
    object_identity = {'object_id': str(_uint(head[3], positive=True)),
                       'created': _date(head[4]), 'last_ddl_time': _date(head[5])}
    counts = list(map(_uint, head[6:]))
    triggers, identities, constraints, columns, indexes, grants, children = counts
    need(triggers == grants == children == 0 and identities == indexes == 1
         and columns == len(value['columns']) and 1 <= constraints <= 21, 'SCHEMA_UNSUPPORTED_METADATA')
    rows = [line.split('|') for line in lines[5:-1]]
    tags = [row[0] for row in rows]
    need(tags == ['C'] * columns + ['I'] * identities + ['K'] * constraints + ['X'] * indexes,
         'SCHEMA_PROTOCOL_INVALID')
    key = next(col['name'] for col in value['columns'] if col['primary_key'])
    for position, (actual, column) in enumerate(zip(rows[:columns], value['columns']), 1):
        identity = column['identity']
        expected_column = ['C', str(position), str(position), column['name'], column['data_type'],
            str(column['length'] if column['data_type'] == 'VARCHAR2' else (22 if column['data_type'] == 'NUMBER' else 7)),
            str(column.get('length', 0)), 'B' if column['data_type'] == 'VARCHAR2' else '-',
            'Y' if column['nullable'] else 'N', 'YES' if identity else 'NO', 'YES' if identity else 'NO',
            'NO', 'NO', 'YES', 'NONE', '-', '-', 'IDENTITY_NEXTVAL' if identity else 'NONE']
        need(actual == expected_column, 'SCHEMA_COLUMN_MISMATCH')
    need(rows[columns] == ['I', key, 'BY DEFAULT', 'SYSTEM'], 'SCHEMA_IDENTITY_MISMATCH')
    not_null, primary = [], 0
    for ordinal, constraint in enumerate(rows[columns + 1:-1], 1):
        need(len(constraint) == 11 and constraint[0] == 'K' and constraint[1] == str(ordinal)
             and constraint[3:8] == ['ENABLED', 'VALIDATED', 'NOT DEFERRABLE', 'IMMEDIATE', '-'],
             'SCHEMA_CONSTRAINT_MISMATCH')
        if constraint[2] == 'P':
            need(constraint[8:] == [key, 'OTHER', '-'], 'SCHEMA_CONSTRAINT_MISMATCH')
            primary += 1
        else:
            need(constraint[2] == 'C' and constraint[9] == 'NOT_NULL' and constraint[8] == constraint[10],
                 'SCHEMA_CONSTRAINT_MISMATCH')
            not_null.append(constraint[10])
    required = {col['name'] for col in value['columns'] if not col['nullable']}
    need(primary == 1 and len(not_null) == len(required) and set(not_null) == required,
         'SCHEMA_CONSTRAINT_MISMATCH')
    need(rows[-1] == ['X', 'NORMAL', 'UNIQUE', 'VALID', 'NO', '1', key, '0'], 'SCHEMA_INDEX_MISMATCH')
    return {**base, 'state': 'EXACT', 'object_identity': object_identity,
            'metadata_sha256': digest({'schema': schema_contract(value), 'rows': rows})}


def _job_root(settings, job_root):
    try:
        root = Path(job_root).absolute()
        jobs = Path(settings.jobs_root).absolute()
        need(root.is_dir() and not root.is_symlink() and root.resolve() == root
             and jobs.is_dir() and not jobs.is_symlink() and jobs.resolve() == jobs
             and root.parent == jobs, 'SCHEMA_JOB_ROOT_UNSAFE')
        return root
    except ProbeError:
        raise
    except (OSError, TypeError, ValueError, AttributeError, RuntimeError):
        raise ProbeError('SCHEMA_JOB_ROOT_UNSAFE') from None


def _readonly_output(settings, expected, commands, root, error_code):
    try:
        result = _run_script(settings.sqlcl_path, ['-S', '-L', '-name', expected['saved_connection']],
                             commands, root, timeout=120)
        need(type(result.returncode) is int and result.returncode == 0
             and type(result.stderr) is str and not result.stderr.strip(), error_code)
        return result.stdout
    except ProbeError:
        raise
    except Exception:
        # Never propagate command arguments, environment, provider logs or
        # credential-bearing exception representations to the business UI.
        raise ProbeError(error_code) from None


def observe(settings, spec, job_root):
    root = _job_root(settings, job_root)
    expected = target(settings)
    output = _readonly_output(settings, expected, observation_commands(settings, spec), root,
                              'SCHEMA_OBSERVATION_UNCONFIRMED')
    return parse_observation(output, spec, expected)


def create_commands(settings, spec, intent_token):
    value = validate_native_spec(spec)
    expected = target(settings)
    need(type(intent_token) is str and re.fullmatch('[a-f0-9]{32}', intent_token), 'SCHEMA_INTENT_TOKEN_INVALID')
    rendered = render_native_schema(value)
    need(rendered.count('CREATE TABLE ') == 1 and rendered.endswith(';\n'), 'SCHEMA_RENDERER_CHANGED')
    ddl = 'CREATE TABLE ' + rendered.split('CREATE TABLE ', 1)[1][:-2]
    need("'" not in ddl and ';' not in ddl and ddl.startswith('CREATE TABLE ' + value['table_name'] + ' ('),
         'SCHEMA_RENDERER_CHANGED')
    name = value['table_name']
    body = _DECLARATIONS + 'begin\n' + _identity_sql(expected) + """
 exact(table_priv=1 and sequence_priv=1 and default_space='DATA'
  and (unlimited_priv=1 or (quota_count=1 and (quota_limit=-1 or quota_limit>quota_used))));
 select count(*) into n from user_objects where object_name='{name}';
 select count(*) into t from user_tables where table_name='{name}';
 select count(*) into public_count from all_synonyms where owner='PUBLIC' and synonym_name='{name}';
 exact(n=0 and t=0 and public_count=0);
 execute immediate '{ddl}';
 select object_id,created,last_ddl_time into oid,created_value,ddl_value
  from user_objects where object_name='{name}' and object_type='TABLE' and status='VALID';
 dbms_output.put_line('FOX_SCHEMA_CREATE_BEGIN=1');
""".format(name=name, ddl=ddl)
    body += _identity_marker(expected)
    body += (" dbms_output.put_line('CREATED|" + name + '|' + intent_token + "|'||num(oid)||'|'"
             "||to_char(created_value,'YYYY-MM-DD\"T\"HH24:MI:SS')||'|'||to_char(ddl_value,'YYYY-MM-DD\"T\"HH24:MI:SS'));\n"
             " dbms_output.put_line('FOX_SCHEMA_CREATE_END=1');\nend;\n/")
    return [*_PREFIX, _target_guard(expected['parsing_schema']), body]


def parse_create_output(output, spec, intent_token, settings):
    value = validate_native_spec(spec)
    expected = target(settings)
    need(type(intent_token) is str and re.fullmatch('[a-f0-9]{32}', intent_token), 'SCHEMA_INTENT_TOKEN_INVALID')
    lines = _lines(output, 'FOX_SCHEMA_CREATE_BEGIN=1', 'FOX_SCHEMA_CREATE_END=1')
    need(len(lines) == 4, 'SCHEMA_CREATE_RESULT_UNCONFIRMED')
    _identity(lines[1], expected)
    fields = lines[2].split('|')
    need(len(fields) == 6 and fields[:3] == ['CREATED', value['table_name'], intent_token],
         'SCHEMA_CREATE_RESULT_UNCONFIRMED')
    return {'schema_version': 1, 'scope': 'fox-native-schema-create-observation-v1',
            'target': expected, 'table_name': value['table_name'], 'schema_sha256': schema_sha256(value),
            'intent_token': intent_token, 'object_identity': {'object_id': str(_uint(fields[3], positive=True)),
                'created': _date(fields[4]), 'last_ddl_time': _date(fields[5])},
            'ddl_sha256': hashlib.sha256(render_native_schema(value).encode('utf-8')).hexdigest(),
            'created_in_this_sqlcl_execution': True, 'metadata_verification_still_required': True}
