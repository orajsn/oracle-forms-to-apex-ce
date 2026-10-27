"""Protected, phase-at-a-time clean installation on the existing JSN converter.

Run inside the already deployed converter's Python 3.11 environment. This is a
lab operator, not a customer deployment endpoint. There are no configurable
target paths, URLs, credentials, grants or SQL commands. The caller must verify
the source observation and this operator's code digest independently. Checks
never create files. Every apply writes a durable, immutable intent before SQL;
an interrupted phase needs human investigation and is never retried here.
"""
from __future__ import annotations

import base64
from collections import Counter
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import urllib.request
import zipfile

from . import contracts as c
from forms2apex.clean_package import validate_native_package


PRIVATE_ROOT = Path('/opt/forms2apex/outputs/jobs/.operator-clean')
URL_BASE = 'https://ASZ8EQWFM8UNCA2-JSNF2APEX.adb.us-ashburn-1.oraclecloudapps.com/ords'
SQLCL = '/opt/sqlcl/bin/sql'
WALLET = '/opt/forms2apex/wallet'
TNS = 'jsnf2apex_low'
ORDER = ('allocate', 'schema', 'import', 'verify')
MAX_FILE = 8_000_000
PASSWORD = re.compile(r'Aa9![a-f0-9]{26}\Z')
LOGIN_PASSWORD = re.compile(r'[A-Za-z0-9_!#%+.,:=?@^*\-]{12,128}\Z')
MARKER = re.compile(r'^FOX_OPERATOR_([A-Z_]+)=([A-Za-z0-9_.|:=/+ -]+)$')
ERROR = re.compile(r'\b(?:ORA|SP2|SP)-[0-9]+')
ERROR_NUMBER = re.compile(r'(?<![A-Za-z0-9_])(?:ORA-[0-9]{5}|SP2-[0-9]{4}|SP-[0-9]{4,5})(?![A-Za-z0-9_])')
PREFIX = b'''whenever sqlerror exit failure rollback
whenever oserror exit failure rollback
set echo off verify off define off heading off feedback off pagesize 0
set linesize 32767
set sqlblanklines on
set serveroutput on size unlimited
'''


class RemoteError(RuntimeError):
    """A fixed, secret-free operator error code."""

    def __init__(self, code, *, diagnostics=None):
        super().__init__(code)
        self.diagnostics = c.safe_diagnostics(diagnostics)


def sql_diagnostics(category, return_code, *outputs):
    codes = []
    for raw in outputs:
        text = raw.decode('utf-8', 'replace') if type(raw) is bytes else raw if type(raw) is str else ''
        for match in ERROR_NUMBER.finditer(text):
            if match[0] not in codes:
                codes.append(match[0])
                if len(codes) == 8:
                    break
        if len(codes) == 8:
            break
    return c.safe_diagnostics({'category': category, 'error_codes': codes, 'return_code': return_code})


def failure_response(error, phase=None):
    if type(error) is RemoteError:
        return c.failure_response(error.args[0] if error.args else None, phase, error.diagnostics)
    return c.failure_response(None, phase)


def require(condition, code):
    if not condition:
        raise RemoteError(code)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def one(markers, name):
    values = [value for key, value in markers if key == name]
    require(len(values) == 1, 'MISSING_OR_DUPLICATE_MARKER')
    return values[0]


def number(markers, name):
    value = one(markers, name)
    require(re.fullmatch(r'0|[1-9][0-9]*', value) is not None, 'INVALID_NUMERIC_MARKER')
    return int(value)


def generated_credentials():
    values = ['Aa9!' + secrets.token_hex(13) for _ in range(3)]
    require(len(set(values)) == 3, 'RANDOM_CREDENTIAL_COLLISION')
    return {'schema_password': values[0], 'password': values[1], 'second_password': values[2]}


class PrivateStore:
    """Fixed-root, owner-only descriptor traversal; no unlink, replace or chmod."""

    def __init__(self, plan_hash, *, create=False):
        require(re.fullmatch(r'[a-f0-9]{64}', plan_hash or '') is not None, 'INVALID_PLAN_DIGEST')
        self.fd = None
        self.path = str(PRIVATE_ROOT / plan_hash)
        self.lock_fd = None
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

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    @staticmethod
    def _name(name):
        require(type(name) is str and re.fullmatch(r'[a-z][a-z0-9.-]{0,79}', name) is not None,
                'PRIVATE_FILE_NAME_INVALID')

    def read(self, name):
        self._name(name)
        if self.fd is None:
            return None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        except OSError:
            raise RemoteError('PRIVATE_FILE_UNSAFE') from None
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_FILE,
                    'PRIVATE_FILE_PERMISSIONS')
            raw = stream.read(MAX_FILE + 1)
        require(len(raw) <= MAX_FILE, 'PRIVATE_FILE_TOO_LARGE')
        return raw

    def create(self, name, raw):
        self._name(name)
        require(self.fd is not None and type(raw) is bytes and len(raw) <= MAX_FILE, 'PRIVATE_WRITE_INVALID')
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(self.fd)
        except OSError:
            raise RemoteError('PRIVATE_CREATE_ONCE_FAILED') from None
        require(self.read(name) == raw, 'PRIVATE_WRITE_READBACK_FAILED')

    def acquire(self):
        import fcntl
        require(self.fd is not None, 'PRIVATE_STORE_ABSENT')
        self.lock_fd = os.open('operator.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        info = os.fstat(self.lock_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_LOCK_UNSAFE')
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RemoteError('ANOTHER_OPERATOR_IS_ACTIVE') from None


def _guard_sql(username, workspace=None, workspace_id=None):
    """Same-session identity assertion, preceding each fixed write batch."""
    require(username == 'ADMIN' or re.fullmatch(r'FOX_QA_[0-9]{6}_[A-F0-9]{8}', username) is not None,
            'SQL_USERNAME_INVALID')
    sql = f"""
declare n pls_integer; v varchar2(100);
begin
 if sys_context('USERENV','SESSION_USER')<>'{username}' or
    sys_context('USERENV','CURRENT_SCHEMA')<>'{username}' or
    sys_context('USERENV','DB_NAME')<>'{c.DB_NAME}' then
  raise_application_error(-20001,'Operator identity mismatch'); end if;
 select version_no into v from apex_release;
 if v<>'{c.VERSIONS['apex']}' then raise_application_error(-20002,'Operator APEX version mismatch'); end if;
"""
    if username == 'ADMIN':
        sql += f"""
 select count(*) into n from v$pdbs where
 lower(json_value(cloud_identity,'$.DATABASE_OCID'))='{c.DATABASE}' and
 lower(json_value(cloud_identity,'$.COMPARTMENT_OCID'))='{c.COMPARTMENT}' and
 json_value(cloud_identity,'$.REGION')='{c.REGION}';
 if n<>1 then raise_application_error(-20003,'Operator cloud identity mismatch'); end if;
 select version_full into v from v$instance;
 if v<>'{c.VERSIONS['database']}' then raise_application_error(-20004,'Operator database version mismatch'); end if;
"""
    else:
        require(workspace == username and type(workspace_id) is str and re.fullmatch(r'[1-9][0-9]{0,37}', workspace_id),
                'SCHEMA_WORKSPACE_INVALID')
        sql += f"""
 if apex_util.find_security_group_id(p_workspace=>'{workspace}')<>{workspace_id} then
  raise_application_error(-20005,'Operator workspace mismatch'); end if;
 select count(*) into n from apex_workspace_schemas
 where workspace_name='{workspace}' and schema='{username}' and workspace_id={workspace_id};
 if n<>1 then raise_application_error(-20006,'Operator schema mapping mismatch'); end if;
 apex_util.set_security_group_id(p_security_group_id=>{workspace_id});
 if sys_context('USERENV','CURRENT_SCHEMA')<>'{username}' then
  raise_application_error(-20007,'Operator schema changed'); end if;
"""
    return (sql + "\n dbms_output.put_line('FOX_OPERATOR_IDENTITY=VERIFIED');\nend;\n/\n").encode('ascii')


def _counts_sql(plan, application_id=None):
    name, alias = plan['target']['workspace'], plan['target']['application_alias']
    queries = {
        'SCHEMA_COUNT': f"all_users where username='{name}'",
        'WORKSPACE_COUNT': f"apex_workspaces where workspace='{name}'",
        'MAPPING_COUNT': f"apex_workspace_schemas where schema='{name}' or workspace_name='{name}'",
        'CORRECT_MAPPING_COUNT': f"apex_workspace_schemas where schema='{name}' and workspace_name='{name}' and first_schema_provisioned='{name}'",
        'APPLICATION_COUNT': f"apex_applications where workspace='{name}'",
        'ALIAS_COUNT': f"apex_applications where upper(alias)='{alias}'",
        'OBJECT_COUNT': f"dba_objects where owner='{name}'",
        'ROLE_COUNT': f"dba_role_privs where grantee='{name}'",
        'GRANT_COUNT': f"dba_tab_privs where grantee='{name}'",
        'PRIVILEGE_COUNT': f"dba_sys_privs where grantee='{name}'",
        'BAD_PRIVILEGE_COUNT': f"dba_sys_privs where grantee='{name}' and (privilege not in ('CREATE SESSION','CREATE TABLE','CREATE SEQUENCE') or admin_option<>'NO')",
        'QUOTA_COUNT': f"dba_ts_quotas where username='{name}'",
        'CORRECT_QUOTA_COUNT': f"dba_ts_quotas where username='{name}' and tablespace_name='DATA' and max_bytes=20971520",
        'ACCOUNT_COUNT': f"dba_users where username='{name}' and account_status='OPEN' and default_tablespace='DATA'",
        'USER_COUNT': f"apex_workspace_apex_users where workspace_name='{name}'",
        'RUNTIME_USER_COUNT': f"apex_workspace_apex_users where workspace_name='{name}' and user_name in ('FOX_QA_A','FOX_QA_B') and upper(is_admin) in ('N','NO') and upper(is_application_developer) in ('N','NO') and upper(is_data_reporter_developer) in ('N','NO') and upper(account_locked) in ('N','NO')",
        'POC_DEPENDENCY_COUNT': f"dba_dependencies where owner='{name}' and referenced_owner='FORMS2APEX_POC'",
        'POC_SYNONYM_COUNT': f"dba_synonyms where owner='{name}' and table_owner='FORMS2APEX_POC'",
    }
    if application_id is not None:
        require(type(application_id) is int and 0 < application_id <= c.MAX_SAFE_INTEGER, 'APPLICATION_ID_INVALID')
        queries['ID_COUNT'] = f'apex_applications where application_id={application_id}'
        queries['EXACT_APP_COUNT'] = f"apex_applications where application_id={application_id} and workspace='{name}' and owner='{name}' and upper(alias)='{alias}'"
    sql = ''.join(f"select 'FOX_OPERATOR_{key}='||count(*) from {value};\n" for key, value in queries.items())
    sql += f"select 'FOX_OPERATOR_WORKSPACE_ID='||to_char(workspace_id,'TM9') from apex_workspaces where workspace='{name}';\n"
    return sql.encode('ascii'), tuple(queries)


def assert_absent(state):
    require(all(state[key] == 0 for key in ('SCHEMA_COUNT', 'WORKSPACE_COUNT', 'MAPPING_COUNT', 'APPLICATION_COUNT',
                                          'ALIAS_COUNT', 'OBJECT_COUNT', 'USER_COUNT')), 'NAMESPACE_NOT_UNUSED')


def assert_isolated(state, allocation):
    expected = {'SCHEMA_COUNT': 1, 'WORKSPACE_COUNT': 1, 'MAPPING_COUNT': 1, 'CORRECT_MAPPING_COUNT': 1,
                'ROLE_COUNT': 0, 'GRANT_COUNT': 0, 'PRIVILEGE_COUNT': 3, 'BAD_PRIVILEGE_COUNT': 0,
                'QUOTA_COUNT': 1, 'CORRECT_QUOTA_COUNT': 1, 'ACCOUNT_COUNT': 1, 'USER_COUNT': 2,
                'RUNTIME_USER_COUNT': 2, 'POC_DEPENDENCY_COUNT': 0, 'POC_SYNONYM_COUNT': 0}
    require(all(state[key] == value for key, value in expected.items())
            and state['workspace_id'] == allocation['target']['workspace_id'], 'TARGET_ISOLATION_MISMATCH')


def allocation_sql(plan, credentials):
    name = plan['target']['workspace']
    require(set(credentials) == {'schema_password', 'password', 'second_password'} and
            all(type(v) is str and PASSWORD.fullmatch(v) for v in credentials.values()) and
            len(set(credentials.values())) == 3, 'GENERATED_CREDENTIALS_INVALID')
    # Kept exclusively in process memory and SQLcl stdin. No script file or log.
    sql = f"""
declare n pls_integer; ws number;
begin
 select count(*) into n from all_users where username='{name}';
 if n<>0 then raise_application_error(-20010,'Schema exists; no replay'); end if;
 select count(*) into n from apex_workspaces where workspace='{name}';
 if n<>0 then raise_application_error(-20011,'Workspace exists; no replay'); end if;
 select count(*) into n from apex_workspace_schemas where schema='{name}' or workspace_name='{name}';
 if n<>0 then raise_application_error(-20012,'Mapping exists; no replay'); end if;
 execute immediate 'create user {name} identified by "{credentials['schema_password']}" default tablespace DATA quota 20M on DATA';
end;
/
""".encode('ascii')
    sql += _guard_sql('ADMIN') + f'grant create session, create table, create sequence to {name};\n'.encode('ascii')
    sql += _guard_sql('ADMIN') + f"""
begin
 apex_instance_admin.add_workspace(p_workspace=>'{name}',p_primary_schema=>'{name}',p_additional_schemas=>NULL);
end;
/
""".encode('ascii')
    for user, key in (('FOX_QA_A', 'password'), ('FOX_QA_B', 'second_password')):
        sql += _guard_sql('ADMIN') + f"""
begin
 apex_util.set_security_group_id(apex_util.find_security_group_id(p_workspace=>'{name}'));
 apex_util.create_user(p_user_name=>'{user}',p_web_password=>'{credentials[key]}',
  p_description=>'Synthetic FOX operator runtime account',p_developer_privs=>NULL,
  p_default_schema=>'{name}',p_allow_access_to_schemas=>'{name}',
  p_account_locked=>'N',p_change_password_on_first_use=>'N',p_allow_app_building_yn=>'N',
  p_allow_sql_workshop_yn=>'N',p_allow_websheet_dev_yn=>'N',p_allow_team_development_yn=>'N');
 commit;
end;
/
""".encode('ascii')
    return _guard_sql('ADMIN') + sql + b'prompt FOX_OPERATOR_ALLOCATE_RETURNED=TRUE\n'


def schema_sql(plan, allocation, package):
    name, ws = plan['target']['workspace'], allocation['target']['workspace_id']
    return _guard_sql(name, name, ws) + f"""
declare n pls_integer;
begin
 select count(*) into n from user_objects;
 if n<>0 then raise_application_error(-20020,'Schema not empty; no replay'); end if;
 select count(*) into n from apex_applications where workspace='{name}';
 if n<>0 then raise_application_error(-20021,'Workspace not empty; no replay'); end if;
end;
/
""".encode('ascii') + package['schema_sql'] + b'\nprompt FOX_OPERATOR_SCHEMA_RETURNED=TRUE\n'


def import_sql(plan, allocation, package):
    name, alias = plan['target']['workspace'], plan['target']['application_alias']
    ws, app = allocation['target']['workspace_id'], allocation['target']['application_id']
    return _guard_sql(name, name, ws) + f"""
declare n pls_integer;
begin
 select count(*) into n from apex_applications where workspace='{name}' or application_id={app} or upper(alias)='{alias}';
 if n<>0 then raise_application_error(-20022,'Application exists; no overwrite'); end if;
 apex_application_install.set_workspace_id({ws});
 apex_application_install.set_schema('{name}');
 apex_application_install.set_application_id({app});
 apex_application_install.generate_offset;
 apex_application_install.set_application_alias('{alias}');
 apex_application_install.set_auto_install_sup_obj(false);
 if apex_application_install.get_application_id<>{app} or apex_application_install.get_schema<>'{name}' then
  raise_application_error(-20023,'Import overrides differ'); end if;
end;
/
""".encode('ascii') + package['application_sql'] + b'\n' + PREFIX + b'prompt FOX_OPERATOR_IMPORT_RETURNED=TRUE\n'


def table_sql(spec):
    table = spec['table_name']
    sql = f"""
select 'FOX_OPERATOR_TABLE_COUNT='||count(*) from user_tables;
select 'FOX_OPERATOR_NATIVE_TABLE_COUNT='||count(*) from user_tables where table_name='{table}';
select 'FOX_OPERATOR_ROW_COUNT='||count(*) from {table};
select 'FOX_OPERATOR_COLUMN='||column_name||'|'||data_type||'|'||nullable||'|'||nvl(char_length,0)||'|'||identity_column
 from user_tab_columns where table_name='{table}' order by column_id;
select 'FOX_OPERATOR_PK='||cc.column_name||'|'||cc.position||'|'||c.status||'|'||c.validated
 from user_constraints c join user_cons_columns cc on cc.constraint_name=c.constraint_name and cc.table_name=c.table_name
 where c.table_name='{table}' and c.constraint_type='P' order by cc.position;
select 'FOX_OPERATOR_PK_COUNT='||count(*) from user_constraints where table_name='{table}' and constraint_type='P';
"""
    forbidden = {'TRIGGER_COUNT': 'user_triggers', 'SYNONYM_COUNT': 'user_synonyms', 'DB_LINK_COUNT': 'user_db_links',
                 'INVALID_OBJECT_COUNT': "user_objects where status<>'VALID'",
                 'UNEXPECTED_OBJECT_COUNT': "user_objects where object_type not in ('TABLE','INDEX','SEQUENCE')",
                 'UNEXPECTED_SCHEMA_DEPENDENCY_COUNT': "user_dependencies where referenced_owner not in (user,'SYS','PUBLIC')"}
    return (sql + ''.join(f"select 'FOX_OPERATOR_{key}='||count(*) from {value};\n" for key, value in forbidden.items())).encode('ascii')


def verify_table(markers, spec, schema):
    expected = ['|'.join((col['name'], col['data_type'], 'Y' if col['nullable'] else 'N',
                          str(col.get('length', 0)), 'YES' if col['identity'] else 'NO')) for col in spec['columns']]
    require([value for key, value in markers if key == 'COLUMN'] == expected, 'TABLE_COLUMN_MISMATCH')
    primary = next(col['name'] for col in spec['columns'] if col['primary_key'])
    require(number(markers, 'TABLE_COUNT') == number(markers, 'NATIVE_TABLE_COUNT') == number(markers, 'PK_COUNT') == 1
            and one(markers, 'PK') == primary + '|1|ENABLED|VALIDATED', 'TABLE_PRIMARY_KEY_MISMATCH')
    for key in ('ROW_COUNT', 'TRIGGER_COUNT', 'SYNONYM_COUNT', 'DB_LINK_COUNT', 'INVALID_OBJECT_COUNT',
                'UNEXPECTED_OBJECT_COUNT', 'UNEXPECTED_SCHEMA_DEPENDENCY_COUNT'):
        require(number(markers, key) == 0, 'TABLE_NOT_CLEAN_AND_EMPTY')
    return {'passed': True, 'schema': schema, 'table_name': spec['table_name'],
            'columns': [{'name': col['name'], 'data_type': col['data_type'], 'nullable': col['nullable'],
                         'char_length': col.get('length', 0), 'identity': col['identity']} for col in spec['columns']],
            'primary_key': {'columns': [primary], 'status': 'ENABLED', 'validated': 'VALIDATED'},
            'row_count': 0, 'unexpected_schema_dependency_count': 0}


def export_sql(app):
    return f"""
declare files apex_t_export_files; pos pls_integer:=1; chunk varchar2(4000); encoded varchar2(8000);
begin
 files:=apex_export.get_application(p_application_id=>{app},p_type=>'SQL',p_split=>false,
  p_with_date=>false,p_with_original_ids=>false,p_with_supporting_objects=>'Y');
 if files.count<>1 or files(1).name<>'f{app}.sql' then raise_application_error(-20030,'Unexpected export file'); end if;
 dbms_output.put_line('FOX_OPERATOR_EXPORT_LENGTH='||dbms_lob.getlength(files(1).contents));
 while pos<=dbms_lob.getlength(files(1).contents) loop
  chunk:=dbms_lob.substr(files(1).contents,3000,pos);
  encoded:=utl_raw.cast_to_varchar2(utl_encode.base64_encode(utl_raw.cast_to_raw(chunk)));
  dbms_output.put_line('FOX_OPERATOR_EXPORT_CHUNK='||replace(replace(encoded,chr(10),''),chr(13),''));
  pos:=pos+length(chunk);
 end loop;
 dbms_output.put_line('FOX_OPERATOR_EXPORT_DONE=TRUE');
end;
/
""".encode('ascii')


def parse_export(markers):
    require(one(markers, 'EXPORT_DONE') == 'TRUE', 'EXPORT_INCOMPLETE')
    chunks = [value for key, value in markers if key == 'EXPORT_CHUNK']
    require(0 < len(chunks) < 1000, 'EXPORT_SIZE_INVALID')
    try:
        raw = b''.join(base64.b64decode(value, validate=True) for value in chunks)
        require(len(raw) < MAX_FILE and len(raw.decode('utf-8')) == number(markers, 'EXPORT_LENGTH'), 'EXPORT_LENGTH_INVALID')
        return raw
    except (ValueError, UnicodeError):
        raise RemoteError('EXPORT_ENCODING_INVALID') from None


CALL = re.compile(r'\b(wwv_imp_workspace\.create_flow|wwv_flow_imp_page\.create_[a-z0-9_]+|wwv_flow_imp_shared\.create_(?:authentication|security_scheme|invokeapi_comp_param))\s*\(', re.I)
FLOW_FIELDS = ('p_authentication_id', 'p_page_protection_enabled_y_n', 'p_browser_cache', 'p_browser_frame',
               'p_rejoin_existing_sessions', 'p_flow_status', 'p_compatibility_mode', 'p_home_url', 'p_login_url',
               'p_global_page_id', 'p_navigation_list_id', 'p_nav_bar_list_id', 'p_theme_id', 'p_authorize_batch_job',
               'p_proxy_server', 'p_no_proxy_domains', 'p_flow_language', 'p_flow_language_derived_from',
               'p_file_storage', 'p_print_server_type', 'p_is_pwa', 'p_pwa_is_installable', 'p_pwa_is_push_enabled')


def native_calls(raw):
    """Normalize only offset IDs; preserve native semantics and security fields."""
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
        require(depth == 0 and not quoted and text[cursor:cursor + 1] == ';', 'NATIVE_EXPORT_PARSE_FAILED')
        call = text[match.start():cursor + 1]
        if match.group(1).lower() == 'wwv_imp_workspace.create_flow':
            fields = []
            for name in FLOW_FIELDS:
                values = re.findall(r'^\s*,?' + name + r'=>([^\n]+)$', call, re.M)
                require(len(values) == 1, 'APPLICATION_SECURITY_FIELD_MISSING')
                fields.append(name + '=>' + values[0])
            call = 'wwv_imp_workspace.create_flow(\n' + '\n,'.join(fields) + '\n);'
        calls.append(call)
        offset = cursor + 1
    require(len(calls) >= 30, 'NATIVE_COMPONENT_SET_INCOMPLETE')
    identities = {}
    def normalize(match):
        value = match[1]
        identities.setdefault(value, str(len(identities) + 1))
        return 'wwv_flow_imp.id(@' + identities[value] + ')'
    return [re.sub(r'wwv_flow_imp\.id\((\d+)\)', normalize, call) for call in calls]


def verify_compiled(original, actual, allocation):
    expected, observed = native_calls(original), native_calls(actual)
    require(expected == observed, 'COMPILED_NATIVE_COMPONENT_MISMATCH')
    text, target = actual.decode('utf-8'), allocation['target']
    require('FORMS2APEX_POC' not in text.upper(), 'ORIGINAL_SCHEMA_REFERENCE_REMAINS')
    patterns = {'workspace_id': r',p_default_workspace_id=>([0-9]+)',
                'application_id': r',p_default_application_id=>([0-9]+)',
                'parsing_schema': r",p_owner=>nvl\(wwv_flow_application_install.get_schema,'([A-Z0-9_]+)'\)",
                'default_owner': r",p_default_owner=>'([A-Z0-9_]+)'",
                'application_alias': r",p_alias=>nvl\(wwv_flow_application_install.get_application_alias,'([A-Z0-9_]+)'\)"}
    for key, pattern in patterns.items():
        values = re.findall(pattern, text)
        expected_value = target['parsing_schema'] if key == 'default_owner' else str(target[key])
        require(values == [expected_value], 'COMPILED_CURRENT_IDENTITY_MISMATCH')
    raw = json.dumps(observed, sort_keys=True, separators=(',', ':')).encode()
    return {'passed': True, 'scope': 'native_pages_authentication_and_selected_application_security_routing_with_id_relation_normalization',
            'p_with_original_ids': False, 'call_count': len(observed),
            'component_counts': dict(sorted(Counter(CALL.match(call)[1].lower() for call in observed).items())),
            'expected_components_sha256': c.digest(raw), 'actual_components_sha256': c.digest(raw),
            'actual_export_sha256': c.digest(actual), 'original_schema_reference_count': 0,
            'current_identity': {'passed': True, **{key: target[key] for key in ('workspace_id', 'application_id', 'application_alias', 'parsing_schema')},
                                 'default_owner': target['parsing_schema']}}


class SqlclDriver:
    """Real driver. All subprocess diagnostics are withheld, including on errors."""

    def scope(self, plan):
        request = urllib.request.Request('http://169.254.169.254/opc/v2/instance/', headers={'Authorization': 'Bearer Oracle'})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read(100_001)
            meta = json.loads(raw)
            require(len(raw) <= 100_000 and meta.get('id') == c.INSTANCE and meta.get('compartmentId') == c.COMPARTMENT
                    and meta.get('canonicalRegionName') == c.REGION, 'VM_SCOPE_MISMATCH')
            require(all(plan['target'][key] == value for key, value in c.FIXED_TARGET.items()), 'PLAN_SCOPE_MISMATCH')
        except RemoteError:
            raise
        except Exception:
            raise RemoteError('VM_SCOPE_UNAVAILABLE') from None

    def sql(self, username, password, body, *, timeout=120):
        require(username == 'ADMIN' or re.fullmatch(r'FOX_QA_[0-9]{6}_[A-F0-9]{8}', username or ''), 'SQL_USERNAME_INVALID')
        require(type(password) is str and LOGIN_PASSWORD.fullmatch(password), 'SQL_PASSWORD_FORMAT_INVALID')
        require(type(body) is bytes and len(body) <= MAX_FILE, 'SQL_BODY_INVALID')
        connect = f'connect -user {username} -password "{password}" -url {TNS}\n'.encode('ascii')
        environment = os.environ.copy()
        require(environment.get('TNS_ADMIN', WALLET) == WALLET, 'WALLET_ENVIRONMENT_MISMATCH')
        environment['TNS_ADMIN'] = WALLET
        try:
            result = subprocess.run([SQLCL, '-nohistory', '-S', '/nolog'], input=PREFIX + connect + body + b'\nexit\n',
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=environment)
            stdout = result.stdout.decode('utf-8', 'replace')
            if result.returncode != 0 or ERROR.search(stdout + result.stderr.decode('utf-8', 'replace')):
                raise RemoteError('SQL_FAILED_OUTPUT_WITHHELD', diagnostics=sql_diagnostics(
                    'SQL_EXECUTION_FAILED', result.returncode, result.stdout, result.stderr))
            return [match.groups() for line in stdout.splitlines() if (match := MARKER.fullmatch(line.strip()))]
        except subprocess.TimeoutExpired as exc:
            raise RemoteError('SQL_TIMEOUT_UNCERTAIN_NO_REPLAY', diagnostics=sql_diagnostics(
                'SQL_EXECUTION_TIMEOUT', None, exc.stdout, exc.stderr)) from None
        except RemoteError:
            raise
        except Exception:
            raise RemoteError('SQL_EXECUTION_UNAVAILABLE', diagnostics=sql_diagnostics('SQL_CLIENT_UNAVAILABLE', None)) from None

    def versions(self, admin):
        markers = self.sql('ADMIN', admin, _guard_sql('ADMIN') + b"select 'FOX_OPERATOR_APEX='||version_no from apex_release;\nselect 'FOX_OPERATOR_DATABASE='||version_full from v$instance;\n")
        require(one(markers, 'IDENTITY') == 'VERIFIED', 'DATABASE_IDENTITY_UNPROVEN')
        try:
            result = subprocess.run([SQLCL, '-V'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            found = re.findall(r'SQLcl:\s*Release\s+([0-9.]+)', result.stdout.decode('utf-8', 'replace'))
            require(result.returncode == 0 and len(found) == 1, 'SQLCL_VERSION_UNAVAILABLE')
            with zipfile.ZipFile('/opt/sqlcl/lib/apexlang-compiler.jar') as jar:
                mmd = json.loads(jar.read('apexlang_meta_data.json'))['buildID']
        except RemoteError:
            raise
        except Exception:
            raise RemoteError('TOOLING_VERSION_UNAVAILABLE') from None
        versions = {'apex': one(markers, 'APEX'), 'database': one(markers, 'DATABASE'), 'sqlcl': found[0], 'mmd': mmd}
        require(versions == c.VERSIONS, 'TESTED_VERSION_PROFILE_MISMATCH')
        return versions

    def observe(self, plan, admin, allocation=None):
        app = allocation['target']['application_id'] if allocation else None
        sql, keys = _counts_sql(plan, app)
        markers = self.sql('ADMIN', admin, _guard_sql('ADMIN') + sql)
        require(one(markers, 'IDENTITY') == 'VERIFIED', 'DATABASE_IDENTITY_UNPROVEN')
        state = {key: number(markers, key) for key in keys}
        state['workspace_id'] = one(markers, 'WORKSPACE_ID') if state['WORKSPACE_COUNT'] == 1 else None
        return state

    def allocate(self, plan, admin, credentials):
        markers = self.sql('ADMIN', admin, allocation_sql(plan, credentials), timeout=180)
        require(one(markers, 'ALLOCATE_RETURNED') == 'TRUE', 'ALLOCATION_RETURN_UNPROVEN')
        state = self.observe(plan, admin)
        ws, name = state['workspace_id'], plan['target']['workspace']
        temporary = {'target': {'workspace_id': ws}}
        assert_isolated(state, temporary)
        require(state['OBJECT_COUNT'] == state['APPLICATION_COUNT'] == state['ALIAS_COUNT'] == 0, 'ALLOCATION_NOT_EMPTY')
        reserve = _guard_sql(name, name, ws) + b"begin apex_application_install.generate_application_id; dbms_output.put_line('FOX_OPERATOR_APPLICATION_ID='||to_char(apex_application_install.get_application_id,'TM9')); end;\n/\n"
        markers = self.sql(name, credentials['schema_password'], reserve)
        app = number(markers, 'APPLICATION_ID')
        require(0 < app <= c.MAX_SAFE_INTEGER and app not in (plan['binding']['source_application_id'],
                plan['binding']['source_reimport_application_id']) and app not in c.PROTECTED_APPLICATION_IDS,
                'ALLOCATED_APPLICATION_ID_UNSAFE')
        check = self.observe(plan, admin, {'target': {'application_id': app}})
        require(check['ID_COUNT'] == check['ALIAS_COUNT'] == 0, 'ALLOCATED_APPLICATION_ID_OCCUPIED')
        return {'workspace_id': ws, 'application_id': app}

    def schema(self, plan, allocation, package, password):
        markers = self.sql(plan['target']['parsing_schema'], password, schema_sql(plan, allocation, package))
        require(one(markers, 'SCHEMA_RETURNED') == 'TRUE', 'SCHEMA_RETURN_UNPROVEN')

    def import_application(self, plan, allocation, package, password):
        markers = self.sql(plan['target']['parsing_schema'], password, import_sql(plan, allocation, package), timeout=240)
        require(one(markers, 'IMPORT_RETURNED') == 'TRUE', 'IMPORT_RETURN_UNPROVEN')

    def table(self, plan, allocation, package, password):
        name, ws = plan['target']['workspace'], allocation['target']['workspace_id']
        markers = self.sql(name, password, _guard_sql(name, name, ws) + table_sql(package['native_form']))
        require(one(markers, 'IDENTITY') == 'VERIFIED', 'SCHEMA_IDENTITY_UNPROVEN')
        return verify_table(markers, package['native_form'], name)

    def export(self, plan, allocation, password):
        name, target = plan['target']['workspace'], allocation['target']
        return parse_export(self.sql(name, password, _guard_sql(name, name, target['workspace_id']) + export_sql(target['application_id'])))


def _phase_record(plan, phase, state, started, evidence=None):
    result = {'schema_version': 1, 'scope': c.PHASE_SCOPE, 'plan_sha256': c.plan_sha256(plan),
              'phase': phase, 'state': state, 'started_at_utc': started,
              'finished_at_utc': None if state == 'intent' else utc_now(),
              'evidence_sha256': c.digest(evidence) if evidence is not None else None}
    c.validate_phase_record(result, plan, phase)
    return result


def phase_state(store, plan, phase):
    intent, complete, attention, evidence = [store.read(phase + suffix) for suffix in
                                            ('.intent.json', '.complete.json', '.attention.json', '.evidence.json')]
    if intent is None:
        require(complete is attention is evidence is None, 'ORPHAN_PHASE_EVIDENCE')
        return 'unattempted'
    require(c.validate_phase_record(intent, plan, phase) == 'attention'
            and c.load_json(intent)['state'] == 'intent', 'PHASE_INTENT_INVALID')
    if attention is not None:
        require(c.validate_phase_record(attention, plan, phase) == 'attention', 'PHASE_ATTENTION_INVALID')
    if complete is not None:
        require(attention is None and c.validate_phase_record(complete, plan, phase) == 'complete'
                and evidence is not None and c.load_json(complete)['evidence_sha256'] == c.digest(evidence)
                and c.load_json(complete)['started_at_utc'] == c.load_json(intent)['started_at_utc'], 'PHASE_COMPLETION_INVALID')
        return 'complete'
    return 'attention'


def _retain(store, name, raw):
    existing = store.read(name)
    if existing is None:
        store.create(name, raw)
    else:
        require(existing == raw, 'IMMUTABLE_ARTIFACT_MISMATCH')


def _credentials(store, name, *, create=False):
    schema, browser = store.read('schema-credentials.json'), store.read('runtime-credentials.json')
    if schema is None and browser is None and create:
        result = generated_credentials()
        store.create('schema-credentials.json', c.canonical_bytes({'schema_username': name, 'schema_password': result['schema_password']}))
        store.create('runtime-credentials.json', c.canonical_bytes({'username': 'FOX_QA_A', 'password': result['password'],
                                                                  'second_username': 'FOX_QA_B', 'second_password': result['second_password']}))
        return result
    require(schema is not None and browser is not None, 'CREDENTIAL_WRITE_INCOMPLETE_NO_REPLAY')
    schema, browser = c.load_json(schema), c.load_json(browser)
    require(set(schema) == {'schema_username', 'schema_password'} and schema['schema_username'] == name
            and set(browser) == {'username', 'password', 'second_username', 'second_password'}
            and browser['username'] == 'FOX_QA_A' and browser['second_username'] == 'FOX_QA_B', 'CREDENTIAL_BINDING_INVALID')
    result = {'schema_password': schema['schema_password'], 'password': browser['password'], 'second_password': browser['second_password']}
    require(all(type(value) is str and PASSWORD.fullmatch(value) for value in result.values()) and len(set(result.values())) == 3,
            'CREDENTIAL_FORMAT_INVALID')
    return result


def _make_allocation(plan, ids, versions):
    result = {'schema_version': 1, 'scope': c.ALLOCATION_SCOPE, 'passed': True, 'plan_sha256': c.plan_sha256(plan),
              'allocated_at_utc': utc_now(), 'binding': {key: plan['binding'][key] for key in
                                                       ('job_id', 'source_manifest_sha256', 'package_sha256')},
              'target': {**plan['target'], **ids}, 'observed_versions': versions,
              'fresh_namespace': {'workspace_created_fresh': True, 'schema_created_fresh': True,
                                  'application_count': 0, 'user_object_count': 0}}
    return c.validate_allocation(result, plan)


def _clean_receipt(plan, allocation, allocation_raw, profile_raw, versions, table, compiled, started):
    target, binding = allocation['target'], plan['binding']
    return {'schema_version': 2, 'scope': 'fox-clean-package-install-v2', 'passed': True,
            'started_at_utc': started, 'finished_at_utc': utc_now(),
            **{key: target[key] for key in ('compartment_id', 'database_id', 'region', 'db_name', 'workspace',
                                           'workspace_id', 'parsing_schema', 'application_id', 'application_alias')},
            **{key: binding[key] for key in ('job_id', 'table_name', 'profile_id', 'package_sha256', 'sql_sha256',
                                             'schema_script_sha256', 'native_spec_sha256', 'source_manifest_sha256')},
            'plan_sha256': c.plan_sha256(plan), 'allocation_receipt_sha256': c.digest(allocation_raw),
            'verification_profile_sha256': c.digest(profile_raw), 'observed_versions': versions,
            'application_url': URL_BASE + '/r/' + target['workspace'].lower() + '/' + target['application_alias'].lower() + '/',
            'clean_install': {'passed': True, 'workspace_created_fresh': True, 'schema_created_fresh': True,
                              'before_install': {'passed': True, 'application_count': 0, 'user_object_count': 0},
                              'after_install': {'passed': True, 'application_count': 1, 'native_table_count': 1,
                                                'initial_row_count': 0, 'unexpected_schema_dependency_count': 0}},
            'table_metadata': table, 'compiled_native_components': compiled,
            'no_original_schema_dependencies': {'passed': True, 'original_schema': 'FORMS2APEX_POC', 'reference_count': 0},
            'human_business_acceptance': False, 'authenticated_runtime_passed': False,
            'limitations': ['Synthetic native-table-form-v1 on the exact tested JSN version tuple only.',
                            'Runtime QA and human business acceptance remain separate.']}


def _expected_table(package, schema):
    spec = package['native_form']
    primary = next(col['name'] for col in spec['columns'] if col['primary_key'])
    return {'passed': True, 'schema': schema, 'table_name': spec['table_name'],
            'columns': [{'name': col['name'], 'data_type': col['data_type'], 'nullable': col['nullable'],
                         'char_length': col.get('length', 0), 'identity': col['identity']} for col in spec['columns']],
            'primary_key': {'columns': [primary], 'status': 'ENABLED', 'validated': 'VALIDATED'},
            'row_count': 0, 'unexpected_schema_dependency_count': 0}


def verify_retained(store, plan, plan_raw, package, package_raw, native_raw, states, allocation, allocation_raw):
    """Completion means its immutable bytes and all downstream bindings survive."""
    if not any(state == 'complete' for state in states.values()):
        return
    require(store.read('plan.json') == plan_raw and store.read('package.zip') == package_raw
            and store.read('native-form-spec.json') == native_raw, 'RETAINED_INPUTS_MISSING_OR_CHANGED')
    table = _expected_table(package, plan['target']['parsing_schema'])
    plan_hash = c.plan_sha256(plan)
    if states['schema'] == 'complete':
        require(store.read('schema.evidence.json') == c.canonical_bytes({
            'passed': True, 'table_metadata': table, 'plan_sha256': plan_hash,
            'schema_script_sha256': plan['binding']['schema_script_sha256']}), 'RETAINED_SCHEMA_PROOF_INVALID')
    if states['import'] == 'complete':
        require(store.read('import.evidence.json') == c.canonical_bytes({
            'passed': True, 'plan_sha256': plan_hash, 'application_id': allocation['target']['application_id'],
            'application_alias': plan['target']['application_alias'], 'sql_sha256': plan['binding']['sql_sha256']}),
            'RETAINED_IMPORT_PROOF_INVALID')
    if states['verify'] == 'complete':
        profile_raw = store.read('verification-profile.json')
        require(profile_raw == c.canonical_bytes(c.make_verification_profile(plan, allocation_raw)),
                'RETAINED_VERIFICATION_PROFILE_MISSING_OR_CHANGED')
        actual = store.read('compiled-application.sql')
        require(actual is not None, 'RETAINED_COMPILED_EXPORT_MISSING')
        compiled = verify_compiled(package['application_sql'], actual, allocation)
        receipt_raw = store.read('verify.evidence.json')
        receipt = c.load_json(receipt_raw)
        journal = c.load_json(store.read('verify.complete.json'))
        require(receipt.get('started_at_utc') == journal['started_at_utc'], 'RETAINED_VERIFY_TIME_MISMATCH')
        receipt_record = {**journal, 'finished_at_utc': receipt.get('finished_at_utc')}
        c.validate_phase_record(receipt_record, plan, 'verify')
        require(datetime.fromisoformat(receipt['finished_at_utc'].replace('Z', '+00:00')) <=
                datetime.fromisoformat(journal['finished_at_utc'].replace('Z', '+00:00')), 'RETAINED_VERIFY_TIME_MISMATCH')
        expected = _clean_receipt(plan, allocation, allocation_raw, profile_raw, plan['expected_versions'],
                                  table, compiled, journal['started_at_utc'])
        expected['finished_at_utc'] = receipt['finished_at_utc']
        require(receipt_raw == c.canonical_bytes(expected), 'RETAINED_VERIFY_PROOF_INVALID')


def verify_completed_live(plan, allocation, states, observation, package, driver, store):
    """Read-only postconditions before a clean-ready claim or no-replay skip.

    After separate runtime QA writes rows, status remains a historical receipt
    inspection; check intentionally no longer calls that target clean/empty.
    Incomplete outcomes remain attention and are never inferred complete here.
    """
    if 'attention' in states.values():
        return
    if allocation is None:
        assert_absent(observation)
        return
    assert_isolated(observation, allocation)
    if states['import'] == 'complete':
        require(all(observation[key] == 1 for key in ('APPLICATION_COUNT', 'ALIAS_COUNT', 'ID_COUNT', 'EXACT_APP_COUNT')),
                'COMPLETED_APPLICATION_STATE_CHANGED')
    else:
        require(observation['APPLICATION_COUNT'] == observation['ALIAS_COUNT'] == observation['ID_COUNT'] == 0,
                'COMPLETED_ALLOCATION_APPLICATION_STATE_CHANGED')
    if states['schema'] == 'complete':
        password = _credentials(store, plan['target']['workspace'])['schema_password']
        require(driver.table(plan, allocation, package, password) == _expected_table(package, plan['target']['parsing_schema']),
                'COMPLETED_SCHEMA_STATE_CHANGED')
        if states['verify'] == 'complete':
            current = driver.export(plan, allocation, password)
            verify_compiled(package['application_sql'], current, allocation)
    else:
        require(observation['OBJECT_COUNT'] == 0, 'COMPLETED_ALLOCATION_OBJECT_STATE_CHANGED')


def qa_handoff(store):
    return {key: store.path + '/' + filename for key, filename in {
        'package': 'package.zip', 'native_spec': 'native-form-spec.json', 'allocation_receipt': 'allocate.evidence.json',
        'verification_profile': 'verification-profile.json', 'import_receipt': 'verify.evidence.json',
        'runtime_credentials': 'runtime-credentials.json'}.items()}


def execute(command, plan_raw, package_raw, *, expected_plan_sha256, phase=None, apply=False,
            admin_password=None, operator_code_sha256=None, driver=None, store=None):
    """Execute one explicit phase, or read-only check/status; never print secrets.

    Driver/store injection exists for offline unit tests, not a CLI option. The
    production caller must pass independently computed operator_code_sha256.
    Returned paths are fixed private evidence paths, never secret file content.
    """
    own_store = store is None
    try:
        require(command in ('check', 'status', 'apply') and type(apply) is bool, 'COMMAND_INVALID')
        require((command == 'apply' and apply is True and phase in ORDER) or
                (command != 'apply' and apply is False and phase is None), 'EXPLICIT_PHASE_APPROVAL_REQUIRED')
        require(type(plan_raw) is bytes and type(package_raw) is bytes and type(operator_code_sha256) is str,
                'EXACT_INPUT_BYTES_AND_CODE_DIGEST_REQUIRED')
        plan = c.validate_plan(plan_raw, operator_code_sha256=operator_code_sha256 if command != 'status' else None)
        plan_hash = c.plan_sha256(plan)
        require(expected_plan_sha256 == plan_hash, 'APPROVED_PLAN_DIGEST_MISMATCH')
        package = validate_native_package(package_raw, plan['binding']['package_sha256'])
        # Full archive validation above owns safety. Read exactly one already
        # validated member for its byte identity; no second generic ZIP parser.
        with zipfile.ZipFile(io.BytesIO(package_raw)) as archive:
            native_raw = archive.read('native-form-spec.json')
        c.validate_plan(plan, validated_package=package, native_spec_sha256=c.digest(native_raw))
        require(len(package_raw) == plan['source_origin']['package_bytes'], 'SOURCE_PACKAGE_SIZE_CHANGED')
        driver = driver or SqlclDriver()
        driver.scope(plan)
        versions = None
        if command != 'status':
            versions = driver.versions(admin_password)
            require(versions == plan['expected_versions'], 'TESTED_VERSION_PROFILE_MISMATCH')
        store = store or PrivateStore(plan_hash, create=command == 'apply')
        if command == 'apply':
            store.acquire()
        retained_plan = store.read('plan.json')
        require(retained_plan is None or retained_plan == plan_raw, 'RETAINED_PLAN_MISMATCH')
        states = {item: phase_state(store, plan, item) for item in ORDER}
        for index, item in enumerate(ORDER):
            if states[item] != 'unattempted':
                require(all(states[earlier] == 'complete' for earlier in ORDER[:index]), 'PHASE_ORDER_INVALID')
        allocation_raw = store.read('allocate.evidence.json') if states['allocate'] == 'complete' else None
        allocation = c.validate_allocation(allocation_raw, plan) if allocation_raw else None
        verify_retained(store, plan, plan_raw, package, package_raw, native_raw, states, allocation, allocation_raw)
        if command == 'status':
            return {'schema_version': 1, 'scope': 'fox-clean-operator-status-v1', 'plan_sha256': plan_hash,
                    'phases': states, 'private_evidence_directory': store.path,
                    'operator_code_matches': operator_code_sha256 == plan['operator_code_sha256'],
                    'database_checked': False, 'historical_evidence_only': True,
                    'state': 'QA_READY_HISTORICAL' if states['verify'] == 'complete' else
                    ('ATTENTION' if 'attention' in states.values() else 'PREPARED')}
        observation = driver.observe(plan, admin_password, allocation)
        if command == 'check' or states[phase] == 'complete':
            verify_completed_live(plan, allocation, states, observation, package, driver, store)
        result = {'schema_version': 1, 'scope': 'fox-clean-operator-status-v1', 'plan_sha256': plan_hash,
                  'phases': states, 'observed_versions': versions, 'observation': observation,
                  'private_evidence_directory': store.path, 'state': 'QA_READY' if states['verify'] == 'complete' else
                  ('ATTENTION' if 'attention' in states.values() else 'PREPARED')}
        if command != 'apply':
            if states['verify'] == 'complete':
                result['qa_handoff'] = qa_handoff(store)
            return result
        if states[phase] == 'complete':
            result['action'] = 'ALREADY_COMPLETE_NO_REPLAY'
            if states['verify'] == 'complete':
                result['qa_handoff'] = qa_handoff(store)
            return result
        require(states[phase] == 'unattempted' and all(states[item] == 'complete' for item in ORDER[:ORDER.index(phase)]),
                'PHASE_NOT_STARTABLE_NO_REPLAY')
        require('attention' not in states.values(), 'UNCERTAIN_PHASE_NO_REPLAY')
        if phase == 'allocate':
            assert_absent(observation)
        else:
            assert_isolated(observation, allocation)
            if phase in ('schema', 'import'):
                require(observation['APPLICATION_COUNT'] == observation['ALIAS_COUNT'] == observation['ID_COUNT'] == 0,
                        'APPLICATION_ALREADY_EXISTS_NO_REPLAY')
            if phase == 'schema':
                require(observation['OBJECT_COUNT'] == 0, 'SCHEMA_NOT_EMPTY_NO_REPLAY')
            if phase == 'verify':
                require(all(observation[key] == 1 for key in ('APPLICATION_COUNT', 'ALIAS_COUNT', 'ID_COUNT', 'EXACT_APP_COUNT')),
                        'IMPORTED_APPLICATION_IDENTITY_MISMATCH')
        _retain(store, 'plan.json', plan_raw)
        _retain(store, 'package.zip', package_raw)
        _retain(store, 'native-form-spec.json', native_raw)
        credentials = _credentials(store, plan['target']['workspace'], create=phase == 'allocate')
        started = utc_now()
        store.create(phase + '.intent.json', c.canonical_bytes(_phase_record(plan, phase, 'intent', started)))
        try:
            # Fresh VM/cloud/version observation immediately before dispatch.
            driver.scope(plan)
            require(driver.versions(admin_password) == versions, 'PRE_DISPATCH_VERSION_CHANGED')
            fresh = driver.observe(plan, admin_password, allocation)
            if phase == 'allocate':
                assert_absent(fresh)
                ids = driver.allocate(plan, admin_password, credentials)
                evidence = _make_allocation(plan, ids, versions)
                post = driver.observe(plan, admin_password, evidence)
                assert_isolated(post, evidence)
                require(post['OBJECT_COUNT'] == post['APPLICATION_COUNT'] == post['ALIAS_COUNT'] == post['ID_COUNT'] == 0,
                        'ALLOCATED_TARGET_NOT_EMPTY')
            else:
                assert_isolated(fresh, allocation)
                password = credentials['schema_password']
                if phase == 'schema':
                    require(fresh['OBJECT_COUNT'] == fresh['APPLICATION_COUNT'] == fresh['ALIAS_COUNT'] == fresh['ID_COUNT'] == 0,
                            'SCHEMA_PRE_DISPATCH_NOT_EMPTY')
                    driver.schema(plan, allocation, package, password)
                    evidence = {'passed': True, 'table_metadata': driver.table(plan, allocation, package, password),
                                'plan_sha256': plan_hash, 'schema_script_sha256': plan['binding']['schema_script_sha256']}
                elif phase == 'import':
                    require(fresh['APPLICATION_COUNT'] == fresh['ALIAS_COUNT'] == fresh['ID_COUNT'] == 0,
                            'IMPORT_PRE_DISPATCH_ID_OCCUPIED')
                    driver.table(plan, allocation, package, password)
                    driver.import_application(plan, allocation, package, password)
                    post = driver.observe(plan, admin_password, allocation)
                    assert_isolated(post, allocation)
                    require(all(post[key] == 1 for key in ('APPLICATION_COUNT', 'ALIAS_COUNT', 'ID_COUNT', 'EXACT_APP_COUNT')),
                            'IMPORT_POSTCONDITION_FAILED')
                    evidence = {'passed': True, 'plan_sha256': plan_hash, 'application_id': allocation['target']['application_id'],
                                'application_alias': plan['target']['application_alias'], 'sql_sha256': plan['binding']['sql_sha256']}
                else:
                    require(all(fresh[key] == 1 for key in ('APPLICATION_COUNT', 'ALIAS_COUNT', 'ID_COUNT', 'EXACT_APP_COUNT')),
                            'VERIFY_APPLICATION_IDENTITY_MISMATCH')
                    table = driver.table(plan, allocation, package, password)
                    actual = driver.export(plan, allocation, password)
                    compiled = verify_compiled(package['application_sql'], actual, allocation)
                    profile_raw = c.canonical_bytes(c.make_verification_profile(plan, allocation_raw))
                    _retain(store, 'verification-profile.json', profile_raw)
                    _retain(store, 'compiled-application.sql', actual)
                    evidence = _clean_receipt(plan, allocation, allocation_raw, profile_raw, versions, table, compiled, started)
            evidence_raw = c.canonical_bytes(evidence)
            store.create(phase + '.evidence.json', evidence_raw)
            store.create(phase + '.complete.json', c.canonical_bytes(_phase_record(plan, phase, 'complete', started, evidence_raw)))
        except Exception as exc:
            # Do not persist exception text: it may contain SQL, credentials or
            # subprocess input. The original intent remains immutable evidence.
            try:
                store.create(phase + '.attention.json', c.canonical_bytes(_phase_record(plan, phase, 'attention', started)))
            except Exception:
                pass
            raise RemoteError('PHASE_UNCONFIRMED_NO_REPLAY',
                              diagnostics=exc.diagnostics if type(exc) is RemoteError else None) from None
        result['phases'][phase] = 'complete'
        result['state'] = 'QA_READY' if phase == 'verify' else 'PHASE_COMPLETE'
        result['action'] = 'COMPLETED_ONCE'
        result['evidence_sha256'] = c.digest(evidence_raw)
        result['evidence_file'] = store.path + '/' + phase + '.evidence.json'
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
