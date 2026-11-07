"""Explicit host factory for the private prototype browser worker.

No work on import, automatic retry, listener, account mutation or infrastructure
creation. The operator installs a private, measured config and existing secrets.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import urllib.request

from forms2apex.project_reviews import digest
from forms2apex.prototype_authority_client import PrototypeAuthorityClient
from forms2apex.prototype_runtime_bridge import REQUEST, MAX_JSON, object_bytes, remaining_seconds
from forms2apex.runtime_preflight import bound_target_profile
from .native_qa_remote import command
from .prototype_browser import PrototypeBrowser, PrototypeBrowserConfig, private
from .prototype_runtime_worker import PodmanNamespaceJobIO, RuntimeWorkerConfig, run_once

VM = 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
COMPARTMENT = 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
DB = 'ASZ8EQWFM8UNCA2_JSNF2APEX'
WORKSPACE = 'FORMS2APEX_POC'
ORIGIN = 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com'


def need(ok):
    if not ok:
        raise RuntimeError('PROTOTYPE_HOST_CONFIGURATION_OR_AUTHORITY_UNCONFIRMED')


def read_private(path):
    path = private(Path(path), secret=True)
    raw = path.read_bytes()
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique), hashlib.sha256(raw).hexdigest()


def observe_host(config, *, run=command):
    request = urllib.request.Request('http://169.254.169.254/opc/v2/instance/',
                                    headers={'Authorization': 'Bearer Oracle'})
    # Do not forward instance metadata through inherited proxy settings.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as response:
        metadata = json.loads(response.read(65537))
    need(metadata.get('id') == VM and metadata.get('compartmentId') == COMPARTMENT
         and metadata.get('canonicalRegionName') == 'us-ashburn-1')
    observed = run(['podman', '--remote=false', 'inspect', '--format',
                    '{{.Id}}|{{.Image}}|{{.State.Running}}', config['converter_id']])
    fields = observed.stdout.decode('ascii').strip().split('|')
    need(len(fields) == 3 and fields[0] == config['converter_id'] and fields[2] == 'true'
         and fields[1].removeprefix('sha256:') == config['converter_image'].removeprefix('sha256:'))


def observe_account(config, *, run=command):
    """SELECT only through the existing parsing-schema saved connection."""
    username = config['username']
    need(type(username) is str and re.fullmatch('[A-Z0-9_.@-]{1,100}', username) is not None)
    sql = f"""set echo off
set heading off
set feedback off
set verify off
set pagesize 0
set linesize 32767
set trimout on
set define off
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback
set transaction read only;
select 'IDENTITY='||sys_context('USERENV','DB_NAME')||'|'||user from dual;
select 'WORKSPACE='||workspace_name||'|'||schema||'|'||workspace_id from apex_workspace_schemas where workspace_name='{WORKSPACE}';
select 'ACCOUNT='||user_name||'|'||account_locked from apex_workspace_apex_users where workspace_name='{WORKSPACE}' and user_name='{username}';
rollback;
exit
"""
    result = run(['podman', '--remote=false', 'exec', '-i', config['converter_id'],
                  '/opt/sqlcl/bin/sql', '-nohistory', '-S', '-L', '-name', 'F2A_APEX'],
                 data=sql.encode(), timeout=60)
    need(not result.stderr.strip() and len(result.stdout) < 8192)
    lines = [line.strip() for line in result.stdout.decode().splitlines() if line.strip()]
    need(lines == [f'IDENTITY={DB}|{WORKSPACE}',
                   f'WORKSPACE={WORKSPACE}|{WORKSPACE}|9009446931169094',
                   f'ACCOUNT={username}|No'])
    return {'scope': 'fox-original-workspace-account-readback-v1', 'lines': lines,
            'converter_id': config['converter_id'], 'compartment_id': COMPARTMENT}


def configure():
    config_path = Path(os.environ['FOX_PROTOTYPE_HOST_CONFIG'])
    config, config_sha = read_private(config_path)
    need(type(config) is dict and set(config) == {
        'schema_version', 'scope', 'converter_id', 'converter_image', 'jobs_root',
        'staging_jobs_root', 'qa_root', 'image_id', 'credentials_file',
        'opaf_credentials_file', 'target_profile_file', 'target_profile_sha256',
        'authority_origin', 'username'})
    need(type(config['schema_version']) is int and config['schema_version'] == 1
         and config['scope'] == 'fox-prototype-host-v1')
    need(re.fullmatch('[a-f0-9]{64}', config['converter_id']) is not None)
    for key in ('converter_image', 'image_id'):
        need(re.fullmatch('sha256:[a-f0-9]{64}', config[key]) is not None)
    need(config['jobs_root'] == '/home/opc/forms2apex/outputs/jobs')
    need(type(config['username']) is str and re.fullmatch('[A-Z0-9_.@-]{1,100}', config['username']) is not None)
    need(config['credentials_file'] == '/home/opc/.config/fox-prototype-runtime/fox-demo-qa.json')
    for key in ('staging_jobs_root', 'qa_root'):
        private(Path(config[key]), directory=True)
    profile_path = private(Path(config['target_profile_file']), secret=True)
    need(hashlib.sha256(profile_path.read_bytes()).hexdigest() == config['target_profile_sha256'])
    profile = json.loads(profile_path.read_bytes())
    credentials, _ = read_private(config['opaf_credentials_file'])
    settings = SimpleNamespace(
        target_profile_path=profile_path, bearer_token=credentials['converter_token'],
        apex_workspace=WORKSPACE, apex_parsing_schema=WORKSPACE,
        sqlcl_connection_name='F2A_APEX', apex_base_url=ORIGIN+'/ords',
        generator_model=profile['opaf']['roles']['mapper']['model'],
        reviewer_model=profile['opaf']['roles']['reviewer']['model'],
        opaf_mapper_workflow_id=profile['opaf']['roles']['mapper']['workflow_id'],
        opaf_reviewer_workflow_id=profile['opaf']['roles']['reviewer']['workflow_id'])
    bound_target_profile(settings)
    authority = PrototypeAuthorityClient(settings,
        authority_url=config['authority_origin']+'/api/internal/prototype/authorize',
        authority_origin=config['authority_origin'])

    def unchanged():
        need(read_private(config_path)[1] == config_sha)
        need(hashlib.sha256(profile_path.read_bytes()).hexdigest() == config['target_profile_sha256'])
        observe_host(config)

    def authorize(request):
        unchanged()
        return authority(request)

    def credential_authorizer(request, *, credential_file):
        need(Path(credential_file) == Path(config['credentials_file']))
        authorize(request)
        observed = observe_account(config)
        secret, secret_sha = read_private(credential_file)
        need(set(secret) == {'username', 'password'} and secret['username'] == config['username']
             and type(secret['password']) is str and 0 < len(secret['password']) <= 1024)
        return {'schema_version': 1, 'scope': 'fox-prototype-runtime-credentials-target-v1',
                'workspace': WORKSPACE, 'db_name': DB, 'ords_origin': ORIGIN,
                'credentials_sha256': secret_sha,
                'username_sha256': hashlib.sha256(config['username'].lower().encode()).hexdigest(),
                'authorization_reference_sha256': digest(observed)}

    browser = PrototypeBrowser(PrototypeBrowserConfig(
        jobs_root=Path(config['staging_jobs_root']), qa_root=Path(config['qa_root']),
        image_id=config['image_id'], credentials_file=Path(config['credentials_file']),
        owner_uid=os.getuid(), owner_gid=os.getgid()), credential_authorizer=credential_authorizer)
    unchanged()
    return RuntimeWorkerConfig(PodmanNamespaceJobIO(config['jobs_root']),
        Path(config['staging_jobs_root']), browser, authorize)


def poll_once():
    """A trusted timer may call this; unknown claims are never rediscovered."""
    config = configure()
    jobs = config.io.pending(limit=100)
    expired = 0
    for job in jobs:
        try:
            remaining_seconds(object_bytes(config.io.read(job, REQUEST, MAX_JSON)))
        except RuntimeError as exc:
            if str(exc) != 'PROTOTYPE_BRIDGE_EXPIRED_UNKNOWN_NO_REPLAY':
                raise
            expired += 1  # Preserve evidence, no claim, mutation or browser call.
            continue
        # run_once exclusively claims before any browser activity. No retry here.
        result = run_once(config, job)
        return {'status': result['state'], 'job_id': job}
    return {'status': 'IDLE_EXPIRED_REQUESTS_RETAINED' if expired else 'IDLE'}


if __name__ == '__main__':
    try:
        print(json.dumps(poll_once()))
    except Exception:
        raise SystemExit('PROTOTYPE_HOST_WORKER_UNCONFIRMED_NO_REPLAY') from None
