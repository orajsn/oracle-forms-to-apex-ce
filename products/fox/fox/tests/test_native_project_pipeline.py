"""Local synthetic transports only: no model, credential or target access."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest

from fox import native_project_pipeline as pipeline
from fox.intake import checked_source, inventory
from fox.opaf import OpafError, canonical_hash
from fox.project_conversion import assess_project_conversion, module_execution_binding
from fox.project_progress import (FILENAME, MAX_PROGRESS_BYTES, FORM_MESSAGES, ProjectProgress,
                                  read_project_progress)
from test_project_qa_plan import trace_for


def write(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def package(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, raw in members.items():
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            archive.writestr(info, raw)
        # The immutable-package resume test must not depend on whether its
        # two requests cross the ZIP format's two-second timestamp boundary.
        archive.writestr(zipfile.ZipInfo('manifest.json', (2026, 1, 1, 0, 0, 0)),
                         json.dumps({name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()}))
    return output.getvalue()


class Harness:
    def __init__(self, tmp_path, monkeypatch):
        self.job = tmp_path / ('fox-' + 'a' * 20); self.job.mkdir()
        fixture = Path(__file__).parent / 'fixtures'
        xml = (fixture / 'native-beta.xml').read_text()
        files = [checked_source('first.xml', xml.encode()),
                 checked_source('second.xml', xml.replace('FOX_NATIVE_BETA_SYNTHETIC', 'SECOND_FORM').encode()),
                 checked_source('schema.sql', (fixture / 'native-beta.sql').read_bytes())]
        self.plan = assess_project_conversion(files, project_id='test-project', project_name='Synthetic project',
                                             source_hash=inventory(files)['source_hash'])
        assert self.plan['state'] == 'READY'
        self.snapshot = {'files': files, 'source_hash': self.plan['source_hash'],
            'project_id': self.plan['project_id'], 'project_name': self.plan['project_name'],
            'plan_sha256': self.plan['plan_sha256'], 'native_project': self.plan['rendering_spec'],
            'conversion_profile': pipeline.PROFILE_ID,
            'approvals': dict.fromkeys(('redacted_source', 'external_ai', 'synthetic_prototype'), True)}
        write(self.job / 'source-snapshot.json', self.snapshot)
        self.profile = {'schema_version': 1, 'profile_id': 'native-table-form-v1',
            'opaf_base_url': 'https://localhost:8080/agentFactory', 'certificate_sha256': '1' * 64,
            'mapper': {'workflow_id': 'A' * 32, 'model': 'xai.grok-4.3', 'graph_sha256': '2' * 64},
            'reviewer': {'workflow_id': 'B' * 32, 'model': 'xai.grok-4.3', 'graph_sha256': '3' * 64}}
        self.target = json.loads((Path(__file__).resolve().parents[2] / 'deployment/target-profile.jsn.json').read_text())
        self.target['opaf'].update(base_url=self.profile['opaf_base_url'], certificate_sha256=self.profile['certificate_sha256'],
                                  roles={role: self.profile[role] for role in ('mapper', 'reviewer')})
        profile_path = tmp_path / 'profile.json'; write(profile_path, self.profile)
        credentials_path = tmp_path / 'synthetic-credentials.json'
        write(credentials_path, {'username': 'synthetic-user', 'password': 'NOT-A-REAL-PASSWORD', 'converter_token': 'x' * 48})
        monkeypatch.setenv('FOX_NATIVE_PROFILE_FILE', str(profile_path))
        monkeypatch.setenv('FOX_OPAF_CREDENTIAL_FILE', str(credentials_path))
        monkeypatch.setenv('FOX_CONVERTER_URL', 'http://127.0.0.1:8091')
        temporary_directory = pipeline.tempfile.TemporaryDirectory
        monkeypatch.setattr(pipeline.tempfile, 'TemporaryDirectory',
                            lambda **kwargs: temporary_directory(dir=tmp_path, **kwargs))
        self.actions, self.model_calls, self.receipts = [], [], {}
        self.progress_events = []
        self.state = None; self.parent = None; self.schema = None
        self.before, self.after, self.overrides = {}, {}, {}
        self.reject_module = None; self.fail_model = None
        self.capability = {'schema_version': 1, 'conversion_profiles': [pipeline.PROFILE_ID],
                           'project_protocol': pipeline.PROFILE_ID, 'schema_preparation': True}
        harness = self
        class FakeOpaf:
            def __init__(self, *args):
                pass
            def invoke_with_environment(self, role, request, *, role_name, target_profile):
                harness.model_calls.append((role_name, deepcopy(request)))
                harness.progress_events.append((role_name, harness.progress()))
                if harness.fail_model == role_name:
                    harness.fail_model = None
                    raise OpafError('synthetic uncertain model response')
                if role_name == 'mapper':
                    output = {'job_id': request['job_id'], 'template_id': 'sqlcl-26.1.2-fox-native-v1',
                        'data_classification': 'synthetic_or_stub_only', 'generator': {'model': role['model']},
                        'native_form': request['native_form'], 'remediation_items': [],
                        'mapping_summary': 'Synthetic source-bound native form.'}
                else:
                    reject = request['inventory']['project_module']['module_id'] == harness.reject_module
                    output = {'verdict': 'reject' if reject else 'approve',
                        'candidate_sha256': canonical_hash(request['candidate']), 'notes': ['Synthetic independent review'],
                        'blocking_findings': ['Needs human meaning'] if reject else []}
                invocation = {**role, 'room_id': request['job_id'] + ':' + role_name,
                    'request_sha256': canonical_hash(request), 'response_sha256': canonical_hash(output),
                    'started_at_utc': '2026-10-25T00:00:' + ('00Z' if role_name == 'mapper' else '11Z'),
                    'completed_at_utc': '2026-10-25T00:00:' + ('10Z' if role_name == 'mapper' else '20Z')}
                opaf = target_profile['opaf']
                environment = {'schema_version': 1, 'scope': 'opaf-model-environment-v1',
                    'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
                    'job_id': request['job_id'], 'role': role_name, 'source_manifest_sha256': request['source_hash'],
                    'target_profile_sha256': canonical_hash(target_profile), 'observed_at_utc': invocation['started_at_utc'],
                    'opaf': {key: opaf[key] for key in ('base_url', 'certificate_sha256', 'model_authentication', 'version_number', 'build_id')},
                    'workflow': {**role, 'published': True}, 'opaf_version': target_profile['tested_versions']['opaf']}
                return deepcopy(output), invocation, environment
        class FakeGateway:
            def __init__(self, *args):
                pass
            def request(self, method, path, payload=None, binary=False):
                return harness.request(method, path, payload, binary)
        monkeypatch.setattr(pipeline, 'OpafClient', FakeOpaf)
        monkeypatch.setattr(pipeline, 'ConverterClient', FakeGateway)

    @property
    def checkpoints(self):
        return self.job / 'native-project-pipeline'

    def run(self):
        return pipeline.run_native_project_job(self.job)

    def progress(self):
        return read_project_progress(self.job, job_id=self.job.name, source_hash=self.snapshot['source_hash'],
            plan_sha256=self.plan['plan_sha256'], module_ids=[form['module_id'] for form in self.plan['forms']])

    def identity(self):
        return {'application_id': 12345, 'application_alias': 'F2A_PROJECT_SYNTHETIC',
            'application_url': 'https://apex.example.invalid/ords/r/test/f2a_project_synthetic/',
            'artifact_binding': {'source_sha256': self.snapshot['source_hash'], 'draft_sha256': 'd' * 64,
                'job_id': self.job.name, 'template_id': pipeline.TEMPLATE_ID,
                'draft_zip_sha256': 'e' * 64, 'intake_sha256': 'f' * 64,
                'reviewed_spec_sha256': hashlib.sha256(canonical(self.parent['candidate']) + b'\n').hexdigest(),
                'project_review_sha256': hashlib.sha256(canonical(self.parent)).hexdigest(),
                'project_trace_sha256': hashlib.sha256(canonical(self.trace())).hexdigest()}}

    def trace(self):
        trace = trace_for(self.snapshot['native_project'])
        trace['human_acceptance_recorded'] = False
        for table in trace['tables']:
            spec = next(form['native_form'] for form in self.plan['forms'] if form['table_name'] == table['table_name'])
            table['schema_sql_sha256'] = hashlib.sha256(pipeline._schema_sql(spec).encode()).hexdigest()
        return trace

    def schema_raw(self):
        return canonical(self.schema) + b'\n'

    def evidence(self):
        sql = self.members_base()['sql/f12345.sql']
        return {'job_id': self.job.name, 'source_manifest_sha256': self.snapshot['source_hash'],
            'conversion_profile': pipeline.PROFILE_ID, 'reviewer_execution_verified': True,
            'review_receipt_sha256': self.parent['receipt_sha256'], 'human_acceptance_recorded': False,
            'template_id': pipeline.TEMPLATE_ID, 'application_count': 1, 'form_count': len(self.plan['forms']),
            'authenticated_runtime_passed': False, 'clean_schema_install_passed': False,
            'form_reviews': self.parent['form_reviews'], 'forms': self.trace()['forms'],
            'schema_preparation_sha256': hashlib.sha256(self.schema_raw()).hexdigest(),
            'imported_application_sha256': hashlib.sha256(canonical(self.imported())).hexdigest(),
            'export_completion_sha256': hashlib.sha256(canonical(self.completion())).hexdigest(),
            'reviewer_approved': True, 'sqlcl_valid': True, 'import_passed': True, 'runtime_smoke_passed': True,
            'package_reimport_passed': True,
            'package_reimport': {'passed': True, 'application_id': 23456,
                                'application_alias': 'F2A_PROJECT_SYNTHETIC_SQLCHECK',
                                'sql_sha256': hashlib.sha256(sql).hexdigest()}, **self.identity()}

    def members_base(self):
        return {'sql/f12345.sql': b'-- Synthetic mocked export, not runnable SQL\n' * 40,
                'apexlang/application.apx': b'// Synthetic mocked export\n',
                'schema/01_synthetic_schema.sql': pipeline._schema_sql(self.plan['forms'][0]['native_form']).encode(),
                'evidence/export-validation.log': b'Synthetic mocked validation\n'}

    def imported(self):
        return {**self.identity(), 'compiled_metadata_sha256': canonical_hash({
            name[len('apexlang/'):]: hashlib.sha256(raw).hexdigest()
            for name, raw in self.members_base().items() if name.startswith('apexlang/')})}

    def completion(self):
        members = self.members_base(); identity = self.identity()
        return {'schema_version': 1, 'job_id': self.job.name,
            'application_id': 12345, 'application_alias': identity['application_alias'],
            'artifact_binding': identity['artifact_binding'], 'apexlang_validation_passed': True,
            'imported_application_sha256': hashlib.sha256(canonical(self.imported())).hexdigest(),
            'files': {'f12345.sql': hashlib.sha256(members['sql/f12345.sql']).hexdigest(),
                identity['application_alias'].lower() + '/application.apx': hashlib.sha256(members['apexlang/application.apx']).hexdigest(),
                'apexlang-validation.log': hashlib.sha256(members['evidence/export-validation.log']).hexdigest()}}

    def members(self):
        members = self.members_base(); evidence = self.evidence()
        def add(name, value):
            members[name] = canonical(value)
        add('native-project-spec.json', self.snapshot['native_project'])
        add('evidence/project-review.json', self.parent)
        members['evidence/migration-spec.json'] = canonical(self.parent['candidate']) + b'\n'
        add('evidence/source-manifest.json', {'job_id': self.job.name,
            'source_manifest_sha256': self.snapshot['source_hash'], 'native_project': self.snapshot['native_project'],
            'files': [{'packaged_name': row['name'], 'sha256': row['sha256']} for row in self.snapshot['files']]})
        add('evidence/target-profile.json', self.target)
        for module, receipt in self.receipts.items():
            add('evidence/form-reviews/' + module + '.json', receipt)
        members['evidence/schema-preparation.json'] = self.schema_raw()
        add('source-to-apex.json', self.trace())
        add('evidence/imported-application.json', self.imported())
        add('evidence/package-reimport.json', evidence['package_reimport'])
        add('evidence/release-evidence.json', evidence)
        add('evidence/export-completion.json', self.completion())
        return members

    def request(self, method, path, payload, binary):
        base = '/fox/jobs/' + self.job.name
        action = ('capabilities' if path == '/fox/capabilities' else 'target-profile'
                  if path == '/fox/target-profile' else 'get' if path == base and method == 'GET'
                  else 'stage' if path == base else 'form-review' if '/reviews/' in path else path.rsplit('/', 1)[1])
        self.actions.append(action)
        self.progress_events.append((action, self.progress()))
        if action in self.before:
            raise self.before.pop(action)
        if action == 'capabilities':
            result = self.capability
        elif action == 'target-profile':
            result = {'target_profile': self.target, 'target_profile_sha256': canonical_hash(self.target)}
        elif action == 'get':
            if self.state is None:
                raise OpafError('synthetic missing job', 404)
            result = self.state
        elif action == 'stage':
            assert set(payload) == {'source_hash', 'files', 'conversion_profile', 'native_project', 'project_id', 'project_name', 'plan_sha256'}
            self.state = {'job_id': self.job.name, 'source_manifest_sha256': self.snapshot['source_hash'],
                'conversion_profile': pipeline.PROFILE_ID, 'native_project': self.snapshot['native_project'], 'state': 'INTAKE_READY'}
            result = self.state
        elif action == 'inspect':
            self.state['state'] = 'INSPECTED'
            shared = {'schema_version': 1, 'modules': [
                {'file': source['name'], 'sha256': source['sha256'], 'bytes': source['bytes'],
                 'readable_source': source['text']} for source in self.snapshot['files']], 'remediation_items': []}
            rows = []
            for form in self.plan['forms']:
                binding = module_execution_binding(self.plan, parent_job_id=self.job.name, module_id=form['module_id'])
                projection = {'scope': 'fox-project-module-source-projection-v1', 'module_id': form['module_id'],
                    'source_manifest_sha256': self.snapshot['source_hash'], 'sources': [
                        {'name': source['name'], 'sha256': source['sha256']} for source in self.plan['source_files']
                        if form['module_id'] in source['module_ids']]}
                rows.append({'module_id': form['module_id'], 'child_job_id': binding['child_job_id'],
                    'source_hash': self.snapshot['source_hash'], 'binding': binding,
                    'inventory': {'job_id': binding['child_job_id'], 'approved_native_form': form['native_form'],
                        'project_module': {key: form[key] for key in ('module_id', 'form_name', 'source_name', 'source_sha256')},
                        'shared_inventory_sha256': canonical_hash(shared), 'source_projection': projection,
                        'source_projection_sha256': canonical_hash(projection), 'remediation_items': []}})
            result = {'job_id': self.job.name, 'source_hash': self.snapshot['source_hash'], 'forms': rows,
                      'inspection_format': 'shared-source-inventory-v1', 'shared_inventory': shared,
                      'shared_inventory_sha256': canonical_hash(shared)}
        elif action == 'form-review':
            module = path.rsplit('/', 1)[1]
            receipt = {**payload, 'schema_version': 2, 'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
                'candidate_sha256': canonical_hash(payload['candidate']), 'intake_sha256': 'f' * 64,
                'historical_target_profile': self.target}
            receipt = {**receipt, 'receipt_sha256': canonical_hash(receipt)}
            self.receipts[module] = deepcopy(receipt)
            result = {'verdict': payload['review']['verdict'], 'candidate_sha256': receipt['candidate_sha256'], 'receipt_sha256': receipt['receipt_sha256']}
        elif action == 'review':
            assert {row['module_id'] for row in payload['form_reviews']} == set(self.receipts)
            candidate = {'job_id': self.job.name, 'template_id': pipeline.TEMPLATE_ID, 'data_classification': 'synthetic_or_stub_only',
                'generator': {'model': self.profile['mapper']['model']}, 'native_project': self.snapshot['native_project'],
                'remediation_items': [], 'mapping_summary': 'One synthetic application with two explicit forms.'}
            receipt = {'schema_version': 1, 'scope': 'fox-native-project-review-v1',
                'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation', 'job_id': self.job.name,
                'source_hash': self.snapshot['source_hash'], 'intake_sha256': 'f' * 64, 'candidate': candidate,
                'candidate_sha256': canonical_hash(candidate), 'verdict': 'approve',
                'form_reviews': [{'module_id': module, 'child_job_id': item['job_id'], 'candidate_sha256': item['candidate_sha256'],
                                 'receipt_sha256': item['receipt_sha256']} for module, item in sorted(self.receipts.items())]}
            self.parent = {**receipt, 'receipt_sha256': canonical_hash(receipt)}
            result = self.parent
        elif action == 'generate':
            assert payload == self.parent['candidate']
            self.state.update(state='DRAFTED', artifact_binding=self.identity()['artifact_binding']); result = {}
        elif action == 'validate':
            self.state.update(state='VALID', validation={'passed': True}); result = {}
        elif action == 'prepare-schema':
            assert not (self.checkpoints / 'import-intent.json').exists()
            assert self.state['state'] == 'VALID'
            binding = {'job_id': self.job.name, 'source_manifest_sha256': self.snapshot['source_hash'],
                'artifact_binding_sha256': canonical_hash(self.identity()['artifact_binding']),
                'validated_draft_sha256': 'd' * 64, 'review_receipts_sha256': canonical_hash(self.parent['form_reviews'])}
            spec = self.plan['forms'][0]['native_form']
            contract = {key: spec[key] for key in ('profile_id', 'data_mode', 'table_name')} | {
                'varchar_semantics': 'BYTE', 'columns': [{key: column[key] for key in
                    ('name', 'data_type', 'nullable', 'primary_key', 'identity', 'length') if key in column}
                    for column in spec['columns']]}
            self.schema = {'schema_version': 1, 'scope': 'fox-native-schema-preparation-v1', 'binding': binding,
                'tables': [{'table_name': 'FOX_NATIVE_BETA', 'state': 'CREATED', 'ownership_sha256': '1' * 64,
                    'bootstrap_schema_sha256': canonical_hash(contract), 'object_identity': {'object_id': '123'}}], 'all_ready': True,
                'business_behavior_verified': False, 'automatic_replay_permitted': False}
            self.schema['record_sha256'] = canonical_hash(self.schema)
            result = {'schema_version': 1, 'scope': 'fox-native-schema-preparation-result-v1', 'state': 'READY',
                'job_id': self.job.name, 'schema_plan_sha256': 'e' * 64, 'receipt_sha256': hashlib.sha256(self.schema_raw()).hexdigest(),
                'tables': self.schema['tables'], 'database_writes_this_call': 1,
                'apex_import_performed_by_operation': False, 'human_acceptance_recorded': False}
            self.state.update(schema_intent_exists=True, schema_preparation=result)
        elif action == 'reconcile-schema':
            if not self.schema:
                result = {'state': 'ATTENTION', 'ready_for_import': False}
            else:
                result = {'state': 'READY', 'ready_for_import': True, 'receipt_sha256': hashlib.sha256(self.schema_raw()).hexdigest()}
        elif action == 'import':
            assert (self.checkpoints / 'schema-prepared.json').exists()
            assert self.state['schema_preparation']['state'] == 'READY'
            self.state.update(state='IMPORTED', import_intent_exists=True, **{'import': self.identity()})
            result = self.identity()
        elif action == 'reconcile-import':
            raise OpafError('synthetic import outcome unconfirmed')
        elif action == 'release':
            result = self.evidence()
        elif action == 'package':
            assert binary
            result = package(self.members())
        else:
            pytest.fail('unexpected fake action ' + action)
        if action in self.after:
            raise self.after.pop(action)
        return deepcopy(self.overrides.get(action, result))


@pytest.fixture
def harness(tmp_path, monkeypatch):
    return Harness(tmp_path, monkeypatch)


def test_two_forms_one_application_and_schema_before_import_intent(harness):
    result = harness.run()
    assert result['application_id'] == 12345
    assert result['human_acceptance_recorded'] is False
    assert [role for role, _ in harness.model_calls] == ['mapper', 'reviewer'] * 2
    assert len({request['job_id'] for _, request in harness.model_calls}) == 2
    assert harness.actions.count('import') == 1
    assert harness.actions.index('prepare-schema') < harness.actions.index('import')
    assert (harness.job / 'apex-package.zip').is_file()
    assert json.loads((harness.job / 'release-evidence.json').read_text()) == result


def test_completed_resume_reuses_all_roles_schema_import_and_reviews(harness):
    first = harness.run(); package_before = (harness.job / 'apex-package.zip').read_bytes()
    assert harness.run() == first
    for action in ('stage', 'inspect', 'review', 'generate', 'validate', 'prepare-schema', 'import'):
        assert harness.actions.count(action) == 1
    assert harness.actions.count('form-review') == 2
    assert len(harness.model_calls) == 4
    assert (harness.job / 'apex-package.zip').read_bytes() == package_before


def test_missing_paired_capability_fails_before_any_post_or_models(harness):
    harness.capability['schema_preparation'] = False
    with pytest.raises(OpafError, match='capability'):
        harness.run()
    assert harness.actions == ['capabilities'] and not harness.model_calls


def test_one_blocked_form_prevents_all_remote_and_model_calls(harness):
    source = harness.snapshot['files'][1]
    source.update(checked_source(source['name'], source['text'].replace('<Item Name="ID"/>',
        '<Item Name="ID"/><Trigger Name="WHEN-NEW-FORM-INSTANCE" TriggerText="null;"/>').encode()))
    harness.snapshot['source_hash'] = inventory(harness.snapshot['files'])['source_hash']
    write(harness.job / 'source-snapshot.json', harness.snapshot)
    with pytest.raises(OpafError, match='whole project'):
        harness.run()
    assert not harness.actions and not harness.model_calls


def test_one_rejected_review_blocks_whole_application(harness):
    harness.reject_module = harness.plan['forms'][1]['module_id']
    with pytest.raises(OpafError, match='whole project'):
        harness.run()
    assert 'generate' not in harness.actions and 'prepare-schema' not in harness.actions and 'import' not in harness.actions


def test_uncertain_model_is_never_replayed(harness):
    harness.fail_model = 'mapper'
    with pytest.raises(OpafError, match='uncertain'):
        harness.run()
    with pytest.raises(OpafError, match='uncertain'):
        harness.run()
    assert len(harness.model_calls) == 1


def test_schema_response_lost_only_read_only_reconciliation_then_import(harness):
    harness.after['prepare-schema'] = OpafError('synthetic response lost')
    with pytest.raises(OpafError, match='lost'):
        harness.run()
    assert not (harness.checkpoints / 'import-intent.json').exists()
    assert harness.run()['application_id'] == 12345
    assert harness.actions.count('prepare-schema') == 1
    assert harness.actions.count('reconcile-schema') == 1
    assert harness.actions.count('import') == 1


def test_schema_dispatch_uncertain_never_replayed_or_imported(harness):
    harness.before['prepare-schema'] = OpafError('synthetic uncertain response')
    with pytest.raises(OpafError):
        harness.run()
    with pytest.raises(OpafError, match='reconciliation'):
        harness.run()
    assert harness.actions.count('prepare-schema') == 1
    assert harness.actions.count('reconcile-schema') == 1
    assert 'import' not in harness.actions
    assert not (harness.checkpoints / 'import-intent.json').exists()


def test_import_dispatch_uncertain_does_not_reprepare_schema(harness):
    harness.before['import'] = OpafError('synthetic uncertain response')
    with pytest.raises(OpafError):
        harness.run()
    with pytest.raises(OpafError, match='unconfirmed'):
        harness.run()
    assert harness.actions.count('import') == 1
    assert harness.actions.count('prepare-schema') == 1
    assert harness.actions.count('reconcile-import') == 1


@pytest.mark.parametrize('field', ['external_ai', 'synthetic_prototype', 'redacted_source'])
def test_missing_approval_never_contacts_converter(harness, field):
    harness.snapshot['approvals'][field] = False; write(harness.job / 'source-snapshot.json', harness.snapshot)
    with pytest.raises(OpafError, match='approvals'):
        harness.run()
    assert not harness.actions and not harness.model_calls


def test_wrong_source_bound_child_fails_before_model(harness):
    harness.after['inspect'] = OpafError('synthetic lost inspection')
    with pytest.raises(OpafError):
        harness.run()
    inspection = harness.request('POST', '/fox/jobs/' + harness.job.name + '/actions/inspect', {}, False)
    inspection['forms'][0]['child_job_id'] = 'fox-' + 'b' * 20
    harness.overrides['inspect'] = inspection
    with pytest.raises(OpafError, match='binding'):
        harness.run()
    assert not harness.model_calls


def test_configuration_helper_is_pure_and_explicitly_not_connectivity():
    env = {'FOX_CONVERSION_PROFILE': pipeline.PROFILE_ID, 'FOX_RUN_ADAPTER': 'embedded-opaf',
        'FOX_NATIVE_PROFILE_FILE': 'not-read-profile.json', 'FOX_OPAF_CREDENTIAL_FILE': 'not-read-secret.json',
        'FOX_CONVERTER_URL': 'http://127.0.0.1:8091'}
    result = pipeline.project_configuration_readiness(env)
    assert result['ready'] and result['scope'] == 'configuration_only'
    assert result['connectivity_checked'] is False and result['converter_capability_checked'] is False
    env['FOX_CONVERTER_URL'] = 'https://external.example.invalid/'
    assert not pipeline.project_configuration_readiness(env)['ready']


@pytest.mark.parametrize('member', ['evidence/form-reviews/{module}.json', 'evidence/schema-preparation.json',
                                   'source-to-apex.json', 'apexlang/application.apx'])
def test_missing_package_evidence_is_not_released(harness, member):
    harness.run()
    members = harness.members(); member = member.format(module=harness.plan['forms'][0]['module_id'])
    del members[member]
    with pytest.raises(OpafError):
        pipeline.verify_project_package(package(members), harness.evidence(), harness.snapshot['native_project'], harness.target)


def test_changed_child_receipt_is_not_hidden_by_new_zip_manifest(harness):
    harness.run(); members = harness.members()
    path = 'evidence/form-reviews/' + harness.plan['forms'][0]['module_id'] + '.json'
    receipt = json.loads(members[path]); receipt['review']['verdict'] = 'approve'; receipt['candidate']['mapping_summary'] = 'Changed'
    members[path] = json.dumps(receipt).encode()
    with pytest.raises(OpafError, match='unbound or changed'):
        pipeline.verify_project_package(package(members), harness.evidence(), harness.snapshot['native_project'], harness.target)


@pytest.mark.parametrize('member', ['evidence/schema-preparation.json', 'source-to-apex.json',
    'schema/01_synthetic_schema.sql', 'evidence/imported-application.json', 'evidence/export-completion.json'])
def test_rehashed_zip_does_not_authorize_changed_schema_trace_or_import(harness, member):
    harness.run(); members = harness.members()
    if member.endswith('.sql'):
        members[member] = b'drop table FOX_NATIVE_BETA;'
    else:
        document = json.loads(members[member])
        if member.endswith('schema-preparation.json'):
            document['tables'][0]['object_identity'] = {'object_id': '999'}
            document['record_sha256'] = canonical_hash({key: value for key, value in document.items() if key != 'record_sha256'})
        elif member == 'source-to-apex.json':
            document['forms'][0]['form_page_id'] = 901
        else:
            document['application_id'] = 98765
        members[member] = canonical(document)
    with pytest.raises(OpafError):
        pipeline.verify_project_package(package(members), harness.evidence(), harness.snapshot['native_project'], harness.target)


@pytest.mark.parametrize('action', ['generate', 'validate', 'import', 'release', 'package'])
def test_remote_completed_response_lost_is_not_replayed(harness, action):
    harness.after[action] = OpafError('synthetic response lost')
    with pytest.raises(OpafError, match='lost'):
        harness.run()
    assert harness.run()['application_id'] == 12345
    for mutation in ('stage', 'generate', 'validate', 'prepare-schema', 'import'):
        assert harness.actions.count(mutation) == 1
    assert len(harness.model_calls) == 4


def test_invalid_last_child_binding_blocks_first_model_too(harness):
    harness.after['inspect'] = OpafError('synthetic lost inspection')
    with pytest.raises(OpafError):
        harness.run()
    inspection = harness.request('POST', '/fox/jobs/' + harness.job.name + '/actions/inspect', {}, False)
    inspection['forms'][-1]['binding']['source_sha256'] = 'f' * 64
    harness.overrides['inspect'] = inspection
    with pytest.raises(OpafError, match='binding'):
        harness.run()
    assert not harness.model_calls


def test_legacy_role_checkpoint_cannot_be_upgraded_or_replayed(harness):
    harness.after['generate'] = OpafError('synthetic stop')
    with pytest.raises(OpafError):
        harness.run()
    role = harness.checkpoints / harness.plan['forms'][0]['module_id'] / 'mapper.json'
    value = json.loads(role.read_text()); del value['model_environment']; write(role, value)
    with pytest.raises(OpafError, match='environment evidence'):
        harness.run()
    assert len(harness.model_calls) == 4 and 'import' not in harness.actions


def test_form_progress_tracks_real_calls_and_parent_generation(harness):
    harness.run()
    active = [(kind, value) for kind, value in harness.progress_events if kind in {'mapper', 'reviewer'}]
    assert len(active) == 4
    first, second = [form['module_id'] for form in harness.plan['forms']]
    for index, (kind, value) in enumerate(active):
        rows = {row['module_id']: row for row in value['forms']}
        module = first if index < 2 else second
        assert rows[module]['stage'] == ('mapping' if kind == 'mapper' else 'reviewing')
        assert all(row['stage'] != 'generated' for row in rows.values())
        if index >= 2:
            assert rows[first]['stage'] == 'reviewed'
    before_render = next(value for action, value in harness.progress_events if action == 'generate')
    assert before_render['project_stage'] == 'generating'
    assert {row['stage'] for row in before_render['forms']} == {'reviewed'}
    final = harness.progress()
    assert final['project_stage'] == 'downloaded'
    assert {row['stage'] for row in final['forms']} == {'generated'}
    assert final['human_acceptance_recorded'] is False and final['authorization_scope'] == 'advisory_only'


def test_partial_form_failure_preserves_reviewed_not_generated_and_static_text(harness):
    harness.reject_module = harness.plan['forms'][1]['module_id']
    with pytest.raises(OpafError):
        harness.run()
    value = harness.progress()
    assert value['project_stage'] == 'attention'
    assert [row['stage'] for row in value['forms']] == ['reviewed', 'attention']
    assert all(row['message'] == FORM_MESSAGES[row['stage']] for row in value['forms'])
    assert 'Needs human meaning' not in (harness.job / FILENAME).read_text()
    assert not (harness.checkpoints / 'generated.json').exists()


def test_resume_rebuilds_reviewed_forms_without_trusting_advisory_document(harness):
    harness.before['generate'] = OpafError('synthetic provider secret must not appear')
    with pytest.raises(OpafError):
        harness.run()
    assert [row['stage'] for row in harness.progress()['forms']] == ['reviewed', 'reviewed']
    assert 'synthetic provider secret' not in (harness.job / FILENAME).read_text()
    forged = harness.progress()
    for row in forged['forms']:
        row.update(stage='generated', message=FORM_MESSAGES['generated'])
    write(harness.job / FILENAME, forged)
    prior_calls = len(harness.model_calls); harness.progress_events.clear()
    harness.run()
    assert len(harness.model_calls) == prior_calls
    before_render = next(value for action, value in harness.progress_events if action == 'generate')
    assert [row['stage'] for row in before_render['forms']] == ['reviewed', 'reviewed']
    assert (harness.checkpoints / 'generated.json').is_file()


def test_generated_requires_bound_artifacts_not_remote_state_alone(harness):
    harness.after['generate'] = OpafError('synthetic lost generation response')
    with pytest.raises(OpafError):
        harness.run()
    harness.state['artifact_binding']['reviewed_spec_sha256'] = '0' * 64
    with pytest.raises(OpafError, match='generation lacks'):
        harness.run()
    assert [row['stage'] for row in harness.progress()['forms']] == ['reviewed', 'reviewed']
    assert harness.progress()['project_stage'] == 'attention'
    assert not (harness.checkpoints / 'generated.json').exists()


def test_completed_parent_generation_is_recovered_after_lost_response(harness):
    harness.after['generate'] = OpafError('synthetic lost generation response')
    with pytest.raises(OpafError):
        harness.run()
    assert [row['stage'] for row in harness.progress()['forms']] == ['reviewed', 'reviewed']
    harness.run()
    assert harness.actions.count('generate') == 1
    assert [row['stage'] for row in harness.progress()['forms']] == ['generated', 'generated']


@pytest.mark.parametrize('change', ['source', 'plan', 'job', 'module', 'duplicate', 'message', 'unknown', 'future', 'oversize'])
def test_progress_reader_rejects_unbound_tampered_or_oversized_document(harness, change):
    ProjectProgress(harness.job, harness.plan)
    path = harness.job / FILENAME; value = harness.progress()
    if change == 'source': value['source_hash'] = '0' * 64
    elif change == 'plan': value['plan_sha256'] = '0' * 64
    elif change == 'job': value['job_id'] = 'fox-' + '0' * 20
    elif change == 'module': value['forms'][0]['module_id'] = 'form-' + '0' * 20
    elif change == 'duplicate': value['forms'][1]['module_id'] = value['forms'][0]['module_id']
    elif change == 'message': value['forms'][0]['message'] = 'Untrusted provider error with private content'
    elif change == 'unknown': value['forms'][0]['stage'] = 'verified'
    elif change == 'future': value['updated_at_utc'] = '2999-01-01T00:00:00Z'
    if change == 'oversize':
        path.write_bytes(b' ' * (MAX_PROGRESS_BYTES + 1))
    else:
        write(path, value)
    assert harness.progress() == {}


def test_progress_accounts_for_all_fifty_forms_with_bounded_atomic_document(tmp_path):
    job = tmp_path / ('fox-' + '1' * 20); job.mkdir()
    plan = {'source_hash': 'a' * 64, 'plan_sha256': 'b' * 64,
            'forms': [{'module_id': 'form-' + format(index, '020x')} for index in range(50)]}
    progress = ProjectProgress(job, plan)
    progress.form(plan['forms'][25]['module_id'], 'mapping')
    value = read_project_progress(job, job_id=job.name, source_hash=plan['source_hash'], plan_sha256=plan['plan_sha256'],
                                  module_ids=[form['module_id'] for form in plan['forms']])
    assert len(value['forms']) == 50 and value['forms'][25]['stage'] == 'mapping'
    assert sum(row['stage'] == 'pending' for row in value['forms']) == 49
    assert (job / FILENAME).stat().st_size < MAX_PROGRESS_BYTES
    assert not list(job.glob('.project-progress-*'))


def test_model_context_is_projected_but_full_manifest_remains_bound(harness):
    harness.run()
    for _, request in harness.model_calls:
        context = request['inventory']; module_id = context['project_module']['module_id']
        expected = {source['name'] for source in harness.plan['source_files'] if module_id in source['module_ids']}
        assert {module['file'] for module in context['modules']} == expected
        assert len(context['modules']) == 2  # this form XML + shared authoritative DDL
        assert {source['name'] for source in context['complete_source_manifest']['files']} == {'first.xml', 'second.xml', 'schema.sql'}
        assert request['source_hash'] == context['source_projection']['source_manifest_sha256'] == harness.snapshot['source_hash']
        assert context['source_projection_sha256'] == canonical_hash(context['source_projection']) != request['source_hash']
    saved = json.loads((harness.checkpoints / 'inspection.json').read_text())
    assert all('modules' not in row['inventory'] for row in saved['forms'])


@pytest.mark.parametrize('change', ['shared_hash', 'shared_bytes', 'overlay_modules', 'projection', 'projection_hash'])
def test_compact_context_tampering_blocks_every_model(harness, change):
    harness.after['inspect'] = OpafError('synthetic stop before saved inspection')
    with pytest.raises(OpafError):
        harness.run()
    value = harness.request('POST', '/fox/jobs/' + harness.job.name + '/actions/inspect', {}, False)
    row = value['forms'][-1]['inventory']
    if change == 'shared_hash': value['shared_inventory_sha256'] = 'f' * 64
    elif change == 'shared_bytes':
        value['shared_inventory']['modules'][0]['readable_source'] = 'altered'
        value['shared_inventory_sha256'] = canonical_hash(value['shared_inventory'])
    elif change == 'overlay_modules': row['modules'] = []
    elif change == 'projection':
        row['source_projection']['sources'] = []
        row['source_projection_sha256'] = canonical_hash(row['source_projection'])
    elif change == 'projection_hash': row['source_projection_sha256'] = 'f' * 64
    harness.overrides['inspect'] = value
    with pytest.raises(OpafError):
        harness.run()
    assert not harness.model_calls


def test_actual_converter_compact_inspection_matches_fox_projection(harness, tmp_path_factory):
    # Runs when the paired converter is on PYTHONPATH; no transport/SQL/model.
    reviews = pytest.importorskip('forms2apex.project_reviews')
    forms_inventory = pytest.importorskip('forms2apex.forms_inventory')
    jobs = tmp_path_factory.mktemp('ci') / 'j'; jobs.mkdir()
    snapshot = {key: harness.snapshot[key] for key in ('source_hash', 'files', 'conversion_profile',
        'native_project', 'project_id', 'project_name', 'plan_sha256')}
    reviews.stage_project_snapshot(jobs, harness.job.name, snapshot)
    root = jobs / harness.job.name
    shared = {key: value for key, value in forms_inventory.inspect_intake(root).items() if key != 'job_id'}
    inspection = {'job_id': harness.job.name, 'source_hash': harness.snapshot['source_hash'],
        'inspection_format': 'shared-source-inventory-v1', 'shared_inventory': shared,
        'shared_inventory_sha256': canonical_hash(shared), 'forms': reviews.ensure_form_intakes(root, shared)}
    rows, expanded = pipeline._project_inventories(inspection, harness.snapshot, harness.plan, harness.job.name)
    assert len(rows) == 2
    assert all(len(context['modules']) == 2 and len(context['complete_source_manifest']['files']) == 3
               for context in expanded.values())


def test_offline_resume_preserves_validated_generated_milestones(harness):
    harness.run()
    prior_calls = len(harness.model_calls)
    harness.before['capabilities'] = OpafError('synthetic offline')
    with pytest.raises(OpafError, match='offline'):
        harness.run()
    assert len(harness.model_calls) == prior_calls
    value = harness.progress()
    assert value['project_stage'] == 'attention'
    assert [row['stage'] for row in value['forms']] == ['generated', 'generated']
    assert value['human_acceptance_recorded'] is False


def test_offline_resume_preserves_reviewed_not_generated_milestones(harness):
    harness.before['generate'] = OpafError('synthetic initial stop')
    with pytest.raises(OpafError):
        harness.run()
    harness.before['capabilities'] = OpafError('synthetic offline')
    with pytest.raises(OpafError, match='offline'):
        harness.run()
    assert [row['stage'] for row in harness.progress()['forms']] == ['reviewed', 'reviewed']
    assert not (harness.checkpoints / 'generated.json').exists()


def test_offline_restore_rejects_changed_generated_receipt_without_network(harness):
    harness.run()
    path = harness.checkpoints / 'generated.json'; value = json.loads(path.read_text())
    value['candidate_sha256'] = '0' * 64; write(path, value)
    actions = len(harness.actions)
    with pytest.raises(OpafError, match='generation receipt changed'):
        harness.run()
    assert len(harness.actions) == actions
    assert [row['stage'] for row in harness.progress()['forms']] == ['reviewed', 'reviewed']


def test_twenty_form_compact_inspection_stays_bounded_and_projects_original_bytes(tmp_path_factory):
    reviews = pytest.importorskip('forms2apex.project_reviews')
    forms_inventory = pytest.importorskip('forms2apex.forms_inventory')
    fixture = Path(__file__).parent / 'fixtures'
    original = (fixture / 'native-beta.xml').read_text()
    files = [checked_source(f'form{index:02}.xml', ('<!--' + 'x' * 10_000 + '-->\n' +
             original.replace('FOX_NATIVE_BETA_SYNTHETIC', f'FORM_{index:02}')).encode()) for index in range(20)]
    files.append(checked_source('schema.sql', (fixture / 'native-beta.sql').read_bytes()))
    plan = assess_project_conversion(files, project_id='capacity-test', project_name='Synthetic capacity test',
                                     source_hash=inventory(files)['source_hash'])
    assert plan['state'] == 'READY' and sum(source['bytes'] for source in files) > 200_000
    snapshot = {'files': files, 'source_hash': plan['source_hash'], 'project_id': plan['project_id'],
        'project_name': plan['project_name'], 'plan_sha256': plan['plan_sha256'],
        'native_project': plan['rendering_spec'], 'conversion_profile': pipeline.PROFILE_ID}
    jobs = tmp_path_factory.mktemp('cp') / 'j'; jobs.mkdir(); job_id = 'fox-' + '3' * 20
    reviews.stage_project_snapshot(jobs, job_id, snapshot)
    root = jobs / job_id
    shared = {key: value for key, value in forms_inventory.inspect_intake(root).items() if key != 'job_id'}
    inspection = {'job_id': job_id, 'source_hash': plan['source_hash'],
        'inspection_format': 'shared-source-inventory-v1', 'shared_inventory': shared,
        'shared_inventory_sha256': canonical_hash(shared), 'forms': reviews.ensure_form_intakes(root, shared)}
    raw = canonical(inspection)
    assert len(raw) < 1_000_000
    rows, expanded = pipeline._project_inventories(inspection, snapshot, plan, job_id)
    assert len(rows) == len(expanded) == 20
    assert all(len(context['modules']) == 2 and len(context['complete_source_manifest']['files']) == 21
               for context in expanded.values())
    originals = {source['name']: source['text'] for source in files}
    assert all(module['readable_source'] == originals[module['file']]
               for context in expanded.values() for module in context['modules'])
