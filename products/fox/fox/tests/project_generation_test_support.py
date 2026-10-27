"""Real local project generation with synthetic provider/transport boundaries.

The source planner, checkpoint writer, converter review seals, deterministic
renderer and status readers are production code. No positive validator is
patched. This in-process transport does not claim HTTP gateway coverage. It
stops before SQLcl validation, schema work or import.
"""
from copy import deepcopy
import json
from pathlib import Path

from fox import native_project_pipeline as pipeline
from fox.opaf import OpafError, canonical_hash


class GeneratedProject:
    def __init__(self, base, jobs, monkeypatch, version):
        root = Path(__file__).resolve().parents[2]
        monkeypatch.syspath_prepend(str(root / 'converter'))
        monkeypatch.syspath_prepend(str(root / 'converter/tests'))
        from forms2apex import project_reviews
        from forms2apex.workflow_router import capabilities
        from test_project_workflow import snapshot, workflow
        if version == 2:
            from mapped_project_test_support import register_mapped_test_profile
            from test_project_source import mapped_snapshot
            register_mapped_test_profile(base, monkeypatch)
            snapshot = mapped_snapshot
        self.snapshot, self.plan = snapshot()
        self.snapshot['approvals'] = dict.fromkeys(
            ('redacted_source', 'external_ai', 'synthetic_prototype'), True)
        self.job = jobs / ('fox-' + 'a' * 20)
        self.job.mkdir()
        self.write(self.job / 'source-snapshot.json', self.snapshot)
        self.workflow, target = workflow(base)
        self.converter_root = self.workflow.settings.jobs_root / self.job.name
        opaf = target['opaf']
        profile = {'schema_version': 1, 'profile_id': 'native-table-form-v1',
            'opaf_base_url': opaf['base_url'], 'certificate_sha256': opaf['certificate_sha256'],
            **{role: opaf['roles'][role] for role in ('mapper', 'reviewer')}}
        if version == 2:
            profile.update(schema_version=2, profile_id=pipeline.PROFILE_ID,
                           **pipeline.PROJECT_MAPPING_CAPABILITY)
        profile_path = base / 'executor-profile.json'
        credentials = base / 'synthetic-credentials.json'
        self.write(profile_path, profile)
        self.write(credentials, {'username': 'synthetic-user', 'password': 'NOT-A-REAL-PASSWORD',
                                 'converter_token': 'x' * 48})
        monkeypatch.setenv('FOX_NATIVE_PROFILE_FILE', str(profile_path))
        monkeypatch.setenv('FOX_OPAF_CREDENTIAL_FILE', str(credentials))
        monkeypatch.setenv('FOX_CONVERTER_URL', 'http://127.0.0.1:8091')
        temporary_directory = pipeline.tempfile.TemporaryDirectory
        monkeypatch.setattr(pipeline.tempfile, 'TemporaryDirectory',
                            lambda **kwargs: temporary_directory(dir=base, **kwargs))
        self.model_calls, self.actions = [], []
        harness = self

        class Provider:
            def __init__(self, *args):
                pass

            def invoke_with_environment(self, role, request, *, role_name, target_profile):
                harness.model_calls.append((role_name, deepcopy(request)))
                if role_name == 'mapper':
                    output = {'job_id': request['job_id'], 'template_id': 'sqlcl-26.1.2-fox-native-v1',
                        'data_classification': 'synthetic_or_stub_only', 'generator': {'model': role['model']},
                        'native_form': request['native_form'], 'remediation_items': [],
                        'mapping_summary': 'Synthetic source-bound fixture; no business equivalence claim.'}
                else:
                    output = {'verdict': 'approve', 'candidate_sha256': canonical_hash(request['candidate']),
                        'notes': ['Synthetic independent provider response'], 'blocking_findings': []}
                second = 0 if role_name == 'mapper' else 2
                invocation = {**role, 'room_id': request['job_id'] + ':' + role_name,
                    'request_sha256': canonical_hash(request), 'response_sha256': canonical_hash(output),
                    'started_at_utc': f'2026-10-25T00:00:0{second}Z',
                    'completed_at_utc': f'2026-10-25T00:00:0{second + 1}Z'}
                environment = {'schema_version': 1, 'scope': 'opaf-model-environment-v1',
                    'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
                    'job_id': request['job_id'], 'role': role_name, 'source_manifest_sha256': request['source_hash'],
                    'target_profile_sha256': canonical_hash(target_profile), 'observed_at_utc': invocation['started_at_utc'],
                    'opaf': {key: target_profile['opaf'][key] for key in
                             ('base_url', 'certificate_sha256', 'model_authentication', 'version_number', 'build_id')},
                    'workflow': {**role, 'published': True}, 'opaf_version': target_profile['tested_versions']['opaf']}
                return deepcopy(output), invocation, environment

        class Gateway:
            def __init__(self, *args):
                pass

            def request(self, method, path, payload=None, binary=False):
                harness.actions.append((method, path))
                base_path = '/fox/jobs/' + harness.job.name
                if path == '/fox/capabilities':
                    return capabilities(target)
                if path == '/fox/target-profile':
                    return {'target_profile': target, 'target_profile_sha256': canonical_hash(target)}
                if path == base_path:
                    if method == 'POST':
                        return project_reviews.stage_project_snapshot(harness.workflow.settings.jobs_root,
                                                                     harness.job.name, payload)
                    if not harness.converter_root.exists():
                        raise OpafError('Synthetic missing converter job', 404)
                    return {**harness.workflow.status(harness.job.name),
                        'source_manifest_sha256': harness.snapshot['source_hash'],
                        'conversion_profile': pipeline.PROFILE_ID, 'native_project': harness.snapshot['native_project']}
                if path == base_path + '/actions/inspect':
                    return harness.workflow.inspect(harness.job.name)
                if path.startswith(base_path + '/reviews/'):
                    receipt = project_reviews.record_project_form_review(harness.converter_root,
                        path.rsplit('/', 1)[1], payload, *harness.workflow.review_identity(), target_profile=target)
                    return {'verdict': receipt['review']['verdict'], 'candidate_sha256': receipt['candidate_sha256'],
                            'receipt_sha256': receipt['receipt_sha256']}
                if path == base_path + '/review':
                    return project_reviews.aggregate_project_review(harness.converter_root, payload,
                                                                    *harness.workflow.review_identity())
                if path == base_path + '/actions/generate':
                    return harness.workflow.generate(harness.job.name, json.dumps(payload))
                if path == base_path + '/actions/validate':
                    raise OpafError('Synthetic disconnected external transport')
                raise AssertionError('No target or post-generation operation is allowed')

        monkeypatch.setattr(pipeline, 'OpafClient', Provider)
        monkeypatch.setattr(pipeline, 'ConverterClient', Gateway)

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value), encoding='utf-8')

    @property
    def checkpoints(self):
        return self.job / 'native-project-pipeline'

    def run(self):
        return pipeline.run_native_project_job(self.job)
