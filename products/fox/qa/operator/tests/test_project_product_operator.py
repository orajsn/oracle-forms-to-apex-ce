"""Offline project routing/queue tests; synthetic boundaries are not live QA."""
import ast
import base64
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from qa.operator import contracts as C, product_verifier as p, product_queue_transport as bridge
from qa.operator import project_operator as route, project_clean_install as clean
from qa.operator import project_qa_dispatch as qa, promote_project as promote
from fox import technical_release
from fox.verification_queue import VerificationBinding, VerificationQueue
from qa.operator.tests import test_product_verifier as native_tests
from qa.operator.tests.test_project_clean_install import fixture, TIME, CODE
from test_project_clean_operator import case, project_job


def project_part():
    return {**{key: CODE for key in bridge.PROJECT_HASHES},
            'modules': {name: 'a' * 64 for name in bridge.PROJECT_MODULES},
            'queue_modules': {name: 'a' * 64 for name in bridge.PROJECT_QUEUE_MODULES}}


def manifest():
    value = {'schema_version': 2, 'scope': bridge.PROJECT_SCOPE, 'enabled': True,
             'images': {'fox': native_tests.FUTURE, 'converter': p.clean.IMAGE},
             'modules': {name: 'a' * 64 for name in bridge.MODULES},
             'code': {name: 'a' * 64 for name in bridge.CODE},
             'clean_operator_code_sha256': 'a' * 64, 'qa_source_sha256': 'a' * 64,
             'promotion_transport_sha256': 'a' * 64, 'native_profile_sha256': 'a' * 64,
             'target': dict(C.FIXED_TARGET), 'project': project_part()}
    return bridge.validate_release(value)


def bound(plan):
    return VerificationBinding(plan['binding']['job_id'], plan['binding']['source_manifest_sha256'],
                               plan['binding']['package_sha256'], 'e' * 64)


def test_v2_release_is_closed_copied_and_does_not_reinterpret_v1():
    value = manifest()
    copied = bridge.validate_release(value)
    copied['project']['modules']['intake.py'] = '0' * 64
    assert value['project']['modules']['intake.py'] == 'a' * 64
    for change in (lambda v: v['project'].pop('operator_code_sha256'),
                   lambda v: v['project']['modules'].pop('project_qa_plan.py'),
                   lambda v: v['project']['queue_modules'].update(unknown='a' * 64),
                   lambda v: v['project']['modules'].update(native_verification_policy='a' * 64),
                   lambda v: v['project']['modules'].update({'native_verification.py': 'b' * 64}),
                   lambda v: v.update(schema_version=1, scope=bridge.SCOPE)):
        altered = deepcopy(value); change(altered)
        with pytest.raises(bridge.QueueTransportError):
            bridge.validate_release(altered)
    value.pop('project'); value.update(schema_version=1, scope=bridge.SCOPE)
    assert bridge.validate_release(value) == value


def test_v2_manifest_requires_explicit_config_and_binds_real_local_sources():
    config = {**p.read_config(), 'schema_version': 2, 'scope': 'fox-product-verifier-operator-config-v2'}
    value = p.build_manifest(config)
    assert value['schema_version'] == 2 and value['enabled'] is False
    assert value['project']['operator_code_sha256'] == C.digest(Path(route.__file__).read_bytes())
    assert value['project']['modules'] == promote.module_hashes()
    assert p.build_manifest()['schema_version'] == 1
    with patch.object(p.clean, 'oci_scope') as external, pytest.raises(bridge.QueueTransportError):
        bridge.require_ready(value, bridge.release_sha256(value))
    external.assert_not_called()


def test_exact_source_package_selection_uses_real_project_validator(case, monkeypatch):
    plan, package, raw = case
    observed = plan['source_origin']
    def read_scope(*, require_database_available):
        assert require_database_available is False
        return {'fixture': True}
    monkeypatch.setattr(clean, 'oci_scope', read_scope)
    ssh = Mock(return_value={'source_attestation': observed, 'package_b64': base64.b64encode(raw).decode()})
    monkeypatch.setattr(clean, 'ssh_json', ssh)
    monkeypatch.setattr(clean, 'now', lambda: C._timestamp(observed['observed_at_utc']))
    with patch.object(route.native_clean, 'validate_native_package') as native:
        assert route.select_profile(bound(plan)) == route.PROFILE
    native.assert_not_called()
    assert ssh.call_count == 1
    assert ssh.call_args.args[0] == clean.SOURCE_HOST
    assert 'admin_password' not in ssh.call_args.args[1]


def test_profile_selection_requires_typed_binding_before_external_read():
    with patch.object(clean, 'oci_scope') as scope, patch.object(clean, 'ssh_json') as ssh, \
         pytest.raises(clean.OperatorError):
        route.select_profile(None)
    scope.assert_not_called(); ssh.assert_not_called()


@pytest.mark.parametrize('change', [
    {'run_state': 'VERIFIED'}, {'source_manifest_sha256': '0' * 64},
    {'observed_at_utc': '2020-01-01T00:00:00Z'}, {'package_bytes': 1}])
def test_source_route_refuses_changed_attestation_before_validation(change):
    plan, package, raw = fixture()
    response = {'source_attestation': {**plan['source_origin'], **change},
                'package_b64': base64.b64encode(raw).decode()}
    with patch.object(clean, 'oci_scope'), patch.object(clean, 'ssh_json', return_value=response), \
         patch.object(clean, 'now', return_value=datetime.fromisoformat(TIME)), \
         patch.object(route.contracts, 'load_package') as project, \
         patch.object(route.native_clean, 'validate_native_package') as native, \
         pytest.raises(clean.OperatorError):
        route.select_profile(bound(plan))
    project.assert_not_called(); native.assert_not_called()


def test_unsupported_or_conflicting_package_never_falls_back():
    plan, _, raw = fixture()
    response = {'source_attestation': plan['source_origin'], 'package_b64': base64.b64encode(raw).decode()}
    for kinds in ({'project', 'native'}, {'legacy'}, set()):
        with patch.object(clean, 'oci_scope'), patch.object(clean, 'ssh_json', return_value=response), \
             patch.object(clean, 'now', return_value=datetime.fromisoformat(TIME)), \
             patch.object(technical_release, '_package_identity', side_effect=lambda raw, output: output.update(kinds)), \
             patch.object(route.contracts, 'load_package') as project, \
             patch.object(route.native_clean, 'validate_native_package') as native, \
             pytest.raises(clean.OperatorError):
            route.select_profile(bound(plan))
        project.assert_not_called(); native.assert_not_called()


def test_project_prepare_selects_once_and_never_uses_native_after_failure():
    plan, _, _ = fixture(); raw = C.canonical_bytes(plan); digest = C.digest(raw)
    native = Mock()
    with patch.object(route, 'select_profile', return_value=route.PROFILE) as selected, \
         patch.object(clean, 'prepare', return_value={'plan_path': '/fixture/plan.json', 'plan_sha256': digest}), \
         patch.object(clean, 'read_plan', return_value=(raw, plan)):
        result = route.perform('prepare', bound(plan), {}, manifest(), native)
        assert result['conversion_profile'] == route.PROFILE
        assert p.safe_phase('prepare', result, bound(plan), {}, manifest()) == result
        selected.assert_called_once()
    with patch.object(route, 'select_profile', return_value=route.PROFILE), \
         patch.object(clean, 'prepare', side_effect=RuntimeError('uncertain')), pytest.raises(RuntimeError):
        route.perform('prepare', bound(plan), {}, manifest(), native)
    native.assert_not_called()


def test_native_v2_route_preserves_existing_phase_implementation():
    native = Mock(return_value={'retained': 'native'})
    with patch.object(route, 'select_profile', return_value=route.NATIVE_PROFILE):
        assert route.perform('prepare', None, {}, manifest(), native) == {
            'retained': 'native', 'conversion_profile': route.NATIVE_PROFILE}
    assert route.perform('qa_run', None, {'conversion_profile': route.NATIVE_PROFILE}, manifest(), native) == {'retained': 'native'}
    assert native.call_count == 2


def test_project_clean_and_qa_phase_bindings_remain_closed():
    plan, _, _ = fixture(); binding = bound(plan); value = manifest()
    context = {'conversion_profile': route.PROFILE, 'plan_sha256': 'c' * 64, 'image_id': native_tests.FUTURE}
    path = clean.PRIVATE / context['plan_sha256'] / 'plan.json'
    for step in ('allocate', 'schema', 'import', 'verify'):
        response = {'state': 'QA_READY' if step == 'verify' else 'PHASE_COMPLETE',
                    'action': 'COMPLETED_ONCE', 'plan_sha256': context['plan_sha256'],
                    'evidence_sha256': 'd' * 64, 'private_output': 'must-not-project'}
        with patch.object(clean, 'dispatch', return_value=response) as dispatch:
            result = route.perform(step, binding, context, value, Mock())
        dispatch.assert_called_once_with('apply', path, expected_sha=context['plan_sha256'], phase=step, apply=True)
        assert p.safe_phase(step, result, binding, context, value) == result
        assert 'private_output' not in result
    for step, status in (('qa_stage', 'STAGED'), ('qa_run', 'PASSED')):
        response = {'status': status, 'plan_sha256': context['plan_sha256'], 'source_sha256': CODE,
                    'image_id': native_tests.FUTURE, 'allocation_receipt_sha256': 'e' * 64, 'exit_code': 0}
        with patch.object(qa, 'dispatch', return_value=response) as dispatch:
            result = route.perform(step, binding, context, value, Mock())
        dispatch.assert_called_once_with(step[3:], path, context['plan_sha256'], CODE, apply=True)
        assert p.safe_phase(step, result, binding, context, value) == result
        with pytest.raises(p.ProductVerifierError):
            p.safe_phase(step, {**result, 'source_sha256': value['qa_source_sha256']}, binding, context, value)


def test_project_promotion_uses_exact_project_modules_and_never_accepts():
    plan, _, _ = fixture(); binding = bound(plan); value = manifest()
    context = {'conversion_profile': route.PROFILE, 'plan_sha256': 'c' * 64, 'collection_manifest_sha256': 'd' * 64}
    for step in ('promotion_check', 'promotion_apply'):
        response = {'status': 'READY_NOT_APPLIED' if step == 'promotion_check' else 'VERIFIED',
                    'job_id': binding.job_id, 'human_acceptance_recorded': False,
                    'proof_sha256': 'e' * 64, 'event_count': 1, 'proof_count': 1}
        with patch.object(promote, 'dispatch', return_value=response) as dispatch:
            result = route.perform(step, binding, context, value, Mock())
        assert dispatch.call_args.kwargs['module_sha256'] == value['project']['modules']
        assert dispatch.call_args.kwargs['apply'] is (step == 'promotion_apply')
        assert p.safe_phase(step, result, binding, context, value) == result


def test_project_results_cannot_select_native_hashes_or_unknown_profile():
    plan, _, _ = fixture(); binding = bound(plan); value = manifest()
    result = {'plan_sha256': 'c' * 64, 'job_id': binding.job_id,
              'source_manifest_sha256': binding.source_manifest_sha256, 'package_sha256': binding.package_sha256,
              'operator_code_sha256': CODE, 'conversion_profile': route.PROFILE}
    for altered in ({**result, 'operator_code_sha256': value['clean_operator_code_sha256']},
                    {**result, 'conversion_profile': 'legacy'},
                    {key: item for key, item in result.items() if key != 'conversion_profile'}):
        with pytest.raises(p.ProductVerifierError):
            p.safe_phase('prepare', altered, binding, {}, value)


def _paired_harness():
    h = native_tests.Harness()
    project = project_part()
    project['modules'] = {name: C.digest((bridge.ROOT / 'fox/fox' / name).read_bytes()) for name in bridge.PROJECT_MODULES}
    h.manifest.update(schema_version=2, scope=bridge.PROJECT_SCOPE, project=project)
    h.release = bridge.release_sha256(h.manifest)
    h.queue = VerificationQueue(h.database, enabled=True, verifier_release_sha256=h.release)
    h.journal = p.PrivateJournal(h.release)
    h.stack.enter_context(patch.object(bridge, 'project_manifest', return_value=project))
    h.stack.enter_context(patch.object(clean, 'FOX_IMAGE', native_tests.FUTURE))
    original = h.phases.perform
    def perform(step, binding, context):
        result = original(step, binding, context)
        if step == 'prepare':
            result.update(conversion_profile=route.PROFILE, operator_code_sha256=CODE)
        if 'source_sha256' in result:
            result['source_sha256'] = CODE
        return result
    h.phases.perform = perform
    return h


def test_project_pump_completes_real_queue_through_dispatcher_fixture_only():
    h = _paired_harness()
    try:
        binding = h.add_job()
        result = h.verifier().pump(apply=True)
        assert result['status'] == 'SESSION_COMPLETE'
        assert h.queue.get(binding.job_id)['state'] == 'completed'
        assert h.gate_calls == [binding.job_id]
        assert [step for step, _ in h.phases.calls] == list(p.STEPS[:-1])
        assert h.product_rows()['acceptances'] == [('existing-fixture', 'synthetic-owner', 'untouched')]
    finally:
        h.close()


def test_project_uncertain_browser_stops_and_cannot_replay_session():
    h = _paired_harness()
    try:
        binding = h.add_job(); h.phases.failures['qa_run'] = 'lost'
        result = h.verifier().pump(apply=True)
        assert result['status'] == 'ATTENTION' and h.queue.get(binding.job_id)['state'] == 'attention'
        assert [step for step, _ in h.phases.calls][-1] == 'qa_run'
        assert h.product_rows()['technical_verifications'] == []
        calls = list(h.phases.calls)
        with pytest.raises(p.ProductVerifierError):
            h.verifier().pump(apply=True)
        assert h.phases.calls == calls
    finally:
        h.close()


def test_v2_generated_bridge_is_optimization_safe_and_requires_dispatcher_closure():
    source = bridge.container_source()
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source)))
    assert "sys.modules['fox.technical_release']" in source
    assert 'FOX_UNBOUND_DEPENDENCY' in source
    assert "expected.update(request['manifest']['project']['queue_modules'])" in source
    assert source.index('for filename in expected:') < source.index('class CheckedFinder')


def _loader(bad_module=None, extra_import=False, real_sources=False):
    from contextlib import redirect_stdout
    names = set(bridge.MODULES) | set(bridge.PROJECT_MODULES) | set(bridge.PROJECT_QUEUE_MODULES)
    effect = b'\nimport builtins\nbuiltins._project_loader_effect(__name__)\n'
    modules = {name: (bridge.ROOT / 'fox/fox' / name).read_bytes() + effect if real_sources else effect for name in names}
    if not real_sources:
        modules['verification_queue.py'] += b'class VerificationQueue:\n def __init__(self,*args,**kwargs):pass\n'
    # Only the heartbeat IO boundary is replaced in the real import-closure
    # test. No database, network, subprocess or persistent contact is touched.
    modules['verification_runtime.py'] += b'\ndef operator_heartbeat(root,release):return None\n'
    if real_sources:
        modules['verification_runtime.py'] += b'import fox.project_verification_runtime\n'
    if extra_import:
        modules['verification_runtime.py'] += b'import fox.not_attested\n'
    value = manifest()
    for group, selected in ((value['modules'], bridge.MODULES),
                             (value['project']['modules'], bridge.PROJECT_MODULES),
                             (value['project']['queue_modules'], bridge.PROJECT_QUEUE_MODULES)):
        group.update({name: C.digest(modules[name]) for name in selected})
    profile = b'profile fixture'
    value['native_profile_sha256'] = C.digest(profile)
    release = bridge.release_sha256(value)
    request = {'operation': 'heartbeat', 'apply': True, 'manifest': value, 'release_sha256': release,
               'binding': None, 'claim': None, 'code': None, 'proof_sha256': None}
    if bad_module:
        modules[bad_module] += b'changed'
    effects, output = Mock(), io.StringIO()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules))
        stack.enter_context(patch.dict(os.environ, {'FOX_VERIFICATION_ENABLED': '1', 'FOX_VERIFIER_RELEASE_SHA256': release}))
        stack.enter_context(patch.object(os, 'geteuid', return_value=1000, create=True))
        stack.enter_context(patch.object(os, 'getegid', return_value=1000, create=True))
        stack.enter_context(patch('builtins._project_loader_effect', effects, create=True))
        stack.enter_context(patch.object(Path, 'resolve', lambda path, **kwargs: path))
        stack.enter_context(patch.object(Path, 'is_file', return_value=True))
        stack.enter_context(patch.object(Path, 'is_symlink', return_value=False))
        stack.enter_context(patch.object(Path, 'stat', return_value=SimpleNamespace(st_size=100)))
        stack.enter_context(patch.object(Path, 'open', lambda path, *args, **kwargs:
            io.BytesIO(profile if path.name == 'profile.json' else modules[path.name])))
        stack.enter_context(patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode()))))
        stack.enter_context(redirect_stdout(output))
        exec(compile(bridge.container_source(), '<project-loader-fixture>', 'exec', optimize=2), {})
    return json.loads(output.getvalue()), effects


def test_v2_loader_hashes_every_project_dependency_before_any_import():
    names = set(bridge.MODULES) | set(bridge.PROJECT_MODULES) | set(bridge.PROJECT_QUEUE_MODULES)
    for name in names:
        result, effects = _loader(bad_module=name)
        assert result['status'] == 'STOPPED'
        effects.assert_not_called()


def test_v2_loader_uses_checked_bytes_and_rejects_unbound_imports():
    result, effects = _loader()
    assert result['status'] == 'CONTACT_RECORDED'
    assert [call.args[0] for call in effects.call_args_list] == [
        'fox.verification_queue', 'fox.verification_runtime', 'fox.technical_release']
    result, _ = _loader(extra_import=True)
    assert result['status'] == 'STOPPED'


def test_v2_loader_actual_local_modules_have_no_unbound_startup_dependency():
    result, effects = _loader(real_sources=True)
    assert result['status'] == 'CONTACT_RECORDED'
    imported = {call.args[0] for call in effects.call_args_list}
    assert {'fox.verification_queue', 'fox.verification_runtime', 'fox.technical_release',
            'fox.verification_recovery', 'fox.native_verification', 'fox.project_verification_runtime'} <= imported


def test_v2_reconcile_reads_dispatcher_then_queue_rechecks_same_proof():
    h = _paired_harness()
    try:
        binding = h.add_job(); claim = h.queue.claim_next()
        h.publish_fixture(binding); h.queue.attention(claim)
        before = h.product_rows()
        result = bridge.container_execute({'operation': 'reconcile', 'apply': True,
            'manifest': h.manifest, 'release_sha256': h.release, 'binding': binding.payload(),
            'claim': None, 'code': None, 'proof_sha256': None},
            native_tests.q, SimpleNamespace(checked_release=h.checked_fixture),
            SimpleNamespace(), root=h.root)
        assert result['status'] == 'COMPLETED'
        assert h.gate_calls == [binding.job_id, binding.job_id]
        assert h.product_rows() == before
        assert h.phases.calls == []
    finally:
        h.close()


def test_v2_reconcile_rejects_wrong_package_before_queue_transition():
    h = _paired_harness()
    try:
        binding = h.add_job(); claim = h.queue.claim_next()
        h.publish_fixture(binding); h.queue.attention(claim)
        with pytest.raises(bridge.QueueTransportError):
            bridge.container_execute({'operation': 'reconcile', 'apply': True,
                'manifest': h.manifest, 'release_sha256': h.release, 'binding': binding.payload(),
                'claim': None, 'code': None, 'proof_sha256': None}, native_tests.q,
                SimpleNamespace(checked_release=lambda *args: {'package': b'other', 'proof': {}}),
                SimpleNamespace(), root=h.root)
        assert h.queue.get(binding.job_id)['state'] == 'attention'
        assert h.phases.calls == []
    finally:
        h.close()
