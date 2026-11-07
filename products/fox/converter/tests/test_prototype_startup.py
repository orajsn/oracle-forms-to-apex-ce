"""Opt-in startup is configuration only; no runtime proof impersonation."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from forms2apex.prototype_startup import build_prototype_gateway, configured_prototype_gateway


SETTINGS = SimpleNamespace(bearer_token='synthetic-test-converter-token')
URL = 'https://fox.example.test/api/internal/prototype/authorize'
ORIGIN = 'https://fox.example.test'


def test_disabled_startup_preserves_existing_routes():
    assert configured_prototype_gateway(SETTINGS, environ={}) is None
    assert configured_prototype_gateway(SETTINGS, environ={'FOX_PROTOTYPE_AUTHORITY_ENABLED': '0'}) is None


def test_explicit_startup_without_browser_is_not_runtime_or_export_ready():
    gateway = build_prototype_gateway(SETTINGS, authority_url=URL, authority_origin=ORIGIN)
    assert [s for s in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export') if gateway.supports(s)] == [
        'validate', 'prepare_schema', 'import']
    assert gateway.runtime_verifier is None


def test_runtime_callback_requires_explicit_injected_callable():
    def synthetic_runtime(*args): raise AssertionError('Synthetic test dependency must not be called at startup')
    gateway = build_prototype_gateway(SETTINGS, authority_url=URL, authority_origin=ORIGIN,
                                      runtime_verifier=synthetic_runtime)
    assert gateway.supports('verify_runtime') and gateway.supports('export')
    assert gateway.runtime_verifier is synthetic_runtime
    with pytest.raises(ValueError):
        build_prototype_gateway(SETTINGS, authority_url=URL, authority_origin=ORIGIN, runtime_verifier=True)


@pytest.mark.parametrize('env', [
    {'FOX_PROTOTYPE_AUTHORITY_ENABLED': 'true'},
    {'FOX_PROTOTYPE_AUTHORITY_ENABLED': '1'},
    {'FOX_PROTOTYPE_AUTHORITY_ENABLED': '1', 'FOX_PROTOTYPE_AUTHORITY_URL': URL},
])
def test_enabled_missing_or_ambiguous_startup_config_fails_closed(env):
    with pytest.raises(ValueError): configured_prototype_gateway(SETTINGS, environ=env)


def test_enabled_uses_only_trusted_startup_environment():
    gateway = configured_prototype_gateway(SETTINGS, environ={'FOX_PROTOTYPE_AUTHORITY_ENABLED': '1',
        'FOX_PROTOTYPE_AUTHORITY_URL': URL, 'FOX_PROTOTYPE_AUTHORITY_ORIGIN': ORIGIN})
    assert gateway.authorize.origin == ORIGIN and gateway.runtime_verifier is None


def test_filesystem_runtime_requires_explicit_opt_in_and_measured_worker(tmp_path):
    settings = SimpleNamespace(bearer_token=SETTINGS.bearer_token, jobs_root=tmp_path)
    env = {'FOX_PROTOTYPE_AUTHORITY_ENABLED': '1', 'FOX_PROTOTYPE_AUTHORITY_URL': URL,
           'FOX_PROTOTYPE_AUTHORITY_ORIGIN': ORIGIN, 'FOX_PROTOTYPE_RUNTIME_BRIDGE_ENABLED': '1'}
    with pytest.raises(RuntimeError, match='WORKER_IDENTITY_REQUIRED'):
        configured_prototype_gateway(settings, environ=env)
    env['FOX_PROTOTYPE_RUNTIME_WORKER_SHA256'] = 'a'*64
    gateway = configured_prototype_gateway(settings, environ=env)
    assert gateway.supports('verify_runtime') and gateway.supports('export')
    assert gateway.runtime_verifier.expected_worker_sha256 == 'a'*64
    with pytest.raises(ValueError, match='one explicit'):
        configured_prototype_gateway(settings, environ=env, runtime_verifier=lambda *a, **kw: None)


def test_server_still_exposes_exactly_five_mcp_tools():
    path = Path(__file__).resolve().parents[1] / 'forms2apex' / 'server.py'
    module = ast.parse(path.read_text())
    tools = [node.name for node in module.body if isinstance(node, ast.FunctionDef)
             and any(isinstance(dec, ast.Attribute) and dec.attr == 'tool' for dec in node.decorator_list)]
    assert tools == ['inspect_forms_job', 'generate_apex_draft', 'validate_apex_draft',
                     'import_validated_draft', 'get_job_status']
