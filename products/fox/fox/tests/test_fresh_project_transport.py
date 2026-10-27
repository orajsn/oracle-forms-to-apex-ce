"""Fresh project wiring with real validators and synthetic external services.

The only real HTTP request is to an owned ephemeral loopback fixture. No
Oracle, OCI, SSH, model, SQLcl, or existing container is contacted. Generated
Harness packages establish local binding checks, not deployed correctness.
"""
from collections import UserDict
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from fox import native_project_pipeline as pipeline
from fox.opaf import ConverterClient, OpafClient, OpafError
from fox.project_progress import ProjectProgress
from test_converter_endpoint_projection import loopback_server
from test_fresh_app_projection import projection
from test_native_project_pipeline import Harness


class ProjectionSubclass(dict):
    pass


INVALID_PROJECTIONS = [
    pytest.param(None, id='explicit-none'),
    pytest.param(False, id='boolean'),
    pytest.param([], id='list'),
    pytest.param({}, id='empty-object'),
    pytest.param(UserDict(projection()), id='mapping-wrapper'),
    pytest.param(ProjectionSubclass(projection()), id='dict-subclass'),
    pytest.param(projection(schema_version=True), id='boolean-schema'),
    pytest.param(projection(installation_mode='legacy'), id='wrong-projection-mode'),
    pytest.param(projection(storage_plan_sha256='A' * 64), id='noncanonical-hash'),
    pytest.param(projection(installation_id='fst-' + '1' * 31), id='invalid-id'),
    pytest.param(projection(converter_endpoint='http://localhost:19091'), id='host-alias'),
    pytest.param(projection(converter_endpoint='http://127.0.0.1:19091/'), id='trailing-slash'),
    pytest.param(projection(ready=True), id='authority-extra'),
    pytest.param(projection(credential_file='synthetic-forbidden'), id='credential-extra'),
]

ENV_MISMATCHES = [
    pytest.param('FOX_INSTALLATION_MODE', None, id='mode-omitted'),
    pytest.param('FOX_INSTALLATION_MODE', '', id='mode-blank'),
    pytest.param('FOX_INSTALLATION_MODE', 'legacy', id='legacy-mode'),
    pytest.param('FOX_INSTALLATION_MODE', 'FRESH', id='mode-uppercase'),
    pytest.param('FOX_INSTALLATION_MODE', 'unknown', id='unknown-mode'),
    pytest.param('FOX_CONVERSION_PROFILE', None, id='profile-omitted'),
    pytest.param('FOX_CONVERSION_PROFILE', 'native-table-form-v1', id='single-form-profile'),
    pytest.param('FOX_CONVERSION_PROFILE', 'legacy-html-prototype-v1', id='legacy-profile'),
    pytest.param('FOX_RUN_ADAPTER', None, id='adapter-omitted'),
    pytest.param('FOX_RUN_ADAPTER', 'synthetic-external-adapter', id='external-adapter'),
    pytest.param('FOX_CONVERTER_URL', None, id='endpoint-omitted'),
    pytest.param('FOX_CONVERTER_URL', 'http://127.0.0.1:8091', id='legacy-endpoint'),
    pytest.param('FOX_CONVERTER_URL', 'http://127.0.0.1:19092', id='different-port'),
    pytest.param('FOX_CONVERTER_URL', 'http://127.0.0.1:19091/', id='normalized-endpoint'),
]


def forbidden(*args, **kwargs):
    pytest.fail('Unexpected secret read, external transport, or process execution.')


@pytest.fixture(autouse=True)
def offline_boundary(monkeypatch):
    """Allow only a test's explicitly registered owned loopback listener."""
    for key in tuple(os.environ):
        if key == 'FOX_INSTALLATION_MODE' or key.startswith('FOX_FRESH_'):
            monkeypatch.delenv(key, raising=False)
    allowed = set()
    connect = socket.socket.connect

    def isolated_connect(sock, address):
        if address not in allowed:
            forbidden()
        return connect(sock, address)

    monkeypatch.setattr(socket.socket, 'connect', isolated_connect)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(OpafClient, '_request', forbidden)
    return allowed


def fresh_environment(monkeypatch, value):
    for key, item in ready_environment(value).items():
        monkeypatch.setenv(key, item)


def ready_environment(value):
    return {
        'FOX_INSTALLATION_MODE': 'fresh',
        'FOX_CONVERSION_PROFILE': pipeline.PROFILE_ID,
        'FOX_RUN_ADAPTER': 'embedded-opaf',
        'FOX_NATIVE_PROFILE_FILE': 'synthetic-profile-not-read.json',
        'FOX_OPAF_CREDENTIAL_FILE': 'synthetic-credentials-not-read.json',
        'FOX_CONVERTER_URL': value['converter_endpoint'],
    }


def change_environment(monkeypatch, key, value):
    if value is None:
        monkeypatch.delenv(key, raising=False)
    else:
        monkeypatch.setenv(key, value)


def configure_harness(harness, monkeypatch, value):
    # Keep Harness's real temporary profile and synthetic credential files.
    for key, item in ready_environment(value).items():
        if key not in {'FOX_NATIVE_PROFILE_FILE', 'FOX_OPAF_CREDENTIAL_FILE'}:
            monkeypatch.setenv(key, item)
    observed = []

    class Gateway:
        def __init__(self, endpoint, token, *, projection):
            # The actual constructor validates the forwarded P and URL. Only
            # the remote request boundary is supplied by the synthetic Harness.
            ConverterClient(endpoint, token, projection=projection)
            observed.append((endpoint, deepcopy(projection)))

        def request(self, method, path, payload=None, binary=False):
            return harness.request(method, path, payload, binary)

    monkeypatch.setattr(pipeline, 'ConverterClient', Gateway)
    return observed


@pytest.mark.parametrize('value', INVALID_PROJECTIONS)
def test_configuration_rejects_explicit_invalid_projection_before_secret_reads(monkeypatch, value):
    fresh_environment(monkeypatch, projection())
    monkeypatch.setattr(pipeline, 'load_project_profile', forbidden)
    monkeypatch.setattr(Path, 'read_text', forbidden)
    monkeypatch.setattr(pipeline, 'ConverterClient', forbidden)
    monkeypatch.setattr(pipeline, 'OpafClient', forbidden)
    with pytest.raises(OpafError):
        pipeline._configuration(installation_projection=value)


@pytest.mark.parametrize('key,value', ENV_MISMATCHES)
def test_configuration_rejects_environment_mismatch_before_secret_reads(monkeypatch, key, value):
    projected = projection()
    fresh_environment(monkeypatch, projected)
    change_environment(monkeypatch, key, value)
    monkeypatch.setattr(pipeline, 'load_project_profile', forbidden)
    monkeypatch.setattr(Path, 'read_text', forbidden)
    monkeypatch.setattr(pipeline, 'ConverterClient', forbidden)
    with pytest.raises(OpafError):
        pipeline._configuration(installation_projection=projected)


@pytest.mark.parametrize('mode,extra', [
    ('fresh', None), ('', None), ('unknown', None), ('FRESH', None),
    (None, 'FOX_FRESH_PROJECTION_FILE'), ('legacy', 'FOX_FRESH_UNKNOWN'),
])
def test_omission_cannot_downgrade_fresh_or_invalid_environment(monkeypatch, mode, extra):
    fresh_environment(monkeypatch, projection())
    change_environment(monkeypatch, 'FOX_INSTALLATION_MODE', mode)
    if extra:
        monkeypatch.setenv(extra, '')  # Presence, not truthiness, is forbidden.
    monkeypatch.setattr(pipeline, 'load_project_profile', forbidden)
    with pytest.raises(OpafError):
        pipeline._configuration()


@pytest.mark.parametrize('boundary', ['entrypoint', 'project-runner'])
@pytest.mark.parametrize('value', [None, {}, projection(ready=True)])
def test_each_pipeline_boundary_rejects_bad_projection_before_configuration(
        tmp_path, monkeypatch, boundary, value):
    harness = Harness(tmp_path, monkeypatch)
    configure_harness(harness, monkeypatch, projection())
    monkeypatch.setattr(pipeline, '_configuration', forbidden)
    with pytest.raises(OpafError):
        if boundary == 'entrypoint':
            pipeline.run_native_project_job(harness.job, installation_projection=value)
        else:
            pipeline._run_project(harness.job, harness.snapshot, harness.plan,
                                  ProjectProgress(harness.job, harness.plan),
                                  installation_projection=value)
    assert harness.actions == [] and harness.model_calls == []
    assert not (harness.job / 'apex-package.zip').exists()


@pytest.mark.parametrize('boundary', ['entrypoint', 'project-runner'])
@pytest.mark.parametrize('key,value', ENV_MISMATCHES)
def test_each_pipeline_boundary_rechecks_environment_before_local_or_external_work(
        tmp_path, monkeypatch, boundary, key, value):
    harness = Harness(tmp_path, monkeypatch)
    projected = projection()
    configure_harness(harness, monkeypatch, projected)
    progress = ProjectProgress(harness.job, harness.plan)
    before = {path: path.read_bytes() for path in harness.job.rglob('*') if path.is_file()}
    change_environment(monkeypatch, key, value)
    monkeypatch.setattr(pipeline, '_json', forbidden)
    monkeypatch.setattr(pipeline, '_restore_progress', forbidden)
    monkeypatch.setattr(pipeline, '_configuration', forbidden)

    with pytest.raises(OpafError):
        if boundary == 'entrypoint':
            pipeline.run_native_project_job(harness.job, installation_projection=projected)
        else:
            pipeline._run_project(harness.job, harness.snapshot, harness.plan, progress,
                                  installation_projection=projected)

    assert harness.actions == [] and harness.model_calls == []
    assert {path: path.read_bytes() for path in harness.job.rglob('*') if path.is_file()} == before


@pytest.mark.parametrize('boundary', ['entrypoint', 'project-runner'])
def test_each_pipeline_boundary_rejects_omitted_projection_before_local_or_external_work(
        tmp_path, monkeypatch, boundary):
    harness = Harness(tmp_path, monkeypatch)
    configure_harness(harness, monkeypatch, projection())
    progress = ProjectProgress(harness.job, harness.plan)
    before = {path: path.read_bytes() for path in harness.job.rglob('*') if path.is_file()}
    monkeypatch.setattr(pipeline, '_json', forbidden)
    monkeypatch.setattr(pipeline, '_restore_progress', forbidden)
    monkeypatch.setattr(pipeline, '_configuration', forbidden)

    with pytest.raises(OpafError):
        if boundary == 'entrypoint':
            pipeline.run_native_project_job(harness.job)
        else:
            pipeline._run_project(harness.job, harness.snapshot, harness.plan, progress)

    assert harness.actions == [] and harness.model_calls == []
    assert {path: path.read_bytes() for path in harness.job.rglob('*') if path.is_file()} == before


@pytest.mark.parametrize('value', INVALID_PROJECTIONS)
def test_readiness_rejects_invalid_projection_without_io(monkeypatch, value):
    monkeypatch.setattr(Path, 'open', forbidden)
    monkeypatch.setattr(pipeline, 'load_project_profile', forbidden)
    monkeypatch.setattr(pipeline, 'ConverterClient', forbidden)
    result = pipeline.project_configuration_readiness(
        ready_environment(projection()), installation_projection=value)
    assert result['ready'] is False and result['configured'] is False
    assert result['connectivity_checked'] is False
    assert result['converter_capability_checked'] is False


@pytest.mark.parametrize('key,value', ENV_MISMATCHES)
def test_readiness_rejects_fresh_configuration_mismatch(monkeypatch, key, value):
    projected = projection()
    env = ready_environment(projected)
    if value is None:
        env.pop(key)
    else:
        env[key] = value
    monkeypatch.setattr(Path, 'open', forbidden)
    result = pipeline.project_configuration_readiness(env, installation_projection=projected)
    assert result['ready'] is False and result['configured'] is False


def test_readiness_explicit_environment_is_pure_and_independent_of_process_environment(monkeypatch):
    projected = projection()
    supplied = ready_environment(projected)
    original = deepcopy(supplied)
    monkeypatch.setattr(Path, 'open', forbidden)
    # A hostile ambient environment cannot override explicitly supplied values.
    monkeypatch.setattr(pipeline.os, 'environ', {'FOX_INSTALLATION_MODE': 'unknown',
                                             'FOX_FRESH_UNEXPECTED': 'synthetic'})
    result = pipeline.project_configuration_readiness(supplied, installation_projection=projected)
    assert result['ready'] is True and result['configured'] is True
    assert result['scope'] == 'configuration_only'
    assert result['connectivity_checked'] is False
    assert result['converter_capability_checked'] is False
    assert supplied == original
    # Missing fields in the supplied mapping cannot be filled from ambient state.
    monkeypatch.setattr(pipeline.os, 'environ', supplied)
    assert pipeline.project_configuration_readiness({}, installation_projection=projected)['ready'] is False
    legacy = {**supplied, 'FOX_CONVERTER_URL': 'http://127.0.0.1:8091'}
    del legacy['FOX_INSTALLATION_MODE']
    assert pipeline.project_configuration_readiness(legacy)['ready'] is True


def test_configuration_real_client_reaches_only_projected_owned_loopback_port(
        tmp_path, monkeypatch, offline_boundary):
    harness = Harness(tmp_path, monkeypatch)
    monkeypatch.setattr(pipeline, 'ConverterClient', ConverterClient)
    monkeypatch.setattr(pipeline, 'OpafClient', OpafClient)
    with loopback_server(body=b'{"synthetic":true}') as (endpoint, received):
        offline_boundary.add(('127.0.0.1', int(endpoint.rsplit(':', 1)[1])))
        projected = projection(converter_endpoint=endpoint)
        # Do not replace profile/credential validation or either constructor.
        for key, value in ready_environment(projected).items():
            if key not in {'FOX_NATIVE_PROFILE_FILE', 'FOX_OPAF_CREDENTIAL_FILE'}:
                monkeypatch.setenv(key, value)
        profile, gateway, client = pipeline._configuration(installation_projection=projected)
        assert profile == harness.profile and isinstance(client, OpafClient)
        projected['converter_endpoint'] = 'http://127.0.0.1:65535'
        assert gateway.request('GET', '/synthetic/project-configuration') == {'synthetic': True}
        assert len(received) == 1
        assert received[0]['path'] == '/synthetic/project-configuration'
        assert received[0]['headers']['Host'] == endpoint.removeprefix('http://')
        assert received[0]['headers']['Authorization'] == 'Bearer ' + 'x' * 48


def test_complete_project_pipeline_forwards_projection_with_real_source_and_package_validation(
        tmp_path, monkeypatch):
    harness = Harness(tmp_path, monkeypatch)
    projected = projection()
    before = deepcopy(projected)
    observed = configure_harness(harness, monkeypatch, projected)
    evidence = pipeline.run_native_project_job(harness.job, installation_projection=projected)
    assert observed == [(projected['converter_endpoint'], before)]
    assert projected == before
    assert evidence['conversion_profile'] == pipeline.PROFILE_ID
    assert evidence['application_count'] == 1 and evidence['form_count'] == 2
    assert evidence['human_acceptance_recorded'] is False
    assert [role for role, _ in harness.model_calls] == ['mapper', 'reviewer'] * 2
    assert harness.actions.count('prepare-schema') == harness.actions.count('import') == 1
    assert (harness.job / 'apex-package.zip').is_file()
    assert json.loads((harness.job / 'release-evidence.json').read_text()) == evidence


@pytest.mark.parametrize('mode', [None, 'legacy'])
def test_legacy_pipeline_omission_preserves_old_internal_call_signatures(tmp_path, monkeypatch, mode):
    harness = Harness(tmp_path, monkeypatch)
    change_environment(monkeypatch, 'FOX_INSTALLATION_MODE', mode)
    original_run, original_config = pipeline._run_project, pipeline._configuration
    calls = []

    def old_run(job, snapshot, plan, progress):
        calls.append('run')
        return original_run(job, snapshot, plan, progress)

    def old_configuration():
        calls.append('configuration')
        return original_config()

    monkeypatch.setattr(pipeline, '_run_project', old_run)
    monkeypatch.setattr(pipeline, '_configuration', old_configuration)
    # Harness's preexisting gateway constructor accepts positional args only.
    evidence = pipeline.run_native_project_job(harness.job)
    assert calls == ['run', 'configuration']
    assert evidence['conversion_profile'] == pipeline.PROFILE_ID
