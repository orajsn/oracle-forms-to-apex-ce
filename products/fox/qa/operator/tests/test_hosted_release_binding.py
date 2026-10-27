"""Offline declaration and real-POSIX hosted image/release binding tests.

The image references and offline paths below are synthetic fixture identities,
not deployment instructions or evidence of built images. Hosted admission uses
the existing real private-files fixture and actual interpreter. No test calls
OCI, SSH, Podman, SQLcl, DPAPI, a model, or any live service.
"""
from __future__ import annotations

import base64
from contextlib import redirect_stdout
from copy import deepcopy
import importlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request


ROOT = Path(__file__).resolve().parents[3]
for directory in (ROOT, ROOT / 'converter', ROOT / 'fox'):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

# Import every image consumer before configuration selection. Hosted tests
# prove that no consumer holds an import-time alias to the legacy image pins.
from forms2apex import target_profile
from qa.operator import runtime_provider as runtime
from qa.operator import clean_install as native, project_clean_install as project
from qa.operator import native_qa_dispatch as native_qa, project_qa_dispatch as project_qa
from qa.operator import product_verifier as verifier, product_queue_transport as bridge
from qa.operator import project_operator
from fox.verification_queue import VerificationBinding
from qa.operator.tests.hosted_provider_fixture import (
    canonical_bytes, configure_fixture, create_hosted_fixture, digest)


POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0
IMAGES = {'fox': 'sha256:' + 'a' * 64, 'converter': 'sha256:' + 'b' * 64}
PROFILE_PATH = 'deployment/project-opaf-profile-v2.json'


def offline_configuration():
    """Valid declaration only; paths deliberately do not name an installation."""
    profile = deepcopy(target_profile._PROFILE_JSN_PROJECT_20261025)
    names = ('forms2apex/__init__.py', 'forms2apex/config.py',
             'forms2apex/target_profile.py', 'forms2apex/oci_identity.py')
    return {'schema_version': 2, 'scope': 'fox-hosted-operator-runtime-v2',
        'owner_uid': 1000, 'provider_sha256': digest(Path(runtime.__file__).read_bytes()),
        'target_profile': profile,
        'target_profile_sha256': target_profile.target_profile_sha256(profile),
        'python': {'path': '/synthetic-only/python3.11', 'sha256': 'c' * 64,
                   'version': [3, 11, 13]},
        'converter_root': '/synthetic-only/converter',
        'converter_sources': {name: digest((ROOT / 'converter' / name).read_bytes()) for name in names},
        'state_root': '/synthetic-only/state',
        'admin_secret_file': '/synthetic-only/secret/admin',
        'public_mount_roots': ['/synthetic-only/public'], 'images': dict(IMAGES)}


def operator_configuration(configuration):
    raw = canonical_bytes(configuration)
    return {'schema_version': 3, 'scope': 'fox-product-verifier-operator-config-v3',
        'enabled': True, 'images': dict(configuration['images']),
        'hosted_runtime_configuration_sha256': digest(raw),
        'opaf_profile': {'path': PROFILE_PATH,
            'sha256': digest((ROOT / PROFILE_PATH).read_bytes()),
            'target_profile_sha256': configuration['target_profile_sha256']}}


class RuntimeDeclarationTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(runtime)
        self.addCleanup(importlib.reload, runtime)

    def test_legacy_images_are_detached_and_original_constants_stay_unchanged(self):
        expected = {'fox': native.FOX_IMAGE, 'converter': native.IMAGE}
        self.assertEqual(native.image_pins(), expected)
        self.assertEqual(project.image_pins(), expected)
        copied = runtime.image_pins(expected)
        copied['fox'] = IMAGES['fox']
        self.assertEqual(native.image_pins(), expected)
        self.assertEqual(project.FOX_IMAGE, native.FOX_IMAGE)
        self.assertEqual(project.IMAGE, native.IMAGE)
        self.assertIsNone(runtime.hosted())

    def test_image_declaration_is_exact_and_has_no_provider_selection(self):
        self.assertEqual(runtime.validated_image_pins(IMAGES), IMAGES)
        mutations = [None, {'fox': IMAGES['fox']}, {**IMAGES, 'qa': IMAGES['fox']},
            {**IMAGES, 'fox': 'fox:latest'}, {**IMAGES, 'converter': 'b' * 64},
            {**IMAGES, 'fox': 'sha256:' + 'A' * 64}, {**IMAGES, 'fox': True}]
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(runtime.ProviderError):
                runtime.validated_image_pins(value)
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_configuration_document_is_pure_and_does_not_trust_its_own_hash(self):
        value = offline_configuration()
        raw = canonical_bytes(value)
        with (patch.object(subprocess, 'run', side_effect=AssertionError('No process')),
              patch.object(runtime, '_read', side_effect=AssertionError('No private file read'))):
            actual = runtime.configuration_document(raw, expected_sha256=digest(raw))
            with self.assertRaises(runtime.ProviderError):
                runtime.configuration_document(raw, expected_sha256='0' * 64)
        self.assertEqual(actual, value)
        actual['images']['fox'] = 'changed'
        self.assertEqual(runtime.configuration_document(raw, expected_sha256=digest(raw)), value)
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_configuration_rejects_unknown_fields_and_noncanonical_bytes(self):
        value = offline_configuration()
        for mutation in (lambda x: x.update(release_sha256='d' * 64),
                         lambda x: x['images'].update(qa=IMAGES['fox']),
                         lambda x: x['python'].update(unreviewed='field'),
                         lambda x: x['converter_sources'].update(unreviewed='d' * 64),
                         lambda x: x.update(schema_version=True),
                         lambda x: x.update(scope='fox-hosted-operator-runtime-v1')):
            altered = deepcopy(value)
            mutation(altered)
            raw = canonical_bytes(altered)
            with self.subTest(altered=altered), self.assertRaises(runtime.ProviderError):
                runtime.configuration_document(raw, expected_sha256=digest(raw))
        raw = canonical_bytes(value)
        for altered in (raw.rstrip(), b' ' + raw,
                        raw.replace(b'{', b'{"schema_version":2,', 1)):
            with self.subTest(raw=altered[:30]), self.assertRaises(runtime.ProviderError):
                runtime.configuration_document(altered, expected_sha256=digest(altered))
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_runtime_v1_declaration_keeps_legacy_schema(self):
        value = offline_configuration()
        value.update(schema_version=1, scope='fox-hosted-operator-runtime-v1')
        value.pop('images')
        raw = canonical_bytes(value)
        self.assertEqual(runtime.configuration_document(raw, expected_sha256=digest(raw)), value)
        value['images'] = dict(IMAGES)
        raw = canonical_bytes(value)
        with self.assertRaises(runtime.ProviderError):
            runtime.configuration_document(raw, expected_sha256=digest(raw))

    def test_registered_target_role_graph_and_certificate_cannot_be_changed(self):
        for route in (('oci', 'region'), ('opaf', 'certificate_sha256'),
                      ('opaf', 'roles', 'mapper', 'workflow_id'),
                      ('opaf', 'roles', 'reviewer', 'graph_sha256')):
            value = offline_configuration()
            cursor = value['target_profile']
            for name in route[:-1]:
                cursor = cursor[name]
            cursor[route[-1]] = 'unreviewed'
            # Even a recomputed envelope digest is not target authorization.
            value['target_profile_sha256'] = digest(canonical_bytes(value['target_profile']))
            raw = canonical_bytes(value)
            with self.subTest(route=route), self.assertRaises(runtime.ProviderError):
                runtime.configuration_document(raw, expected_sha256=digest(raw))
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_explicit_qa_image_declaration_never_selects_runtime_or_changes_base(self):
        for module in (native_qa, project_qa):
            with self.subTest(module=module.__name__):
                descriptor = module.bundle(images=IMAGES)[2]
                self.assertEqual(descriptor['fox_image'], IMAGES['fox'])
                self.assertEqual(descriptor['converter_image'], IMAGES['converter'])
                self.assertEqual(descriptor['base_qa_image'], native_qa.BASE_QA_IMAGE)
                self.assertEqual(descriptor['base_digest'], native_qa.BASE_DIGEST)
                self.assertEqual(native_qa.BASE_QA_IMAGE,
                    'sha256:e3f7b9648271a741cf320b7ad928a17e0e1591ba66835e7420864905524eb571')
        self.assertIs(runtime._selected, runtime._UNSELECTED)


class HostedManifestDeclarationTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(runtime)
        self.addCleanup(importlib.reload, runtime)
        self.configuration = offline_configuration()
        self.raw = canonical_bytes(self.configuration)
        self.operator = operator_configuration(self.configuration)

    def build(self, operator=None, raw=None):
        return verifier.build_manifest(self.operator if operator is None else operator,
            hosted_configuration=self.raw if raw is None else raw)

    def test_v3_offline_build_binds_configuration_profile_images_and_actual_code(self):
        with (patch.object(subprocess, 'run', side_effect=AssertionError('No process')),
              patch.object(runtime, 'hosted', side_effect=AssertionError('No selection'))):
            value = self.build()
        self.assertEqual(value['schema_version'], 3)
        self.assertEqual(value['scope'], 'fox-product-verifier-release-v3')
        self.assertEqual(value['images'], IMAGES)
        self.assertEqual(value['hosted_runtime_configuration_sha256'], digest(self.raw))
        expected_profile = {**self.operator['opaf_profile'],
            'host_path': str(PurePosixPath(self.configuration['converter_root']).parent / PROFILE_PATH)}
        self.assertEqual(value['opaf_profile'], expected_profile)
        self.assertEqual(value['native_profile_sha256'], value['opaf_profile']['sha256'])
        self.assertEqual(value['qa_source_sha256'], native_qa.bundle(images=IMAGES)[3])
        self.assertEqual(value['project']['qa_source_sha256'], project_qa.bundle(images=IMAGES)[3])
        self.assertTrue({'runtime_provider.py', 'retirement_handoff.py', 'retirement_remote.py'} <= set(value['code']))
        for name, sha in value['code'].items():
            self.assertEqual(sha, digest((ROOT / 'qa/operator' / name).read_bytes()))
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_v3_operator_configuration_is_readable_without_selecting_a_provider(self):
        with tempfile.TemporaryDirectory(prefix='fox-operator-config-') as temporary:
            path = Path(temporary).resolve() / 'operator.json'
            path.write_bytes(canonical_bytes(self.operator))
            self.assertEqual(verifier.read_config(path), self.operator)
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_offline_build_does_not_grant_readiness(self):
        manifest = self.build()
        with (patch.object(subprocess, 'run', side_effect=AssertionError('No process')),
              patch.object(native, 'oci_scope', side_effect=AssertionError('No OCI')),
              self.assertRaises(bridge.QueueTransportError)):
            bridge.require_ready(manifest, bridge.release_sha256(manifest))

    def test_omitted_offline_configuration_does_not_seal_legacy_selection(self):
        with self.assertRaises(verifier.ProductVerifierError):
            verifier.build_manifest(self.operator)
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_operator_configuration_and_supplied_configuration_must_match_exactly(self):
        for mutation in (lambda x: x.update(hosted_runtime_configuration_sha256='d' * 64),
                         lambda x: x['images'].update(fox='sha256:' + 'd' * 64),
                         lambda x: x['opaf_profile'].update(target_profile_sha256='d' * 64),
                         lambda x: x['opaf_profile'].update(sha256='d' * 64),
                         lambda x: x.update(unreviewed=True),
                         lambda x: x['opaf_profile'].update(unreviewed=True)):
            altered = deepcopy(self.operator)
            mutation(altered)
            with self.subTest(altered=altered), self.assertRaises((
                    verifier.ProductVerifierError, bridge.QueueTransportError, runtime.ProviderError)):
                self.build(operator=altered)

    def test_reviewed_target_roles_cannot_be_paired_with_old_profile(self):
        altered = deepcopy(self.operator)
        altered['opaf_profile'].update(path='deployment/native-beta-profile.json',
            sha256=digest((ROOT / 'deployment/native-beta-profile.json').read_bytes()))
        with self.assertRaises((verifier.ProductVerifierError, bridge.QueueTransportError, runtime.ProviderError)):
            self.build(operator=altered)

    def test_reviewed_profile_preserves_json_numeric_types_not_python_equality(self):
        with tempfile.TemporaryDirectory(prefix='fox-profile-json-types-') as temporary:
            source_root = Path(temporary).resolve()
            (source_root / 'deployment').mkdir()
            profile_path = source_root / PROFILE_PATH
            profile_raw = (ROOT / PROFILE_PATH).read_bytes()
            profile_path.write_bytes(profile_raw)
            reference = deepcopy(self.operator['opaf_profile'])
            with patch.object(bridge, 'ROOT', source_root):
                accepted = bridge.reviewed_profile(reference, self.configuration)
                self.assertEqual(accepted['sha256'], digest(profile_raw))
                self.assertEqual(accepted['target_profile_sha256'], self.configuration['target_profile_sha256'])
                profile = json.loads(profile_raw)
                self.assertEqual(profile['native_project_schema_versions'], [1, 2])
                profile['native_project_schema_versions'] = [True, 2]
                altered_raw = canonical_bytes(profile)
                profile_path.write_bytes(altered_raw)
                reference['sha256'] = digest(altered_raw)
                # The actual bytes and supplied source hash agree; only the
                # reviewed JSON types differ. Python dict equality is unsafe.
                self.assertEqual(profile_path.read_bytes(), altered_raw)
                with self.assertRaisesRegex(bridge.QueueTransportError, 'HOSTED_PROFILE_TARGET_DIFFERS'):
                    bridge.reviewed_profile(reference, self.configuration)

    def test_profile_paths_are_bounded_reviewed_relative_references(self):
        for path in ('../deployment/project-opaf-profile-v2.json', '/tmp/profile.json',
                     'deployment/../deployment/project-opaf-profile-v2.json',
                     'C:\\unreviewed\\profile.json', 'deployment\\project-opaf-profile-v2.json'):
            altered = deepcopy(self.operator)
            altered['opaf_profile']['path'] = path
            with self.subTest(path=path), self.assertRaises((
                    verifier.ProductVerifierError, bridge.QueueTransportError, runtime.ProviderError)):
                self.build(operator=altered)

    def test_operator_and_compiled_container_validate_same_v3_shape(self):
        value = self.build()
        namespace = {}
        exec(compile(bridge._helper_source(), '<actual-queue-helper>', 'exec'), namespace)
        self.assertEqual(namespace['validate_release'](value), bridge.validate_release(value))
        for mutation in (lambda x: x.update(unreviewed=True),
                         lambda x: x['opaf_profile'].update(unreviewed=True),
                         lambda x: x['opaf_profile'].update(host_path='../deployment/project-opaf-profile-v2.json'),
                         lambda x: x['opaf_profile'].update(host_path='/tmp/../deployment/project-opaf-profile-v2.json'),
                         lambda x: x['code'].pop('retirement_handoff.py'),
                         lambda x: x['images'].update(qa=IMAGES['fox']),
                         lambda x: x.update(hosted_runtime_configuration_sha256='invalid'),
                         lambda x: x.update(native_profile_sha256='e' * 64)):
            altered = deepcopy(value)
            mutation(altered)
            with self.subTest(altered=altered):
                with self.assertRaises(bridge.QueueTransportError):
                    bridge.validate_release(altered)
                with self.assertRaises(namespace['QueueTransportError']):
                    namespace['validate_release'](altered)

    def test_legacy_release_formats_do_not_gain_hosted_fields_or_code_closure(self):
        for version in (1, 2):
            config = {'schema_version': version,
                'scope': 'fox-product-verifier-operator-config-v' + str(version),
                'enabled': False, 'images': {'fox': native.FOX_IMAGE, 'converter': native.IMAGE}}
            value = verifier.build_manifest(config)
            self.assertEqual(value['schema_version'], version)
            self.assertNotIn('hosted_runtime_configuration_sha256', value)
            self.assertNotIn('opaf_profile', value)
            self.assertEqual(set(value['code']), set(bridge.CODE))
            self.assertNotIn('retirement_handoff.py', value['code'])
            self.assertEqual(bridge.validate_release(value), value)


@unittest.skipUnless(POSIX, 'Real hosted selection requires an unprivileged POSIX filesystem')
class SelectedHostedReleaseTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(runtime)
        self.addCleanup(importlib.reload, runtime)
        self.temporary = tempfile.TemporaryDirectory(prefix='fox-hosted-release-')
        self.addCleanup(self.temporary.cleanup)
        self.config = create_hosted_fixture(Path(self.temporary.name) / 'installed')
        self.config.update(schema_version=2, scope='fox-hosted-operator-runtime-v2', images=dict(IMAGES))
        self.config['target_profile'] = deepcopy(target_profile._PROFILE_JSN_PROJECT_20261025)
        self.config['target_profile_sha256'] = target_profile.target_profile_sha256(self.config['target_profile'])

    def configured(self):
        return configure_fixture(self.config, runtime)

    def test_selection_after_all_consumer_imports_uses_configured_images_everywhere(self):
        constants = (native.FOX_IMAGE, native.IMAGE, project.FOX_IMAGE, project.IMAGE)
        provider = self.configured()
        for module in (native, project):
            self.assertEqual(module.image_pins(), IMAGES)
            copy = module.image_pins()
            copy['fox'] = 'cannot mutate provider'
            self.assertEqual(module.image_pins(), IMAGES)
        for module in (native_qa, project_qa):
            descriptor = module.bundle()[2]
            self.assertEqual(descriptor['fox_image'], IMAGES['fox'])
            self.assertEqual(descriptor['converter_image'], IMAGES['converter'])
        provider.configuration['images']['fox'] = 'cannot mutate provider'
        self.assertEqual(runtime.image_pins({'fox': native.FOX_IMAGE, 'converter': native.IMAGE}), IMAGES)
        self.assertEqual((native.FOX_IMAGE, native.IMAGE, project.FOX_IMAGE, project.IMAGE), constants)

    def test_source_fetch_packets_use_selected_fox_pin_without_constant_patching(self):
        self.configured()
        for module in (native, project):
            with (self.subTest(module=module.__name__),
                  patch.object(module, 'ssh_json', side_effect=RuntimeError('EXTERNAL_FIXTURE_STOP')) as boundary):
                with self.assertRaisesRegex(RuntimeError, 'EXTERNAL_FIXTURE_STOP'):
                    module.fetch_source('fox-' + '1' * 20, '2' * 64, {})
                self.assertEqual(boundary.call_args.args[1]['fox_image'], IMAGES['fox'])

    def test_project_profile_selection_packet_uses_selected_pin_without_constant_patching(self):
        self.configured()
        binding = VerificationBinding('fox-' + '1' * 20, '2' * 64, '3' * 64, '4' * 64)
        with (patch.object(project, 'oci_scope', return_value={'synthetic': 'read-only'}) as scope,
              patch.object(project, 'ssh_json', side_effect=RuntimeError('EXTERNAL_FIXTURE_STOP')) as boundary):
            with self.assertRaisesRegex(RuntimeError, 'EXTERNAL_FIXTURE_STOP'):
                project_operator.select_profile(binding)
        scope.assert_called_once_with(require_database_available=False)
        self.assertEqual(boundary.call_count, 1)
        program, packet = boundary.call_args.args
        self.assertEqual(program, project.SOURCE_HOST)
        self.assertEqual(packet['fox_image'], IMAGES['fox'])
        self.assertNotEqual(packet['fox_image'], project.FOX_IMAGE)
        self.assertEqual(packet['job_id'], binding.job_id)
        self.assertEqual(packet['package_sha256'], binding.package_sha256)

    def test_generated_host_uses_real_profile_file_and_exact_inspected_container(self):
        """Only IMDS and Podman are doubled; host guards use actual file bytes."""
        installation = Path(self.config['converter_root']).parent
        deployment = installation / 'deployment'
        deployment.mkdir(mode=0o700)
        profile = deployment / Path(PROFILE_PATH).name
        profile_raw = (ROOT / PROFILE_PATH).read_bytes()
        profile.write_bytes(profile_raw)
        profile.chmod(0o600)
        raw = canonical_bytes(self.config)
        manifest = verifier.build_manifest(operator_configuration(self.config), hosted_configuration=raw)
        self.configured()
        self.assertEqual(bridge.require_ready(manifest, bridge.release_sha256(manifest)), manifest)
        self.assertEqual(manifest['opaf_profile']['host_path'], str(profile))
        self.assertTrue(profile.is_file())
        self.assertEqual(profile.stat().st_mode & 0o777, 0o600)

        release = bridge.release_sha256(manifest)
        request = bridge._validate_request({'operation': 'heartbeat', 'apply': True,
            'manifest': manifest, 'release_sha256': release,
            'binding': None, 'claim': None, 'code': None, 'proof_sha256': None})
        target = self.config['target_profile']['oci']
        packet = {'request': request, 'cli_scope': {
            'instance_id': target['instance_id'], 'database_id': target['database_id'],
            'compartment_id': target['compartment_id']}}
        metadata = {'id': target['instance_id'], 'compartmentId': target['compartment_id'],
                    'canonicalRegionName': target['region']}
        container = 'e' * 64
        inspection = {'Id': container, 'Image': IMAGES['fox'], 'State': {'Running': True},
            'Config': {'User': '1000:1000', 'Env': ['FOX_VERIFICATION_ENABLED=1',
                        'FOX_VERIFIER_RELEASE_SHA256=' + release]},
            'HostConfig': {'UsernsMode': '', 'ReadonlyRootfs': True,
                           'Tmpfs': {'/tmp': 'rw,noexec,nosuid'}},
            'Mounts': [
                {'Type': 'bind', 'Source': '/home/opc/fox/data', 'Destination': '/data', 'RW': True},
                {'Type': 'bind', 'Source': str(profile),
                 'Destination': '/run/fox-native/profile.json', 'RW': False},
                {'Type': 'bind', 'Source': '/home/opc/fox/secure/opaf-client',
                 'Destination': '/run/fox-opaf', 'RW': False}]}

        def execute(inspected, *, optimize=0):
            events, calls = [], []

            def imds(http_request, *, timeout):
                events.append('imds')
                self.assertEqual(http_request.full_url, 'http://169.254.169.254/opc/v2/instance/')
                self.assertEqual(http_request.get_header('Authorization'), 'Bearer Oracle')
                self.assertEqual(timeout, 5)
                return io.BytesIO(json.dumps(metadata).encode())

            def podman(arguments, **options):
                calls.append((list(arguments), dict(options)))
                if arguments == ['podman', 'inspect', 'fox']:
                    events.append('inspect')
                    self.assertEqual(options,
                        {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE, 'timeout': 20})
                    return subprocess.CompletedProcess(arguments, 0, json.dumps([inspected]).encode(), b'')
                events.append('exec')
                self.assertEqual(arguments[:8],
                    ['podman', 'exec', '-i', container, '/usr/local/bin/python', '-I', '-B', '-c'])
                self.assertEqual(len(arguments), 9)
                script, body = options['input'].split(b'\n', 1)
                self.assertEqual(base64.b64decode(script, validate=True).decode(), bridge.container_source())
                self.assertEqual(json.loads(body), request)
                response = {'status': 'CONTACT_RECORDED', 'verifier_release_sha256': release}
                return subprocess.CompletedProcess(arguments, 0, json.dumps(response).encode(), b'')

            output = io.StringIO()
            with (patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(canonical_bytes(packet)))),
                  patch.object(urllib.request, 'urlopen', side_effect=imds),
                  patch.object(subprocess, 'run', side_effect=podman), redirect_stdout(output)):
                exec(compile(bridge.host_source(), '<actual-hosted-v3-host-guard>', 'exec', optimize=optimize), {})
            return json.loads(output.getvalue()), events, calls

        for optimize in (0, 1, 2):
            with self.subTest(optimize=optimize):
                result, events, calls = execute(inspection, optimize=optimize)
                self.assertEqual(result, {'status': 'CONTACT_RECORDED', 'verifier_release_sha256': release,
                    'host_scope_verified': True, 'fox_image': IMAGES['fox']})
                self.assertEqual(events, ['imds', 'inspect', 'exec'])
                self.assertEqual(len(calls), 2)

        cases = ('old-profile-mount', 'wrong-image', 'stale-profile-bytes')
        for case in cases:
            inspected = deepcopy(inspection)
            if case == 'old-profile-mount':
                inspected['Mounts'][1]['Source'] = (
                    '/home/opc/fox/releases/native-beta-20261017h/deployment/native-beta-profile.json')
            elif case == 'wrong-image':
                inspected['Image'] = native.FOX_IMAGE
            else:
                profile.write_bytes(profile_raw + b'\n')
            try:
                with self.subTest(case=case):
                    result, events, calls = execute(inspected, optimize=2)
                    self.assertEqual(result, {'status': 'STOPPED',
                        'code': 'QUEUE_HOST_OUTCOME_UNCONFIRMED_NO_REPLAY',
                        'automatic_replay_permitted': False})
                    self.assertEqual(events, ['imds', 'inspect'])
                    self.assertEqual([call[0] for call in calls], [['podman', 'inspect', 'fox']])
            finally:
                profile.write_bytes(profile_raw)

    def test_selected_configuration_allows_matching_fresh_release_only(self):
        raw = canonical_bytes(self.config)
        config = operator_configuration(self.config)
        manifest = verifier.build_manifest(config, hosted_configuration=raw)
        self.configured()
        with patch.object(subprocess, 'run', side_effect=AssertionError('No process during readiness')):
            self.assertEqual(verifier.build_manifest(config), manifest)
            self.assertEqual(bridge.require_ready(manifest, bridge.release_sha256(manifest)), manifest)
            for mutation in (lambda x: x.update(hosted_runtime_configuration_sha256='e' * 64),
                             lambda x: x['images'].update(converter='sha256:' + 'e' * 64),
                             lambda x: x['opaf_profile'].update(host_path='/other-installation/' + PROFILE_PATH),
                             lambda x: x['code'].update({'runtime_provider.py': 'e' * 64}),
                             lambda x: x['project'].update(qa_source_sha256='e' * 64)):
                altered = deepcopy(manifest)
                mutation(altered)
                with self.subTest(altered=altered), self.assertRaises(bridge.QueueTransportError):
                    bridge.require_ready(altered, bridge.release_sha256(altered))

    def test_runtime_v1_keeps_legacy_pins_and_cannot_admit_v3_release(self):
        raw = canonical_bytes(self.config)
        manifest = verifier.build_manifest(operator_configuration(self.config), hosted_configuration=raw)
        old = deepcopy(self.config)
        old.update(schema_version=1, scope='fox-hosted-operator-runtime-v1')
        old.pop('images')
        configure_fixture(old, runtime)
        self.assertEqual(native.image_pins(), {'fox': native.FOX_IMAGE, 'converter': native.IMAGE})
        self.assertEqual(project.image_pins(), {'fox': project.FOX_IMAGE, 'converter': project.IMAGE})
        with self.assertRaises(bridge.QueueTransportError):
            bridge.require_ready(manifest, bridge.release_sha256(manifest))

    def test_invalid_configured_image_pins_fail_before_selection_or_process(self):
        for images in ({'fox': IMAGES['fox']}, {**IMAGES, 'qa': IMAGES['fox']},
                       {**IMAGES, 'fox': 'fox:latest'}):
            value = deepcopy(self.config)
            value['images'] = images
            raw = canonical_bytes(value)
            with (self.subTest(images=images),
                  patch.object(subprocess, 'run', side_effect=AssertionError('No process')),
                  self.assertRaises(runtime.ProviderError)):
                runtime.configure_hosted(raw, expected_sha256=digest(raw))
            self.assertIs(runtime._selected, runtime._UNSELECTED)


if __name__ == '__main__':
    unittest.main(verbosity=2)
