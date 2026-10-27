"""Pure policy + generated reader with synthetic external I/O; no mount calls."""
import ast
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import inspect
import io
import json
from pathlib import PurePosixPath
import subprocess
import sys
import unittest
from unittest.mock import patch

from qa.operator import runtime_provider as runtime


OPTIONS = 'rw,noexec,nosuid,nodev,size=64m,mode=1777'
TMP = {'Type': 'tmpfs', 'Source': '', 'Destination': '/tmp', 'RW': True}
BIND = {'Type': 'bind', 'Source': '/synthetic/source', 'Destination': '/data', 'RW': True}


class EphemeralPolicyTests(unittest.TestCase):
    def test_both_inspector_representations_preserve_persistent_mounts_and_inputs(self):
        for rows in ([BIND], [BIND, TMP]):
            with self.subTest(rows=rows):
                original = deepcopy(rows)
                host = {'Tmpfs': {'/tmp': OPTIONS}}
                selected = runtime._selected
                with patch.object(subprocess, 'run', side_effect=AssertionError('NO_PROCESS')):
                    result = runtime.persistent_mounts('fox', host, rows)
                self.assertEqual(result, [BIND])
                self.assertEqual(rows, original)
                self.assertEqual(host, {'Tmpfs': {'/tmp': OPTIONS}})
                self.assertIs(runtime._selected, selected)

    def test_non_fox_roles_can_omit_ephemeral_storage(self):
        for role in ('converter', 'opaf'):
            for tmpfs in (None, {}):
                with self.subTest(role=role, tmpfs=tmpfs):
                    self.assertEqual(runtime.persistent_mounts(role, {'Tmpfs': tmpfs}, [BIND]), [BIND])

    def test_missing_fox_scratch_rejects(self):
        for host in ({}, {'Tmpfs': None}, {'Tmpfs': {}}):
            with self.subTest(host=host), self.assertRaisesRegex(runtime.ProviderError, 'WRITABLE_SCRATCH_REQUIRED'):
                runtime.persistent_mounts('fox', host, [BIND])

    def test_size_units_and_boundaries(self):
        for size in ('16m', '512m', '64M', '65536k', '16777216', '536870912'):
            with self.subTest(size=size):
                options = OPTIONS.replace('64m', size)
                self.assertEqual(runtime.persistent_mounts('fox', {'Tmpfs': {'/tmp': options}}, [TMP]), [])
        for size in ('1m', '513m', '1g', '0', '-1', '64mb', '64.0m', '99999999999m'):
            with self.subTest(size=size), self.assertRaises(runtime.ProviderError):
                runtime.persistent_mounts('fox', {'Tmpfs': {'/tmp': OPTIONS.replace('64m', size)}}, [TMP])

    def test_options_cannot_enable_execution_or_remove_bounds(self):
        invalid = [None, 1, '', OPTIONS + ',exec', OPTIONS + ',dev', OPTIONS + ',suid',
            OPTIONS + ',rw', OPTIONS.replace('rw,', 'ro,'), OPTIONS.replace('mode=1777', 'mode=0777'),
            OPTIONS.replace('size=64m', 'size'), OPTIONS.replace('mode=1777', 'mode'),
            OPTIONS.replace('noexec,', ''), OPTIONS.replace('nosuid,', ''),
            OPTIONS.replace('size=64m,', ''), OPTIONS + ',bind', OPTIONS + ',size=32m']
        for options in invalid:
            with self.subTest(options=options), self.assertRaises(runtime.ProviderError):
                runtime.persistent_mounts('fox', {'Tmpfs': {'/tmp': options}}, [TMP])

    def test_unknown_destination_duplicate_ephemeral_and_readonly_scratch_reject(self):
        invalid = [({'Tmpfs': {'/other': OPTIONS}}, [TMP]),
                   ({'Tmpfs': {'/tmp': OPTIONS}}, [TMP, TMP]),
                   ({'Tmpfs': {'/tmp': OPTIONS}}, [{**TMP, 'RW': False}]),
                   ({'Tmpfs': {'/tmp': OPTIONS}}, [{**TMP, 'Destination': '/data'}]),
                   ({'Tmpfs': False}, []), ({'Tmpfs': {'/tmp': OPTIONS}}, [None])]
        for host, rows in invalid:
            with self.subTest(host=host, rows=rows), self.assertRaises(runtime.ProviderError):
                runtime.persistent_mounts('fox', host, rows)

    def test_generated_reader_contains_exact_reviewed_policy(self):
        source = runtime.fresh_mount_program()
        functions = {node.name: node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}
        expected = ast.parse(inspect.getsource(runtime.persistent_mounts)).body[0]
        self.assertEqual(ast.dump(functions['persistent_mounts'], include_attributes=False),
                         ast.dump(expected, include_attributes=False))
        compile(source, '<checked-fresh-mount-reader>', 'exec')


def reader_case(*, representation=True, mutation=None):
    roles, observed = {}, []
    for index, role in enumerate(('fox', 'converter', 'opaf'), 1):
        name = {'fox': 'fox-fresh-unit', 'converter': 'forms2apex-fresh-unit', 'opaf': 'opaf-unit'}[role]
        desired = {'name': name, 'image': 'sha256:' + str(index) * 64, 'user': str(1000 + index),
                   'read_only_rootfs': role == 'fox',
                   'mounts': [{'source': '/synthetic/' + role, 'destination': '/data', 'read_only': False}]}
        roles[role] = desired
        observed.append({'Id': str(index + 3) * 64, 'Name': '/' + name, 'Image': desired['image'],
            'State': {'Running': True}, 'Config': {'User': desired['user']},
            'HostConfig': {'ReadonlyRootfs': desired['read_only_rootfs'],
                           'Tmpfs': {'/tmp': OPTIONS} if role == 'fox' else {}},
            'Mounts': [{'Type': 'bind', 'Source': row['source'], 'Destination': row['destination'],
                        'RW': not row['read_only']} for row in desired['mounts']]})
    if representation:
        observed[0]['Mounts'].append(deepcopy(TMP))
    if mutation:
        mutation(observed)
    projection = {'runtime': {'roles': roles}, 'synthetic_test_only': True}
    canonical = (json.dumps(projection, sort_keys=True, separators=(',', ':')) + '\n').encode()
    packet = {'projection': projection, 'projection_sha256': hashlib.sha256(canonical).hexdigest(),
              'private_paths': ['/synthetic-private/operator', '/synthetic-private/admin']}
    calls = []

    def process(args, **kwargs):
        calls.append(args)
        if args != ['/usr/bin/podman', 'inspect', '--', 'fox-fresh-unit', 'forms2apex-fresh-unit', 'opaf-unit']:
            raise AssertionError('NO_OTHER_PROCESS')
        return subprocess.CompletedProcess(args, 0, json.dumps(observed).encode(), b'')

    class ExistingSyntheticPath(PurePosixPath):
        # External filesystem boundary only. No actual host mount is attested.
        def resolve(self, *, strict):
            assert strict is True
            return self

    output = io.StringIO()
    with patch.object(sys, 'stdin', io.StringIO(json.dumps(packet))), patch.object(subprocess, 'run', process), \
         patch('pathlib.Path', ExistingSyntheticPath), redirect_stdout(output):
        exec(compile(runtime.fresh_mount_program(), '<synthetic-fresh-mount-reader>', 'exec'), {})
    result = json.loads(output.getvalue())
    assert len(calls) == 1
    return result


class GeneratedReaderTests(unittest.TestCase):
    def test_known_bounded_tmpfs_is_not_mistaken_for_extra_host_mount(self):
        for representation in (False, True):
            with self.subTest(representation=representation):
                result = reader_case(representation=representation)
                self.assertIs(result['safe'], True)
                self.assertEqual(set(result['observed_roles']), {'fox', 'converter', 'opaf'})

    def test_new_scratch_exception_does_not_admit_extra_host_backing_or_bad_flags(self):
        mutations = [
            lambda rows: rows[0]['HostConfig'].update(Tmpfs={}),
            lambda rows: rows[0]['HostConfig']['Tmpfs'].update({'/tmp': OPTIONS.replace('size=64m', 'size=1g')}),
            lambda rows: rows[0]['HostConfig']['Tmpfs'].update({'/tmp': OPTIONS + ',exec'}),
            lambda rows: rows[0]['Mounts'].append({**BIND, 'Destination': '/tmp'}),
            lambda rows: rows[0]['Mounts'].append({**BIND, 'Destination': '/unreviewed'}),
            lambda rows: rows[0]['Mounts'].__setitem__(0, {**rows[0]['Mounts'][0], 'Source': '/wrong-source'}),
            lambda rows: rows[1]['Mounts'].__setitem__(0, {**rows[1]['Mounts'][0], 'RW': False}),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index), self.assertRaises(RuntimeError):
                reader_case(mutation=mutation)


if __name__ == '__main__':
    unittest.main()
