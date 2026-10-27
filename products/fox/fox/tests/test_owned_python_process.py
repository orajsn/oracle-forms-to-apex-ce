"""Test-only ownership helper; mocks only, no service/native tools started."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[2] / 'work/owned-python-process.py'
SPEC = importlib.util.spec_from_file_location('owned_python_process', PATH)
OWNED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNED)
NOW = 134000000000000000
PARENT = {'pid': 1234, 'parent_pid': 12, 'executable': r'C:\fox\.venv\Scripts\python.exe', 'created_ticks': NOW - 10000000}
CHILD = {'pid': 5678, 'parent_pid': 1234, 'executable': r'C:\Python313\python.exe', 'created_ticks': NOW}


class Process:
    pid = 1234
    stopped = False
    def poll(self):
        return 1 if self.stopped else None
    def wait(self, timeout):
        self.stopped = True
        return 1


class Queries:
    def __init__(self):
        self.records = {1234: dict(PARENT), 5678: dict(CHILD)}
        self.rows = [{'pid': 5678, 'address': '127.0.0.1', 'port': 18100}]
        self.queried, self.terminated = [], []
    def process(self, pid):
        self.queried.append(pid)
        return self.records.get(pid)
    def listeners(self, port):
        assert port == 18100
        return self.rows
    def terminate_tree(self, pid):
        self.terminated.append(pid)


class OwnedPythonProcessTests(unittest.TestCase):
    def make(self):
        process, queries = Process(), Queries()
        guard = OWNED.OwnedPythonProcess(process, launcher_executable=PARENT['executable'],
            python_executable=CHILD['executable'], port=18100, queries=queries, now_ticks=lambda: NOW)
        return process, queries, guard

    def test_accepts_only_same_process_or_exact_direct_child(self):
        for same_pid in (False, True):
            _, query, guard = self.make()
            if same_pid:
                query.rows[0]['pid'] = 1234
            first = guard.require_listener()
            self.assertEqual(first, guard.require_listener())
            self.assertEqual(first['relationship'], 'same-process' if same_pid else 'direct-python-child')
            self.assertLessEqual(set(query.queried), {1234, 5678})

    def test_wrong_parent_executable_time_or_missing_metadata_fail_closed(self):
        for change in ({'parent_pid': 999}, {'executable': r'C:\untrusted\python.exe'},
                       {'created_ticks': PARENT['created_ticks'] - 1}, {'created_ticks': NOW + 610000000},
                       {'created_ticks': True}, {'executable': r'\\server\python.exe'}):
            with self.subTest(fields=tuple(change)):
                _, query, guard = self.make()
                query.records[5678].update(change)
                with self.assertRaises(OWNED.OwnershipError):
                    guard.require_listener()
        _, query, guard = self.make()
        query.records[5678] = None
        with self.assertRaises(OWNED.OwnershipError):
            guard.require_listener()

    def test_never_accepts_grandchild_replacement_or_pid_reuse(self):
        _, query, guard = self.make()
        guard.require_listener()
        query.records[5678]['created_ticks'] += 1
        with self.assertRaises(OWNED.OwnershipError):
            guard.require_listener()
        _, query, guard = self.make()
        query.records[5678]['parent_pid'] = 4000
        with self.assertRaises(OWNED.OwnershipError):
            guard.require_listener()

    def test_requires_live_unchanged_held_launcher_before_and_after_queries(self):
        process, query, guard = self.make()
        process.stopped = True
        with self.assertRaises(OWNED.OwnershipError):
            guard.require_listener()
        self.assertEqual(query.queried, [1234])
        _, query, guard = self.make()
        query.records[1234]['created_ticks'] += 1
        with self.assertRaises(OWNED.OwnershipError):
            guard.require_listener()
        process, query, guard = self.make()
        original = query.process
        def exited_during_query(pid):
            result = original(pid)
            process.stopped = True
            return result
        query.process = exited_during_query
        with self.assertRaises(OWNED.OwnershipError):
            guard.require_listener()

    def test_nonloopback_multiple_or_missing_listener_is_rejected(self):
        for rows in ([], [{'pid': 5678, 'address': '0.0.0.0', 'port': 18100}],
                     [{'pid': 5678, 'address': '127.0.0.1', 'port': 18100}] * 2):
            _, query, guard = self.make()
            query.rows = rows
            with self.assertRaises(OWNED.OwnershipError):
                guard.require_listener()

    def test_cleanup_targets_only_still_held_parent_tree(self):
        _, query, guard = self.make()
        guard.terminate_owned_tree()
        self.assertEqual(query.terminated, [1234])
        process, query, guard = self.make()
        process.stopped = True
        guard.terminate_owned_tree()
        self.assertEqual(query.terminated, [])
        _, query, guard = self.make()
        query.records[1234]['created_ticks'] += 1
        with self.assertRaises(OWNED.OwnershipError):
            guard.terminate_owned_tree()
        self.assertEqual(query.terminated, [])

    def test_queries_are_targeted_and_do_not_read_credentials(self):
        query = object.__new__(OWNED.WindowsQueries)
        scripts = []
        query._query = lambda script: scripts.append(script) or None
        query.process(5678)
        self.assertIn("-Filter 'ProcessId = 5678'", scripts[0])
        self.assertNotIn('CommandLine', scripts[0])
        self.assertNotIn('Environment', scripts[0])
        with self.assertRaises(OWNED.OwnershipError):
            query.process('5678; untrusted')


if __name__ == '__main__':
    unittest.main()
