"""Synthetic initial-direct saved proofs only; no Oracle, compiler or model calls."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from contextvars import copy_context
from copy import deepcopy
import os
from pathlib import Path

import pytest

from fox import prototype_direct_container as container
from fox import prototype_export_only as package
from fox import prototype_initial_direct_read_scope as scope
from fox import prototype_read_scope as epochs
from fox import worker
from fox.opaf import OpafError, canonical_hash
from test_oci_genai import target
from test_oci_genai_container import retained, correction_body
from test_prototype_job import queued, saved_row


@pytest.fixture
def tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp('dr')


@pytest.fixture
def job(tmp_path):
    job = tmp_path / 'job'
    root = job / 'prototype-pipeline'
    (root / container.PREFIX).mkdir(parents=True)
    (root / container.TECHNICAL).write_bytes(b'{}')
    (job / 'source-snapshot.json').write_bytes(b'{"original":true}')
    (root / 'original.json').write_bytes(b'{"proof":true}')
    return job


def read(job, key='a', compute=lambda: {'proof': ['original']}):
    return scope.optional_proof(job / 'prototype-pipeline', canonical_hash(key), compute)


def test_detached_results_and_no_reuse_across_operations(job):
    calls = []
    def compute():
        calls.append(True)
        return ({'proof': ['original']}, [1])
    expected = compute()
    calls.clear()
    for _ in range(2):
        with scope.initial_direct_read_scope(job, target()):
            first = read(job, compute=compute)
            assert type(first) is tuple and first == expected
            first[0]['proof'].clear()
            first[1].append(2)
            assert read(job, compute=compute) == expected
    assert len(calls) == 2
    read(job, compute=compute)
    read(job, compute=compute)
    assert len(calls) == 4


@pytest.mark.parametrize('change', ['content', 'same-size-restored-mtime', 'replace', 'remove',
                                   'add', 'outside-pipeline', 'directory', 'permission'])
def test_complete_job_fence_rejects_changes_after_cache_hit(job, change):
    path = job / 'prototype-pipeline/original.json'
    with pytest.raises((OpafError, OSError)):
        with scope.initial_direct_read_scope(job, target()):
            assert read(job) == read(job)
            if change in ('content', 'same-size-restored-mtime'):
                before = path.stat()
                path.write_bytes(b'{"proof":null}')
                if change == 'same-size-restored-mtime':
                    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            elif change == 'replace':
                replacement = job / 'replacement'
                replacement.write_bytes(path.read_bytes())
                os.replace(replacement, path)
            elif change == 'remove':
                path.unlink()
            elif change == 'add':
                (job / 'new.json').write_bytes(b'{}')
            elif change == 'outside-pipeline':
                (job / 'source-snapshot.json').write_bytes(b'{"original":false}')
            elif change == 'directory':
                (job / 'empty').mkdir()
            else:
                path.chmod(0o444)
    if path.exists():
        path.chmod(0o666)


@pytest.mark.parametrize('kind', ['symlink', 'directory-link', 'hardlink'])
@pytest.mark.parametrize('at_entry', [True, False])
def test_unsafe_links_are_rejected(job, kind, at_entry):
    outside = job.parent / 'outside'
    outside.mkdir()
    source = outside / 'source.json'
    source.write_bytes(b'{}')
    link = job / 'linked'
    def create():
        try:
            if kind == 'hardlink':
                os.link(source, link)
            else:
                link.symlink_to(outside if kind == 'directory-link' else source,
                                target_is_directory=kind == 'directory-link')
        except OSError as error:
            pytest.skip('Host cannot create this link: ' + str(error))
    if at_entry:
        create()
    with pytest.raises((OpafError, OSError)):
        with scope.initial_direct_read_scope(job, target()):
            read(job)
            if not at_entry:
                create()


def test_root_replacement_and_noncanonical_path_are_rejected(job):
    with pytest.raises((OpafError, OSError)):
        with scope.initial_direct_read_scope(job, target()):
            read(job)
            job.rename(job.with_name('old-job'))
            job.mkdir()
            (job / 'new.json').write_bytes(b'{}')
    moved = job.with_name('old-job')
    with pytest.raises(OpafError):
        with scope.initial_direct_read_scope(moved / '..' / moved.name, target()):
            pass


def test_changed_ancestor_identity_is_rejected(tmp_path):
    parent = tmp_path / 'parent'
    job = parent / 'job'
    (job / 'prototype-pipeline' / container.PREFIX).mkdir(parents=True)
    (job / 'prototype-pipeline' / container.TECHNICAL).write_bytes(b'{}')
    with pytest.raises(OpafError):
        with scope.initial_direct_read_scope(job, target()):
            read(job)
            parent.rename(tmp_path / 'old-parent')
            parent.mkdir()
            (tmp_path / 'old-parent/job').rename(job)


@pytest.mark.parametrize('change', ['create', 'remove'])
def test_unrelated_sibling_directory_changes_are_allowed(job, change):
    sibling = job.parent / 'another-job'
    if change == 'remove':
        sibling.mkdir()
    with scope.initial_direct_read_scope(job, target()):
        expected = read(job)
        if change == 'create':
            sibling.mkdir()
        else:
            sibling.rmdir()
        assert read(job) == expected


def test_other_job_nested_scope_and_execution_are_rejected(job, monkeypatch):
    with scope.initial_direct_read_scope(job, target()):
        with pytest.raises(OpafError):
            read(job.parent)
        with pytest.raises(OpafError):
            with scope.initial_direct_read_scope(job, target()):
                pass
        with pytest.raises(OpafError):
            scope.forbid_execution()
        with pytest.raises(OpafError):
            container.active_focus(None, None, None, None, None, None, runtime=object())
        with pytest.raises(OpafError):
            package.validate_offline(b'', job)
        with pytest.raises(OpafError):
            package.package_configuration('a' * 64)
    scope.forbid_execution()


def test_inherited_thread_and_task_cannot_reuse(job):
    with scope.initial_direct_read_scope(job, target()):
        context = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(context.run, read, job)
            with pytest.raises(OpafError):
                result.result()
    async def run():
        with scope.initial_direct_read_scope(job, target()):
            async def child():
                with pytest.raises(OpafError):
                    read(job)
            await asyncio.create_task(child())
    asyncio.run(run())


def test_captured_same_thread_context_is_revoked_at_operation_end(job):
    with scope.initial_direct_read_scope(job, target()):
        assert read(job) == {'proof': ['original']}
        captured = copy_context()
    with pytest.raises(OpafError):
        captured.run(read, job)
    with scope.initial_direct_read_scope(job, target()):
        with pytest.raises(OpafError):
            captured.run(read, job)


def test_independent_threads_have_independent_caches(job):
    def operation():
        calls = []
        with scope.initial_direct_read_scope(job, target()):
            compute = lambda: calls.append(True) or {}
            read(job, compute=compute)
            read(job, compute=compute)
        return calls
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(operation) for _ in range(2)]
        assert [future.result() for future in futures] == [[True], [True]]


@pytest.mark.parametrize('limit', ['count', 'value', 'total'])
def test_capacity_declines_storage_without_skipping_computation(job, monkeypatch, limit):
    monkeypatch.setattr(scope, {'count': 'MAX_PROOFS', 'value': 'MAX_VALUE_BYTES',
                               'total': 'MAX_CACHE_BYTES'}[limit], 0)
    calls = []
    with scope.initial_direct_read_scope(job, target()):
        for _ in range(2):
            assert read(job, compute=lambda: calls.append(True) or {'valid': True}) == {'valid': True}
    assert len(calls) == 2


def test_compute_errors_and_fence_errors_reset_scope(job):
    with pytest.raises(ValueError, match='synthetic failure'):
        with scope.initial_direct_read_scope(job, target()):
            read(job, compute=lambda: (_ for _ in ()).throw(ValueError('synthetic failure')))
    scope.forbid_execution()
    with pytest.raises(OpafError):
        with scope.initial_direct_read_scope(job, target()):
            (job / 'added.json').write_bytes(b'{}')
    scope.forbid_execution()
    with scope.initial_direct_read_scope(job, target()):
        assert read(job) == {'proof': ['original']}


@pytest.mark.parametrize('gate', ['not-direct', 'no-container', 'epoch'])
def test_other_paths_keep_existing_scope_semantics(job, gate):
    current = target()
    if gate == 'not-direct':
        current = {}
    elif gate == 'no-container':
        (job / 'prototype-pipeline' / container.TECHNICAL).unlink()
    else:
        (job / 'prototype-pipeline/epochs').mkdir()
    calls = []
    with scope.initial_direct_read_scope(job, current):
        for _ in range(2):
            read(job, compute=lambda: calls.append(True) or {})
    assert len(calls) == 2


def test_initial_direct_never_fabricates_epoch_continuation(job):
    with pytest.raises(FileNotFoundError):
        with epochs.readonly_proof_scope(job / 'prototype-pipeline'):
            pass
    with scope.initial_direct_read_scope(job, target()):
        assert read(job) == read(job)
    assert not (job / 'mapping-continuation.json').exists()


def test_exact_derive_inputs_do_not_alias(job, monkeypatch):
    calls = []
    def compute(root, packet, plan, current):
        calls.append((deepcopy(packet), deepcopy(plan), deepcopy(current)))
        return ({'packet': packet, 'plan': plan, 'target': current}, [], 0, {}, {})
    monkeypatch.setattr(container, '_derive', compute)
    with scope.initial_direct_read_scope(job, target()):
        for packet, plan, current in [({}, {}, {}), ({'changed': True}, {}, {}),
                                      ({}, {'changed': True}, {}), ({}, {}, {'changed': True})]:
            assert container.derive(job / 'prototype-pipeline', packet, plan, current)
            assert container.derive(job / 'prototype-pipeline', packet, plan, current)
    assert len(calls) == 4


def test_saved_candidate_exact_output_with_one_baseline_reconstruction(retained, monkeypatch):
    r = retained
    body = correction_body(r.http.get(r.path).json())
    assert r.http.post(r.path, json=body).status_code == 202
    r.converter.fail_stage = 'verify_runtime'
    worker.process_one(r.db, r.root)
    run = saved_row(r.db, r.job)
    assert run['state'] == 'ATTENTION'
    assert not (r.job / 'mapping-continuation.json').exists()
    original = (r.job / 'source-snapshot.json').read_bytes()
    current = {'target_profile': r.current, 'target_profile_sha256': canonical_hash(r.current)}
    before = {p.relative_to(r.job).as_posix(): p.read_bytes() for p in r.job.rglob('*') if p.is_file()}
    counts, old_baseline = [], container._baseline
    def baseline(*args, **kwargs):
        counts.append(True)
        return old_baseline(*args, **kwargs)
    monkeypatch.setattr(container, '_baseline', baseline)
    def forbidden(*args, **kwargs):
        pytest.fail('Saved proof reads must not execute models, configuration, compiler or converter.')
    from fox import prototype_job
    monkeypatch.setattr(prototype_job, '_configuration', forbidden)
    monkeypatch.setattr(r.client, 'invoke', forbidden)
    monkeypatch.setattr(r.converter, 'run_stage', forbidden)
    monkeypatch.setattr(package, 'validate_offline', forbidden)
    with monkeypatch.context() as uncached:
        uncached.setattr(scope, 'initial_direct_read_scope', lambda *args: nullcontext())
        expected = package.saved_candidate(r.job, r.snapshot, original, current, run)
    uncached_count = len(counts)
    counts.clear()
    assert package.saved_candidate(r.job, r.snapshot, original, current, run) == expected
    assert len(counts) == 1 and uncached_count > 1
    counts.clear()
    assert package.saved_candidate(r.job, r.snapshot, original, current, run) == expected
    assert len(counts) == 1
    assert before == {p.relative_to(r.job).as_posix(): p.read_bytes() for p in r.job.rglob('*') if p.is_file()}
