"""One-shot private host worker; no polling daemon, listener or implicit config.

Trusted operator invocation (factory is never taken from dispatch JSON)::

  PYTHONPATH=converter:. python -m qa.operator.prototype_runtime_worker run \
      --factory operator_private.prototype:configure --job-id fox-...

Read-only discovery for the trusted host polling unit::

  PYTHONPATH=converter:. python -m qa.operator.prototype_runtime_worker pending \
      --factory operator_private.prototype:configure --limit 1

The factory receives no arguments and returns RuntimeWorkerConfig containing
the explicit host PrototypeBrowser, real current authorizer, private staging
root and JobIO. PodmanNamespaceJobIO is provided for the existing rootless host
volume; it launches only this module's fixed bounded filesystem subcommand.
Unknown/interrupted claims and browser evidence are retained, never retried.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time

from forms2apex.project_reviews import canonical, digest
from forms2apex.prototype_release import validate_runtime_receipt
from forms2apex.prototype_runtime_bridge import (
    CLAIM, FOX_JOB, MAX_JSON, MAX_PENDING, MAX_PENDING_RESPONSE, RECEIPT, REQUEST, RESULT, JobIO, LocalJobIO, check_artifacts,
    check_retained, checked_path, code_sha256, create_bytes, need, object_bytes, remaining_seconds, validate_packet,
)
from forms2apex.security import validate_job_id
from .prototype_browser import PrototypeBrowser, PrototypeBrowserConfig


_PROCESS_LOCK = threading.Lock()


@dataclass(frozen=True)
class RuntimeWorkerConfig:
    io: JobIO
    staging_jobs_root: Path
    browser: PrototypeBrowser
    authorize: object
    execution_seconds: int = 420


class PodmanNamespaceJobIO:
    """Existing opc rootless namespace only. No SSH, container run or secrets.

    jobs_root and python executable/module installation come from trusted host
    startup. The namespace helper restores published files to the exact existing
    prototype-converter directory UID/GID; it does not chmod/chown other state.
    """
    def __init__(self, jobs_root, *, python_executable=sys.executable, command=subprocess.run):
        self.jobs_root = Path(jobs_root)
        need(self.jobs_root.is_absolute(), "PROTOTYPE_WORKER_ABSOLUTE_ROOT_REQUIRED")
        self.python_executable, self.command = str(python_executable), command

    def _operation(self, operation, job_id, name, limit, raw=None):
        need(type(limit) is int and 0 < limit <= 64 * 1024 * 1024, "PROTOTYPE_WORKER_IO_LIMIT_INVALID")
        # Validate logical name before crossing the namespace. No lookup needed
        # here: the ordinary opc user may not traverse converter-owned jobs.
        from forms2apex.prototype_runtime_bridge import _CONTEXT, _ARTIFACT
        if operation == 'pending':
            need(job_id is None and name is None and limit <= MAX_PENDING, "PROTOTYPE_BRIDGE_PENDING_LIMIT_INVALID")
        else:
            validate_job_id(job_id)
            need(name in _CONTEXT or bool(_ARTIFACT.fullmatch(name)), "PROTOTYPE_BRIDGE_PATH_INVALID")
        args = ["podman", "--remote=false", "unshare", self.python_executable, "-m",
                "qa.operator.prototype_runtime_worker", "namespace-io", "--jobs-root", str(self.jobs_root),
                "--operation", operation, "--limit", str(limit)]
        if operation != 'pending':
            args += ["--job-id", job_id, "--name", name]
        result = self.command(args, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                              check=False)
        if result.returncode == 17:
            raise FileExistsError("PROTOTYPE_WORKER_NAMESPACE_ALREADY_EXISTS")
        output_limit = MAX_PENDING_RESPONSE if operation == 'pending' else max(limit, 1)
        need(result.returncode == 0 and not result.stderr and len(result.stdout) <= output_limit,
             "PROTOTYPE_WORKER_NAMESPACE_IO_UNCONFIRMED")
        return result.stdout

    def read(self, job_id, name, limit):
        return self._operation("read", job_id, name, limit)

    def create(self, job_id, name, raw):
        need(type(raw) is bytes and 0 < len(raw) <= 20_000_000, "PROTOTYPE_WORKER_WRITE_SIZE_INVALID")
        self._operation("create", job_id, name, len(raw), raw)

    def exists(self, job_id, name):
        raw = self._operation("exists", job_id, name, 1)
        need(raw in (b"0", b"1"), "PROTOTYPE_WORKER_NAMESPACE_IO_UNCONFIRMED")
        return raw == b"1"

    def pending(self, *, limit=1):
        raw = self._operation('pending', None, None, limit)
        result = object_bytes(raw)
        jobs = result.get('jobs')
        need(set(result) == {'jobs'} and type(jobs) is list and len(jobs) <= limit
             and all(type(job) is str and FOX_JOB.fullmatch(job) for job in jobs)
             and len(set(jobs)) == len(jobs), "PROTOTYPE_WORKER_PENDING_RESPONSE_INVALID")
        return jobs


def private_directory(path):
    path = Path(path).absolute()
    for parent in (*reversed(path.parents), path):
        need(not parent.is_symlink(), "PROTOTYPE_WORKER_LINKED_STAGING")
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode), "PROTOTYPE_WORKER_STAGING_INVALID")
    if os.name == "posix":
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
             "PROTOTYPE_WORKER_PRIVATE_STAGING_REQUIRED")
    return path


@contextmanager
def single_worker(root):
    need(_PROCESS_LOCK.acquire(blocking=False), "PROTOTYPE_WORKER_BUSY")
    stream = None
    try:
        # POSIX flock survives process crashes without deleting retained locks.
        if os.name == "posix":
            import fcntl
            path = root / "runtime-worker.lock"
            need(not path.is_symlink(), "PROTOTYPE_WORKER_LINKED_LOCK")
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            stream = os.fdopen(descriptor, "r+b")
            info = os.fstat(stream.fileno())
            need(info.st_uid == os.getuid() and info.st_nlink == 1 and stat.S_ISREG(info.st_mode),
                 "PROTOTYPE_WORKER_LOCK_INVALID")
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("PROTOTYPE_WORKER_BUSY") from None
        yield
    finally:
        if stream is not None:
            stream.close()
        _PROCESS_LOCK.release()


class BoundedHostCommand:
    def __init__(self, command, deadline):
        self.command, self.deadline = command, deadline

    def __call__(self, args, *, timeout=60, **kwargs):
        remaining = self.deadline - time.monotonic()
        need(remaining > 0, "PROTOTYPE_WORKER_EXECUTION_TIMEOUT_UNKNOWN")
        return self.command(args, timeout=min(timeout, remaining), **kwargs)


def run_once(config, job_id):
    need(isinstance(config, RuntimeWorkerConfig) and callable(config.authorize)
         and isinstance(config.browser, PrototypeBrowser) and isinstance(config.browser.config, PrototypeBrowserConfig)
         and callable(config.browser.credential_authorizer), "PROTOTYPE_WORKER_ACTUAL_EXECUTOR_REQUIRED")
    need(type(config.execution_seconds) is int and 0 < config.execution_seconds <= 420,
         "PROTOTYPE_WORKER_EXECUTION_DEADLINE_INVALID")
    validate_job_id(job_id)
    staging = private_directory(config.staging_jobs_root)
    need(Path(config.browser.config.jobs_root).absolute() == staging, "PROTOTYPE_WORKER_BROWSER_STAGING_MISMATCH")
    with single_worker(staging):
        packet = validate_packet(object_bytes(config.io.read(job_id, REQUEST, MAX_JSON)))
        need(packet["request"]["job_id"] == job_id, "PROTOTYPE_WORKER_JOB_CHANGED")
        dispatch_sha = digest(packet)
        check_retained(config.io, packet)
        if config.io.exists(job_id, CLAIM):
            # Even a retained completed result is observation only, not a retry.
            return {"state": "UNKNOWN_NO_REPLAY", "dispatch_sha256": dispatch_sha}
        request = deepcopy(packet["request"])
        def fresh():
            remaining_seconds(packet)
            check_retained(config.io, packet)
            need(object_bytes(config.io.read(job_id, REQUEST, MAX_JSON)) == packet,
                 "PROTOTYPE_WORKER_DISPATCH_CHANGED")
            value = deepcopy(request)
            need(config.authorize(value) == request and value == request,
                 "PROTOTYPE_WORKER_CURRENT_AUTHORITY_CHANGED")
        fresh()
        config.io.create(job_id, CLAIM, canonical({"dispatch_sha256": dispatch_sha,
                         "worker_sha256": code_sha256(__file__), "state": "CLAIMED_NO_AUTOMATIC_REPLAY"}))
        # No cleanup: a crash at any later point preserves uncertainty/evidence.
        job = staging / job_id
        job.mkdir(mode=0o700)
        root = job / "prototype-converter"
        root.mkdir(mode=0o700)
        for name, value in ((REQUEST, packet), ("snapshot.json", packet["artifact_binding"]),
                            ("import.json", packet["imported"])):
            create_bytes(root / name, canonical(value))
        original_command = config.browser.command
        original_browser_config = config.browser.config
        execution_seconds = min(config.execution_seconds, remaining_seconds(packet))
        config.browser.config = replace(original_browser_config,
            request_deadline_at_utc=packet['deadline_at_utc'],
            execution_deadline_at_utc=(datetime.now(timezone.utc) + timedelta(seconds=execution_seconds)).isoformat())
        config.browser.command = BoundedHostCommand(original_command,
            time.monotonic() + execution_seconds)
        try:
            fresh()
            receipt = config.browser(request, root=root, imported=packet["imported"], trace=packet["trace"],
                                     artifact_binding=packet["artifact_binding"], freshness_check=fresh)
        finally:
            config.browser.command = original_command
            config.browser.config = original_browser_config
        fresh()
        rows = check_artifacts(receipt)
        validate_runtime_receipt(root, request, packet["imported"], packet["artifact_binding"], receipt)
        # Snapshot exact checked bytes before any original-job publication.
        artifacts = []
        local = LocalJobIO(staging)
        for row in rows:
            raw = local.read(job_id, row["path"], row["bytes"])
            need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
                 "PROTOTYPE_WORKER_ARTIFACT_CHANGED")
            artifacts.append((row["path"], raw))
        fresh()
        for name, raw in artifacts:
            config.io.create(job_id, name, raw)
        config.io.create(job_id, RECEIPT, canonical(receipt))
        fresh()
        result = {"schema_version": 1, "scope": "fox-prototype-runtime-result-v1",
                  "dispatch_sha256": dispatch_sha, "binding": packet["binding"],
                  "worker_sha256": code_sha256(__file__), "receipt_sha256": digest(receipt)}
        config.io.create(job_id, RESULT, canonical(result))
        return {"state": "PUBLISHED", "dispatch_sha256": dispatch_sha}


def namespace_io(args):
    need(os.name == "posix" and os.getuid() == 0 and 0 < args.limit <= 64 * 1024 * 1024,
         "PROTOTYPE_WORKER_ROOTLESS_NAMESPACE_REQUIRED")
    io = LocalJobIO(args.jobs_root)
    if args.operation == 'pending':
        need(args.job_id is None and args.name is None, 'PROTOTYPE_WORKER_PENDING_FIELDS_INVALID')
        sys.stdout.buffer.write(canonical({'jobs': io.pending(limit=args.limit)}))
        return
    path = checked_path(args.jobs_root, args.job_id, args.name)
    if args.operation == "read":
        sys.stdout.buffer.write(io.read(args.job_id, args.name, args.limit))
    elif args.operation == "exists":
        sys.stdout.buffer.write(b"1" if io.exists(args.job_id, args.name) else b"0")
    else:
        raw = sys.stdin.buffer.read(args.limit + 1)
        need(len(raw) == args.limit, "PROTOTYPE_WORKER_WRITE_SIZE_INVALID")
        owner = path.parent if not args.name.startswith("runtime-evidence/") else path.parent.parent
        info = owner.stat()
        io.publication_owner = (info.st_uid, info.st_gid)
        io.create(args.job_id, args.name, raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    run = sub.add_parser("run")
    run.add_argument("--factory", required=True)
    run.add_argument("--job-id", required=True)
    pending = sub.add_parser('pending', help='Read-only bounded discovery; never claims or runs jobs')
    pending.add_argument('--factory', required=True)
    pending.add_argument('--limit', type=int, default=1)
    io = sub.add_parser("namespace-io")
    io.add_argument("--jobs-root", required=True)
    io.add_argument("--job-id")
    io.add_argument("--name")
    io.add_argument("--limit", type=int, required=True)
    io.add_argument("--operation", choices=("read", "exists", "create", "pending"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "namespace-io":
            namespace_io(args)
        else:
            need(bool(re.fullmatch(r"[A-Za-z_][\w.]*:[A-Za-z_]\w*", args.factory)),
                 "PROTOTYPE_WORKER_FACTORY_INVALID")
            module, factory = args.factory.split(":")
            config = getattr(importlib.import_module(module), factory)()
            if args.mode == 'pending':
                need(isinstance(config, RuntimeWorkerConfig), 'PROTOTYPE_WORKER_ACTUAL_EXECUTOR_REQUIRED')
                print(canonical({'jobs': config.io.pending(limit=args.limit)}).decode())
            else:
                print(canonical(run_once(config, args.job_id)).decode())
    except FileExistsError:
        return 17
    return 0


if __name__ == "__main__":
    # A factory imports this module by its canonical name. Execute that same
    # module's entrypoint so its dataclass/Protocol identities are not split
    # between __main__ and qa.operator.prototype_runtime_worker under python -m.
    from qa.operator.prototype_runtime_worker import main as canonical_main
    raise SystemExit(canonical_main())
