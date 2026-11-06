"""On-demand private host processor; no HTTP listener or AI/database authority."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import time

from .hosted_forms_jobs import HostedFormsJobs, HostedFormsJobError, _path
from .linux_forms import LinuxOracleFormsBackend
from .native_preparation import prepare_native_source


def restore_job_owner(queue: HostedFormsJobs, job_id: str, uid: int, gid: int) -> None:
    """Allow a rootless user-namespace runner to return its *new* files.

    This is opt-in, requires namespace root, and only uses the existing queue
    job directory's owner, never a client-supplied destination UID. Native media,
    old jobs and the queue parent are not changed. All paths are checked before
    any ownership operation; symbolic links and hard-linked files are rejected.
    """
    if os.name != 'posix' or os.geteuid() != 0:
        raise HostedFormsJobError('Queue ownership handoff requires the configured user-namespace runner.')
    job = queue._job(job_id)
    current = job.stat()
    if (current.st_uid, current.st_gid) != (uid, gid):
        raise HostedFormsJobError('Queue job owner changed during processing.')
    targets = []
    for folder, dirs, files in os.walk(job, followlinks=False):
        for name in dirs + files:
            path = _path(Path(folder) / name)
            info = path.lstat()
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise HostedFormsJobError('Queue contains an unsupported filesystem object.')
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise HostedFormsJobError('Queue contains a multiply-linked file.')
            if info.st_uid not in {0, uid} or info.st_gid not in {0, gid}:
                raise HostedFormsJobError('Queue contains an unexpected file owner.')
            if info.st_uid == 0 or info.st_gid == 0:
                targets.append(path)
    for path in reversed(targets):
        _path(path)
        os.chown(path, uid, gid, follow_symlinks=False)


def run_once(queue: HostedFormsJobs, prepare, *, handoff_owner: bool = False) -> list[dict]:
    outcomes = []
    for jid in queue.list_pending(limit=5):
        owner = queue._job(jid).stat()
        outcome = queue.process(jid, prepare=prepare)
        if handoff_owner:
            restore_job_owner(queue, jid, owner.st_uid, owner.st_gid)
        # Public-shaped observations contain neither paths nor customer code.
        outcomes.append({'job_id': jid, 'status': outcome['status']})
    return outcomes


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Process private FOX FMB preparation jobs on the installed Oracle host.')
    parser.add_argument('--queue-root', type=Path, required=True)
    parser.add_argument('--oracle-home', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--temp-root', type=Path, required=True)
    parser.add_argument('--poll-seconds', type=int, default=0,
                        help='0 runs one bounded batch; 2–60 enables a private polling worker.')
    parser.add_argument('--handoff-job-owner', action='store_true',
                        help='Rootless namespace root returns new artifacts to the job directory owner.')
    args = parser.parse_args(argv)
    if args.poll_seconds != 0 and not 2 <= args.poll_seconds <= 60:
        parser.error('Polling interval must be zero or between 2 and 60 seconds.')
    if args.handoff_job_owner and (os.name != 'posix' or os.geteuid() != 0):
        parser.error('Ownership handoff requires the configured user-namespace runner.')
    queue = HostedFormsJobs(args.queue_root)
    # Check operator-selected tool configuration before claiming any job.
    homes = tuple(_path(p) for p in (args.oracle_home, args.java_home, args.temp_root))
    def backend(mode):
        return LinuxOracleFormsBackend(homes[0], homes[1], temp_root=homes[2], dump_mode=mode)
    try:
        backend('OVERRIDDEN').check()
    except (ValueError, OSError):
        print(json.dumps({'status': 'NATIVE_TOOLS_NOT_READY', 'jobs_claimed': 0}), flush=True)
        return 1
    def prepare(source, output_root, **kwargs):
        return prepare_native_source(source, output_root, backend_factory=backend, **kwargs)
    while True:
        try:
            result = run_once(queue, prepare, handoff_owner=args.handoff_job_owner)
            print(json.dumps({'status': 'BATCH_OBSERVED', 'jobs': result,
                              'model_calls': 0, 'database_calls': 0}), flush=True)
        except (ValueError, OSError):
            print(json.dumps({'status': 'QUEUE_REQUIRES_OPERATOR_ATTENTION',
                              'automatic_retry': False}), flush=True)
            return 1
        if not args.poll_seconds:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == '__main__':
    raise SystemExit(main())
