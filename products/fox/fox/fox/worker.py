"""Single worker; external execution adapter is configured and verified during deployment."""
import json
import os
import subprocess
import time
import zipfile
from pathlib import Path

_NO_INSTALLATION_PROJECTION = object()


def _worker_installation_projection(installation_projection):
    """Check configuration before claiming; the application owns admission."""
    mode = os.environ.get('FOX_INSTALLATION_MODE')
    if mode is not None and (type(mode) is not str or mode not in ('legacy', 'fresh')):
        raise RuntimeError('Worker installation mode is invalid; no legacy fallback is permitted.')
    if mode != 'fresh':
        if (any(name.startswith('FOX_FRESH_') for name in os.environ)
                or installation_projection is not _NO_INSTALLATION_PROJECTION):
            raise RuntimeError('Fresh worker configuration requires explicit fresh mode and projection.')
        return _NO_INSTALLATION_PROJECTION
    if installation_projection is _NO_INSTALLATION_PROJECTION:
        raise RuntimeError('Fresh worker requires its validated installation projection before claiming work.')
    from .native_project_pipeline import _checked_installation_projection
    return _checked_installation_projection(os.environ, installation_projection)


def process_one(db,root:Path,*,installation_projection=_NO_INSTALLATION_PROJECTION):
    projection = _worker_installation_projection(installation_projection)
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("SELECT id FROM runs WHERE state='QUEUED' ORDER BY created LIMIT 1").fetchone()
        if not row: return
        rid=row['id']
        c.execute("UPDATE runs SET state='PROCESSING',message='Analyzing source with the embedded conversion workflow.',updated=? WHERE id=?",(time.time(),rid))
    native_completed = False
    try:
        job = root/'jobs'/rid
        snapshot_path = job/'source-snapshot.json'
        if (job.is_symlink() or snapshot_path.is_symlink() or not snapshot_path.is_file()
                or snapshot_path.stat().st_size > 2_000_000):
            raise RuntimeError('The immutable source snapshot is unavailable. The job is retained for review.')
        snapshot_raw = snapshot_path.read_bytes()
        snapshot = json.loads(snapshot_raw)
        if not isinstance(snapshot, dict):
            raise RuntimeError('The immutable source snapshot is invalid. The job is retained for review.')
        project = snapshot.get('conversion_profile') == 'native-project-v1'
        if projection is not _NO_INSTALLATION_PROJECTION and not project:
            raise RuntimeError('Fresh conversion requires an immutable native project source; no legacy fallback is permitted.')
        project_cache = job/'native-project-pipeline'
        if (project_cache.exists() or project_cache.is_symlink() or 'native_project' in snapshot) and not project:
            raise RuntimeError('Project source identity is inconsistent. No legacy conversion is permitted.')
        # Fixed operator-configured executable; no shell interpolation or arbitrary browser commands.
        adapter=os.environ.get('FOX_RUN_ADAPTER','')
        if not adapter: raise RuntimeError('Conversion adapter has not been configured.')
        if project:
            if adapter != 'embedded-opaf':
                raise RuntimeError('Project conversion requires the embedded project adapter.')
            from .native_project_pipeline import run_native_project_job
            if projection is _NO_INSTALLATION_PROJECTION:
                run_native_project_job(job)
            else:
                run_native_project_job(job, installation_projection=projection)
            result=None
        elif adapter == 'embedded-opaf':
            from .opaf import run_job
            run_job(job)
            result=None
        else:
            result=subprocess.run([adapter,str(job)],capture_output=True,text=True,timeout=600,check=False)
        if snapshot_path.read_bytes() != snapshot_raw:
            raise RuntimeError('The immutable source snapshot changed. The job requires operator reconciliation.')
        evidence_path=job/'release-evidence.json'
        if (result is not None and result.returncode!=0) or not evidence_path.exists(): raise RuntimeError('Conversion did not complete. The run is retained for operator review.')
        evidence=json.loads(evidence_path.read_text())
        if project and evidence.get('conversion_profile') != 'native-project-v1':
            raise RuntimeError('Project release identity differs. No legacy release is permitted.')
        if not project and evidence.get('conversion_profile') == 'native-project-v1':
            raise RuntimeError('Project release lacks its immutable project source identity.')
        required=['reviewer_approved','sqlcl_valid','import_passed','runtime_smoke_passed','package_reimport_passed']
        native=evidence.get('conversion_profile') in {'native-table-form-v1', 'native-project-v1'}
        if native: required.append('reviewer_execution_verified')
        if not all(evidence.get(k) is True for k in required): raise RuntimeError('The release checks did not all pass. No package is marked verified.')
        artifact=job/'apex-package.zip'
        if not artifact.is_file(): raise RuntimeError('The verified package was not produced.')
        state='QA_REQUIRED' if native else 'REVIEW_REQUIRED'
        message=('Technical checks passed. Developer-only authenticated and clean-install verification is pending.'
                 if native else 'Technical checks passed. Review the business flow and remediation before accepting the package.')
        with db() as c:
            c.execute('UPDATE runs SET state=?,message=?,artifact=?,updated=? WHERE id=?',(state,message,str(artifact.relative_to(root)),time.time(),rid))
        native_completed = native
    except (RuntimeError,subprocess.TimeoutExpired,OSError,ValueError,KeyError,zipfile.BadZipFile) as exc:
        # Only our own bounded messages leave this worker. Raw provider output may contain source.
        message=str(exc) if type(exc) is RuntimeError else 'Conversion needs operator attention. Source and job history are preserved.'
        with db() as c: c.execute("UPDATE runs SET state='ATTENTION',message=?,updated=? WHERE id=?",(message,time.time(),rid))
    except Exception:
        # Unexpected adapter failures must not leave a run permanently PROCESSING.
        # Do not expose provider bodies, source text, or secret parser excerpts.
        with db() as c:
            c.execute("UPDATE runs SET state='ATTENTION',message='Unexpected worker failure. Retained job requires operator reconciliation.',updated=? WHERE id=?",(time.time(),rid))
    if native_completed:
        # This separate boundary cannot turn a completed conversion into a
        # conversion failure, even if writing its diagnostic also fails.
        try:
            from .verification_runtime import enqueue_native
            enqueue_native(root, rid)
        except Exception:
            try:
                with db() as c:
                    c.execute("UPDATE runs SET message=?,updated=? WHERE id=? AND state='QA_REQUIRED'",
                        ('The conversion package is retained. Verification handoff needs operator reconciliation; do not restart conversion.', time.time(), rid))
            except Exception:
                # Public queue status independently shows not_queued/unavailable.
                # Keep QA_REQUIRED and the artifact; never rerun the conversion.
                pass
