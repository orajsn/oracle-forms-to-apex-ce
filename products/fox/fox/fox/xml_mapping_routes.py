"""Authenticated, source/version-bound admission for installed local mappings."""
import uuid
import time

from fastapi import HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from . import source_history, xml_mapping_job as jobs
from .forms_native_plan import POLICY_ID


class MappingRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    selected_source_set_id: str | None = Field(default=None, pattern=r'^ss-[a-f0-9]{32}$')
    source_binding: str = Field(pattern=r'^[a-f0-9]{64}$')
    catalog_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    request_id: uuid.UUID
    approved_synthetic_scope: StrictBool
    approved_local_source_processing: StrictBool


def attach_xml_mapping_routes(app, *, root, db, project, fresh=False):
    def selected(c, pid):
        sources = source_history.selected_sources(c, pid)
        return source_history._hash(sources), source_history.selected_source_set_id(c, pid)

    def get_run(c, pid, rid):
        row = c.execute('SELECT * FROM runs WHERE id=? AND project=?', (rid, pid)).fetchone()
        if row is None or not jobs.is_mapping_run(c, row):
            raise HTTPException(404, 'XML mapping run not found.')
        return dict(row)

    def assessment(c, pid):
        sources = source_history.selected_sources(c, pid)
        value = {'project_id': pid, 'source_hash': source_history._hash(sources),
            'selected_source_set_id': source_history.selected_source_set_id(c, pid),
            'source_binding': None, 'catalog_sha256': jobs.xml_mapping.mapping_catalog()['catalog_sha256'],
            'available': False, 'reason': None, 'source_count': len(sources), 'code_unit_count': None,
            'scope_notice': jobs.SCOPE_NOTICE}
        try:
            state, _, _ = jobs.source_state(c, pid)
            value.update(state)
            if fresh:
                value['reason'] = 'Local XML mapping is unavailable for fresh installations pending dedicated installation binding.'
            else:
                jobs._sqlcl_path()
                active = c.execute("SELECT 1 FROM runs WHERE state IN ('QUEUED','PROCESSING') LIMIT 1").fetchone()
                value.update(available=not active, reason='Another run is active. Wait for its retained outcome.' if active else None)
        except (ValueError, OSError, RuntimeError):
            value['reason'] = 'A complete supported Forms XML set and installed offline SQLcl compiler are required. No source was transmitted.'
        value['runs'] = [jobs.public_run(c, root, dict(row), value['source_hash'], value['selected_source_set_id'])
            for row in c.execute('SELECT * FROM runs WHERE project=? ORDER BY created DESC', (pid,))
            if jobs.is_mapping_run(c, row)]
        if value['available'] and any(row['state'] == 'ATTENTION' and row['source_hash'] == value['source_hash'] for row in value['runs']):
            value.update(available=False, reason='A prior mapping attempt for this source needs reconciliation. No uncertain attempt will be repeated.')
        return value

    @app.get('/api/projects/{pid}/xml-mapping')
    def mapping_scope(pid: str, request: Request):
        project(request, pid)
        with db() as c:
            c.execute('BEGIN')
            return assessment(c, pid)

    @app.post('/api/projects/{pid}/xml-mapping/runs', status_code=202)
    def queue_mapping(pid: str, body: MappingRequest, request: Request):
        p = project(request, pid)
        if fresh:
            raise HTTPException(503, 'Local XML mapping needs dedicated fresh-installation binding.', headers={'X-FOX-Admission': 'not-admitted'})
        content = body.model_dump(mode='json')
        # Canonical UUID plus project make an idempotent identity in the existing schema.
        rid = 'fox-' + jobs.sha(jobs.encoded([pid, content['request_id']]))[:20]
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            existing = c.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone()
            if existing is not None:
                if existing['project'] != pid:
                    raise HTTPException(409, 'Request identity conflicts with retained work.', headers={'X-FOX-Admission': 'uncertain'})
                try:
                    saved, _ = jobs.load_snapshot(c, root, existing)
                    if saved['request'] != content:
                        raise ValueError()
                except (ValueError, OSError, KeyError, TypeError):
                    raise HTTPException(409, 'This request identity has a different or uncertain retained outcome. Do not repeat it.', headers={'X-FOX-Admission': 'uncertain'}) from None
                current_hash, current_sid = selected(c, pid)
                return jobs.public_run(c, root, dict(existing), current_hash, current_sid)
            if not body.approved_synthetic_scope or not body.approved_local_source_processing:
                raise HTTPException(422, 'Confirm synthetic scope and local processing of the complete original XML, including unredacted source.', headers={'X-FOX-Admission': 'not-admitted'})
            try:
                state, sources, documents = jobs.source_state(c, pid)
                if any(content[key] != state[key] for key in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')):
                    raise HTTPException(409, 'Source version or installed mapping catalog changed. Review a fresh scope.', headers={'X-FOX-Admission': 'not-admitted'})
                jobs._sqlcl_path()
                # Run the real deterministic planner now to reject unsupported complete sets before queueing.
                jobs.xml_mapping.generate_xml_package(documents, pid, p['name'], POLICY_ID)
            except (ValueError, OSError, RuntimeError):
                raise HTTPException(409, 'The complete XML source set or installed SQLcl compiler is unavailable for this mapping scope.', headers={'X-FOX-Admission': 'not-admitted'}) from None
            if c.execute("SELECT 1 FROM runs WHERE state IN ('QUEUED','PROCESSING') LIMIT 1").fetchone():
                raise HTTPException(409, 'Another run is active. Wait for its retained outcome.', headers={'X-FOX-Admission': 'not-admitted'})
            for row in c.execute('SELECT * FROM runs WHERE project=? AND source_hash=?', (pid, body.source_hash)):
                if (jobs.is_mapping_run(c, row) and jobs.public_run(c, root, dict(row),
                        state['source_hash'], state['selected_source_set_id'])['state'] == 'ATTENTION'):
                    raise HTTPException(409, 'A prior mapping attempt for this source needs reconciliation. No uncertain attempt was repeated.', headers={'X-FOX-Admission': 'not-admitted'})
            now = time.time()
            snapshot = {'conversion_profile': jobs.PROFILE, 'project_id': pid, 'project_name': p['name'],
                **{key: state[key] for key in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')},
                'files': sources, 'policy_id': POLICY_ID, 'owner': p['owner'], 'approved_at': now,
                'request': content, 'scope_notice': jobs.SCOPE_NOTICE,
                'implementation_sources': jobs.xml_mapping.mapping_catalog()['implementation_sources']}
            raw = jobs.encoded(snapshot)
            job = jobs.job_path(root, rid)
            # A prior crash before the SQLite commit is uncertain, never overwritten/replayed.
            try:
                job.mkdir(parents=True, exist_ok=False)
                (job / 'source-snapshot.json').write_bytes(raw)
            except OSError:
                raise HTTPException(409, 'A retained request folder requires reconciliation. No operation was repeated.', headers={'X-FOX-Admission': 'uncertain'}) from None
            c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                (rid, pid, body.source_hash, 'QUEUED', 'Waiting for installed local XML mapping and offline format validation.', now, now, None))
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                (p['owner'], jobs.APPROVAL + jobs.sha(raw), rid, now))
            return jobs.public_run(c, root, get_run(c, pid, rid), state['source_hash'], state['selected_source_set_id'])

    @app.get('/api/projects/{pid}/xml-mapping/runs/{rid}')
    def mapping_run(pid: str, rid: str, request: Request):
        project(request, pid)
        with db() as c:
            c.execute('BEGIN')
            run = get_run(c, pid, rid)
            current_hash, current_sid = selected(c, pid)
            return jobs.public_run(c, root, run, current_hash, current_sid)

    @app.get('/api/projects/{pid}/xml-mapping/runs/{rid}/download')
    def mapping_download(pid: str, rid: str, request: Request):
        project(request, pid)
        with db() as c:
            c.execute('BEGIN')
            run = get_run(c, pid, rid)
            try:
                package, _ = jobs.checked_output(c, root, run)
            except (ValueError, OSError, KeyError, TypeError, RuntimeError):
                raise HTTPException(409, 'Source-bound mapping package or compiler proof is unavailable or changed. Download is blocked.') from None
        return Response(package, media_type='application/zip', headers={
            'Content-Disposition': f'attachment; filename="{rid}-APEXlang.zip"',
            'X-FOX-Runtime-Verified': 'false', 'X-FOX-Business-Acceptance': 'not-asserted'})
