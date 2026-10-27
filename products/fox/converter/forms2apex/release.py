"""Export and reimport evidence for the JSN POC; never declares business parity."""
import hashlib
import http.cookiejar
import json
import os
import re
import tempfile
import urllib.request
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from .security import alias_for_job
from .sqlcl import _run_script, _target_guard, _candidate_application_ids, _IMPORT_LOCK, validate_apexlang


_EXPORT_MANIFEST = '.export-complete.json'
_PUBLICATION_FILES = ('release-evidence.json', 'apex-package.zip', 'release-integrity.json')


def _sync_directory(path):
    # Windows cannot open a directory for fsync. Files themselves are flushed on
    # both platforms, and same-filesystem renames are the publication boundary.
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _write_bytes(path, value):
    with path.open('xb') as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def _atomic_json(path, value):
    temporary = path.with_name('.tmp-' + uuid.uuid4().hex)
    _write_bytes(temporary, json.dumps(value, sort_keys=True, indent=2).encode('utf-8'))
    temporary.replace(path)
    _sync_directory(path.parent)


def _tree_hashes(root, exclude=()):
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError('Export must be a regular directory')
    hashes = {}
    total = 0
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Export cannot contain symlinks')
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        if name in exclude:
            continue
        if not path.is_file() or '\\' in name or ':' in name or any(ord(c) < 32 for c in name):
            raise RuntimeError('Unsafe export member')
        total += path.stat().st_size
        if len(hashes) >= 480 or total > 18_000_000:
            raise RuntimeError('Export exceeds package size limits')
        hashes[name] = _file_digest(path)
    return hashes


def _verify_completed_export(root, job_id, binding, app_id, alias):
    export = root / 'export'
    completion = _read_object(export / _EXPORT_MANIFEST)
    if (completion.get('schema_version') != 1 or completion.get('job_id') != job_id
            or completion.get('artifact_binding') != binding
            or completion.get('application_id') != app_id or completion.get('application_alias') != alias
            or completion.get('imported_application_sha256') != _file_digest(root / 'imported-application.json')
            or completion.get('apexlang_validation_passed') is not True):
        raise RuntimeError('Export completion is not bound to this validated application')
    files = _tree_hashes(export, (_EXPORT_MANIFEST,))
    if not files or completion.get('files') != files:
        raise RuntimeError('Completed export files changed or are incomplete')
    if f'f{app_id}.sql' not in files or f'{alias.lower()}/application.apx' not in files:
        raise RuntimeError('Completed export lacks SQL or APEXlang')
    return completion


def _ensure_export(workflow, root, job_id, binding, app_id, alias, args, guard):
    export = root / 'export'
    receipt = root / 'package-reimport.json'
    intent = root / 'package-reimport-intent.json'
    if (export / _EXPORT_MANIFEST).exists():
        _verify_completed_export(root, job_id, binding, app_id, alias)
        return export
    # A receipt pins the exact SQL already imported. Never refresh that export,
    # bless old unbound files, or retry an import whose result is uncertain.
    if receipt.exists():
        _verify_reimport_receipt(export / f'f{app_id}.sql', receipt, alias_for_job(job_id + '-sqlcheck'))
        raise RuntimeError('Legacy export has no bound completion manifest; operator reconciliation required')
    if intent.exists():
        raise RuntimeError('A previous SQL reimport attempt needs operator reconciliation; no automatic retry')
    spec=_read_object(root/'migration-spec.json')
    preflight=workflow.native_target_preflight(job_id,'release') if 'native_form' in spec else None
    imported_digest = _file_digest(root / 'imported-application.json')
    if export.exists() or export.is_symlink():
        if export.is_symlink() or not export.is_dir():
            raise RuntimeError('Unsafe existing export directory')
        # Retain partial/unbound output for diagnostics, without certifying it.
        export.rename(root / ('.export-preserved-' + uuid.uuid4().hex))
        _sync_directory(root)
    attempt = Path(tempfile.mkdtemp(prefix='.export-attempt-', dir=root))
    result = _run_script(workflow.settings.sqlcl_path, args, [guard,
        f"select 'FOX_EXPORT_MATCH='||count(*) from apex_applications where workspace='{workflow.settings.apex_workspace}' and application_id={app_id} and upper(alias)='{alias}';",
        f'apex export -applicationid {app_id} -exptype SQL',
        f'apex export -applicationid {app_id} -exptype APEXLANG'], attempt)
    _write_bytes(attempt / 'export.log', (result.stdout + '\n' + result.stderr).encode('utf-8'))
    if result.returncode != 0 or not re.search(r'FOX_EXPORT_MATCH=1\b', result.stdout):
        raise RuntimeError('Export did not confirm the expected application; partial output retained')
    sql = attempt / f'f{app_id}.sql'
    exported_app = attempt / alias.lower()
    if not sql.is_file() or sql.stat().st_size < 1000 or not (exported_app / 'application.apx').is_file():
        raise RuntimeError('The actual SQL and APEXlang export files are incomplete')
    before = _tree_hashes(exported_app)
    sql_digest = _file_digest(sql)
    # A multifile export must be compiled as a project. Validating only the
    # application file loses sibling pages, shared components and MMD settings.
    validation = validate_apexlang(workflow.settings.sqlcl_path, exported_app, attempt / 'apexlang-validation.log')
    if not validation.get('passed'):
        raise RuntimeError('The actual APEXlang export failed SQLcl validation')
    if _tree_hashes(exported_app) != before or _file_digest(sql) != sql_digest:
        raise RuntimeError('Export changed during validation')
    if workflow.assert_artifact_binding(job_id) != binding:
        raise RuntimeError('Artifact binding changed during export')
    if _file_digest(root / 'imported-application.json') != imported_digest:
        raise RuntimeError('Imported application identity changed during export')
    completion = {'schema_version': 1, 'job_id': job_id, 'artifact_binding': binding,
        'application_id': app_id, 'application_alias': alias,
        'imported_application_sha256': imported_digest,
        'apexlang_validation_passed': True, 'files': _tree_hashes(attempt)}
    if preflight is not None:completion['target_preflight']=preflight
    # The manifest moves with the directory: a crash cannot expose an incomplete
    # canonical export. Orphan attempts are retained, and only export is retried.
    for path in attempt.rglob('*'):
        if path.is_file():
            with path.open('r+b') as handle:
                os.fsync(handle.fileno())
    for path in sorted((p for p in attempt.rglob('*') if p.is_dir()), key=lambda p:len(p.parts), reverse=True):
        _sync_directory(path)
    _atomic_json(attempt / _EXPORT_MANIFEST, completion)
    attempt.rename(export)
    _sync_directory(root)
    _verify_completed_export(root, job_id, binding, app_id, alias)
    return export


def runtime_login_check(url):
    result={'url':url,'scope':'login_page_reachability','authenticated_business_flow_tested':False,'passed':False}
    try:
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        with opener.open(url,timeout=30) as response:
            text=response.read(2_000_000).decode('utf-8',errors='replace')
            result.update(http_status=response.status,passed=response.status==200 and 'P9999_USERNAME' in text and 'P9999_PASSWORD' in text)
    except Exception as exc:
        result['error_type']=type(exc).__name__
    return result


def _file_digest(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Release integrity requires an existing regular file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_object(path):
    try:
        if path.is_symlink():
            raise ValueError('Symlink')
        value=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value,dict):
            raise ValueError('Object required')
        return value
    except (OSError,ValueError) as exc:
        raise RuntimeError('Release integrity metadata is missing or invalid') from exc


def _verify_reimport_receipt(sql,receipt_path,expected_alias=None):
    receipt=_read_object(receipt_path)
    if receipt.get('passed') is not True or receipt.get('sql_sha256')!=_file_digest(sql):
        raise RuntimeError('SQL export changed after reimport verification')
    if type(receipt.get('application_id')) is not int or receipt['application_id'] <= 0:
        raise RuntimeError('Reimport receipt application identity mismatch')
    if expected_alias is not None and receipt.get('application_alias')!=expected_alias:
        raise RuntimeError('Reimport receipt application identity mismatch')
    return receipt


def _verify_package_members(package,evidence_path,sql,receipt_path,exported_app=None):
    try:
        with zipfile.ZipFile(package) as archive:
            entries=archive.infolist()
            names=[entry.filename for entry in entries]
            if len(names)!=len(set(names)) or len(names)>500 or sum(entry.file_size for entry in entries)>20_000_000:
                raise ValueError('Invalid package member set')
            for entry in entries:
                path=PurePosixPath(entry.filename)
                mode=(entry.external_attr>>16)&0o170000
                if (path.is_absolute() or not path.parts or any(part in {'.','..'} for part in path.parts)
                        or '\\' in entry.filename or ':' in entry.filename or entry.is_dir()
                        or mode not in {0,0o100000} or entry.flag_bits&1):
                    raise ValueError('Unsafe package member')
            manifest=json.loads(archive.read('manifest.json'))
            if not isinstance(manifest,dict) or set(names)!=set(manifest)|{'manifest.json'}:
                raise ValueError('Incomplete package manifest')
            for name,digest in manifest.items():
                if not isinstance(digest,str) or not re.fullmatch(r'[a-f0-9]{64}',digest) or hashlib.sha256(archive.read(name)).hexdigest()!=digest:
                    raise ValueError('Package member hash mismatch')
            if exported_app is not None:
                expected={'apexlang/'+name:digest for name,digest in _tree_hashes(exported_app).items()}
                actual={name:digest for name,digest in manifest.items() if name.startswith('apexlang/')}
                if not expected or actual!=expected:
                    raise ValueError('Packaged APEXlang differs from the complete validated export')
            for member,path in [('evidence/release-evidence.json',evidence_path),
                                ('evidence/package-reimport.json',receipt_path),
                                (f'sql/{sql.name}',sql)]:
                if hashlib.sha256(archive.read(member)).hexdigest()!=_file_digest(path):
                    raise ValueError('Packaged evidence or SQL differs from the verified export')
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,RuntimeError) as exc:
        raise RuntimeError('Release package integrity verification failed') from exc


def _verify_cached_release(root,job_id,binding):
    integrity=_read_object(root/'release-integrity.json')
    if (integrity.get('schema_version')!=1 or integrity.get('job_id')!=job_id
            or integrity.get('artifact_binding')!=binding):
        raise RuntimeError('Cached release is not bound to the current validated artifact')
    evidence_path=root/'release-evidence.json'
    package=root/'apex-package.zip'
    if integrity.get('evidence_sha256')!=_file_digest(evidence_path) or integrity.get('package_sha256')!=_file_digest(package):
        raise RuntimeError('Cached release package or evidence changed')
    evidence=_read_object(evidence_path)
    app_id=evidence.get('application_id')
    if evidence.get('job_id')!=job_id or evidence.get('artifact_binding')!=binding or type(app_id) is not int or app_id<=0:
        raise RuntimeError('Cached release application identity is invalid')
    sql=root/'export'/f'f{app_id}.sql'
    if integrity.get('sql_sha256')!=_file_digest(sql):
        raise RuntimeError('Cached release SQL export changed')
    if 'export_completion_sha256' in integrity:
        if integrity['export_completion_sha256'] != _file_digest(root/'export'/_EXPORT_MANIFEST):
            raise RuntimeError('Cached export completion manifest changed')
        _verify_completed_export(root,job_id,binding,app_id,alias_for_job(job_id))
    receipt_path=root/'package-reimport.json'
    receipt=_verify_reimport_receipt(sql,receipt_path,alias_for_job(job_id+'-sqlcheck'))
    if evidence.get('package_reimport')!=receipt:
        raise RuntimeError('Cached release reimport evidence changed')
    exported_app=(root/'export'/alias_for_job(job_id).lower()) if 'export_completion_sha256' in integrity else None
    _verify_package_members(package,evidence_path,sql,receipt_path,exported_app)
    return evidence


def _recover_publication(root, job_id, binding):
    """Finish only a previously hashed publication; never certify new content."""
    journal = _read_object(root / 'release-publication.json')
    stage_name = journal.get('stage_directory', '')
    components = journal.get('components', {})
    if (journal.get('schema_version') != 1 or journal.get('job_id') != job_id
            or journal.get('artifact_binding') != binding
            or not isinstance(stage_name, str) or not re.fullmatch(r'\.release-publication-[a-zA-Z0-9_-]+', stage_name)
            or not isinstance(components, dict) or set(components) != set(_PUBLICATION_FILES)
            or any(not isinstance(v, str) or not re.fullmatch(r'[a-f0-9]{64}', v) for v in components.values())):
        raise RuntimeError('Publication journal is not bound to this validated artifact')
    stage = root / stage_name
    if stage.is_symlink() or (stage.exists() and not stage.is_dir()):
        raise RuntimeError('Unsafe publication staging directory')
    selected = {}
    for name in _PUBLICATION_FILES:
        present = [path for path in (root / name, stage / name) if path.exists() or path.is_symlink()]
        if not present or any(_file_digest(path) != components[name] for path in present):
            raise RuntimeError('Pending publication component missing or changed; operator reconciliation required')
        selected[name] = present[0]
    evidence = _read_object(selected['release-evidence.json'])
    integrity = _read_object(selected['release-integrity.json'])
    app_id = evidence.get('application_id')
    if (type(app_id) is not int or app_id <= 0 or evidence.get('job_id') != job_id
            or evidence.get('artifact_binding') != binding or integrity.get('schema_version') != 1
            or integrity.get('job_id') != job_id or integrity.get('artifact_binding') != binding
            or integrity.get('package_sha256') != components['apex-package.zip']
            or integrity.get('evidence_sha256') != components['release-evidence.json']
            or integrity.get('export_completion_sha256') != _file_digest(root / 'export' / _EXPORT_MANIFEST)):
        raise RuntimeError('Pending publication evidence binding mismatch')
    _verify_completed_export(root, job_id, binding, app_id, alias_for_job(job_id))
    sql = root / 'export' / f'f{app_id}.sql'
    receipt_path = root / 'package-reimport.json'
    receipt = _verify_reimport_receipt(sql, receipt_path, alias_for_job(job_id + '-sqlcheck'))
    if (integrity.get('sql_sha256') != _file_digest(sql) or evidence.get('package_reimport') != receipt
            or journal.get('reimport_receipt_sha256') != _file_digest(receipt_path)):
        raise RuntimeError('Pending publication SQL reimport evidence changed')
    _verify_package_members(selected['apex-package.zip'], selected['release-evidence.json'], sql, receipt_path,
                            root/'export'/alias_for_job(job_id).lower())
    # The journal and every component were durable before any public name was
    # written. Each rename can be retried independently without SQL or network.
    for name in _PUBLICATION_FILES:
        target = root / name
        if not target.exists():
            (stage / name).replace(target)
            _sync_directory(root)
    return _verify_cached_release(root, job_id, binding)


def finalize_release(workflow,job_id):
    root=workflow.store.require(job_id)
    binding=workflow.assert_artifact_binding(job_id)
    status=workflow.status(job_id)
    if status['state']!='IMPORTED' or not status.get('validation',{}).get('passed'):
        raise RuntimeError('A reviewed, validated and imported job is required before export')
    evidence_path=root/'release-evidence.json'
    package=root/'apex-package.zip'
    if (root/'release-publication.json').exists():
        evidence=_recover_publication(root,job_id,binding)
        if workflow.assert_artifact_binding(job_id)!=binding:
            raise RuntimeError('Artifact binding changed during release')
        return evidence
    if package.exists() or (root/'release-integrity.json').exists():
        evidence=_verify_cached_release(root,job_id,binding)
        if workflow.assert_artifact_binding(job_id)!=binding:
            raise RuntimeError('Artifact binding changed during release')
        return evidence
    if evidence_path.exists() or evidence_path.is_symlink():
        raise RuntimeError('Unbound release evidence requires operator reconciliation')
    settings=workflow.settings
    app=_read_object(root/'imported-application.json')
    app_id=app.get('application_id')
    if type(app_id) is not int or app_id<=0:
        raise RuntimeError('Imported application identity mismatch')
    alias=alias_for_job(job_id)
    if app['application_alias']!=alias or app['workspace']!=settings.apex_workspace:
        raise RuntimeError('Imported application identity mismatch')
    args=['-S','-L','-name',settings.sqlcl_connection_name]
    guard=_target_guard(settings.apex_workspace)
    export=_ensure_export(workflow,root,job_id,binding,app_id,alias,args,guard)
    spec=_read_object(root/'migration-spec.json')
    is_native='native_form' in spec
    sql=export/f'f{app_id}.sql'
    exported_app=export/alias.lower()
    test_job=job_id+'-sqlcheck'
    test_alias=alias_for_job(test_job)
    receipt=root/'package-reimport.json'
    intent=root/'package-reimport-intent.json'
    with _IMPORT_LOCK:
        if receipt.exists():
            _verify_reimport_receipt(sql,receipt,test_alias)
        else:
            if intent.exists():
                raise RuntimeError('A previous SQL reimport attempt needs operator reconciliation; no automatic retry')
            preflight=workflow.native_target_preflight(job_id,'release') if is_native else None
            candidates=_candidate_application_ids(test_job)
            pre=_run_script(settings.sqlcl_path,args,[guard,
                f"select 'FOX_ALIAS_COUNT='||count(*) from apex_applications where workspace='{settings.apex_workspace}' and upper(alias)='{test_alias}';",
                "select 'FOX_USED_ID='||application_id from apex_applications where application_id in ("+','.join(map(str,candidates))+');'],root)
            if pre.returncode or not re.search(r'FOX_ALIAS_COUNT=0\b',pre.stdout):
                raise RuntimeError('Reimport alias is not proven absent; existing applications are preserved')
            used=set(map(int,re.findall(r'FOX_USED_ID=(\d+)',pre.stdout)))
            test_id=next((i for i in candidates if i not in used),None)
            if test_id is None: raise RuntimeError('No free reimport application ID')
            _verify_completed_export(root,job_id,binding,app_id,alias)
            sql_digest=_file_digest(sql)
            if preflight is not None:workflow.assert_native_preflight_fresh(job_id,preflight,'release')
            reservation={'application_id':test_id,'alias':test_alias,'job_id':job_id,
                'artifact_binding':binding,'sql_sha256':sql_digest}
            if preflight is not None:reservation['target_preflight']=preflight
            _atomic_json(intent,reservation)
            parsing_schema=settings.apex_parsing_schema if is_native else settings.apex_workspace
            if preflight is not None:workflow.assert_native_preflight_fresh(job_id,preflight,'release')
            result=_run_script(settings.sqlcl_path,args,[guard,
                f"begin apex_application_install.set_workspace('{settings.apex_workspace}'); apex_application_install.set_schema('{parsing_schema}'); apex_application_install.set_application_id({test_id}); apex_application_install.generate_offset; apex_application_install.set_application_alias('{test_alias}'); end;\n/",
                '@'+sql.resolve().as_posix(),
                f"select 'FOX_REIMPORT_MATCH='||count(*) from apex_applications where workspace='{settings.apex_workspace}' and application_id={test_id} and upper(alias)='{test_alias}';"],root,timeout=1200)
            (root/'package-reimport.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf-8')
            if result.returncode or not re.search(r'FOX_REIMPORT_MATCH=1\b',result.stdout):
                raise RuntimeError('The conventional SQL export did not pass reimport verification')
            if _file_digest(sql)!=sql_digest:
                raise RuntimeError('SQL export changed during reimport; operator reconciliation required')
            checked={'passed':True,'application_id':test_id,'application_alias':test_alias,'sql_sha256':sql_digest}
            if preflight is not None:checked['target_preflight']=preflight
            _atomic_json(receipt,checked)
    _verify_reimport_receipt(sql,receipt,test_alias)
    smoke=runtime_login_check(app['application_url'])
    (root/'smoke-test-report.json').write_text(json.dumps(smoke,indent=2),encoding='utf-8')
    if not smoke['passed']: raise RuntimeError('The imported APEX login page is not reachable')
    manifest=json.loads((root/'intake/manifest.json').read_text())
    spec=json.loads((root/'migration-spec.json').read_text())
    is_native='native_form' in spec
    native_review=workflow.verify_native_review(root,spec) if is_native else None
    from .review_receipts import review_proof_scope
    scope=('Native APEX Interactive Report and table form; synthetic test schema; query/insert/update only; customer business logic not converted'
           if is_native else 'Single-page read-only HTML prototype in APEX; synthetic data; not native CRUD or functional equivalence')
    evidence={'job_id':job_id,'source_manifest_sha256':manifest.get('source_manifest_sha256'),'artifact_binding':binding,
        'reviewer':spec.get('reviewer'),'remediation_items':spec.get('remediation_items',[]),'mapping_summary':spec.get('mapping_summary'),
        'reviewer_approved':True,'sqlcl_valid':True,'import_passed':True,'runtime_smoke_passed':True,
        'runtime_smoke_scope':'login_page_reachability_only','business_acceptance_required':True,
        'package_reimport_passed':True,'application_id':app_id,'application_alias':alias,
        'application_url':app['application_url'],'prototype_scope':scope,
        'conversion_profile':'native-table-form-v1' if is_native else 'read-only-html-prototype',
        'reviewer_execution_verified':is_native,
        'review_receipt_sha256':native_review['receipt_sha256'] if native_review else None,
        'review_proof_scope':review_proof_scope(native_review) if native_review else None,
        'model_environment_verified':bool(native_review and native_review.get('schema_version')==2),
        'authenticated_runtime_passed':False,'clean_schema_install_passed':False,
        'native_schema_verification':app.get('native_schema_verification') if is_native else None,
        'package_reimport':json.loads(receipt.read_text())}
    stage=Path(tempfile.mkdtemp(prefix='.release-publication-',dir=root))
    evidence_path=stage/'release-evidence.json'
    _write_bytes(evidence_path,json.dumps(evidence,indent=2).encode('utf-8'))
    readme='''FOX prototype package\n\nThis is a read-only, synthetic-data prototype, not a complete Forms migration.\nRequires Oracle APEX 26.1.4 or compatible later 26.1 patch, an existing workspace and parsing schema, and an APEX workspace account.\n\nManual import: in APEX App Builder choose Import, select sql/fNNN.sql, choose the intended workspace/parsing schema and a NEW application ID and alias. Never replace an existing application. Review authentication and all remediation items before use.\n\nThe apexlang directory is an actual SQLcl export. Validate it using SQLcl 26.1 before importing to a different target. Database transaction behavior and desktop integrations have not been converted.\n\nTechnical evidence includes SQLcl validation, first import and conventional SQL export reimport to a second unique application in JSN. Runtime automation verifies the protected login page only. Human testing of report/search/details and remediation acceptance is required before release. No passwords, wallet or API keys are included.\n'''
    if is_native:
        readme='''FOX native APEX table-form package\n\nThis application contains native Interactive Report and Form components with query/insert/update. It uses an explicitly synthetic test table; it is not a complete conversion of customer Forms transaction logic.\n\nIn an explicitly selected empty test parsing schema, run schema/01_synthetic_schema.sql before importing sql/fNNN.sql into the mapped APEX workspace. The schema script creates only the table declared by native-form-spec.json, fails if it already exists, and contains no records, credentials or business APIs. Confirm actual APEX/SQLcl compatibility and authentication; select a NEW application ID and alias, never replace an existing app.\n\nSQLcl validation and recorded JSN imports do not prove business equivalence. This package records login-page reachability only. Authenticated functional tests and clean-schema installation evidence are detached receipts bound to this exact ZIP hash; they must be supplied separately before release acceptance. Review all remediation and prerequisites.\n'''
    members={f'sql/{sql.name}':sql.read_bytes(),'README.txt':readme.encode()}
    if is_native:
        from .native_schema import render_native_schema
        members['native-form-spec.json']=json.dumps(spec['native_form'],indent=2).encode()
        members['schema/01_synthetic_schema.sql']=render_native_schema(spec['native_form']).encode()
        members['evidence/native-review.json']=(root/'native-review.json').read_bytes()
        if native_review['schema_version']==2:
            # Copy the sealed historical document, never substitute today's
            # active target or make package verification require live OPAF.
            from .target_profile import validate_historical_target_profile
            historical=validate_historical_target_profile(native_review['historical_target_profile'])
            members['evidence/target-profile.json']=json.dumps(historical,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
        # Preserve only actual new probe evidence; never backfill retained
        # packages or imply that old v1 model receipts contain version proof.
        references=[status.get('validation',{}).get('target_preflight'),app.get('target_preflight'),
                    _read_object(export/_EXPORT_MANIFEST).get('target_preflight'),
                    _read_object(receipt).get('target_preflight')]
        for reference in references:
            if reference is None:continue
            name=reference.get('file') if isinstance(reference,dict) else None
            if (not isinstance(name,str) or not re.fullmatch(r'target-check-(?:validate|import|reconcile|release)-[a-f0-9]{16}\.json',name)
                    or _file_digest(root/name)!=reference.get('sha256')):
                raise RuntimeError('Native target preflight evidence is missing or changed')
            members['evidence/'+name]=(root/name).read_bytes()
    for path in exported_app.rglob('*'):
        if path.is_file(): members['apexlang/'+path.relative_to(exported_app).as_posix()]=path.read_bytes()
    for name in ['normalized-forms-inventory.json','migration-and-exception-report.json','migration-spec.json','validation-results.log','imported-application.json','package-reimport.json','smoke-test-report.json']:
        members['evidence/'+name]=(root/name).read_bytes()
    members['evidence/release-evidence.json']=evidence_path.read_bytes()
    members['evidence/export-completion.json']=(export/_EXPORT_MANIFEST).read_bytes()
    members['evidence/export-validation.log']=(export/'apexlang-validation.log').read_bytes()
    if workflow.assert_artifact_binding(job_id)!=binding:
        raise RuntimeError('Artifact binding changed during release')
    _verify_reimport_receipt(sql,receipt,test_alias)
    members['manifest.json']=json.dumps({name:hashlib.sha256(data).hexdigest() for name,data in members.items()},indent=2).encode()
    package=stage/'apex-package.zip'
    with zipfile.ZipFile(package,'x',zipfile.ZIP_DEFLATED) as archive:
        for name,data in members.items(): archive.writestr(name,data)
    with package.open('r+b') as handle:
        os.fsync(handle.fileno())
    _verify_package_members(package,evidence_path,sql,receipt,exported_app)
    if workflow.assert_artifact_binding(job_id)!=binding:
        raise RuntimeError('Artifact binding changed during release')
    integrity={'schema_version':1,'job_id':job_id,'artifact_binding':binding,
        'package_sha256':_file_digest(package),'evidence_sha256':_file_digest(evidence_path),
        'sql_sha256':_file_digest(sql),'export_completion_sha256':_file_digest(export/_EXPORT_MANIFEST)}
    _atomic_json(stage/'release-integrity.json',integrity)
    _sync_directory(stage)
    _verify_completed_export(root,job_id,binding,app_id,alias)
    _atomic_json(root/'release-publication.json',{'schema_version':1,'job_id':job_id,'artifact_binding':binding,
        'stage_directory':stage.name,'components':{name:_file_digest(stage/name) for name in _PUBLICATION_FILES},
        'reimport_receipt_sha256':_file_digest(receipt)})
    evidence=_recover_publication(root,job_id,binding)
    if workflow.assert_artifact_binding(job_id)!=binding:
        raise RuntimeError('Artifact binding changed during release')
    return evidence
