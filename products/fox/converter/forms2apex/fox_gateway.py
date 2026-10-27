"""Bearer-protected FOX handoff routes, exposed only on VM loopback."""
import asyncio
import hashlib
import hmac
import json
import re
import tempfile
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from starlette.responses import JSONResponse, Response
from .release import finalize_release, _verify_cached_release, _read_object
from .security import assert_no_secrets
from .native_contract import validate_native_spec
from .review_receipts import record_review
from .provenance import inspection_binding
from . import native_project, project_reviews
from .project_workflow import ProjectWorkflow
from .workflow_router import WorkflowRouter, capabilities
from .project_release import finalize_project_release, verify_project_cached_release

_RELEASE_LOCK=threading.Lock()


def stage_snapshot(root,job_id,snapshot):
    if not isinstance(snapshot,dict):raise ValueError('Source snapshot must be an object')
    if not re.fullmatch(r'fox-[a-f0-9]{20}',job_id): raise ValueError('Invalid FOX job ID')
    if not re.fullmatch(r'[a-f0-9]{64}',snapshot.get('source_hash','')): raise ValueError('Approved manifest hash required')
    files=snapshot.get('files',[])
    if not isinstance(files,list) or not 1<=len(files)<=50: raise ValueError('One to fifty readable files required')
    validated=[]; names=set(); total=0
    for file in files:
        if not isinstance(file,dict):raise ValueError('Source entries must be objects')
        name=file.get('name',''); content=file.get('text')
        if not name or '/' in name or '\\' in name or '..' in name or ':' in name or len(name)>180 or any(ord(c)<32 for c in name): raise ValueError('Unsafe source filename')
        if Path(name).suffix.lower() not in {'.xml','.pld','.sql','.pks','.pkb','.txt'} or not isinstance(content,str): raise ValueError('Readable text only')
        if name in names: raise ValueError('Duplicate source filename')
        names.add(name); raw=content.encode()
        if hashlib.sha256(raw).hexdigest()!=file.get('sha256') and hashlib.sha256(b'\xef\xbb\xbf'+raw).hexdigest()==file.get('sha256'):
            raw=b'\xef\xbb\xbf'+raw
        total+=len(raw)
        if not raw or total>300000 or '\x00' in content: raise ValueError('Nonempty readable source under 300 KB required')
        if hashlib.sha256(raw).hexdigest()!=file.get('sha256'): raise ValueError('Source hash mismatch')
        assert_no_secrets(content,name)
        if re.search(r'<!DOCTYPE|<!ENTITY|\b(?:INSERT\s+INTO|MERGE\s+INTO)\b',content,re.I): raise ValueError('Unsafe XML or data-loading source')
        if name.lower().endswith('.xml'): ET.fromstring(content)
        validated.append((name,raw,file['sha256']))
    calculated=hashlib.sha256('\n'.join(name+':'+digest for name,raw,digest in sorted(validated)).encode()).hexdigest()
    if calculated!=snapshot['source_hash']:raise ValueError('Source manifest hash mismatch')
    native_form=None
    if snapshot.get('conversion_profile') not in {None,'read-only-html-prototype','native-table-form-v1'}:
        raise ValueError('Unknown or unsupported conversion profile')
    if snapshot.get('native_project') is not None:
        raise ValueError('Project metadata requires the project staging contract')
    if snapshot.get('conversion_profile')=='native-table-form-v1':
        native_form=validate_native_spec(snapshot.get('native_form'))
    elif snapshot.get('native_form') is not None:
        raise ValueError('Native metadata requires the native conversion profile')
    target=root/job_id
    if target.exists() or target.is_symlink(): raise FileExistsError('Job already exists; reconcile instead of replaying')
    temp=Path(tempfile.mkdtemp(prefix='.fox-intake-',dir=root))
    try:
        intake=temp/'intake';intake.mkdir()
        manifest=[]
        for name,raw,digest in validated:
            (intake/name).write_bytes(raw)
            manifest.append({'packaged_name':name,'source_kind':'approved_readable_source','sha256':digest})
        value={'job_id':job_id,'source_manifest_sha256':snapshot['source_hash'],'files':manifest}
        if native_form is not None:value.update(conversion_profile='native-table-form-v1',native_form=native_form)
        (intake/'manifest.json').write_text(json.dumps(value),encoding='utf-8')
        project_reviews.publish_directory(temp,target)
    finally:
        project_reviews.cleanup_temporary(temp,root,'.fox-intake-')
    return {'job_id':job_id,'state':'INTAKE_READY','source_manifest_sha256':snapshot['source_hash']}


def attach_routes(mcp,workflow,settings):
    router=workflow if isinstance(workflow,WorkflowRouter) else WorkflowRouter(settings,legacy=workflow)

    def authorized(request):
        return hmac.compare_digest(request.headers.get('authorization','').encode(),('Bearer '+settings.bearer_token).encode())

    class PayloadTooLarge(ValueError):
        pass

    async def body(request,limit):
        raw=bytearray()
        async for chunk in request.stream():
            if len(raw)+len(chunk)>limit:raise PayloadTooLarge()
            raw.extend(chunk)
        return json.loads(raw or b'{}',object_pairs_hook=project_reviews.review_receipts._unique_keys,
                          parse_constant=lambda value:(_ for _ in ()).throw(ValueError('Nonfinite JSON is not permitted')))

    @mcp.custom_route('/fox/capabilities',methods=['GET'],include_in_schema=False)
    async def installed_capabilities(request):
        if not authorized(request):return JSONResponse({'error':'Unauthorized'},status_code=401)
        try:return JSONResponse(capabilities(router.target_profile()))
        except (ImportError,ValueError,TypeError,RuntimeError,OSError):
            return JSONResponse({'error':'Installed conversion capabilities could not be verified'},status_code=409)

    @mcp.custom_route('/fox/target-profile',methods=['GET'],include_in_schema=False)
    async def target_profile(request):
        if not authorized(request):return JSONResponse({'error':'Unauthorized'},status_code=401)
        try:
            from .target_profile import target_profile_sha256
            profile=router.target_profile()
            return JSONResponse({'target_profile':profile,'target_profile_sha256':target_profile_sha256(profile)})
        except (ValueError,TypeError,RuntimeError,OSError):
            return JSONResponse({'error':'Active target profile is not configured or does not match the deployment'},status_code=409)

    @mcp.custom_route('/fox/jobs/{job_id}',methods=['POST','GET'],include_in_schema=False)
    async def job(request):
        if not authorized(request): return JSONResponse({'error':'Unauthorized'},status_code=401)
        job_id=request.path_params['job_id']
        try:
            if request.method=='POST':
                value=await body(request,1_000_000)
                if not isinstance(value,dict):raise ValueError('Source snapshot must be an object')
                stage=project_reviews.stage_project_snapshot if value.get('conversion_profile')==native_project.PROFILE_ID else stage_snapshot
                return JSONResponse(stage(settings.jobs_root,job_id,value),status_code=201)
            selected=router.select(job_id)
            status=selected.status(job_id)
            root=selected.store.require(job_id)
            manifest=project_reviews.read_object(root/'intake/manifest.json')
            result={'job_id':job_id,'state':status['state'],'source_manifest_sha256':manifest.get('source_manifest_sha256'),
                    'conversion_profile':manifest.get('conversion_profile'),'native_form':manifest.get('native_form'),
                    'import_intent_exists':(root/'import-intent.json').exists(),
                    'validation':status.get('validation'),'import':status.get('import')}
            if isinstance(selected,ProjectWorkflow):
                result.update(native_project=manifest['native_project'],artifact_binding=status.get('artifact_binding'),
                              schema_preparation=status.get('schema_preparation'),
                              schema_intent_exists=status.get('schema_intent_exists',False),
                              import_reconciliation_required=status.get('import_reconciliation_required',False))
            return JSONResponse(result)
        except PayloadTooLarge:return JSONResponse({'error':'Source package too large'},status_code=413)
        except FileExistsError: return JSONResponse({'error':'Existing job will not be overwritten'},status_code=409)
        except (ValueError,KeyError,TypeError,ET.ParseError): return JSONResponse({'error':'Invalid or unsafe source package'},status_code=422)
        except FileNotFoundError: return JSONResponse({'error':'Job not found'},status_code=404)
        except RuntimeError:return JSONResponse({'error':'Job evidence changed; existing source is preserved'},status_code=409)

    @mcp.custom_route('/fox/jobs/{job_id}/review',methods=['POST'],include_in_schema=False)
    async def review(request):
        if not authorized(request):return JSONResponse({'error':'Unauthorized'},status_code=401)
        try:
            selected=router.select(request.path_params['job_id'])
            value=await body(request,256_000)
            root=selected.store.require(request.path_params['job_id'])
            if isinstance(selected,ProjectWorkflow):
                receipt=project_reviews.aggregate_project_review(root,value,*selected.review_identity())
                # FOX verifies and checkpoints the complete sealed parent,
                # including per-form source/mapping bindings and resume evidence.
                return JSONResponse(receipt)
            receipt=record_review(root,value,*selected.review_identity(),target_profile=selected.review_target_profile())
            return JSONResponse({'job_id':root.name,'verdict':receipt['review']['verdict'],'candidate_sha256':receipt['candidate_sha256'],'receipt_sha256':receipt['receipt_sha256']})
        except PayloadTooLarge:return JSONResponse({'error':'Review evidence too large'},status_code=413)
        except (ValueError,KeyError,TypeError,RuntimeError,FileNotFoundError):
            return JSONResponse({'error':'Review evidence rejected; source and existing receipt preserved'},status_code=409)

    @mcp.custom_route('/fox/jobs/{job_id}/reviews/{module_id}',methods=['POST'],include_in_schema=False)
    async def form_review(request):
        if not authorized(request):return JSONResponse({'error':'Unauthorized'},status_code=401)
        try:
            selected=router.select(request.path_params['job_id'])
            if not isinstance(selected,ProjectWorkflow):return JSONResponse({'error':'Unknown action'},status_code=404)
            value=await body(request,256_000)
            root=selected.store.require(request.path_params['job_id'])
            receipt=project_reviews.record_project_form_review(root,request.path_params['module_id'],value,
                        *selected.review_identity(),target_profile=selected.review_target_profile())
            return JSONResponse({'job_id':root.name,'module_id':request.path_params['module_id'],
                'child_job_id':receipt['job_id'],'verdict':receipt['review']['verdict'],
                'candidate_sha256':receipt['candidate_sha256'],'receipt_sha256':receipt['receipt_sha256']})
        except PayloadTooLarge:return JSONResponse({'error':'Review evidence too large'},status_code=413)
        except (ValueError,KeyError,TypeError,RuntimeError,FileNotFoundError):
            return JSONResponse({'error':'Review evidence rejected; source and existing receipt preserved'},status_code=409)

    @mcp.custom_route('/fox/jobs/{job_id}/actions/{action}',methods=['POST'],include_in_schema=False)
    async def action(request):
        if not authorized(request):return JSONResponse({'error':'Unauthorized'},status_code=401)
        selected=request.path_params['action'];jid=request.path_params['job_id']
        if selected not in {'inspect','generate','validate','import','reconcile-import','prepare-schema','reconcile-schema'}:return JSONResponse({'error':'Unknown action'},status_code=404)
        try:
            chosen=router.select(jid)
            project=isinstance(chosen,ProjectWorkflow)
            if selected in {'prepare-schema','reconcile-schema'} and not project:
                return JSONResponse({'error':'Unknown action'},status_code=404)
            value=await body(request,4_000_000 if project and selected=='generate' else 256_000)
            if project and selected!='generate' and value!={}:raise ValueError('This action accepts no payload fields')
            def execute():
                state=chosen.status(jid)
                if selected=='inspect' and state['state']=='INSPECTED' and not project:
                    root=chosen.store.require(jid)
                    if inspection_binding(root)!=state.get('inspection_binding'):raise RuntimeError('Inspection changed')
                    return json.loads((root/'normalized-forms-inventory.json').read_text())
                if selected=='inspect':return chosen.inspect(jid)
                if selected=='generate':return chosen.generate(jid,json.dumps(value))
                if selected=='validate':return chosen.validate(jid)
                if selected=='prepare-schema':return chosen.prepare_schema(jid)
                if selected=='reconcile-schema':return chosen.reconcile_schema(jid)
                if selected=='reconcile-import':return chosen.reconcile_import(jid)
                return chosen.import_draft(jid)
            return JSONResponse(await asyncio.to_thread(execute))
        except PayloadTooLarge:return JSONResponse({'error':'Action payload too large'},status_code=413)
        except (ValueError,KeyError,TypeError,RuntimeError,FileNotFoundError):
            return JSONResponse({'error':'Conversion action blocked; reconcile existing evidence before retry'},status_code=409)

    @mcp.custom_route('/fox/jobs/{job_id}/release',methods=['POST'],include_in_schema=False)
    async def release(request):
        if not authorized(request): return JSONResponse({'error':'Unauthorized'},status_code=401)
        def execute():
            chosen=router.select(request.path_params['job_id'])
            finalizer=finalize_project_release if isinstance(chosen,ProjectWorkflow) else finalize_release
            with _RELEASE_LOCK: return finalizer(chosen,request.path_params['job_id'])
        try:
            value=await body(request,256_000)
            if value!={}:raise ValueError('Release accepts no payload fields')
            return JSONResponse(await asyncio.to_thread(execute))
        except PayloadTooLarge:return JSONResponse({'error':'Action payload too large'},status_code=413)
        except (RuntimeError,ValueError,TypeError,KeyError,FileNotFoundError):
            return JSONResponse({'error':'Release checks failed; existing job retained for operator review'},status_code=409)

    @mcp.custom_route('/fox/jobs/{job_id}/package',methods=['GET'],include_in_schema=False)
    async def package(request):
        if not authorized(request): return JSONResponse({'error':'Unauthorized'},status_code=401)
        try:
            root=router.store.require(request.path_params['job_id'])
            if not (root/'release-evidence.json').is_file() or not (root/'apex-package.zip').is_file():
                return JSONResponse({'error':'Package not ready'},status_code=409)
            chosen=router.select(request.path_params['job_id'])
            if chosen.status(request.path_params['job_id'])['state'] != 'IMPORTED':
                raise RuntimeError('An imported job is required')
            binding=chosen.assert_artifact_binding(request.path_params['job_id'])
            verifier=verify_project_cached_release if isinstance(chosen,ProjectWorkflow) else _verify_cached_release
            verifier(root,request.path_params['job_id'],binding)
            expected=_read_object(root/'release-integrity.json')['package_sha256']
            payload=(root/'apex-package.zip').read_bytes()
            if hashlib.sha256(payload).hexdigest()!=expected or chosen.assert_artifact_binding(request.path_params['job_id'])!=binding:
                raise RuntimeError('Package changed during download')
            return Response(payload,media_type='application/zip')
        except (RuntimeError,KeyError,TypeError):
            return JSONResponse({'error':'Package integrity is not verified; existing job retained'},status_code=409)
        except (ValueError,FileNotFoundError): return JSONResponse({'error':'Job not found'},status_code=404)
