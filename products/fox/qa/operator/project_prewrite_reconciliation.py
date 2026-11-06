"""Pure failed-project-QA classification before business writes, never promotion.

The 22-file completed/failed QA transcript is deliberately not the 17-file
staging failure or the native single-form failure contract. Captures are data,
not host-exclusion authority; protected integration must freshly observe the
actual current installation and producers under its real OS lease.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit

from . import contracts as c, project_contracts as pc, product_queue_transport as bridge
from . import product_verifier as verifier, project_qa_contracts as preparation
from .qa_stage_reconciliation import _decode, _capture_digest, CLEAN_FILES, PHASES
from fox.verification_queue import VerificationBinding, VerificationQueue
from fox.native_qa_plan import qa_plan_sha256
from fox.project_qa_plan import derive_project_qa_plan

CAPTURE_SCOPE = 'fox-project-prewrite-qa-capture-v1'
SCOPE = 'fox-project-prewrite-qa-assessment-v1'
STEPS = ('prepare', 'clean_check', *PHASES, 'qa_stage', 'qa_run', 'qa_collect')
COLLECTION_FILES = frozenset({'package.zip','native-project-spec.json','source-to-apex.json',
    'allocation-receipt.json','verification-profile.json','clean-import-receipt.json',
    'qa-profile.json','target-receipt.json','qa-result.json','stage-receipt.json',
    'launch-intent.json','launch-receipt.json'})
QA_FILES = frozenset({'package.json','package-lock.json','run-project.mjs','lib/contracts.mjs',
    'lib/package-evidence.mjs','lib/project-profile.mjs','lib/project-runner-inputs.mjs',
    'lib/project-runtime.mjs','lib/project-browser.mjs'})
HASH = re.compile(r'[a-f0-9]{64}\Z')


class ProjectPrewriteEvidenceError(ValueError):
    """Fixed categories only; never captured text, tokens or credentials."""


def need(ok, code):
    if not ok:
        raise ProjectPrewriteEvidenceError(code)


def _journal(capture, binding, queue, manifest):
    encoded=capture['journal'];release=binding.verifier_release_sha256
    expected={'session.json','attention.json',*('p0001-'+s.replace('_','-')+suffix
        for s in ('claim',*STEPS) for suffix in ('.intent.json','.complete.json'))}
    need(type(encoded) is dict and set(encoded)==expected,'PROJECT_PREWRITE_JOURNAL_MEMBERS')
    raw={name:_decode(value,65536) for name,value in encoded.items()}
    docs={name:c.load_json(value) for name,value in raw.items()}
    header=docs['session.json']
    need(set(header)=={'scope','release_sha256','started_at_utc','bounds','startup_authorized'}
        and header['scope']=='fox-product-verifier-session-v1' and header['release_sha256']==release
        and header['startup_authorized'] is True,'PROJECT_PREWRITE_SESSION')
    c._timestamp(header['started_at_utc']);bounds=header['bounds']
    need(type(bounds) is dict and set(bounds)=={'max_jobs','max_polls','max_seconds','poll_seconds'}
        and all(type(v) is int for v in bounds.values()) and bounds['max_jobs']==1
        and 1<=bounds['max_polls']<=120 and 1<=bounds['max_seconds']<=7200
        and 1<=bounds['poll_seconds']<=60,'PROJECT_PREWRITE_BOUNDS')
    need(docs['attention.json']=={'status':'ATTENTION','release_sha256':release,'known_claim':True,
        'code':'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE','automatic_replay_permitted':False},'PROJECT_PREWRITE_ATTENTION')
    results={};context={}
    for step in ('claim',*STEPS):
        label='p0001-'+step.replace('_','-');intent=docs[label+'.intent.json'];done=docs[label+'.complete.json']
        need(intent=={'scope':'fox-product-verifier-step-v1','release_sha256':release,'step':label,
            'binding_sha256':None if step=='claim' else c.digest(c.canonical_bytes(binding.payload()))},'PROJECT_PREWRITE_INTENT')
        need(set(done)=={'scope','release_sha256','intent_sha256','result'}
            and done['scope']=='fox-product-verifier-step-result-v1' and done['release_sha256']==release
            and done['intent_sha256']==c.digest(raw[label+'.intent.json']),'PROJECT_PREWRITE_COMPLETION')
        results[step]=done['result']
        if step=='claim':
            need(done['result']=={'status':'CLAIMED','claim':{'binding':binding.payload(),'attempt_token':queue['claim_token']}},'PROJECT_PREWRITE_CLAIM')
        else:context.update(verifier.safe_phase(step,done['result'],binding,context,manifest))
    need(context['conversion_profile']=='native-project-v1'
        and results['qa_run']['status']=='QA_FAILED_OR_INCOMPLETE'
        and type(results['qa_run']['exit_code']) is int and results['qa_run']['exit_code']==2,'PROJECT_PREWRITE_TERMINAL_QA')
    return raw,results,context


def _clean(capture, binding, manifest, context, results):
    encoded=capture['clean'];need(type(encoded) is dict and set(encoded)==CLEAN_FILES,'PROJECT_PREWRITE_CLEAN_MEMBERS')
    files={name:_decode(value,8_000_000 if name=='package.zip' else 2_000_000) for name,value in encoded.items()}
    plan=pc.validate_plan(files['plan.json'],operator_code_sha256=manifest['project']['clean_operator_code_sha256'])
    need(c.digest(files['plan.json'])==context['plan_sha256'] and all(plan['binding'][k]==v
        for k,v in binding.payload().items() if k!='verifier_release_sha256'),'PROJECT_PREWRITE_PLAN')
    prepared=preparation.prepare_evidence(files['plan.json'],{name:files[name] for name in preparation.EVIDENCE},
        operator_code_sha256=plan['operator_code_sha256'],historical=True)
    for phase in PHASES:
        intent,done=(c.load_json(files[phase+suffix]) for suffix in ('.intent.json','.complete.json'))
        need(pc.validate_phase_record(intent,plan,phase)=='attention' and intent['state']=='intent'
            and pc.validate_phase_record(done,plan,phase)=='complete' and done['started_at_utc']==intent['started_at_utc']
            and done['evidence_sha256']==results[phase]['evidence_sha256']==c.digest(files[phase+'.evidence.json']),
            'PROJECT_PREWRITE_CLEAN_PHASE')
    return files,plan,prepared


def _collection(capture, binding, manifest, context, results, clean, plan, prepared):
    encoded=capture['collection']
    need(type(encoded) is dict and set(encoded)==COLLECTION_FILES|{'collection-manifest.json'},'PROJECT_PREWRITE_COLLECTION_MEMBERS')
    files={name:_decode(value,8_000_000 if name=='package.zip' else 2_000_000) for name,value in encoded.items()}
    need(sum(map(len,files.values()))<=12_000_000,'PROJECT_PREWRITE_COLLECTION_BOUND')
    collection=c.load_json(files['collection-manifest.json']);source=manifest['project']['qa_source_sha256'];psha=context['plan_sha256']
    need(set(collection)=={'status','plan_sha256','source_sha256','report_path','sha256','credentials_and_logs_excluded','screenshots_retained_remotely'}
        and collection['status']=='COLLECTED' and collection['credentials_and_logs_excluded'] is True
        and collection['screenshots_retained_remotely'] is False and collection['plan_sha256']==psha
        and collection['source_sha256']==source and set(collection['sha256'])==COLLECTION_FILES
        and all(collection['sha256'][name]==c.digest(files[name]) for name in COLLECTION_FILES)
        and c.digest(files['collection-manifest.json'])==context['collection_manifest_sha256'], 'PROJECT_PREWRITE_COLLECTION_BINDING')
    same_files={'package.zip':'package.zip','native-project-spec.json':'native-project-spec.json','source-to-apex.json':'source-to-apex.json',
        'allocation-receipt.json':'allocate.evidence.json','verification-profile.json':'verification-profile.json','clean-import-receipt.json':'verify.evidence.json'}
    need(all(files[name]==clean[original] for name,original in same_files.items())
        and files['qa-profile.json']==prepared['profile.json'] and files['target-receipt.json']==prepared['target.json'],
        'PROJECT_PREWRITE_COLLECTED_INPUTS')
    descriptor=capture['qa_descriptor']
    fields={'schema_version','scope','files','helpers','remote_sha256','wrapper_sha256','clean_operator_code_sha256',
        'clean_operator_manifest','base_qa_image','base_digest','converter_image','fox_image'}
    need(type(descriptor) is dict and set(descriptor)==fields and type(descriptor['schema_version']) is int
        and descriptor['schema_version']==1 and descriptor['scope']=='fox-project-qa-stage-source-v1'
        and c.digest(c.canonical_bytes(descriptor))==source and set(descriptor['files'])==QA_FILES
        and set(descriptor['helpers'])=={'native_qa_remote.py','project_qa_contracts.py'}
        and all(type(v) is str and HASH.fullmatch(v) for v in (*descriptor['files'].values(),*descriptor['helpers'].values(),descriptor['remote_sha256'],descriptor['wrapper_sha256']))
        and descriptor['clean_operator_code_sha256']==manifest['project']['clean_operator_code_sha256']
        ==c.digest(c.canonical_bytes(descriptor['clean_operator_manifest']))
        and descriptor['converter_image']==manifest['images']['converter'] and descriptor['fox_image']==manifest['images']['fox'],
        'PROJECT_PREWRITE_HISTORICAL_QA_SOURCE')
    stage_path='/home/opc/.config/fox-qa/project-v1-stages/'+psha+'/'+source
    stage,launch,completed,report=(c.load_json(files[name]) for name in ('stage-receipt.json','launch-intent.json','launch-receipt.json','qa-result.json'))
    image=results['qa_run']['image_id'];allocation=c.digest(files['allocation-receipt.json']);tag='localhost/fox-project-qa:v1-'+psha[:16]+'-'+source[:16]
    need(stage=={'status':'STAGED','plan_sha256':psha,'source_sha256':source,'allocation_receipt_sha256':allocation,
        'image_id':image,'image_tag':tag,'stage':stage_path,'bound_files':stage.get('bound_files')}
        and results['qa_stage']['image_id']==image and results['qa_stage']['allocation_receipt_sha256']==allocation,'PROJECT_PREWRITE_STAGE')
    bound={'source/'+name:digest for name,digest in descriptor['files'].items()}
    bound['source/Containerfile']=c.digest(('FROM '+tag+'-base\nUSER root\nCOPY lib /opt/fox-qa/lib\nCOPY run-project.mjs /opt/fox-qa/\nRUN chmod -R a+rX /opt/fox-qa\nUSER pwuser\n').encode())
    mapping={'inputs/'+name:original for name,original in {'package.zip':'package.zip','native-project-spec.json':'native-project-spec.json',
        'source-to-apex.json':'source-to-apex.json','allocate.evidence.json':'allocation-receipt.json','verification-profile.json':'verification-profile.json',
        'verify.evidence.json':'clean-import-receipt.json'}.items()}
    mapping.update({'prepared/profile.json':'qa-profile.json','prepared/target.json':'target-receipt.json'})
    bound.update({name:c.digest(files[original]) for name,original in mapping.items()})
    need(type(stage['bound_files']) is dict and set(stage['bound_files'])==set(bound)|{'inputs/runtime-credentials.json'}
        and all(stage['bound_files'][name]==digest for name,digest in bound.items())
        and type(stage['bound_files']['inputs/runtime-credentials.json']) is str and HASH.fullmatch(stage['bound_files']['inputs/runtime-credentials.json']),
        'PROJECT_PREWRITE_STAGE_BYTES')
    need(launch=={'scope':'fox-project-qa-launch-v1','allocation_receipt_sha256':allocation,'plan_sha256':psha,
        'source_sha256':source,'image_id':image,'state':'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY'}
        and completed=={'status':'QA_FAILED_OR_INCOMPLETE','exit_code':2,'plan_sha256':psha,'source_sha256':source,
            'image_id':image,'result_directory':stage_path+'/results','automatic_replay_permitted':False}
        and type(completed['exit_code']) is int,'PROJECT_PREWRITE_LAUNCH')
    project=c.load_json(files['native-project-spec.json']);trace=c.load_json(files['source-to-apex.json'])
    qa_plan=derive_project_qa_plan(project,c.digest(files['native-project-spec.json']),trace,c.digest(files['source-to-apex.json']))
    target=c.load_json(files['target-receipt.json']);run=report.get('run_id')
    report_keys={'application_id','browser_dialogs','browser_errors','browser_storage_saved','credentials_recorded',
        'delete_or_reset_performed','dispatch_state','failure','final_table_records','finished_at','forms',
        'human_acceptance_recorded','input_sha256','network_denials','run_id','runtime','runtime_image_id',
        'schema_version','scope','started_at','status','target','target_receipt_sha256','test_plan','test_plan_sha256','write_attempts'}
    need(set(report)==report_keys and type(run) is str and re.fullmatch(r'FPQ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}',run)
        and collection['report_path']==stage_path+'/results/'+run+'/qa-result.json'
        and type(report.get('schema_version')) is int and report['schema_version']==1 and report.get('scope')=='fox-project-runtime-qa-v1'
        and report.get('status')=='FAILED' and report.get('dispatch_state')=='PREFLIGHT_BLOCKED'
        and report.get('write_attempts')==[] and report.get('final_table_records')=={}
        and report.get('target')==target and report.get('target_receipt_sha256')==c.digest(files['target-receipt.json'])
        and type(report.get('application_id')) is int and report['application_id']==target['target']['application_id']
        and report.get('test_plan')==qa_plan and report.get('test_plan_sha256')==qa_plan_sha256(qa_plan)
        and report.get('runtime_image_id')==image and all(report.get(k) is False for k in
            ('credentials_recorded','browser_storage_saved','human_acceptance_recorded','delete_or_reset_performed'))
        and report.get('browser_errors')==[] and report.get('browser_dialogs')==[],
        'PROJECT_PREWRITE_REPORT_NOT_PREBUSINESS_FAILURE')
    # The pinned failed preflight may record an aborted request to its own
    # target origin. This is failure evidence, never a passed-QA exception.
    # The target URL was independently derived from authenticated clean inputs.
    url=urlsplit(target['url']);origin='https://'+url.netloc
    denials=report.get('network_denials')
    need(url.scheme=='https' and url.username is None and url.password is None and url.port is None
        and type(denials) is list and len(denials)<=1
        and all(type(value) is str and value==origin for value in denials),
        'PROJECT_PREWRITE_NETWORK_DENIALS')
    expected_input={key:target[key] for key in ('job_id',*pc.HASH_KEYS,'verification_profile_sha256','allocation_receipt_sha256','profile_sha256','import_receipt_sha256')}
    expected_input['target_receipt_sha256']=c.digest(files['target-receipt.json'])
    need(report.get('input_sha256')==expected_input and type(report.get('failure')) is str
        and 0<len(report['failure'])<=4096 and c._timestamp(report.get('started_at'))<=c._timestamp(report.get('finished_at')),
        'PROJECT_PREWRITE_REPORT_INPUTS')
    imported=c.load_json(clean['verify.evidence.json']);policy=c.load_json(clean['verification-profile.json'])
    start,finish=c._timestamp(report['started_at']),c._timestamp(report['finished_at'])
    clean_finish=c._timestamp(imported['finished_at_utc'])
    need(clean_finish<=start<=finish<=datetime.now(timezone.utc)+timedelta(seconds=5)
        and (start-clean_finish).total_seconds()<=policy['max_evidence_age_seconds'],'PROJECT_PREWRITE_REPORT_SEQUENCE')
    forms=report.get('forms');need(type(forms) is list and len(forms)==len(qa_plan['forms']),'PROJECT_PREWRITE_FORM_COVERAGE')
    for row,form in zip(forms,qa_plan['forms']):
        tests=[{**case,'required':case['applicable'],'status':'NOT_RUN' if case['applicable'] else 'NOT_APPLICABLE',
            'field_results':[],'reason':'Not reached' if case['applicable'] else 'No matching editable fields in the exact specification'} for case in form['cases']]
        optional=[{'name':name,'required':False,'status':'NOT_RUN',
            'reason':'This runner observes authenticated browser behavior only; independent operator SQL checks are separate.'}
            for name in ('database_constraints','database_sql_readback')]
        need(set(row)=={'module_id','status','form_binding','tests','additional_checks'}
            and row.get('module_id')==form['module_id'] and row.get('status')=='NOT_RUN'
            and row.get('form_binding')=={k:v for k,v in form.items() if k not in ('cases','row_tracking','edit_field')}
            and row.get('tests')==tests and row.get('additional_checks')==optional,'PROJECT_PREWRITE_CASE_ALREADY_ATTEMPTED')
    runtime=report.get('runtime')
    need(type(runtime) is dict and set(runtime)=={'playwright','chromium','chromium_sandbox','isolation'}
        and runtime['playwright']=='1.64.0' and type(runtime['chromium']) is str and 0<len(runtime['chromium'])<=128
        and runtime['chromium_sandbox'] is False
        and runtime['isolation']=='Rootless on-demand container; no published ports; exact allocated JSN synthetic project only',
        'PROJECT_PREWRITE_RUNTIME_OBSERVATION')
    return files,report,stage_path


def assess_capture(capture, *, expected_release_sha256, expected_installation_sha256, expected_converter_id, expected_converter_image):
    """Pure exact-byte validation; no capture/closure, producer or retry authority."""
    try:
        need(all(type(v) is str and HASH.fullmatch(v) for v in (expected_release_sha256,expected_installation_sha256,expected_converter_id))
            and type(expected_converter_image) is str and re.fullmatch(r'sha256:[a-f0-9]{64}',expected_converter_image),'PROJECT_PREWRITE_INDEPENDENT_PINS')
        need(type(capture) is dict and set(capture)=={'scope','writes_requested','installation_sha256','release','session','journal','product','clean','collection','qa_descriptor','observation'}
            and capture['scope']==CAPTURE_SCOPE and capture['writes_requested'] is False and capture['installation_sha256']==expected_installation_sha256,
            'PROJECT_PREWRITE_CAPTURE')
        manifest=bridge.validate_release(capture['release'])
        need(c.digest(c.canonical_bytes(manifest))==expected_release_sha256 and manifest['schema_version'] in (2,3)
            and manifest['enabled'] is True and manifest['images']['converter']==expected_converter_image,'PROJECT_PREWRITE_RELEASE')
        need(type(capture['session']) is str and re.fullmatch(r'session-[a-f0-9]{24}',capture['session']),'PROJECT_PREWRITE_SESSION')
        product=capture['product'];need(type(product) is dict and set(product)=={'queue','run','technical_proof_count','human_acceptance_count'}
            and all(type(product[k]) is int and product[k]==0 for k in ('technical_proof_count','human_acceptance_count')),'PROJECT_PREWRITE_NO_PROOF_OR_ACCEPTANCE')
        queue=VerificationQueue._record(product['queue']);need(queue is not None and queue['state']=='attention'
            and queue['proof_sha256'] is None and queue['attention_code']=='BACKEND_OUTCOME_UNCONFIRMED','PROJECT_PREWRITE_QUEUE')
        binding=VerificationBinding.from_payload({k:queue[k] for k in ('job_id','source_manifest_sha256','package_sha256','verifier_release_sha256')})
        need(binding.verifier_release_sha256==expected_release_sha256 and product['run']=={'id':binding.job_id,'state':'QA_REQUIRED',
            'source_hash':binding.source_manifest_sha256,'artifact':'jobs/'+binding.job_id+'/apex-package.zip'},'PROJECT_PREWRITE_RUN')
        journal,results,context=_journal(capture,binding,queue,manifest)
        clean,plan,prepared=_clean(capture,binding,manifest,context,results)
        collection,report,stage_path=_collection(capture,binding,manifest,context,results,clean,plan,prepared)
        observed=capture['observation']
        need(type(observed) is dict and set(observed)=={'service','converter','active_sqlcl_pids','active_browser_pids','active_qa_containers','original_coordinator_live','stage_path','stage_exists','launch_intent_exists','launch_completion_exists','dispatch_receipt_exists'}
            and observed['service']=={'LoadState':'loaded','ActiveState':'failed','SubState':'failed','MainPID':'0'}
            and observed['converter']=={'id':expected_converter_id,'image':expected_converter_image}
            and all(type(observed[k]) is list and observed[k]==[] for k in ('active_sqlcl_pids','active_browser_pids','active_qa_containers'))
            and observed['original_coordinator_live'] is False and observed['stage_path']==stage_path
            and all(observed[k] is True for k in ('stage_exists','launch_intent_exists','launch_completion_exists'))
            and observed['dispatch_receipt_exists'] is False,'PROJECT_PREWRITE_PRODUCER_UNCONFIRMED')
        return {'schema_version':1,'scope':SCOPE,'status':'CLASSIFIED_PROJECT_PREWRITE_QA_NOT_CLOSED',
            'binding':binding.payload(),'session':capture['session'],'installation_sha256':expected_installation_sha256,
            'legacy_record_sha256':queue['record_sha256'],'claim_sha256':c.digest(c.canonical_bytes(results['claim']['claim'])),
            'retained_sha256':{k:c.digest(v) for k,v in sorted(journal.items())},'clean_sha256':{k:c.digest(v) for k,v in sorted(clean.items())},
            'collection_sha256':{k:c.digest(v) for k,v in sorted(collection.items())},'capture_sha256':_capture_digest(capture),
            'plan_sha256':context['plan_sha256'],'qa_source_sha256':manifest['project']['qa_source_sha256'],
            'qa_image':results['qa_run']['image_id'],'qa_run_id':report['run_id'],'qa_report_sha256':c.digest(collection['qa-result.json']),
            'retained_steps':list(STEPS),'failed_phase':'qa_run','dispatch_state':'PREFLIGHT_BLOCKED',
            'target':c.load_json(prepared['target.json'])['target'],'expected_versions':plan['expected_versions'],
            'current_admission_blocks':True,'closure_performed':False,'technical_success':False,'human_acceptance_recorded':False,
            'automatic_replay_permitted':False,'recovery_authorized':False}
    except ProjectPrewriteEvidenceError:
        raise
    except Exception:
        raise ProjectPrewriteEvidenceError('PROJECT_PREWRITE_RETAINED_CONTRACT_INVALID') from None
