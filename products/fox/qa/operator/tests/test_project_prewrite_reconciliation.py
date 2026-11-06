"""Real package/plan validators; authored failed browser data, never live proof."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

import pytest

ROOT=Path(__file__).resolve().parents[3];sys.path[:0]=[str(ROOT),str(ROOT/'fox'),str(ROOT/'converter')]
from qa.operator import contracts as c, project_prewrite_reconciliation as r
from qa.operator import product_verifier as verifier
from qa.operator.tests.test_qa_stage_reconciliation import capture as stage_capture, qa_case, case, project_job, INSTALLATION, CONVERTER, TOKEN

raw=c.canonical_bytes
encode=lambda value:base64.b64encode(value).decode()


@pytest.fixture(autouse=True)
def synthetic_unused_native_profile(monkeypatch):
    # The project release manifest also pins an unused legacy-native profile.
    # That operator-local file is intentionally absent from the public checkout.
    # Keep this project-only fixture deterministic without reading private data.
    source_bytes=verifier.source_bytes
    profile=ROOT/'deployment/native-beta-profile.json'
    monkeypatch.setattr(verifier,'source_bytes',lambda path:
        b'synthetic-unused-native-profile\n' if Path(path)==profile else source_bytes(path))


@pytest.fixture
def capture(stage_capture,qa_case):
    value=deepcopy(stage_capture);packet,inputs,package=qa_case
    value.pop('dependency_probe');value.update(scope=r.CAPTURE_SCOPE)
    docs={name:c.load_json(base64.b64decode(data)) for name,data in value['journal'].items()}
    binding={k:value['product']['queue'][k] for k in ('job_id','source_manifest_sha256','package_sha256','verifier_release_sha256')}
    psha=packet['plan_sha256'];source=packet['source_sha256'];image='7'*64
    stage_path='/home/opc/.config/fox-qa/project-v1-stages/'+psha+'/'+source
    descriptor=packet['descriptor'];tag='localhost/fox-project-qa:v1-'+psha[:16]+'-'+source[:16]
    files={'package.zip':inputs['package.zip'],'native-project-spec.json':inputs['native-project-spec.json'],
        'source-to-apex.json':inputs['source-to-apex.json'],'allocation-receipt.json':inputs['allocate.evidence.json'],
        'verification-profile.json':inputs['verification-profile.json'],'clean-import-receipt.json':inputs['verify.evidence.json'],
        'qa-profile.json':inputs['profile.json'],'target-receipt.json':inputs['target.json']}
    allocation=c.digest(files['allocation-receipt.json'])
    bindings={'source/'+name:sha for name,sha in descriptor['files'].items()}
    bindings['source/Containerfile']=c.digest(('FROM '+tag+'-base\nUSER root\nCOPY lib /opt/fox-qa/lib\nCOPY run-project.mjs /opt/fox-qa/\nRUN chmod -R a+rX /opt/fox-qa\nUSER pwuser\n').encode())
    for name in ('package.zip','native-project-spec.json','source-to-apex.json','allocate.evidence.json','verification-profile.json','verify.evidence.json','runtime-credentials.json'):
        bindings['inputs/'+name]=c.digest(inputs[name])
    for name in ('profile.json','target.json'):bindings['prepared/'+name]=c.digest(inputs[name])
    files['stage-receipt.json']=raw({'status':'STAGED','plan_sha256':psha,'source_sha256':source,'allocation_receipt_sha256':allocation,
        'image_id':image,'image_tag':tag,'stage':stage_path,'bound_files':bindings})
    files['launch-intent.json']=raw({'scope':'fox-project-qa-launch-v1','plan_sha256':psha,'source_sha256':source,'allocation_receipt_sha256':allocation,
        'image_id':image,'state':'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY'})
    files['launch-receipt.json']=raw({'status':'QA_FAILED_OR_INCOMPLETE','exit_code':2,'plan_sha256':psha,'source_sha256':source,
        'image_id':image,'result_directory':stage_path+'/results','automatic_replay_permitted':False})
    node=shutil.which('node')
    if node is None:pytest.skip('Existing Node runtime needed for authored browser-result fixture')
    program=r'''
import {readFileSync} from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
const p=JSON.parse(readFileSync(0,'utf8'));
const {validateProjectRunnerInputs}=await import(pathToFileURL(path.join(p.root,'qa/lib/project-runner-inputs.mjs')));
const {createProjectRuntimeResult}=await import(pathToFileURL(path.join(p.root,'qa/lib/project-runtime.mjs')));
const names={targetRaw:'target.json',profileRaw:'profile.json',projectRaw:'native-project-spec.json',traceRaw:'source-to-apex.json',
 importRaw:'verify.evidence.json',verificationRaw:'verification-profile.json',allocationRaw:'allocate.evidence.json',packageRaw:'package.zip',credentialRaw:'runtime-credentials.json'};
const inputs=Object.fromEntries(Object.entries(names).map(([key,name])=>[key,Buffer.from(p.inputs[name],'base64')]));
const b=validateProjectRunnerInputs(inputs,{now:Date.parse('2026-10-25T01:02:00Z')});
const r=createProjectRuntimeResult(b,'FPQ-20261025T010130-1234abcd');
Object.assign(r,{started_at:'2026-10-25T01:01:30Z',finished_at:'2026-10-25T01:01:31Z',status:'FAILED',dispatch_state:'PREFLIGHT_BLOCKED',
 failure:'Authenticated runtime account differs or cannot be observed',runtime_image_id:p.image,
 runtime:{playwright:'1.64.0',chromium:'synthetic-browser-version',chromium_sandbox:false,isolation:'Rootless on-demand container; no published ports; exact allocated JSN synthetic project only'}});
process.stdout.write(JSON.stringify(r));
'''
    result=subprocess.run([node,'--input-type=module','-e',program],input=json.dumps({'root':str(ROOT),'image':image,
        'inputs':{name:encode(data) for name,data in inputs.items()}}).encode(),capture_output=True,check=True,timeout=20)
    report=json.loads(result.stdout);files['qa-result.json']=raw(report)
    collection={'status':'COLLECTED','plan_sha256':psha,'source_sha256':source,'report_path':stage_path+'/results/'+report['run_id']+'/qa-result.json',
        'sha256':{name:c.digest(data) for name,data in files.items()},'credentials_and_logs_excluded':True,'screenshots_retained_remotely':False}
    files['collection-manifest.json']=raw(collection)
    phase_results={'qa_stage':{'status':'STAGED','plan_sha256':psha,'source_sha256':source,'allocation_receipt_sha256':allocation,'image_id':image},
        'qa_run':{'status':'QA_FAILED_OR_INCOMPLETE','exit_code':2,'plan_sha256':psha,'source_sha256':source,'image_id':image},
        'qa_collect':{'status':'COLLECTED','plan_sha256':psha,'source_sha256':source,'collection_manifest_sha256':c.digest(files['collection-manifest.json'])}}
    for step,result in phase_results.items():
        label='p0001-'+step.replace('_','-');intent={'scope':'fox-product-verifier-step-v1','release_sha256':binding['verifier_release_sha256'],
            'step':label,'binding_sha256':c.digest(raw(binding))}
        docs[label+'.intent.json']=intent;docs[label+'.complete.json']={'scope':'fox-product-verifier-step-result-v1',
            'release_sha256':binding['verifier_release_sha256'],'intent_sha256':c.digest(raw(intent)),'result':result}
    value['journal']={name:encode(raw(data)) for name,data in docs.items()}
    value['collection']={name:encode(data) for name,data in files.items()};value['qa_descriptor']=deepcopy(descriptor)
    value['observation']={'service':{'LoadState':'loaded','ActiveState':'failed','SubState':'failed','MainPID':'0'},
        'converter':{'id':CONVERTER,'image':value['release']['images']['converter']},'active_sqlcl_pids':[],'active_browser_pids':[],
        'active_qa_containers':[],'original_coordinator_live':False,'stage_path':stage_path,'stage_exists':True,
        'launch_intent_exists':True,'launch_completion_exists':True,'dispatch_receipt_exists':False}
    return value


def assess(value,**overrides):
    return r.assess_capture(value,**{'expected_release_sha256':c.digest(raw(value['release'])),
        'expected_installation_sha256':INSTALLATION,'expected_converter_id':CONVERTER,
        'expected_converter_image':value['release']['images']['converter'],**overrides})


def rebind_collection(value,name,change):
    """Model a self-consistent FAILED report, not merely a damaged file hash."""
    document=json.loads(base64.b64decode(value['collection'][name]));change(document);data=raw(document)
    value['collection'][name]=encode(data)
    manifest=json.loads(base64.b64decode(value['collection']['collection-manifest.json']))
    manifest['sha256'][name]=c.digest(data);data=raw(manifest);value['collection']['collection-manifest.json']=encode(data)
    done=json.loads(base64.b64decode(value['journal']['p0001-qa-collect.complete.json']))
    done['result']['collection_manifest_sha256']=c.digest(data);value['journal']['p0001-qa-collect.complete.json']=encode(raw(done))


def test_exact_completed_failed_prebusiness_project_is_not_a_pass_or_retry(capture,monkeypatch):
    original=deepcopy(capture)
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('Classifier must not run a process'))
    result=assess(capture)
    assert capture==original and len(result['retained_sha256'])==22
    assert result['retained_steps']==list(r.STEPS) and result['failed_phase']=='qa_run'
    assert all(result[k] is False for k in ('closure_performed','technical_success','human_acceptance_recorded','automatic_replay_permitted','recovery_authorized'))
    assert TOKEN not in json.dumps(result) and 'runtime-credentials.json' not in result['collection_sha256']


def test_retained_reader_does_not_weaken_new_qa_version_admission(qa_case,monkeypatch):
    from fox import native_verification_policy as policy
    from qa.operator import project_qa_contracts as preparation
    packet,inputs,_=qa_case
    plan_raw=base64.b64decode(packet['plan_b64'])
    evidence={name:inputs[name] for name in preparation.EVIDENCE}
    options={'operator_code_sha256':packet['descriptor']['clean_operator_code_sha256']}
    # Model a retained tuple removed from today's active allowlist. A historical
    # reader can authenticate it; normal new QA preparation must still reject it.
    monkeypatch.setattr(policy,'SUPPORTED_ACTIVE_VERSIONS',frozenset())
    assert preparation.prepare_evidence(plan_raw,evidence,historical=True,**options)=={
        name:inputs[name] for name in ('profile.json','target.json')}
    with pytest.raises(policy.VerificationPolicyError,match='not supported for a new technical decision'):
        preparation.prepare_evidence(plan_raw,evidence,**options)
    with pytest.raises(policy.VerificationPolicyError,match='not supported for a new technical decision'):
        preparation.prepare_inputs(plan_raw,{name:inputs[name] for name in preparation.HANDOFF},**options)


def target_origin(value):
    target=json.loads(base64.b64decode(value['collection']['target-receipt.json']))
    return 'https://'+urlsplit(target['url']).netloc


def test_failed_preflight_may_retain_one_blocked_same_target_origin(capture):
    value=deepcopy(capture);origin=target_origin(value)
    rebind_collection(value,'qa-result.json',lambda report:report.update(network_denials=[origin]))
    result=assess(value)
    assert result['dispatch_state']=='PREFLIGHT_BLOCKED' and result['technical_success'] is False
    assert result['automatic_replay_permitted'] is False and result['recovery_authorized'] is False


@pytest.mark.parametrize('fault',['foreign','path','query','userinfo','port','http','duplicate','not-list','not-string'])
def test_failed_preflight_denials_are_only_unique_canonical_same_target_origins(capture,fault):
    value=deepcopy(capture);origin=target_origin(value)
    denials={
        'foreign':['https://foreign.invalid'],'path':[origin+'/'],'query':[origin+'?x=1'],
        'userinfo':[origin.replace('https://','https://user@')],'port':[origin+':443'],
        'http':[origin.replace('https://','http://')],'duplicate':[origin,origin],
        'not-list':origin,'not-string':[None],
    }[fault]
    rebind_collection(value,'qa-result.json',lambda report:report.update(network_denials=denials))
    with pytest.raises(r.ProjectPrewriteEvidenceError,match='NETWORK_DENIALS'):assess(value)


@pytest.mark.parametrize('fault',['extra-journal','missing-qa-run','timeout','descriptor','collection-extra','collection-sha',
    'producer','coordinator','sqlcl','stage-absent','dispatch','service','wrong-pin','proof','bool-count'])
def test_uncertain_live_changed_or_mixed_captures_are_not_dispositions(capture,fault):
    value=deepcopy(capture)
    if fault=='extra-journal':value['journal']['p0001-promotion-check.intent.json']=encode(b'{}')
    elif fault=='missing-qa-run':value['journal'].pop('p0001-qa-run.complete.json')
    elif fault=='timeout':
        row=json.loads(base64.b64decode(value['journal']['p0001-qa-run.complete.json']));row['result']['exit_code']=124
        value['journal']['p0001-qa-run.complete.json']=encode(raw(row))
    elif fault=='descriptor':value['qa_descriptor']['files']['lib/project-browser.mjs']='0'*64
    elif fault=='collection-extra':value['collection']['dispatch-receipt.json']=encode(b'{}')
    elif fault=='collection-sha':value['collection']['qa-result.json']=encode(b'{}')
    elif fault=='producer':value['observation']['active_qa_containers']=['synthetic-live']
    elif fault=='coordinator':value['observation']['original_coordinator_live']=True
    elif fault=='sqlcl':value['observation']['active_sqlcl_pids']=[1]
    elif fault=='stage-absent':value['observation']['stage_exists']=False
    elif fault=='dispatch':value['observation']['dispatch_receipt_exists']=True
    elif fault=='service':value['observation']['service']['MainPID']='12'
    elif fault=='wrong-pin':value['observation']['converter']['id']='0'*64
    elif fault=='proof':value['product']['technical_proof_count']=1
    else:value['product']['human_acceptance_count']=False
    with pytest.raises(r.ProjectPrewriteEvidenceError):assess(value)


@pytest.mark.parametrize('fault',['passed','business-dispatch','write-attempt','human','other-app','wrong-target','wrong-input',
    'case-ran','form-missing','duplicate-form','extra-field','browser-error','future','stale-at-start'])
def test_self_consistent_collection_cannot_hide_started_work_or_claim_success(capture,fault):
    value=deepcopy(capture)
    def change(report):
        # A permitted failed-origin observation cannot excuse writes, cases,
        # success, foreign targets or any other contradictory retained evidence.
        report['network_denials']=[target_origin(value)]
        if fault=='passed':report['status']='PASSED'
        elif fault=='business-dispatch':report['dispatch_state']='ATTEMPT_STARTED'
        elif fault=='write-attempt':report['write_attempts']=[{'synthetic':'attempt'}]
        elif fault=='human':report['human_acceptance_recorded']=True
        elif fault=='other-app':report['application_id']+=1
        elif fault=='wrong-target':report['target']['target']['workspace']='OTHER_WORKSPACE'
        elif fault=='wrong-input':report['input_sha256']['package_sha256']='0'*64
        elif fault=='case-ran':report['forms'][0]['tests'][0]['status']='PASSED'
        elif fault=='form-missing':report['forms'].pop()
        elif fault=='duplicate-form':report['forms'][1]=deepcopy(report['forms'][0])
        elif fault=='extra-field':report['unknown_private_blob']='must-not-be-adopted'
        elif fault=='browser-error':report['browser_errors']=['synthetic failure']
        elif fault=='future':report.update(started_at='2099-01-01T00:00:00Z',finished_at='2099-01-01T00:00:01Z')
        else:report.update(started_at='2026-10-28T00:00:00Z',finished_at='2026-10-28T00:00:01Z')
    rebind_collection(value,'qa-result.json',change)
    with pytest.raises(r.ProjectPrewriteEvidenceError):assess(value)
