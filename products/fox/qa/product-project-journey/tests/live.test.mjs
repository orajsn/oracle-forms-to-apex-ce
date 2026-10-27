import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,mkdirSync,lstatSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ORIGIN,APEX_ORIGIN,INSTANCE,FIXTURE_FILES,SOURCE_SHA,sha,receiptHash,canonical,validateInput,publicInput,
 Journal,MutationGate,validateMultipart,validatePlan,statusProjection,verifiedEvidence,runBrowser,validateEnvironment} from '../live.mjs';
import {fixture,NOW,reseal} from './fixtures.mjs';

const ID='a'.repeat(32),RUN='fox-'+'b'.repeat(20),SOURCE_ID='ss-'+'c'.repeat(32);
const clone=value=>JSON.parse(JSON.stringify(value));
class MemoryJournal {constructor(){this.files=new Map();}write(name,value){assert.ok(!this.files.has(name));this.files.set(name,clone(value));return receiptHash(value);}}
function request(pathname,body,{raw=null,type='application/json'}={}){
 const bytes=raw??Buffer.from(JSON.stringify(body));return {url:()=>ORIGIN+pathname,method:()=> 'POST',postDataJSON:()=>body,postDataBuffer:()=>bytes,headers:()=>({'content-type':type})};
}
function normalGate(){return new MutationGate(fixture(),new MemoryJournal());}
function login(gate){gate.arm('login','/api/login',gate.input.credentials);const action=gate.dispatch(request('/api/login',gate.input.credentials));
 gate.record(action,200,{username:gate.input.credentials.username},Buffer.from('{}'));}
function created(gate){login(gate);gate.arm('create','/api/projects',gate.input.project);const action=gate.dispatch(request('/api/projects',gate.input.project));
 gate.record(action,201,{id:ID},Buffer.from('{}'));}
function multipart(files,{boundary='FOX-Boundary',selected='null',mutate=null}={}){
 const parts=[];
 for(const file of files){const bytes=mutate?mutate(file):Buffer.from(file.base64,'base64');
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="files"; filename="${file.name}"\r\nContent-Type: text/plain\r\n\r\n`),bytes,Buffer.from('\r\n'));}
 parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="expected_current_source_set_id"\r\n\r\n${selected}\r\n--${boundary}--\r\n`));
 return {raw:Buffer.concat(parts),type:'multipart/form-data; boundary='+boundary};
}
function plan(gate){
 return {project_id:ID,project_name:gate.input.project.name,source_hash:SOURCE_SHA,selected_source_set_id:SOURCE_ID,
  plan_sha256:'d'.repeat(64),state:'READY',can_generate:true,assessment_complete:true,
  source_files:gate.input.files.map(({name,sha256})=>({name,sha256})),forms:['ALPHA','BETA'].map((name,index)=>{
   const table=index?'STATUS_LOG':'WORK_ITEMS',filename=index?'beta.xml':'alpha.xml',identity=String(index+1).repeat(64);
   return {module_id:'form-'+String(index+1).repeat(20),form_name:name,state:'READY',source_name:filename,source_sha256:FIXTURE_FILES[filename],table_name:table,
    storage_mapping:{schema_version:1,scope:'fox-project-storage-v1',project_id:ID,source_table_name:table,source_schema_sha256:'f'.repeat(64),
     identity_sha256:identity,target_table_name:'FOX_NATIVE_'+identity.slice(0,19).toUpperCase()}};})};
}
function uploaded(gate){
 created(gate);gate.arm('upload','/api/projects/'+ID+'/sources',null);const wire=multipart(gate.input.files);
 const action=gate.dispatch(request('/api/projects/'+ID+'/sources',null,wire));
 gate.record(action,200,{source_hash:SOURCE_SHA,selected_source_set_id:SOURCE_ID,conversion_profile:'native-project-v1'},Buffer.from('{}'));
 gate.plan=plan(gate);
}
function running(gate){uploaded(gate);const body=validatePlan(gate.plan,gate);gate.arm('process','/api/projects/'+ID+'/runs',body);
 const action=gate.dispatch(request('/api/projects/'+ID+'/runs',body));gate.record(action,202,{id:RUN,state:'QUEUED'},Buffer.from('{}'));}
function detail(gate,state='VERIFIED'){
 return {id:ID,name:gate.input.project.name,inventory:{source_hash:SOURCE_SHA,selected_source_set_id:SOURCE_ID},
  runs:[{id:RUN,project_id:ID,source_hash:SOURCE_SHA,state,artifact_generated:state==='VERIFIED',technical_verified:state==='VERIFIED',human_accepted:false,
   downloadable:false,review_available:state==='VERIFIED',forms:gate.plan.forms.map(({module_id})=>({module_id,state:'generated'}))}]};
}
function evidence(gate){
 const forms=gate.plan.forms.map(({module_id})=>({module_id}));
 return {job_id:RUN,project_id:ID,source_manifest_sha256:SOURCE_SHA,conversion_profile:'native-project-v1',application_count:1,form_count:2,
  application_id:12345,application_alias:'F2A_SYNTHETIC',application_url:APEX_ORIGIN+'/ords/r/forms2apex_poc/f2a_synthetic/',forms,form_reviews:forms,
  reviewer_approved:true,reviewer_execution_verified:true,model_environment_verified:true,sqlcl_valid:true,import_passed:true,package_reimport_passed:true,
  human_acceptance_recorded:false,schema_preparation_sha256:'d'.repeat(64),technical_verification:{scope:'fox-project-technical-verification-v1',conversion_profile:'native-project-v1',
   job_id:RUN,source_manifest_sha256:SOURCE_SHA,package_sha256:'e'.repeat(64),authenticated_runtime_passed:true,clean_schema_install_passed:true,
   human_acceptance_recorded:false,form_results:forms}};
}

test('exact original synthetic source bytes and bounded caller observation validate',()=>{
 const input=fixture();assert.equal(validateInput(input,{now:NOW}),input);
 assert.equal(sha(input.files.map(x=>x.name+':'+x.sha256).sort().join('\n')),SOURCE_SHA);
});
test('browser environment rejects injection debug proxy and TLS overrides',()=>{
 validateEnvironment({PATH:'controlled',SYSTEMROOT:'C:\\Windows',NO_PROXY:'127.0.0.1'});
 for(const name of ['NODE_OPTIONS','NODE_PATH','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED','DEBUG','PWDEBUG',
  'HTTP_PROXY','https_proxy','ALL_PROXY','SSL_CERT_FILE','SSL_CERT_DIR','LD_PRELOAD','DYLD_INSERT_LIBRARIES','PLAYWRIGHT_BROWSERS_PATH'])
  assert.throws(()=>validateEnvironment({[name]:'override'}));
});
for(const [name,change] of [
 ['other origin',x=>{x.origin='https://example.com';}],['extra top field',x=>{x.unsafe=true;}],
 ['implicit apply',x=>{x.apply=false;}],['unlabelled project',x=>{x.project.name='Customer project';}],
 ['extra source',x=>{x.files.push(clone(x.files[0]));}],['changed source',x=>{x.files[0].base64=Buffer.from('changed').toString('base64');}],
 ['raw form name',x=>{x.files[0].name='alpha.fmb';}],['other compartment',x=>{x.preflight.instance.compartment_id='other';reseal(x);}],
 ['stopped database',x=>{x.preflight.database.lifecycle_state='STOPPED';reseal(x);}],['missing operator',x=>{x.preflight.operator_service.pid=0;reseal(x);}],
 ['busy conversion',x=>{x.preflight.active_conversion_count=1;reseal(x);}],['mismatched image',x=>{x.preflight.images.fox='sha256:'+'f'.repeat(64);reseal(x);}],
 ['modified receipt',x=>{x.preflight.receipt_sha256='0'.repeat(64);}],['stale receipt',x=>{x.preflight.observed_at_utc=new Date(NOW-120001).toISOString();reseal(x);}],
 ['future receipt',x=>{x.preflight.observed_at_utc=new Date(NOW+5001).toISOString();reseal(x);}],['unbounded wait',x=>{x.max_wait_seconds=3601;}],
 ['external asset',x=>{x.ui_assets['https://outside/app.js']='f'.repeat(64);}],['implicit browser',x=>{delete x.browser.index_sha256;}],
])test('input rejects '+name,()=>{const input=fixture();change(input);assert.throws(()=>validateInput(input,{now:NOW}));});

test('public input contains neither credentials nor source contents',()=>{
 const input=fixture(),publicValue=publicInput(input),raw=JSON.stringify(publicValue);
 assert.ok(!raw.includes(input.credentials.password));assert.ok(!raw.includes(input.credentials.username));
 for(const file of input.files)assert.ok(!raw.includes(file.base64));
 assert.equal(publicValue.files.length,4);assert.equal(publicValue.preflight_scope,'caller_supplied_observation_not_a_signature');
});
test('credential accidentally repeated in a public label is rejected before journal publication',()=>{
 const input=fixture();input.project.description='Synthetic '+input.credentials.password;
 assert.throws(()=>publicInput(input),/PASSWORD_IN_PUBLIC_METADATA/);
});
test('real create-only journal preserves original result and private modes',()=>{
 const parent=mkdtempSync(path.join(os.tmpdir(),'fox-live-journal-'));
 const output=path.join(parent,'run');const journal=new Journal(output);journal.write('result.json',{status:'TEST_ONLY'});
 const before=readFileSync(path.join(output,'result.json'));assert.throws(()=>journal.write('result.json',{changed:true}));
 assert.deepEqual(readFileSync(path.join(output,'result.json')),before);assert.throws(()=>new Journal(output));
 assert.throws(()=>journal.write('../escape.json',{}));
 if(process.platform!=='win32'){assert.equal(lstatSync(output).mode&0o777,0o700);assert.equal(lstatSync(path.join(output,'result.json')).mode&0o777,0o600);}
});
test('login intent and dispatch never persist password or its body digest',()=>{
 const gate=normalGate();login(gate);const raw=JSON.stringify([...gate.journal.files.values()]);
 assert.ok(!raw.includes(gate.input.credentials.password));assert.ok(!raw.includes(gate.input.credentials.username));
 assert.equal(gate.journal.files.get('login.dispatch.json').request_sha256,undefined);
 assert.deepEqual([...gate.journal.files.keys()],['login.intent.json','login.dispatch.json','login.response.json']);
});
test('exact mutation order and one-shot dispatch are enforced before network',()=>{
 const gate=normalGate();assert.throws(()=>gate.arm('create','/api/projects',gate.input.project),/PREVIOUS_ACTION_UNCONFIRMED/);
 login(gate);assert.throws(()=>gate.arm('login','/api/login',gate.input.credentials),/REPLAY/);
 gate.arm('create','/api/projects',gate.input.project);const requestValue=request('/api/projects',gate.input.project);
 gate.dispatch(requestValue);assert.ok(gate.journal.files.has('create.intent.json'));assert.ok(gate.journal.files.has('create.dispatch.json'));
 assert.throws(()=>gate.dispatch(requestValue),/UNARMED/);assert.throws(()=>gate.arm('upload','/api/projects/'+ID+'/sources',null));
 assert.deepEqual([...gate.dispatched],['login','create']);assert.ok(!gate.journal.files.has('upload.intent.json'));
});
test('unknown response leaves durable intent and prohibits fresh create',()=>{
 const gate=normalGate();login(gate);gate.arm('create','/api/projects',gate.input.project);gate.dispatch(request('/api/projects',gate.input.project));
 gate.fail(new Error('Synthetic private transport failure'));assert.equal(gate.failure,'JOURNEY_STEP_FAILED');
 assert.throws(()=>gate.arm('create','/api/projects',gate.input.project));assert.ok(!gate.journal.files.has('create.response.json'));
});
test('known rejection is retained but cannot enable next mutation',()=>{
 const gate=normalGate();gate.arm('login','/api/login',gate.input.credentials);const action=gate.dispatch(request('/api/login',gate.input.credentials));
 assert.throws(()=>gate.record(action,401,{detail:'withheld'},Buffer.from('{}')),/MUTATION_HTTP/);
 assert.equal(gate.journal.files.get('login.response.json').http_status,401);assert.throws(()=>gate.arm('create','/api/projects',gate.input.project));
});
test('wrong mutation body is blocked before dispatch receipt',()=>{
 const gate=normalGate();login(gate);gate.arm('create','/api/projects',gate.input.project);
 assert.throws(()=>gate.dispatch(request('/api/projects',{...gate.input.project,name:'different'})),/PAYLOAD_CHANGED/);
 assert.ok(!gate.journal.files.has('create.dispatch.json'));
});
test('multipart checks exact original bytes and source-selection CAS',()=>{
 const input=fixture(),wire=multipart(input.files);assert.equal(validateMultipart(wire.raw,wire.type,input.files,null).file_count,4);
 const wrong=multipart(input.files,{mutate:file=>Buffer.concat([Buffer.from(file.base64,'base64'),Buffer.from('\n')])});
 assert.throws(()=>validateMultipart(wrong.raw,wrong.type,input.files,null),/BYTES_DIFFER/);
 const selected=multipart(input.files,{selected:SOURCE_ID});assert.throws(()=>validateMultipart(selected.raw,selected.type,input.files,null),/SELECTION_DIFFERS/);
 const missing=multipart(input.files.slice(1));assert.throws(()=>validateMultipart(missing.raw,missing.type,input.files,null),/COMPLETE_UPLOAD/);
});
test('multipart rejects duplicate, unsafe and trailing parts',()=>{
 const input=fixture(),duplicates=multipart([...input.files,input.files[0]]);
 assert.throws(()=>validateMultipart(duplicates.raw,duplicates.type,input.files,null));
 const wire=multipart(input.files);assert.throws(()=>validateMultipart(Buffer.concat([wire.raw,Buffer.from('extra')]),wire.type,input.files,null),/TRAILER/);
 assert.throws(()=>validateMultipart(wire.raw,'multipart/form-data; boundary=x\r\ny',input.files,null));
});
test('acceptance, downloads, other project reads and redirects cannot be armed',()=>{
 const gate=normalGate();running(gate);
 for(const suffix of ['/accept','/download']){assert.equal(gate.allowedGet(ORIGIN+'/api/projects/'+ID+'/runs/'+RUN+suffix),false);
  assert.throws(()=>gate.dispatch(request('/api/projects/'+ID+'/runs/'+RUN+suffix,{})));}
 assert.equal(gate.allowedGet(ORIGIN+'/api/projects/'+'d'.repeat(32)),false);
 assert.equal(gate.allowedGet('https://outside.invalid/api/projects'),false);
 assert.equal(gate.allowedGet(ORIGIN+'/api/projects?other=1'),false);
 assert.equal(gate.allowedGet(ORIGIN+'/api/projects/'+ID+'/runs/'+RUN+'/evidence'),true);
});
test('complete plan yields only strict six-field process approval',()=>{
 const gate=normalGate();uploaded(gate);const body=validatePlan(gate.plan,gate);
 assert.deepEqual(Object.keys(body).sort(),['approved_external_ai','approved_prototype_scope','approved_redacted_source','expected_current_source_set_id','plan_sha256','source_hash'].sort());
 for(const change of [x=>x.forms.pop(),x=>{x.forms[0].state='NEEDS_HUMAN';},x=>{x.source_files[0].sha256='0'.repeat(64);},
  x=>{delete x.forms[0].storage_mapping;},x=>{x.forms[0].storage_mapping.project_id='b'.repeat(32);},x=>{x.can_generate=false;}]){
  const changed=clone(gate.plan);change(changed);assert.throws(()=>validatePlan(changed,gate));}
});
test('state observations need not see short-lived intermediate states',()=>{
 const gate=normalGate();running(gate);assert.equal(statusProjection(detail(gate,'QUEUED'),gate).state,'QUEUED');
 assert.equal(statusProjection(detail(gate,'VERIFIED'),gate).state,'VERIFIED');
});
test('owner-checked queue attention is an error even while the saved run is QA_REQUIRED',()=>{
 const gate=normalGate();running(gate);const value=detail(gate,'QA_REQUIRED');
 value.runs[0].artifact_generated=true;
 value.runs[0].verification_status={configured:true,state:'attention',operator_contact:'recent',claim_token:'PRIVATE_SENTINEL'};
 const projected=statusProjection(value,gate);
 assert.equal(projected.state,'QA_REQUIRED');assert.equal(projected.artifact_generated,true);assert.equal(projected.technical_verified,false);
 assert.equal(projected.error_reported,true);assert.ok(!JSON.stringify(projected).includes('PRIVATE_SENTINEL'));
 for(const status of [{configured:true,state:'queued'},{configured:true,state:'running'},{configured:false,state:'attention'}]){
  value.runs[0].verification_status=status;assert.equal(statusProjection(value,gate).error_reported,false);
 }
});
test('only whole-project evidence yields verified output without acceptance',()=>{
 const gate=normalGate();running(gate);const result=verifiedEvidence(evidence(gate),detail(gate),gate);
 assert.equal(result.application_id,12345);assert.equal(result.form_ids.length,2);assert.equal(result.public_human_acceptance_recorded,false);
 assert.equal(result.physical_absence_before_creation_verified,false);assert.equal(result.download_endpoint_called,false);
});
for(const [name,change] of [
 ['one missing form',x=>x.technical_verification.form_results.pop()],['auth runtime false',x=>{x.technical_verification.authenticated_runtime_passed=false;}],
 ['fabricated acceptance',x=>{x.technical_verification.human_acceptance_recorded=true;}],['two applications',x=>{x.application_count=2;}],
 ['wrong target URL',x=>{x.application_url='https://example.com/ords/r/forms2apex_poc/f2a_synthetic/';}],['wrong source',x=>{x.source_manifest_sha256='0'.repeat(64);}],
 ['missing review',x=>x.form_reviews.pop()],['missing schema evidence',x=>{delete x.schema_preparation_sha256;}],
])test('final evidence rejects '+name,()=>{
 const gate=normalGate();running(gate);const value=evidence(gate);change(value);assert.throws(()=>verifiedEvidence(value,detail(gate),gate));
});

test('missing POST is handled without an unhandled response rejection or replay',async()=>{
 const input=fixture(),parent=mkdtempSync(path.join(os.tmpdir(),'fox-ui-no-post-'));
 input.output_dir=path.join(parent,'run');input.preflight.observed_at_utc=new Date().toISOString();reseal(input);
 const unhandled=[];const listener=value=>unhandled.push(value);process.on('unhandledRejection',listener);
 let closes=0;
 const page={on(){},goto:async()=>{},getByLabel:()=>({fill:async()=>{}}),
  waitForResponse:()=>new Promise((_,reject)=>setTimeout(()=>reject(new Error('Synthetic timeout')),5)),
  getByRole:()=>({click:()=>new Promise((_,reject)=>setTimeout(()=>reject(new Error('Synthetic disabled button')),15))})};
 const context={setDefaultTimeout(){},route:async()=>{},routeWebSocket:async()=>{},newPage:async()=>page,close:async()=>{}};
 const browser={version:()=> 'synthetic-controller-only',newContext:async()=>context,close:async()=>{closes++;}};
 try{
  const result=await runBrowser(input,{chromium:{launch:async()=>browser}});await new Promise(resolve=>setTimeout(resolve,25));
  assert.equal(result.status,'NOT_CONFIRMED');assert.equal(result.phase,'login');assert.deepEqual(result.dispatched_actions,[]);
  assert.equal(result.browser_close_returned,true);assert.equal(closes,1);assert.deepEqual(unhandled,[]);
  const intent=readFileSync(path.join(input.output_dir,'login.intent.json'),'utf8');assert.ok(!intent.includes(input.credentials.password));
 }finally{process.off('unhandledRejection',listener);}
});
