// Real headless browser, exact frozen B UI, synthetic in-memory backend only.
// No live server/Oracle/model call and no human acceptance is performed.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync,mkdtempSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import {runBrowser,sha,SOURCE_SHA,APEX_ORIGIN,JourneyError} from '../live.mjs';
import {ROOT,fixture,reseal} from './fixtures.mjs';

const PROJECT='a'.repeat(32),SOURCE_ID='ss-'+'c'.repeat(32),RUN='fox-'+'b'.repeat(20);
const B=path.join(ROOT,'work/b27a/bundle');
const PYTHON=path.join(ROOT,'fox/.venv/Scripts/python.exe');
const PLAYWRIGHT=path.join(os.homedir(),'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs');

function files(root,prefix=''){
 const values={};for(const item of readdirSync(path.join(root,prefix),{withFileTypes:true})){
  const relative=prefix?prefix+'/'+item.name:item.name;
  if(item.isDirectory())Object.assign(values,files(root,relative));else values[relative]=readFileSync(path.join(root,relative));
 }return values;
}
function plans(input){
 const code=String.raw`
import base64,json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path[:0]=[str(root/'fox'),str(root/'converter')]
from fox.intake import checked_source,inventory
from fox.project_conversion import assess_project_conversion
v=json.load(sys.stdin)
sources=[checked_source(f['name'],base64.b64decode(f['base64'])) for f in v['files']]
out={}
for name,items in (('empty',[]),('ready',sources)):
 plan=assess_project_conversion(items,project_id='a'*32,project_name=v['project']['name'],source_hash=inventory(items)['source_hash'])
 plan={k:value for k,value in plan.items() if k!='rendering_spec'}
 plan['forms']=[{k:value for k,value in form.items() if k!='native_form'} for form in plan['forms']]
 plan['selected_source_set_id']=None if name=='empty' else 'ss-'+'c'*32
 out[name]=plan
print(json.dumps(out))
`;
 return JSON.parse(execFileSync(PYTHON,['-I','-B','-c',code,B],{input:JSON.stringify(input),encoding:'utf8',maxBuffer:2_000_000,
  env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'},timeout:20000}));
}

test('actual frozen project workbench: one-shot normal UI journey over synthetic HTTP backend only',{
 skip:process.env.FOX_PROJECT_JOURNEY_BROWSER_TEST!=='1',timeout:180000,
},async t=>{
 const input=fixture(),assets=files(path.join(B,'fox/dist'));
 input.output_dir=path.join(mkdtempSync(path.join(os.tmpdir(),'fox-project-live-ui-')),'browser');
 input.ui_assets=Object.fromEntries(Object.entries(assets).map(([name,raw])=>[name,sha(raw)]));
 input.browser={playwright_module:PLAYWRIGHT,index_sha256:sha(readFileSync(PLAYWRIGHT)),
  version:JSON.parse(readFileSync(path.join(path.dirname(PLAYWRIGHT),'package.json'),'utf8')).version,channel:'msedge'};
 const derived=plans(input);input.preflight.observed_at_utc=new Date().toISOString();reseal(input);
 const state={login:false,created:false,uploaded:false,processed:false,runReads:0,evidenceRequested:false,delayedRefresh:false};const requests=[];
 function inventory(){const plan=state.uploaded?derived.ready:derived.empty;return {
  selected_source_set_id:plan.selected_source_set_id,source_hash:plan.source_hash,
  files:plan.source_files.map(file=>({file:file.name,bytes:file.bytes,sha256:file.sha256,blocks:[]})),dependencies:[],issues:[],missing_count:0,
  scope_note:'Synthetic backend only.',source_bytes:plan.source_files.reduce((n,file)=>n+file.bytes,0),
  conversion_source_bytes:plan.source_files.reduce((n,file)=>n+file.bytes,0),max_conversion_bytes:300000,
  forms_source_files:plan.source_files.filter(file=>file.kind==='FORM_XML').map(file=>file.name),
  conversion_eligible:state.uploaded,conversion_blockers:[],conversion_profile:'native-project-v1',
  source_preparation:{mode:'DIRECT_READABLE',matches_current_source:false,scope:'Synthetic metadata only.'}};}
 const run=()=>({id:RUN,project_id:PROJECT,source_hash:SOURCE_SHA,state:state.runReads>2?'VERIFIED':'QA_REQUIRED',message:'Synthetic backend state, not Oracle evidence.',
  artifact_generated:true,technical_verified:state.runReads>2,human_accepted:false,downloadable:false,preview_available:true,review_available:state.runReads>2,
  application_url:APEX_ORIGIN+'/ords/r/forms2apex_poc/f2a_synthetic/',
  steps:[{id:'generate',label:'APEX generated',state:'complete'}],forms:derived.ready.forms.map(form=>({module_id:form.module_id,state:'generated'})),
  recovery:{kind:'check_status',enabled:true,safety:'read_only'},verification_status:{enabled:false}});
 const detail=()=>({id:PROJECT,...input.project,file_count:state.uploaded?4:0,run_count:state.processed?1:0,inventory:inventory(),
  project_plan:structuredClone(state.uploaded?derived.ready:derived.empty),project_plan_error:null,
  project_capabilities:{upload:{enabled:true},process:{enabled:state.uploaded},select_version:{enabled:true},local_preparation:{enabled:false}},
  processing_notice:'Synthetic browser test only. No actual source transmission, model or database.',runs:state.processed?[run()]:[]});
 const proof=()=>({job_id:RUN,project_id:PROJECT,source_manifest_sha256:SOURCE_SHA,conversion_profile:'native-project-v1',application_count:1,form_count:2,
  application_id:12345,application_alias:'F2A_SYNTHETIC',application_url:APEX_ORIGIN+'/ords/r/forms2apex_poc/f2a_synthetic/',
  forms:derived.ready.forms.map(({module_id})=>({module_id})),form_reviews:derived.ready.forms.map(({module_id})=>({module_id})),
  reviewer_approved:true,reviewer_execution_verified:true,model_environment_verified:true,sqlcl_valid:true,import_passed:true,package_reimport_passed:true,
  human_acceptance_recorded:false,schema_preparation_sha256:'d'.repeat(64),technical_verification:{scope:'fox-project-technical-verification-v1',
   conversion_profile:'native-project-v1',job_id:RUN,source_manifest_sha256:SOURCE_SHA,package_sha256:'e'.repeat(64),authenticated_runtime_passed:true,
   clean_schema_install_passed:true,human_acceptance_recorded:false,form_results:derived.ready.forms.map(({module_id})=>({module_id}))}});
 const json=(body,status=200)=>({status:()=>status,body:async()=>Buffer.from(JSON.stringify(body)),headers:()=>({'content-type':'application/json'})});
 const sourceSummary=()=>({id:SOURCE_ID,source_hash:SOURCE_SHA,file_count:4,source_bytes:inventory().source_bytes,created:1000,origin:'upload',is_selected:true,
  run_ids:state.processed?[RUN]:[]});
 const forward=async request=>{
  const url=new URL(request.url()),method=request.method(),base='/api/projects/'+PROJECT;
  requests.push({method,path:url.pathname});
  const asset=url.pathname==='/'?'index.html':url.pathname.slice(1);
  if(method==='GET'&&Object.hasOwn(assets,asset))return {status:()=>200,body:async()=>assets[asset],headers:()=>({'content-type':asset.endsWith('.html')?'text/html':asset.endsWith('.css')?'text/css':'text/javascript'})};
  if(url.pathname==='/favicon.ico')return json({},404);
  if(url.pathname==='/api/login'&&method==='POST'){assert.deepEqual(request.postDataJSON(),input.credentials);state.login=true;return json({username:input.credentials.username});}
  if(url.pathname==='/api/session')return state.login?json({username:input.credentials.username,conversion_profile:'native-project-v1',conversion_configured:true,
   configured_project_schema_versions:[1,2],configuration_checks:[],mode:'Synthetic backend'}):json({detail:'Sign in'},401);
  if(url.pathname==='/api/health')return json({status:'ok',product:'FOX',version:'0.1.0',worker:{healthy:true,enabled:true}});
  if(url.pathname==='/api/local-preparation/capabilities')return json({enabled:false});
  if(url.pathname==='/api/projects'&&method==='GET')return json(state.created?[{id:PROJECT,...input.project,file_count:state.uploaded?4:0,run_count:state.processed?1:0}]:[]);
  if(url.pathname==='/api/projects'&&method==='POST'){assert.equal(state.created,false);state.created=true;return json({id:PROJECT},201);}
  if(url.pathname===base+'/sources'&&method==='POST'){assert.equal(state.uploaded,false);state.uploaded=true;return json(inventory());}
  if(url.pathname===base+'/runs'&&method==='POST'){assert.equal(state.processed,false);state.processed=true;return json({id:RUN,state:'QUEUED'},202);}
  if(url.pathname===base&&method==='GET'){
   if(state.processed)state.runReads++;
   if(state.evidenceRequested&&!state.delayedRefresh){state.delayedRefresh=true;await new Promise(resolve=>setTimeout(resolve,250));}
   return json(detail());
  }
  if(url.pathname===base+'/conversion-plan')return json(derived.ready);
  if(url.pathname===base+'/source-sets')return json({selected_source_set_id:state.uploaded?SOURCE_ID:null,source_sets:state.uploaded?[sourceSummary()]:[],next_cursor:null});
  if(url.pathname===base+'/source-sets/'+SOURCE_ID)return json({source_set:sourceSummary(),files:[],assessment_summary:{source_hash:SOURCE_SHA,conversion_profile:'native-project-v1'},run_ids:[]});
  if(url.pathname===base+'/runs/'+RUN+'/evidence'){state.evidenceRequested=true;return json(proof());}
  throw new JourneyError('SYNTHETIC_BACKEND_UNEXPECTED_ROUTE');
 };
 const result=await runBrowser(input,{forward});
 t.diagnostic('Synthetic-backend browser artifacts: '+input.output_dir);
 assert.equal(result.status,'SIMULATED_BACKEND_VERIFIED_NOT_LIVE',JSON.stringify(result));
 assert.equal(result.browser_close_returned,true);assert.deepEqual(result.dispatched_actions,['login','create','upload','process']);
 assert.deepEqual(result.states_observed,['QA_REQUIRED','VERIFIED']);assert.equal(state.delayedRefresh,true);
 assert.equal(result.acceptance_requests,0);assert.equal(result.download_requests,0);
 assert.equal(requests.filter(row=>row.method==='POST').length,4);assert.ok(!requests.some(row=>/accept|download/.test(row.path)));
 assert.equal(Object.keys(result.served_assets).length,Object.keys(assets).length);
 const retained=JSON.stringify(result)+readFileSync(path.join(input.output_dir,'input.json'),'utf8');assert.ok(!retained.includes(input.credentials.password));
});
