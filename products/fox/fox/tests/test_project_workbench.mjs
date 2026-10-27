// UI contract/render tests. Browser mode is isolated, synthetic and opt-in.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdir,writeFile,stat} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';

const foxRoot=fileURLToPath(new URL('../',import.meta.url));
const workspace=path.dirname(foxRoot),require=createRequire(import.meta.url);
const sources={};
for(const name of ['projectConversion.ts','ProjectWorkbench.tsx','preparedUpload.ts','projectWorkbench.css'])sources[name]=await readFile(path.join(foxRoot,'web',name),'utf8');
const sha=raw=>createHash('sha256').update(raw).digest('hex');
function load(source,fileName,imports={}){
 const compiled=ts.transpileModule(source,{fileName,compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,jsx:ts.JsxEmit.ReactJSX,esModuleInterop:true}}).outputText;
 const module={exports:{}};
 new Function('require','module','exports',compiled)(name=>Object.hasOwn(imports,name)?imports[name]:name.endsWith('.css')?{}:require(name),module,module.exports);
 return module.exports;
}
const api=load(sources['projectConversion.ts'],'projectConversion.ts');
const upload=load(sources['preparedUpload.ts'],'preparedUpload.ts');
const components=load(sources['ProjectWorkbench.tsx']+'\nexport {ReviewForms,OutputRun,RunProgress,Finding,FormDetails};','ProjectWorkbench.tsx',{'./projectConversion':api,'./preparedUpload':upload});
const render=(Component,props)=>renderToStaticMarkup(React.createElement(Component,props));
const clone=value=>JSON.parse(JSON.stringify(value));

// Exercise the real producer's fixture helpers and assessment API. No app
// initialization, model, SQLcl, database, credentials or live network is used.
const fixtureCode=String.raw`
import json,runpy
d=runpy.run_path('tests/test_project_conversion.py')
pair,assess,source,module,xml=[d[x] for x in ('pair','assess','source','module','xml')]
files=pair()+pair('BETA','FOX_NATIVE_BETA')
human=pair();human[0]=source('alpha.xml',xml(module(extra='<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="UTIL.RUN();"/>')))
unsupported=pair();unsupported[0]=source('alpha.xml',xml(module().replace('Prompt="Title"','Prompt="Title" ItemType="Push Button"')))
ordinary_human=pair('BETA','ORDER_ITEMS');ordinary_human[0]=source('beta.xml',xml(module('BETA','ORDER_ITEMS',extra='<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="UTIL.RUN();"/>')))
result={'ready':assess(files),'changed':assess(pair(prompt='Revised title')+pair('BETA','FOX_NATIVE_BETA')),
 'missing':assess(pair()[:1]),'human':assess(human),'unsupported':assess(unsupported),'empty':assess([]),
 'orders':assess(pair(table='ORDERS')),'orders_shared':assess(pair(table='ORDERS')+pair('BETA','ORDERS')),
 'orders_mixed':assess(pair(table='ORDERS')+pair('BETA','FOX_NATIVE_BETA')),
 'orders_multi':assess(pair(table='ORDERS')+pair('BETA','ORDER_ITEMS')),
 'orders_blocked':assess(pair(table='ORDERS')+ordinary_human),
 'capacity':assess([source('note'+str(x)+'.txt','Synthetic note.') for x in range(51)])}
print(json.dumps(result,ensure_ascii=False))
`;
const python=process.env.FOX_TEST_PYTHON??path.join(foxRoot,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
const fixtures=JSON.parse(execFileSync(python,['-B','-c',fixtureCode],{
 cwd:foxRoot,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'},encoding:'utf8',timeout:15000,maxBuffer:2_000_000,
}));
const binding=(plan=fixtures.ready)=>({project_id:plan.project_id,source_hash:plan.source_hash,selected_source_set_id:'ss-'+(plan===fixtures.changed?'2':'1').repeat(32)});
const confirmations={approved_redacted_source:true,approved_external_ai:true,approved_prototype_scope:true};
const project={id:fixtures.ready.project_id,name:'Synthetic UI QA — two forms',customer:'Automated UI test only',description:'No live conversion, model call or business acceptance is performed by this test.'};
const baseRun=(overrides={})=>({id:'fox-'+'a'.repeat(20),project_id:project.id,source_hash:fixtures.ready.source_hash,state:'VERIFIED',message:'Synthetic UI fixture only.',artifact_generated:true,technical_verified:true,human_accepted:false,downloadable:false,preview_available:true,review_available:true,...overrides});
const common={project,source:binding(),plan:fixtures.ready,runs:[],capabilities:{upload:{enabled:true},generate:{enabled:true},select_version:{enabled:true}},processingNotice:'Synthetic UI fixture: no source is transmitted by this test.',onUpload:async()=>({status:'confirmed'}),onGenerate:async()=>({status:'confirmed'})};

test('real two-form producer is presented as one project plan, not generated output',()=>{
 const plan=api.readProjectPlan(fixtures.ready,binding());
 assert.equal(plan.forms.length,2);assert.equal(plan.can_generate,true);
 const html=render(components.ReviewForms,{plan,onResolve:()=>{}});
 assert.match(html,/All selected forms belong to one planned APEX application/);
 assert.match(html,/ALPHA/);assert.match(html,/BETA/);
 assert.match(html,/Planned page/);assert.match(html,/not a generated or validated application/);
 assert.doesNotMatch(html,/APEX application generated/);
});
for(const kind of ['ready','changed','missing','human','unsupported','empty','capacity']){
 test(`actual producer ${kind} payload survives the presentation contract`,()=>{
  const plan=api.readProjectPlan(fixtures[kind],binding(fixtures[kind]));
  assert.equal(plan.state,fixtures[kind].state);
  assert.deepEqual(plan.summary,fixtures[kind].summary);
 });
}
for(const kind of ['orders','orders_shared','orders_mixed','orders_multi','orders_blocked'])test(`real ${kind} storage plan preserves its source and public shape`,()=>{
 const sourcePlan=fixtures[kind],plan=api.readProjectPlan(sourcePlan,binding(sourcePlan));
 assert.equal(plan.schema_version,1);assert.equal(plan.scope,'fox-project-conversion-plan-v1');
 assert.equal(Object.hasOwn(plan,'rendering_spec'),false);
 assert.deepEqual(plan.forms.map(form=>form.table_name),sourcePlan.forms.map(form=>form.table_name));
 assert.deepEqual(plan.forms.map(form=>form.ddl_sources),sourcePlan.forms.map(form=>form.ddl_sources));
 assert.ok(plan.forms.every(form=>!Object.hasOwn(form,'native_form')));
 if(kind==='orders_blocked'){assert.equal(plan.can_generate,false);assert.ok(plan.forms.every(form=>!Object.hasOwn(form,'storage_mapping')));}
 else {assert.equal(plan.can_generate,true);assert.ok(plan.forms.every(form=>form.storage_mapping));assert.deepEqual(plan.forms.map(form=>form.storage_mapping),sourcePlan.forms.map(form=>form.storage_mapping));}
});
test('all-FOX_NATIVE plans retain their original unmapped presentation',()=>{
 const plan=api.readProjectPlan(fixtures.ready,binding());assert.ok(plan.forms.every(form=>!Object.hasOwn(form,'storage_mapping')));
 const html=render(components.FormDetails,{form:plan.forms[0],onResolve:()=>{}});assert.match(html,/Supplied table:/);assert.doesNotMatch(html,/Planned prototype table|Source and prototype tables/);
});
test('ORDERS mapping is a read-only empty-table plan with detailed hashes under evidence',()=>{
 const plan=api.readProjectPlan(fixtures.orders,binding(fixtures.orders)),form=plan.forms[0],mapping=form.storage_mapping;
 assert.equal(form.table_name,'ORDERS');assert.equal(mapping.target_table_name,'FOX_NATIVE_'+mapping.identity_sha256.slice(0,19).toUpperCase());
 const html=render(components.FormDetails,{form,onResolve:()=>{}}),beforeEvidence=html.slice(0,html.indexOf('<summary>Show table mapping evidence'));
 assert.match(html,/Original table/);assert.match(html,/>ORDERS<\/code>/);assert.match(html,/Planned empty table/);
 assert.match(html,/Your original files stay unchanged\. No production data is copied\./);
 assert.match(html,/Changing the table structure creates a separate empty prototype table\. This is not a data migration\./);
 assert.match(html,/This is a plan, not a generated or validated application/);
 assert.equal(beforeEvidence.includes(mapping.identity_sha256),false);assert.equal(beforeEvidence.includes(mapping.source_schema_sha256),false);
 assert.ok(html.includes(mapping.identity_sha256)&&html.includes(mapping.source_schema_sha256));
 assert.doesNotMatch(html,/<input|<select|<textarea|contenteditable|APEX application generated/);
});
for(const [label,mutate] of [
 ['null',value=>{value.forms[0].storage_mapping=null;}],
 ['undefined',value=>{value.forms[0].storage_mapping=undefined;}],
 ['array',value=>{value.forms[0].storage_mapping=[];}],
 ['missing key',value=>{delete value.forms[0].storage_mapping.source_schema_sha256;}],
 ['extra key',value=>{value.forms[0].storage_mapping.generated=true;}],
 ['wrong version',value=>{value.forms[0].storage_mapping.schema_version=2;}],
 ['wrong scope',value=>{value.forms[0].storage_mapping.scope='fox-project-module-execution-v2';}],
 ['cross project',value=>{value.forms[0].storage_mapping.project_id='another-project';}],
 ['different source table',value=>{value.forms[0].storage_mapping.source_table_name='OTHER_TABLE';}],
 ['lowercase source table',value=>{value.forms[0].storage_mapping.source_table_name=value.forms[0].table_name='orders';}],
 ['source table newline',value=>{value.forms[0].storage_mapping.source_table_name=value.forms[0].table_name='ORDERS\n';}],
 ['malformed source schema',value=>{value.forms[0].storage_mapping.source_schema_sha256='A'.repeat(64);}],
 ['source schema newline',value=>{value.forms[0].storage_mapping.source_schema_sha256='a'.repeat(64)+'\n';}],
 ['malformed identity',value=>{value.forms[0].storage_mapping.identity_sha256='b'.repeat(63);}],
 ['identity newline',value=>{const mapping=value.forms[0].storage_mapping;mapping.identity_sha256='b'.repeat(64)+'\n';mapping.target_table_name='FOX_NATIVE_'+'B'.repeat(19);}],
 ['mismatched target',value=>{value.forms[0].storage_mapping.target_table_name='FOX_NATIVE_WRONG';}],
 ['lowercase target',value=>{value.forms[0].storage_mapping.target_table_name=value.forms[0].storage_mapping.target_table_name.toLowerCase();}],
 ['partial mapping',value=>{delete value.forms[0].storage_mapping;}],
 ['all ordinary mappings stripped',value=>{for(const form of value.forms)delete form.storage_mapping;}],
 ['same target for different sources',value=>{const first=value.forms[0].storage_mapping,second=value.forms[1].storage_mapping;second.identity_sha256=first.identity_sha256.slice(0,19)+(first.identity_sha256[19]==='0'?'1':'0')+first.identity_sha256.slice(20);second.target_table_name=first.target_table_name;}],
])test(`storage mapping ${label} fails closed without granting generation`,()=>{
 const value=clone(fixtures.orders_multi);mutate(value);const result=api.presentProjectPlan(value,binding(fixtures.orders_multi));assert.equal(result.plan,null);
 assert.equal(api.processAvailability(result.plan,{enabled:true},true,confirmations,'Synthetic route').enabled,false);
});
for(const field of ['source_schema_sha256','identity_sha256'])test(`shared source table requires matching ${field}`,()=>{
 const value=clone(fixtures.orders_shared),mapping=value.forms[1].storage_mapping;mapping[field]='e'.repeat(64);
 if(field==='identity_sha256')mapping.target_table_name='FOX_NATIVE_'+mapping.identity_sha256.slice(0,19).toUpperCase();
 assert.equal(api.presentProjectPlan(value,binding(fixtures.orders_shared)).plan,null);
});
test('a blocked project cannot gain a storage mapping even for otherwise-ready forms',()=>{
 const value=clone(fixtures.orders_blocked);for(const form of value.forms){const mapped=fixtures.orders_multi.forms.find(item=>item.table_name===form.table_name);form.storage_mapping=clone(mapped.storage_mapping);}
 assert.equal(api.presentProjectPlan(value,binding(fixtures.orders_blocked)).plan,null);
});
test('nullable producer evidence is normalized without inventing a source',()=>{
 const plan=api.readProjectPlan(fixtures.missing,binding(fixtures.missing));
 assert.ok(plan.forms[0].findings.length);
 assert.ok(plan.forms[0].findings.every(item=>typeof item.source==='string'&&typeof item.evidence==='string'));
});
test('capacity refusal says assessment incomplete rather than zero forms found',()=>{
 const plan=api.readProjectPlan(fixtures.capacity,binding(fixtures.capacity));
 assert.equal(plan.assessment_complete,false);
 const html=render(components.ReviewForms,{plan,onResolve:()=>{}});
 assert.match(html,/Assessment not completed/);assert.match(html,/51 selected sources have not been assessed/);
 assert.doesNotMatch(html,/No Forms modules are ready/);
});
for(const mutate of [
 value=>{value.can_generate=true;value.state='READY';},
 value=>{value.summary.blocking_findings=0;},
 value=>{value.forms[0].findings[0].owner='AI_DECIDES';},
 value=>{value.forms[0].state='ACCEPTED';},
 value=>{value.source_hash='a'.repeat(64);},
 value=>{value.project_id='another-project';},
 value=>{value.scope='untrusted-plan';},
 value=>{value.assessment_complete='true';},
])test('changed or inconsistent blocked plan cannot become ready',()=>{
 const value=clone(fixtures.human);mutate(value);
 assert.equal(api.presentProjectPlan(value,binding(fixtures.human)).plan,null);
});
for(const mutate of [
 value=>{value.forms[1].module_id=value.forms[0].module_id;},
 value=>{value.forms[1].planned_pages=clone(value.forms[0].planned_pages);},
 value=>{value.source_files.find(file=>file.kind==='FORM_XML').module_ids=[];},
 value=>{value.forms[0].source_sha256='b'.repeat(64);},
 value=>{value.forms[0].mapping[0].status='GENERATED';},
 value=>{value.summary.ready_forms=3;},
])test('source membership, planned mapping and page uniqueness stay explicit',()=>{
 const value=clone(fixtures.ready);mutate(value);
 assert.equal(api.presentProjectPlan(value,binding()).plan,null);
});
test('human meaning and technical ownership are shown separately',()=>{
 const plan=api.readProjectPlan(fixtures.human,binding(fixtures.human));
 const item=plan.forms.flatMap(form=>form.findings).find(item=>item.category==='NEEDS_HUMAN');
 const html=render(components.Finding,{finding:item,moduleName:'ALPHA',onUpload:()=>{}});
 assert.match(html,/Business \/ application owner/);assert.match(html,/FOX will not guess/);
 assert.match(html,/Next action/);assert.doesNotMatch(html,/Approve automatically|Ignore and continue/);
});
test('process needs both whole-project readiness and an enabled backend capability',()=>{
 const plan=api.readProjectPlan(fixtures.ready,binding());
 assert.equal(api.processAvailability(plan,{enabled:true},true,confirmations,'Approved route').enabled,true);
 for(const capability of [undefined,null,{},true,{enabled:'true'},{enabled:false,reason:'Service unavailable'}]){
  assert.equal(api.processAvailability(plan,capability,true,confirmations,'Approved route').enabled,false);
 }
 assert.equal(api.processAvailability(plan,{enabled:true},false,confirmations,'Approved route').enabled,false);
 assert.equal(api.processAvailability(plan,{enabled:true},true,confirmations,'').enabled,false);
 assert.equal(api.processAvailability(plan,{enabled:true},true,confirmations,'Approved route',true).enabled,false);
 assert.equal(api.processAvailability(plan,{enabled:true},true,confirmations,'Approved route',false,true).enabled,false);
 assert.equal(api.processAvailability(api.readProjectPlan(fixtures.human,binding(fixtures.human)),{enabled:true},true,confirmations,'Approved route').enabled,false);
});
test('the exact three user confirmations are required',()=>{
 const plan=api.readProjectPlan(fixtures.ready,binding());
 for(const value of [{},{a:true,b:true,c:true},{...confirmations,approved_external_ai:false},{...confirmations,approved_external_ai:'true'},{...confirmations,extra:true}]){
  assert.equal(api.processAvailability(plan,{enabled:true},true,value,'Approved route').enabled,false);
 }
});
test('action context binds project, selected version, plan and historical run source separately',()=>{
 const plan=api.readProjectPlan(fixtures.ready,binding());
 const context=api.actionContext(binding(),plan,'fox-'+'a'.repeat(20),'b'.repeat(64));
 assert.equal(context.project_id,project.id);assert.equal(context.source_hash,fixtures.ready.source_hash);
 assert.equal(context.expected_current_source_set_id,binding().selected_source_set_id);
 assert.equal(context.plan_sha256,plan.plan_sha256);assert.equal(context.run_source_hash,'b'.repeat(64));
 assert.throws(()=>api.actionContext(binding(),plan,'fox-abc'));
 assert.throws(()=>api.actionContext({...binding(),project_id:'other'},plan));
});
test('generated, verified and accepted are distinct facts',()=>{
 const generated=api.presentProjectRun(baseRun({state:'QA_REQUIRED',technical_verified:false}),binding().source_hash,project.id);
 assert.equal(generated.generated,true);assert.equal(generated.technicalVerified,false);assert.equal(generated.humanAccepted,false);assert.equal(generated.canDownload,false);
 const verified=api.presentProjectRun(baseRun(),binding().source_hash,project.id);
 assert.equal(verified.technicalVerified,true);assert.equal(verified.humanAccepted,false);assert.equal(verified.canReview,true);assert.equal(verified.canDownload,false);
 const accepted=api.presentProjectRun(baseRun({state:'ACCEPTED',human_accepted:true,downloadable:true}),binding().source_hash,project.id);
 assert.equal(accepted.canDownload,true);assert.equal(accepted.canReview,false);
});
test('legacy state, queue completion and recent contact do not fabricate proof',()=>{
 for(const value of [baseRun({technical_verified:undefined}),baseRun({state:'ACCEPTED',human_accepted:undefined,downloadable:true}),baseRun({artifact_generated:undefined,downloadable:true}),baseRun({state:'QA_REQUIRED',verification_status:{state:'completed',operator_contact:'recent'},technical_verified:false})]){
  const result=api.presentProjectRun(value,binding().source_hash,project.id);
  assert.equal(result.canDownload,false);assert.equal(result.humanAccepted,false);
 }
 assert.equal(api.presentProjectRun(null,binding().source_hash,project.id).label,'Status unavailable');
});
test('historical unaccepted output is locked, accepted historical bytes remain releasable',()=>{
 const changed=binding(fixtures.changed),plan=api.readProjectPlan(fixtures.changed,changed);
 const old=baseRun();
 assert.equal(api.presentProjectRun(old,changed.source_hash,project.id).canReview,false);
 const html=render(components.OutputRun,{run:old,binding:changed,plan,busy:false,onPreview:()=>{},onDownload:()=>{},renderHumanReview:()=>React.createElement('p',null,'SECRET_REVIEW_SLOT')});
 assert.match(html,/Earlier source version/);assert.doesNotMatch(html,/SECRET_REVIEW_SLOT/);
 assert.match(html,/<button[^>]*disabled=""[^>]*>.*?Download APEX package/s);
 const accepted=baseRun({state:'ACCEPTED',human_accepted:true,downloadable:true});
 assert.equal(api.presentProjectRun(accepted,changed.source_hash,project.id).canDownload,true);
});
test('another project run never gets preview/review/download authority',()=>{
 const run=baseRun({project_id:'another-project',state:'ACCEPTED',human_accepted:true,downloadable:true});
 const view=api.presentProjectRun(run,binding().source_hash,project.id);
 assert.equal(view.canDownload,false);assert.equal(view.canPreview,false);assert.equal(view.canReview,false);
 const html=render(components.default,{...common,runs:[run]});
 assert.match(html,/Some run records could not be matched to this project/);
});
test('malformed or duplicate stage checkpoints are not rendered as progress',()=>{
 const run=baseRun({state:'PROCESSING',steps:[{id:'a',label:'Generate',state:'complete'},{id:'a',label:'Import',state:'complete'}],forms:[{module_id:'same',state:'generated'},{module_id:'same',state:'generated'}]});
 const view=api.presentProjectRun(run,binding().source_hash,project.id);
 assert.equal(view.detailsIncomplete,true);assert.deepEqual(view.steps,[]);assert.deepEqual(view.forms,[]);
});
test('retry is absent unless server confirms a safe failed-step action',()=>{
 for(const recovery of [undefined,{kind:'retry_step',enabled:true},{kind:'retry_step',enabled:true,safety:'read_only'},{kind:'start_over',enabled:true,safety:'server_confirmed_safe'},{kind:'resume',enabled:false,safety:'server_confirmed_safe'}]){
  assert.equal(api.recoveryAvailability(baseRun({state:'ATTENTION',recovery}),true).enabled,false);
 }
 assert.equal(api.recoveryAvailability(baseRun({state:'ATTENTION',recovery:{kind:'retry_step',enabled:true,safety:'server_confirmed_safe'}}),true).enabled,true);
 assert.equal(api.recoveryAvailability(baseRun({state:'ATTENTION',recovery:{kind:'check_status',enabled:true,safety:'read_only'}}),true).enabled,true);
 assert.equal(api.recoveryAvailability(baseRun({state:'PROCESSING',recovery:{kind:'resume',enabled:true,safety:'server_confirmed_safe'}}),true).enabled,false);
});
test('raw input guidance does not pretend the browser converts Forms binaries',()=>{
 const html=render(components.default,{...common,source:binding(fixtures.empty),plan:fixtures.empty});
 assert.match(html,/binary files need approved Oracle tooling/);
 assert.match(html,/hosted browser does not perform that conversion or upload raw binaries/);
 assert.doesNotMatch(html,/python -m|frmf2xml\.bat|Codex must/);
 assert.match(html,/One APEX application/);
});
test('project dashboard manages separate projects without inventing conversion metrics',()=>{
 const html=render(components.ProjectDashboard,{projects:[project,{id:'two',name:'Different application',customer:'Another team',file_count:7,run_count:2}],onOpenProject:()=>{},onNewProject:()=>{}});
 assert.match(html,/2 projects/);assert.match(html,/Different application/);assert.match(html,/7 source files/);
 assert.match(html,/Sources not yet counted/);assert.doesNotMatch(html,/7 forms converted/);
});
test('selected version metadata cannot label another source hash as current',()=>{
 const html=render(components.default,{...common,versions:[{id:binding().selected_source_set_id,label:'Incorrect version metadata',source_hash:'b'.repeat(64),file_count:4}]});
 assert.match(html,/selected project and source version do not match/);
 assert.doesNotMatch(html,/<strong>2<\/strong><span>Forms assessed/);
});
test('invalid source binding offers a safe project-only reload without fabricated source context',()=>{
 const html=render(components.default,{...common,source:{...binding(),project_id:'wrong-project'},onReloadProject:async()=>({status:'confirmed'})});
 const reload=[...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map(item=>item[0]).find(item=>item.includes('Reload project'));
 assert.ok(reload);assert.doesNotMatch(reload,/disabled=/);
 assert.match(html,/Reload this project before taking action/);
});
test('malformed nested error or stage values cannot crash the render or invent messages',()=>{
 const run=baseRun({state:'ATTENTION',stage_message:{secret:'do not stringify'},error:{message:{unexpected:'object'},action:['bad'],owner:'BUSINESS_OWNER'}});
 const view=api.presentProjectRun(run,binding().source_hash,project.id);
 assert.equal(view.stageMessage,null);assert.equal(view.error,null);assert.equal(view.detailsIncomplete,true);
 let html;assert.doesNotThrow(()=>{html=render(components.RunProgress,{run,binding:binding(),plan:api.readProjectPlan(fixtures.ready,binding()),busy:false,execute:async()=>false});});
 assert.match(html,/Some progress or error details could not be read/);assert.doesNotMatch(html,/\[object Object\]|do not stringify/);
});
test('human review participates in the workbench mutation boundary',()=>{
 const props={run:baseRun(),binding:binding(),plan:api.readProjectPlan(fixtures.ready,binding()),onPreview:()=>{},onDownload:()=>{},renderHumanReview:(_run,_context,controls)=>React.createElement('button',{disabled:controls.disabled},'Review mutation')};
 for(const [busy,disabled]of [[true,false],[false,true]]){
  const html=render(components.OutputRun,{...props,busy,reviewControls:{disabled,perform:async()=>false}});
  assert.match(html,/<fieldset[^>]*disabled=""/);assert.match(html,/Review controls are paused/);
  assert.match(html,/<button disabled="">Review mutation<\/button>/);
 }
 const missing=render(components.OutputRun,{...props,busy:false});
 assert.doesNotMatch(missing,/Review mutation/);assert.match(missing,/Human review has not been connected/);
});

test('isolated browser: guided flow, source reset, unknown writes and historical output',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:120000},async()=>{
 const packageRoot=process.env.FOX_TEST_NODE_MODULES;
 assert.ok(packageRoot,'Use the discovered bundled browser packages; no install is performed.');
 const runtimeRequire=createRequire(path.join(packageRoot,'../package.json'));
 const {chromium}=runtimeRequire('playwright');
 const {build}=require('esbuild');
 const out=path.resolve(workspace,process.env.FOX_UI_ARTIFACT_DIR??'work/project-workbench-ui-20261025a');
 assert.ok(out.startsWith(path.join(workspace,'work')+path.sep));
 await assert.rejects(stat(out),{code:'ENOENT'});
 await mkdir(out);
 const source=String.raw`
import React,{useState} from 'react';import{createRoot}from'react-dom/client';
import Workbench from './web/ProjectWorkbench';import './web/style.css';
const f=${JSON.stringify(fixtures)},project=${JSON.stringify(project)};
window.__events=[];window.__heldByteReads=[];window.__holdBytes=false;window.__holdRefresh=false;window.__holdReview=false;const actualArrayBuffer=File.prototype.arrayBuffer;
File.prototype.arrayBuffer=function(){if(!window.__holdBytes)return actualArrayBuffer.call(this);const file=this;return new Promise((resolve,reject)=>window.__heldByteReads.push(()=>actualArrayBuffer.call(file).then(resolve,reject)))};
window.__releaseBytes=async()=>{window.__holdBytes=false;await Promise.all(window.__heldByteReads.map(release=>release()))};
const fixtureVersions=Object.entries(f).map(([name,p],index)=>({id:'ss-'+String(index+1).repeat(32),label:name==='ready'?'Original supplied version':name==='changed'?'Revised supplied version':name+' fixture',source_hash:p.source_hash,file_count:p.source_files.length}));
const sourceFor=p=>({project_id:p.project_id,source_hash:p.source_hash,selected_source_set_id:fixtureVersions.find(v=>v.source_hash===p.source_hash).id});
function Fixture(){const[plan,setPlan]=useState(f.ready),[runs,setRuns]=useState([]),[unknown,setUnknown]=useState(false),[safe,setSafe]=useState(false),[invalid,setInvalid]=useState(false);
 const source=invalid?{...sourceFor(plan),source_hash:'b'.repeat(64)}:sourceFor(plan),contextNote='Automated isolated UI QA only. No model, database, conversion or live acceptance.';
 const run=()=>({id:'fox-'+ 'a'.repeat(20),project_id:project.id,source_hash:f.ready.source_hash,state:'VERIFIED',message:contextNote,artifact_generated:true,technical_verified:true,human_accepted:false,downloadable:false,preview_available:true,review_available:true});
 return <><div className="fixture-controls" aria-label="Synthetic test controls"><strong>Isolated UI QA only</strong><button onClick={()=>{setPlan(f.human);setRuns([])}}>Show human blocker</button><button onClick={()=>{setPlan(f.ready);setRuns([])}}>Show ready plan</button><button onClick={()=>{setPlan(f.empty);setRuns([])}}>Show empty project</button><button onClick={()=>setPlan(f.changed)}>Change source version</button><button onClick={()=>setUnknown(true)}>Simulate unconfirmed action</button><button onClick={()=>setSafe(true)}>Confirm safe status</button><button onClick={()=>setInvalid(true)}>Invalidate source binding</button><button onClick={()=>setRuns([run()])}>Show verified fixture</button><button onClick={()=>setRuns([{...run(),state:'ACCEPTED',human_accepted:true,downloadable:true}])}>Show accepted fixture</button></div><main><Workbench project={project} source={source} plan={plan} runs={runs} processingNotice={contextNote} versions={fixtureVersions} capabilities={{upload:{enabled:true},generate:{enabled:true},select_version:{enabled:true}}}
 onUpload={async(files,mode,context)=>{window.__events.push({kind:'upload',files:files.map(x=>x.name),mode,context});return{status:'confirmed'}}}
 onGenerate={async(context,confirmations)=>{window.__events.push({kind:'generate',context,confirmations});return{status:unknown?'unconfirmed':'confirmed'}}}
 onRefresh={async(context)=>{window.__events.push({kind:'refresh',context});if(window.__holdRefresh)return new Promise(resolve=>window.__releaseRefresh=resolve);return{status:'confirmed',safe_to_continue:safe}}}
 onReloadProject={async(projectId)=>{window.__events.push({kind:'reload-project',projectId});setInvalid(false);return{status:'confirmed'}}}
 onSelectVersion={async(id,context)=>{window.__events.push({kind:'select',id,context});setPlan(Object.values(f).find(p=>p.source_hash===fixtureVersions.find(v=>v.id===id).source_hash));return{status:'confirmed'}}}
 onDownload={context=>window.__events.push({kind:'download',context})} onPreview={context=>window.__events.push({kind:'preview',context})}
 renderHumanReview={(_run,context,controls)=><div data-testid="review-slot"><p>Interactive review fixture only. No business acceptance is recorded.</p><label>Synthetic review notes<textarea aria-label="Synthetic review notes"/></label><button data-testid="review-button" onClick={()=>void controls.perform(async()=>{window.__events.push({kind:'synthetic-review',context});if(window.__holdReview)return new Promise(resolve=>window.__releaseReview=resolve);return{status:'confirmed'}})}>Record synthetic review fixture</button></div>}/></main></>;
}createRoot(document.getElementById('root')).render(<Fixture/>);
`;
 const built=await build({stdin:{contents:source,resolveDir:foxRoot,sourcefile:'ui-proof.tsx',loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',define:{'process.env.NODE_ENV':'"production"'},logLevel:'silent'});
 const js=built.outputFiles.find(file=>file.path.endsWith('.js')).text,css=built.outputFiles.find(file=>file.path.endsWith('.css')).text;
 const browser=await chromium.launch({channel:'msedge',headless:true});
 let context;
 const events=[];
 try{
  context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
  await context.setOffline(true);await context.route('**/*',route=>route.abort());
  const page=await context.newPage();page.on('pageerror',error=>events.push(error.message));
  await page.setContent('<div id="root"></div>');await page.addStyleTag({content:css+'body{margin:0}.fixture-controls{padding:10px 18px;background:#e6ebe2;display:flex;gap:8px;flex-wrap:wrap}.fixture-controls button{padding:7px 10px;font-size:12px}main{max-width:1280px;padding:32px 40px}'});await page.addScriptTag({content:js});
  await page.getByRole('heading',{name:'Review every form'}).waitFor();
  await page.screenshot({path:path.join(out,'desktop-form-review.png')});
  await page.getByRole('button',{name:'Simulate unconfirmed action',exact:true}).click();
  await page.getByRole('button',{name:'4 Convert',exact:true}).click();
  const checks=page.getByRole('group',{name:'Confirm before processing this source version'}).getByRole('checkbox');
  for(let index=0;index<3;index++)await checks.nth(index).check();
  const generate=page.getByRole('button',{name:'Generate APEX application',exact:true});await generate.click();
  await page.getByText('Check the existing result first.',{exact:true}).waitFor();assert.equal(await generate.isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__events.filter(x=>x.kind==='generate').length),1);
  await page.getByRole('button',{name:'Check status',exact:true}).click();assert.equal(await generate.isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__events.filter(x=>x.kind==='generate').length),1);
  await page.getByRole('button',{name:'Confirm safe status',exact:true}).click();await page.getByRole('button',{name:'Check status',exact:true}).click();
  await page.getByRole('button',{name:'Change source version',exact:true}).click();
  await page.getByRole('button',{name:'4 Convert',exact:true}).click();
  assert.equal(await page.getByRole('group',{name:'Confirm before processing this source version'}).getByRole('checkbox',{checked:true}).count(),0);assert.equal(await generate.isDisabled(),true);
  await page.getByRole('button',{name:'1 Upload',exact:true}).click();
  await page.getByRole('radio',{name:'Readable files, without a preparation manifest'}).check();
  await page.getByLabel('Choose project source files').setInputFiles({name:'raw.fmb',mimeType:'application/octet-stream',buffer:Buffer.from('binary')});
  await page.getByText(/These are raw Forms binaries/).waitFor();assert.equal(await page.getByRole('button',{name:'Upload and assess',exact:true}).isDisabled(),true);
  await page.getByLabel('Choose project source files').setInputFiles({name:'approved.txt',mimeType:'text/plain',buffer:Buffer.from('Approved synthetic readable source.')});
  await page.evaluate(()=>{window.__holdBytes=true;window.__heldByteReads=[];});
  await page.getByRole('button',{name:'Upload and assess',exact:true}).evaluate(button=>{button.click();button.click();});
  await page.waitForFunction(()=>window.__heldByteReads.length===1);
  assert.equal(await page.evaluate(()=>window.__events.filter(x=>x.kind==='upload').length),0);
  await page.evaluate(()=>window.__releaseBytes());
  await page.waitForFunction(()=>window.__events.filter(x=>x.kind==='upload').length===1);
  assert.equal(await page.evaluate(()=>window.__events.filter(x=>x.kind==='upload').length),1);
  const uploaded=await page.evaluate(()=>window.__events.find(x=>x.kind==='upload'));
  assert.equal(uploaded.context.source_hash,fixtures.changed.source_hash);assert.equal(uploaded.context.expected_current_source_set_id,'ss-'+'2'.repeat(32));
  await page.getByRole('button',{name:'Invalidate source binding',exact:true}).click();
  const reload=page.getByRole('button',{name:'Reload project',exact:true});assert.equal(await reload.isEnabled(),true);await reload.click();
  await page.getByRole('heading',{name:'Review every form',exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.__events.filter(x=>x.kind==='reload-project').length),1);
  assert.equal(await page.evaluate(()=>window.__events.find(x=>x.kind==='reload-project').projectId),project.id);
  await page.getByRole('button',{name:'Show human blocker',exact:true}).click();await page.getByRole('button',{name:'3 Resolve',exact:true}).click();
  await page.getByText(/FOX will not guess the intended business behavior/).first().waitFor();
  await page.screenshot({path:path.join(out,'desktop-human-decision.png')});
  await page.getByRole('button',{name:'Show ready plan',exact:true}).click();await page.getByRole('button',{name:'Show verified fixture',exact:true}).click();
  await page.getByRole('button',{name:'5 Output',exact:true}).click();await page.getByTestId('review-slot').waitFor();
  assert.equal(await page.getByRole('button',{name:'Download APEX package',exact:true}).isDisabled(),true);
  await page.getByLabel('Synthetic review notes').fill('Synthetic notes only. Not human acceptance.');
  await page.evaluate(()=>{window.__holdRefresh=true;});await page.getByRole('button',{name:'Refresh',exact:true}).click();
  const reviewButton=page.getByTestId('review-button');assert.equal(await reviewButton.isDisabled(),true);
  await reviewButton.evaluate(button=>button.click());assert.equal(await page.evaluate(()=>window.__events.filter(x=>x.kind==='synthetic-review').length),0);
  await page.evaluate(()=>{window.__holdRefresh=false;window.__releaseRefresh({status:'confirmed',safe_to_continue:false});});
  await page.waitForFunction(()=>!document.querySelector('[data-testid="review-button"]').matches(':disabled'));
  assert.equal(await page.getByLabel('Synthetic review notes').inputValue(),'Synthetic notes only. Not human acceptance.');
  await page.evaluate(()=>{window.__holdReview=true;});await reviewButton.click();
  assert.equal(await page.getByLabel('Select a saved source version').isDisabled(),true);
  assert.equal(await reviewButton.isDisabled(),true);await reviewButton.evaluate(button=>button.click());
  assert.equal(await page.evaluate(()=>window.__events.filter(x=>x.kind==='synthetic-review').length),1);
  await page.evaluate(()=>{window.__holdReview=false;window.__releaseReview({status:'unconfirmed'});});
  await page.getByText('Check the existing result first.',{exact:true}).waitFor();assert.equal(await reviewButton.isDisabled(),true);
  assert.equal(await page.getByLabel('Synthetic review notes').inputValue(),'Synthetic notes only. Not human acceptance.');
  await page.screenshot({path:path.join(out,'desktop-review-paused.png')});
  await page.getByRole('button',{name:'Check status',exact:true}).click();
  await page.getByRole('button',{name:'Change source version',exact:true}).click();await page.getByRole('button',{name:'5 Output',exact:true}).click();
  assert.equal(await page.getByTestId('review-slot').count(),0);
  await page.getByRole('button',{name:'Show accepted fixture',exact:true}).click();
  await page.getByRole('button',{name:'Download APEX package',exact:true}).click();
  const downloaded=await page.evaluate(()=>window.__events.find(x=>x.kind==='download'));
  assert.equal(downloaded.context.run_source_hash,fixtures.ready.source_hash);assert.equal(downloaded.context.source_hash,fixtures.changed.source_hash);
  await page.screenshot({path:path.join(out,'desktop-historical-output.png')});
  await page.setViewportSize({width:390,height:844});await page.getByRole('button',{name:'Show ready plan',exact:true}).click();
  await page.getByRole('button',{name:'2 Review forms',exact:true}).click();
  await page.getByRole('heading',{name:'Review every form',exact:true}).evaluate(element=>element.scrollIntoView({block:'start'}));
  await page.screenshot({path:path.join(out,'mobile-form-review.png')});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.getByRole('button',{name:'Show human blocker',exact:true}).click();await page.getByRole('button',{name:'3 Resolve',exact:true}).click();
  await page.getByRole('heading',{name:'What is needed before conversion',exact:true}).evaluate(element=>element.scrollIntoView({block:'start'}));
  await page.screenshot({path:path.join(out,'mobile-human-decision.png')});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.getByRole('button',{name:'Show empty project',exact:true}).click();await page.getByRole('button',{name:'3 Resolve',exact:true}).click();
  await page.getByRole('heading',{name:'Add your source files first',exact:true}).waitFor();
  assert.equal(await page.getByText('This source plan is ready.',{exact:false}).count(),0);
  assert.deepEqual(events,[]);
  await writeFile(path.join(out,'result.json'),JSON.stringify({scope:'isolated-business-workbench-ui-proof-v1',passed:true,producer:'actual project_conversion assessment on synthetic source',source_sha256:Object.fromEntries(Object.entries(sources).map(([name,raw])=>[name,sha(raw)])),browser:await browser.version(),page_errors:events,scenarios:['per-form review','unknown-write blocked and read-only refresh','source-change clears consent','raw binary rejected and readable upload bound','duplicate upload blocked across deferred validation','invalid binding has project-only reload','human-meaning blocker','review controls share mutation guard and preserve draft notes','current verified vs historical accepted output','390px no horizontal overflow','empty project is not ready'],backend_simulated:true,oracle_executed:false,model_executed:false,live_acceptance_recorded:false},null,2));
 }catch(error){await writeFile(path.join(out,'failure.json'),JSON.stringify({scope:'isolated-business-workbench-ui-proof-v1',passed:false,code:error?.name??'Error',message:String(error?.message??'UI proof failed').slice(0,2000),backend_simulated:true,oracle_executed:false,model_executed:false,live_acceptance_recorded:false},null,2));throw error;}
 finally{await context?.close();await browser.close();}
});
