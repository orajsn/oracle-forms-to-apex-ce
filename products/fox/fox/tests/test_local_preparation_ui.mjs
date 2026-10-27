// Mocked local preparation only: no browser, native tooling or live service.
import {test,afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';

const compile=(source,name)=>ts.transpileModule(source,{fileName:name,compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022,jsx:ts.JsxEmit.React}}).outputText;
const moduleURL=source=>'data:text/javascript;base64,'+Buffer.from(source).toString('base64');
const preparedURL=moduleURL(compile(await readFile(new URL('../web/preparedUpload.ts',import.meta.url),'utf8'),'prepared.ts'));
const source=await readFile(new URL('../web/LocalPreparation.tsx',import.meta.url),'utf8');
const compiled=compile(source,'LocalPreparation.tsx').replace("from 'react'",'from '+JSON.stringify(import.meta.resolve('react'))).replace("from './preparedUpload'",'from '+JSON.stringify(preparedURL));
const {LocalPreparationSession,LocalPreparationView,isLocalPreparationOrigin,readLocalCapabilities,checkLocalSelection,readLocalJob,scheduleLocalPreparationPoll}=await import(moduleURL(compiled));
const prefix='/api/local-preparation',manifestName='fox-readable-upload.json',MiB=1024*1024;
const pathBudgetMessage='Local preparation paths exceed this installation’s limit. Start a new session from a shorter installation folder; keep the original files unchanged.';
const pathBudgetBody=()=>({detail:{code:'LOCAL_PATH_BUDGET_EXCEEDED',message:pathBudgetMessage}});
const digest=raw=>createHash('sha256').update(raw).digest('hex');
const id='prep-'+'1'.repeat(32),fid=n=>'file-'+String(n).padStart(32,'0');
const originalFetch=globalThis.fetch,originalLocation=Object.getOwnPropertyDescriptor(globalThis,'location');
const sessions=[];
afterEach(()=>{for(const session of sessions.splice(0))session.dispose();globalThis.fetch=originalFetch;if(originalLocation)Object.defineProperty(globalThis,'location',originalLocation);else delete globalThis.location;});
function origin(value='http://127.0.0.1:8100'){Object.defineProperty(globalThis,'location',{configurable:true,value:new URL(value)});}
function capabilities(overrides={}){return {local_only:true,readable_formats:['.pkb','.pks','.pld','.sql','.txt','.xml'],native_formats:[],tool_presence_only:true,native_extraction_verified:false,max_files:50,max_file_bytes:20*MiB,max_selected_bytes:25*MiB,max_session_jobs:20,automatic_upload:false,conversion_available:false,note:'PRIVATE-SERVER-NOTE',...overrides};}
function fixture({job=id,manifestJob=job}={}){
 const inputs=[['mini.xml',Buffer.from('\ufeff<FormModule Name="MINI"/>\r\n')],['table.sql',Buffer.from('CREATE TABLE MINI (ID NUMBER);\r\n')]];
 const entries=inputs.map(([name,raw])=>({name,bytes:raw.length,sha256:digest(raw)}));
 const sidecar=Buffer.from(JSON.stringify({format:'FOX-READABLE-UPLOAD',schema_version:1,extraction_job_id:manifestJob,files:entries,readable_source_hash:digest(entries.slice().sort((a,b)=>a.name<b.name?-1:1).map(entry=>entry.name+':'+entry.sha256).join('\n'))}));
 const bytes=new Map([...inputs,[manifestName,sidecar]]);
 const files=[...bytes].map(([name,raw],index)=>({file_id:fid(index+1),name,bytes:raw.length,sha256:digest(raw)}));
 return {bytes,job:{job_id:job,state:'PREPARED_REVIEW_REQUIRED',code:'REVIEW_READABLE_OUTPUT',requires_human_review:true,approved_for_upload:false,automatic_upload:false,conversion_started:false,missing_dependency_count:0,files,note:'PRIVATE-SERVER-NOTE'}};
}
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json'}});
function harness({caps=capabilities(),data=fixture(),handle}={}){
 origin();const calls=[],states=[];
 globalThis.fetch=async(path,options)=>{
  calls.push({path,options});const intercepted=await handle?.(path,options,calls);if(intercepted)return intercepted;
  if(path===prefix+'/capabilities')return json(caps);
  if(path===prefix+'/jobs'&&options.method==='POST')return json(data.job,202);
  if(path===prefix+'/jobs/'+data.job.job_id)return json(data.job);
  const entry=data.job.files.find(file=>path===prefix+'/jobs/'+data.job.job_id+'/files/'+file.file_id);
  if(entry)return new Response(data.bytes.get(entry.name));
  throw new Error('Unexpected mock route: '+path);
 };
 const session=new LocalPreparationSession(state=>states.push(state));sessions.push(session);
 return {session,calls,states,data};
}
async function ready(options){const result=harness(options);await result.session.initialize();result.session.select([new File(['<FormModule/>'],'mini.xml')]);await result.session.prepare();return result;}
const noop=()=>{};
function html(state,busy=false){return renderToStaticMarkup(React.createElement(LocalPreparationView,{state,busy,onSelect:noop,onPrepare:noop,onRefresh:noop,onReview:noop,onUse:noop,onDownload:noop}));}
function deadlineClock(){
 const oldSet=globalThis.setTimeout,oldClear=globalThis.clearTimeout,oldAdd=AbortSignal.prototype.addEventListener,oldRemove=AbortSignal.prototype.removeEventListener;
 const timers=new Map(),listeners=new Map();let serial=0,created=0,cleared=0;
 globalThis.setTimeout=(callback,delay)=>{const timer=++serial;timers.set(timer,{callback,delay});created++;return timer;};
 globalThis.clearTimeout=timer=>{timers.delete(timer);cleared++;};
 AbortSignal.prototype.addEventListener=function(type,callback,options){if(type==='abort'){if(!listeners.has(this))listeners.set(this,new Set());listeners.get(this).add(callback);}return oldAdd.call(this,type,callback,options);};
 AbortSignal.prototype.removeEventListener=function(type,callback,options){if(type==='abort')listeners.get(this)?.delete(callback);return oldRemove.call(this,type,callback,options);};
 return {
  fire(){const timer=[...timers].find(([,value])=>value.delay===30000);assert.ok(timer,'one finite 30-second request deadline is active');timers.delete(timer[0]);timer[1].callback();},
  assertClean(){assert.equal(timers.size,0,'request timers are released');assert.equal([...listeners.values()].reduce((sum,set)=>sum+set.size,0),0,'request abort listeners are released');assert.equal(cleared,created,'every request timer is cleaned even after firing');},
  restore(){globalThis.setTimeout=oldSet;globalThis.clearTimeout=oldClear;AbortSignal.prototype.addEventListener=oldAdd;AbortSignal.prototype.removeEventListener=oldRemove;},
 };
}
async function until(check){for(let i=0;i<100;i++){if(check())return;await new Promise(done=>setImmediate(done));}assert.fail('mock operation did not reach the expected checkpoint');}
function hangingBody(status=200,cancelNeverSettles=false){
 let canceled=0;
 const response=new Response(new ReadableStream({start(controller){controller.enqueue(new Uint8Array([123]));},cancel(){canceled++;if(cancelNeverSettles)return new Promise(()=>{});}}),{status});
 return {response,get canceled(){return canceled;}};
}

for(const url of ['https://fox.example.com','https://127.0.0.1:8100','http://localhost:8100','http://127.0.0.2:8100','http://[::1]:8100','http://127.0.0.1','http://127.0.0.1:1023']){
 test('inert with no fetch outside exact permitted loopback origin '+url,async()=>{
  const {session,calls}=harness();origin(url);assert.equal(isLocalPreparationOrigin(),false);await session.initialize();assert.equal(calls.length,0);assert.equal(html(session.state),'');
 });
}
for(const port of [1024,8100,65535])test('permits the exact loopback origin on port '+port,()=>{origin('http://127.0.0.1:'+port);assert.equal(isLocalPreparationOrigin(),true);});
test('capabilities 404 hides component without a mutation',async()=>{
 const {session,calls}=harness({handle:()=>new Response(null,{status:404})});await session.initialize();assert.equal(html(session.state),'');assert.equal(calls.length,1);
});
for(const status of [401,403,500])test('capabilities failure is honest and hides source controls: '+status,async()=>{
 const {session}=harness({handle:()=>json({detail:'PRIVATE-PATH-TOKEN'},status)});await session.initialize();const rendered=html(session.state);assert.match(rendered,/role="alert"/);assert.doesNotMatch(rendered,/<input|PRIVATE-PATH-TOKEN/);
});
test('missing native tools leaves readable preparation available and presence is not approval',async()=>{
 const {session}=harness();await session.initialize();assert.ok(session.state.capabilities);const rendered=html(session.state);assert.match(rendered,/No native tools detected/);assert.match(rendered,/Readable-file preparation is still available/);assert.match(rendered,/not proof of compatibility, licensing entitlement or redaction approval/);assert.doesNotMatch(rendered,/PRIVATE-SERVER-NOTE/);
 session.select([new File(['<FormModule/>'],'mini.xml')]);assert.equal(session.state.selected.length,1);
 session.select([new File(['raw'],'mini.fmb')]);assert.equal(session.state.selected.length,0);assert.match(session.state.error,/not available/);
});
for(const change of [
 {local_only:false},{automatic_upload:true},{conversion_available:true},{native_extraction_verified:true},{tool_presence_only:false},
 {readable_formats:[]},{readable_formats:['.xml','.xml']},{readable_formats:['.exe']},{native_formats:['.rdf']},{native_formats:['.fmb','.fmb']},
 {max_files:51},{max_files:true},{max_file_bytes:20*MiB+1},{max_selected_bytes:25*MiB+1},{max_session_jobs:21},
])test('rejects unsupported capability evidence '+JSON.stringify(change),()=>{assert.throws(()=>readLocalCapabilities(capabilities(change)));});
test('selection and capability discovery never post; explicit prepare posts original Files only',async()=>{
 const {session,calls}=harness({caps:capabilities({native_formats:['.fmb']})});await session.initialize();
 const raw=new File([new Uint8Array([0,255,3,13,10])],'mini.fmb');session.select([raw]);assert.equal(calls.length,1);assert.equal(calls[0].options.method,'GET');
 await session.prepare();assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
 const form=calls[1].options.body;assert.ok(form instanceof FormData);const entries=[...form.entries()];assert.deepEqual(entries.map(([key])=>key),['files']);assert.equal(entries[0][1].name,raw.name);assert.deepEqual(await entries[0][1].arrayBuffer(),await raw.arrayBuffer());
});
for(const files of [[],[{name:'a.xml',size:0}],[{name:'a.xml',size:20*MiB+1}],[{name:'a.xml',size:20*MiB},{name:'b.sql',size:6*MiB}],Array.from({length:51},(_,i)=>({name:'a'+i+'.xml',size:1})),
 [{name:'a.xml',size:1},{name:'A.XML',size:1}],...[ '../a.xml','C:\\a.xml','a/mini.xml','a.xml\n','bad..xml','CON.xml','LPT9.txt','a.xml.','file.zip','file.json','fox-readable-upload.json'].map(name=>[{name,size:1}])]){
 test('rejects unsafe empty duplicate unsupported or excessive selection '+JSON.stringify(files).slice(0,100),()=>{assert.throws(()=>checkLocalSelection(files,readLocalCapabilities(capabilities())));});
}
test('advertised lower limits and mixed known formats are enforced',()=>{
 const cap=readLocalCapabilities(capabilities({max_files:2,max_file_bytes:10,max_selected_bytes:15,native_formats:['.pll']}));
 checkLocalSelection([{name:'a.pll',size:5},{name:'b.XML',size:10}],cap);
 assert.throws(()=>checkLocalSelection([{name:'a.pll',size:6},{name:'b.XML',size:10}],cap));
});
test('every actual request stays fixed relative same-origin with cookies and rejects redirects',async()=>{
 const {session,calls}=await ready();session.setReviewed(true);await session.useReviewed(async()=>true);
 for(const {path,options} of calls){assert.match(path,/^\/api\/local-preparation\/(capabilities|jobs)/);assert.equal(options.credentials,'same-origin');assert.equal(options.mode,'same-origin');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');assert.ok(options.signal instanceof AbortSignal);assert.ok(!options.headers);}
 assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
});
test('redirected response is rejected even if a mock followed it',async()=>{
 const {session}=harness({handle:()=>{const response=json(capabilities());Object.defineProperty(response,'redirected',{value:true});return response;}});await session.initialize();assert.equal(session.state.capabilities,null);
});
test('every request rechecks origin and never follows supplied URL fields',async()=>{
 const {session,calls}=await ready();const count=calls.length;origin('https://hosted.example.com');session.setReviewed(true);let invoked=0;await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,0);assert.equal(calls.length,count);assert.match(session.state.error,/localhost/);
});
for(const change of [
 {job_id:id+'\n'},{job_id:'../status'},{job_id:'https://example.com'},{job_id:id+'?secret'},
 {requires_human_review:false},{approved_for_upload:true},{automatic_upload:true},{conversion_started:true},{missing_dependency_count:true},{missing_dependency_count:-1},
 {state:'VERIFIED'},{state:'RUNNING'},{code:'PRIVATE-PATH'},{files:[]},{files:null},
])test('rejects invalid job evidence '+JSON.stringify(change),()=>{assert.throws(()=>readLocalJob({...fixture().job,...change}));});
for(const change of [
 {file_id:fid(1)+'\n'},{file_id:'../secret'},{name:'private-manifest.json'},{name:'raw.fmb'},{name:'../mini.xml'},
 {bytes:0},{bytes:true},{bytes:5*MiB+1},{sha256:'A'.repeat(64)},{sha256:'0'.repeat(64)+'\n'},
])test('rejects invalid output metadata '+JSON.stringify(change),()=>{const {job}=fixture();job.files[0]={...job.files[0],...change};assert.throws(()=>readLocalJob(job));});
test('job mismatch duplicate IDs duplicate names missing sidecar and too many outputs reject',()=>{
 const {job}=fixture();assert.throws(()=>readLocalJob(job,'prep-'+'2'.repeat(32)));
 for(const files of [[job.files[0],job.files[0],job.files[2]],[job.files[0],{...job.files[1],name:'MINI.XML'},job.files[2]],[job.files[0]],
  [...Array.from({length:51},(_,i)=>({...job.files[0],name:'a'+i+'.xml',file_id:fid(i+10)})),job.files[2]],
  [job.files[0],{...job.files[2],bytes:32769}]])assert.throws(()=>readLocalJob({...job,files}));
});
test('supports 50 readable outputs plus sidecar without confusing input count',()=>{
 const {job}=fixture();const files=[...Array.from({length:50},(_,i)=>({...job.files[0],name:'a'+i+'.xml',file_id:fid(i+10)})),job.files[2]];assert.equal(readLocalJob({...job,files}).files.length,51);
});
test('RUNNING and BLOCKED accept no downloadable files',()=>{
 const {job}=fixture();assert.equal(readLocalJob({...job,state:'RUNNING',code:'PREPARING_LOCALLY',files:[]}).state,'RUNNING');
 assert.equal(readLocalJob({...job,state:'BLOCKED',code:'PREPARED_OUTPUT_CHANGED',files:[]}).state,'BLOCKED');
});
test('poll schedules only a known running job and cleanup cancels the next check',async()=>{
 const data=fixture();data.job={...data.job,state:'RUNNING',code:'PREPARING_LOCALLY',files:[]};
 const {session,calls}=await ready({data});const previousSet=globalThis.setTimeout,previousClear=globalThis.clearTimeout;const scheduled=[],cleared=[];
 try{
  globalThis.setTimeout=(callback,delay)=>{scheduled.push({callback,delay});return 7;};globalThis.clearTimeout=timer=>cleared.push(timer);
  const cleanup=scheduleLocalPreparationPoll(session,session.state,false);assert.equal(scheduled.length,1);assert.equal(scheduled[0].delay,2000);cleanup();assert.deepEqual(cleared,[7]);
  for(const state of [{...session.state,working:true},{...session.state,error:'Unavailable'},{...session.state,job:fixture().job},{...session.state,job:null}])assert.equal(scheduleLocalPreparationPoll(session,state,false),undefined);
  assert.equal(scheduleLocalPreparationPoll(session,session.state,true),undefined);assert.equal(scheduled.length,1);
  data.job=fixture().job;scheduled[0].callback();while(session.state.working)await new Promise(done=>setImmediate(done));
  assert.equal(session.state.job.state,'PREPARED_REVIEW_REQUIRED');assert.equal(scheduleLocalPreparationPoll(session,session.state,false),undefined);
  assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(calls.at(-1).options.method,'GET');
 }finally{globalThis.setTimeout=previousSet;globalThis.clearTimeout=previousClear;}
});
test('prepared files and handoff are gated by explicit review',async()=>{
 const {session,calls,data}=await ready();let invoked=0;const before=calls.length;
 await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,0);assert.equal(calls.length,before);
 assert.match(html(session.state),/Verified readable output/);assert.match(html(session.state),/uses the unchanged prepared bytes, not edited downloaded copies/);
 session.setReviewed(true);await session.useReviewed(async files=>{invoked++;assert.equal(files.length,3);for(const file of files){assert.ok(file instanceof File);assert.deepEqual(Buffer.from(await file.arrayBuffer()),data.bytes.get(file.name));}return true;});
 assert.equal(invoked,1);assert.equal(session.state.handedOff,true);assert.equal(session.state.reviewed,false);
 await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,1);
});
test('false callback retains the exact job and downloads, with no automatic retry',async()=>{
 const {session,data}=await ready();session.setReviewed(true);let invoked=0;await session.useReviewed(async()=>{invoked++;return false;});
 assert.equal(invoked,1);assert.equal(session.state.job.job_id,data.job.job_id);assert.equal(session.state.handedOff,false);assert.equal(session.state.reviewed,false);assert.match(session.state.notice,/retained/);
 const file=await session.download(data.job.files[0].file_id);assert.equal(file.name,'mini.xml');assert.equal(invoked,1);
});
test('callback exceptions remain bounded retain job and require renewed review',async()=>{
 const {session,data}=await ready();session.setReviewed(true);await session.useReviewed(async()=>{throw new Error('PRIVATE-TOKEN-PATH');});assert.equal(session.state.job.job_id,data.job.job_id);assert.equal(session.state.reviewed,false);assert.doesNotMatch(html(session.state),/PRIVATE-TOKEN-PATH/);
});
test('changed status before handoff resets review and does not invoke callback',async()=>{
 const {session,data}=await ready();session.setReviewed(true);data.job.files[0].sha256='0'.repeat(64);let invoked=0;await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,0);assert.equal(session.state.reviewed,false);assert.match(session.state.error,/changed/);
});
test('changed missing-dependency summary resets review too',async()=>{
 const {session,data}=await ready();session.setReviewed(true);data.job.missing_dependency_count=2;await session.refresh();assert.equal(session.state.reviewed,false);
});
test('reordered unchanged output metadata does not invalidate the same set',async()=>{
 const {session,data}=await ready();session.setReviewed(true);data.job.files.reverse();await session.refresh();assert.equal(session.state.reviewed,true);
});
for(const status of [404,409,500])test('output failure '+status+' invalidates review and never calls callback',async()=>{
 const {session}=await ready({handle:path=>path.includes('/files/')?json({detail:'PRIVATE'},status):undefined});session.setReviewed(true);let invoked=0;await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,0);assert.equal(session.state.reviewed,false);assert.doesNotMatch(html(session.state),/PRIVATE/);if(status===409){assert.equal(session.state.job.state,'BLOCKED');assert.equal(session.state.job.files.length,0);}
});
test('status409 immediately hides previously verified outputs and clears review',async()=>{
 let invalidate=false;const {session}=await ready({handle:path=>invalidate&&path===prefix+'/jobs/'+id?json({detail:'PRIVATE'},409):undefined});
 session.setReviewed(true);invalidate=true;await session.refresh();assert.equal(session.state.job.state,'BLOCKED');assert.equal(session.state.reviewed,false);assert.doesNotMatch(html(session.state),/Verified readable output|Download mini.xml|PRIVATE/);
});
test('a failed integrity set cannot be revived by a later unchanged status response',async()=>{
 let unavailable=true;const {session,data}=await ready({handle:path=>unavailable&&path.includes('/files/')?json({},409):undefined});
 assert.equal(await session.download(data.job.files[0].file_id),null);assert.equal(session.state.job.state,'BLOCKED');
 unavailable=false;await session.refresh();session.setReviewed(true);assert.equal(session.state.job.state,'BLOCKED');assert.equal(session.state.reviewed,false);assert.match(session.state.error,/previously failed/);
});
for(const kind of ['size','hash'])test('raw output '+kind+' mismatch prevents handoff',async()=>{
 const {session,data}=await ready();data.bytes.set('mini.xml',kind==='size'?Buffer.from('x'):Buffer.alloc(data.bytes.get('mini.xml').length,65));session.setReviewed(true);let invoked=0;await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,0);assert.equal(session.state.reviewed,false);
});
test('download is an exact verified File with BOM and CRLF intact',async()=>{
 const {session,data}=await ready();const file=await session.download(data.job.files[0].file_id);const bytes=Buffer.from(await file.arrayBuffer());assert.deepEqual(bytes,data.bytes.get('mini.xml'));assert.deepEqual([...bytes.subarray(0,3)],[239,187,191]);assert.equal(bytes.subarray(-2).toString(),'\r\n');
});
test('download never accepts non-member file IDs or paths',async()=>{
 const {session,calls}=await ready();for(const identifier of [fid(999),'../private',fid(1)+'\n','https://example.com']){const before=calls.length;assert.equal(await session.download(identifier),null);assert.equal(calls.slice(before).filter(call=>call.path.includes('/files/')).length,0);}
});
test('valid sidecar from different extraction job is not a valid handoff',async()=>{
 const {session}=await ready({data:fixture({manifestJob:'prep-'+'2'.repeat(32)})});session.setReviewed(true);let invoked=0;await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,0);assert.match(session.state.error,/different local job/);
});
test('sidecar membership must match downloaded output names and hashes',async()=>{
 const data=fixture();const manifest=JSON.parse(data.bytes.get(manifestName));manifest.files[0].name='other.xml';const raw=Buffer.from(JSON.stringify(manifest));data.bytes.set(manifestName,raw);Object.assign(data.job.files[2],{bytes:raw.length,sha256:digest(raw)});
 const {session}=await ready({data});session.setReviewed(true);let invoked=0;await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,0);assert.equal(session.state.reviewed,false);
});
test('fresh status is checked again after all file bytes are fetched',async()=>{
 let statusCalls=0;const {session,calls}=await ready({handle:path=>{if(path===prefix+'/jobs/'+id&&++statusCalls===2){const {job}=fixture();job.files[0].bytes++;return json(job);}}});
 session.setReviewed(true);let invoked=0;await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,0);assert.equal(statusCalls,2);assert.equal(calls.filter(call=>call.path.includes('/files/')).length,3);
});
test('bounded response reader rejects over-size body even without Content-Length',async()=>{
 const {session}=harness({handle:()=>new Response(' '.repeat(65537))});await session.initialize();assert.equal(session.state.capabilities,null);assert.ok(session.state.error);
});
test('bounded response reader rejects advertised oversized length',async()=>{
 const {session}=harness({handle:()=>new Response('{}',{headers:{'content-length':'65537'}})});await session.initialize();assert.equal(session.state.capabilities,null);
});
for(const body of [JSON.stringify(capabilities()).replace('"local_only":true','"local_only":false,"local_only":true'),'{"a":{"b":{"c":{"d":{}}}}}',new Uint8Array([255])])test('malformed duplicate deeply nested or non-UTF8 response fails closed',async()=>{
 const {session}=harness({handle:()=>new Response(body)});await session.initialize();assert.equal(session.state.capabilities,null);assert.ok(session.state.error);
});
test('uncertain POST is never retried and prevents resubmission',async()=>{
 const {session,calls}=harness({handle:(_path,options)=>{if(options.method==='POST')throw new Error('PRIVATE network error');}});await session.initialize();session.select([new File(['source'],'a.xml')]);await session.prepare();await session.prepare();assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(session.state.uncertain,true);assert.match(session.state.error,/Do not resubmit/);assert.doesNotMatch(html(session.state),/PRIVATE/);
});
for(const status of [400,401,403,404,409,413,415,422,429])test('definite POST rejection '+status+' retains selection and permits explicit correction only',async()=>{
 let reject=true;const {session,calls}=harness({handle:(_path,options)=>reject&&options.method==='POST'?json({detail:'PRIVATE-SERVER-DETAIL'},status):undefined});
 await session.initialize();session.select([new File(['x'],'a.xml')]);await session.prepare();assert.equal(session.state.uncertain,false);assert.equal(session.state.selected.length,1);assert.equal(session.state.job,null);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.doesNotMatch(html(session.state),/PRIVATE-SERVER-DETAIL|outcome is uncertain/);
 reject=false;session.select([new File(['corrected'],'a.xml')]);await session.prepare();assert.equal(calls.filter(call=>call.options.method==='POST').length,2);assert.equal(session.state.job.state,'PREPARED_REVIEW_REQUIRED');
});
for(const status of [500,503,202])test('server failure or malformed success '+status+' is uncertain and not resubmitted',async()=>{
 const {session,calls}=harness({handle:(_path,options)=>options.method==='POST'?json({detail:'PRIVATE'},status):undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);await session.prepare();await session.prepare();assert.equal(session.state.uncertain,true);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.doesNotMatch(html(session.state),/PRIVATE/);
});
test('exact known path-budget422 displays only the fixed actionable message and allows explicit correction',async()=>{
 let reject=true;const {session,calls}=harness({handle:(_path,options)=>reject&&options.method==='POST'?json(pathBudgetBody(),422):undefined});
 await session.initialize();session.select([new File(['x'],'a.xml')]);await session.prepare();assert.equal(session.state.error,pathBudgetMessage);assert.equal(session.state.uncertain,false);assert.equal(session.state.selected.length,1);assert.equal(session.state.job,null);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.ok(html(session.state).includes(pathBudgetMessage));
 reject=false;session.select([new File(['corrected'],'a.xml')]);await session.prepare();assert.equal(session.state.job.state,'PREPARED_REVIEW_REQUIRED');assert.equal(calls.filter(call=>call.options.method==='POST').length,2);
});
for(const value of [
 {detail:'PRIVATE-MESSAGE'}, {detail:{code:'UNKNOWN',message:pathBudgetMessage}},
 {detail:{code:'LOCAL_PATH_BUDGET_EXCEEDED',message:'PRIVATE-MESSAGE <script>alert(1)</script>'}},
 {detail:{code:'LOCAL_PATH_BUDGET_EXCEEDED',message:pathBudgetMessage,path:'PRIVATE-PATH'}},
 {detail:{code:'LOCAL_PATH_BUDGET_EXCEEDED'}}, {detail:{code:'LOCAL_PATH_BUDGET_EXCEEDED',message:null}},
 {detail:pathBudgetBody().detail,private:'PRIVATE-PATH'}, {detail:[pathBudgetBody().detail]}, null,
])test('unknown or altered path-error shape stays generic without provider content',async()=>{
 const {session,calls}=harness({handle:(_path,options)=>options.method==='POST'?json(value,422):undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);await session.prepare();assert.match(session.state.error,/selected files were rejected/);assert.equal(session.state.uncertain,false);assert.doesNotMatch(html(session.state),/PRIVATE|<script>|installation’s limit/);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
});
for(const status of [400,409,500,202])test('path-budget detail on non422 cannot present a path-budget diagnosis: '+status,async()=>{
 const {session}=harness({handle:(_path,options)=>options.method==='POST'?json(pathBudgetBody(),status):undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);await session.prepare();assert.ok(!session.state.error.includes(pathBudgetMessage));
});
for(const body of ['PRIVATE-MALFORMED-JSON',JSON.stringify(pathBudgetBody()).replace('"code":"LOCAL_PATH_BUDGET_EXCEEDED"','"code":"UNKNOWN","code":"LOCAL_PATH_BUDGET_EXCEEDED"'),new Uint8Array([255])])test('malformed or duplicate error JSON remains a definite generic422 rejection',async()=>{
 const {session}=harness({handle:(_path,options)=>options.method==='POST'?new Response(body,{status:422}):undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);await session.prepare();assert.equal(session.state.uncertain,false);assert.match(session.state.error,/selected files were rejected/);assert.doesNotMatch(html(session.state),/PRIVATE|installation’s limit/);
});
test('busy guards selection prepare review download and handoff without network',async()=>{
 const {session,calls}=await ready();session.externalBusy=true;const before=calls.length;session.select([new File(['x'],'new.xml')]);session.setReviewed(true);await session.prepare();await session.refresh();await session.download(fid(1));await session.useReviewed(async()=>{throw new Error('should not invoke');});assert.equal(calls.length,before);assert.equal(session.state.reviewed,false);
 assert.match(html(session.state,true),/disabled=""/);
});
test('concurrent prepare clicks emit one POST',async()=>{
 let resolve;const pending=new Promise(done=>{resolve=done;});const {session,calls}=harness({handle:(_path,options)=>options.method==='POST'?pending:undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);const first=session.prepare();await Promise.resolve();await session.prepare();resolve(json(fixture().job,202));await first;assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
});
test('concurrent callback clicks invoke once and retain job on false',async()=>{
 let resolve;const pending=new Promise(done=>{resolve=done;});const {session}=await ready();session.setReviewed(true);let invoked=0;const first=session.useReviewed(async()=>{invoked++;return pending;});while(!invoked)await new Promise(done=>setImmediate(done));await session.useReviewed(async()=>{invoked++;return true;});resolve(false);await first;assert.equal(invoked,1);assert.equal(session.state.handedOff,false);
});
test('dispose aborts in-flight request and suppresses late state updates',async()=>{
 let resolve;const pending=new Promise(done=>{resolve=done;});const {session,calls,states}=harness({handle:()=>pending});const action=session.initialize();session.dispose();resolve(json(capabilities()));await action;assert.equal(states.length,0);assert.equal(calls[0].options.signal.aborted,true);
});
test('normal metadata status and output reads clean every deadline and abort listener',async()=>{
 const clock=deadlineClock();try{const {session}=await ready();clock.assertClean();session.setReviewed(true);let invoked=0;await session.useReviewed(async()=>{invoked++;return true;});assert.equal(invoked,1);clock.assertClean();}finally{clock.restore();}
});
test('definite rejection without typed detail cancels unread body without awaiting cancellation',async()=>{
 const clock=deadlineClock();try{const stalled=hangingBody(413,true);const {session}=harness({handle:(_path,options)=>options.method==='POST'?stalled.response:undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);await session.prepare();assert.equal(session.state.uncertain,false);assert.equal(stalled.canceled,1);clock.assertClean();}finally{clock.restore();}
});
test('a422 error-body timeout stays a definite rejection and does not retry automatically',async()=>{
 const clock=deadlineClock();try{const stalled=hangingBody(422,true);const {session,calls}=harness({handle:(_path,options)=>options.method==='POST'?stalled.response:undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);const action=session.prepare();await until(()=>stalled.response.body.locked);clock.fire();await action;await until(()=>!stalled.response.body.locked);assert.equal(session.state.uncertain,false);assert.equal(session.state.selected.length,1);assert.match(session.state.error,/timed out/);assert.doesNotMatch(session.state.error,/Do not resubmit/);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);clock.assertClean();}finally{clock.restore();}
});
test('hanging capability fetch times out even when the mock ignores abort',async()=>{
 const clock=deadlineClock();try{const {session,calls}=harness({handle:()=>new Promise(()=>{})});const action=session.initialize();clock.fire();await action;assert.equal(calls.length,1);assert.equal(calls[0].options.signal.aborted,true);assert.equal(session.state.capabilities,null);assert.match(session.state.error,/timed out/);clock.assertClean();}finally{clock.restore();}
});
test('hanging capability response body is canceled by the same request deadline',async()=>{
 const clock=deadlineClock();try{const stalled=hangingBody();const {session}=harness({handle:()=>stalled.response});const action=session.initialize();await until(()=>stalled.response.body.locked);clock.fire();await action;await until(()=>!stalled.response.body.locked);assert.equal(stalled.canceled,1);assert.equal(session.state.capabilities,null);assert.match(session.state.error,/timed out/);clock.assertClean();}finally{clock.restore();}
});
test('timed-out creation remains uncertain and ignores a late successful fetch',async()=>{
 const clock=deadlineClock();try{let resolve;const pending=new Promise(done=>{resolve=done;});const {session,calls}=harness({handle:(_path,options)=>options.method==='POST'?pending:undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);const action=session.prepare();clock.fire();await action;assert.equal(session.state.uncertain,true);assert.equal(session.state.working,false);assert.equal(session.state.job,null);assert.match(session.state.error,/timed out/);clock.assertClean();
  const lateResponse=json(fixture().job,202);resolve(lateResponse);await new Promise(done=>setImmediate(done));await session.prepare();assert.equal(lateResponse.bodyUsed,true,'late response body was canceled');assert.equal(session.state.job,null);assert.equal(session.state.uncertain,true);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);clock.assertClean();
 }finally{clock.restore();}
});
test('timed-out creation body remains uncertain and releases a hanging stream',async()=>{
 const clock=deadlineClock();try{const stalled=hangingBody(202,true);const {session,calls}=harness({handle:(_path,options)=>options.method==='POST'?stalled.response:undefined});await session.initialize();session.select([new File(['x'],'a.xml')]);const action=session.prepare();await until(()=>stalled.response.body.locked);clock.fire();await action;await until(()=>!stalled.response.body.locked);assert.equal(stalled.canceled,1);assert.equal(session.state.uncertain,true);assert.equal(session.state.job,null);assert.match(session.state.error,/Do not resubmit/);await session.prepare();assert.equal(calls.filter(call=>call.options.method==='POST').length,1);clock.assertClean();}finally{clock.restore();}
});
for(const stage of ['fetch','body'])test('status '+stage+' timeout prevents reviewed handoff and clears confirmation',async()=>{
 const clock=deadlineClock();try{const stalled=hangingBody();const {session,calls}=await ready({handle:path=>path===prefix+'/jobs/'+id?(stage==='fetch'?new Promise(()=>{}):stalled.response):undefined});session.setReviewed(true);let invoked=0;const action=session.useReviewed(async()=>{invoked++;return true;});if(stage==='body')await until(()=>stalled.response.body.locked);clock.fire();await action;assert.equal(invoked,0);assert.equal(session.state.reviewed,false);assert.equal(session.state.working,false);assert.equal(session.state.job.state,'PREPARED_REVIEW_REQUIRED');assert.match(session.state.error,/timed out/);assert.equal(calls.filter(call=>call.path.includes('/files/')).length,0);if(stage==='body'){await until(()=>!stalled.response.body.locked);assert.equal(stalled.canceled,1);}clock.assertClean();}finally{clock.restore();}
});
for(const stage of ['fetch','body'])test('file '+stage+' timeout returns no download and does not invent an integrity failure',async()=>{
 const clock=deadlineClock();try{const stalled=hangingBody(200,true);const {session,data,calls}=await ready({handle:path=>path.includes('/files/')?(stage==='fetch'?new Promise(()=>{}):stalled.response):undefined});session.setReviewed(true);const action=session.download(data.job.files[0].file_id);await until(()=>calls.some(call=>call.path.includes('/files/')));if(stage==='body')await until(()=>stalled.response.body.locked);clock.fire();assert.equal(await action,null);assert.equal(session.state.reviewed,false);assert.equal(session.state.working,false);assert.equal(session.state.job.state,'PREPARED_REVIEW_REQUIRED');assert.match(session.state.error,/timed out/);if(stage==='body'){await until(()=>!stalled.response.body.locked);assert.equal(stalled.canceled,1);}clock.assertClean();}finally{clock.restore();}
});
test('an explicit status check after timeout gets a fresh request signal and deadline',async()=>{
 const clock=deadlineClock();try{let stall=true;const {session,calls}=await ready({handle:path=>stall&&path===prefix+'/jobs/'+id?new Promise(()=>{}):undefined});const action=session.refresh();clock.fire();await action;const expired=calls.at(-1).options.signal;assert.equal(expired.aborted,true);clock.assertClean();
  stall=false;await session.refresh();const fresh=calls.at(-1).options.signal;assert.notEqual(fresh,expired);assert.equal(fresh.aborted,false);assert.equal(session.state.error,'');assert.equal(session.state.job.state,'PREPARED_REVIEW_REQUIRED');clock.assertClean();
 }finally{clock.restore();}
});
test('file-body timeout during handoff never invokes the callback',async()=>{
 const clock=deadlineClock();try{const stalled=hangingBody();const {session}=await ready({handle:path=>path.includes('/files/')?stalled.response:undefined});session.setReviewed(true);let invoked=0;const action=session.useReviewed(async()=>{invoked++;return true;});await until(()=>stalled.response.body.locked);clock.fire();await action;await until(()=>!stalled.response.body.locked);assert.equal(invoked,0);assert.equal(session.state.handedOff,false);assert.equal(session.state.reviewed,false);assert.equal(stalled.canceled,1);clock.assertClean();}finally{clock.restore();}
});
for(const stage of ['fetch','body'])test('unmount aborts hanging '+stage+' and removes deadline and listeners',async()=>{
 const clock=deadlineClock();try{const stalled=hangingBody(200,true);const {session,states}=harness({handle:()=>stage==='fetch'?new Promise(()=>{}):stalled.response});const action=session.initialize();if(stage==='body')await until(()=>stalled.response.body.locked);session.dispose();await action;assert.equal(states.length,0);if(stage==='body'){await until(()=>!stalled.response.body.locked);assert.equal(stalled.canceled,1);}clock.assertClean();}finally{clock.restore();}
});
test('already unmounted sessions do not dispatch another request or leak a timer',async()=>{
 const clock=deadlineClock();try{const {session,calls}=harness();session.dispose();await session.initialize();assert.equal(calls.length,0);clock.assertClean();}finally{clock.restore();}
});
test('private arbitrary strings are not rendered and dynamic filenames remain escaped',async()=>{
 const {session}=await ready();const rendered=html(session.state);assert.doesNotMatch(rendered,/PRIVATE-SERVER-NOTE|claim_token|Run QA|Accept tested package|Process once|https?:\/\//);assert.match(rendered,/not processing consent, technical verification or business acceptance/);
 const supplied={...session.state,selected:[new File(['x'],'<script>.xml')]};assert.doesNotMatch(html(supplied),/<script>/);assert.match(html(supplied),/&lt;script&gt;/);
});
test('component contains no automatic POST upload conversion shell paths or public QA controls',()=>{
 assert.equal((source.match(/request\('\/jobs',/g)||[]).length,1);assert.doesNotMatch(source,/\/api\/(?:projects|runs)|\/process|\/acceptance|\/download|dangerouslySetInnerHTML|child_process|localStorage|sessionStorage/);
 assert.match(source,/state\.job\?\.state!=='RUNNING'/);assert.match(source,/clearTimeout\(timer\)/);assert.match(source,/next\.dispose\(\)/);
});
