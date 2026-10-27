// Canonical source-history presentation tests: mocked requests and server-rendered React, no browser.
import {test,afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const require=createRequire(new URL('../package.json',import.meta.url)),ts=require('typescript'),React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const compile=(source,fileName)=>ts.transpileModule(source,{fileName,compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022,jsx:ts.JsxEmit.React}}).outputText;
const data=source=>'data:text/javascript;base64,'+Buffer.from(source).toString('base64');
const helperSource=readFileSync(new URL('../web/sourceVersionPresentation.ts',import.meta.url),'utf8'),helperURL=data(compile(helperSource,'helper.ts')),api=await import(helperURL);
const componentSource=readFileSync(new URL('../web/SourceVersionHistory.tsx',import.meta.url),'utf8');
const componentJS=compile(componentSource,'component.tsx').replace(/from ['"]react['"]/g,'from '+JSON.stringify(pathToFileURL(require.resolve('react')).href)).replace(/from ['"]\.\/sourceVersionPresentation['"]/g,'from '+JSON.stringify(helperURL));
const {SourceHistorySession,SourceVersionHistoryView}=await import(data(componentJS));
const pid='a'.repeat(32),sid=n=>'ss-'+String(n).repeat(32),rid=n=>'fox-'+String(n).repeat(20),sha=raw=>createHash('sha256').update(raw).digest('hex');
const originalFetch=globalThis.fetch,sessions=[];
afterEach(()=>{globalThis.fetch=originalFetch;for(const session of sessions.splice(0))session.dispose();});
async function fixtures(){
 const base=[{id:'legacy-id/opaque?1',name:'mini.xml',sha256:sha('<old/>'),bytes:6},{id:'common-sql',name:'table.sql',sha256:sha('ddl'),bytes:3}];
 const newer=[{id:'new-xml',name:'mini.xml',sha256:sha('<new/>'),bytes:6},base[1],{id:'unrelated-file',name:'extra.xml',sha256:sha('<x/>'),bytes:4}];
 const records=new Map();for(const [id,origin,files,created] of [[sid(1),'legacy-current',base,1000],[sid(2),'upload',newer,2000],[sid(3),'exclude',newer.slice(0,2),3000]]){
  records.set(id,{summary:{id,origin,file_count:files.length,source_bytes:files.reduce((sum,file)=>sum+file.bytes,0),source_hash:await api.readableManifestHash(files),created,is_selected:false,run_ids:id===sid(1)?[rid(1)]:[]},files:files.slice().sort((a,b)=>api.pythonNameCompare(a.name,b.name))});
 }return records;
}
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json'}});
const assessmentSummary=source=>({source_hash:source.source_hash,conversion_profile:'native-table-form-v1',source_checks_passed:true,file_count:source.file_count,source_bytes:source.source_bytes,conversion_source_bytes:source.source_bytes,max_conversion_bytes:300000,max_conversion_files:50,missing_dependency_count:0,assessment_finding_count:0,conversion_blocker_count:source.file_count>50?1:0,blocker_codes:source.file_count>50?['CONVERSION_FILE_COUNT_LIMIT']:[],native_state:source.file_count>50?'BLOCKED':'READY'});
const pagedDetail=(source,files,selected=source.id,offset=0)=>({selected_source_set_id:selected,source_set:{...source,is_selected:source.id===selected},files:files.slice(offset,offset+50),files_page:{offset,limit:50,total:source.file_count,next_cursor:offset+50<files.length?files[offset+49].id:null},assessment_summary:assessmentSummary(source)});
test('project profile history preserves strict source-set identity checks',async()=>{
 const records=await fixtures(),record=records.get(sid(2));
 const value=pagedDetail(record.summary,record.files);value.assessment_summary.conversion_profile='native-project-v1';
 const parsed=await api.parseSourceSetDetail(value,sid(2));assert.equal(parsed.assessment_summary.conversion_profile,'native-project-v1');
 value.assessment_summary.source_hash='f'.repeat(64);await assert.rejects(()=>api.parseSourceSetDetail(value,sid(2)));
});
async function largeRecord(count=101){const files=Array.from({length:count},(_,index)=>({id:'legacy/opaque?'+index,name:'part'+String(index).padStart(3,'0')+'.txt',sha256:sha(String(index)),bytes:1}));return {files,summary:{id:sid(2),source_hash:await api.readableManifestHash(files),file_count:count,source_bytes:count,created:2000,origin:'upload',is_selected:true,run_ids:[]}};}
async function harness({override,selected=sid(2),allIds=[sid(2),sid(1)],sourceRecord}={}){
 const records=await fixtures(),calls=[];if(sourceRecord)records.set(sourceRecord.summary.id,sourceRecord);const state={selected};
 const summary=id=>({...records.get(id).summary,is_selected:id===state.selected});
 const inventory=id=>({source_hash:records.get(id).summary.source_hash,selected_source_set_id:id});
 const page=(ids=allIds,next=null)=>({selected_source_set_id:state.selected,source_sets:ids.map(summary),next_cursor:next});
 const detail=(id,offset=0)=>pagedDetail(summary(id),records.get(id).files,state.selected,offset);
 const ack=id=>({selected_source_set_id:id,source_set:summary(id),assessment_summary:assessmentSummary(summary(id)),selection_changed:true});
 globalThis.fetch=async(url,options)=>{
  calls.push({url,options});const overrideResponse=await override?.(url,options,{state,records,page,detail,ack,summary});if(overrideResponse)return overrideResponse;
  const base='/api/projects/'+pid+'/source-sets';
  if(url===base&&options.method==='GET')return json(page());
  for(const id of records.keys()){
   if(url===base+'/'+id&&options.method==='GET')return json(detail(id));
   if(url.startsWith(base+'/'+id+'?files_after=')&&options.method==='GET'){const cursor=decodeURIComponent(url.slice((base+'/'+id+'?files_after=').length));const index=records.get(id).files.findIndex(file=>file.id===cursor);if(index<0)throw new Error('Unexpected mock file cursor');return json(detail(id,index+1));}
   if(url===base+'/'+id+'/download')return new Response(new Uint8Array([80,75,3,4,0]),{headers:{'content-type':'application/zip','content-disposition':'attachment; filename="PRIVATE-PATH.zip"'}});
   if(url===base+'/'+id+'/select'){const body=JSON.parse(options.body);if(body.expected_current_source_set_id!==state.selected)return json({detail:'PRIVATE',code:'SOURCE_SELECTION_CHANGED'},409);state.selected=id;return json(ack(id));}
   if(url===base+'/'+id+'/exclude'){const body=JSON.parse(options.body);if(body.expected_current_source_set_id!==state.selected)return json({detail:'PRIVATE',code:'SOURCE_SELECTION_CHANGED'},409);state.selected=sid(3);return json(ack(sid(3)));}
  }
  throw new Error('Unexpected mock request');
 };
 const session=new SourceHistorySession(pid,selected,records.get(selected).summary.source_hash,()=>{});sessions.push(session);
 return {session,calls,records,state,page,detail,ack,summary,inventory};
}
const noop=()=>{};
function html(session,extra={}){return renderToStaticMarkup(React.createElement(SourceVersionHistoryView,{state:session.state,currentId:session.currentId,currentHash:session.currentHash,busy:false,onInspect:noop,onUse:noop,onExport:noop,onOlder:noop,onRefresh:noop,onClose:noop,onBeginRemoval:noop,onConfirmRemoval:noop,onCancelRemoval:noop,onRemove:noop,onManifestNext:noop,onManifestPrevious:noop,...extra}));}
async function ready(options){const value=await harness(options);await value.session.load();return value;}
async function readyPaged(count=101,override){const sourceRecord=await largeRecord(count);return ready({sourceRecord,allIds:[sid(2)],override});}

test('list shows current complete saved sets and honest legacy provenance',async()=>{
 const {session,calls}=await ready();const rendered=html(session);assert.match(rendered,/Saved source versions/);assert.match(rendered,/Current<\/span>/);assert.match(rendered,/Legacy current set, captured/);assert.match(rendered,/Earlier complete versions are not reconstructed/);assert.match(rendered,/1970-01-01 00:16:40 UTC/);assert.match(rendered,/2 files/);assert.match(rendered,/3 files/);assert.equal(calls.length,1);assert.equal(calls[0].options.method,'GET');
 assert.doesNotMatch(rendered,/Run QA|Retry verification|Accept tested package|Process source/);
});
test('manifest inspects saved membership page and keeps opaque legacy file IDs out of visible copy',async()=>{
 const {session,calls}=await ready();await session.inspect(sid(1));assert.equal(session.state.inspected.files.length,2);assert.equal(session.state.inspected.files[0].id,'legacy-id/opaque?1');
 const rendered=html(session);assert.match(rendered,/Readable source manifest/);assert.match(rendered,/not a reconstruction of earlier complete versions/);assert.doesNotMatch(rendered,/legacy-id\/opaque\?1/);assert.equal(calls.filter(call=>call.options.method==='POST').length,0);
});
test('complete source sets can have more than50 files without claiming they are processable',async()=>{
 const record=await largeRecord(60),value=pagedDetail(record.summary,record.files);const parsed=await api.parseSourceSetDetail(value,sid(2));
 assert.equal(parsed.files.length,50);assert.equal(parsed.source_set.file_count,60);assert.equal(parsed.files_page.total,60);assert.equal(parsed.assessment_summary.max_conversion_files,50);assert.equal(parsed.assessment_summary.native_state,'BLOCKED');assert.deepEqual(parsed.assessment_summary.blocker_codes,['CONVERSION_FILE_COUNT_LIMIT']);assert.equal(api.parseSourceSetPage({selected_source_set_id:sid(2),source_sets:[value.source_set],next_cursor:null}).source_sets[0].file_count,60);
});
test('Unicode manifest order matches Python scalar order rather than JavaScript UTF16 order',async()=>{
 const files=[{id:'a',name:'\u{10000}.xml',sha256:'a'.repeat(64),bytes:1},{id:'b',name:'\ue000.xml',sha256:'b'.repeat(64),bytes:1}];
 assert.ok(api.pythonNameCompare(files[0].name,files[1].name)>0);assert.equal(await api.readableManifestHash(files),sha(files[1].name+':'+files[1].sha256+'\n'+files[0].name+':'+files[0].sha256));
});
test('a manifest page never presents its partial hash or byte sum as the whole saved set',async()=>{
 const record=await largeRecord(101),value=pagedDetail(record.summary,record.files);assert.notEqual(await api.readableManifestHash(value.files),value.source_set.source_hash);assert.notEqual(value.files.reduce((sum,file)=>sum+file.bytes,0),value.source_set.source_bytes);
 const parsed=await api.parseSourceSetDetail(value,sid(2));assert.equal(parsed.source_set.source_hash,record.summary.source_hash);assert.equal(parsed.source_set.source_bytes,101);assert.equal(parsed.files.length,50);
 const h=await readyPaged();await h.session.inspect(sid(2));const rendered=html(h.session);assert.match(rendered,/101 files/);assert.match(rendered,/1[–-]50 of 101|1 to 50 of 101|1–50.*101/);assert.match(rendered,/its files alone do not establish the complete source-set hash/);assert.doesNotMatch(rendered,/complete manifest verified|all 101 files displayed/i);
});
test('manifest next and previous explicitly replace pages without eager fetch or mutation',async()=>{
 const h=await readyPaged();await h.session.inspect(sid(2));assert.equal(h.calls.length,2);assert.equal(h.session.state.manifestPageIndex,0);assert.deepEqual(h.session.state.manifestCursors,[null]);
 await h.session.manifestPrevious();assert.equal(h.calls.length,2);await h.session.manifestNext();assert.equal(h.calls.length,3);assert.equal(h.session.state.manifestPageIndex,1);assert.equal(h.session.state.inspected.files.length,50);assert.equal(h.session.state.inspected.files[0].id,'legacy/opaque?50');assert.equal(h.session.state.inspected.files_page.offset,50);assert.equal(h.calls.at(-1).url,'/api/projects/'+pid+'/source-sets/'+sid(2)+'?files_after='+encodeURIComponent('legacy/opaque?49'));
 assert.equal(h.session.state.inspected.files.some(file=>file.id==='legacy/opaque?0'),false);await h.session.manifestNext();assert.equal(h.session.state.manifestPageIndex,2);assert.equal(h.session.state.inspected.files.length,1);assert.equal(h.session.state.inspected.files_page.offset,100);const finalCalls=h.calls.length;await h.session.manifestNext();assert.equal(h.calls.length,finalCalls);
 await h.session.manifestPrevious();assert.equal(h.session.state.manifestPageIndex,1);assert.equal(h.session.state.inspected.files_page.offset,50);await h.session.manifestPrevious();assert.equal(h.session.state.manifestPageIndex,0);assert.equal(h.session.state.inspected.files_page.offset,0);assert.equal(h.calls.at(-1).url,'/api/projects/'+pid+'/source-sets/'+sid(2));assert.equal(h.calls.filter(call=>call.options.method==='POST').length,0);
});
test('manifest close and switching inspection reset page and removal state',async()=>{
 const h=await readyPaged();await h.session.inspect(sid(2));await h.session.manifestNext();h.session.beginRemoval('legacy/opaque?50');h.session.confirmRemoval(true);assert.ok(h.session.state.removal);await h.session.manifestPrevious();assert.equal(h.session.state.removal,null);h.session.closeManifest();assert.equal(h.session.state.inspected,null);assert.equal(h.session.state.manifestPageIndex,0);assert.deepEqual(h.session.state.manifestCursors,[]);await h.session.inspect(sid(2));assert.equal(h.session.state.inspected.files_page.offset,0);
});
for(const [label,change] of [
 ['hash',value=>{value.source_set.source_hash='0'.repeat(64);value.assessment_summary.source_hash='0'.repeat(64);}],
 ['count',value=>{value.source_set.file_count++;value.files_page.total++;value.assessment_summary.file_count++;}],
 ['bytes',value=>{value.source_set.source_bytes++;value.assessment_summary.source_bytes++;}],
 ['created',value=>{value.source_set.created++;}],['origin',value=>{value.source_set.origin='exclude';}],['run identity',value=>{value.source_set.run_ids=['opaque-new-run'];}],
 ['set identity',value=>{value.source_set.id=sid(3);value.source_set.is_selected=false;}],
 ['current pointer',value=>{value.selected_source_set_id=sid(1);value.source_set.is_selected=false;}]
])test('changed whole-set '+label+' across manifest pages locks changes and keeps the last page',async()=>{
 const h=await readyPaged(101,(url,options,mock)=>{if(url.includes('?files_after=')){const value=structuredClone(mock.detail(sid(2),50));change(value);return json(value);}});await h.session.inspect(sid(2));await h.session.manifestNext();assert.equal(h.session.state.refreshRequired,true);assert.equal(h.session.state.inspected.files_page.offset,0);assert.equal(h.session.state.manifestPageIndex,0);assert.equal(h.session.state.inspected.source_set.file_count,101);assert.equal(h.calls.filter(call=>call.options.method==='POST').length,0);
});
for(const [label,change] of [
 ['wrong offset',value=>{value.files_page.offset=1;}],['negative offset',value=>{value.files_page.offset=-1;}],['boolean offset',value=>{value.files_page.offset=false;}],['wrong limit',value=>{value.files_page.limit=49;}],['wrong total',value=>{value.files_page.total=102;}],
 ['missing next cursor',value=>{value.files_page.next_cursor=null;}],['unrelated next cursor',value=>{value.files_page.next_cursor='unrelated';}],['control cursor',value=>{value.files_page.next_cursor='bad\n';}],['extra page key',value=>{value.files_page.private_path='PRIVATE';}],['empty page',value=>{value.files=[];}],['short middle page',value=>{value.files.pop();value.files_page.next_cursor=value.files.at(-1).id;}],['too many members',value=>{value.files.push({...value.files[0],id:'extra',name:'extra.txt'});value.files_page.next_cursor='extra';}]
])test('malformed manifest page '+label+' is rejected',async()=>{const record=await largeRecord(101),value=pagedDetail(record.summary,record.files);change(value);await assert.rejects(api.parseSourceSetDetail(value,sid(2),0));});
test('final manifest page validates requested offset and has no continuation cursor',async()=>{
 const record=await largeRecord(51),value=pagedDetail(record.summary,record.files,sid(2),50);assert.equal((await api.parseSourceSetDetail(value,sid(2),50)).files.length,1);await assert.rejects(api.parseSourceSetDetail(value,sid(2),0));value.files_page.next_cursor=value.files[0].id;await assert.rejects(api.parseSourceSetDetail(value,sid(2),50));
});
test('manifest files remain strictly Python-name ordered inside each returned page',async()=>{
 const record=await largeRecord(101),value=pagedDetail(record.summary,record.files);[value.files[0],value.files[1]]=[value.files[1],value.files[0]];await assert.rejects(api.parseSourceSetDetail(value,sid(2),0));
});
for(const overlap of ['name','id'])test('next manifest page rejects a repeated boundary '+overlap+' and preserves the cursor stack',async()=>{
 const h=await readyPaged(101,(url,options,mock)=>{if(url.includes('?files_after=')){const value=structuredClone(mock.detail(sid(2),50));if(overlap==='name')value.files[0].name='part049.txt';else value.files[0].id='legacy/opaque?49';return json(value);}});await h.session.inspect(sid(2));await h.session.manifestNext();assert.equal(h.session.state.refreshRequired,true);assert.equal(h.session.state.inspected.files_page.offset,0);assert.deepEqual(h.session.state.manifestCursors,[null]);assert.equal(h.session.state.manifestPageIndex,0);
});
test('failed previous-page reads preserve the trusted page and page index',async()=>{
 let failPrevious=false;const h=await readyPaged(101,(url,options,mock)=>failPrevious&&url.endsWith('/'+sid(2))?json({code:'PRIVATE',detail:'PRIVATE'},500):undefined);await h.session.inspect(sid(2));await h.session.manifestNext();failPrevious=true;await h.session.manifestPrevious();assert.equal(h.session.state.inspected.files_page.offset,50);assert.equal(h.session.state.manifestPageIndex,1);assert.deepEqual(h.session.state.manifestCursors,[null,'legacy/opaque?49']);assert.equal(h.session.state.refreshRequired,true);assert.doesNotMatch(h.session.state.error,/PRIVATE/);
});
test('one displayed member of a 51-file current version may be explicitly removed',async()=>{
 const h=await readyPaged(51);await h.session.inspect(sid(2));await h.session.manifestNext();assert.equal(h.session.state.inspected.files.length,1);h.session.beginRemoval('legacy/opaque?50');assert.equal(h.session.state.removal.confirmed,false);h.session.confirmRemoval(true);let removed=0;await h.session.remove(async(id,file,expected)=>{removed++;assert.deepEqual([id,file,expected],[sid(2),'legacy/opaque?50',sid(2)]);return {ok:false,refreshRequired:false};});assert.equal(removed,1);assert.doesNotMatch(html(h.session),/Upload a replacement before removing the only readable file/);
});
test('unknown or off-page file IDs cannot acquire removal authority',async()=>{
 const h=await readyPaged(51);await h.session.inspect(sid(2));h.session.beginRemoval('not-saved');assert.equal(h.session.state.removal,null);h.session.beginRemoval('legacy/opaque?50');assert.equal(h.session.state.removal,null);await h.session.manifestNext();h.session.beginRemoval('legacy/opaque?0');assert.equal(h.session.state.removal,null);let removed=0;await h.session.remove(async()=>{removed++;return {ok:true};});assert.equal(removed,0);assert.equal(h.calls.filter(call=>call.options.method==='POST').length,0);
});
test('busy and refresh-required manifest navigation do not issue new reads',async()=>{
 const h=await readyPaged();await h.session.inspect(sid(2));const count=h.calls.length;h.session.externalBusy=true;await h.session.manifestNext();await h.session.manifestPrevious();h.session.externalBusy=false;h.session.state.refreshRequired=true;await h.session.manifestNext();await h.session.manifestPrevious();assert.equal(h.calls.length,count);
});
test('maximum opaque cursor uses one encoded fixed query and never an injected URL',async()=>{
 const record=await largeRecord(51),cursor='/??&=#%'+ '\u{10000}'.repeat(121);assert.equal(Array.from(cursor).length,128);record.files[49].id=cursor;
 const h=await ready({sourceRecord:record,allIds:[sid(2)]});const value=await api.inspectSourceSet(pid,sid(2),undefined,cursor,50);assert.equal(value.files_page.offset,50);assert.equal(h.calls.at(-1).url,'/api/projects/'+pid+'/source-sets/'+sid(2)+'?files_after='+encodeURIComponent(cursor));assert.equal((h.calls.at(-1).url.match(/\?/g)||[]).length,1);assert.equal(h.calls.at(-1).options.method,'GET');
});
test('invalid opaque cursors and offsets reject before fetch',async()=>{
 const h=await harness();for(const cursor of ['', 'x'.repeat(129),'bad\n','bad\u007f','bad\ud800'])await assert.rejects(api.inspectSourceSet(pid,sid(2),undefined,cursor,50));for(const offset of [-1,false,0.5,Number.MAX_SAFE_INTEGER+1])await assert.rejects(api.inspectSourceSet(pid,sid(2),undefined,'valid',offset));assert.equal(h.calls.length,0);
});
test('one opaque legacy run ID is accepted by scalar length but never rendered as source authority',async()=>{
 const h=await ready(),value=h.page();value.source_sets[1].run_ids=['\u{10000}'.repeat(128)];const parsed=api.parseSourceSetPage(value);assert.equal(parsed.source_sets[1].run_ids[0],value.source_sets[1].run_ids[0]);h.session.state.items=parsed.source_sets;const rendered=html(h.session);assert.doesNotMatch(rendered,new RegExp(value.source_sets[1].run_ids[0]));assert.match(rendered,/linked saved run/);
 value.source_sets[1].run_ids=['\u{10000}'.repeat(129)];assert.throws(()=>api.parseSourceSetPage(value));
});
for(const [label,change] of [
 ['extra raw inventory',s=>{s.inventory={private_path:'PRIVATE'};}],['arbitrary detail',s=>{s.detail='PRIVATE';}],['missing native state',s=>{delete s.native_state;}],['bad source hash',s=>{s.source_hash='0'.repeat(64);}],['bad profile',s=>{s.conversion_profile='PRIVATE';}],['nonboolean checks',s=>{s.source_checks_passed='yes';}],['file count mismatch',s=>{s.file_count++;}],['bytes mismatch',s=>{s.source_bytes++;}],['negative conversion bytes',s=>{s.conversion_source_bytes=-1;}],['unsafe count',s=>{s.assessment_finding_count=Number.MAX_SAFE_INTEGER+1;}],['negative dependency count',s=>{s.missing_dependency_count=-1;}],['boolean blockers',s=>{s.conversion_blocker_count=true;}],['wrong byte limit',s=>{s.max_conversion_bytes=300001;}],['wrong file limit',s=>{s.max_conversion_files=51;}],['bad native state',s=>{s.native_state='PRIVATE';}],['lowercase codes',s=>{s.blocker_codes=['private'];}],['duplicate codes',s=>{s.blocker_codes=['A','A'];}],['unsorted codes',s=>{s.blocker_codes=['B','A'];}],['long code',s=>{s.blocker_codes=['A'.repeat(65)];}],['too many codes',s=>{s.blocker_codes=Array.from({length:65},(_,n)=>'C'+String(n).padStart(2,'0'));}]
])test('bounded assessment summary rejects '+label+' in detail and mutation acknowledgement',async()=>{
 const h=await harness(),detail=structuredClone(h.detail(sid(1)));change(detail.assessment_summary);await assert.rejects(api.parseSourceSetDetail(detail,sid(1)));h.state.selected=sid(1);const ack=structuredClone(h.ack(sid(1)));change(ack.assessment_summary);assert.throws(()=>api.parseSourceSelection(ack));
});
test('bounded summaries expose only fixed fields and do not render invented raw identifiers',async()=>{
 const h=await ready(),privateID='PRIVATE-PATH-AND-RAW-IDENTIFIER-'.repeat(500);const value=h.detail(sid(1));value.source_set.run_ids=['PRIVATE-OPAQUE-RUN'];const parsed=await api.parseSourceSetDetail(value,sid(1));assert.deepEqual(Object.keys(parsed.assessment_summary).sort(),Object.keys(assessmentSummary(value.source_set)).sort());h.session.state.inspected=parsed;const rendered=html(h.session);assert.doesNotMatch(rendered,/PRIVATE-OPAQUE-RUN|source_preparation|source_path|filesystem_path|\[object Object\]/);
 for(const key of ['assessment','inventory','source_preparation']){const unsafe={...value,[key]:{raw_identifier:privateID}};await assert.rejects(api.parseSourceSetDetail(unsafe,sid(1)));}
 for(const profile of ['native-table-form-v1','legacy-html-prototype-v1','unconfigured'])for(const native_state of ['READY','BLOCKED',null]){const accepted=structuredClone(value);accepted.assessment_summary.conversion_profile=profile;accepted.assessment_summary.native_state=native_state;assert.equal((await api.parseSourceSetDetail(accepted,sid(1))).assessment_summary.conversion_profile,profile);}
});
for(const change of [{id:sid(1)+'\n'},{source_hash:'A'.repeat(64)},{file_count:true},{file_count:0},{source_bytes:0},{created:'today'},{created:NaN},{origin:'guessed-history'},{is_selected:true},{run_ids:['']},{run_ids:['x'.repeat(129)]},{run_ids:['opaque\u007f']},{run_ids:['opaque\n']},{run_ids:['opaque\ud800']},{run_ids:[rid(1),rid(2)]},{approvals:true}])test('malformed source-set metadata rejects without fabricating history',async()=>{
 const h=await harness();const value=h.page();value.source_sets[1]={...value.source_sets[1],...change};assert.throws(()=>api.parseSourceSetPage(value));
});
test('pagination shows older control until complete and sends only validated before cursor',async()=>{
 const {session,calls}=await ready({override:(url,options,h)=>url.endsWith('/source-sets')?json(h.page([sid(2)],sid(2))):url.endsWith('?before='+sid(2))?json(h.page([sid(1)],null)):undefined});
 assert.match(html(session),/Load older versions/);assert.doesNotMatch(html(session),/All saved versions have been listed/);await session.load(true);assert.equal(session.state.items.length,2);assert.match(html(session),/All saved versions have been listed/);assert.equal(calls.at(-1).url,'/api/projects/'+pid+'/source-sets?before='+sid(2));
});
test('a changed selected pointer during pagination cannot mix current markers',async()=>{
 const {session}=await ready({override:(url,options,h)=>url.endsWith('/source-sets')?json(h.page([sid(2)],sid(2))):url.includes('?before=')?json({...h.page([sid(1)]),selected_source_set_id:sid(1),source_sets:[{...h.summary(sid(1)),is_selected:true}]}):undefined});await session.load(true);assert.equal(session.state.items.length,1);assert.equal(session.state.refreshRequired,true);assert.match(session.state.error,/current source version changed/);
});
test('selected current set outside first page can be explicitly inspected',async()=>{
 const {session}=await ready({selected:sid(1),override:(url,options,h)=>url.endsWith('/source-sets')?json(h.page([sid(2)],sid(2))):undefined});
 assert.match(html(session),/Inspect current version/);await session.inspect(sid(1));assert.equal(session.state.inspected.source_set.is_selected,true);
});
test('terminal pagination missing the selected set locks changes and never claims complete history',async()=>{
 for(const older of [false,true]){
  const {session}=await ready({selected:sid(1),override:(url,options,h)=>url.endsWith('/source-sets')?json(h.page([sid(2)],older?sid(2):null)):url.includes('?before=')?json(h.page([],null)):undefined});
  if(older)await session.load(true);assert.equal(session.state.refreshRequired,true);assert.match(session.state.error,/current source version changed/);
  assert.doesNotMatch(html(session),/All saved versions have been listed|current version is on an older page/);let changes=0;await session.useVersion(sid(2),async()=>{changes++;return {ok:true};});assert.equal(changes,0);
 }
});
test('stored filenames follow Python scalar length and visibly disclose DEL without altering identity',async()=>{
 const h=await ready();for(const name of ['\u{10000}'.repeat(176)+'.txt','a\u007f.txt']){
  const files=[{id:'name-edge',name,sha256:sha('x'),bytes:1}],source_hash=await api.readableManifestHash(files);
  const parsed=await api.parseSourceSetDetail(pagedDetail({...h.summary(sid(1)),source_hash,file_count:1,source_bytes:1,is_selected:true},files,sid(1)),sid(1));
  assert.equal(parsed.files[0].name,name);h.session.state={...h.session.state,inspected:parsed};const rendered=html(h.session);
  if(name.includes('\u007f')){assert.match(rendered,/a⟪U\+007F⟫\.txt/);assert.doesNotMatch(rendered,/\u007f/);}
 }
 const files=[{id:'too-long',name:'\u{10000}'.repeat(177)+'.txt',sha256:sha('x'),bytes:1}],source_hash=await api.readableManifestHash(files);
 await assert.rejects(api.parseSourceSetDetail(pagedDetail({...h.summary(sid(1)),source_hash,file_count:1,source_bytes:1,is_selected:true},files,sid(1)),sid(1)));
});
for(const edit of [detail=>{detail.files[0].bytes=5*1024*1024+1;},detail=>{detail.files[0].sha256='not-a-sha';},detail=>{detail.files[0].name='../private.xml';},detail=>{detail.files[0].name='C:\\private.xml';},detail=>{detail.files[0].text='PRIVATE';},detail=>{detail.files[1].id=detail.files[0].id;},detail=>{detail.files[1].name=detail.files[0].name;},detail=>{detail.assessment_summary.source_hash='0'.repeat(64);}])test('manifest page metadata membership and basename failures reject',async()=>{
 const h=await harness();const value=structuredClone(h.detail(sid(1)));edit(value);await assert.rejects(api.parseSourceSetDetail(value,sid(1)));
});
for(const [label,edit] of [['byte total',detail=>{detail.files[0].bytes++;}],['hash',detail=>{detail.files[0].sha256='0'.repeat(64);}]])test('a complete single-page manifest still rejects its '+label+' mismatch',async()=>{
 const h=await harness(),value=structuredClone(h.detail(sid(1)));edit(value);await assert.rejects(api.parseSourceSetDetail(value,sid(1)));
});
test('manifest metadata uses React escaping, not raw HTML or arbitrary JSON',async()=>{
 const h=await ready();const files=[{id:'safe',name:'<script>.xml',sha256:sha('x'),bytes:1}];const source_hash=await api.readableManifestHash(files);
 const parsed=await api.parseSourceSetDetail(pagedDetail({...h.summary(sid(1)),source_hash,file_count:1,source_bytes:1,is_selected:true},files,sid(1)),sid(1));h.session.state={...h.session.state,inspected:parsed};
 const rendered=html(h.session,{currentHash:'PRIVATE-FAKE-HASH'});assert.match(rendered,/&lt;script&gt;/);assert.doesNotMatch(rendered,/<script>|PRIVATE-FAKE-HASH|\[object Object\]/);
});
test('select is explicit, current selection is no-op, and complete compare-and-swap body is exact',async()=>{
 const {session,calls,state,records}=await ready();let invoked=0;
 const select=async(id,expected)=>{invoked++;const ack=await api.selectSourceSet(pid,id,expected);api.assertRefreshedSourceProject({id:pid,inventory:{selected_source_set_id:id,source_hash:records.get(id).summary.source_hash}},pid,ack);return {ok:true,refreshRequired:false};};
 await session.useVersion(sid(2),select);assert.equal(invoked,0);await session.useVersion(sid(1),select);assert.equal(invoked,1);assert.equal(state.selected,sid(1));assert.deepEqual(JSON.parse(calls.find(call=>call.options.method==='POST').options.body),{expected_current_source_set_id:sid(2)});assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.match(session.state.notice,/confirm processing separately/);
});
test('remove is current-manifest only and requires explicit confirmation before one callback',async()=>{
 const {session}=await ready();await session.inspect(sid(1));session.beginRemoval('legacy-id/opaque?1');assert.equal(session.state.removal,null);
 await session.inspect(sid(2));session.beginRemoval('unrelated-file');assert.equal(session.state.removal.confirmed,false);let calls=0;
 const remove=async(id,file,expected)=>{calls++;assert.deepEqual([id,file,expected],[sid(2),'unrelated-file',sid(2)]);await api.excludeSourceFile(pid,id,file,expected);return {ok:true,refreshRequired:false};};
 await session.remove(remove);assert.equal(calls,0);assert.match(html(session),/not erased from history/);session.confirmRemoval(true);await session.remove(remove);assert.equal(calls,1);assert.equal(session.state.removal,null);
});
test('cancel and the last readable file cannot issue removal',async()=>{
 const {session}=await ready();await session.inspect(sid(2));session.beginRemoval('unrelated-file');session.confirmRemoval(true);session.cancelRemoval();let calls=0;await session.remove(async()=>{calls++;return {ok:true};});assert.equal(calls,0);
 session.state.inspected.files=session.state.inspected.files.filter(file=>file.id==='new-xml');session.state.inspected.source_set.file_count=1;session.state.inspected.files_page.total=1;session.beginRemoval('new-xml');assert.equal(session.state.removal,null);assert.match(session.state.error,/replacement/);assert.match(html(session),/Upload a replacement before removing/);
});
test('opaque file IDs are JSON data and never interpolated into source-history URLs',async()=>{
 const {calls}=await ready();await api.excludeSourceFile(pid,sid(2),'legacy-id/opaque?1',sid(2));const call=calls.at(-1);assert.equal(call.url,'/api/projects/'+pid+'/source-sets/'+sid(2)+'/exclude');assert.deepEqual(JSON.parse(call.options.body),{expected_current_source_set_id:sid(2),excluded_file_ids:['legacy-id/opaque?1']});
});
test('removal response cannot silently claim the unchanged set was selected',async()=>{
 await ready({override:(url,options,h)=>url.endsWith('/exclude')?json({...h.ack(sid(2)),selection_changed:false}):undefined});await assert.rejects(api.excludeSourceFile(pid,sid(2),'unrelated-file',sid(2)));
});
test('stale compare-and-swap never automatically retries or changes selected source',async()=>{
 const {calls,state}=await ready();await assert.rejects(api.selectSourceSet(pid,sid(1),sid(3)),error=>{assert.equal(api.sourceHistoryRefreshRequired(error),true);assert.doesNotMatch(api.sourceHistoryErrorMessage(error),/PRIVATE/);return true;});assert.equal(state.selected,sid(2));assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
});
test('failed or unknown callbacks lock mutations until an explicit project refresh',async()=>{
 const {session,calls}=await ready();let invoked=0;await session.useVersion(sid(1),async()=>{invoked++;throw new Error('PRIVATE-PROVIDER');});await session.useVersion(sid(1),async()=>{invoked++;return {ok:true};});assert.equal(invoked,1);assert.equal(session.state.refreshRequired,true);assert.doesNotMatch(html(session),/PRIVATE/);const count=calls.length;await session.refresh(async()=>true);assert.equal(session.state.refreshRequired,false);assert.equal(calls.length,count+1);
});
test('busy and concurrent use clicks cannot dispatch duplicate actions',async()=>{
 const {session}=await ready();session.externalBusy=true;let invoked=0;await session.useVersion(sid(1),async()=>{invoked++;return {ok:true};});assert.equal(invoked,0);session.externalBusy=false;
 let done;const waiting=new Promise(resolve=>{done=resolve;});const first=session.useVersion(sid(1),async()=>{invoked++;return waiting;});await session.useVersion(sid(1),async()=>{invoked++;return {ok:true};});done({ok:false,refreshRequired:false});await first;assert.equal(invoked,1);
});
test('all network paths are fixed same-origin requests and raw redirect responses reject',async()=>{
 const {session,calls}=await ready();await session.inspect(sid(1));await session.download(sid(1));for(const {url,options} of calls){assert.ok(url.startsWith('/api/projects/'+pid+'/source-sets'));assert.equal(options.credentials,'same-origin');assert.equal(options.mode,'same-origin');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');}
 await harness({override:()=>{const response=json({});Object.defineProperty(response,'redirected',{value:true});return response;}});await assert.rejects(api.listSourceSets(pid));
});
for(const status of [401,403,404,409,422,500])test('owner-auth and API error '+status+' never echo provider details',async()=>{
 await harness({override:()=>json({detail:'PRIVATE-PATH-TOKEN <script>',code:'PRIVATE-CODE'},status)});await assert.rejects(api.listSourceSets(pid),error=>{assert.doesNotMatch(api.sourceHistoryErrorMessage(error),/PRIVATE|<script>/);return true;});
});
const responseLimitCopy='Source history could not be displayed within the response limit. No source version was changed. Refresh or ask the operator for help.';
const exportLimitCopy='This source version is too large for one readable export. Its files remain saved; use a smaller coherent version or ask the operator for an approved export.';
for(const [code,detail,operation] of [['SOURCE_HISTORY_RESPONSE_TOO_LARGE',responseLimitCopy,'read'],['SOURCE_HISTORY_EXPORT_TOO_LARGE',exportLimitCopy,'export']])test('exact bounded '+code+' failure uses safe fixed copy without retry',async()=>{
 const h=await harness({override:()=>json({code,detail},409)});await assert.rejects(operation==='export'?api.exportSourceSet(pid,sid(1)):api.listSourceSets(pid),error=>{assert.equal(api.sourceHistoryErrorMessage(error),detail);return true;});assert.equal(h.calls.length,1);assert.equal(h.state.selected,sid(2));
});
for(const body of [
 {code:'SOURCE_HISTORY_RESPONSE_TOO_LARGE',detail:responseLimitCopy+' PRIVATE'},
 {code:'SOURCE_HISTORY_EXPORT_TOO_LARGE',detail:exportLimitCopy+' PRIVATE'},
 {code:'SOURCE_HISTORY_RESPONSE_TOO_LARGE',detail:responseLimitCopy,private_path:'PRIVATE'},
 {code:'PRIVATE',detail:responseLimitCopy},
 {code:'SOURCE_HISTORY_RESPONSE_TOO_LARGE',detail:exportLimitCopy},
 {code:'SOURCE_HISTORY_RESPONSE_TOO_LARGE',detail:'PRIVATE'.repeat(800)}
])test('near-match or oversized 409 body never becomes an allowlisted response',async()=>{
 await harness({override:()=>json(body,409)});await assert.rejects(api.listSourceSets(pid),error=>{const message=api.sourceHistoryErrorMessage(error);assert.notEqual(message,responseLimitCopy);assert.notEqual(message,exportLimitCopy);assert.doesNotMatch(message,/PRIVATE/);return true;});
});
test('duplicate error body keys cannot activate safe-size error copy',async()=>{
 const raw=JSON.stringify({code:'SOURCE_HISTORY_RESPONSE_TOO_LARGE',detail:responseLimitCopy}).replace('{','{"code":"PRIVATE",');await harness({override:()=>new Response(raw,{status:409,headers:{'content-type':'application/json'}})});await assert.rejects(api.listSourceSets(pid),error=>{assert.notEqual(api.sourceHistoryErrorMessage(error),responseLimitCopy);assert.doesNotMatch(api.sourceHistoryErrorMessage(error),/PRIVATE/);return true;});
});
test('source export preserves returned ZIP bytes, ignores unsafe headers, and is not an APEX package',async()=>{
 const {session}=await ready();const value=await session.download(sid(1));assert.equal(value.filename,'fox-source-set-'+sid(1)+'.zip');assert.deepEqual([...new Uint8Array(await value.blob.arrayBuffer())],[80,75,3,4,0]);assert.match(html(session),/not an APEX package/);assert.doesNotMatch(html(session),/PRIVATE-PATH/);
});
test('export content type signature and safe409 failure cannot produce a download',async()=>{
 for(const response of [new Response('PRIVATE',{headers:{'content-type':'text/plain'}}),new Response('PRIVATE',{headers:{'content-type':'application/zip'}}),json({detail:'PRIVATE'},409)]){
  const {session}=await ready({override:url=>url.endsWith('/download')?response:undefined});assert.equal(await session.download(sid(1)),null);assert.doesNotMatch(html(session),/PRIVATE/);
 }
});
test('unknown export failures lock mutations while explicit export409 remains safely read-only',async()=>{
 for(const status of [404,500,409]){
  const {session}=await ready({override:url=>url.endsWith('/download')?json({detail:'PRIVATE'},status):undefined});assert.equal(await session.download(sid(1)),null);
  assert.equal(session.state.refreshRequired,status!==409);let changes=0;await session.useVersion(sid(1),async()=>{changes++;return {ok:false,refreshRequired:false};});assert.equal(changes,status===409?1:0);
 }
 const {session}=await ready({override:url=>url.endsWith('/download')?json({detail:'PRIVATE'},409):undefined});session.state.refreshRequired=true;await session.download(sid(1));assert.equal(session.state.refreshRequired,true);
});
test('malformed duplicated or oversized JSON is rejected without leaking it',async()=>{
 for(const raw of ['PRIVATE','{"selected_source_set_id":null,"selected_source_set_id":null,"source_sets":[],"next_cursor":null}',' '.repeat(2*1024*1024+1)]){
  await harness({override:()=>new Response(raw,{headers:{'content-type':'application/json'}})});await assert.rejects(api.listSourceSets(pid),error=>{assert.doesNotMatch(api.sourceHistoryErrorMessage(error),/PRIVATE/);return true;});
 }
});
test('JSON and readable archive content-length limits reject before body download',async()=>{
 for(const [isExport,size,type] of [[false,2*1024*1024+1,'application/json'],[true,108*1024*1024+1,'application/zip']]){
  let canceled=0;const response=new Response(new ReadableStream({cancel(){canceled++;}}),{headers:{'content-type':type,'content-length':String(size)}});const h=await harness({override:()=>response});await assert.rejects(isExport?api.exportSourceSet(pid,sid(1)):api.listSourceSets(pid));assert.equal(h.calls.length,1);assert.equal(canceled,1);
 }
});
test('bad IDs and cursors reject before fetch',async()=>{
 const {calls}=await harness();for(const id of [sid(1)+'\n','../private','https://example.com',sid(1)+'?x']){await assert.rejects(api.inspectSourceSet(pid,id));await assert.rejects(api.listSourceSets(pid,id));await assert.rejects(api.selectSourceSet(pid,id,null));}assert.equal(calls.length,0);
});
test('refreshed project must match acknowledged project selection and hash',async()=>{
 const h=await harness();h.state.selected=sid(1);const ack=api.parseSourceSelection(h.ack(sid(1)));api.assertRefreshedSourceProject({id:pid,inventory:h.inventory(sid(1))},pid,ack);
 for(const value of [{id:'b'.repeat(32),inventory:h.inventory(sid(1))},{id:pid,inventory:h.inventory(sid(2))},{id:pid,inventory:{...h.inventory(sid(1)),source_hash:'0'.repeat(64)}}])assert.throws(()=>api.assertRefreshedSourceProject(value,pid,ack));
});
test('request deadline covers a hung body and marks mutation outcome for refresh, never retry',async()=>{
 const oldSet=globalThis.setTimeout,oldClear=globalThis.clearTimeout;let fire,cleared=0,canceled=0;
 globalThis.setTimeout=callback=>{fire=callback;return 7;};globalThis.clearTimeout=()=>{cleared++;};
 try{const response=new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode('{'));},cancel(){canceled++;return new Promise(()=>{});}}));const {calls}=await harness({override:()=>response});const operation=api.selectSourceSet(pid,sid(1),sid(2));for(let i=0;i<50&&!response.body.locked;i++)await new Promise(done=>setImmediate(done));assert.equal(response.body.locked,true);fire();await assert.rejects(operation,error=>{assert.equal(api.sourceHistoryRefreshRequired(error),true);return true;});assert.equal(calls.length,1);assert.equal(canceled,1);assert.equal(cleared,1);
 }finally{globalThis.setTimeout=oldSet;globalThis.clearTimeout=oldClear;}
});
test('disposed history session aborts reads and never publishes a late response',async()=>{
 let resolve;const pending=new Promise(done=>{resolve=done;});const h=await harness({override:()=>pending});const action=h.session.load();h.session.dispose();resolve(json(h.page()));await action;assert.equal(h.calls[0].options.signal.aborted,true);assert.equal(h.session.state.loaded,false);
});
test('candidate presentation has no conversion verification acceptance or package-download control',()=>{
 assert.doesNotMatch(componentSource,/\/runs|\/accept|Run QA|Retry verification|dangerouslySetInnerHTML|JSON\.stringify/);
 assert.doesNotMatch(helperSource,/\/runs|\/accept|\/process|localStorage|sessionStorage/);
});
