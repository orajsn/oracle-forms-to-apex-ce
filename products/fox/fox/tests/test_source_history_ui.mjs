// Canonical source-history integration checks. Loads the actual canonical main.
// Mocked React/API execution only; no browser, service, dependency install or live request.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const require=createRequire(new URL('../package.json',import.meta.url));
const ts=require('typescript'),React=require('react');
const helperSource=await readFile(new URL('../web/sourceVersionPresentation.ts',import.meta.url),'utf8');
const helperJS=ts.transpileModule(helperSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const helpers=await import('data:text/javascript;base64,'+Buffer.from(helperJS).toString('base64'));
const mainURL=new URL('../web/main.tsx',import.meta.url);
const candidate=await readFile(mainURL,'utf8');
const parsed=ts.createSourceFile('main.candidate.tsx',candidate,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
assert.equal(parsed.parseDiagnostics.length,0);
const declarations=parsed.statements.filter(node=>ts.isFunctionDeclaration(node)&&['App','Acceptance','SourceUpload'].includes(node.name?.text)).map(node=>node.getText(parsed)).join('\n');
const instrumented=declarations.replace(' if(loading)return',' __capture({open,refresh,closeProject,changeSource,refreshSourceProject,upload});\n if(loading)return');
assert.notEqual(instrumented,declarations);
function nameHooks(context){
 const visitor=node=>{
  if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&['useState','useRef'].includes(node.expression.text)){
   const binding=node.parent.name;const name=ts.isArrayBindingPattern(binding)?binding.elements[0].name.text:binding.text;
   assert.equal(typeof name,'string');
   return context.factory.updateCallExpression(node,context.factory.createIdentifier('__'+node.expression.text),undefined,[context.factory.createStringLiteral(name),...node.arguments]);
  }
  return ts.visitEachChild(node,visitor,context);
 };
 return node=>ts.visitNode(node,visitor);
}
const compiled=ts.transpileModule(instrumented,{fileName:'main.candidate.tsx',compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext,jsx:ts.JsxEmit.React},transformers:{before:[nameHooks]}}).outputText;
const iconNames=['ArrowRight','FolderOpen','Plus','Upload','Download','ShieldCheck','ChevronLeft','LogOut','FileCode2','TriangleAlert'];
const componentNames=['SourceVersionHistory','LocalPreparation','SourceOverview','SourceEligibility','ManagedVerificationStatus','RunEvidence'];
const stubs=Object.fromEntries([...iconNames,...componentNames].map(name=>[name,Object.defineProperty(()=>null,'name',{value:name})]));
const names=['React','__useState','__useRef','useEffect','api','json','runLabel','checkSelectedSources','uploadManifestName','selectSourceSet','excludeSourceFile','assertRefreshedSourceProject','sourceHistoryErrorMessage','sourceHistoryRefreshRequired','__capture','setInterval','clearInterval',...Object.keys(stubs)];
const factory=new Function(...names,compiled+'\nreturn {App,Acceptance,SourceUpload};');
const sid=n=>'ss-'+String(n).repeat(32),hash=n=>String(n).repeat(64),pid='p'.repeat(32),otherPid='q'.repeat(32);
const clone=value=>structuredClone(value);
const defaultSession={username:'synthetic',conversion_configured:true,conversion_profile:'native-table-form-v1',configuration_scope:'Synthetic local mock.',configuration_checks:[]};
const historicRuns=[
 {id:'fox-verified-old',state:'VERIFIED',source_hash:hash(1),downloadable:false,message:'Synthetic verified old version.'},
 {id:'fox-accepted-old',state:'ACCEPTED',source_hash:hash(1),downloadable:true,message:'Synthetic accepted old version.'},
];
function project({id=pid,selected=sid(2),sourceHash=hash(2),runs=historicRuns}={}){
 return {id,name:'Synthetic project',customer:'Synthetic only',description:'Mocked integration.',file_count:1,run_count:runs.length,
 inventory:{selected_source_set_id:selected,source_hash:sourceHash,files:[{file:'mini.xml',bytes:5,sha256:hash(8),blocks:[]}],dependencies:[],issues:[],missing_count:0,scope_note:'Synthetic.',source_bytes:5,conversion_source_bytes:5,max_conversion_bytes:300000,forms_source_files:['mini.xml'],conversion_eligible:true,conversion_blockers:[],conversion_profile:'native-table-form-v1',native_assessment:{state:'READY',profile_id:'synthetic',scope_note:'Synthetic.',blockers:[],native_form:null}},runs:clone(runs)};
}
function ack(value,changed=true){return {selectedSourceSetId:value.inventory.selected_source_set_id,sourceHash:value.inventory.source_hash,selectionChanged:changed,sourceSet:{id:value.inventory.selected_source_set_id}};}
const deferred=()=>{let resolve,reject;const promise=new Promise((ok,no)=>{resolve=ok;reject=no;});return {promise,resolve,reject};};
function walk(node,predicate,result=[]){if(Array.isArray(node)){for(const child of node)walk(child,predicate,result);}else if(React.isValidElement(node)){if(predicate(node))result.push(node);walk(node.props.children,predicate,result);}return result;}
const component=(tree,name)=>walk(tree,node=>typeof node.type==='function'&&node.type.name===name)[0];
const textOf=node=>Array.isArray(node)?node.map(textOf).join(''):React.isValidElement(node)?textOf(node.props.children):typeof node==='string'?node:'';
function harness(options={}){
 const stores=new Map(),refs=new Map(),effects=new Map(),calls=[],selectionCalls=[],exclusionCalls=[],timers=new Map();let scope='App',captures={},rawTree,tree,seen=new Set(),effectIndex=0,effectQueue=[];
 let response=options.response||project({selected:sid(1),sourceHash:hash(1)});
 const state=(name,initial)=>{const key=scope+':'+name;if(!stores.has(key))stores.set(key,typeof initial==='function'?initial():initial);return [stores.get(key),next=>stores.set(key,typeof next==='function'?next(stores.get(key)):next)];};
 const ref=(name,initial)=>{const key=scope+':'+name;if(!refs.has(key))refs.set(key,{current:initial});return refs.get(key);};
 const effect=(fn,deps)=>{const key=scope+':effect-'+effectIndex++,old=effects.get(key);if(!old||deps.some((value,index)=>value!==old.deps[index])){old?.cleanup?.();effects.set(key,{deps});if(deps.length)effectQueue.push(()=>{effects.get(key).cleanup=fn();});}};
 const api=async(path,init)=>{calls.push({path,init});const custom=options.api?.(path,init,calls);if(custom!==undefined)return await custom;if(path==='/projects')return [project()];if(path.endsWith('/sources'))return clone(response.inventory);if(path==='/projects/'+pid||path==='/projects/'+otherPid)return clone(response);throw new Error('Unexpected mocked API route.');};
 const select=async(...args)=>{selectionCalls.push(args);return options.select?await options.select(...args):ack(response);};
 const exclude=async(...args)=>{exclusionCalls.push(args);return options.exclude?await options.exclude(...args):ack(response);};
 const assertRefresh=(value,id,ackValue)=>{options.onAssert?.(value,id,ackValue);helpers.assertRefreshedSourceProject(value,id,ackValue);};
 const errorMessage=helpers.sourceHistoryErrorMessage;
 const refreshRequired=helpers.sourceHistoryRefreshRequired;
 const check=options.check|| (async files=>({files:files.filter(file=>file.name!=='fox-readable-upload.json'),manifest:files.find(file=>file.name==='fox-readable-upload.json')}));
 const components=factory(React,state,ref,effect,api,body=>({method:'POST',body:JSON.stringify(body)}),value=>value,check,'fox-readable-upload.json',select,exclude,assertRefresh,errorMessage,refreshRequired,value=>{captures=value;},(fn,delay)=>{const id=timers.size+1;timers.set(id,{fn,delay});return id;},id=>timers.delete(id),...Object.values(stubs));
 stores.set('App:session',defaultSession);stores.set('App:loading',false);stores.set('App:detail',clone(options.detail||project()));stores.set('App:projects',[project()]);stores.set('App:tab','Sources');
 function expand(node,path='root'){
  if(Array.isArray(node))return node.map((child,index)=>expand(child,path+'/'+index));
  if(!React.isValidElement(node))return node;
  if(node.type===components.Acceptance||node.type===components.SourceUpload){
   const prior=scope;scope=node.type.name+':'+(node.key||path);seen.add(scope);effectIndex=0;const result=expand(node.type(node.props),path);scope=prior;return result;
  }
  return React.cloneElement(node,{},...React.Children.toArray(node.props.children).map((child,index)=>expand(child,path+'/'+index)));
 }
 const result={calls,selectionCalls,exclusionCalls,timers,stores,refs,components,
  get actions(){return captures;},get raw(){return rawTree;},get tree(){return tree;},
  get(name){return stores.get('App:'+name);},set(name,value){stores.set('App:'+name,value);},
  respond(value){response=value;},
  render(runEffects=true){scope='App';effectIndex=0;seen=new Set(['App']);effectQueue=[];rawTree=components.App();tree=expand(rawTree);for(const key of [...stores.keys()])if(!seen.has(key.slice(0,key.lastIndexOf(':'))))stores.delete(key);if(runEffects)for(const run of effectQueue)run();return tree;},
  history(){return component(rawTree,'SourceVersionHistory');},
  upload(){return component(rawTree,'SourceUpload');},
  acceptance(){return component(rawTree,'Acceptance');},
 };
 result.render();return result;
}
const processButton=h=>walk(h.tree,node=>node.type==='button'&&textOf(node).includes('Process source'))[0];
function checkProcessing(h,review=false){h.set('tab','Conversion runs');h.render();for(let index=0;index<(review?5:3);index++){walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox')[index].props.onChange({target:{checked:true}});h.render();}if(review){walk(h.tree,node=>node.type==='textarea')[0].props.onChange({target:{value:'Intentional current review'}});h.render();}assert.equal(processButton(h).props.disabled,false);}
function selectPendingUpload(h){h.set('tab','Sources');h.render();walk(h.tree,node=>node.type==='input'&&node.props.type==='file')[0].props.onChange({target:{files:[new File(['pending'],'pending.xml')],value:'pending'}});h.render();}

test('canonical source is parsed and unchanged during inspection',async()=>{
 assert.equal(parsed.parseDiagnostics.length,0);
 assert.equal(await readFile(mainURL,'utf8'),candidate);
});
for(const item of [
 {state:'QA_REQUIRED',current:true,downloadable:false,review:false,download:false},
 {state:'VERIFIED',current:true,downloadable:false,review:true,download:false},
 {state:'VERIFIED',current:false,downloadable:false,review:false,download:false},
 {state:'ACCEPTED',current:false,downloadable:true,review:false,download:true},
 {state:'ACCEPTED',current:false,downloadable:false,review:false,download:false},
])test('canonical review/download gates '+JSON.stringify(item),()=>{
 const run={id:'fox-gate-fixture',state:item.state,source_hash:item.current?hash(2):hash(1),downloadable:item.downloadable,message:'Synthetic gate fixture only.'};
 const h=harness({detail:project({runs:[run]})});h.set('tab','Conversion runs');h.render();
 assert.equal(Boolean(h.acceptance()),item.review);
 const links=walk(h.tree,node=>node.type==='a'&&String(node.props.href).endsWith('/download'));
 assert.equal(links.length,item.download?1:0);
 if(item.review)assert.equal(walk(h.tree,node=>node.type==='button'&&textOf(node).includes('Accept tested package'))[0].props.disabled,true);
});
test('Sources mounts exact history contract and public selection state',()=>{
 const h=harness(),history=h.history();assert.ok(history);assert.equal(history.props.projectId,pid);assert.equal(history.props.selectedSourceSetId,sid(2));assert.equal(history.props.currentSourceHash,hash(2));assert.equal(history.props.busy,false);
 for(const name of ['onUseVersion','onExcludeFile','onRefreshProject'])assert.equal(typeof history.props[name],'function');
 assert.equal(history.key,pid+'-'+sid(2)+'-'+hash(2));
});
test('selection holds global busy before POST and clears consent plus pending component keys immediately',async()=>{
 const waiting=deferred(),h=harness({select:()=>waiting.promise});h.set('consent',[true,true,true]);h.render();
 const beforeUpload=h.upload().key,beforeLocal=component(h.raw,'LocalPreparation').key;
 const pending=h.history().props.onUseVersion(sid(1),sid(2));assert.equal(h.get('busy'),true);assert.deepEqual(h.get('consent'),[false,false,false]);assert.equal(h.get('sourceUiEpoch'),1);
 h.render();assert.equal(h.history().props.busy,true);assert.notEqual(h.upload().key,beforeUpload);assert.notEqual(component(h.raw,'LocalPreparation').key,beforeLocal);
 assert.deepEqual(h.selectionCalls,[[pid,sid(1),sid(2)]]);
 waiting.resolve(ack(project({selected:sid(1),sourceHash:hash(1)})));assert.deepEqual(await pending,{ok:true,refreshRequired:false});assert.equal(h.get('busy'),false);
});
test('same render reentrant selection is refused by source-action lock',async()=>{
 const waiting=deferred(),h=harness({select:()=>waiting.promise}),history=h.history();
 const first=history.props.onUseVersion(sid(1),sid(2));assert.deepEqual(await history.props.onUseVersion(sid(1),sid(2)),{ok:false,refreshRequired:false});assert.equal(h.selectionCalls.length,1);
 waiting.resolve(ack(project({selected:sid(1),sourceHash:hash(1)})));await first;
});
test('successful selection validates ack-bound detail and refreshes project list without altering runs',async()=>{
 const order=[],h=harness({onAssert:()=>order.push('assert'),api:(path,init)=>{order.push(path);}}),original=clone(h.get('detail').runs);
 assert.deepEqual(await h.history().props.onUseVersion(sid(1),sid(2)),{ok:true,refreshRequired:false});
 assert.equal(h.get('detail').inventory.selected_source_set_id,sid(1));assert.equal(h.get('detail').inventory.source_hash,hash(1));
 assert.deepEqual(h.get('detail').runs,original);assert.deepEqual(order,['/projects/'+pid,'assert','/projects']);assert.ok(h.calls.every(call=>!call.init?.method));
 h.render();assert.equal(h.history().key,pid+'-'+sid(1)+'-'+hash(1));
});
test('exclusion passes one file ID and CAS expectation and resets all source UI state',async()=>{
 const h=harness();h.set('consent',[true,true,true]);h.render();
 assert.deepEqual(await h.history().props.onExcludeFile(sid(2),'f'.repeat(32),sid(2)),{ok:true,refreshRequired:false});
 assert.deepEqual(h.exclusionCalls,[[pid,sid(2),'f'.repeat(32),sid(2)]]);assert.equal(h.get('sourceUiEpoch'),2);assert.deepEqual(h.get('consent'),[false,false,false]);
});
test('same-hash no-op selection still clears processing consent and remounts human acceptance',async()=>{
 const same=project({selected:sid(1),sourceHash:hash(1)}),h=harness({detail:same,response:same,select:()=>ack(same,false)});
 h.set('tab','Conversion runs');h.render();const prior=h.acceptance().key;
 for(let index=0;index<5;index++){walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox')[index].props.onChange({target:{checked:true}});h.render();}
 walk(h.tree,node=>node.type==='textarea')[0].props.onChange({target:{value:'Previous notes must not return.'}});h.render();
 assert.deepEqual(h.get('consent'),[true,true,true]);assert.ok(walk(h.tree,node=>node.type==='textarea')[0].props.value);
 await h.actions.changeSource(()=>Promise.resolve(ack(same,false)));h.render();
 assert.notEqual(h.acceptance().key,prior);assert.deepEqual(h.get('consent'),[false,false,false]);
 assert.ok(walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox').every(node=>node.props.checked===false));
 assert.equal(walk(h.tree,node=>node.type==='textarea')[0].props.value,'');
});
test('new upload then restore old VERIFIED hash starts with no consent or human review; historical accepted download remains',async()=>{
 const old=project({selected:sid(1),sourceHash:hash(1)}),newer=project({selected:sid(2),sourceHash:hash(2)}),h=harness({detail:old,response:newer});
 h.set('tab','Conversion runs');h.render();
 for(let index=0;index<5;index++){walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox')[index].props.onChange({target:{checked:true}});h.render();}
 walk(h.tree,node=>node.type==='textarea')[0].props.onChange({target:{value:'Old reviewed notes'}});h.render();const initialKey=h.acceptance().key;
 assert.equal(await h.actions.upload([new File(['new'],'mini.xml')],'direct'),true);h.render();assert.equal(h.get('detail').inventory.source_hash,hash(2));assert.equal(h.acceptance(),undefined);
 assert.equal(walk(h.tree,node=>node.type==='a'&&node.props.href?.endsWith('/fox-accepted-old/download')).length,1);
 h.respond(old);await h.actions.changeSource(()=>Promise.resolve(ack(old)));h.render();
 assert.equal(h.get('detail').inventory.source_hash,hash(1));assert.notEqual(h.acceptance().key,initialKey);
 assert.deepEqual(h.get('consent'),[false,false,false]);assert.ok(walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox').every(node=>node.props.checked===false));
 assert.equal(walk(h.tree,node=>node.type==='textarea')[0].props.value,'');
 assert.equal(walk(h.tree,node=>node.type==='a'&&node.props.href?.endsWith('/fox-accepted-old/download')).length,1);
 assert.deepEqual(h.get('detail').runs,old.runs);assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,1);
});
for(const selected of [null,sid(2)])test('upload sends exact CAS field and unchanged file/sidecar bytes: '+selected,async()=>{
 const h=harness({detail:project({selected})}),file=new File([new Uint8Array([239,187,191,65,13,10])],'mini.xml'),sidecar=new File(['{}'],'fox-readable-upload.json');
 assert.equal(await h.actions.upload([file,sidecar],'prepared'),true);
 const call=h.calls.find(item=>item.init?.method==='POST'),parts=[...call.init.body.entries()];assert.equal(call.path,'/projects/'+pid+'/sources');
 assert.deepEqual(parts.map(([key])=>key),['files','prepared_manifest','expected_current_source_set_id']);assert.equal(parts[2][1],selected===null?'null':selected);
 assert.equal(parts[0][1],file);assert.equal(parts[1][1],sidecar);assert.deepEqual(await parts[0][1].arrayBuffer(),await file.arrayBuffer());
 assert.deepEqual(h.get('consent'),[false,false,false]);assert.equal(h.get('sourceUiEpoch'),1);
});
for(const selected of [undefined,'bad','ss-'+'1'.repeat(32)+'\n',true])test('malformed or absent expected selection cannot become null upload CAS: '+String(selected),async()=>{
 const detail=project();detail.inventory.selected_source_set_id=selected;const h=harness({detail});
 assert.equal(await h.actions.upload([new File(['a'],'mini.xml')],'direct'),false);assert.equal(h.calls.length,0);assert.equal(h.get('detail'),null);assert.match(h.get('error'),/Reopen/);
});
test('upload local validation failure retains pending component identity and does not echo raw errors',async()=>{
 const h=harness({check:async()=>{throw new Error('PRIVATE-FILE-CONTENT');}}),key=h.upload().key;
 assert.equal(await h.actions.upload([new File(['a'],'mini.xml')],'direct'),false);h.render();
 assert.equal(h.upload().key,key);assert.equal(h.calls.length,0);assert.doesNotMatch(h.get('error'),/PRIVATE/);assert.notEqual(h.get('detail'),null);
});
test('upload validation finishing after navigation performs no POST and does not reopen project',async()=>{
 const waiting=deferred(),h=harness({check:()=>waiting.promise}),file=new File(['a'],'mini.xml'),pending=h.actions.upload([file],'direct');
 h.actions.closeProject();waiting.resolve({files:[file]});assert.equal(await pending,false);
 assert.equal(h.calls.length,0);assert.equal(h.get('detail'),null);assert.equal(h.get('busy'),false);
});
for(const status of [409,422,500])test('uncertain upload failure stays safe and never retries POST: '+status,async()=>{
 const h=harness({api:(path,init)=>{if(init?.method==='POST')throw Object.assign(new Error('PRIVATE-BACKEND-TOKEN'),{status});}});
 assert.equal(await h.actions.upload([new File(['a'],'mini.xml')],'direct'),false);assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,1);
 assert.doesNotMatch(h.get('error'),/PRIVATE/);assert.deepEqual(h.get('consent'),[false,false,false]);
 assert.equal(h.get('detail')===null,status!==422);
});
test('upload ack with a later mismatched selected ID/hash closes detail rather than showing stale processing',async()=>{
 const h=harness({api:(path,init)=>init?.method==='POST'?project({selected:sid(3),sourceHash:hash(3)}).inventory:undefined});
 assert.equal(await h.actions.upload([new File(['a'],'mini.xml')],'direct'),false);assert.equal(h.get('detail'),null);assert.match(h.get('error'),/Reopen/);
});
for(const failure of ['cas','network','project-read','list-read','ack-mismatch'])test('source mutation '+failure+' fails closed with no automatic POST retry',async()=>{
 const h=harness({select:()=>{if(['cas','network'].includes(failure))throw Object.assign(new Error('PRIVATE-TOKEN'),{status:failure==='cas'?409:undefined});return failure==='ack-mismatch'?ack(project({selected:sid(3),sourceHash:hash(3)})):ack(project({selected:sid(1),sourceHash:hash(1)}));},
 api:path=>{if(failure==='project-read'&&path==='/projects/'+pid||failure==='list-read'&&path==='/projects')throw new Error('PRIVATE-PATH');}});
 h.set('consent',[true,true,true]);h.render();assert.deepEqual(await h.history().props.onUseVersion(sid(1),sid(2)),{ok:false,refreshRequired:true});
 assert.equal(h.selectionCalls.length,1);assert.equal(h.get('detail'),null);assert.deepEqual(h.get('consent'),[false,false,false]);assert.match(h.get('error'),/Reopen/);assert.doesNotMatch(h.get('error'),/PRIVATE/);assert.equal(h.get('busy'),false);
});
test('known nonrefresh access error from actual helper clears intent consent but retains detail',async()=>{
 const original=globalThis.fetch;let rejected;
 try{globalThis.fetch=async()=>new Response(null,{status:403});await helpers.selectSourceSet('a'.repeat(32),sid(1),sid(2));}catch(error){rejected=error;}finally{globalThis.fetch=original;}
 assert.ok(rejected);assert.equal(helpers.sourceHistoryRefreshRequired(rejected),false);
 const h=harness({select:()=>{throw rejected;}});
 assert.deepEqual(await h.history().props.onUseVersion(sid(1),sid(2)),{ok:false,refreshRequired:false});assert.notEqual(h.get('detail'),null);assert.equal(h.get('sourceUiEpoch'),1);
});
test('explicit project refresh is read-only and clears pending selections and consent',async()=>{
 const h=harness();h.set('consent',[true,true,true]);h.render();assert.equal(await h.history().props.onRefreshProject(),true);
 assert.deepEqual(h.calls.map(call=>call.path),['/projects/'+pid,'/projects']);assert.ok(h.calls.every(call=>!call.init?.method));assert.equal(h.get('sourceUiEpoch'),2);assert.deepEqual(h.get('consent'),[false,false,false]);assert.equal(h.selectionCalls.length,0);
});
test('explicit refresh failure closes only its current project and requests reopen',async()=>{
 const h=harness({api:()=>{throw new Error('PRIVATE');}});assert.equal(await h.history().props.onRefreshProject(),false);
 assert.equal(h.get('detail'),null);assert.match(h.get('error'),/Reopen/);assert.doesNotMatch(h.get('error'),/PRIVATE/);
});
test('an older open response is ignored after a source selection intent',async()=>{
 const waiting=deferred();let reads=0;
 const h=harness({api:path=>path==='/projects/'+pid&&++reads===1?waiting.promise:undefined});
 const oldRead=h.actions.open(pid);await h.history().props.onUseVersion(sid(1),sid(2));
 waiting.resolve(project({selected:sid(2),sourceHash:hash(2)}));await oldRead;assert.equal(h.get('detail').inventory.selected_source_set_id,sid(1));
});
test('poll opens are suppressed while source action is in flight',async()=>{
 const waiting=deferred(),h=harness({select:()=>waiting.promise}),pending=h.history().props.onUseVersion(sid(1),sid(2));
 await h.actions.open(pid);assert.equal(h.calls.length,0);
 waiting.resolve(ack(project({selected:sid(1),sourceHash:hash(1)})));await pending;
});
test('pending open cannot reopen after leaving; A to B to A uses latest response',async()=>{
 const first=deferred(),second=deferred(),third=deferred();let reads=0;
 const h=harness({api:path=>path.startsWith('/projects/')?[first,second,third][reads++].promise:undefined});
 const a=h.actions.open(pid);h.actions.closeProject();first.resolve(project());await a;assert.equal(h.get('detail'),null);
 const b=h.actions.open(otherPid),c=h.actions.open(pid);third.resolve(project({selected:sid(1),sourceHash:hash(1)}));await c;
 second.resolve(project({id:otherPid}));await b;assert.equal(h.get('detail').id,pid);assert.equal(h.get('detail').inventory.source_hash,hash(1));
});
for(const [label,before,after] of [
 ['selected set',project({selected:sid(1),sourceHash:hash(1)}),project({selected:sid(3),sourceHash:hash(1)})],
 ['source hash',project({selected:sid(1),sourceHash:hash(1)}),project({selected:sid(1),sourceHash:hash(2)})],
 ['project ID',project({selected:sid(1),sourceHash:hash(1)}),project({id:otherPid,selected:sid(1),sourceHash:hash(1)})],
 ['empty selection',project({selected:sid(1),sourceHash:hash(1)}),project({selected:null,sourceHash:hash(1)})],
 ['first saved selection',project({selected:null,sourceHash:hash(1)}),project({selected:sid(1),sourceHash:hash(1)})]
])test('observed '+label+' change clears processing, pending upload/local preparation and current human review',async()=>{
 after.runs[0].source_hash=after.inventory.source_hash;
 const h=harness({detail:before,response:after});checkProcessing(h);selectPendingUpload(h);const uploadKey=h.upload().key,localKey=component(h.raw,'LocalPreparation').key;
 await h.actions.open(after.id);assert.deepEqual(h.get('consent'),[false,false,false]);assert.equal(h.get('consentSource'),null);h.render(false);assert.notEqual(h.upload().key,uploadKey);assert.notEqual(component(h.raw,'LocalPreparation').key,localKey);assert.doesNotMatch(textOf(h.tree),/pending.xml/);
 const review=harness({detail:before,response:after});checkProcessing(review,true);const acceptanceKey=review.acceptance().key;await review.actions.open(after.id);review.render(false);assert.notEqual(review.acceptance().key,acceptanceKey);assert.ok(walk(review.tree,node=>node.type==='input'&&node.props.type==='checkbox').every(node=>node.props.checked===false));assert.equal(walk(review.tree,node=>node.type==='textarea')[0].props.value,'');assert.equal(processButton(review).props.disabled,true);assert.deepEqual(review.get('detail').runs,after.runs);
});
test('first render of an unbound new identity cannot process or reuse human review before effects',()=>{
 const old=project({selected:sid(1),sourceHash:hash(1)}),next=project({selected:sid(3),sourceHash:hash(1)}),h=harness({detail:old});checkProcessing(h,true);const acceptanceKey=h.acceptance().key;h.set('detail',next);h.render(false);
 assert.deepEqual(h.get('consent'),[true,true,true]);assert.equal(processButton(h).props.disabled,true);assert.notEqual(h.acceptance().key,acceptanceKey);assert.ok(walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox').every(node=>node.props.checked===false));const calls=h.calls.length;processButton(h).props.onClick();assert.equal(h.calls.length,calls);
});
test('a retained Process callback cannot submit old confirmation after a new source is observed but before rerender',async()=>{
 const before=project({selected:sid(1),sourceHash:hash(1)}),after=project({selected:sid(3),sourceHash:hash(1)}),h=harness({detail:before,response:after});checkProcessing(h);const oldClick=processButton(h).props.onClick;await h.actions.open(pid,true);const count=h.calls.length;oldClick();assert.equal(h.calls.length,count);assert.equal(h.get('detail').inventory.selected_source_set_id,sid(3));assert.deepEqual(h.get('consent'),[false,false,false]);
});
test('same-identity polling preserves intentional consent, review notes and pending source selections',async()=>{
 const same=project({selected:sid(1),sourceHash:hash(1)}),h=harness({detail:same,response:same});checkProcessing(h,true);const acceptanceKey=h.acceptance().key;await h.actions.open(pid,true);h.render(false);assert.equal(h.get('sourceUiEpoch'),0);assert.deepEqual(h.get('consent'),[true,true,true]);assert.equal(processButton(h).props.disabled,false);assert.equal(h.acceptance().key,acceptanceKey);assert.equal(walk(h.tree,node=>node.type==='textarea')[0].props.value,'Intentional current review');assert.ok(walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox').every(node=>node.props.checked===true));
 const upload=harness({detail:same,response:same});selectPendingUpload(upload);const uploadKey=upload.upload().key,localKey=component(upload.raw,'LocalPreparation').key;await upload.actions.open(pid,true);upload.render(false);assert.equal(upload.upload().key,uploadKey);assert.equal(component(upload.raw,'LocalPreparation').key,localKey);assert.match(textOf(upload.tree),/pending.xml/);
});
test('a stale callback carrying the old render identity does not clear same-identity checks after source selection',async()=>{
 const h=harness(),oldOpen=h.actions.open;await h.history().props.onUseVersion(sid(1),sid(2));h.render();checkProcessing(h,true);const epoch=h.get('sourceUiEpoch'),key=h.acceptance().key;await oldOpen(pid,true);h.render(false);assert.equal(h.get('sourceUiEpoch'),epoch);assert.deepEqual(h.get('consent'),[true,true,true]);assert.equal(h.acceptance().key,key);
});
test('wrong-project and malformed current identity responses cannot replace detail or reset current consent',async()=>{
 for(const response of [project({id:otherPid}),{...project(),inventory:{...project().inventory,selected_source_set_id:undefined}}]){const h=harness({detail:project({selected:sid(1),sourceHash:hash(1)}),response});checkProcessing(h,true);await assert.rejects(h.actions.open(pid,true),/Source state is unavailable/);assert.equal(h.get('detail').id,pid);assert.deepEqual(h.get('consent'),[true,true,true]);assert.equal(h.get('sourceUiEpoch'),0);}
});
test('obsolete timer and human-review completion callbacks cannot start a new GET after B navigation',async()=>{
 const a=project({selected:sid(1),sourceHash:hash(1)});a.runs.push({id:'fox-queued',state:'QUEUED',source_hash:hash(1),downloadable:false});const b=project({id:otherPid,selected:sid(1),sourceHash:hash(1)}),h=harness({detail:a,response:b});checkProcessing(h,true);const timer=[...h.timers.values()][0].fn,onAccepted=h.acceptance().props.onAccepted;await h.actions.open(otherPid);h.render();checkProcessing(h,true);const count=h.calls.length,epoch=h.get('sourceUiEpoch');await timer();await onAccepted();assert.equal(h.calls.length,count);assert.equal(h.get('detail').id,otherPid);assert.deepEqual(h.get('consent'),[true,true,true]);assert.equal(h.get('sourceUiEpoch'),epoch);
});
test('obsolete queued poll cannot reopen a project forcibly closed by an uncertain source mutation',async()=>{
 const a=project();a.runs.push({id:'fox-queued',state:'QUEUED',source_hash:hash(2),downloadable:false});const h=harness({detail:a,select:()=>{throw new Error('PRIVATE');}}),timer=[...h.timers.values()][0].fn;
 assert.deepEqual(await h.history().props.onUseVersion(sid(1),sid(2)),{ok:false,refreshRequired:true});assert.equal(h.get('detail'),null);const count=h.calls.length;await timer();assert.equal(h.calls.length,count);assert.equal(h.get('detail'),null);
});
test('late A Process completion cannot refresh or navigate after explicit B navigation',async()=>{
 const pending=deferred(),a=project({selected:sid(1),sourceHash:hash(1)}),b=project({id:otherPid,selected:sid(1),sourceHash:hash(1)}),h=harness({detail:a,response:b,api:(path,init)=>path==='/projects/'+pid+'/runs'&&init?.method==='POST'?pending.promise:undefined});checkProcessing(h);processButton(h).props.onClick();assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,1);h.actions.closeProject();await h.actions.open(otherPid);h.render();const count=h.calls.length;pending.resolve({});for(let turn=0;turn<5;turn++)await Promise.resolve();assert.equal(h.calls.length,count);assert.equal(h.get('detail').id,otherPid);
});
test('late A GET after B has intentional checks cannot replace B or reset its source UI',async()=>{
 const waiting=deferred(),b=project({id:otherPid,selected:sid(1),sourceHash:hash(1)});let reads=0;const h=harness({api:path=>path.startsWith('/projects/')&&++reads===1?waiting.promise:undefined,response:b}),old=h.actions.open(pid);await h.actions.open(otherPid);h.render();checkProcessing(h,true);const epoch=h.get('sourceUiEpoch');waiting.resolve(project());await old;h.render(false);assert.equal(h.get('detail').id,otherPid);assert.deepEqual(h.get('consent'),[true,true,true]);assert.equal(h.get('sourceUiEpoch'),epoch);
});
test('late mutation success does not reopen a navigated-away project',async()=>{
 const waiting=deferred(),h=harness({select:()=>waiting.promise}),pending=h.history().props.onUseVersion(sid(1),sid(2));
 h.actions.closeProject();waiting.resolve(ack(project({selected:sid(1),sourceHash:hash(1)})));await pending;assert.equal(h.get('detail'),null);
});
test('functional project guard preserves another project even without navigation generation change',async()=>{
 const waiting=deferred(),h=harness({select:()=>waiting.promise}),pending=h.history().props.onUseVersion(sid(1),sid(2));
 h.set('detail',project({id:otherPid}));waiting.resolve(ack(project({selected:sid(1),sourceHash:hash(1)})));await pending;assert.equal(h.get('detail').id,otherPid);
});
test('late uncertain mutation error cannot close or overwrite a different navigation state',async()=>{
 const waiting=deferred(),h=harness({select:()=>waiting.promise}),pending=h.history().props.onUseVersion(sid(1),sid(2));
 h.actions.closeProject();h.set('detail',project({id:otherPid}));h.set('error','New view notice.');waiting.reject(new Error('PRIVATE'));await pending;
 assert.equal(h.get('detail').id,otherPid);assert.equal(h.get('error'),'New view notice.');
});
test('older project list read cannot replace the refreshed list',async()=>{
 const waiting=deferred();let reads=0;const h=harness({api:path=>path==='/projects'&&++reads===1?waiting.promise:undefined});
 const oldRead=h.actions.refresh();await h.history().props.onUseVersion(sid(1),sid(2));waiting.resolve([{id:'obsolete'}]);await oldRead;assert.equal(h.get('projects')[0].id,pid);
});
test('pending upload selection state actually remounts after source intent',async()=>{
 const h=harness(),file=new File(['pending'],'pending.xml');
 const input=walk(h.tree,node=>node.type==='input'&&node.props.type==='file')[0];input.props.onChange({target:{files:[file],value:'pending'}});h.render();assert.match(textOf(h.tree),/pending.xml/);
 await h.history().props.onUseVersion(sid(1),sid(2));h.render();assert.doesNotMatch(textOf(h.tree),/pending.xml/);
});
test('canonical App includes no automatic source mutation effect or public QA control',()=>{
 const writes=parsed.statements.filter(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='App')[0].getText(parsed);
 assert.doesNotMatch(writes,/useEffect\([^;]*(?:selectSourceSet|excludeSourceFile|\/sources)/);
 assert.doesNotMatch(writes,/(?:Force pass|Skip verification|run-qa|approved?_external_ai:true|consent:\s*\[true)/m);
});

test('retained local preparation handoff cannot upload to a departed project',async()=>{
 const a=project({selected:sid(1),sourceHash:hash(1)}),b=project({id:otherPid,selected:sid(1),sourceHash:hash(1)}),h=harness({detail:a,response:b});
 const prior=component(h.raw,'LocalPreparation').props.onUseReviewed;h.actions.closeProject();await h.actions.open(otherPid);h.render();await prior([new File(['old'],'mini.xml')]);assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,0);assert.equal(h.get('detail').id,otherPid);
});
test('same-identity explicit refresh invalidates retained Process and acceptance authority',async()=>{
 const same=project({selected:sid(1),sourceHash:hash(1)}),h=harness({detail:same,response:same,api:(path,init)=>init?.method==='POST'?{}:undefined});checkProcessing(h,true);
 const process=processButton(h).props.onClick,accept=walk(h.tree,node=>node.type==='button'&&textOf(node).includes('Accept tested package'))[0].props.onClick;
 await h.actions.refreshSourceProject();h.render();process();accept();assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,0);
});
test('retained acceptance cannot submit after another project is opened',async()=>{
 const a=project({selected:sid(1),sourceHash:hash(1)}),b=project({id:otherPid,selected:sid(1),sourceHash:hash(1)}),h=harness({detail:a,response:b,api:(path,init)=>init?.method==='POST'?{}:undefined});checkProcessing(h,true);
 const prior=walk(h.tree,node=>node.type==='button'&&textOf(node).includes('Accept tested package'))[0].props.onClick;h.actions.closeProject();await h.actions.open(otherPid);h.render();prior();assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,0);
});
for(const action of ['upload','select','exclude','refresh'])test('retained '+action+' callback cannot act after a changed identity is observed before rerender',async()=>{
 const next=project({selected:sid(3),sourceHash:hash(3)}),h=harness({response:next}),prior=h.history().props,upload=h.actions.upload;
 await h.actions.open(pid,true);const calls=h.calls.length;
 if(action==='upload')await upload([new File(['old'],'mini.xml')],'direct');
 else if(action==='select')await prior.onUseVersion(sid(1),sid(2));
 else if(action==='exclude')await prior.onExcludeFile(sid(2),'opaque-file',sid(2));
 else await prior.onRefreshProject();
 assert.equal(h.calls.length,calls);assert.equal(h.selectionCalls.length,0);assert.equal(h.exclusionCalls.length,0);assert.equal(h.get('detail').inventory.selected_source_set_id,sid(3));
});
test('acceptance controls and submission remain blocked while a source refresh is in flight',async()=>{
 const same=project({selected:sid(1),sourceHash:hash(1)}),waiting=deferred(),h=harness({detail:same,response:same,api:path=>path==='/projects/'+pid?waiting.promise:undefined});checkProcessing(h,true);
 const prior=walk(h.tree,node=>node.type==='button'&&textOf(node).includes('Accept tested package'))[0].props.onClick,pending=h.actions.refreshSourceProject();h.render();
 const accept=walk(h.tree,node=>node.type==='button'&&textOf(node).includes('Accept tested package'))[0];assert.equal(accept.props.disabled,true);assert.equal(walk(h.tree,node=>node.type==='textarea')[0].props.disabled,true);
 prior();accept.props.onClick();assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,0);waiting.resolve(same);await pending;
});
test('retained Process cannot reuse consent after definite upload rejection or deliberate uncheck',async()=>{
 const h=harness({detail:project({selected:sid(1),sourceHash:hash(1)}),api:(path,init)=>{if(init?.method==='POST')throw Object.assign(new Error('Synthetic rejection'),{status:422});}});checkProcessing(h);const prior=processButton(h).props.onClick;
 await h.actions.upload([new File(['new'],'mini.xml')],'direct');const calls=h.calls.length;prior();assert.equal(h.calls.length,calls);
 const second=harness({detail:project({selected:sid(1),sourceHash:hash(1)})});checkProcessing(second);const beforeUncheck=processButton(second).props.onClick;walk(second.tree,node=>node.type==='input'&&node.props.type==='checkbox')[0].props.onChange({target:{checked:false}});beforeUncheck();assert.equal(second.calls.length,0);
});
test('retained acceptance authority cannot survive review revocation or changed notes',()=>{
 for(const change of ['uncheck','notes']){const h=harness({detail:project({selected:sid(1),sourceHash:hash(1)}),api:(path,init)=>init?.method==='POST'?{}:undefined});checkProcessing(h,true);
 const prior=walk(h.tree,node=>node.type==='button'&&textOf(node).includes('Accept tested package'))[0].props.onClick;
 if(change==='uncheck')walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox')[3].props.onChange({target:{checked:false}});
 else walk(h.tree,node=>node.type==='textarea')[0].props.onChange({target:{value:'Revised review'}});
 h.render();prior();assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,0);}
});
test('retained consent input cannot resurrect approvals after an explicit reset',async()=>{
 const same=project({selected:sid(1),sourceHash:hash(1)}),h=harness({detail:same,response:same});checkProcessing(h);const prior=walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox')[0].props.onChange;
 await h.actions.refreshSourceProject();h.render();prior({target:{checked:true}});h.render();assert.deepEqual(h.get('consent'),[false,false,false]);assert.equal(processButton(h).props.disabled,true);
});
test('patched main type-checks in memory against the exact history callback contract',()=>{
 const mainPath=ts.sys.resolvePath(fileURLToPath(mainURL));
 const basePath=mainPath.slice(0,mainPath.lastIndexOf('/'));
 const virtual=new Map([
  [mainPath,candidate],
  [basePath+'/SourceVersionHistory.tsx',"export default function SourceVersionHistory(props:{projectId:string;selectedSourceSetId:string|null;currentSourceHash:string;busy:boolean;onUseVersion:(sid:string,expected:string|null)=>Promise<{ok:boolean;refreshRequired:boolean}>;onExcludeFile:(sid:string,fileId:string,expected:string)=>Promise<{ok:boolean;refreshRequired:boolean}>;onRefreshProject:()=>Promise<boolean>}){return null;}"],
  [basePath+'/sourceVersionPresentation.ts',helperSource],
 ]);
 const options={target:ts.ScriptTarget.ES2022,lib:['lib.es2022.d.ts','lib.dom.d.ts','lib.dom.iterable.d.ts'],module:ts.ModuleKind.ESNext,moduleResolution:ts.ModuleResolutionKind.Bundler,jsx:ts.JsxEmit.ReactJSX,strict:true,skipLibCheck:true,noEmit:true,allowImportingTsExtensions:true};
 const host=ts.createCompilerHost(options),fileExists=host.fileExists,read=host.readFile,get=host.getSourceFile;
 const key=name=>ts.sys.resolvePath(name).replaceAll('\\','/');
 host.fileExists=name=>virtual.has(key(name))||fileExists(name);
 host.readFile=name=>virtual.get(key(name))??read(name);
 host.getSourceFile=(name,version,onError,newFile)=>virtual.has(key(name))?ts.createSourceFile(name,virtual.get(key(name)),version,true):get(name,version,onError,newFile);
 const program=ts.createProgram([mainPath],options,host);
 const errors=ts.getPreEmitDiagnostics(program).filter(item=>item.category===ts.DiagnosticCategory.Error);
 assert.deepEqual(errors.map(item=>ts.flattenDiagnosticMessageText(item.messageText,' ')),[]);
});

test('explicit upload rejection preserves both pending upload and local preparation component identity',async()=>{
 const h=harness({api:(path,init)=>{if(init?.method==='POST')throw Object.assign(new Error('PRIVATE'),{status:422});}});
 const uploadKey=h.upload().key,localKey=component(h.raw,'LocalPreparation').key;
 assert.equal(await h.actions.upload([new File(['a'],'mini.xml')],'direct'),false);h.render();
 assert.equal(h.upload().key,uploadKey);assert.equal(component(h.raw,'LocalPreparation').key,localKey);
 assert.equal(h.calls.filter(call=>call.init?.method==='POST').length,1);assert.equal(h.get('sourceUiEpoch'),0);
});
test('same-state explicit refresh clears consent and human review entered while its GET is pending',async()=>{
 const same=project({selected:sid(1),sourceHash:hash(1)}),waiting=deferred();
 const h=harness({detail:same,response:same,api:path=>path==='/projects/'+pid?waiting.promise:undefined});
 const pending=h.history().props.onRefreshProject();h.set('tab','Conversion runs');h.render();
 const duringKey=h.acceptance().key;
 for(let index=0;index<5;index++){walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox')[index].props.onChange({target:{checked:true}});h.render();}
 walk(h.tree,node=>node.type==='textarea')[0].props.onChange({target:{value:'While refresh pending'}});h.render();
 assert.deepEqual(h.get('consent'),[true,true,true]);
 waiting.resolve(same);assert.equal(await pending,true);h.render();
 assert.deepEqual(h.get('consent'),[false,false,false]);assert.notEqual(h.acceptance().key,duringKey);
 assert.ok(walk(h.tree,node=>node.type==='input'&&node.props.type==='checkbox').every(node=>node.props.checked===false));
 assert.equal(walk(h.tree,node=>node.type==='textarea')[0].props.value,'');
});
