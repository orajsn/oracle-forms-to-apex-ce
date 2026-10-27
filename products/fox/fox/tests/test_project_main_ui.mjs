// Actual canonical main mounted with synthetic in-browser API only.
// No service, database, model, real source upload, or live acceptance is used.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createHash} from 'node:crypto';

const foxRoot=fileURLToPath(new URL('../',import.meta.url));
const workspace=path.dirname(foxRoot),require=createRequire(import.meta.url);
const fixtureCode=String.raw`
import json,runpy
d=runpy.run_path('tests/test_project_conversion.py')
pair,assess,source,module,xml=[d[x] for x in ('pair','assess','source','module','xml')]
ready=pair()+pair('BETA','FOX_NATIVE_BETA')
changed=pair(prompt='Revised title')+pair('BETA','FOX_NATIVE_BETA')
mapped=pair('ORDERS','ORDERS')+pair('ORDER_ITEMS','ORDER_ITEMS')
human=pair();human[0]=source('alpha.xml',xml(module(extra='<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="UTIL.RUN();"/>')))
result={}
for key,files,pid,title in [('ready',ready,'a'*32,'Synthetic two form project'),('changed',changed,'a'*32,'Synthetic two form project'),('mapped',mapped,'a'*32,'Synthetic two form project'),('human',human,'b'*32,'Synthetic human decision project'),('empty',[],'c'*32,'Created synthetic project')]:
 result[key]={'plan':assess(files,project_id=pid,project_name=title),'files':[{'name':f['name'],'text':f['text']} for f in files]}
print(json.dumps(result))
`;

test('canonical main: source-bound multi-project workflow and uncertain-write recovery',{
 skip:process.env.FOX_UI_BROWSER!=='1',timeout:240000,
},async()=>{
 const packageRoot=process.env.FOX_TEST_NODE_MODULES;
 assert.ok(packageRoot,'Use discovered bundled Playwright packages; this test installs nothing.');
 const runtimeRequire=createRequire(path.join(packageRoot,'../package.json'));
 const {chromium}=runtimeRequire('playwright'),{build}=require('esbuild');
 const python=process.env.FOX_TEST_PYTHON??path.join(foxRoot,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
 const fixtures=JSON.parse(execFileSync(python,['-B','-c',fixtureCode],{cwd:foxRoot,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'},encoding:'utf8',timeout:15000,maxBuffer:2_000_000}));
 assert.equal(fixtures.mapped.plan.state,'READY','The real producer must support project-isolated ORDERS storage before the UI proof runs.');
 const orders=fixtures.mapped.plan.forms.find(form=>form.table_name==='ORDERS'),ordersMapping=orders?.storage_mapping;
 assert.equal(ordersMapping?.scope,'fox-project-storage-v1');assert.equal(ordersMapping.source_table_name,'ORDERS');
 assert.equal(ordersMapping.target_table_name,'FOX_NATIVE_'+ordersMapping.identity_sha256.slice(0,19).toUpperCase());
 const out=path.resolve(workspace,process.env.FOX_UI_ARTIFACT_DIR??`work/project-main-ui-${Date.now()}`);
 assert.ok(out.startsWith(path.join(workspace,'work')+path.sep));await mkdir(out);
 const uiSourceNames=['main.tsx','projectConversion.ts','ProjectWorkbench.tsx'];
 const uiSourcesAtBuild=Object.fromEntries(await Promise.all(uiSourceNames.map(async name=>[name,await readFile(path.join(foxRoot,'web',name),'utf8')])));
 const mainAtBuild=uiSourcesAtBuild['main.tsx'];
 const built=await build({entryPoints:[path.join(foxRoot,'web/main.tsx')],absWorkingDir:foxRoot,bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',define:{'process.env.NODE_ENV':'"production"'},logLevel:'silent'});
 const js=built.outputFiles.find(file=>file.path.endsWith('.js')).text,css=built.outputFiles.find(file=>file.path.endsWith('.css')).text;
 const browser=await chromium.launch({channel:'msedge',headless:true});let context,page;const errors=[];
 try{
  context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
  await context.setOffline(true);await context.route('**/*',route=>route.request().url()==='http://fox.synthetic.test/'?route.fulfill({status:200,contentType:'text/html',body:'<div id="root"></div>'}):route.abort());page=await context.newPage();
  page.setDefaultTimeout(10000);page.on('pageerror',error=>errors.push(error.message));
  await page.goto('http://fox.synthetic.test/');
  const installMock=async retained=>page.evaluate(({fixtures,retained})=>{
   const clone=value=>JSON.parse(JSON.stringify(value)),sid=n=>'ss-'+String(n).repeat(32);
   const pid='a'.repeat(32),other='b'.repeat(32),created='c'.repeat(32);
   const state=retained??{events:[],current:'ready',planOverride:null,projects:[pid,other],showCreated:false,createdRecord:null,visibleRun:false,pendingRun:null,run:null,acceptMode:'unknown',username:'Synthetic UI QA',loggedIn:true};
   window.__fixture=state;
   const json=(value,status=200)=>Promise.resolve(new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json'}}));
   const sourceId=key=>key==='changed'?sid(2):key==='mapped'?sid(3):key==='empty'?null:sid(1);
   const planFor=id=>id===pid?(state.planOverride??fixtures[state.current].plan):id===other?fixtures.human.plan:fixtures.empty.plan;
   const runList=id=>id===pid&&state.visibleRun?[state.run??state.pendingRun]:[];
   const summary=(id,key)=>{const plan=fixtures[key].plan;return {id:sourceId(key),source_hash:plan.source_hash,file_count:plan.source_files.length,source_bytes:plan.source_files.reduce((n,f)=>n+f.bytes,0),created:key==='changed'?2000:1000,origin:'upload',is_selected:sourceId(key)===sourceId(id===pid?state.current:'human'),run_ids:runList(id).filter(run=>run.source_hash===plan.source_hash).map(run=>run.id)};};
   const assessment=metadata=>({source_hash:metadata.source_hash,conversion_profile:'native-project-v1',source_checks_passed:true,file_count:metadata.file_count,source_bytes:metadata.source_bytes,conversion_source_bytes:metadata.source_bytes,max_conversion_bytes:300000,max_conversion_files:50,missing_dependency_count:0,assessment_finding_count:0,conversion_blocker_count:0,blocker_codes:[],native_state:null});
   const detail=id=>{const plan=planFor(id),key=id===pid?state.current:id===other?'human':'empty';return {id,name:plan.project_name,customer:'Synthetic browser QA only',description:'No real conversion or human business acceptance.',...(id===created?state.createdRecord:{}),file_count:plan.source_files.length,run_count:runList(id).length,
    inventory:{selected_source_set_id:sourceId(key),source_hash:plan.source_hash,files:plan.source_files.map(f=>({file:f.name,bytes:f.bytes,sha256:f.sha256,blocks:[]})),dependencies:[],issues:[],missing_count:0,scope_note:'Synthetic API fixture.',source_bytes:plan.source_files.reduce((n,f)=>n+f.bytes,0),conversion_source_bytes:plan.source_files.reduce((n,f)=>n+f.bytes,0),max_conversion_bytes:300000,forms_source_files:plan.source_files.filter(f=>f.kind==='FORM_XML').map(f=>f.name),conversion_eligible:plan.can_generate,conversion_blockers:[],conversion_profile:'native-project-v1',source_preparation:{mode:'DIRECT_READABLE',matches_current_source:false,scope:'Synthetic source metadata only.'}},
    runs:clone(runList(id)),project_plan:clone(plan),project_plan_error:null,project_capabilities:{upload:{enabled:true},process:{enabled:true}},processing_notice:'Synthetic UI check only. No model, source transmission, database or live acceptance.'};};
   window.fetch=async(input,init={})=>{
    const url=String(input),method=init.method??'GET';
    const body=typeof init.body==='string'?JSON.parse(init.body):null;
    state.events.push({url,method,body});
    if(url==='/api/session')return state.loggedIn?json({username:state.username,conversion_configured:true,conversion_profile:'native-project-v1',configuration_scope:'Synthetic fixture',configuration_checks:[]}):json({detail:'Synthetic signed-out session'},401);
    if(url==='/api/logout'&&method==='POST'){state.loggedIn=false;return json({ok:true});}
    if(url==='/api/login'&&method==='POST'){state.loggedIn=true;state.username=body.username;return json({ok:true});}
    if(url==='/api/projects'&&method==='GET')return json(state.projects.filter(id=>id!==created||state.showCreated).map(id=>detail(id)));
    if(url==='/api/projects'&&method==='POST'){state.projects.push(created);state.createdRecord=clone(body);throw new Error('Synthetic project creation response loss');}
    for(const id of state.projects){
     const base='/api/projects/'+id;
     if(url===base)return json(detail(id));
     if(url===base+'/source-sets')return json({selected_source_set_id:detail(id).inventory.selected_source_set_id,source_sets:id===created?[]:(id===pid?(state.current==='mapped'?['mapped','changed','ready']:['changed','ready']):['human']).map(key=>summary(id,key)),next_cursor:null});
     if(url===base+'/source-sets/'+sid(1)+'/select'&&method==='POST'){
      if(body.expected_current_source_set_id!==detail(id).inventory.selected_source_set_id)return json({detail:'Fixture CAS rejected'},409);
      state.current='ready';const metadata=summary(id,'ready');return json({selected_source_set_id:sid(1),source_set:metadata,assessment_summary:assessment(metadata),selection_changed:true});
     }
     if(url===base+'/sources'&&method==='POST'){
      state.events.at(-1).files=init.body.getAll('files').map(file=>file.name);
      state.events.at(-1).expected=init.body.get('expected_current_source_set_id');state.current='changed';return json(detail(id).inventory);
     }
     if(url===base+'/runs'&&method==='POST'){
      const plan=planFor(id);state.pendingRun={id:'fox-synthetic-main-run',project_id:id,source_hash:plan.source_hash,state:'QUEUED',message:'Synthetic saved run. No processing was executed.',artifact_generated:false,technical_verified:false,human_accepted:false,downloadable:false,preview_available:false,review_available:false,steps:[{id:'queue',label:'Saved for conversion',state:'complete'}],forms:plan.forms.map(form=>({module_id:form.module_id,state:'queued'})),recovery:{kind:'check_status',enabled:true,safety:'read_only'}};
      throw new Error('Synthetic response loss after dispatch');
     }
     if(url===base+'/runs/fox-synthetic-main-run/accept'&&method==='POST'){
      if(state.acceptMode==='unknown')throw new Error('Synthetic acceptance response loss');
      state.run={...state.run,state:'ACCEPTED',human_accepted:true,downloadable:true,review_available:false};return json({state:'ACCEPTED'});
     }
     if(url===base+'/runs/fox-synthetic-main-run/evidence')return json({prototype_scope:'Synthetic recorded evidence only.',application_url:'https://conflicting-evidence.synthetic.test/unapproved-preview',reviewer:{verdict:'APPROVED',notes:['Synthetic automated check, not business acceptance.']},remediation_items:[]});
    }
    throw new Error('Unexpected synthetic request: '+method+' '+url);
   };
  },{fixtures,retained});
  const mount=async retained=>{await installMock(retained);await page.addStyleTag({content:css});await page.addScriptTag({content:js});};
  const reload=async(options={})=>{const retained=await page.evaluate(()=>window.__fixture);await page.reload({waitUntil:'domcontentloaded'});if(options.storageUnavailable)await page.evaluate(()=>{const get=Storage.prototype.getItem,set=Storage.prototype.setItem;Storage.prototype.getItem=function(key){if(key==='fox.project-uncertainty.v1')throw new DOMException('Synthetic storage unavailable','SecurityError');return get.call(this,key);};Storage.prototype.setItem=function(key,value){if(key==='fox.project-uncertainty.v1')throw new DOMException('Synthetic storage unavailable','SecurityError');return set.call(this,key,value);};});await mount(retained);};
  await mount();
  await page.getByRole('heading',{name:'Your projects',exact:true}).waitFor();
  await page.screenshot({path:path.join(out,'desktop-project-dashboard.png')});
  await page.getByRole('button',{name:'New project',exact:true}).click();
  assert.equal(await page.getByLabel('Project name',{exact:true}).getAttribute('maxlength'),'80');
  await page.getByLabel('Customer / organization',{exact:true}).fill('Synthetic browser QA only');
  await page.getByLabel('Project name',{exact:true}).fill('Created synthetic project');
  await page.getByRole('button',{name:'Create project',exact:true}).click();
  await page.getByRole('heading',{name:'Check the saved project first',exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'New project',exact:true}).isDisabled(),true);
  assert.equal(await page.getByRole('button',{name:'Create project',exact:true}).isDisabled(),true);
  await reload();
  await page.getByRole('heading',{name:'Check the saved project first',exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'New project',exact:true}).isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.url==='/api/projects'&&event.method==='POST').length),1);
  await page.getByRole('button',{name:'Check project creation status',exact:true}).click();
  assert.equal(await page.getByRole('button',{name:'New project',exact:true}).isDisabled(),true);
  await page.evaluate(()=>{window.__fixture.showCreated=true;});
  await page.getByRole('button',{name:'Check project creation status',exact:true}).click();
  await page.getByRole('heading',{name:'Created synthetic project',exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.url==='/api/projects'&&event.method==='POST').length),1);
  await page.getByRole('button',{name:'All projects',exact:true}).click();
  assert.equal(await page.getByRole('heading',{name:'3 projects',exact:true}).count(),1);
  await page.getByRole('button',{name:/Synthetic human decision project/}).click();
  await page.getByRole('button',{name:'3 Resolve',exact:true}).click();
  await page.getByText(/FOX will not guess the intended business behavior/).waitFor();
  await page.screenshot({path:path.join(out,'desktop-human-decision.png')});
  await page.getByRole('button',{name:'4 Convert',exact:true}).click();
  assert.equal(await page.getByRole('button',{name:'Generate APEX application',exact:true}).isDisabled(),true);
  await page.getByRole('button',{name:'All projects',exact:true}).click();
  await page.getByRole('button',{name:/Synthetic two form project/}).click();
  await page.getByRole('heading',{name:'Review every form',exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:/ALPHA alpha.xml/}).count(),1);assert.equal(await page.getByRole('button',{name:/BETA beta.xml/}).count(),1);
  await page.screenshot({path:path.join(out,'desktop-two-forms.png')});
  await page.getByRole('button',{name:'1 Upload',exact:true}).click();
  await page.getByRole('radio',{name:'Readable files, without a preparation manifest'}).check();
  await page.getByLabel('Choose project source files').setInputFiles({name:'raw.fmb',mimeType:'application/octet-stream',buffer:Buffer.from('synthetic binary')});
  await page.getByText(/These are raw Forms binaries/).waitFor();
  assert.equal(await page.getByRole('button',{name:'Upload and assess',exact:true}).isDisabled(),true);
  await page.getByLabel('Choose project source files').setInputFiles(fixtures.changed.files.map(file=>({name:file.name,mimeType:'text/plain',buffer:Buffer.from(file.text)})));
  await page.getByRole('button',{name:'Upload and assess',exact:true}).click();
  await page.getByRole('heading',{name:'Review every form',exact:true}).waitFor();
  const upload=await page.evaluate(()=>window.__fixture.events.find(event=>event.url.endsWith('/sources')&&event.method==='POST'));
  assert.deepEqual(upload.files.sort(),fixtures.changed.files.map(file=>file.name).sort());assert.equal(upload.expected,'ss-'+'1'.repeat(32));
  await page.getByRole('button',{name:'4 Convert',exact:true}).click();
  const confirmations=()=>page.getByRole('group',{name:'Confirm before processing this source version'}).getByRole('checkbox');
  for(let i=0;i<3;i++)await confirmations().nth(i).check();
  await page.getByText('Source history and preparation receipt',{exact:true}).click();
  await page.getByRole('article',{name:'Source version ss-'+'1'.repeat(32)}).getByRole('button',{name:'Use this version',exact:true}).click();
  await page.getByRole('heading',{name:'Review every form',exact:true}).waitFor();
  await page.getByRole('button',{name:'4 Convert',exact:true}).click();
  assert.equal(await confirmations().evaluateAll(inputs=>inputs.filter(input=>input.checked).length),0);
  for(let i=0;i<3;i++)await confirmations().nth(i).check();
  const generate=page.getByRole('button',{name:'Generate APEX application',exact:true});
  await generate.click();await page.getByText('Check the existing result first.',{exact:true}).waitFor();
  const submitted=await page.evaluate(()=>window.__fixture.events.filter(event=>event.url.endsWith('/runs')&&event.method==='POST'));
  assert.equal(submitted.length,1);assert.deepEqual(submitted[0].body,{source_hash:fixtures.ready.plan.source_hash,expected_current_source_set_id:'ss-'+'1'.repeat(32),plan_sha256:fixtures.ready.plan.plan_sha256,approved_redacted_source:true,approved_external_ai:true,approved_prototype_scope:true});
  await page.getByRole('button',{name:'Check status',exact:true}).click();assert.equal(await generate.isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST'&&event.url.endsWith('/runs')).length),1);
  await page.screenshot({path:path.join(out,'desktop-unconfirmed-write.png')});
  await page.getByRole('button',{name:'All projects',exact:true}).click();await page.getByRole('button',{name:/Synthetic two form project/}).click();
  await page.getByText('Check the existing result first.',{exact:true}).waitFor();
  await reload();await page.getByRole('heading',{name:'Your projects',exact:true}).waitFor();await page.getByRole('button',{name:/Synthetic two form project/}).click();
  await page.getByText('Check the existing result first.',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Check status',exact:true}).click();
  await page.getByText('Check the existing result first.',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST'&&event.url.endsWith('/runs')).length),1);
  await page.evaluate(()=>{window.__fixture.visibleRun=true;});await page.getByRole('button',{name:'Check status',exact:true}).click();
  await page.getByText('Check the existing result first.',{exact:true}).waitFor({state:'hidden'});
  await page.getByRole('button',{name:'4 Convert',exact:true}).click();await page.getByRole('heading',{name:'Waiting to start',exact:true}).waitFor();
  assert.equal(await generate.isDisabled(),true);
  await page.evaluate(()=>{const state=window.__fixture;state.run={...state.pendingRun,state:'VERIFIED',message:'Synthetic verified projection only.',artifact_generated:true,technical_verified:true,human_accepted:false,preview_available:true,review_available:true,application_url:'https://authorized-run.synthetic.test/verified-preview'};});
  await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByRole('button',{name:'5 Output',exact:true}).click();
  await page.getByRole('heading',{name:'Final human review',exact:true}).waitFor();
  const accept=page.getByRole('button',{name:'Accept tested package',exact:true});
  const download=page.getByRole('button',{name:'Download APEX package',exact:true});assert.equal(await download.isDisabled(),true);
  await page.getByLabel('I tested the business flow.',{exact:true}).check();await page.getByLabel('I reviewed the unresolved remediation.',{exact:true}).check();
  const noteInput=page.locator('section[aria-label="Human acceptance"] textarea');
  const notes='Synthetic automated UI QA only; this is not live business acceptance.';await noteInput.fill(notes);
  await accept.evaluate(button=>{button.click();button.click();});
  await page.getByText('Check the existing result first.',{exact:true}).waitFor();assert.equal(await accept.isDisabled(),true);assert.equal(await noteInput.inputValue(),notes);
  const acceptance=await page.evaluate(()=>window.__fixture.events.filter(event=>event.url.endsWith('/accept')));
  assert.equal(acceptance.length,1);assert.deepEqual(acceptance[0].body,{source_hash:fixtures.ready.plan.source_hash,business_flow_tested:true,remediation_reviewed:true,notes});
  await page.getByRole('button',{name:'Check status',exact:true}).click();assert.equal(await accept.isDisabled(),true);
  assert.equal(await page.evaluate(notes=>Object.values(sessionStorage).some(value=>String(value).includes(notes)),notes),false);
  await page.screenshot({path:path.join(out,'desktop-paused-human-review.png')});
  await reload();await page.getByRole('heading',{name:'Your projects',exact:true}).waitFor();await page.getByRole('button',{name:/Synthetic two form project/}).click();await page.getByRole('button',{name:'5 Output',exact:true}).click();
  await page.getByText('Check the existing result first.',{exact:true}).waitFor();assert.equal(await accept.isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.url.endsWith('/accept')).length),1);
  await page.evaluate(()=>{const state=window.__fixture;state.run={...state.run,state:'ACCEPTED',human_accepted:true,downloadable:true,review_available:false};});
  await page.getByRole('button',{name:'Check status',exact:true}).click();await page.getByText('Human review recorded',{exact:true}).first().waitFor();assert.equal(await download.isEnabled(),true);
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.url.endsWith('/accept')).length),1);
  await page.getByRole('button',{name:'View mapping and remediation',exact:true}).click();await page.getByRole('heading',{name:'Mapping and remediation',exact:true}).waitFor();
  await page.getByText('Synthetic recorded evidence only.',{exact:true}).waitFor();
  assert.equal(await page.getByRole('link',{name:'Open APEX application',exact:true}).getAttribute('href'),'https://authorized-run.synthetic.test/verified-preview');
  assert.equal(await page.locator('a[href*="conflicting-evidence.synthetic.test"]').count(),0);
  await page.setViewportSize({width:390,height:844});await page.getByRole('button',{name:'2 Review forms',exact:true}).click();
  await page.getByRole('heading',{name:'Review every form',exact:true}).evaluate(element=>element.scrollIntoView({block:'start'}));await page.screenshot({path:path.join(out,'mobile-two-forms.png')});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.setViewportSize({width:1440,height:1100});
  const postsBeforeMapping=await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST').length);
  await page.evaluate(()=>{const state=window.__fixture;state.current='mapped';state.planOverride=null;state.visibleRun=false;});
  await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByRole('heading',{name:'Review every form',exact:true}).waitFor();
  await page.getByRole('button',{name:/^ORDERS orders.xml/}).click();
  const orderDetails=page.getByRole('region',{name:'Details for ORDERS',exact:true});
  await orderDetails.getByText('ORDERS',{exact:true}).last().waitFor();
  await orderDetails.getByText(ordersMapping.target_table_name,{exact:true}).first().waitFor();
  const mappingRegion=orderDetails.getByRole('region',{name:'Planned prototype table',exact:true});
  await mappingRegion.getByRole('heading',{name:'Source and prototype tables',exact:true}).waitFor();
  await mappingRegion.getByText('Your original files stay unchanged. No production data is copied.',{exact:true}).waitFor();
  await mappingRegion.getByText('Changing the table structure creates a separate empty prototype table. This is not a data migration.',{exact:true}).waitFor();
  assert.equal(await orderDetails.locator('input,textarea,select').count(),0,'Storage mapping is an inspect-only explanation, never a target-name editor.');
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST').length),postsBeforeMapping);
  await mappingRegion.evaluate(element=>element.scrollIntoView({block:'center'}));
  await page.screenshot({path:path.join(out,'desktop-orders-storage-mapping.png')});
  await page.setViewportSize({width:390,height:844});await mappingRegion.evaluate(element=>element.scrollIntoView({block:'start'}));
  await page.screenshot({path:path.join(out,'mobile-orders-storage-mapping.png')});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'Long generated table names must not overflow the mobile workbench.');
  await page.setViewportSize({width:1440,height:1100});
  const invalidMappings=[
   ['malformed target',plan=>{plan.forms[0].storage_mapping.target_table_name='WRONG_TARGET';}],
   ['cross-project mapping',plan=>{plan.forms[0].storage_mapping.project_id='b'.repeat(32);}],
   ['mixed mapped and unmapped forms',plan=>{delete plan.forms[0].storage_mapping;}],
   ['all storage mappings stripped',plan=>{for(const form of plan.forms)delete form.storage_mapping;}],
   ['colliding generated target',plan=>{plan.forms[1].storage_mapping.identity_sha256=plan.forms[0].storage_mapping.identity_sha256;plan.forms[1].storage_mapping.target_table_name=plan.forms[0].storage_mapping.target_table_name;}],
  ];
  for(const [label,mutate]of invalidMappings){
   const malformed=structuredClone(fixtures.mapped.plan);mutate(malformed);
   await page.evaluate(plan=>{window.__fixture.planOverride=plan;},malformed);
   await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByRole('button',{name:'4 Convert',exact:true}).click();
   await page.getByText(/The project assessment is incomplete or out of date/).first().waitFor();
   assert.equal(await generate.isDisabled(),true,`${label} must not allow generation.`);
   assert.equal(await page.getByRole('region',{name:'Details for ORDERS',exact:true}).count(),0,`${label} must not present an apparently trusted form mapping.`);
   assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST').length),postsBeforeMapping,`${label} must not send a mutation.`);
  }
  await page.screenshot({path:path.join(out,'desktop-invalid-storage-mapping.png')});
  await page.evaluate(()=>{const state=window.__fixture;state.current='changed';state.planOverride=null;state.visibleRun=false;state.run=null;state.pendingRun=null;});
  await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByRole('button',{name:'4 Convert',exact:true}).click();
  for(let i=0;i<3;i++)await confirmations().nth(i).check();await generate.click();await page.getByText('Check the existing result first.',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST'&&event.url.endsWith('/runs')).length),2);
  await page.evaluate(()=>{window.__fixture.username='Other synthetic owner';});await reload();
  await page.getByRole('heading',{name:'Your projects',exact:true}).waitFor();await page.getByRole('button',{name:/Synthetic two form project/}).click();
  assert.equal(await page.getByText('Check the existing result first.',{exact:true}).count(),0);
  await page.getByRole('button',{name:'4 Convert',exact:true}).click();assert.equal(await confirmations().evaluateAll(inputs=>inputs.filter(input=>input.checked).length),0);
  for(let i=0;i<3;i++)await confirmations().nth(i).check();assert.equal(await generate.isEnabled(),true);
  await generate.click();await page.getByText('Check the existing result first.',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST'&&event.url.endsWith('/runs')).length),3);
  await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('button',{name:'Sign in',exact:true}).waitFor();
  await page.getByLabel('Username',{exact:true}).fill('Other synthetic owner');await page.getByLabel('Password',{exact:true}).fill('synthetic-local-fixture-only');
  await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('heading',{name:'Your projects',exact:true}).waitFor();await page.getByRole('button',{name:/Synthetic two form project/}).click();
  assert.equal(await page.getByText('Check the existing result first.',{exact:true}).count(),0);
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST'&&event.url.endsWith('/runs')).length),3);
  await page.evaluate(()=>sessionStorage.setItem('fox.project-uncertainty.v1','{synthetic-corrupt-storage'));
  await reload();await page.getByText(/Saved operation safety state could not be verified/).first().waitFor();
  assert.equal(await page.getByRole('button',{name:'New project',exact:true}).isDisabled(),true);
  const writesBeforeStorageCheck=await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST').length);
  await page.getByRole('button',{name:'Check saved project status',exact:true}).click();
  await page.getByText(/Saved operation safety state could not be verified/).first().waitFor();assert.equal(await page.getByRole('button',{name:'New project',exact:true}).isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST').length),writesBeforeStorageCheck);
  await page.screenshot({path:path.join(out,'desktop-corrupt-storage-guard.png')});
  await reload({storageUnavailable:true});await page.getByText(/Browser session storage is unavailable/).first().waitFor();
  assert.equal(await page.getByRole('button',{name:'New project',exact:true}).isDisabled(),true);
  await page.getByRole('button',{name:'Check saved project status',exact:true}).click();await page.getByText(/Browser session storage is unavailable/).first().waitFor();
  assert.equal(await page.getByRole('button',{name:'New project',exact:true}).isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__fixture.events.filter(event=>event.method==='POST').length),writesBeforeStorageCheck);
  assert.deepEqual(errors,[]);
  const main=await readFile(path.join(foxRoot,'web/main.tsx'),'utf8');
  const sourceHashes=Object.fromEntries(uiSourceNames.map(name=>[name,createHash('sha256').update(uiSourcesAtBuild[name]).digest('hex')]));
  const sourceChanged=Object.fromEntries(await Promise.all(uiSourceNames.map(async name=>[name,(await readFile(path.join(foxRoot,'web',name),'utf8'))!==uiSourcesAtBuild[name]])));
  assert.deepEqual(sourceChanged,Object.fromEntries(uiSourceNames.map(name=>[name,false])),'All UI source files must stay unchanged throughout the browser proof.');
  await writeFile(path.join(out,'result.json'),JSON.stringify({scope:'canonical-main-project-ui-synthetic-proof-v1',passed:true,canonical_main_sha256:createHash('sha256').update(mainAtBuild).digest('hex'),canonical_main_changed_during_test:main!==mainAtBuild,source_sha256:sourceHashes,source_changed_during_test:sourceChanged,built_javascript_sha256:createHash('sha256').update(js).digest('hex'),browser:await browser.version(),page_errors:errors,storage_mapping:ordersMapping,scenarios:['dashboard create and switch projects','uncertain creation survives real reload without duplicate POST and reconciles exact saved project','two-form ready plan','human decision blocker','raw binary refused','exact readable source upload and CAS','history selection clears consent','source-plan-bound generation','unconfirmed generation cannot retry across navigation or real browser reload','read-only reconciliation finds existing saved run','public projection controls verification and download','shared acceptance guard blocks duplicate submit and preserves in-document notes','human notes are not persisted in sessionStorage','uncertain acceptance survives reload and only clears with accepted public evidence','pending state is not reused for another authenticated owner','logout clears pending state before same-owner login','corrupt storage stays blocked after manual read-only check','unavailable storage stays blocked after manual read-only check','mapping evidence','preview URL only follows authorized run projection, never conflicting raw evidence','390px no horizontal overflow','real ORDERS storage mapping keeps source name and explains generated target read-only','malformed target mapping fails closed without POST','cross-project mapping fails closed without POST','mixed mapped and unmapped forms fail closed without POST','all mappings stripped from ordinary source tables fail closed without POST','colliding generated targets fail closed without POST'],backend_simulated:true,oracle_executed:false,model_executed:false,live_acceptance_recorded:false},null,2));
 }catch(error){await page?.screenshot({path:path.join(out,'failure.png')}).catch(()=>{});await writeFile(path.join(out,'failure.json'),JSON.stringify({scope:'canonical-main-project-ui-synthetic-proof-v1',passed:false,message:String(error?.message??error).slice(0,4000),page_errors:errors,backend_simulated:true,oracle_executed:false,model_executed:false,live_acceptance_recorded:false},null,2));throw error;}
 finally{await context?.close();await browser.close();}
});
