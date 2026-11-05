// Canonical UI + real local API/SQLite. Synthetic sources, no conversion worker,
// Oracle tooling, model, OCI resource or business acceptance is exercised.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import net from 'node:net';

const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
const python=process.env.FOX_TEST_PYTHON;
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));

test('real local UI: partial preview, lost-response recovery, preserved originals and narrow layout',{
 skip:process.env.FOX_UI_BROWSER!=='1',timeout:120000,
},async()=>{
 assert.ok(python);assert.ok(process.env.FOX_TEST_NODE_MODULES);
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild');
 const runId=`draft-ui-${Date.now()}`;
 const out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR??path.join(root,'work'),runId);await mkdir(out,{recursive:true});
 const data=path.resolve(process.env.FOX_TEST_WORK_ROOT??out,runId,'data');
 const probe=net.createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));
 const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
 const origin=`http://127.0.0.1:${port}`;
 const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('FOX_')&&!key.startsWith('F2A_')));
 Object.assign(env,{PYTHONPATH:root,PYTHONDONTWRITEBYTECODE:'1',FOX_DATA_DIR:data,
  FOX_PUBLIC_ORIGIN:origin,FOX_ADMIN_USERNAME:'synthetic-demo-reviewer',FOX_CONVERSION_PROFILE:'native-project-v1',FOX_VERIFICATION_ENABLED:'0'});
 const code=`from pathlib import Path\nimport os\nfrom fox.app import create_app,password_hash\nimport uvicorn\nos.environ['FOX_PASSWORD_HASH']=password_hash('local-synthetic-test-only')\nuvicorn.run(create_app(Path(os.environ['FOX_DATA_DIR']),enable_worker=False),host='127.0.0.1',port=${port},access_log=False)`;
 const child=spawn(python,['-B','-c',code],{cwd:root,env,windowsHide:true,stdio:['ignore','pipe','pipe']});
 let log='',spawnError=null;child.stdout.on('data',data=>{log+=data;});child.stderr.on('data',data=>{log+=data;});child.on('error',error=>{spawnError=error;});
 let browser,context;const errors=[],requests=[];
 try{
  let ready=false;
  for(let i=0;i<150;i++){
   if(spawnError)throw spawnError;
   if(child.exitCode!==null)throw new Error('Local test server exited: '+log);
   try{ready=(await fetch(origin+'/api/health')).ok;}catch{}
   if(ready)break;await delay(100);
  }
  assert.ok(ready,'The isolated local test API must start.');
  const built=await build({entryPoints:[path.join(root,'web/main.tsx')],absWorkingDir:root,bundle:true,write:false,
   outfile:'preview.js',format:'iife',platform:'browser',define:{'process.env.NODE_ENV':'"production"'},logLevel:'silent'});
  const js=built.outputFiles.find(file=>file.path.endsWith('.js')).text,css=built.outputFiles.find(file=>file.path.endsWith('.css')).text;
  browser=await chromium.launch({channel:'msedge',headless:true});
  context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
  let loseResponse=true,failPreview=true;
  await context.route('**/*',async route=>{
   const request=route.request(),url=request.url();
   if(url===origin+'/')return route.fulfill({status:200,contentType:'text/html',body:'<div id="root"></div>'});
   if(url.startsWith(origin+'/api/')){
    requests.push({method:request.method(),path:new URL(url).pathname});
    if(request.method()==='GET'&&url.endsWith('/partial-draft')&&failPreview){
     failPreview=false;return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Synthetic preview unavailable'})});
    }
    if(request.method()==='POST'&&url.endsWith('/partial-draft')&&loseResponse){
     loseResponse=false;const response=await route.fetch();assert.equal(response.status(),201);return route.abort('connectionfailed');
    }
    return route.continue();
   }
   return route.abort();
  });
  const page=await context.newPage();page.setDefaultTimeout(15000);page.on('pageerror',error=>errors.push(error.message));
  await page.goto(origin+'/');await page.addStyleTag({content:css});await page.addScriptTag({content:js});
  await page.getByLabel('Username',{exact:true}).fill('synthetic-demo-reviewer');
  await page.getByLabel('Password',{exact:true}).fill('local-synthetic-test-only');
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await page.getByRole('button',{name:'New project',exact:true}).click();
  await page.getByLabel('Customer / organization',{exact:true}).fill('Synthetic QA only');
  await page.getByLabel('Project name',{exact:true}).fill('Order Entry demo');
  await page.getByRole('button',{name:'Create project',exact:true}).click();
  await page.getByRole('heading',{name:'Order Entry demo',exact:true}).waitFor();
  await page.getByLabel('Readable files, without a preparation manifest',{exact:true}).check();
  await page.getByLabel('Choose project source files',{exact:true}).setInputFiles([
   {name:'orders.xml',mimeType:'text/xml',buffer:Buffer.from('<FormModule Name="Order Entry"><Block Name="MAIN" QueryDataSourceName="ORDERS"><Item Name="ID"/><Item Name="TITLE" Prompt="Order title"/></Block><Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="ORDER_API.SUBMIT_ORDER();"/></FormModule>')},
   {name:'orders.sql',mimeType:'text/plain',buffer:Buffer.from('CREATE TABLE ORDERS (ID NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY, TITLE VARCHAR2(40) NOT NULL);')},
  ]);
  await page.getByRole('button',{name:'Upload and assess',exact:true}).click();
  await page.getByRole('button',{name:'Explore partial draft',exact:true}).waitFor();
  const original=await page.evaluate(async()=>{const projects=await(await fetch('/api/projects')).json();const pid=projects[0].id;return(await fetch('/api/projects/'+pid)).json();});
  await page.getByRole('button',{name:'Explore partial draft',exact:true}).click();
  await page.getByRole('button',{name:'Preview what can be generated',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'The draft preview could not be checked.'}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Create draft source version',exact:true}).count(),0,'Failed preview must not expose creation or imply conversion.');
  await page.screenshot({path:path.join(out,'00-preview-unavailable-desktop.png'),fullPage:true});
  await page.getByRole('button',{name:'Preview what can be generated',exact:true}).click();
  await page.getByRole('heading',{name:'Included in this draft',exact:true}).waitFor();
  assert.ok(await page.getByText('Order Entry',{exact:true}).count());
  await page.getByText('A referenced package source is missing: ORDER_API.',{exact:true}).waitFor();
  await page.getByText(/Provide the package specification .*ORDER_API, then reassess this project/).waitFor();
  assert.ok(await page.getByText('Not implemented in the draft; no working substitute is invented.',{exact:true}).count());
  await page.getByText(/This creates no APEX app yet\. Your originals remain saved/).waitFor();
  await page.screenshot({path:path.join(out,'01-draft-preview-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'No horizontal overflow on a narrow screen.');
  await page.screenshot({path:path.join(out,'02-draft-preview-mobile.png'),fullPage:true});
  const confirm=page.getByRole('button',{name:'Create draft source version',exact:true});assert.equal(await confirm.isEnabled(),false);
  await page.getByLabel('I accept the listed omissions. This is a partial demo, not a complete conversion.',{exact:true}).check();
  await confirm.evaluate(button=>{button.click();button.click();});
  await page.getByText('Check the existing result first.',{exact:true}).waitFor();
  await page.getByText(/No automatic retry was made/).waitFor();
  assert.equal(await confirm.isEnabled(),false,'Unknown outcome must pause branch creation.');
  assert.equal(await page.getByRole('button',{name:'Refresh draft preview',exact:true}).isEnabled(),false);
  const beforeStatus=requests.length;
  await page.screenshot({path:path.join(out,'02a-unknown-result-mobile.png'),fullPage:true});
  await page.getByRole('button',{name:'Check status',exact:true}).click();
  await page.getByRole('region',{name:'Partial draft scope',exact:true}).waitFor();
  assert.ok(requests.slice(beforeStatus).some(row=>row.method==='GET'&&row.path==='/api/projects/'+original.id),'Status recovery must read the existing project.');
  const derived=await page.evaluate(async pid=>(await fetch('/api/projects/'+pid)).json(),original.id);
  assert.notEqual(derived.inventory.source_hash,original.inventory.source_hash);
  assert.equal(derived.draft_scope.parent_source_hash,original.inventory.source_hash);
  assert.equal(derived.project_plan.can_generate,true);assert.equal(derived.runs.length,0);
  assert.equal(requests.filter(row=>row.method==='POST'&&row.path.endsWith('/partial-draft')).length,1,'Lost responses must not replay branch creation.');
  assert.equal(await page.evaluate(()=>Object.keys(JSON.parse(sessionStorage.getItem('fox.project-uncertainty.v1')).projects).length),0);
  const receipt=await page.evaluate(async({pid,hash})=>(await fetch('/api/projects/'+pid+'/draft-scope?source_hash='+hash)).json(),{pid:original.id,hash:derived.inventory.source_hash});
  assert.equal(receipt.draft_sha256,derived.draft_scope.draft_sha256);
  await page.setViewportSize({width:1440,height:1100});
  await page.screenshot({path:path.join(out,'03-saved-draft-desktop.png'),fullPage:true});
  await page.getByRole('button',{name:'Return to original sources',exact:true}).click();
  await page.getByRole('button',{name:'Explore partial draft',exact:true}).waitFor();
  const returned=await page.evaluate(async pid=>(await fetch('/api/projects/'+pid)).json(),original.id);
  assert.equal(returned.inventory.source_hash,original.inventory.source_hash);assert.equal(returned.draft_scope,null);
  assert.equal(returned.project_plan.can_generate,false);assert.equal(returned.runs.length,0);
  assert.match(original.inventory.selected_source_set_id,/^ss-[a-f0-9]{32}$/);
  assert.equal(returned.inventory.selected_source_set_id,original.inventory.selected_source_set_id,'Original saved source version must be returnable, not reconstructed.');
  // Another browser/tab changes the selected source after this preview. The
  // current UI must report the conflict, not branch against its stale consent.
  await page.getByRole('button',{name:'Explore partial draft',exact:true}).click();
  await page.getByRole('button',{name:'Preview what can be generated',exact:true}).click();
  await page.getByRole('heading',{name:'Included in this draft',exact:true}).waitFor();
  await page.getByLabel('I accept the listed omissions. This is a partial demo, not a complete conversion.',{exact:true}).check();
  const switched=await page.evaluate(async({pid,sid,expected})=>{
   const response=await fetch('/api/projects/'+pid+'/source-sets/'+sid+'/select',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({expected_current_source_set_id:expected})});
   return {status:response.status,body:await response.json()};
  },{pid:original.id,sid:derived.inventory.selected_source_set_id,expected:original.inventory.selected_source_set_id});
  assert.equal(switched.status,200);
  const sourcesBeforeStale=await page.evaluate(async pid=>(await fetch('/api/projects/'+pid+'/source-sets')).json(),original.id);
  await page.getByRole('button',{name:'Create draft source version',exact:true}).click();
  await page.getByText('The source version changed. Review a fresh draft preview.',{exact:true}).waitFor();
  const sourcesAfterStale=await page.evaluate(async pid=>(await fetch('/api/projects/'+pid+'/source-sets')).json(),original.id);
  assert.deepEqual(sourcesAfterStale,sourcesBeforeStale,'Stale consent must not create another source version.');
  await page.screenshot({path:path.join(out,'04-stale-preview-rejected-desktop.png'),fullPage:true});
  assert.equal(requests.some(row=>row.method==='POST'&&/\/runs(?:\/|$)/.test(row.path)),false);
  assert.deepEqual(errors,[]);
  await writeFile(path.join(out,'result.json'),JSON.stringify({passed:true,scope:'canonical UI and real local API only',
   preserved_originals:true,preview_failure_clear_and_nonmutating:true,unknown_result_reconciled_without_replay:true,rapid_double_submit_single_post:true,
   stale_preview_rejected_without_new_version:true,partial_scope_bound:true,narrow_layout_no_overflow:true,
   original_source_hash:original.inventory.source_hash,derived_source_hash:derived.inventory.source_hash,
   model_called:false,oracle_called:false,apex_generated:false,human_acceptance_recorded:false,requests},null,2));
  console.log('Partial-draft browser evidence: '+out);
 }finally{
  if(context)await context.close();if(browser)await browser.close();
  child.kill();await Promise.race([new Promise(resolve=>child.once('exit',resolve)),delay(5000)]);
  await writeFile(path.join(out,'server.log'),log);
 }
});
