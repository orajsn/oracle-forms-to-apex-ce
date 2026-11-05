// Real local API + package readers; synthetic Oracle/OPAF transport fixture only.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=fileURLToPath(new URL('../',import.meta.url)),product=path.dirname(root);

test('saved output survives reopen and renamed sources, with read-only status and no replay',{
 skip:process.env.FOX_UI_BROWSER!=='1',timeout:90000,
},async()=>{
 const packages=process.env.FOX_TEST_NODE_MODULES;assert.ok(packages);
 const {chromium}=createRequire(path.join(packages,'../package.json'))('playwright');
 const {build}=createRequire(import.meta.url)('esbuild');
 const built=await build({entryPoints:[path.join(root,'web/main.tsx')],absWorkingDir:root,bundle:true,write:false,
  outfile:'preview.js',format:'iife',platform:'browser',define:{'process.env.NODE_ENV':'"production"'},logLevel:'silent'});
 const js=built.outputFiles.find(file=>file.path.endsWith('.js')).text,css=built.outputFiles.find(file=>file.path.endsWith('.css')).text;
 const python=process.env.FOX_TEST_PYTHON??path.join(root,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
 const out=path.join(product,'work',process.env.FOX_RUN_HISTORY_ARTIFACT??`run-history-${Date.now()}`);
 assert.ok(out.startsWith(path.join(product,'work')+path.sep));await mkdir(path.dirname(out),{recursive:true});await mkdir(out);
 const child=spawn(python,['-B','tests/serve_run_history_test.py','--root',out],{cwd:root,stdio:['pipe','pipe','pipe'],windowsHide:true});
 let errors='';child.stderr.on('data',v=>{errors+=v.toString();});
 let browser,context,page;const pageErrors=[],writes=[];
 try{
  const input=createInterface({input:child.stdout});
  const first=await Promise.race([once(input,'line').then(([v])=>v),once(child,'exit').then(()=>{throw Error('Fixture exited before readiness: '+errors);}),new Promise((_,reject)=>setTimeout(()=>reject(Error('Fixture readiness timed out: '+errors)),20000).unref())]);
  const fixture=JSON.parse(first),{origin}=fixture;assert.match(origin,/^http:\/\/127\.0\.0\.1:\d+$/);
  let healthy=false;
  for(let n=0;n<100;n++){
   if(child.exitCode!==null||child.signalCode!==null)throw Error('Fixture exited before HTTP readiness: '+errors);
   try{if((await fetch(origin+'/api/health',{signal:AbortSignal.timeout(1000)})).ok){healthy=true;break;}}catch{}
   await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.ok(healthy,'Fixture never reached actual HTTP health readiness: '+errors);
  browser=await chromium.launch({channel:'msedge',headless:true});context=await browser.newContext({viewport:{width:1440,height:1100}});page=await context.newPage();page.setDefaultTimeout(12000);
  // Test the current source, not an optional/stale ignored dist build. Keeping
  // assets on routes also exercises a true reload against the same real API.
  await context.route('**/*',route=>{const url=route.request().url();
   if(url===origin+'/')return route.fulfill({status:200,contentType:'text/html',body:'<div id="root"></div><link rel="stylesheet" href="/__test-ui.css"><script src="/__test-ui.js"></script>'});
   if(url===origin+'/__test-ui.js')return route.fulfill({status:200,contentType:'text/javascript',body:js});
   if(url===origin+'/__test-ui.css')return route.fulfill({status:200,contentType:'text/css',body:css});
   return url.startsWith(origin+'/api/')?route.continue():route.abort();
  });
  page.on('pageerror',e=>pageErrors.push(e.message));page.on('request',request=>{if(request.method()!=='GET')writes.push({method:request.method(),url:request.url()});});
  await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('synthetic-owner');await page.getByLabel('Password',{exact:true}).fill('synthetic-history-only');await page.getByRole('button',{name:'Sign in',exact:true}).click();
  const openOutput=async()=>{await page.getByRole('button',{name:'5 Output',exact:true}).click();const card=page.getByRole('article',{name:'Output for run '+fixture.run_id,exact:true});await card.getByText('Saved progress and form responses',{exact:true}).click();return card;};
  await page.getByRole('heading',{name:fixture.project_name,exact:true}).click();let card=await openOutput();
  for(const name of fixture.form_names)await card.getByText(name,{exact:true}).waitFor();
  assert.equal(await card.getByRole('button',{name:'Download APEX package',exact:true}).isDisabled(),true);
  await card.getByRole('button',{name:'Check run status',exact:true}).click();
  for(const name of fixture.form_names)await card.getByText(name,{exact:true}).waitFor();
  await card.screenshot({path:path.join(out,'output-desktop.png')});await page.setViewportSize({width:390,height:844});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));await card.screenshot({path:path.join(out,'output-mobile.png')});
  await page.reload();await page.getByRole('heading',{name:fixture.project_name,exact:true}).click();card=await openOutput();
  for(const name of fixture.form_names)await card.getByText(name,{exact:true}).waitFor();
  await page.getByRole('button',{name:'1 Upload',exact:true}).click();await page.getByLabel('Readable files, without a preparation manifest',{exact:true}).check();
  await page.getByLabel('Choose project source files',{exact:true}).setInputFiles([{name:fixture.replacement.name,mimeType:'text/plain',buffer:Buffer.from(fixture.replacement.text)}]);
  await page.getByRole('button',{name:'Upload and assess',exact:true}).click();await page.getByRole('heading',{name:'Review every form',exact:true}).waitFor();
  card=await openOutput();await card.getByText('RENAMED_AFTER_RUN',{exact:true}).waitFor({state:'hidden'});
  for(const name of fixture.form_names)await card.getByText(name,{exact:true}).waitFor();
  assert.match(await card.textContent(),/Earlier source version/);assert.equal(await card.getByRole('button',{name:'Download APEX package',exact:true}).isDisabled(),true);
  const detail=await (await context.request.get(origin+'/api/projects/'+fixture.project_id)).json();
  assert.ok(detail.project_plan.forms.some(f=>f.form_name==='RENAMED_AFTER_RUN'));assert.equal(detail.runs.length,1);
  assert.equal(detail.runs[0].technical_verified,false);assert.equal(detail.runs[0].human_accepted,false);
  assert.notEqual(detail.inventory.source_hash,detail.runs[0].source_hash);assert.equal(detail.runs[0].artifact_generated,true);
  assert.deepEqual(pageErrors,[]);assert.ok(writes.every(r=>r.url.endsWith('/api/login')||r.url.endsWith('/sources')),'History must never submit conversion or acceptance.');
  await card.screenshot({path:path.join(out,'historical-mobile.png')});
  await writeFile(path.join(out,'result.json'),JSON.stringify({passed:true,actual_local_api:true,actual_local_sqlite:true,
   real_package_and_status_readers:true,synthetic_oracle_opaf_transports:true,oracle_executed:false,model_executed:false,
   human_acceptance_recorded:false,reopened_history:true,original_labels_retained:true,conversion_or_import_replayed:false},null,2));
 }catch(error){await page?.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});
  await writeFile(path.join(out,'failure.json'),JSON.stringify({passed:false,error:String(error.message),pageErrors}));throw error;
 }finally{
  await context?.close();await browser?.close();if(!child.stdin.destroyed)child.stdin.end('STOP\n');
  if(child.exitCode===null)await Promise.race([once(child,'exit'),new Promise(resolve=>setTimeout(()=>{child.kill();resolve();},15000).unref())]);
  await writeFile(path.join(out,'server.log'),errors);
 }
 assert.equal(child.exitCode,0,errors);const saved=JSON.parse(await readFile(path.join(out,'server-result.json'),'utf8'));assert.equal(saved.retained_run_preserved,true);
});
