// Real authenticated local API + canonical built UI. Synthetic native exporter only.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {spawn,execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const foxRoot=fileURLToPath(new URL('../',import.meta.url));
test('hosted FMB real local HTTP/browser journey',{skip:process.env.FOX_HOSTED_BROWSER!=='1',timeout:120000},async()=>{
 const out=path.resolve(process.env.FOX_HOSTED_EVIDENCE);
 await mkdir(out,{recursive:false});
 const python=process.env.FOX_TEST_PYTHON;
 assert.ok(python);assert.ok(process.env.FOX_TEST_NODE_MODULES);
 const require=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=require('playwright');
 const port=Number(process.env.FOX_HOSTED_PORT??18391),origin=`http://127.0.0.1:${port}`;
 const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('FOX_')));
 env.PYTHONPATH=foxRoot;env.PYTHONDONTWRITEBYTECODE='1';
 const child=spawn(python,['-B','tests/hosted_forms_local_server.py','--root',path.join(out,'server'),'--port',String(port)],{cwd:foxRoot,env,windowsHide:true});
 let logs='',browser,context,page;const errors=[],requests=[],responses=[];
 child.stdout.on('data',raw=>{logs+=raw;});child.stderr.on('data',raw=>{logs+=raw;});
 try{
  let ready=false;
  for(let i=0;i<100;i++){
   if(child.exitCode!==null)throw Error(`Server exited ${child.exitCode}: ${logs}`);
   try{const r=await fetch(origin);if(r.ok){ready=true;break;}}catch{}
   await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.ok(ready,'isolated local server became ready');
  browser=await chromium.launch({channel:'msedge',headless:true});
  context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
  page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
  page.on('request',r=>{if(r.url().includes('/api/'))requests.push({method:r.method(),path:new URL(r.url()).pathname});});
  page.on('response',async r=>{if(r.url().includes('/api/'))responses.push({method:r.request().method(),path:new URL(r.url()).pathname,status:r.status(),...(r.status()>=400?{body:await r.text().catch(()=>'<unavailable>')}:{})});});
  await page.goto(origin);await page.getByLabel('Username').fill('synthetic-hosted-qa');
  await page.getByLabel('Password',{exact:true}).fill('synthetic-local-test-only');
  await page.getByRole('button',{name:'Sign in'}).click();
  await page.getByRole('button',{name:'New project'}).click();
  await page.getByLabel('Customer / organization').fill('Synthetic isolated QA');
  await page.getByLabel('Project name').fill('Hosted FMB local journey');
  const created=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname==='/api/projects');
  await page.getByRole('button',{name:'Create project'}).click();
  const response=await created;assert.equal(response.status(),201);const {id:pid}=await response.json();
  await page.getByRole('button',{name:'Add sources',exact:true}).click();
  const input=page.getByLabel('Forms FMB file');await input.waitFor();
  assert.equal(await page.getByRole('button',{name:'Prepare FMB',exact:true}).isDisabled(),true);
  await input.setInputFiles({name:'empty.fmb',mimeType:'application/octet-stream',buffer:Buffer.alloc(0)});
  await page.getByRole('button',{name:'Prepare FMB',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'non-empty .fmb'}).waitFor();
  assert.equal(requests.filter(r=>r.method==='POST'&&r.path.endsWith('/native-preparations')).length,0);
  const fixture=Buffer.from('SYNTHETIC_NOT_A_REAL_ORACLE_BINARY');
  await writeFile(path.join(out,'synthetic.fmb'),fixture);
  await input.setInputFiles(path.join(out,'synthetic.fmb'));
  const submitted=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith('/native-preparations'));
  await page.getByRole('button',{name:'Prepare FMB',exact:true}).click();
  const submittedResponse=await submitted;assert.equal(submittedResponse.status(),202);
  const job=await submittedResponse.json();assert.equal(job.model_submission_allowed,false);assert.equal(job.business_accepted,false);
  for(let i=0;i<40;i++){
   await page.getByRole('button',{name:'Check preparation status',exact:true}).click();
   if(await page.getByRole('button',{name:'Add prepared form to project',exact:true}).count())break;
   await page.waitForTimeout(100);
  }
  await page.getByText('Preparation is not conversion, technical verification, or business acceptance.',{exact:true}).waitFor();
  await page.screenshot({path:path.join(out,'desktop-prepared.png'),fullPage:true});
  const adoption=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith('/adopt'));
  await page.getByRole('button',{name:'Add prepared form to project',exact:true}).click();
  const adoptedResponse=await adoption;assert.equal(adoptedResponse.status(),200);
  const adopted=await adoptedResponse.json();assert.equal(adopted.processing_approved,false);assert.match(adopted.selected_source_set_id,/^ss-/);
  // A source binding change clears transient workbench messages by design.
  const detail=await context.request.get(`${origin}/api/projects/${pid}`);assert.equal(detail.status(),200);
  const project=await detail.json();assert.equal(project.inventory.selected_source_set_id,adopted.selected_source_set_id);assert.equal(project.runs.length,0);
  await page.getByText('Saved source version selected',{exact:true}).waitFor();
  const assessment=await context.request.get(`${origin}/api/projects/${pid}/prototype-assessment`);assert.equal(assessment.status(),200);
  const assessed=await assessment.json();await writeFile(path.join(out,'prototype-assessment.json'),JSON.stringify(assessed,null,2));
  await page.getByRole('button',{name:'Open prepared prototype intake',exact:true}).click();
  await page.getByRole('button',{name:'Review prototype scope',exact:true}).click();
  await page.getByText('1 source files; 1 code units identified.',{exact:true}).waitFor();
  await page.getByText('0 of 1 code units selected — metadata-only; no business code selected.',{exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Generate native APEX prototype',exact:true}).isDisabled(),true);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.screenshot({path:path.join(out,'desktop-adopted.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.screenshot({path:path.join(out,'mobile-adopted.png'),fullPage:true});
  const dbCode=`import sqlite3,json,sys\nc=sqlite3.connect(sys.argv[1])\nr={t:c.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ['sources','source_sets','source_redaction_receipts','runs','acceptances']}\nr['approvals']=c.execute("SELECT COUNT(*) FROM events WHERE action LIKE 'approved%'").fetchone()[0]\nprint(json.dumps(r))`;
  const counts=JSON.parse(execFileSync(python,['-B','-c',dbCode,path.join(out,'server/data/fox.sqlite3')],{encoding:'utf8',windowsHide:true}));
  assert.equal(counts.sources,1);assert.equal(counts.source_redaction_receipts,1);assert.equal(counts.runs,0);assert.equal(counts.acceptances,0);assert.equal(counts.approvals,0);
  assert.deepEqual(await readFile(path.join(out,'synthetic.fmb')),fixture);
  assert.deepEqual(await readFile(path.join(out,'server/queue',job.job_id,'input/synthetic.fmb')),fixture);
  assert.deepEqual(errors,[]);
  assert.equal(requests.some(r=>r.method==='POST'&&/\/(runs|approve|accept|process|generate)$/.test(r.path)),false);
  await writeFile(path.join(out,'result.json'),JSON.stringify({passed:true,scope:'real-local-authenticated-api-canonical-browser-synthetic-native-exporter',pid,job_id:job.job_id,source_set_id:adopted.selected_source_set_id,counts,requests,page_errors:errors,desktop_no_overflow:true,mobile_no_overflow:true,oracle_executed:false,model_executed:false,apex_imported:false,business_accepted:false},null,2));
 }catch(error){if(page)await page.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});await writeFile(path.join(out,'failure.txt'),String(error.stack??error));throw error;}
 finally{await context?.close();await browser?.close();child.kill();await writeFile(path.join(out,'server.log'),logs);await writeFile(path.join(out,'http-responses.json'),JSON.stringify(responses,null,2));}
});
