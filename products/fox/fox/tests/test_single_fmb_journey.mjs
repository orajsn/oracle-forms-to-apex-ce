// Modeled browser regression of the real preparation component. No Oracle/API proof.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url));
const enabled=process.env.FOX_UI_BROWSER==='1';
const hash='a'.repeat(64), adoptedHash='b'.repeat(64);
test('single FMB: bounded read-only polling, once-only adoption and safe recovery',{skip:!enabled,timeout:90000},async()=>{
 const modules=path.resolve(process.env.FOX_TEST_NODE_MODULES);
 const runtime=createRequire(path.join(modules,'../package.json'));
 const dependencies=createRequire(path.join(path.resolve(process.env.FOX_UI_NODE_MODULES??modules),'../package.json'));
 const {chromium}=runtime('playwright'),{build}=dependencies('esbuild');
 const out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);
 await mkdir(out,{recursive:false});
 const entry=`import React,{useState} from 'react';import{createRoot}from'react-dom/client';import Workbench from './web/ProjectWorkbench';import './web/style.css';function Harness(){const[source,setSource]=useState({project_id:'synthetic-p',source_hash:'${hash}',selected_source_set_id:null});return <Workbench project={{id:'synthetic-p',name:'Single FMB synthetic QA',customer:'Isolated QA'}} source={source} plan={null} runs={[]} capabilities={{}} processingNotice="" onRefresh={async()=>{window.refreshCount=(window.refreshCount??0)+1;if(window.refreshFails)return{status:'unconfirmed'};setSource({project_id:'synthetic-p',source_hash:'${adoptedHash}',selected_source_set_id:'ss-synthetic'});return{status:'confirmed'};}}/>;}createRoot(document.getElementById('root')).render(<Harness/>);`;
 const built=await build({stdin:{contents:entry,resolveDir:root,loader:'tsx'},nodePaths:[modules,path.resolve(process.env.FOX_UI_NODE_MODULES??modules)],bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const js=built.outputFiles.find(f=>f.path.endsWith('.js')).text,css=built.outputFiles.find(f=>f.path.endsWith('.css')).text;
 const browser=await chromium.launch({channel:'msedge',headless:true});
 const receipts=[];
 async function scenario(name,run){
  const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
  const page=await context.newPage(),errors=[],calls=[];
  let state='QUEUED',id='',getFailure=false,uncertain=false,stale=false,malformed=false,adoptionReject=false;
  const reviews=Object.fromEntries(['overridden','all','effective'].map(v=>[v,{finding_count:0,findings:[],findings_truncated:false}]));
  const makeJob=()=>({job_id:id,name:'synthetic.fmb',status:state,preparation_mode:'development_preserve',credential_review:reviews,source_set_sha256:stale?'c'.repeat(64):hash,selected_source_set_id:null,model_submission_allowed:false,business_accepted:false});
  page.on('pageerror',e=>errors.push(e.message));
  await page.clock.install();
  await page.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url());
   if(url.href==='http://localhost/')return route.fulfill({contentType:'text/html',body:'<div id="root"></div>'});
   calls.push({method:req.method(),path:url.pathname});
   if(!url.pathname.startsWith('/api/projects/synthetic-p/native-preparations'))return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Unconfigured synthetic route'})});
   const json=(body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
   if(req.method()==='POST'&&url.pathname.endsWith('/adopt'))return adoptionReject?json({detail:'Source version changed; refresh first.'},409):json({adopted:true,already_adopted:false,source_hash:adoptedHash,selected_source_set_id:'ss-synthetic',processing_approved:false});
   if(req.method()==='POST'){
    id=req.postData().match(/name="request_id"\r\n\r\n([^\r]+)/)?.[1];assert.ok(id,'request identity retained');
    return uncertain?route.abort('connectionfailed'):json(makeJob(),202);
   }
   if(getFailure)return json({detail:'Synthetic status service unavailable.'},503);
   if(malformed)return json({enabled:true,jobs:[{...makeJob(),business_accepted:true}],model_processing_started:false,formats:['.fmb'],max_file_bytes:20971520});
   return json(url.pathname.endsWith('/native-preparations')?{enabled:true,formats:['.fmb'],max_file_bytes:20971520,preparation_modes:['development_preserve','legacy_masked'],jobs:id?[makeJob()]:[],model_processing_started:false}:makeJob());
  });
  try{
   await page.goto('http://localhost/');await page.addStyleTag({content:css});await page.addScriptTag({content:js});
   await page.getByLabel('Forms FMB file').waitFor();
   const h={page,calls,postCount:()=>calls.filter(c=>c.method==='POST').length,getCount:()=>calls.filter(c=>c.method==='GET').length,set:values=>{if('state'in values)state=values.state;if('getFailure'in values)getFailure=values.getFailure;if('uncertain'in values)uncertain=values.uncertain;if('stale'in values)stale=values.stale;if('malformed'in values)malformed=values.malformed;if('adoptionReject'in values)adoptionReject=values.adoptionReject;},upload:async()=>{await page.getByLabel('Forms FMB file').setInputFiles({name:'synthetic.fmb',mimeType:'application/octet-stream',buffer:Buffer.from('SYNTHETIC_NOT_ORACLE_BINARY')});await page.getByRole('button',{name:'Prepare FMB',exact:true}).click();}};
   await run(h);
   assert.deepEqual(errors,[]);
   assert.equal(calls.some(c=>c.method!=='GET'&&c.method!=='POST'),false);
   assert.equal(calls.some(c=>/\/(runs|generate|approve|accept)$/.test(c.path)),false);
   await page.screenshot({path:path.join(out,`${name}.png`),fullPage:true});
   receipts.push({name,passed:true,scope:'modeled-browser-real-component',calls,page_errors:errors});
  }catch(e){await page.screenshot({path:path.join(out,`${name}-failure.png`),fullPage:true}).catch(()=>{});receipts.push({name,passed:false,error:String(e.stack??e),calls,page_errors:errors});throw e;}
  finally{await context.close();await writeFile(path.join(out,'receipts.json'),JSON.stringify(receipts,null,2));}
 }
 try{
  await scenario('happy-poll-adopt-continue',async h=>{
   const {page}=h;
   assert.equal(await page.getByRole('button',{name:'Prepare FMB',exact:true}).isDisabled(),true);
   await page.getByLabel('Forms FMB file').setInputFiles({name:'empty.fmb',mimeType:'application/octet-stream',buffer:Buffer.alloc(0)});
   await page.getByRole('button',{name:'Prepare FMB',exact:true}).click();
   await page.getByRole('alert').filter({hasText:'non-empty .fmb'}).waitFor();assert.equal(h.postCount(),0);
   await h.upload();await page.getByText('Queued for preparation',{exact:false}).waitFor();
   assert.equal(h.postCount(),1);
   const gets=h.getCount();
   h.set({state:'PREPARED_DEVELOPMENT_REVIEW_REQUIRED'});
   await page.clock.runFor(5100);
   await page.getByRole('button',{name:'Add prepared form to project',exact:true}).waitFor();
   assert.ok(h.getCount()>gets,'automatic refresh issued a GET');assert.equal(h.postCount(),1,'poll did not replay upload');
   await page.getByText('Preparation is not conversion, technical verification, or business acceptance.',{exact:true}).waitFor();
   const stopped=h.getCount();await page.clock.runFor(16000);assert.equal(h.getCount(),stopped,'terminal preparation stopped polling');
   await page.getByRole('button',{name:'Add prepared form to project',exact:true}).click();
   await page.getByRole('button',{name:'Continue to Convert',exact:true}).waitFor();
   assert.equal(h.postCount(),2);assert.equal(await page.evaluate(()=>window.refreshCount),1);
   assert.equal(await page.getByRole('button',{name:'Add prepared form to project',exact:true}).isDisabled(),true,'adopted result cannot be submitted again');
   await page.getByRole('button',{name:'Continue to Convert',exact:true}).click();
   await page.getByRole('region',{name:'Convert the project',exact:true}).waitFor();assert.equal(h.postCount(),2,'continue is navigation only');
   await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  });
  await scenario('poll-budget',async h=>{
   await h.upload();await h.page.getByText('Queued for preparation',{exact:false}).waitFor();
   const before=h.getCount();
   for(let i=0;i<14;i++){await h.page.clock.runFor(5100);await h.page.getByRole('button',{name:'Check preparation status',exact:true}).isEnabled();await new Promise(resolve=>setTimeout(resolve,25));}
   const after=h.getCount();assert.ok(after>before,'automatic checks occurred');assert.ok(after-before<=12,'at most twelve automatic GET checks');
   await h.page.clock.runFor(30000);assert.equal(h.getCount(),after,'poll budget stops further checks');assert.equal(h.postCount(),1);
  });
  await scenario('unknown-upload',async h=>{
   h.set({uncertain:true});await h.upload();await h.page.getByText(/Upload outcome unknown/).waitFor();assert.equal(h.postCount(),1);
   assert.equal(await h.page.getByRole('button',{name:'Prepare FMB',exact:true}).isDisabled(),true);
   await h.page.getByRole('button',{name:'Check preparation status',exact:true}).click();await h.page.getByText('Queued for preparation',{exact:false}).waitFor();
   assert.equal(h.postCount(),1,'reconciliation never reuploads');
  });
  await scenario('stale-source',async h=>{
   h.set({state:'PREPARED_DEVELOPMENT_REVIEW_REQUIRED',stale:true});await h.upload();
   await h.page.getByText(/project source has changed/).waitFor();assert.equal(await h.page.getByRole('button',{name:'Add prepared form to project',exact:true}).isDisabled(),true);assert.equal(h.postCount(),1);
  });
  await scenario('poll-error-recovery',async h=>{
   await h.upload();await h.page.getByText('Queued for preparation',{exact:false}).waitFor();h.set({getFailure:true});
   await h.page.clock.runFor(5100);await h.page.getByRole('alert').waitFor();const after=h.getCount();
   await h.page.clock.runFor(16000);assert.equal(h.getCount(),after,'failed poll does not loop');assert.equal(h.postCount(),1);
   h.set({getFailure:false,state:'BLOCKED'});await h.page.getByRole('button',{name:'Check preparation status',exact:true}).click();await h.page.getByText(/Preparation blocked/).waitFor();
   assert.equal(await h.page.getByRole('button',{name:'Add prepared form to project',exact:true}).count(),0);
  });
  await scenario('malformed-status',async h=>{
   await h.upload();await h.page.getByText('Queued for preparation',{exact:false}).waitFor();h.set({malformed:true});
   await h.page.getByRole('button',{name:'Check preparation status',exact:true}).click();await h.page.getByRole('alert').filter({hasText:'could not be verified'}).waitFor();
   assert.equal(await h.page.getByRole('button',{name:'Add prepared form to project',exact:true}).count(),0);assert.equal(h.postCount(),1);
  });
  await scenario('adopt-refresh-unknown',async h=>{
   h.set({state:'PREPARED_DEVELOPMENT_REVIEW_REQUIRED'});await h.upload();await h.page.getByRole('button',{name:'Add prepared form to project',exact:true}).waitFor();await h.page.evaluate(()=>{window.refreshFails=true;});
   await h.page.getByRole('button',{name:'Add prepared form to project',exact:true}).click();
   await h.page.waitForFunction(()=>window.refreshCount===1);assert.equal(await h.page.getByRole('button',{name:'Continue to Convert',exact:true}).count(),0,'unconfirmed source refresh does not offer continue');assert.equal(h.postCount(),2);
   assert.equal(await h.page.getByRole('button',{name:'Add prepared form to project',exact:true}).isDisabled(),true,'unknown adoption refresh fences repeat mutation');
  });
  await scenario('adoption-rejected',async h=>{
   h.set({state:'PREPARED_DEVELOPMENT_REVIEW_REQUIRED',adoptionReject:true});await h.upload();await h.page.getByRole('button',{name:'Add prepared form to project',exact:true}).click();
   await h.page.getByText('Source version changed; refresh first.',{exact:true}).waitFor();assert.equal(h.postCount(),2);
   assert.equal(await h.page.getByRole('button',{name:'Continue to Convert',exact:true}).count(),0);assert.equal(await h.page.evaluate(()=>window.refreshCount??0),0,'rejected adoption does not refresh a fictional new source');
  });
 }finally{await browser.close();}
});
