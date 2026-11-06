import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('hosted FMB preparation: simulated queue, uncertain upload and responsive screens',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild');
 const out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);await mkdir(out,{recursive:true});
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Hosted from './web/HostedFormsPreparation';import './web/style.css';import './web/projectWorkbench.css';const source={project_id:'p',source_hash:'${'a'.repeat(64)}',selected_source_set_id:null};createRoot(document.getElementById('root')).render(<div className="fox-workbench"><Hosted projectId="p" source={source} busy={false} unknownOutcome={false} execute={async f=>(await f()).status==='confirmed'} onRefresh={async()=>({status:'confirmed'})}/></div>);`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const js=built.outputFiles.find(f=>f.path.endsWith('.js')).text,css=built.outputFiles.find(f=>f.path.endsWith('.css')).text;
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{const page=await browser.newPage({viewport:{width:1440,height:900}});let postCount=0,id='',state='QUEUED';
  await page.route('**/*',async route=>{const req=route.request(),url=req.url();if(url==='http://localhost/')return route.fulfill({contentType:'text/html',body:'<div id="root"></div>'});if(url.includes('/native-preparations')){if(req.method()==='POST'){postCount++;id=req.postData().match(/name="request_id"\r\n\r\n([^\r]+)/)?.[1];return route.abort('connectionfailed');}const j={job_id:id,status:state,name:'sample.fmb',source_set_sha256:'a'.repeat(64),selected_source_set_id:null,model_submission_allowed:false,business_accepted:false};return route.fulfill({contentType:'application/json',body:JSON.stringify(url.endsWith('/native-preparations')?{enabled:true,formats:['.fmb'],max_file_bytes:20971520,jobs:id?[j]:[],model_processing_started:false}:j)});}return route.abort();});
  await page.goto('http://localhost/');await page.addStyleTag({content:css});await page.addScriptTag({content:js});
  await page.getByLabel('Forms FMB file').setInputFiles({name:'sample.fmb',mimeType:'application/octet-stream',buffer:Buffer.from('synthetic')});await page.getByRole('button',{name:'Prepare FMB'}).click();
  await page.getByText(/Upload outcome unknown/).waitFor();assert.equal(postCount,1);assert.equal(await page.getByRole('button',{name:'Prepare FMB'}).isDisabled(),true);
  await page.screenshot({path:path.join(out,'hosted-unknown-desktop.png'),fullPage:true});await page.getByRole('button',{name:'Check preparation status'}).click();await page.getByText('Queued for preparation',{exact:false}).waitFor();assert.equal(postCount,1);
  state='PREPARED_REDACTED_REVIEW_REQUIRED';await page.getByRole('button',{name:'Check preparation status'}).click();await page.getByRole('button',{name:'Add prepared form to project'}).waitFor();
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:path.join(out,'hosted-prepared-mobile.png'),fullPage:true});
 }finally{await browser.close();}
});
