import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

test('export mode keeps saved package access and hides legacy recovery', {skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000}, async()=>{
 const require=createRequire(import.meta.url),runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {build}=require('esbuild'),{chromium}=runtime('playwright');
 const root=fileURLToPath(new URL('../',import.meta.url)),out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);await mkdir(out,{recursive:true});
 const h='a'.repeat(64),run='fox-'+ 'a'.repeat(20);
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Prototype from './web/PrototypeConversion';import './web/style.css';import './web/projectWorkbench.css';const root=createRoot(document.getElementById('root'));window.renderMode=(mode)=>root.render(<div className="fox-workbench"><Prototype exportOnly={mode} projectId="p" source={{project_id:'p',source_hash:'${h}',selected_source_set_id:'ss'}} activeRun={{id:'${run}',project_id:'p',source_hash:'${h}',state:'ATTENTION'}} busy={false} unknownOutcome={false} hasRun={true} execute={async()=>true}/></div>);window.renderMode(true);`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{const page=await browser.newPage({viewport:{width:1440,height:900}});let posts=0,retryGets=0;
  await page.route('**/*',route=>{const req=route.request(),url=req.url();if(url==='http://localhost/')return route.fulfill({contentType:'text/html',body:'<div id="root"></div>'});if(req.method()!=='GET')posts++;if(/retry-validation|container-repair|mapping-recovery/.test(url))retryGets++;return route.fulfill({status:409,json:{detail:'Synthetic unavailable'}});});
  await page.goto('http://localhost/');await page.addStyleTag({content:built.outputFiles.find(f=>f.path.endsWith('.css')).text});await page.addScriptTag({content:built.outputFiles.find(f=>f.path.endsWith('.js')).text});
  await page.getByRole('heading',{name:'Generate APEX package'}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Check saved APEX output'}).count(),1);assert.equal(await page.getByRole('button',{name:'Check repair plan'}).count(),0);assert.equal(await page.getByRole('heading',{name:'Recheck the saved draft'}).count(),0);assert.equal(retryGets,0);assert.equal(posts,0);
  await page.screenshot({path:path.join(out,'export-desktop.png'),fullPage:true});await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:path.join(out,'export-mobile.png'),fullPage:true});
  await page.evaluate(()=>window.renderMode(false));await page.getByRole('button',{name:'Check repair plan'}).waitFor();assert.equal(await page.getByRole('heading',{name:'Recheck the saved draft'}).count(),1);assert.equal(posts,0);
 }finally{await browser.close();}
});
