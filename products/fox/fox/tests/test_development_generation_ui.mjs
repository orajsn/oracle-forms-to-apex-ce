import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {readFile} from 'node:fs/promises';
const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('development and legacy generation require explicit consent and preserve their contracts',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild');
 const h=c=>c.repeat(64),base={source_hash:h('a'),source_binding:h('b'),selected_source_set_id:'ss-example',target_profile_sha256:h('c'),conversion_configured:true,source_count:1,code_unit_count:1,chunks:[{id:'unit',sha256:h('d'),bytes:10}],scope_notice:'Review the source.'};
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Panel from './web/PrototypeConversion';createRoot(document.getElementById('root')).render(<Panel exportOnly projectId="p" source={{project_id:'p',source_hash:'${h('a')}',selected_source_set_id:'ss-example'}} busy={false} unknownOutcome={false} hasRun={Boolean((window as any).__run)} activeRun={(window as any).__run} execute={async f=>(await f()).status==='confirmed'}/>);`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const css=await readFile(path.join(root,'web/projectWorkbench.css'),'utf8');
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{for(const mode of ['development','legacy','invalid','unknown','active-run']){
  const page=await browser.newPage({viewport:{width:1000,height:800}}),posts=[],errors=[];page.on('pageerror',e=>errors.push(e.message));
  const assessment=mode==='development'?{...base,processing_mode:'development',development_processing_context_sha256:h('e'),source_processing_allowed:true}:mode==='invalid'?{...base,processing_mode:'development',source_processing_allowed:true}:mode==='unknown'?{...base,processing_mode:'other'}:base;
  await page.route('**/*',r=>{const q=r.request(),u=new URL(q.url());if(q.method()==='POST'){posts.push(q.postDataJSON());return r.fulfill({json:{id:'fox-'+ '1'.repeat(20),state:'QUEUED',conversion_profile:'native-blueprint-prototype-v1'}});}if(q.url()==='http://localhost/')return r.fulfill({contentType:'text/html',body:'<div class="fox-workbench"><div id="root"></div></div>'});if(u.pathname.endsWith('/prototype-assessment'))return r.fulfill({json:assessment});return r.abort();});
  await page.goto('http://localhost/');await page.addStyleTag({content:css});
  if(mode==='active-run')await page.evaluate(run=>{window.__run=run;},{id:'fox-'+'1'.repeat(20),project_id:'p',source_hash:h('a'),state:'GENERATED',message:'Generated',processing_mode:'development'});
  await page.addScriptTag({content:built.outputFiles.find(f=>f.path.endsWith('.js')).text});
  await page.getByRole('button',{name:'Review prototype scope'}).waitFor();
  if(mode==='active-run'){assert.equal(await page.getByRole('heading',{name:'Saved APEX output',exact:true}).count(),0);assert.equal(posts.length,0);assert.deepEqual(errors,[]);await page.close();continue;}
  await page.getByRole('button',{name:'Review prototype scope'}).click();
  if(mode==='invalid'||mode==='unknown'){await page.getByRole('alert').waitFor();assert.equal(posts.length,0);await page.close();continue;}
  await page.getByRole('button',{name:'Select all code units'}).click();const boxes=page.getByRole('group',{name:'Confirm before processing'}).getByRole('checkbox');assert.equal(await boxes.count(),3);for(const box of await boxes.all())await box.check();
  await page.getByRole('button',{name:'Clear selection'}).click();for(const box of await boxes.all())assert.equal(await box.isChecked(),false);assert.equal(posts.length,0);
  await page.getByRole('button',{name:'Select all code units'}).click();for(const box of await boxes.all())await box.check();
  await page.getByRole('button',{name:'Review prototype scope'}).click();for(const box of await boxes.all())assert.equal(await box.isChecked(),false);assert.equal(posts.length,0);await page.getByRole('button',{name:'Select all code units'}).click();for(const box of await boxes.all())await box.check();
  if(mode==='development'&&process.env.FOX_UI_EVIDENCE)await page.screenshot({path:path.join(process.env.FOX_UI_EVIDENCE,'development-generation.png'),fullPage:true});
  if(mode==='development'&&process.env.FOX_UI_EVIDENCE){await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(process.env.FOX_UI_EVIDENCE,'development-generation-narrow.png'),fullPage:true});}
  await page.getByRole('button',{name:'Generate APEX package',exact:true}).click();assert.equal(posts.length,1);const body=posts[0];assert.deepEqual(body.approved_chunk_hashes,{unit:h('d')});assert.equal(body.delivery_mode,'apexlang_package');assert.equal(body.approved_redacted_source,mode==='legacy');if(mode==='development'){assert.equal(body.processing_mode,'development');assert.equal(body.development_processing_context_sha256,h('e'));assert.equal(body.approved_unredacted_development_source,true);}else{assert.equal('processing_mode'in body,false);assert.equal('development_processing_context_sha256'in body,false);assert.equal('approved_unredacted_development_source'in body,false);}assert.deepEqual(errors,[]);await page.close();
 }}finally{await browser.close();}
});
