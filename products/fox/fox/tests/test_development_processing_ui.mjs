import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('preserved development assessment explains and disables legacy processing consent',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild');
 const assessment={source_hash:'a'.repeat(64),source_binding:'b'.repeat(64),selected_source_set_id:'ss-example',target_profile_sha256:'c'.repeat(64),conversion_configured:true,source_processing_allowed:false,source_processing_reason:'Development sources are preserved for review and analysis. AI conversion for this source mode is not enabled yet; the existing redacted-source approval does not authorize it.',source_count:1,code_unit_count:0,chunks:[],scope_notice:'Synthetic preserved development input.'};
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Panel from './web/PrototypeConversion';createRoot(document.getElementById('root')).render(<Panel exportOnly projectId="p" source={{project_id:'p',source_hash:'${'a'.repeat(64)}',selected_source_set_id:'ss-example'}} busy={false} unknownOutcome={false} hasRun={false} execute={async f=>(await f()).status==='confirmed'}/>);`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{
  const page=await browser.newPage();let posts=0;const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',r=>{const q=r.request(),u=new URL(q.url());if(q.method()==='POST')posts++;if(q.url()==='http://localhost/')return r.fulfill({contentType:'text/html',body:'<div id="root"></div>'});if(u.pathname.endsWith('/prototype-assessment'))return r.fulfill({json:assessment});if(u.pathname.endsWith('/prototype-count-checks'))return r.fulfill({status:409,json:{detail:'Synthetic check unavailable.'}});return r.abort();});
  await page.goto('http://localhost/');await page.addScriptTag({content:built.outputFiles.find(f=>f.path.endsWith('.js')).text});
  await page.getByRole('button',{name:'Review prototype scope'}).click();
  await page.getByText(assessment.source_processing_reason,{exact:true}).waitFor();
  const controls=page.getByRole('group',{name:'Confirm before processing'}).getByRole('checkbox');assert.equal(await controls.count(),3);for(const box of await controls.all())assert(await box.isDisabled());
  assert(await page.getByRole('button',{name:'Generate APEX package',exact:true}).isDisabled());
  assert.equal(posts,0);assert.deepEqual(errors,[]);
 }finally{await browser.close();}
});
