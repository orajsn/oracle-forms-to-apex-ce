// Canonical main + real isolated local API. Synthetic files, fake native tooling.
// No customer sources, Oracle runtime, models, remote requests or acceptance.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,mkdtemp} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createHash} from 'node:crypto';

const foxRoot=fileURLToPath(new URL('../',import.meta.url));
const outer=path.resolve(process.env.FOX_TEST_WORKSPACE_ROOT??path.dirname(foxRoot));
const require=createRequire(import.meta.url);
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const pythonServer=String.raw`
import json,os,socket,sys
from pathlib import Path
root,fox=map(Path,sys.argv[1:3])
for key in tuple(os.environ):
    if key.startswith(('FOX_','F2A_')):os.environ.pop(key)
sock=socket.socket();sock.bind(('127.0.0.1',0))
origin='http://127.0.0.1:'+str(sock.getsockname()[1])
os.environ.update(FOX_DATA_DIR=str(root/'initial'),FOX_PUBLIC_ORIGIN=origin,
 FOX_ADMIN_USERNAME='synthetic-browser-qa',FOX_CONVERSION_PROFILE='native-project-v1',FOX_VERIFICATION_ENABLED='0',
 TMP=str(root),TEMP=str(root),PYTHONDONTWRITEBYTECODE='1')
sys.path.insert(0,str(fox));sys.path.insert(0,str(fox/'tests'))
from fox.local_security import protect_new_directory
protect_new_directory(root)
from fox.app import create_app,password_hash
from test_local_forms_assessment import SyntheticNative,synthetic_xml
class PickerNative(SyntheticNative):
    def extract(self,source,destination):
        count=int(source.read_bytes().decode().split(':')[1])
        if count not in (9,51):raise ValueError('Synthetic fixture count unsupported')
        self.raw=synthetic_xml(count)
        return super().extract(source,destination)
os.environ['FOX_PASSWORD_HASH']=password_hash('synthetic-browser-password-only')
app=create_app(root/'data',enable_worker=False,enable_local_preparation=True,
 local_preparation_backend=PickerNative(synthetic_xml(9)))
print('FOX_TEST_ORIGIN='+origin,flush=True)
import uvicorn
server=uvicorn.Server(uvicorn.Config(app,log_level='error',access_log=False))
server.run(sockets=[sock])
`;

test('canonical main + authenticated local API: synthetic FMB assessment, safety and responsive evidence',{
 skip:process.env.FOX_UI_BROWSER!=='1',timeout:180000,
},async()=>{
 assert.ok(process.env.FOX_TEST_NODE_MODULES,'Use existing bundled Playwright; install nothing.');
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild');
 const python=process.env.FOX_TEST_PYTHON??path.join(outer,'fox/.venv/Scripts/python.exe');
 await mkdir(path.join(outer,'work'),{recursive:true});
 const root=await mkdtemp(path.join(outer,'work/g1br-'));
 const out=path.resolve(process.env.FOX_UI_ARTIFACT_DIR??path.join(outer,'outputs/opaf-first/G1-browser',path.basename(root)));
 assert.ok(out.startsWith(path.join(outer,'outputs/opaf-first/G1-browser')+path.sep));
 await mkdir(out,{recursive:true});
 const built=await build({entryPoints:[path.join(foxRoot,'web/main.tsx')],absWorkingDir:foxRoot,
  bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',
  define:{'process.env.NODE_ENV':'"production"'},logLevel:'silent'});
 const js=built.outputFiles.find(file=>file.path.endsWith('.js')).text;
 const css=built.outputFiles.find(file=>file.path.endsWith('.css')).text;
 const server=spawn(python,['-u','-B','-c',pythonServer,root,foxRoot],{
  cwd:foxRoot,windowsHide:true,stdio:['ignore','pipe','pipe'],env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'},
 });
 let logs='',errors='',origin,browser;
 server.stdout.on('data',chunk=>{logs+=chunk;});server.stderr.on('data',chunk=>{errors+=chunk;});
 const wait=async(check,message)=>{
  for(let i=0;i<200;i++){if(await check())return;if(server.exitCode!==null)throw new Error('Local test server exited: '+errors);await new Promise(resolve=>setTimeout(resolve,50));}
  throw new Error(message+' '+errors);
 };
 const requests=[],external=[],pageErrors=[],screenshots=[],cases=[];
 let context;
 try{
  await wait(()=>{origin=/FOX_TEST_ORIGIN=(http:\/\/127\.0\.0\.1:\d+)/.exec(logs)?.[1];return origin;},'Server origin unavailable');
  await wait(async()=>{try{return (await fetch(origin+'/api/release')).ok;}catch{return false;}},'Server not ready');
  browser=await chromium.launch({channel:'msedge',headless:true});
  context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
  await context.route('**/*',async route=>{
   const url=new URL(route.request().url());
   if(url.origin!==origin){external.push(url.href);await route.abort();return;}
   if(url.pathname==='/')await route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1"><div id="root"></div>'});
   else await route.continue();
  });
  const page=await context.newPage();page.setDefaultTimeout(15000);
  page.on('pageerror',error=>pageErrors.push(error.message));
  page.on('request',request=>{if(request.url().startsWith(origin+'/api/'))requests.push({url:new URL(request.url()).pathname,method:request.method()});});
  const mount=async()=>{await page.goto(origin);await page.addStyleTag({content:css});await page.addScriptTag({content:js});};
  const login=async()=>{
   await page.getByLabel('Username',{exact:true}).fill('synthetic-browser-qa');
   await page.getByLabel('Password',{exact:true}).fill('synthetic-browser-password-only');
   await page.getByRole('button',{name:'Sign in',exact:true}).click();
   await page.getByRole('heading',{name:'Your projects',exact:true}).waitFor();
  };
  const screenshot=async name=>{await page.screenshot({path:path.join(out,name),fullPage:true});screenshots.push(name);};
  const panel=()=>page.getByRole('region',{name:'Prepare source locally',exact:true});
  const open=async()=>{
   await page.getByRole('button',{name:'1 Upload',exact:true}).click();
   await page.getByText('I have FMB, MMB, OLB or PLL files',{exact:true}).click();
   await page.getByRole('button',{name:'Open local preparation',exact:true}).click();
   await panel().getByLabel('Choose local source files',{exact:true}).waitFor();
  };
  await mount();await login();
  await page.getByRole('button',{name:'New project',exact:true}).click();
  await page.getByLabel('Customer / organization',{exact:true}).fill('Public synthetic browser QA');
  await page.getByLabel('Project name',{exact:true}).fill('Synthetic local assessment project');
  await page.getByRole('button',{name:'Create project',exact:true}).click();
  await page.getByRole('heading',{name:'Synthetic local assessment project',exact:true}).waitFor();
  await open();
  for(const count of [9,51]){
   const raw=Buffer.from('SYNTHETIC:'+count);
   await panel().getByLabel('Choose local source files',{exact:true}).setInputFiles({name:`synthetic${count}.fmb`,mimeType:'application/octet-stream',buffer:raw});
   const answer=page.waitForResponse(response=>response.url()===origin+'/api/local-preparation/assessments'&&response.request().method()==='POST');
   await panel().getByRole('button',{name:'Extract and assess locally',exact:true}).click();
   const posted=await answer;assert.equal(posted.status(),202);const initial=await posted.json();
   await panel().getByRole('heading',{name:'Understand the Forms source',exact:true}).waitFor();
   assert.equal(await panel().locator('.forms-understanding__stats strong').first().innerText(),String(count));
   await panel().getByText('Not run',{exact:true}).waitFor();
   assert.equal(await panel().getByRole('button',{name:'Use reviewed set',exact:true}).count(),0);
   assert.equal(await panel().getByRole('button',{name:/Download /}).count(),0);
   const statusResponse=await context.request.get(origin+'/api/local-preparation/jobs/'+initial.job_id);
   assert.equal(statusResponse.status(),200);const status=await statusResponse.json();
   const artifactResponse=await context.request.get(origin+'/api/local-preparation/jobs/'+initial.job_id+'/assessment');
   assert.equal(artifactResponse.status(),200);const bytes=await artifactResponse.body(),artifact=JSON.parse(bytes);
   assert.equal(sha(bytes),status.assessment_sha256);
   assert.equal(artifact.files[0].source.sha256,sha(raw));
   assert.equal(artifact.files[0].facts.totals.blocks,count);
   assert.equal(artifact.files[0].facts.totals.items,count);
   assert.equal(artifact.files[0].facts.totals.triggers,count);
   assert.equal(artifact.model_calls,false);assert.equal(artifact.conversion_started,false);
   assert.equal(status.approved_for_upload,false);assert.deepEqual(status.files,[]);
   const names=artifact.files[0].facts.dependencies.map(row=>row.name);
   assert.ok(names.includes('SYN_ORDERS'));assert.ok(names.includes('SYN_API.SAVE'));assert.ok(!names.includes('NOT_REAL'));
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),'Desktop must not overflow');
   await screenshot(`desktop-${count}-blocks.png`);
   await page.setViewportSize({width:390,height:844});
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),'Mobile must not overflow');
   await screenshot(`mobile-${count}-blocks.png`);
   await page.setViewportSize({width:1440,height:1100});
   cases.push({blocks:count,items:count,triggers:count,job_id:initial.job_id,assessment_sha256:status.assessment_sha256,
    original_sha256:sha(raw),actual_local_api:true,fake_native_only:true});
  }
  // Real retained artifact tamper must revoke facts through the actual API.
  const retained=path.join(root,'data/p',cases.at(-1).job_id,'assessment.json');
  await writeFile(retained,Buffer.concat([await readFile(retained),Buffer.from(' ')]));
  await panel().getByRole('button',{name:'Check local status',exact:true}).click();
  await panel().getByText(/The retained output changed or is unavailable/).waitFor();
  assert.equal(await panel().getByRole('heading',{name:'Understand the Forms source',exact:true}).count(),0);
  await screenshot('desktop-changed-artifact.png');
  // Test a real accepted request whose HTTP response is deliberately lost.
  await panel().getByLabel('Choose local source files',{exact:true}).setInputFiles({name:'uncertain.fmb',mimeType:'application/octet-stream',buffer:Buffer.from('SYNTHETIC:9')});
  let uncertainPosts=0;
  await page.route('**/api/local-preparation/assessments',async route=>{uncertainPosts++;await route.fetch();await route.abort('failed');});
  await panel().getByRole('button',{name:'Extract and assess locally',exact:true}).click();
  await panel().getByRole('alert').filter({hasText:/outcome is uncertain/}).waitFor();
  assert.equal(await panel().getByRole('button',{name:'Extract and assess locally',exact:true}).isDisabled(),true);
  assert.equal(uncertainPosts,1);
  await screenshot('desktop-unknown-submit.png');
  await page.unroute('**/api/local-preparation/assessments');
  // Capability policy is the only mocked API field; all other API traffic stays real.
  for(const value of [undefined,false]){
   await page.route('**/api/local-preparation/capabilities',async route=>{
    const real=await route.fetch(),body=await real.json();
    if(value===undefined)delete body.forms_assessment_available;else body.forms_assessment_available=value;
    await route.fulfill({response:real,json:body});
   });
   await mount();await page.getByRole('heading',{name:'Your projects',exact:true}).waitFor();
   await page.getByRole('button',{name:/Synthetic local assessment project/}).click();
   await open();
   assert.equal(await panel().getByRole('button',{name:'Extract and assess locally',exact:true}).count(),0);
   await page.unroute('**/api/local-preparation/capabilities');
  }
  assert.equal(requests.filter(request=>request.method==='POST'&&/\/sources$|\/runs(?:\/|$)|\/accept/.test(request.url)).length,0,'No source handoff, conversion or acceptance');
  assert.equal(requests.filter(request=>request.method==='POST'&&request.url==='/api/local-preparation/assessments').length,3);
  assert.deepEqual(external,[]);assert.deepEqual(pageErrors,[]);
  await writeFile(path.join(out,'result.json'),JSON.stringify({scope:'canonical-main-real-local-api-synthetic-native-only',passed:true,
   cases,screenshots,desktop:{width:1440,height:1100,horizontal_overflow:false},mobile:{width:390,height:844,horizontal_overflow:false},
   changed_artifact_revoked:true,uncertain_submission_replayed:false,absent_and_false_capability_hidden:true,
   external_requests:external,source_handoff_posts:0,conversion_posts:0,model_calls:0,oracle_calls:0,
   fake_native_is_not_oracle_proof:true,requests},null,2));
  console.log('G1 browser evidence: '+out);
 }catch(error){
  await writeFile(path.join(out,'failure.json'),JSON.stringify({passed:false,message:error.message,server_stderr:errors,requests,external,pageErrors},null,2));
  throw error;
 }finally{
  await context?.close();await browser?.close();
  server.kill();
 }
});
