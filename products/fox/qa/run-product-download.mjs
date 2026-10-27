// One isolated synthetic product acceptance. Never targets a deployed FOX site.
// Imports are inert; the cached image supplies Playwright only at main().
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,lstatSync,readdirSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

export const ORIGIN='http://127.0.0.1:8100';
export const BACKEND_IMAGE='d69b0e8a39dfe3fabf6c703dbd4ec42513e5a19bad75988096db3f22c7584bec';
export const QA_IMAGE='142e37662816c276b33ca8b1be3da0d5afcc5e075667809be4f11898a34685f3';
export const UI=Object.freeze({
 'index.html':'8a5ebb5325f2abed410ae09a7ecb16b68f7673a7cfff64cda56895d151e281db',
 'assets/index-DcyynC8H.js':'3fd3b2430080b84d9134721124766f9732f06c500d06f74aab72939730f0d95b',
 'assets/index-7JXG_oaM.css':'9776c2b71fc626803a40411f7b4893ca9edc464979a1f3b476c31aad30637ac6',
});
export const NOTES='Synthetic isolated browser regression only; not Jason approval, customer review, or live acceptance.';
export const sha=raw=>createHash('sha256').update(raw).digest('hex');
const check=(condition,message)=>{if(!condition)throw new Error(message);};
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}(?![^])/.test(value);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

export function validateManifest(value){
 check(value?.schema_version===1&&value.scope==='fox-isolated-product-download-v1'&&value.simulated_fixtures===true&&value.live_acceptance_recorded===false,'Only isolated synthetic fixtures are permitted');
 check(value.origin===ORIGIN&&value.backend_image===BACKEND_IMAGE&&value.qa_image===QA_IMAGE,'Isolated release binding differs');
 check(Object.keys(value.ui??{}).length===3&&Object.entries(UI).every(([key,digest])=>value.ui[key]===digest),'Candidate UI bytes differ');
 check(typeof value.owner==='string'&&/^synthetic-product-[a-f0-9]{12}(?![^])/.test(value.owner),'Synthetic owner required');
 check(typeof value.project_id==='string'&&/^[a-f0-9]{24}(?![^])/.test(value.project_id)&&typeof value.run_id==='string'&&/^fox-[a-f0-9]{20}(?![^])/.test(value.run_id),'Invalid fixture identifiers');
 check(value.project_name==='Synthetic isolated acceptance browser check'&&value.notes===NOTES,'Synthetic review description differs');
 check(hash(value.source_hash)&&hash(value.package_sha256)&&hash(value.files?.['credentials.json'])&&Number.isSafeInteger(value.package_bytes)&&value.package_bytes>0&&value.package_bytes<=8_000_000,'Invalid package binding');
 return value;
}

export function permittedGet(url,manifest){
 try{const parsed=new URL(url);if(parsed.origin!==ORIGIN||parsed.username||parsed.password||parsed.search||parsed.hash)return false;
  const run=`/api/projects/${manifest.project_id}/runs/${manifest.run_id}`;
  return ['/', '/favicon.ico','/api/health','/api/session','/api/projects',`/api/projects/${manifest.project_id}`,`${run}/evidence`,`${run}/download`,...Object.keys(UI).filter(key=>key!=='index.html').map(key=>'/'+key)].includes(parsed.pathname);
 }catch{return false;}
}

export function acceptanceBody(manifest){return {source_hash:manifest.source_hash,business_flow_tested:true,remediation_reviewed:true,notes:NOTES};}

export function permittedPost(url,body,manifest,credentials,armed){
 if(armed==='login'&&url===`${ORIGIN}/api/login`)return same(body,{username:credentials.username,password:credentials.password});
 if(armed==='accept'&&url===`${ORIGIN}/api/projects/${manifest.project_id}/runs/${manifest.run_id}/accept`)return same(body,acceptanceBody(manifest));
 return false;
}

function read(file,max=65536){
 check(path.isAbsolute(file),'Absolute input path required');const stat=lstatSync(file);
 check(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=max,'Bounded regular input required');return readFileSync(file);
}
const jsonNew=(file,value)=>writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});

export async function run({fixture,output}){
 check(process.env.FOX_ISOLATED_PRODUCT_QA==='1','Explicit isolated lab launch required');
 check(process.env.FOX_QA_IMAGE===QA_IMAGE&&process.env.FOX_BACKEND_IMAGE===BACKEND_IMAGE,'Pinned image launch bindings required');
 const manifestRaw=read(path.join(fixture,'manifest.json')),manifest=validateManifest(JSON.parse(manifestRaw));
 const credentialRaw=read(path.join(fixture,'credentials.json'));
 check(sha(credentialRaw)===manifest.files['credentials.json'],'Synthetic credential bytes differ');
 const credentials=JSON.parse(credentialRaw);
 check(credentials.username===manifest.owner&&typeof credentials.password==='string'&&credentials.password.length>=32,'Synthetic login differs');
 check(path.isAbsolute(output),'Absolute output directory required');
 try{const stat=lstatSync(output);check(stat.isDirectory()&&!stat.isSymbolicLink()&&readdirSync(output).length===0,'Output must be new or empty');}
 catch(error){if(error.code==='ENOENT')mkdirSync(output,{mode:0o700});else throw error;}
 jsonNew(path.join(output,'intent.json'),{scope:manifest.scope,manifest_sha256:sha(manifestRaw),simulated_acceptance_only:true,live_acceptance_recorded:false});
 const report={schema_version:1,scope:manifest.scope,simulated_acceptance_only:true,live_acceptance_recorded:false,
  backend_image:BACKEND_IMAGE,qa_image:QA_IMAGE,candidate_ui:UI,manifest_sha256:sha(manifestRaw),tests:[],screenshots:[],passed:false};
 let browser,phase='launch',armed=null,blocked=0,loginPosts=0,acceptPosts=0;
 const mark=name=>report.tests.push({name,status:'PASSED'});
 try{
  const {chromium}=await import('playwright');browser=await chromium.launch({headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1000},acceptDownloads:true,serviceWorkers:'block'});
  context.setDefaultTimeout(15000);
  await context.route('**/*',async route=>{
   const request=route.request();
   if(request.method()==='GET'&&permittedGet(request.url(),manifest))return route.continue();
   let body;try{body=request.postDataJSON();}catch{}
   if(request.method()==='POST'&&permittedPost(request.url(),body,manifest,credentials,armed)){
    if(armed==='login')loginPosts++;else acceptPosts++;armed=null;return route.continue();
   }
   blocked++;await route.abort('blockedbyclient');
  });
  if(context.routeWebSocket)await context.routeWebSocket('**/*',socket=>{blocked++;socket.close();});
  const page=await context.newPage();
  page.on('popup',popup=>{blocked++;void popup.close();});
  page.on('pageerror',()=>{blocked++;});
  const get=async(relative)=>{check(permittedGet(ORIGIN+relative,manifest),'Read path not allowed');return context.request.get(ORIGIN+relative,{maxRedirects:0});};
  phase='health-and-ui-binding';
  const health=await get('/api/health');check(health.status()===200,'Isolated backend health failed');
  const healthBody=await health.json();check(healthBody.worker?.enabled===false&&healthBody.worker?.state==='disabled','Backend worker must be disabled');
  for(const [file,digest] of Object.entries(UI)){
   const response=await get(file==='index.html'?'/':'/'+file);check(response.status()===200&&sha(await response.body())===digest,'Served candidate UI differs');
  }
  mark('isolated_worker_disabled_and_candidate_ui_bytes');
  phase='synthetic-login';await page.goto(ORIGIN,{waitUntil:'domcontentloaded'});
  await page.getByLabel('Username',{exact:true}).fill(credentials.username);
  await page.getByLabel('Password',{exact:true}).fill(credentials.password);
  armed='login';await page.getByRole('button',{name:'Sign in',exact:true}).click();
  const project=page.locator('button.project-card').filter({has:page.getByRole('heading',{name:manifest.project_name,exact:true})});
  await project.waitFor({state:'visible'});check(await project.count()===1,'Expected one synthetic project');
  check(await page.locator('input[type="password"]').count()===0,'Do not capture credential fields');
  await project.click();await page.getByRole('tab',{name:'Conversion runs',exact:true}).click();
  const run=page.locator('div.finding').filter({has:page.getByRole('heading',{name:manifest.run_id,exact:true,level:3})});
  await run.waitFor({state:'visible'});check(await run.count()===1,'Expected one synthetic run');
  await run.getByText('Technical checks passed',{exact:true}).waitFor();mark('login_and_verified_run_rendered');
  const acceptance=run.getByRole('region',{name:'Human acceptance',exact:true});
  const tested=acceptance.getByLabel('I tested the business flow.',{exact:true});
  const reviewed=acceptance.getByLabel('I reviewed the unresolved remediation.',{exact:true});
  const notes=acceptance.getByLabel('Test notes',{exact:true});
  const accept=acceptance.getByRole('button',{name:'Accept tested package',exact:true});
  const disabled=async()=>check(await accept.isDisabled(),'Incomplete review must keep acceptance disabled');
  const screenshot=async name=>{check(await page.locator('input[type="password"]').count()===0,'Credential screenshot forbidden');
   const file=path.join(output,name+'.png');await page.screenshot({path:file,fullPage:true});report.screenshots.push({file:path.basename(file),sha256:sha(readFileSync(file))});};
  phase='withheld-confirmations';await disabled();check(await run.getByRole('link',{name:'Accepted APEX package',exact:true}).count()===0,'Download must not be offered before acceptance');
  const locked=await get(`/api/projects/${manifest.project_id}/runs/${manifest.run_id}/download`);check(locked.status()===409,'VERIFIED package must remain locked');
  await tested.check();await disabled();await tested.uncheck();await reviewed.check();await disabled();
  await tested.check();await disabled();await notes.fill('   ');await disabled();
  await notes.fill(NOTES);await reviewed.uncheck();await disabled();await reviewed.check();await tested.uncheck();await disabled();
  await screenshot('verified-withheld');await tested.check();check(await accept.isEnabled(),'Complete synthetic review should enable acceptance');
  check(acceptPosts===0&&blocked===0,'Unexpected request before explicit acceptance');
  mark('both_confirmations_and_nonblank_notes_required');await screenshot('acceptance-ready');
  phase='synthetic-acceptance';armed='accept';
  const acceptedResponse=page.waitForResponse(response=>response.url()===`${ORIGIN}/api/projects/${manifest.project_id}/runs/${manifest.run_id}/accept`&&response.request().method()==='POST');
  await accept.click();const accepted=await acceptedResponse;
  check(accepted.status()===200,'Synthetic acceptance did not succeed');const acceptedBody=await accepted.json();
  check(acceptedBody.id===manifest.run_id&&acceptedBody.state==='ACCEPTED'&&acceptedBody.artifact_sha256===manifest.package_sha256,'Accepted package binding differs');
  const downloadLink=run.getByRole('link',{name:'Accepted APEX package',exact:true});await downloadLink.waitFor({state:'visible'});
  check(await run.getByRole('region',{name:'Human acceptance',exact:true}).count()===0,'Acceptance controls must disappear');mark('explicit_synthetic_acceptance_recorded');
  phase='exact-download';const downloadEvent=page.waitForEvent('download');await downloadLink.click();const download=await downloadEvent;
  check(download.suggestedFilename()===`${manifest.run_id}-apex.zip`,'Download filename differs');
  const downloaded=path.join(output,'accepted-synthetic-package.zip');await download.saveAs(downloaded);
  const bytes=read(downloaded,8_000_000);check(bytes.length===manifest.package_bytes&&sha(bytes)===manifest.package_sha256,'Downloaded ZIP bytes differ');
  check(loginPosts===1&&acceptPosts===1&&blocked===0,'Unexpected browser request or mutation count');
  report.download={file:path.basename(downloaded),bytes:bytes.length,sha256:sha(bytes)};
  await screenshot('accepted-download');mark('exact_accepted_zip_download');report.passed=true;
 }catch{report.failure_phase=phase;report.tests.push({name:phase,status:'FAILED'});}
 finally{if(browser)await browser.close();report.requests={login:loginPosts,synthetic_acceptance:acceptPosts,blocked};jsonNew(path.join(output,'product-download-result.json'),report);}
 return report;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 const args=process.argv.slice(2);
 check(args.length===4&&args[0]==='--fixture'&&args[2]==='--output','Usage: --fixture ABSOLUTE --output ABSOLUTE');
 const report=await run({fixture:args[1],output:args[3]});
 process.stdout.write(JSON.stringify({passed:report.passed,simulated_acceptance_only:true,live_acceptance_recorded:false,failure_phase:report.failure_phase??null})+'\n');
 process.exitCode=report.passed?0:2;
}
