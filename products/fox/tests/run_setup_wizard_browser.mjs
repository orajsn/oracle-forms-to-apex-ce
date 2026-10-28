// Developer-only real browser journey. Python dependencies/browser must already exist.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import path from 'node:path';
import fs from 'node:fs/promises';
import {fileURLToPath} from 'node:url';

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const output=process.env.FOX_SETUP_TEST_OUTPUT;
if(!output||!path.isAbsolute(output))throw Error('Explicit absolute test output required');
await fs.mkdir(output,{recursive:false});
const runtime=process.env.FOX_TEST_NODE_MODULES;
const require=createRequire(runtime?path.join(runtime,'playwright','package.json'):import.meta.url);
const {chromium}=require('playwright');
const python=process.env.FOX_SETUP_TEST_PYTHON;
if(!python)throw Error('Explicit isolated Python required');
let helper=path.join(root,'tests','serve_setup_wizard.py'),command=python,args=['-I','-B',helper];
if(process.platform==='win32'&&process.env.FOX_SETUP_WSL_DISTRO){
  if(!process.env.FOX_SETUP_WSL_USER)throw Error('Explicit WSL test user required');
  const common=['-d',process.env.FOX_SETUP_WSL_DISTRO,'-u',process.env.FOX_SETUP_WSL_USER,'--exec'];
  const converted=spawnSync('wsl.exe',[...common,'/usr/bin/wslpath','-u',helper],{encoding:'utf8',windowsHide:true});
  if(converted.status!==0)throw Error('WSL path resolution failed');
  helper=converted.stdout.trim();command='wsl.exe';args=[...common,python,'-I','-B',helper];
}
const child=spawn(command,args,{stdio:['pipe','pipe','pipe'],windowsHide:true});
let buffer='',boot,terminal,stderr='',resolveReady,rejectReady;
const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject;});
const exited=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
child.stdout.on('data',chunk=>{buffer+=chunk.toString();let i;while((i=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,i);buffer=buffer.slice(i+1);try{const value=JSON.parse(line);if(value.url){boot=value;resolveReady(value);}else if('closed'in value)terminal=value;}catch{rejectReady(Error('Test server protocol failed'));}}});
child.stderr.on('data',chunk=>{stderr=(stderr+chunk.toString()).slice(-4096);});
child.once('error',()=>rejectReady(Error('Test server could not start')));
child.once('exit',()=>{if(!boot)rejectReady(Error('Test server exited before ready'));});
let browser,passed=false,failure=null,requests=[],pageErrors=[],connectionSettingsSaved=false;
async function bounded(promise,ms,fallback){let timer;try{return await Promise.race([promise,new Promise(resolve=>{timer=setTimeout(()=>resolve(fallback),ms);})]);}finally{clearTimeout(timer);}}
try{
  await bounded(ready,20000,null);if(!boot)throw Error('Test server readiness timed out');
  assert.match(boot.url,/^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/);
  const expectedPage=await fs.readFile(path.join(root,'installer','web','index.html'),'utf8');
  // WSL can report its real listener before Windows localhost forwarding is
  // ready. Poll GET on this same owned server; never retry a setup mutation.
  for(let i=0;i<40;i++){
    assert.equal(child.exitCode,null,'Owned test server exited during readiness');
    try{const response=await fetch(boot.url,{signal:AbortSignal.timeout(1000)});if(response.ok&&await response.text()===expectedPage)break;}
    catch{}
    if(i===39)throw Error('Loopback forwarding did not become reachable');
    await new Promise(resolve=>setTimeout(resolve,250));
  }
  browser=await chromium.launch({headless:true,...(process.env.FOX_SETUP_BROWSER_CHANNEL?{channel:process.env.FOX_SETUP_BROWSER_CHANNEL}:{})});
  const page=await browser.newPage({viewport:{width:1280,height:1050}});
  page.on('pageerror',error=>pageErrors.push(error.name));
  page.on('request',r=>{if(r.url().startsWith(boot.url+'/api/'))requests.push({method:r.method(),path:new URL(r.url()).pathname});});
  await page.goto(boot.url,{waitUntil:'networkidle',timeout:20000});
  await page.locator('#setup-code').fill('synthetic-wrong-code');
  await page.locator('#installation-root').fill(boot.installation_root);
  await page.locator('#review').click();
  await page.getByText('Setup could not be planned',{exact:true}).waitFor();
  assert.equal(await page.locator('#review-panel').isVisible(),false);
  await page.locator('#setup-code').fill(boot.token);
  await page.locator('#installation-root').fill(boot.installation_root+'/missing/child');
  await page.locator('#review').click();
  await page.getByText('INSTALLATION_PARENT_MISSING',{exact:true}).waitFor();
  await page.locator('#installation-root').fill(boot.installation_root);
  await page.locator('#review').click();
  await page.getByText('New installation folder',{exact:true}).waitFor();
  assert.equal(await page.locator('#initialize').isEnabled(),false);
  await page.screenshot({path:path.join(output,'desktop-review.png'),fullPage:true});
  await page.locator('#confirmed').check();
  await page.locator('#initialize').click();
  await page.getByText('Storage is prepared',{exact:true}).waitFor({timeout:20000});
  assert.match(await page.locator('#outcome-text').textContent(),/not yet conversion-ready/);
  await page.locator('#recheck').click();
  await page.getByText('Existing storage phase verified',{exact:true}).waitFor();
  assert.equal(await page.locator('#step-connections').getAttribute('aria-current'),'step');
  assert.equal(await page.locator('#plan-form').isVisible(),false);
  assert.equal(requests.filter(x=>x.path==='/api/initialize').length,1);
  assert.equal(await page.locator('#initialize').isEnabled(),false);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.screenshot({path:path.join(output,'desktop-storage.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.screenshot({path:path.join(output,'mobile-storage.png'),fullPage:true});
  if(process.env.FOX_SETUP_TEST_CONNECTIONS==='1'){
    await page.locator('#connections-form').waitFor();
    assert.equal(await page.locator('#save-connections').isEnabled(),false);
    await page.locator('#fox-username').fill('synthetic-demo');
    await page.locator('#fox-password').fill('synthetic-browser-password-only');
    await page.locator('#opaf-username').fill('synthetic-opaf');
    await page.locator('#opaf-password').fill('synthetic-opaf-password-only');
    await page.locator('#connections-confirmed').check();
    await page.locator('#save-connections').click();
    await page.getByText('Protected settings are saved',{exact:true}).waitFor();
    assert.match(await page.locator('#outcome-text').textContent(),/Connectivity has not been tested/);
    assert.equal(await page.locator('#fox-password').inputValue(),'');
    assert.equal(await page.locator('#opaf-password').inputValue(),'');
    assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
    const checked=page.waitForResponse(response=>response.url()===boot.url+'/api/status'&&response.request().method()==='GET');
    await page.locator('#recheck').click();await checked;
    await page.waitForFunction(()=>!document.getElementById('recheck').disabled);
    await page.getByText('Protected settings are saved',{exact:true}).waitFor();
    assert.equal(requests.filter(x=>x.path==='/api/connections').length,1);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await page.screenshot({path:path.join(output,'mobile-settings-saved.png'),fullPage:true});
    await page.setViewportSize({width:1280,height:1050});
    await page.screenshot({path:path.join(output,'desktop-settings-saved.png'),fullPage:true});
    connectionSettingsSaved=true;
  }
  assert.deepEqual(pageErrors,[]);passed=true;
}catch(error){failure=error.message;}
finally{
  if(browser)await browser.close();
  child.stdin.end('STOP\n');
  const exit=await bounded(exited,15000,{unconfirmed:true});
  const summary={passed:passed&&exit.code===0&&terminal?.closed===true,failure,
    startupError:boot?null:stderr,
    browser:process.env.FOX_SETUP_BROWSER_CHANNEL||'chromium',requests,pageErrors,
    serverExit:exit,serverClosed:terminal?.closed===true,
    finalState:terminal?.state,syntheticTestStateRetained:true,connectionSettingsSaved,
    secretsIncluded:false,oracleOrModelCalls:false};
  await fs.writeFile(path.join(output,'result.json'),JSON.stringify(summary,null,2),{flag:'wx'});
  console.log(JSON.stringify({passed:summary.passed,failure,serverClosed:summary.serverClosed,
    initializeRequests:requests.filter(x=>x.path==='/api/initialize').length,pageErrors:pageErrors.length}));
  if(!summary.passed)process.exitCode=1;
}
