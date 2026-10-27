// Explicitly dispatched synthetic FOX journey. No provisioning or acceptance.
// Unit-test imports are inert; Playwright is imported only by guarded main().
import {createHash,randomBytes} from 'node:crypto';
import {readFileSync,lstatSync,mkdirSync,openSync,writeFileSync,fsyncSync,closeSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

export const FOX_ORIGIN='https://fox.129.213.189.48.sslip.io';
export const TARGET=Object.freeze({
 compartment_id:'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',
 instance_id:'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
 database_id:'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq',
 region:'us-ashburn-1',db_name:'ASZ8EQWFM8UNCA2_JSNF2APEX',parsing_schema:'FORMS2APEX_POC',table_name:'FOX_NATIVE_MINI',
});
export const FIXED=Object.freeze({
 happy:{job_id:'journey-happy-v1',readable_source_hash:'b7ba121603d8ebb046ec2d889b33a0b1e7a97a946f1aaf92c107f6767e9f09d7',
  manifest_sha256:'097e3e085f92fcb64f181e5c18517e0cc902fd550ca350d34c718ac767ca487c',
  files:[{name:'mini.sql',bytes:132,sha256:'8e66edefe2dfd5b6fb3614dfba179b997e4151b962dd9761bd7909abf87adc7e'},
   {name:'mini.xml',bytes:283,sha256:'4e9416890275043aac6061330d44c5bef713ea13d3d01e8251679ac941231197'}]},
 blocked:{job_id:'journey-blocked-v1',readable_source_hash:'ed4ad70b2bad380d9172a8ef3219d9a2d055373e43f2926b1da4b00bdbc9476e',
  manifest_sha256:'e736bf38d0ad941de9e333ad2fe591632ecfe4f4ca26d1a5dd71b8a9645a6b65',
  files:[{name:'blocked.sql',bytes:132,sha256:'8e66edefe2dfd5b6fb3614dfba179b997e4151b962dd9761bd7909abf87adc7e'},
   {name:'blocked.xml',bytes:359,sha256:'a687cff597ce10257d410a34529c32cf8f65a80a00be126fd99a630d414974a0'}]},
});
const SIDECAR='fox-readable-upload.json';
const sha=value=>createHash('sha256').update(value).digest('hex');
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}(?![^])/.test(value);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join('|')===[...keys].sort().join('|');
class JourneyError extends Error{}
const check=(value,message)=>{if(!value)throw new JourneyError(message);};
const canonical=value=>JSON.stringify(value,(_,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.entries(item).sort(([a],[b])=>a<b?-1:a>b?1:0)):item);
const equal=(a,b)=>canonical(a)===canonical(b);

// Duplicate-aware, bounded parser; protocol integers reject 0.0/0e0/booleans.
export function parseJson(raw){
 const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw);let at=0;
 const space=()=>{while(/[\t\n\r ]/.test(text[at]??'x'))at++;};
 function string(){const start=at++;while(at<text.length){if(text[at]==='\\'){at+=2;continue;}if(text[at++]==='"')return JSON.parse(text.slice(start,at));}throw new JourneyError('Invalid JSON string');}
 function value(depth=0,key=''){
  check(depth<=12,'JSON nesting exceeds its bound');space();const first=text[at];
  if(first==='"')return string();
  if(first==='{'||first==='['){const object=first==='{',end=object?'}':']',result=object?Object.create(null):[],keys=new Set();at++;space();
   if(text[at]===end){at++;return result;}
   while(at<text.length){space();let field='';if(object){check(text[at]==='"','Invalid JSON key');field=string();check(!keys.has(field),'Duplicate JSON key');keys.add(field);space();check(text[at++]===':','Invalid JSON separator');}
    const item=value(depth+1,field);if(object)result[field]=item;else result.push(item);space();if(text[at]===end){at++;return result;}check(text[at++]===',','Invalid JSON collection');}
   throw new JourneyError('Unterminated JSON');}
  const token=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));check(token,'Invalid JSON value');at+=token[0].length;
  const result=JSON.parse(token[0]);check(typeof result!=='number'||Number.isFinite(result),'Non-finite JSON');
  if(['schema_version','initial_row_count','bytes'].includes(key))check(/^(?:0|[1-9][0-9]*)(?![^])/.test(token[0])&&Number.isSafeInteger(result),'Protocol integer required');
  return result;
 }
 const result=value();space();check(at===text.length,'Unexpected JSON trailing data');return result;
}
function readRaw(file,max=65536){
 check(typeof file==='string'&&path.isAbsolute(file),'Absolute mounted input path required');const stat=lstatSync(file);
 check(stat.isFile()&&!stat.isSymbolicLink()&&stat.nlink===1&&stat.size>0&&stat.size<=max,'Input must be a bounded regular single-link file');
 const raw=readFileSync(file);check(raw.length===stat.size,'Mounted input changed while reading');return raw;
}
function readJson(file,max){const raw=readRaw(file,max);return {raw,value:parseJson(raw),sha256:sha(raw)};}
function safeDirectory(directory){check(path.isAbsolute(directory),'Absolute mounted directory required');const stat=lstatSync(directory);check(stat.isDirectory()&&!stat.isSymbolicLink(),'Mounted directory must not be a symlink');}
function durable(file,value){const fd=openSync(file,'wx',0o600);try{writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fsyncSync(fd);}finally{closeSync(fd);}if(process.platform!=='win32'){const dir=openSync(path.dirname(file),'r');try{fsyncSync(dir);}finally{closeSync(dir);}}}

export function loadFixtures(receiptPath){
 const receipt=readJson(receiptPath),value=receipt.value,base=path.dirname(receiptPath);
 check(exact(value,['schema_version','scope','table_name','happy','blocked'])&&value.schema_version===1&&value.scope==='fox-prepared-journey-fixtures-v1'&&value.table_name===TARGET.table_name,'Unexpected fixture receipt');
 const result={sha256:receipt.sha256,cases:{}};
 for(const kind of ['happy','blocked']){
  const record=value[kind],fixed=FIXED[kind],relative=`${kind}/extraction/${fixed.job_id}/ready`;
  check(exact(record,['job_id','ready_directory','readable_source_hash','manifest_sha256','files'])&&record.job_id===fixed.job_id&&record.ready_directory===relative&&record.readable_source_hash===fixed.readable_source_hash&&record.manifest_sha256===fixed.manifest_sha256,'Fixture identity differs from approved synthetic bytes');
  check(Array.isArray(record.files)&&record.files.length===2,'Exactly two readable fixture files required');
  const metadata=record.files.map(file=>{check(exact(file,['name','sha256','bytes']),'Unknown fixture metadata');return {name:file.name,bytes:file.bytes,sha256:file.sha256};}).sort((a,b)=>a.name<b.name?-1:1);
  check(equal(metadata,fixed.files),'Fixture source metadata differs');let folder=base;
  for(const segment of relative.split('/')){folder=path.join(folder,segment);safeDirectory(folder);}
  const files=fixed.files.map(file=>{const raw=readRaw(path.join(folder,file.name),5242880);check(raw.length===file.bytes&&sha(raw)===file.sha256,'Synthetic source byte identity differs');return {...file,buffer:raw,mimeType:file.name.endsWith('.xml')?'text/xml':'text/plain'};});
  const manifestRaw=readRaw(path.join(folder,SIDECAR),32768);check(sha(manifestRaw)===fixed.manifest_sha256,'Public manifest byte identity differs');
  const manifest=parseJson(manifestRaw);check(exact(manifest,['format','schema_version','extraction_job_id','readable_source_hash','files'])&&manifest.format==='FOX-READABLE-UPLOAD'&&manifest.schema_version===1&&manifest.extraction_job_id===fixed.job_id&&manifest.readable_source_hash===fixed.readable_source_hash,'Public manifest contract differs');
  result.cases[kind]={kind,...fixed,files,manifest:{name:SIDECAR,bytes:manifestRaw.length,sha256:sha(manifestRaw),buffer:manifestRaw,mimeType:'application/json'}};
 }
 return result;
}
export function validatePrerequisite(value,now=Date.now()){
 check(exact(value,['schema_version','scope',...Object.keys(TARGET),'ddl_sha256','readable_source_hash','metadata_verified','initial_row_count','checked_at_utc']),'Unexpected product prerequisite receipt fields');
 check(value.schema_version===1&&value.scope==='fox-journey-product-table-prerequisite-v1'&&Object.entries(TARGET).every(([key,expected])=>value[key]===expected),'Product prerequisite is outside fixed JSN scope');
 check(value.ddl_sha256===FIXED.happy.files[0].sha256&&value.readable_source_hash===FIXED.happy.readable_source_hash&&value.metadata_verified===true&&Number.isSafeInteger(value.initial_row_count)&&value.initial_row_count===0,'Product prerequisite does not prove the empty approved table');
 const checked=typeof value.checked_at_utc==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)(?![^])/.test(value.checked_at_utc)?Date.parse(value.checked_at_utc):NaN;
 check(Number.isFinite(checked)&&now-checked>=-60000&&now-checked<=3600000,'Product prerequisite is stale or future-dated');return value;
}
export function validateRelease(value){
 check(exact(value,['schema_version','scope','fox_image_id','qa_image_id','html_sha256','assets'])&&value.schema_version===1&&value.scope==='fox-journey-release-binding-v1'&&hash(value.fox_image_id)&&hash(value.qa_image_id)&&hash(value.html_sha256),'Release binding is invalid');
 check(Array.isArray(value.assets)&&value.assets.length===2,'Exactly JS and CSS release assets required');const extensions=new Set();
 for(const item of value.assets){check(exact(item,['path','sha256'])&&typeof item.path==='string'&&/^\/assets\/index-[A-Za-z0-9_-]+\.(js|css)(?![^])/.test(item.path)&&hash(item.sha256),'Unexpected release asset');extensions.add(path.extname(item.path));}
 check(extensions.size===2,'Release assets must contain one JS and one CSS file');return value;
}
export function dispatchKey(foxImageId){
 check(hash(foxImageId),'Immutable FOX image ID required for dispatch');
 // Receipt whitespace/key order must never create another mutation allowance.
 return sha([FIXED.happy.readable_source_hash,FIXED.happy.manifest_sha256,FIXED.blocked.readable_source_hash,FIXED.blocked.manifest_sha256,foxImageId].join(':'));
}
export function permittedGet(raw,projects,runs,release){
 try{const url=new URL(raw);if(url.origin!==FOX_ORIGIN||url.username||url.password||url.search||url.hash)return false;
  if(['/', '/favicon.ico','/api/session','/api/projects'].includes(url.pathname)||release.assets.some(asset=>asset.path===url.pathname))return true;
  return [...projects].some(id=>url.pathname===`/api/projects/${id}`)||[...runs].some(([pid,rid])=>url.pathname===`/api/projects/${pid}/runs/${rid}/evidence`);
 }catch{return false;}
}
export function validateMultipart(contentType,raw,source){
 check(Buffer.isBuffer(raw)&&raw.length<=65536,'Multipart request exceeds fixture bound');
 const match=/^multipart\/form-data; boundary=([-A-Za-z0-9]{16,80})(?![^])/.exec(contentType??'');check(match,'Unexpected multipart content type');
 const boundary=match[1],parts=raw.toString('latin1').split(`--${boundary}`);check(parts.shift()===''&&parts.pop()==='--\r\n','Invalid multipart boundary');
 const expected=[...source.files.map(file=>({...file,field:'files'})),{...source.manifest,field:'prepared_manifest'}];check(parts.length===expected.length,'Unexpected multipart file count');
 for(let index=0;index<parts.length;index++){
  const part=parts[index],file=expected[index],separator=part.indexOf('\r\n\r\n');check(part.startsWith('\r\n')&&part.endsWith('\r\n')&&separator>0,'Invalid multipart framing');
  const header=part.slice(2,separator);check(header===`Content-Disposition: form-data; name="${file.field}"; filename="${file.name}"\r\nContent-Type: ${file.mimeType}`,'Unexpected multipart field or filename');
  const bytes=Buffer.from(part.slice(separator+4,-2),'latin1');check(bytes.length===file.bytes&&sha(bytes)===file.sha256,'Multipart does not contain the exact approved file bytes');
 }
 return true;
}
export function validateInventory(inventory,source){
 check(inventory?.source_hash===source.readable_source_hash&&inventory.conversion_profile==='native-table-form-v1','Uploaded project source/profile differs');
 const receipt=inventory.source_preparation;
 check(receipt?.mode==='PREPARED_SET_MATCH'&&receipt.matches_current_source===true&&receipt.readable_source_hash===source.readable_source_hash&&receipt.extraction_job_id===source.job_id&&receipt.canonical_manifest_sha256===source.manifest_sha256,'Prepared receipt does not match the complete current project');
 check(Array.isArray(inventory.files)&&inventory.files.length===2,'Unexpected project source files');
 for(const file of source.files)check(inventory.files.some(item=>item.file===file.name&&item.sha256===file.sha256&&item.bytes===file.bytes),'Project source metadata differs');
 const native=inventory.native_assessment;check(native?.state===(source.kind==='happy'?'READY':'BLOCKED'),'Native eligibility differs from the synthetic case');
 if(source.kind==='happy'){
  check(inventory.conversion_eligible===true,'Normal intake conversion eligibility did not pass');
  const form=native.native_form;check(form?.table_name===TARGET.table_name&&form.columns?.length===2,'Minimal native form mapping differs');
  const [id,code]=form.columns;check(id.name==='ID'&&id.data_type==='NUMBER'&&id.primary_key===true&&id.identity===true&&id.nullable===false&&code.name==='CODE'&&code.data_type==='VARCHAR2'&&code.length===1&&code.nullable===false&&code.label==='Code','Minimal native columns differ');
 }else check(native.blockers?.some(item=>item.code==='BUSINESS_CODE_REVIEW_REQUIRED'),'Expected unsupported trigger blocker missing');
 return {source_hash:inventory.source_hash,preparation_mode:receipt.mode,native_state:native.state,table_name:native.native_form?.table_name??null};
}
export function validateEvidence(value,jobId){
 check(value?.job_id===jobId&&value.source_manifest_sha256===FIXED.happy.readable_source_hash&&value.conversion_profile==='native-table-form-v1','Release evidence source binding differs');
 check(value.reviewer_execution_verified===true&&value.reviewer_approved===true&&value.reviewer?.verdict==='approve'&&hash(value.review_receipt_sha256)&&value.reviewer.receipt_sha256===value.review_receipt_sha256&&value.sqlcl_valid===true&&value.import_passed===true&&value.package_reimport_passed===true,'Reviewed/imported package evidence is incomplete');
 check(value.artifact_binding?.job_id===jobId&&hash(value.artifact_binding.draft_sha256)&&hash(value.artifact_binding.reviewed_spec_sha256)&&hash(value.artifact_binding.native_review_sha256),'Reviewed artifact binding is incomplete');
 check(Number.isSafeInteger(value.application_id)&&value.application_id>0&&value.application_alias===`F2A_${jobId.replaceAll('-','_').toUpperCase()}`,'Imported application identity differs');
 const expected=`https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/ords/r/forms2apex_poc/${value.application_alias.toLowerCase()}/`;
 check(typeof value.application_url==='string'&&new URL(value.application_url).href===expected,'Imported application is outside fixed product POC scope');
 return {job_id:jobId,application_id:value.application_id,application_alias:value.application_alias,application_url:expected,
  reviewer_execution_verified:true,review_receipt_sha256:value.review_receipt_sha256,reviewer_model:typeof value.reviewer.model==='string'&&/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}(?![^])/.test(value.reviewer.model)?value.reviewer.model:null,
  artifact_binding:{job_id:jobId,draft_sha256:value.artifact_binding.draft_sha256,reviewed_spec_sha256:value.artifact_binding.reviewed_spec_sha256,native_review_sha256:value.artifact_binding.native_review_sha256},
  package_sha256:null,package_hash_scope:'Not exposed by this endpoint; no download requested.',authenticated_runtime_passed:value.authenticated_runtime_passed===true,clean_schema_install_passed:value.clean_schema_install_passed===true};
}

export async function main(){
 process.umask(0o077);const runId=`FOXJ-${new Date().toISOString().replace(/[-:]/g,'').slice(0,15)}-${randomBytes(4).toString('hex')}`;
 const result={schema_version:1,scope:'fox-prepared-source-rendered-journey-v1',run_id:runId,status:'RUNNING',started_at_utc:new Date().toISOString(),
  projects:{},post_requests:[],state_history:[],screenshots:[],denied_requests:0,browser_error_count:0,human_acceptance_recorded:false,download_requested:false,mutation_retry_performed:false};
 let browser,output,stopped=false,armed=null,sequence=0,secrets=[];const projects=new Set(),runs=new Map(),identities={};
 const save=()=>{if(output)writeFileSync(path.join(output,'fox-journey-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});};
 const halt=message=>{stopped=true;result.stop_reason=message;save();};
 const intent=(action,details={})=>{check(!stopped,'Journey stopped; reconcile retained intents before another dispatch');const record={sequence:++sequence,at_utc:new Date().toISOString(),action,...details};durable(path.join(output,`${String(sequence).padStart(3,'0')}-intent.json`),record);return record;};
 try{
  check(process.env.FOX_JOURNEY_DISPATCH==='approved-synthetic-prepared-journey-v1','Explicit operator dispatch required');
  check(!process.env.DEBUG&&!process.env.PWDEBUG,'Debug/trace logging prohibited');
  const fixtures=loadFixtures(process.env.FOX_JOURNEY_FIXTURES),prerequisite=readJson(process.env.FOX_JOURNEY_PREREQUISITE),releaseFile=readJson(process.env.FOX_JOURNEY_RELEASE);
  validatePrerequisite(prerequisite.value);const release=validateRelease(releaseFile.value);
  check(process.env.FOX_QA_IMAGE_ID===release.qa_image_id,'Actual immutable QA image binding differs');
  safeDirectory(process.env.FOX_QA_OUTPUT_DIR);safeDirectory(process.env.FOX_JOURNEY_DISPATCH_DIR);
  output=path.join(process.env.FOX_QA_OUTPUT_DIR,runId);mkdirSync(output,{mode:0o700});
  result.bindings={fixtures_sha256:fixtures.sha256,prerequisite_sha256:prerequisite.sha256,release_sha256:releaseFile.sha256,
   operator_reported_fox_image_id:release.fox_image_id,operator_reported_qa_image_id:release.qa_image_id,observed_asset_hashes:{}};save();
  const credentialFile=process.env.FOX_QA_CREDENTIAL_FILE;const credentialStat=lstatSync(credentialFile);
  check(process.platform==='win32'||(credentialStat.mode&0o077)===0,'Protected credentials require owner-only permissions');
  const credentials=readJson(credentialFile,16384).value;
  check(exact(credentials,['username','password'])&&credentials.username==='jason'&&typeof credentials.password==='string'&&credentials.password.length>0&&credentials.password.length<=1024,'Protected FOX credential shape differs');secrets=[credentials.username,credentials.password];
  // Same fixture bytes and FOX image may not be dispatched twice automatically.
  const key=dispatchKey(release.fox_image_id);durable(path.join(process.env.FOX_JOURNEY_DISPATCH_DIR,`${key}.json`),{schema_version:1,scope:'fox-prepared-journey-dispatch-intent-v1',run_id:runId,...result.bindings,at_utc:new Date().toISOString()});
  const {chromium}=await import('playwright');browser=await chromium.launch({headless:true,chromiumSandbox:false});
  const context=await browser.newContext({locale:'en-US',viewport:{width:1440,height:1000},ignoreHTTPSErrors:false,acceptDownloads:false,serviceWorkers:'block'});
  context.setDefaultTimeout(20000);context.setDefaultNavigationTimeout(45000);
  const page=await context.newPage();result.runtime={chromium:browser.version(),headless:true,trace:false,video:false,har:false};save();
  page.on('pageerror',()=>{result.browser_error_count++;halt('Browser runtime error; no further submissions permitted');});
  page.on('dialog',async dialog=>{halt('Unexpected browser dialog');await dialog.dismiss();});
  page.on('download',download=>{halt('Unexpected download prohibited');void download.cancel();});
  context.on('page',other=>{if(other!==page){halt('Unexpected popup prohibited');void other.close();}});
  await context.routeWebSocket('**/*',socket=>{halt('WebSocket prohibited');socket.close();});
  async function responseBody(response){check(response.status()<300&&response.status()>=200,'Expected request failed; do not retry mutation');const raw=await response.body();check(raw.length<=2097152,'API response exceeded bound');return {raw,value:parseJson(raw)};}
  await context.route('**/*',async route=>{
   const request=route.request();try{
    const url=new URL(request.url()),method=request.method();
    check(url.origin===FOX_ORIGIN&&!url.username&&!url.password&&!url.search&&!url.hash,'Out-of-scope request prohibited');
    if(method==='GET'){
     check(permittedGet(request.url(),projects,runs,release),'Unrelated project or route prohibited');
     const asset=url.pathname==='/'?{sha256:release.html_sha256}:release.assets.find(item=>item.path===url.pathname);
     if(asset){const response=await route.fetch({maxRetries:0,maxRedirects:0,timeout:30000}),raw=await response.body();check(response.status()===200&&raw.length<=1048576&&sha(raw)===asset.sha256,'Deployed FOX UI bytes differ from release binding');result.bindings.observed_asset_hashes[url.pathname]=sha(raw);save();await route.fulfill({response,body:raw});return;}
     // Playwright routing runs only for a redirect's first URL. Fetch without
     // following redirects so an otherwise allowed GET cannot escape scope.
     const response=await route.fetch({maxRetries:0,maxRedirects:0,timeout:30000});
     const expected=response.status()===200||(url.pathname==='/api/session'&&response.status()===401)||(url.pathname==='/favicon.ico'&&response.status()===404);
     check(expected&&!/^attachment(?:;|$)/i.test(response.headers()['content-disposition']??''),'Unexpected GET status or attachment prohibited');
     const raw=await response.body();check(raw.length<=2097152,'GET response exceeded bound');await route.fulfill({response,body:raw});return;
    }
    check(method==='POST'&&!stopped&&armed&&!armed.consumed&&url.pathname===armed.endpoint,'Unapproved mutation prohibited');
    const current=armed,raw=request.postDataBuffer();check(raw&&raw.length<=65536,'POST payload exceeds scope');
    if(current.kind==='upload')validateMultipart(request.headers()['content-type'],raw,fixtures.cases[current.case]);
    else check(equal(parseJson(raw),current.body),'POST JSON body differs from exact armed intent');
    current.consumed=true;result.post_requests.push({intent_sequence:current.intent.sequence,kind:current.kind,case:current.case??null,endpoint:current.endpoint,outcome:'REQUEST_STARTED'});save();
    const response=await route.fetch({maxRetries:0,maxRedirects:0,timeout:20000});check(response.status()===current.status,'Unexpected mutation status; reconcile rather than retry');
    const body=await responseBody(response),data=body.value;
    if(current.kind==='create'){
     check(exact(data,['id'])&&typeof data.id==='string'&&/^[a-f0-9]{32}(?![^])/.test(data.id)&&!projects.has(data.id),'Fresh project identity missing');
     projects.add(data.id);identities[current.case]={id:data.id,name:current.body.name};result.projects[current.case]={project_id:data.id,name:current.body.name,source_hash:fixtures.cases[current.case].readable_source_hash};
    }else if(current.kind==='upload')result.projects[current.case].assessment=validateInventory(data,fixtures.cases[current.case]);
    else if(current.kind==='process'){
     check(exact(data,['id','state'])&&typeof data.id==='string'&&/^fox-[a-f0-9]{20}(?![^])/.test(data.id)&&data.state==='QUEUED','Fresh queued run identity missing');
     runs.set(identities.happy.id,data.id);result.projects.happy.job_id=data.id;
    }else check(data.username==='jason','Authenticated FOX identity differs');
    result.post_requests.at(-1).outcome='RESPONSE_VALIDATED';result.post_requests.at(-1).response_sha256=sha(body.raw);current.response=data;save();
    await route.fulfill({response,body:body.raw});
   }catch{result.denied_requests++;halt('Request guard stopped the journey; inspect retained intents before any retry');await route.abort('blockedbyclient').catch(()=>{});}
  });
  async function click(locator,label,kind){intent('ui_click',{target:label,case:kind??null,project_id:kind?identities[kind]?.id??null:null});await locator.click();check(!stopped,'Browser or request guard stopped the journey');}
  async function mutation(kind,caseName,endpoint,body,status,locator,label){
   check(!armed,'Mutation already armed');const record=intent('mutation_click',{kind,case:caseName??null,endpoint,source_hash:caseName?FIXED[caseName].readable_source_hash:null,target:label});
   armed={kind,case:caseName,endpoint,body,status,intent:record,consumed:false};const current=armed;
   const waiting=page.waitForResponse(response=>response.url()===FOX_ORIGIN+endpoint&&response.request().method()==='POST');
   await Promise.all([waiting,locator.click()]);check(!stopped&&current.consumed&&current.response,'Mutation outcome uncertain; no automatic retry');armed=null;return current.response;
  }
  async function capture(name,kind){
   check(!stopped&&identities[kind]&&await page.getByRole('heading',{name:identities[kind].name,exact:true}).count()===1&&await page.locator('input[type="password"]').count()===0,'Only this journey project may be captured');
   const file=`${name}.png`;await page.screenshot({path:path.join(output,file),fullPage:true,mask:secrets.map(secret=>page.getByText(secret,{exact:true}))});result.screenshots.push({file,project_id:identities[kind].id,sha256:sha(readFileSync(path.join(output,file)))});save();
  }
  await page.goto(FOX_ORIGIN+'/',{waitUntil:'networkidle'});check(Object.keys(result.bindings.observed_asset_hashes).length===3&&!stopped,'Exact deployed UI assets were not observed');
  await page.getByLabel('Username',{exact:true}).fill(credentials.username);await page.getByLabel('Password',{exact:true}).fill(credentials.password);
  await mutation('login',null,'/api/login',{username:credentials.username,password:credentials.password},200,page.getByRole('button',{name:/^Sign in$/i}),'Sign in');
  await page.getByRole('button',{name:'New project',exact:true}).waitFor({state:'visible'});
  for(const kind of ['blocked','happy']){
   const source=fixtures.cases[kind],name=`FOX prepared journey ${runId} ${kind}`;
   await click(page.getByRole('button',{name:'New project',exact:true}),'New project',kind);
   const body={customer:'FOX synthetic QA',name,description:'Explicit synthetic prepared-source journey; no customer data or human acceptance.'};
   await page.getByLabel('Customer / organization',{exact:true}).fill(body.customer);await page.getByLabel('Project name',{exact:true}).fill(name);await page.getByLabel('Business flow',{exact:true}).fill(body.description);
   await mutation('create',kind,'/api/projects',body,201,page.getByRole('button',{name:'Create project',exact:true}),'Create project');
   await page.getByRole('heading',{name,exact:true}).waitFor({state:'visible'});
   // Creating a project preserves the prior tab in FOX; select this explicitly.
   await click(page.getByRole('tab',{name:'Sources',exact:true}),'Sources',kind);
   check(await page.getByRole('button',{name:'Prepared source set',exact:true}).getAttribute('aria-pressed')==='true','Prepared route is not selected');
   intent('select_local_public_ready_files',{case:kind,project_id:identities[kind].id,files:[...source.files,source.manifest].map(file=>({name:file.name,bytes:file.bytes,sha256:file.sha256}))});
   await page.getByLabel('Choose prepared manifest and readable files',{exact:true}).setInputFiles([...source.files,source.manifest].map(file=>({name:file.name,mimeType:file.mimeType,buffer:file.buffer})));
   check(await page.locator('.selected-sources li').count()===3,'The complete public ready set is not selected');
   await page.waitForTimeout(500);check(!stopped,'File selection attempted an unarmed request');
   check(!result.post_requests.some(item=>item.case===kind&&item.kind==='upload'),'File selection unexpectedly uploaded source');
   await mutation('upload',kind,`/api/projects/${identities[kind].id}/sources`,null,200,page.getByRole('button',{name:/^Upload and assess/}),'Upload and assess');
   await page.getByText('Prepared set matches the current project',{exact:true}).waitFor({state:'visible'});
   await click(page.getByText('View integrity receipt',{exact:true}),'View integrity receipt',kind);
   await page.locator('[aria-label="Source preparation receipt"]').getByText(source.readable_source_hash,{exact:true}).waitFor({state:'visible'});
   if(kind==='happy'){
    await click(page.getByText('Review supplied table and field mapping',{exact:true}),'Review supplied table and field mapping',kind);
    await page.getByRole('heading',{name:'FOX_NATIVE_MINI',exact:true}).waitFor({state:'visible'});
   }
   await capture(`${kind}-prepared-assessment`,kind);
   await click(page.getByRole('tab',{name:'Conversion runs',exact:true}),'Conversion runs',kind);
   const consents=page.locator('.consents input[type="checkbox"]');check(await consents.count()===3,'Processing consent controls differ');
   for(let index=0;index<3;index++)check(!await consents.nth(index).isChecked(),'Processing consent was automatically granted');
   const processButton=page.getByRole('button',{name:/^Process source/});check(await processButton.isDisabled(),'Process unexpectedly enabled before consent');
   if(kind==='blocked'){
    check(await page.getByRole('heading',{name:'What is needed before conversion',exact:true}).count()===1,'Native blocker not rendered');
    check(await page.getByText('No conversion runs. Source changes get a new manifest and a separate run.',{exact:true}).count()===1,'Blocked project unexpectedly has a run');
    result.projects.blocked.process_disabled=true;result.projects.blocked.process_post_count=0;await capture('blocked-conversion-locked',kind);
    await click(page.getByRole('button',{name:'All projects',exact:true}),'All projects',kind);continue;
   }
   validatePrerequisite(prerequisite.value); // Recheck freshness immediately before costly work.
   for(let index=0;index<3;index++){intent('processing_consent_click',{case:kind,project_id:identities[kind].id,consent_index:index,source_hash:source.readable_source_hash,justification:'Fixed synthetic fixture; approved explicit journey processing scope.'});await consents.nth(index).check();}
   check(!await processButton.isDisabled(),'Configured native processing did not enable after explicit consent');
   await capture('happy-processing-consents',kind);
   await mutation('process',kind,`/api/projects/${identities.happy.id}/runs`,{source_hash:source.readable_source_hash,approved_redacted_source:true,approved_external_ai:true,approved_prototype_scope:true},202,processButton,'Process source once');
   const pid=identities.happy.id,jobId=result.projects.happy.job_id,deadline=Date.now()+900000;
   let complete=false;
   while(Date.now()<deadline&&!complete){
    check(!stopped,'Journey stopped while observing conversion');const response=await page.waitForResponse(item=>item.url()===`${FOX_ORIGIN}/api/projects/${pid}`&&item.request().method()==='GET',{timeout:45000});
    const {value:detail}=await responseBody(response);check(detail.id===pid&&detail.name===identities.happy.name,'Observed project identity differs');validateInventory(detail.inventory,source);
    check(Array.isArray(detail.runs)&&detail.runs.length===1,'Fresh happy project run count differs');const run=detail.runs[0];
    check(run.id===jobId&&run.source_hash===source.readable_source_hash&&!run.downloadable,'Observed queued run identity or release gate differs');
    check(['QUEUED','PROCESSING','QA_REQUIRED'].includes(run.state),'Conversion needs reconciliation; no retry or acceptance is permitted');
    const state={state:run.state,stage:typeof run.stage==='string'&&/^[a-z_]{1,40}$/.test(run.stage)?run.stage:null};
    if(!equal(result.state_history.at(-1)?.state,state)){result.state_history.push({at_utc:new Date().toISOString(),state});save();}
    complete=run.state==='QA_REQUIRED';
   }
   check(complete,'Conversion did not reach QA_REQUIRED within the bounded observation period');result.projects.happy.state='QA_REQUIRED';
   await click(page.getByRole('tab',{name:'Sources',exact:true}),'Sources',kind);
   const evidencePath=`/api/projects/${pid}/runs/${jobId}/evidence`,waiting=page.waitForResponse(response=>response.url()===FOX_ORIGIN+evidencePath&&response.request().method()==='GET');
   await click(page.getByRole('tab',{name:'Conversion runs',exact:true}),'Conversion runs',kind);
   const evidence=await responseBody(await waiting);result.projects.happy.evidence=validateEvidence(evidence.value,jobId);result.projects.happy.evidence.response_sha256=sha(evidence.raw);
   await page.getByRole('heading',{name:jobId,exact:true}).waitFor({state:'visible'});
   await page.getByText('Lab verification pending',{exact:true}).waitFor({state:'visible'});
   const renderedEvidence=page.getByRole('region',{name:'Conversion evidence',exact:true});await renderedEvidence.waitFor({state:'visible'});
   const applicationLink=renderedEvidence.getByRole('link',{name:new RegExp(`^Open APEX app ${result.projects.happy.evidence.application_id}`)});
   await applicationLink.waitFor({state:'visible'});check(new URL(await applicationLink.getAttribute('href')).href===result.projects.happy.evidence.application_url,'Rendered application link differs from release evidence');
   check(await page.getByRole('region',{name:'Human acceptance',exact:true}).count()===0&&await page.getByRole('link',{name:'Accepted APEX package',exact:true}).count()===0,'Human acceptance or download exposed before lab verification');
   await capture('happy-qa-required',kind);
  }
  check(result.post_requests.length===6&&result.post_requests.filter(item=>item.kind==='process').length===1&&result.post_requests.every(item=>item.outcome==='RESPONSE_VALIDATED')&&!stopped&&!result.denied_requests&&!result.browser_error_count,'Journey request budget or runtime checks differ');
  result.status='PASSED';result.finished_at_utc=new Date().toISOString();save();
 }catch(error){stopped=true;result.status='INCOMPLETE';result.failure=error instanceof JourneyError?error.message:'Journey did not complete; inspect retained intents without retrying mutations.';result.finished_at_utc=new Date().toISOString();save();}
 finally{await browser?.close().catch(()=>{});}
 console.log(JSON.stringify({run_id:runId,status:result.status,receipt:output?path.join(output,'fox-journey-result.json'):null}));return result.status==='PASSED'?0:2;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)process.exitCode=await main();
