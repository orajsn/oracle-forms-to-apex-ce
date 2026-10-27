// Normal FOX UI/API journey. Human acceptance and downloads are forbidden here.
import {createHash} from 'node:crypto';
import {openSync,closeSync,fsyncSync,writeFileSync,readFileSync,lstatSync,mkdirSync,existsSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

export const ORIGIN='https://fox.129.213.189.48.sslip.io';
export const INSTANCE={id:'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
 compartment_id:'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',region:'us-ashburn-1'};
export const FIXTURE_FILES={
 'alpha.sql':'5a259b6d39e189180a16bcdcc5b59ea1f7ce18bb22cfd876a9b0572c3ca1e6bd',
 'alpha.xml':'446a73cf6c83c0b3584fadf37ab3c67978796f87f21f27f3a991d142c00aa5f0',
 'beta.sql':'4499836da0994f2314e569b3ff43c3a076d43d7f6a5c81c5ab9fc11af8ddc838',
 'beta.xml':'4b62238f1eada83b21de4726445db389ac103993e16092ae2492b76021cfb557'};
export const SOURCE_SHA='00cd6353d749d21236aa5e62f1440018a24819c50d1570939ef3b7bef9714218';
export const APEX_ORIGIN='https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com';
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const pid=value=>typeof value==='string'&&/^[a-f0-9]{32}$/.test(value);
const sid=value=>typeof value==='string'&&/^ss-[a-f0-9]{32}$/.test(value);
const rid=value=>typeof value==='string'&&/^fox-[a-f0-9]{20}$/.test(value);
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exact=(value,keys)=>object(value)&&Object.keys(value).sort().join('\0')===[...keys].sort().join('\0');
export const sha=raw=>createHash('sha256').update(raw).digest('hex');
export class JourneyError extends Error {constructor(code){super(code);this.name='JourneyError';}}
export const need=(ok,code)=>{if(!ok)throw new JourneyError(code);};
export function canonical(value){
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(object(value))return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';
 need(value===null||typeof value==='string'||typeof value==='boolean'||typeof value==='number'&&Number.isFinite(value),'CANONICAL_JSON_REQUIRED');
 return JSON.stringify(value);
}
const same=(a,b)=>canonical(a)===canonical(b);
export const receiptHash=value=>sha(canonical(value)+'\n');
const codeOf=error=>error instanceof JourneyError?error.message:'JOURNEY_STEP_FAILED';
const utc=()=>new Date().toISOString();
export function validateEnvironment(environment){
 const denied=new Set(['DEBUG','PWDEBUG','NODE_OPTIONS','NODE_PATH','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED',
  'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SSL_CERT_FILE','SSL_CERT_DIR','LD_PRELOAD','DYLD_INSERT_LIBRARIES']);
 for(const [name,value] of Object.entries(environment))if(value)need(!denied.has(name.toUpperCase())&&!name.toUpperCase().startsWith('PLAYWRIGHT_'),
  'BROWSER_RUNTIME_OVERRIDE_FORBIDDEN');
}

export function validateInput(value,{now=Date.now()}={}){
 need(exact(value,['schema_version','scope','mode','apply','origin','attempt_id','output_dir','credentials','project','files',
  'source_manifest_sha256','expected_forms','preflight','ui_assets','max_wait_seconds','poll_seconds','browser']), 'INPUT_FIELDS_INVALID');
 need(value.schema_version===1&&value.scope==='fox-live-project-journey-input-v1'&&value.mode==='live'&&value.apply===true
  &&value.origin===ORIGIN&&/^live-[a-f0-9]{24}$/.test(value.attempt_id),'EXPLICIT_JSN_LIVE_INPUT_REQUIRED');
 need(typeof value.output_dir==='string'&&path.isAbsolute(value.output_dir)&&path.resolve(value.output_dir)===value.output_dir,'ABSOLUTE_OUTPUT_REQUIRED');
 need(exact(value.credentials,['username','password'])&&typeof value.credentials.username==='string'&&value.credentials.username.length>0
  &&value.credentials.username.length<=100&&typeof value.credentials.password==='string'&&value.credentials.password.length>=12
  &&value.credentials.password.length<=256,'PROTECTED_LOGIN_INPUT_REQUIRED');
 need(exact(value.project,['customer','name','description'])&&typeof value.project.customer==='string'&&value.project.customer.startsWith('Synthetic')
  &&value.project.customer.length<=100&&typeof value.project.name==='string'&&/^Synthetic[A-Za-z0-9 ._-]{1,70}$/.test(value.project.name)
  &&typeof value.project.description==='string'&&value.project.description.startsWith('Synthetic')&&value.project.description.length<=1000,
  'LABELLED_SYNTHETIC_PROJECT_REQUIRED');
 need(Object.values(value.project).every(text=>text.trim()===text),'TRIMMED_SYNTHETIC_PROJECT_REQUIRED');
 need(Array.isArray(value.files)&&value.files.length===4&&Array.isArray(value.expected_forms)&&same([...value.expected_forms].sort(),['ALPHA','BETA'])
  &&value.source_manifest_sha256===SOURCE_SHA,'ORIGINAL_TWO_FORM_FIXTURE_REQUIRED');
 const seen=new Set();
 for(const file of value.files){
  need(exact(file,['name','sha256','base64'])&&Object.hasOwn(FIXTURE_FILES,file.name)&&!seen.has(file.name)
   &&file.sha256===FIXTURE_FILES[file.name]&&typeof file.base64==='string'&&file.base64.length<=400000,'SOURCE_FIXTURE_CHANGED');
  const bytes=Buffer.from(file.base64,'base64');
  need(bytes.length>0&&bytes.toString('base64')===file.base64&&sha(bytes)===file.sha256,'SOURCE_BYTES_CHANGED');
  seen.add(file.name);
 }
 need(sha(value.files.map(file=>file.name+':'+file.sha256).sort().join('\n'))===SOURCE_SHA,'SOURCE_MANIFEST_CHANGED');
 const p=value.preflight;
 need(exact(p,['schema_version','scope','observed_at_utc','source_bundle_sha256','release_sha256','provider_sha256','admission_sha256',
  'images','containers','instance','database','operator_service','active_conversion_count','application_profile','receipt_sha256'])&&p.schema_version===1
  &&p.scope==='fox-live-project-preflight-v1'&&same(p.instance,INSTANCE)&&p.active_conversion_count===0
  &&p.application_profile==='native-project-v1','EXACT_JSN_PREFLIGHT_REQUIRED');
 need(exact(p.database,['id','compartment_id','lifecycle_state','db_name'])
  &&p.database.id==='ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq'
  &&p.database.compartment_id===INSTANCE.compartment_id&&p.database.lifecycle_state==='AVAILABLE'&&p.database.db_name==='JSNF2APEX',
  'EXACT_AVAILABLE_JSN_DATABASE_REQUIRED');
 need(exact(p.operator_service,['unit','pid','start_ticks','state'])&&p.operator_service.unit==='fox-product-verifier.service'
  &&Number.isSafeInteger(p.operator_service.pid)&&p.operator_service.pid>0&&typeof p.operator_service.start_ticks==='string'
  &&/^[0-9]{1,30}$/.test(p.operator_service.start_ticks)&&p.operator_service.state==='running','OBSERVED_RUNNING_OPERATOR_REQUIRED');
 for(const key of ['source_bundle_sha256','release_sha256','provider_sha256','admission_sha256','receipt_sha256'])need(hash(p[key]),'PREFLIGHT_HASH_INVALID');
 need(exact(p.images,['fox','converter'])&&Object.values(p.images).every(x=>typeof x==='string'&&/^sha256:[a-f0-9]{64}$/.test(x)), 'PREFLIGHT_IMAGES_INVALID');
 need(exact(p.containers,['fox','forms2apex-mcp','oracle-applied-ai-label']),'PREFLIGHT_CONTAINERS_INVALID');
 for(const [name,item] of Object.entries(p.containers)){
  need(exact(item,['id','image'])&&hash(item.id)&&/^sha256:[a-f0-9]{64}$/.test(item.image),'PREFLIGHT_CONTAINER_INVALID');
  if(name!=='oracle-applied-ai-label')need(item.image===p.images[name==='fox'?'fox':'converter'],'PREFLIGHT_CONTAINER_IMAGE_DIFFERS');
 }
 const {receipt_sha256,...unsigned}=p;
 need(receiptHash(unsigned)===receipt_sha256,'PREFLIGHT_RECEIPT_CHANGED');
 need(typeof p.observed_at_utc==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(p.observed_at_utc)
  &&Number.isFinite(Date.parse(p.observed_at_utc))&&now-Date.parse(p.observed_at_utc)>=-5000&&now-Date.parse(p.observed_at_utc)<=120000,
  'PREFLIGHT_TOO_OLD_OR_FUTURE');
 need(object(value.ui_assets)&&Object.keys(value.ui_assets).length>=3&&Object.keys(value.ui_assets).length<=20&&hash(value.ui_assets['index.html'])
  &&Object.entries(value.ui_assets).every(([name,digest])=>hash(digest)&&(name==='index.html'||/^assets\/[A-Za-z0-9_.-]+\.(?:js|css|svg|png|jpg|webp)$/.test(name))),
  'PINNED_UI_ASSETS_REQUIRED');
 need(Number.isInteger(value.max_wait_seconds)&&value.max_wait_seconds>=30&&value.max_wait_seconds<=3600
  &&Number.isInteger(value.poll_seconds)&&value.poll_seconds>=2&&value.poll_seconds<=10,'BOUNDED_WAIT_REQUIRED');
 need(exact(value.browser,['playwright_module','index_sha256','version','channel'])&&typeof value.browser.playwright_module==='string'
  &&path.isAbsolute(value.browser.playwright_module)&&path.basename(value.browser.playwright_module)==='index.mjs'
  &&hash(value.browser.index_sha256)&&/^\d+\.\d+\.\d+$/.test(value.browser.version)
  &&['msedge','chromium'].includes(value.browser.channel),'EXPLICIT_INSTALLED_BROWSER_REQUIRED');
 publicInput(value); // Reject accidental credential reuse before any output path is created.
 return value;
}

export function publicInput(value){
 const {credentials,files,...rest}=value;
 const redacted={...rest,files:files.map(({name,sha256,base64})=>({name,sha256,bytes:Buffer.from(base64,'base64').length})),
  credentials:'protected_stdin_not_retained',preflight_scope:'caller_supplied_observation_not_a_signature'};
 need(!canonical(redacted).includes(JSON.stringify(credentials.password).slice(1,-1)),'PASSWORD_IN_PUBLIC_METADATA_FORBIDDEN');
 return redacted;
}
function checkedParent(file){
 let current=path.resolve(file);
 while(true){const info=lstatSync(current);need(!info.isSymbolicLink(),'OUTPUT_OR_RUNTIME_LINK_FORBIDDEN');
  const next=path.dirname(current);if(next===current)break;current=next;}
}
function syncDirectory(directory){if(process.platform==='win32')return;const fd=openSync(directory,'r');try{fsyncSync(fd);}finally{closeSync(fd);}}
export class Journal {
 constructor(directory){
  need(path.isAbsolute(directory)&&!existsSync(directory),'FRESH_OUTPUT_DIRECTORY_REQUIRED');checkedParent(path.dirname(directory));
  const parent=lstatSync(path.dirname(directory));need(parent.isDirectory(),'OUTPUT_PARENT_DIRECTORY_REQUIRED');
  if(process.platform!=='win32')need(parent.uid===process.geteuid()&&(parent.mode&0o077)===0,'PRIVATE_OUTPUT_PARENT_REQUIRED');
  mkdirSync(directory,{mode:0o700});syncDirectory(path.dirname(directory));this.directory=directory;this.names=new Set();this.observations=0;
 }
 write(name,value){
  need(/^[a-z0-9_.-]+\.json$/.test(name)&&!this.names.has(name),'CREATE_ONLY_JOURNAL_REQUIRED');
  const fd=openSync(path.join(this.directory,name),'wx',0o600);
  try{writeFileSync(fd,canonical(value)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
  syncDirectory(this.directory);this.names.add(name);return receiptHash(value);
 }
 observe(value){return this.write('observation-'+String(++this.observations).padStart(4,'0')+'.json',value);}
}

export function validateMultipart(raw,contentType,files,expectedSourceSet){
 need(Buffer.isBuffer(raw)&&raw.length<=1_000_000&&typeof contentType==='string','UPLOAD_BODY_INVALID');
 const match=/^multipart\/form-data;\s*boundary=(?:"([^"\r\n]{1,150})"|([A-Za-z0-9'()+_,.\/:=?-]{1,150}))$/i.exec(contentType);
 need(match,'UPLOAD_BOUNDARY_INVALID');const marker=Buffer.from('--'+(match[1]??match[2]));
 const expected=new Map(files.map(file=>[file.name,file.sha256]));let position=0;const seen=new Set();let selected=false;
 while(true){
  need(raw.subarray(position,position+marker.length).equals(marker),'UPLOAD_BOUNDARY_CHANGED');position+=marker.length;
  if(raw.subarray(position,position+2).toString()==='--'){
   position+=2;need(position===raw.length||raw.subarray(position).equals(Buffer.from('\r\n')),'UPLOAD_TRAILER_INVALID');break;
  }
  need(raw.subarray(position,position+2).toString()==='\r\n','UPLOAD_SEPARATOR_INVALID');position+=2;
  const end=raw.indexOf(Buffer.from('\r\n\r\n'),position);need(end>=position&&end-position<=1000,'UPLOAD_HEADERS_INVALID');
  const headers=raw.subarray(position,end).toString('utf8').split('\r\n'),headerMap=new Map();
  for(const line of headers){const split=line.indexOf(':');need(split>0,'UPLOAD_HEADER_INVALID');const key=line.slice(0,split).toLowerCase();
   need(['content-disposition','content-type'].includes(key)&&!headerMap.has(key),'UPLOAD_HEADER_INVALID');headerMap.set(key,line.slice(split+1).trim());}
  const disposition=/^form-data; name="([A-Za-z0-9_]+)"(?:; filename="([A-Za-z0-9_.-]+)")?$/.exec(headerMap.get('content-disposition')??'');
  need(disposition,'UPLOAD_DISPOSITION_INVALID');position=end+4;
  const next=raw.indexOf(Buffer.concat([Buffer.from('\r\n'),marker]),position);need(next>=position,'UPLOAD_PART_UNTERMINATED');
  const bytes=raw.subarray(position,next);position=next+2;
  if(disposition[1]==='files'){
   const name=disposition[2];need(expected.has(name)&&!seen.has(name)&&sha(bytes)===expected.get(name),'UPLOADED_SOURCE_BYTES_DIFFER');seen.add(name);
  }else{
   need(disposition[1]==='expected_current_source_set_id'&&!disposition[2]&&!selected
    &&bytes.toString('utf8')===(expectedSourceSet??'null'),'UPLOAD_SELECTION_DIFFERS');selected=true;
  }
 }
 need(seen.size===expected.size&&selected,'COMPLETE_UPLOAD_REQUIRED');return {file_count:seen.size,source_selection:expectedSourceSet};
}

export class MutationGate {
 constructor(input,journal){this.input=input;this.journal=journal;this.armed=null;this.dispatched=new Set();this.completed=new Map();this.projectId=null;this.runId=null;this.sourceSetId=null;this.plan=null;this.failure=null;}
 arm(label,pathname,body){
  need(['login','create','upload','process'].includes(label)&&!this.armed&&!this.dispatched.has(label),'MUTATION_CANNOT_BE_REPLAYED');
  const paths={login:'/api/login',create:'/api/projects',upload:'/api/projects/'+this.projectId+'/sources',process:'/api/projects/'+this.projectId+'/runs'};
  need(pathname===paths[label]&&!this.failure,'MUTATION_PATH_OR_GUARD_CHANGED');
  const order=['login','create','upload','process'],expectedStatus={login:200,create:201,upload:200};
  need(order.slice(0,order.indexOf(label)).every(name=>this.completed.get(name)?.http_status===expectedStatus[name]),'PREVIOUS_ACTION_UNCONFIRMED');
  if(label==='login')need(same(body,this.input.credentials),'LOGIN_INPUT_CHANGED');
  if(label==='create')need(same(body,this.input.project),'PROJECT_INPUT_CHANGED');
  if(label==='upload')need(pid(this.projectId)&&this.sourceSetId===null,'ONLY_NEW_PROJECT_UPLOAD_SUPPORTED');
  if(label==='process')need(same(body,validatePlan(this.plan,this)),'PROCESS_APPROVAL_BINDING_CHANGED');
  const binding=label==='login'?{normal_login:true,credentials_not_retained:true}:label==='upload'?{source_manifest_sha256:SOURCE_SHA,
   files:this.input.files.map(({name,sha256})=>({name,sha256})),expected_current_source_set_id:this.sourceSetId}:body;
  const intent={schema_version:1,scope:'fox-live-ui-mutation-intent-v1',attempt_id:this.input.attempt_id,label,method:'POST',pathname,
   binding,created_at_utc:utc(),automatic_replay_permitted:false};
  this.journal.write(label+'.intent.json',intent);this.armed={label,pathname,body};
 }
 dispatch(request){
  const url=new URL(request.url());const action=this.armed;
  need(request.method()==='POST'&&url.origin===this.input.origin&&!url.search&&!url.hash&&action&&url.pathname===action.pathname,'UNARMED_MUTATION_FORBIDDEN');
  need(!url.pathname.endsWith('/accept')&&!url.pathname.endsWith('/download')&&!this.dispatched.has(action.label),'ACCEPTANCE_DOWNLOAD_OR_REPLAY_FORBIDDEN');
  if(action.label==='upload')validateMultipart(request.postDataBuffer(),request.headers()['content-type'],this.input.files,this.sourceSetId);
  else need(same(request.postDataJSON(),action.body),'MUTATION_PAYLOAD_CHANGED');
  this.armed=null;this.dispatched.add(action.label);
  this.journal.write(action.label+'.dispatch.json',{scope:'fox-live-ui-dispatch-v1',attempt_id:this.input.attempt_id,label:action.label,
   method:'POST',pathname:url.pathname,dispatched_at_utc:utc(),...(action.label==='login'?{credentials_not_retained:true}:{request_sha256:sha(request.postDataBuffer())}),
   automatic_replay_permitted:false});
  return action;
 }
 record(action,status,body,raw){
  const expected={login:200,create:201,upload:200,process:202}[action.label];
  const summary={scope:'fox-live-ui-response-v1',label:action.label,http_status:status,response_sha256:sha(raw),observed_at_utc:utc(),automatic_replay_permitted:false};
  if(status===expected){
   if(action.label==='login')need(exact(body,['username'])&&body.username===this.input.credentials.username,'NORMAL_LOGIN_NOT_CONFIRMED');
   if(action.label==='create'){need(exact(body,['id'])&&pid(body.id),'CREATED_PROJECT_ID_INVALID');this.projectId=body.id;summary.project_id=body.id;}
   if(action.label==='upload'){need(object(body)&&body.source_hash===SOURCE_SHA&&sid(body.selected_source_set_id)&&body.conversion_profile==='native-project-v1','UPLOADED_SELECTION_NOT_CONFIRMED');
    this.sourceSetId=body.selected_source_set_id;summary.source_hash=body.source_hash;summary.selected_source_set_id=this.sourceSetId;}
   if(action.label==='process'){need(exact(body,['id','state'])&&rid(body.id)&&body.state==='QUEUED','NEW_RUN_NOT_CONFIRMED');this.runId=body.id;summary.run_id=body.id;summary.state=body.state;}
  }
  this.journal.write(action.label+'.response.json',summary);this.completed.set(action.label,summary);
  need(status===expected,'MUTATION_HTTP_REJECTED_OR_UNCONFIRMED');return summary;
 }
 allowedGet(raw){
  const url=new URL(raw);if(url.origin!==this.input.origin||url.username||url.password||url.hash||url.search)return false;
  if(['/', '/favicon.ico','/api/health','/api/session','/api/projects','/api/local-preparation/capabilities'].includes(url.pathname))return true;
  if(Object.hasOwn(this.input.ui_assets,url.pathname.slice(1)))return true;
  if(!this.projectId)return false;const base='/api/projects/'+this.projectId;
  if([base,base+'/conversion-plan',base+'/assessment',base+'/source-sets'].includes(url.pathname))return true;
  if(this.sourceSetId&&url.pathname===base+'/source-sets/'+this.sourceSetId)return true;
  return Boolean(this.runId&&url.pathname===base+'/runs/'+this.runId+'/evidence');
 }
 fail(error){if(!this.failure)this.failure=codeOf(error);}
 requireSafe(){need(!this.failure,this.failure??'REQUEST_GUARD_FAILED');}
}

export function validatePlan(plan,gate){
 need(object(plan)&&plan.project_id===gate.projectId&&plan.project_name===gate.input.project.name&&plan.source_hash===SOURCE_SHA
  &&hash(plan.plan_sha256)&&plan.state==='READY'&&plan.can_generate===true&&plan.assessment_complete===true
  &&plan.selected_source_set_id===gate.sourceSetId,'COMPLETE_READY_PROJECT_PLAN_REQUIRED');
 need(Array.isArray(plan.forms)&&plan.forms.length===2&&same(plan.forms.map(f=>f.form_name).sort(),['ALPHA','BETA'])
  &&new Set(plan.forms.map(f=>f.module_id)).size===2&&plan.forms.every(f=>/^form-[a-f0-9]{20}$/.test(f.module_id)&&f.state==='READY'),
  'BOTH_READY_FORMS_REQUIRED');
 for(const form of plan.forms){
  const filename=form.form_name==='ALPHA'?'alpha.xml':'beta.xml',table=form.form_name==='ALPHA'?'WORK_ITEMS':'STATUS_LOG',mapping=form.storage_mapping;
  need(form.source_name===filename&&form.source_sha256===FIXTURE_FILES[filename]&&form.table_name===table
   &&exact(mapping,['schema_version','scope','project_id','source_table_name','source_schema_sha256','identity_sha256','target_table_name'])
   &&mapping.schema_version===1&&mapping.scope==='fox-project-storage-v1'&&mapping.project_id===gate.projectId
   &&mapping.source_table_name===table&&hash(mapping.source_schema_sha256)&&hash(mapping.identity_sha256)
   &&mapping.target_table_name==='FOX_NATIVE_'+mapping.identity_sha256.slice(0,19).toUpperCase(),'EXPLICIT_ORIGINAL_STORAGE_MAPPING_REQUIRED');
 }
 need(Array.isArray(plan.source_files)&&plan.source_files.length===4&&same(Object.fromEntries(plan.source_files.map(f=>[f.name,f.sha256])),FIXTURE_FILES),
  'PLAN_ORIGINAL_SOURCE_MEMBERS_DIFFER');
 return {source_hash:SOURCE_SHA,expected_current_source_set_id:gate.sourceSetId,plan_sha256:plan.plan_sha256,
  approved_redacted_source:true,approved_external_ai:true,approved_prototype_scope:true};
}

export function statusProjection(detail,gate){
 need(object(detail)&&detail.id===gate.projectId&&detail.name===gate.input.project.name&&detail.inventory?.source_hash===SOURCE_SHA
  &&detail.inventory?.selected_source_set_id===gate.sourceSetId,'PROJECT_OR_SOURCE_CHANGED_DURING_RUN');
 need(Array.isArray(detail.runs)&&detail.runs.length===1,'EXACTLY_ONE_NEW_RUN_REQUIRED');
 const run=detail.runs[0];need(run.id===gate.runId&&run.project_id===gate.projectId&&run.source_hash===SOURCE_SHA
  &&['QUEUED','PROCESSING','QA_REQUIRED','VERIFIED','ATTENTION','FAILED'].includes(run.state),'RUN_IDENTITY_OR_STATE_CHANGED');
 need(run.human_accepted!==true&&run.downloadable!==true,'LIVE_ACCEPTANCE_MUST_REMAIN_ABSENT');
 return {state:run.state,artifact_generated:run.artifact_generated===true,technical_verified:run.technical_verified===true,
  human_accepted:false,downloadable:false,forms:Array.isArray(run.forms)?run.forms.map(row=>({module_id:row.module_id,state:row.state})):[],
  error_reported:Boolean(run.error)};
}

export function verifiedEvidence(evidence,detail,gate){
 const status=statusProjection(detail,gate),run=detail.runs[0],ids=gate.plan.forms.map(x=>x.module_id).sort();
 need(status.state==='VERIFIED'&&status.artifact_generated&&status.technical_verified&&!status.error_reported
  &&same(status.forms.map(x=>x.module_id).sort(),ids)&&status.forms.every(x=>x.state==='generated')&&run.review_available===true,
  'WHOLE_PROJECT_NOT_TECHNICALLY_VERIFIED');
 need(object(evidence)&&evidence.job_id===gate.runId&&evidence.source_manifest_sha256===SOURCE_SHA&&evidence.project_id===gate.projectId
  &&evidence.conversion_profile==='native-project-v1'&&evidence.application_count===1&&evidence.form_count===2
  &&Number.isSafeInteger(evidence.application_id)&&evidence.application_id>0
  &&typeof evidence.application_alias==='string'&&/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(evidence.application_alias)
  &&typeof evidence.application_url==='string'
  &&Array.isArray(evidence.forms)&&evidence.forms.length===2&&same(evidence.forms.map(form=>form.module_id).sort(),ids)
  &&Array.isArray(evidence.form_reviews)&&evidence.form_reviews.length===2&&same(evidence.form_reviews.map(form=>form.module_id).sort(),ids)
  &&evidence.reviewer_approved===true&&evidence.reviewer_execution_verified===true&&evidence.model_environment_verified===true
  &&evidence.sqlcl_valid===true&&evidence.import_passed===true&&evidence.package_reimport_passed===true
  &&evidence.human_acceptance_recorded===false&&hash(evidence.schema_preparation_sha256),'GENERATED_APPLICATION_EVIDENCE_INCOMPLETE');
 const applicationUrl=new URL(evidence.application_url);
 need(applicationUrl.origin===APEX_ORIGIN&&!applicationUrl.username&&!applicationUrl.password&&!applicationUrl.search&&!applicationUrl.hash
  &&applicationUrl.pathname==='/ords/r/forms2apex_poc/'+evidence.application_alias.toLowerCase()+'/','EXACT_JSN_APPLICATION_URL_REQUIRED');
 const proof=evidence.technical_verification;
 need(object(proof)&&proof.scope==='fox-project-technical-verification-v1'&&proof.conversion_profile==='native-project-v1'
  &&proof.job_id===gate.runId&&proof.source_manifest_sha256===SOURCE_SHA&&hash(proof.package_sha256)
  &&proof.authenticated_runtime_passed===true&&proof.clean_schema_install_passed===true&&proof.human_acceptance_recorded===false
  &&Array.isArray(proof.form_results)&&proof.form_results.length===2&&same(proof.form_results.map(x=>x.module_id).sort(),ids),
  'GENUINE_WHOLE_PROJECT_PROOF_REQUIRED');
 return {project_id:gate.projectId,run_id:gate.runId,application_id:evidence.application_id,application_alias:evidence.application_alias,
  application_url:evidence.application_url,package_sha256:proof.package_sha256,form_ids:ids,
  schema_preparation_sha256:evidence.schema_preparation_sha256,technical_proof_api_canonical_sha256:sha(canonical(proof)),
  physical_absence_before_creation_verified:false,public_human_acceptance_recorded:false,download_endpoint_called:false};
}

async function loadBrowser(input){
 const filename=path.resolve(input.browser.playwright_module);checkedParent(filename);
 need(lstatSync(filename).isFile()&&sha(readFileSync(filename))===input.browser.index_sha256,'INSTALLED_BROWSER_MODULE_CHANGED');
 const metadata=JSON.parse(readFileSync(path.join(path.dirname(filename),'package.json'),'utf8'));
 need(metadata.name==='playwright'&&metadata.version===input.browser.version,'INSTALLED_BROWSER_VERSION_CHANGED');
 const {chromium}=await import(pathToFileURL(filename).href);return chromium;
}

export async function runBrowser(input,{chromium=null,forward=null}={}){
 validateInput(input);const journal=new Journal(input.output_dir),gate=new MutationGate(input,journal);
 const evidenceMode=forward?'synthetic_backend_test':'live_http';
 journal.write('input.json',{...publicInput(input),evidence_mode:evidenceMode});
 const result={schema_version:1,scope:'fox-project-live-ui-journey-v1',attempt_id:input.attempt_id,status:'NOT_CONFIRMED',
  evidence_mode:evidenceMode,preflight_receipt_sha256:input.preflight.receipt_sha256,source_bundle_sha256:input.preflight.source_bundle_sha256,
  release_sha256:input.preflight.release_sha256,source_manifest_sha256:SOURCE_SHA,started_at_utc:utc(),
  accepted:false,downloaded:false,automatic_replay_permitted:false,screenshots_saved:false,traces_saved:false,
  preflight_authority:'provided_by_parent_guard_not_a_signature',served_assets:{},states_observed:[],tests:[]};
 let browser,context,page,phase='launch',browserClosed=false;
 const mark=name=>result.tests.push({name,status:'PASSED'});
 const read=async pathname=>{
  gate.requireSafe();const value=await page.evaluate(async path=>{const response=await fetch(path,{credentials:'same-origin',redirect:'error'});
   return {status:response.status,body:await response.json()};},pathname);gate.requireSafe();need(value.status===200,'READ_ONLY_STATUS_UNAVAILABLE');return value.body;
 };
 const mutate=async(label,pathname,body,action)=>{
  gate.requireSafe();gate.arm(label,pathname,body);
  await Promise.all([page.waitForResponse(value=>new URL(value.url()).pathname===pathname&&value.request().method()==='POST'),action()]);
  gate.requireSafe();need(gate.completed.has(label),'MUTATION_RESPONSE_NOT_RETAINED');
 };
 try{
  chromium??=await loadBrowser(input);
  browser=await chromium.launch({...(input.browser.channel==='chromium'?{}:{channel:input.browser.channel}),headless:true,
   args:['--disable-background-networking','--disable-component-update','--disable-sync','--no-first-run']});
  result.browser_version=browser.version();result.playwright_version=input.browser.version;
  context=await browser.newContext({viewport:{width:1440,height:1100},acceptDownloads:false,serviceWorkers:'block'});context.setDefaultTimeout(20000);
  await context.route('**/*',async route=>{
   try{
    const request=route.request(),url=new URL(request.url());let action=null;
    if(request.method()==='GET')need(gate.allowedGet(request.url()),'READ_OUTSIDE_CURRENT_PROJECT_FORBIDDEN');
    else action=gate.dispatch(request);
    const response=forward?await forward(request):await route.fetch({maxRedirects:0,maxRetries:0,timeout:30000});
    const status=response.status();need(status<300||status>=400,'REDIRECT_FORBIDDEN');
    const raw=await response.body();need(raw.length<=8_000_000,'HTTP_RESPONSE_TOO_LARGE');
    const asset=url.pathname==='/'?'index.html':url.pathname.slice(1);
    if(Object.hasOwn(input.ui_assets,asset)){need(status===200&&sha(raw)===input.ui_assets[asset],'SERVED_UI_ASSET_CHANGED');result.served_assets[asset]=sha(raw);}
    if(action)gate.record(action,status,JSON.parse(raw),raw);
    if(forward)await route.fulfill({status,headers:response.headers(),body:raw});else await route.fulfill({response});
   }catch(error){gate.fail(error);await route.abort('blockedbyclient').catch(()=>{});}
  });
  await context.routeWebSocket('**/*',socket=>{gate.fail(new JourneyError('WEBSOCKET_FORBIDDEN'));socket.close();});
  page=await context.newPage();page.on('popup',popup=>{gate.fail(new JourneyError('POPUP_FORBIDDEN'));void popup.close();});
  page.on('pageerror',()=>gate.fail(new JourneyError('PAGE_SCRIPT_ERROR')));
  phase='login';await page.goto(input.origin,{waitUntil:'domcontentloaded'});
  await page.getByLabel('Username',{exact:true}).fill(input.credentials.username);await page.getByLabel('Password',{exact:true}).fill(input.credentials.password);
  await mutate('login','/api/login',input.credentials,()=>page.getByRole('button',{name:/^Sign in/}).click());
  await page.getByRole('heading',{name:'Your projects',exact:true}).waitFor();
  const session=await read('/api/session');need(session.username===input.credentials.username&&session.conversion_profile==='native-project-v1'
   &&session.conversion_configured===true,'LIVE_PROJECT_INTEGRATION_NOT_CONFIGURED');
  const health=await read('/api/health');need(health.product==='FOX'&&health.worker?.enabled===true&&health.worker?.healthy===true,'LIVE_WORKER_NOT_HEALTHY');
  const projects=await read('/api/projects');need(Array.isArray(projects)&&!projects.some(p=>p.name===input.project.name),'FRESH_UNIQUE_PROJECT_NAME_REQUIRED');
  mark('normal_login_and_pinned_project_ui');
  phase='create';await page.getByRole('button',{name:'New project',exact:true}).click();
  const form=page.locator('form').filter({has:page.getByRole('heading',{name:'Start a project',exact:true})});
  await form.getByLabel('Customer / organization',{exact:true}).fill(input.project.customer);await form.getByLabel('Project name',{exact:true}).fill(input.project.name);
  await form.getByLabel('Business flow',{exact:true}).fill(input.project.description);
  await mutate('create','/api/projects',input.project,()=>form.getByRole('button',{name:/^Create project/}).click());
  const projectPath='/api/projects/'+gate.projectId;
  await page.getByRole('heading',{name:input.project.name,exact:true,level:1}).waitFor();
  const empty=await read(projectPath);need(empty.inventory?.selected_source_set_id===null&&Array.isArray(empty.runs)&&empty.runs.length===0,'NEW_EMPTY_PROJECT_REQUIRED');
  phase='upload';await page.getByRole('radio',{name:'Readable files, without a preparation manifest',exact:true}).check();
  await page.getByLabel('Choose project source files',{exact:true}).setInputFiles(input.files.map(file=>({name:file.name,mimeType:'text/plain',buffer:Buffer.from(file.base64,'base64')})));
  await mutate('upload',projectPath+'/sources',null,()=>page.getByRole('button',{name:'Upload and assess',exact:true}).click());
  await page.getByRole('heading',{name:'Review every form',exact:true}).waitFor();
  gate.plan=await read(projectPath+'/conversion-plan');const processBody=validatePlan(gate.plan,gate);
  const forms=page.locator('[aria-label="Forms in this project"]');need(await forms.locator('button.fw-form-card').count()===2,'BOTH_FORMS_NOT_RENDERED');
  journal.write('ready-plan.json',{project_id:gate.projectId,source_hash:SOURCE_SHA,selected_source_set_id:gate.sourceSetId,
   plan_sha256:gate.plan.plan_sha256,module_ids:gate.plan.forms.map(row=>row.module_id),files:FIXTURE_FILES});mark('two_original_forms_assessed_together');
  phase='process';await page.getByRole('button',{name:/^Continue to conversion/}).click();
  const section=page.getByRole('region',{name:'Convert the project',exact:true});const confirmations=section.getByRole('group',{name:'Confirm before processing this source version',exact:true});
  need(await confirmations.getByRole('checkbox').count()===3,'EXACT_PROCESSING_CONFIRMATIONS_REQUIRED');
  for(const checkbox of await confirmations.getByRole('checkbox').all())await checkbox.check();
  await mutate('process',projectPath+'/runs',processBody,()=>section.getByRole('button',{name:'Generate APEX application',exact:true}).click());
  mark('one_source_bound_process_request');
  phase='observe';const deadline=Date.now()+input.max_wait_seconds*1000;let finalDetail=null,previous=null;
  while(Date.now()<deadline){
   const detail=await read(projectPath),status=statusProjection(detail,gate);const encoded=canonical(status);
   if(encoded!==previous){journal.observe({project_id:gate.projectId,run_id:gate.runId,observed_at_utc:utc(),...status});previous=encoded;
    if(!result.states_observed.includes(status.state))result.states_observed.push(status.state);}
   need(!['ATTENTION','FAILED'].includes(status.state),'CONVERSION_REQUIRES_OPERATOR_ATTENTION');
   if(status.state==='VERIFIED'){finalDetail=detail;break;}
   await page.waitForTimeout(input.poll_seconds*1000);
  }
  need(finalDetail,'WAIT_BOUND_REACHED_NO_REPLAY');
  const evidence=await read(projectPath+'/runs/'+gate.runId+'/evidence');result.output=verifiedEvidence(evidence,finalDetail,gate);
  // Refresh the actual workbench using its normal read-only control, then show output.
  await Promise.all([page.waitForResponse(response=>new URL(response.url()).pathname===projectPath&&response.request().method()==='GET'),
   page.getByRole('button',{name:'Refresh',exact:true}).click()]);
  await page.getByRole('navigation',{name:'Conversion steps',exact:true}).getByRole('button',{name:/Output/}).click();
  const output=page.getByRole('article',{name:'Output for run '+gate.runId,exact:true});
  await output.getByRole('heading',{name:'APEX application generated',exact:true}).waitFor();
  await output.getByRole('group',{name:'Genuine human review',exact:true}).waitFor({state:'visible'});
  need(await output.getByRole('button',{name:'Download APEX package',exact:true}).isDisabled(),'LIVE_DOWNLOAD_MUST_REMAIN_LOCKED');
  need(await output.getByRole('group',{name:'Genuine human review',exact:true}).count()===1,'HUMAN_REVIEW_NOT_RENDERED');
  need(await output.getByRole('button',{name:'Accept tested package',exact:true}).isDisabled(),'HUMAN_REVIEW_MUST_START_UNCHECKED');
  gate.requireSafe();need(Object.keys(result.served_assets).includes('index.html')&&Object.keys(result.served_assets).some(name=>name.endsWith('.js'))
   &&Object.keys(result.served_assets).some(name=>name.endsWith('.css')),'PINNED_UI_NOT_FULLY_OBSERVED');
  mark('whole_project_verified_and_human_review_separate');
  result.status=forward?'SIMULATED_BACKEND_VERIFIED_NOT_LIVE':'LIVE_VERIFIED_NOT_ACCEPTED';
 }catch(error){result.code=gate.failure??codeOf(error);result.phase=phase;result.project_id=gate.projectId;result.run_id=gate.runId;}
 finally{
  if(context)await context.close().catch(()=>{});
  if(browser){try{await browser.close();browserClosed=true;}catch{result.status='NOT_CONFIRMED';result.code='BROWSER_CLOSE_UNCONFIRMED';}}
  result.browser_close_returned=browserClosed;result.finished_at_utc=utc();
  result.dispatched_actions=[...gate.dispatched];result.completed_actions=[...gate.completed.keys()];
  result.acceptance_requests=0;result.download_requests=0;
  journal.write('result.json',result);
 }
 return result;
}

export async function main(){
 need(process.argv.slice(2).length===1&&process.argv[2]==='--apply','EXPLICIT_LIVE_APPLY_REQUIRED');
 validateEnvironment(process.env); // The parent must also remove injection flags before Node starts.
 let raw=Buffer.alloc(0);for await(const chunk of process.stdin){raw=Buffer.concat([raw,chunk]);need(raw.length<=2_000_000,'STDIN_TOO_LARGE');}
 const input=JSON.parse(raw.toString('utf8'));const result=await runBrowser(input);
 process.stdout.write(JSON.stringify({status:result.status,phase:result.phase??null,code:result.code??null,
  project_id:result.output?.project_id??result.project_id??null,run_id:result.output?.run_id??result.run_id??null,
  result_file:path.join(input.output_dir,'result.json'),accepted:false,downloaded:false,automatic_replay_permitted:false})+'\n');
 return result.status==='LIVE_VERIFIED_NOT_ACCEPTED'?0:1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 try{process.exitCode=await main();}catch(error){process.stderr.write(JSON.stringify({status:'NOT_CONFIRMED',code:codeOf(error),automatic_replay_permitted:false})+'\n');process.exitCode=1;}
}
