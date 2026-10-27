import React, {useEffect, useState} from 'react';
import {checkSelectedSources, uploadManifestName} from './preparedUpload';

// This client is only a local preparation/review surface, never upload or
// conversion authority. The authenticated server repeats every safety check.
const prefix='/api/local-preparation';
const readable=['.xml','.pld','.sql','.pks','.pkb','.txt'];
const native=['.fmb','.mmb','.olb','.pll'];
const MiB=1024*1024;
const requestDeadlineMs=30000;
const exact=(value:unknown,pattern:RegExp):value is string=>typeof value==='string'&&pattern.test(value);
const jobId=(value:unknown):value is string=>exact(value,/^prep-[0-9a-f]{32}(?![\s\S])/);
const fileId=(value:unknown):value is string=>exact(value,/^file-[0-9a-f]{32}(?![\s\S])/);
const hash=(value:unknown):value is string=>exact(value,/^[0-9a-f]{64}(?![\s\S])/);
const object=(value:unknown):value is Record<string,unknown>=>typeof value==='object'&&value!==null&&!Array.isArray(value);
const integer=(value:unknown,min:number,max:number):value is number=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=min&&value<=max;
const suffix=(name:string)=>name.slice(name.lastIndexOf('.')).toLowerCase();
const safeName=(name:unknown):name is string=>exact(name,/^[A-Za-z0-9][A-Za-z0-9_. -]{0,119}(?![\s\S])/)
 &&!name.includes('..')&&!/[ .]$/.test(name)&&!/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(name);
const fail=()=>new Error('Local preparation returned incomplete or unexpected evidence. Nothing was handed off.');
class LocalPreparationError extends Error{constructor(text:string,readonly definiteRejection=false){super(text);}}
const message=(error:unknown)=>error instanceof LocalPreparationError?error.message:'Local preparation could not be confirmed. No automatic retry was made.';
const localError=(text:string,definiteRejection=false)=>new LocalPreparationError(text,definiteRejection);
const pathBudgetMessage='Local preparation paths exceed this installation’s limit. Start a new session from a shorter installation folder; keep the original files unchanged.';
function isPathBudgetRejection(value:unknown){
 return object(value)&&Object.keys(value).length===1&&object(value.detail)&&Object.keys(value.detail).length===2
  &&value.detail.code==='LOCAL_PATH_BUDGET_EXCEEDED'&&value.detail.message===pathBudgetMessage;
}

export type LocalCapabilities={readableFormats:string[];nativeFormats:string[];maxFiles:number;maxFileBytes:number;maxSelectedBytes:number};
export type LocalOutput={file_id:string;name:string;bytes:number;sha256:string};
export type LocalJob={job_id:string;state:'RUNNING'|'PREPARED_REVIEW_REQUIRED'|'BLOCKED';code:string;missing_dependency_count:number;files:LocalOutput[]};
export type PreparationState={visible:boolean;capabilities:LocalCapabilities|null;selected:File[];job:LocalJob|null;working:boolean;reviewed:boolean;handedOff:boolean;uncertain:boolean;error:string;notice:string};

export function isLocalPreparationOrigin(){
 if(typeof location==='undefined')return false;
 return location.protocol==='http:'&&location.hostname==='127.0.0.1'
  &&/^[0-9]+$/.test(location.port)&&Number(location.port)>=1024&&Number(location.port)<=65535
  &&location.origin==='http://127.0.0.1:'+Number(location.port);
}
export function readLocalCapabilities(value:unknown):LocalCapabilities{
 if(!object(value)||value.local_only!==true||value.tool_presence_only!==true||value.native_extraction_verified!==false
  ||value.automatic_upload!==false||value.conversion_available!==false
  ||!integer(value.max_files,1,50)||!integer(value.max_file_bytes,1,20*MiB)
  ||!integer(value.max_selected_bytes,1,25*MiB)||!integer(value.max_session_jobs,1,20))throw fail();
 const formats=(items:unknown,allowed:string[],required:boolean)=>{
  if(!Array.isArray(items)||(required&&!items.length)||items.some(item=>typeof item!=='string'||!allowed.includes(item))
   ||new Set(items).size!==items.length)throw fail();
  return items as string[];
 };
 return {readableFormats:formats(value.readable_formats,readable,true),nativeFormats:formats(value.native_formats,native,false),
  maxFiles:value.max_files,maxFileBytes:value.max_file_bytes,maxSelectedBytes:value.max_selected_bytes};
}
export function checkLocalSelection(files:File[],capabilities:LocalCapabilities){
 if(!files.length||files.length>capabilities.maxFiles)throw localError('Choose 1–'+capabilities.maxFiles+' files to prepare locally.');
 const names=new Set<string>();let total=0;
 for(const file of files){
  if(!safeName(file.name)||names.has(file.name.toLowerCase()))throw localError('Use unique safe filenames, without paths or reserved names.');
  names.add(file.name.toLowerCase());
  if(![...capabilities.readableFormats,...capabilities.nativeFormats].includes(suffix(file.name)))
   throw localError('This file type is not available for local preparation. Readable source files remain available when native tools are missing.');
  total+=file.size;
  if(!integer(file.size,1,capabilities.maxFileBytes)||total>capabilities.maxSelectedBytes)
   throw localError('Selected files are empty or exceed the displayed local preparation limits.');
 }
}
export function readLocalJob(value:unknown,expected?:string):LocalJob{
 if(!object(value)||!jobId(value.job_id)||(expected!==undefined&&value.job_id!==expected)
  ||value.requires_human_review!==true||value.approved_for_upload!==false||value.automatic_upload!==false||value.conversion_started!==false
  ||!integer(value.missing_dependency_count,0,Number.MAX_SAFE_INTEGER)||!Array.isArray(value.files))throw fail();
 const pairs:Record<string,string[]>={RUNNING:['PREPARING_LOCALLY'],PREPARED_REVIEW_REQUIRED:['REVIEW_READABLE_OUTPUT'],BLOCKED:['LOCAL_PREPARATION_FAILED','PREPARED_OUTPUT_CHANGED']};
 if(typeof value.state!=='string'||!Object.hasOwn(pairs,value.state)||typeof value.code!=='string'||!pairs[value.state].includes(value.code))throw fail();
 const files:LocalOutput[]=[];const ids=new Set<string>(),names=new Set<string>();let total=0,manifests=0;
 for(const entry of value.files){
  if(!object(entry)||!fileId(entry.file_id)||!safeName(entry.name)||!hash(entry.sha256)
   ||!integer(entry.bytes,1,entry.name===uploadManifestName?32768:5*MiB)
   ||ids.has(entry.file_id)||names.has(entry.name.toLowerCase()))throw fail();
  if(entry.name===uploadManifestName)manifests++;
  else {if(!readable.includes(suffix(entry.name)))throw fail();total+=entry.bytes;}
  ids.add(entry.file_id);names.add(entry.name.toLowerCase());
  files.push({file_id:entry.file_id,name:entry.name,bytes:entry.bytes,sha256:entry.sha256});
 }
 if(value.state==='PREPARED_REVIEW_REQUIRED'?(files.length<2||files.length>51||manifests!==1||total>25*MiB):files.length!==0)throw fail();
 return {job_id:value.job_id,state:value.state as LocalJob['state'],code:value.code,missing_dependency_count:value.missing_dependency_count,files};
}
function membership(job:LocalJob){return JSON.stringify([job.job_id,job.state,job.code,job.missing_dependency_count,[...job.files].sort((a,b)=>a.file_id.localeCompare(b.file_id))]);}
async function sha256(bytes:ArrayBuffer){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');}
async function abortable<T>(work:Promise<T>,signal:AbortSignal):Promise<T>{
 let abort=()=>{};
 const interrupted=new Promise<never>((_,reject)=>{
  abort=()=>reject(signal.reason);
  if(signal.aborted)abort();else signal.addEventListener('abort',abort,{once:true});
 });
 try{return await Promise.race([work,interrupted]);}
 finally{signal.removeEventListener('abort',abort);}
}
async function boundedBytes(response:Response,maximum:number,signal:AbortSignal):Promise<ArrayBuffer>{
 signal.throwIfAborted();
 const length=response.headers.get('content-length');
 if(length!==null&&(!/^[0-9]+$/.test(length)||Number(length)>maximum))throw fail();
 if(!response.body)throw fail();
 const reader=response.body.getReader();const chunks:Uint8Array[]=[];let total=0;
 const cancel=()=>{void reader.cancel(signal.reason).catch(()=>{});};
 signal.addEventListener('abort',cancel,{once:true});
 try{while(true){const {done,value}=await abortable(reader.read(),signal);signal.throwIfAborted();if(done)break;total+=value.byteLength;if(total>maximum)throw fail();chunks.push(value);}}
 catch(error){cancel();throw error;}
 finally{signal.removeEventListener('abort',cancel);reader.releaseLock();}
 const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}return bytes.buffer;
}
async function responseJSON(response:Response,signal:AbortSignal){
 const text=new TextDecoder('utf-8',{fatal:true}).decode(await boundedBytes(response,65536,signal));
 // Reject duplicate object keys and excessive nesting before JSON.parse.
 const stack:(Set<string>|null)[]=[];
 for(const token of text.matchAll(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]]/g)){
  const part=token[0];
  if(part==='{'||part==='['){stack.push(part==='{'?new Set():null);if(stack.length>4)throw fail();}
  else if(part==='}'||part===']'){if(!stack.length)throw fail();stack.pop();}
  else if(/^\s*:/.test(text.slice(token.index!+part.length))){const keys=stack[stack.length-1],key=JSON.parse(part);if(!keys||keys.has(key))throw fail();keys.add(key);}
 }
 return JSON.parse(text) as unknown;
}
async function request<T>(path:string,sessionSignal:AbortSignal,consume:(response:Response,signal:AbortSignal)=>Promise<T>,body?:FormData):Promise<T>{
 if(!isLocalPreparationOrigin())throw localError('Local preparation is only available in the authenticated localhost app.',true);
 // Callers construct only fixed route suffixes from validated opaque IDs.
 if(!/^\/(?:capabilities|jobs(?:\/prep-[0-9a-f]{32}(?:\/files\/file-[0-9a-f]{32})?)?)(?![\s\S])/.test(path))throw fail();
 sessionSignal.throwIfAborted();
 const controller=new AbortController(),signal=controller.signal;
 const abort=()=>controller.abort(sessionSignal.reason);
 sessionSignal.addEventListener('abort',abort,{once:true});
 const timer=setTimeout(()=>controller.abort(localError('Local preparation request timed out. No automatic retry was made.')),requestDeadlineMs);
 let response:Response|undefined;
 try{
  const pending=fetch(prefix+path,{method:body?'POST':'GET',body,credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal}).then(value=>{
   // Even a late mocked/custom response must not survive a timed-out request.
   if(signal.aborted){void value.body?.cancel().catch(()=>{});signal.throwIfAborted();}return value;
  });
  response=await abortable(pending,signal);
  if(response.redirected)throw fail();
  if(response.status===401||response.status===403)throw localError('Sign in to the authenticated localhost FOX session to prepare files.',true);
  signal.throwIfAborted();
  const result=await abortable(consume(response,signal),signal);signal.throwIfAborted();return result;
 }finally{
  clearTimeout(timer);sessionSignal.removeEventListener('abort',abort);
  // Error/404 bodies are intentionally not read; release their streams too.
  if(response?.body&&!response.bodyUsed&&!response.body.locked)void response.body.cancel().catch(()=>{});
 }
}

// Kept independent of rendering so the full interaction can be tested with
// mocked fetches, without a browser, native tools, or conversion side effects.
export class LocalPreparationSession{
 state:PreparationState={visible:false,capabilities:null,selected:[],job:null,working:false,reviewed:false,handedOff:false,uncertain:false,error:'',notice:''};
 externalBusy=false;
 private controller=new AbortController();private disposed=false;private invalidated=new Set<string>();
 constructor(private changed:(state:PreparationState)=>void){}
 private update(next:Partial<PreparationState>){if(!this.disposed){this.state={...this.state,...next};this.changed(this.state);}}
 dispose(){this.disposed=true;this.controller.abort();}
 async initialize(){
  if(!isLocalPreparationOrigin())return;
  try{const capabilities=await request('/capabilities',this.controller.signal,async(response,signal)=>{
   if(response.status===404)return null;if(!response.ok)throw fail();return readLocalCapabilities(await responseJSON(response,signal));
  });if(capabilities)this.update({visible:true,capabilities});
  }catch(error){this.update({visible:true,error:message(error)});}
 }
 select(files:File[]){
  if(this.state.working||this.externalBusy||this.state.job?.state==='RUNNING'||this.state.uncertain)return;
  try{if(!this.state.capabilities)throw fail();checkLocalSelection(files,this.state.capabilities);this.update({selected:[...files],reviewed:false,error:'',notice:''});}
  catch(error){this.update({selected:[],error:message(error)});}
 }
 setReviewed(value:boolean){if(!this.state.working&&!this.externalBusy&&!this.state.uncertain&&this.state.job?.state==='PREPARED_REVIEW_REQUIRED'&&!this.state.handedOff)this.update({reviewed:value,error:'',notice:''});}
 async prepare(){
  if(this.state.working||this.externalBusy||this.state.uncertain||this.state.job?.state==='RUNNING')return;
  try{if(!this.state.capabilities)throw fail();checkLocalSelection(this.state.selected,this.state.capabilities);}
  catch(error){this.update({error:message(error)});return;}
  this.update({working:true,reviewed:false,handedOff:false,error:'',notice:''});
  let submitted=false,rejected=false;
  try{const form=new FormData();for(const file of this.state.selected)form.append('files',file,file.name);
   submitted=true;const job=await request('/jobs',this.controller.signal,async(response,signal)=>{
    if([400,404,409,413,415,422,429].includes(response.status)){
     rejected=true; // Headers already establish that no preparation was created.
     let rejection=response.status===409?'Local preparation could not start. Another job may be active or the required native tools are unavailable. Check the existing local job or select readable source.':response.status===429?'The local session preparation limit was reached. Existing jobs are retained; contact the local operator.':response.status===404?'Local preparation is no longer available in this session. Contact the local operator.':'The selected files were rejected. Check the displayed limits and file formats before trying again.';
     if(response.status===422){
      try{if(isPathBudgetRejection(await responseJSON(response,signal)))rejection=pathBudgetMessage;}
      catch{signal.throwIfAborted();} // Never display arbitrary error bodies.
     }
     throw localError(rejection,true);
    }
    if(response.status!==202)throw fail();return readLocalJob(await responseJSON(response,signal));
   },form);
   this.update({job,selected:[]});
  }catch(error){const uncertain=submitted&&!rejected&&!(error instanceof LocalPreparationError&&error.definiteRejection);
   this.update({uncertain,error:message(error)+(uncertain?' The preparation outcome is uncertain. Do not resubmit; ask the local operator to inspect the retained job.':'')});}
  finally{this.update({working:false});}
 }
 async refresh(){
  if(this.state.working||this.externalBusy||!this.state.job)return;
  this.update({working:true,error:'',notice:''});
  try{const job=await this.fetchStatus(this.state.job.job_id);const changed=membership(job)!==membership(this.state.job);
   this.update({job,reviewed:changed||job.state!=='PREPARED_REVIEW_REQUIRED'?false:this.state.reviewed,handedOff:changed?false:this.state.handedOff});
  }catch(error){this.update({reviewed:false,error:message(error)});}
  finally{this.update({working:false});}
 }
 private async fetchStatus(identifier:string){
  if(!jobId(identifier))throw fail();return request('/jobs/'+identifier,this.controller.signal,async(response,signal)=>{
   if(response.status===409&&this.state.job?.job_id===identifier){
    this.invalidate(this.state.job);
    throw localError('The prepared output changed or is unavailable. Prepare a new set before using it.');
   }
   if(!response.ok)throw fail();const job=readLocalJob(await responseJSON(response,signal),identifier);
   if(this.invalidated.has(identifier))throw localError('This prepared set previously failed an integrity check. Prepare a new set before using it.');
   return job;
  });
 }
 private invalidate(job:LocalJob){this.invalidated.add(job.job_id);this.update({job:{...job,state:'BLOCKED',code:'PREPARED_OUTPUT_CHANGED',files:[]},reviewed:false,handedOff:false});}
 private async currentPrepared(){
  const original=this.state.job;if(!original||original.state!=='PREPARED_REVIEW_REQUIRED')throw fail();
  const current=await this.fetchStatus(original.job_id);
  if(current.state!=='PREPARED_REVIEW_REQUIRED'||membership(current)!==membership(original)){
   this.update({job:current,reviewed:false,handedOff:false});throw localError('The prepared output changed. Review a freshly prepared set before using it.');
  }
  return current;
 }
 private async output(job:LocalJob,identifier:string){
  const entry=job.files.find(file=>file.file_id===identifier);if(!entry||!fileId(identifier))throw fail();
  return request('/jobs/'+job.job_id+'/files/'+identifier,this.controller.signal,async(response,signal)=>{
   if(response.status===409){
    this.invalidate(job);
    throw localError('The prepared output changed or is unavailable. Prepare a new set before using it.');
   }
   if(!response.ok)throw fail();
   let raw:ArrayBuffer;
   try{raw=await boundedBytes(response,entry.bytes,signal);if(raw.byteLength!==entry.bytes||await sha256(raw)!==entry.sha256)throw fail();}
   catch{signal.throwIfAborted();this.invalidate(job);throw localError('A prepared file changed or is incomplete. Prepare a new set; nothing was handed off.');}
   signal.throwIfAborted();return new File([raw],entry.name,{type:entry.name===uploadManifestName?'application/json':'text/plain'});
  });
 }
 async download(identifier:string):Promise<File|null>{
  if(this.state.working||this.externalBusy)return null;
  this.update({working:true,error:'',notice:''});
  try{const file=await this.output(await this.currentPrepared(),identifier);return this.disposed?null:file;}
  catch(error){this.update({reviewed:false,error:message(error)});return null;}
  finally{this.update({working:false});}
 }
 async useReviewed(callback:(files:File[])=>Promise<boolean>){
  if(this.state.working||this.externalBusy||this.state.uncertain||!this.state.reviewed||this.state.handedOff)return;
  this.update({working:true,error:'',notice:''});
  try{const job=await this.currentPrepared();const files:File[]=[];
   const sidecar=job.files.find(file=>file.name===uploadManifestName)!;
   for(const entry of [sidecar,...job.files.filter(file=>file!==sidecar)])files.push(await this.output(job,entry.file_id));
   await checkSelectedSources(files,'prepared');
   const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await files[0].arrayBuffer()));
   if(manifest.extraction_job_id!==job.job_id)throw localError('The prepared manifest belongs to a different local job. Nothing was handed off.');
   // Re-read after all downloads; never use stale membership as approval.
   await this.currentPrepared();
   if(this.disposed||this.externalBusy)return;
   const accepted=await callback(files);
   this.update({reviewed:false,handedOff:accepted===true,notice:accepted===true?'Reviewed files handed back to FOX. Processing consent remains separate.':'The reviewed set was not used. The local job is retained; review and choose Use reviewed set again when ready.'});
  }catch(error){this.update({reviewed:false,error:message(error)});}
  finally{this.update({working:false});}
 }
}

export type LocalPreparationProps={busy:boolean;onUseReviewed:(files:File[])=>Promise<boolean>};
export function scheduleLocalPreparationPoll(session:LocalPreparationSession|null,state:PreparationState|null,busy:boolean){
 if(!session||!state||state.job?.state!=='RUNNING'||state.working||state.error||busy)return;
 const timer=setTimeout(()=>void session.refresh(),2000);return()=>clearTimeout(timer);
}
export function LocalPreparationView({state,busy,onSelect,onPrepare,onRefresh,onReview,onUse,onDownload}:{state:PreparationState;busy:boolean;onSelect:(files:File[])=>void;onPrepare:()=>void;onRefresh:()=>void;onReview:(value:boolean)=>void;onUse:()=>void;onDownload:(id:string)=>void}){
 if(!state.visible)return null;
 const locked=busy||state.working;const capabilities=state.capabilities,job=state.job;
 return <section className="panel" aria-label="Prepare source locally">
  <h2>Prepare source locally</h2>
  <p>Selected files stay in this authenticated localhost app during preparation. Nothing is uploaded to a hosted project or sent for conversion automatically.</p>
  {capabilities&&<><p>Readable files: {capabilities.readableFormats.join(', ')}. {capabilities.nativeFormats.length?'Native formats with installed tools: '+capabilities.nativeFormats.join(', ')+'.':'No native tools detected. Readable-file preparation is still available.'}</p>
   <p className="subtle">Installed-tool presence is not proof of compatibility, licensing entitlement or redaction approval. Review all readable output before using it.</p>
   <p className="subtle">Up to {capabilities.maxFiles} files · {capabilities.maxFileBytes/MiB} MB/file · {capabilities.maxSelectedBytes/MiB} MB selected. Prepared readable output must fit 5 MB/file and 25 MB total.</p>
   <label className="button secondary upload-button">Choose local source files<input aria-label="Choose local source files" type="file" multiple accept={[...capabilities.readableFormats,...capabilities.nativeFormats].join(',')} disabled={locked||job?.state==='RUNNING'||state.uncertain} onChange={event=>{onSelect(Array.from(event.target.files||[]));event.target.value='';}}/></label>
   {state.selected.length>0&&<ul>{state.selected.map(file=><li key={file.name}>{file.name} ({file.size.toLocaleString()} bytes)</li>)}</ul>}
   <button type="button" disabled={locked||!state.selected.length||job?.state==='RUNNING'||state.uncertain} onClick={onPrepare}>Prepare locally</button>
  </>}
  {job&&<div aria-live="polite"><p>Local job: <code>{job.job_id}</code></p>
   {job.state==='RUNNING'?<p>Preparing selected files locally. No upload or conversion has started.</p>:job.state==='BLOCKED'?<p>Preparation is blocked. {job.code==='PREPARED_OUTPUT_CHANGED'?'The retained output changed or is unavailable. Do not reuse it.':'No verified readable set is available. Check the selected source and installed tooling with the local operator.'}</p>:<>
    <h3>Verified readable output — review required</h3><p>Integrity checks match this prepared set. They do not establish safe redaction, complete dependencies or behavioral equivalence.</p>
    <p>{job.missing_dependency_count} candidate missing {job.missing_dependency_count===1?'dependency':'dependencies'} reported. Review these with the source owner.</p>
    <ul>{job.files.map(file=><li key={file.file_id}><strong>{file.name}</strong> ({file.bytes.toLocaleString()} bytes) <button className="secondary" type="button" disabled={locked} onClick={()=>onDownload(file.file_id)}>Download {file.name}</button><details><summary>File integrity</summary><code>{file.sha256}</code></details></li>)}</ul>
    <p>Use reviewed set uses the unchanged prepared bytes, not edited downloaded copies. If redaction or changes are needed, select those edited readable copies and prepare a new set. Do not reuse the old manifest.</p>
    <label className="acceptance-check"><input type="checkbox" checked={state.reviewed} disabled={locked||state.handedOff||state.uncertain} onChange={event=>onReview(event.target.checked)}/><span>I reviewed every readable output and confirm this set is authorized and appropriately redacted for use in FOX.</span></label>
    <button type="button" disabled={locked||!state.reviewed||state.handedOff||state.uncertain} onClick={onUse}>Use reviewed set</button>
    <p className="subtle">This is a source handoff only, not processing consent, technical verification or business acceptance.</p>
   </>}
   <button className="secondary" type="button" disabled={locked} onClick={onRefresh}>Check local status</button>
  </div>}
  {state.working&&<p role="status">Checking local preparation…</p>}
  {state.error&&<p role="alert">{state.error}</p>}{state.notice&&<p role="status">{state.notice}</p>}
 </section>;
}

export default function LocalPreparation({busy,onUseReviewed}:LocalPreparationProps){
 const [session,setSession]=useState<LocalPreparationSession|null>(null);
 const [state,setState]=useState<PreparationState|null>(null);
 useEffect(()=>{const next=new LocalPreparationSession(setState);setSession(next);setState(next.state);void next.initialize();return()=>next.dispose();},[]);
 if(session)session.externalBusy=busy;
 useEffect(()=>scheduleLocalPreparationPoll(session,state,busy),[session,state,busy]);
 if(!session||!state)return null;
 async function download(identifier:string){
  const file=await session!.download(identifier);if(!file)return;
  const url=URL.createObjectURL(file),link=document.createElement('a');link.href=url;link.download=file.name;link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
 }
 return <LocalPreparationView state={state} busy={busy} onSelect={files=>session.select(files)} onPrepare={()=>void session.prepare()} onRefresh={()=>void session.refresh()} onReview={value=>session.setReviewed(value)} onUse={()=>void session.useReviewed(onUseReviewed)} onDownload={identifier=>void download(identifier)}/>;
}
