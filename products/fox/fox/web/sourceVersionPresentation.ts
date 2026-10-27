// Candidate presentation/client contract only. No active FOX source is changed.
const maxSourceBytes=100*1024*1024, maxJSONBytes=2*1024*1024, maxExportBytes=maxSourceBytes+8*1024*1024;
const setPattern=/^ss-[a-f0-9]{32}(?![\s\S])/;
const projectPattern=/^[a-f0-9]{32}(?![\s\S])/;
const hashPattern=/^[a-f0-9]{64}(?![\s\S])/;
const object=(value:unknown):value is Record<string,unknown>=>typeof value==='object'&&value!==null&&!Array.isArray(value);
const fields=(value:unknown,names:string[]):value is Record<string,unknown>=>object(value)&&Object.keys(value).sort().join('|')===names.slice().sort().join('|');
const integer=(value:unknown,min:number,max:number):value is number=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=min&&value<=max;
export const isSourceSetId=(value:unknown):value is string=>typeof value==='string'&&setPattern.test(value);
const pointer=(value:unknown):value is string|null=>value===null||isSourceSetId(value);
const hash=(value:unknown):value is string=>typeof value==='string'&&hashPattern.test(value);
const fileId=(value:unknown):value is string=>typeof value==='string'&&value.length>=1&&Array.from(value).length<=128&&!/[\u0000-\u001f\u007f]/.test(value)
 &&!Array.from(value).some(character=>{const point=character.codePointAt(0)!;return point>=0xd800&&point<=0xdfff;});
const readableName=(value:unknown):value is string=>typeof value==='string'&&value.length>=1&&Array.from(value).length<=180
 &&!/[\\/:\u0000-\u001f]/.test(value)&&!value.includes('..')&&/\.(xml|pld|sql|pks|pkb|txt)$/i.test(value)
 &&!Array.from(value).some(character=>{const point=character.codePointAt(0)!;return point>=0xd800&&point<=0xdfff;});

export type SourceSetMetadata={id:string;source_hash:string;file_count:number;source_bytes:number;created:number;origin:'upload'|'legacy-current'|'exclude';is_selected:boolean;run_ids:string[]};
export type SourceSetPage={selected_source_set_id:string|null;source_sets:SourceSetMetadata[];next_cursor:string|null};
export type SourceManifestFile={id:string;name:string;sha256:string;bytes:number};
export type SourceAssessmentSummary={source_hash:string;conversion_profile:'native-project-v1'|'native-table-form-v1'|'legacy-html-prototype-v1'|'unconfigured';source_checks_passed:boolean;file_count:number;source_bytes:number;conversion_source_bytes:number;max_conversion_bytes:300000;max_conversion_files:50;missing_dependency_count:number;assessment_finding_count:number;conversion_blocker_count:number;blocker_codes:string[];native_state:'READY'|'BLOCKED'|null};
export type SourceFilesPage={offset:number;limit:50;total:number;next_cursor:string|null};
export type SourceSetDetail={selected_source_set_id:string|null;source_set:SourceSetMetadata;files:SourceManifestFile[];files_page:SourceFilesPage;assessment_summary:SourceAssessmentSummary};
export type SourceSelectionAck={selectedSourceSetId:string;sourceHash:string;selectionChanged:boolean;sourceSet:SourceSetMetadata};
export type SourceVersionActionResult={ok:boolean;refreshRequired:boolean};

class SourceHistoryError extends Error{
 constructor(message:string,readonly refreshRequired=false,readonly status:number|null=null){super(message);}
}
const invalid=()=>new SourceHistoryError('Saved source history could not be verified. Refresh the project before choosing a version.',true);
export function sourceHistoryErrorMessage(error:unknown){return error instanceof SourceHistoryError?error.message:'Source history could not be confirmed. Reopen the project to refresh it before trying again.';}
export function sourceHistoryRefreshRequired(error:unknown){return !(error instanceof SourceHistoryError)||error.refreshRequired;}
export function sourceSetOriginLabel(origin:SourceSetMetadata['origin']){
 return origin==='legacy-current'?'Legacy current set, captured':origin==='exclude'?'Saved without selected files':'Saved after upload';
}
export function sourceSetDate(value:number){return new Date(value*1000).toISOString().replace('T',' ').slice(0,19)+' UTC';}
export function sourceFileName(value:string){return value.replace(/\u007f/g,'⟪U+007F⟫');}
export function sameSourceSet(left:SourceSetMetadata,right:SourceSetMetadata){
 return (['id','source_hash','file_count','source_bytes','created','origin','is_selected'] as const).every(key=>left[key]===right[key])
  &&left.run_ids.length===right.run_ids.length&&left.run_ids.every((id,index)=>id===right.run_ids[index]);
}

function metadata(value:unknown,selected:string|null):SourceSetMetadata{
 if(!fields(value,['id','source_hash','file_count','source_bytes','created','origin','is_selected','run_ids'])||!isSourceSetId(value.id)||!hash(value.source_hash)
  ||!integer(value.source_bytes,1,maxSourceBytes)||!integer(value.file_count,1,value.source_bytes)
  ||typeof value.created!=='number'||!Number.isFinite(value.created)||value.created<0||value.created>253402300799
  ||typeof value.origin!=='string'||!['upload','legacy-current','exclude'].includes(value.origin)
  ||typeof value.is_selected!=='boolean'||value.is_selected!==(value.id===selected)
  ||!Array.isArray(value.run_ids)||value.run_ids.length>1||value.run_ids.some(id=>!fileId(id)))throw invalid();
 return {id:value.id,source_hash:value.source_hash,file_count:value.file_count,source_bytes:value.source_bytes,created:value.created,
  origin:value.origin as SourceSetMetadata['origin'],is_selected:value.is_selected,run_ids:[...value.run_ids] as string[]};
}
export function parseSourceSetPage(value:unknown):SourceSetPage{
 if(!fields(value,['selected_source_set_id','source_sets','next_cursor'])||!pointer(value.selected_source_set_id)||!pointer(value.next_cursor)
  ||!Array.isArray(value.source_sets)||value.source_sets.length>50)throw invalid();
 const source_sets=value.source_sets.map(item=>metadata(item,value.selected_source_set_id as string|null));
 if(new Set(source_sets.map(item=>item.id)).size!==source_sets.length||(value.selected_source_set_id===null&&source_sets.length)
  ||(value.next_cursor!==null&&source_sets.at(-1)?.id!==value.next_cursor))throw invalid();
 return {selected_source_set_id:value.selected_source_set_id,source_sets,next_cursor:value.next_cursor};
}
export function pythonNameCompare(a:string,b:string){
 const left=Array.from(a),right=Array.from(b);for(let index=0;index<Math.min(left.length,right.length);index++){
  const difference=left[index].codePointAt(0)!-right[index].codePointAt(0)!;if(difference)return difference;
 }return left.length-right.length;
}
export async function readableManifestHash(files:SourceManifestFile[]){
 const lines=files.slice().sort((a,b)=>pythonNameCompare(a.name,b.name)).map(file=>file.name+':'+file.sha256).join('\n');
 return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(lines))),byte=>byte.toString(16).padStart(2,'0')).join('');
}
function assessmentMatches(value:unknown,selected:string,sourceHash:string){
 return object(value)&&value.selected_source_set_id===selected&&value.source_hash===sourceHash;
}
function assessmentSummary(value:unknown,summary:SourceSetMetadata):SourceAssessmentSummary{
 if(!fields(value,['source_hash','conversion_profile','source_checks_passed','file_count','source_bytes','conversion_source_bytes','max_conversion_bytes','max_conversion_files','missing_dependency_count','assessment_finding_count','conversion_blocker_count','blocker_codes','native_state'])
  ||value.source_hash!==summary.source_hash||value.file_count!==summary.file_count||value.source_bytes!==summary.source_bytes
  ||!['native-project-v1','native-table-form-v1','legacy-html-prototype-v1','unconfigured'].includes(value.conversion_profile as string)
  ||typeof value.source_checks_passed!=='boolean'||!integer(value.conversion_source_bytes,0,summary.source_bytes)
  ||value.max_conversion_bytes!==300000||value.max_conversion_files!==50
  ||!integer(value.missing_dependency_count,0,Number.MAX_SAFE_INTEGER)||!integer(value.assessment_finding_count,0,Number.MAX_SAFE_INTEGER)||!integer(value.conversion_blocker_count,0,Number.MAX_SAFE_INTEGER)
  ||!Array.isArray(value.blocker_codes)||value.blocker_codes.length>64||value.blocker_codes.some(code=>typeof code!=='string'||!/^[A-Z][A-Z0-9_]{0,63}(?![\s\S])/.test(code))
  ||new Set(value.blocker_codes).size!==value.blocker_codes.length||value.blocker_codes.some((code,index,all)=>index>0&&all[index-1]>=code)
  ||!(value.native_state===null||value.native_state==='READY'||value.native_state==='BLOCKED'))throw invalid();
 return {...value,blocker_codes:[...value.blocker_codes]} as SourceAssessmentSummary;
}
export async function parseSourceSetDetail(value:unknown,requested:string,expectedOffset=0):Promise<SourceSetDetail>{
 if(!isSourceSetId(requested)||!integer(expectedOffset,0,maxSourceBytes)||!fields(value,['selected_source_set_id','source_set','files','files_page','assessment_summary'])||!pointer(value.selected_source_set_id)||!Array.isArray(value.files))throw invalid();
 const summary=metadata(value.source_set,value.selected_source_set_id);
 const page=value.files_page;
 if(summary.id!==requested||!fields(page,['offset','limit','total','next_cursor'])||page.offset!==expectedOffset||page.offset>=summary.file_count||page.limit!==50||page.total!==summary.file_count
  ||!(page.next_cursor===null||fileId(page.next_cursor))||value.files.length!==Math.min(50,summary.file_count-expectedOffset))throw invalid();
 const files:SourceManifestFile[]=value.files.map(item=>{
  if(!fields(item,['id','name','sha256','bytes'])||!fileId(item.id)||!readableName(item.name)||!hash(item.sha256)||!integer(item.bytes,1,5*1024*1024))throw invalid();
  return {id:item.id,name:item.name,sha256:item.sha256,bytes:item.bytes};
 });
 const bytes=files.reduce((sum,file)=>sum+file.bytes,0),terminal=expectedOffset+files.length===summary.file_count;
 if(new Set(files.map(file=>file.id)).size!==files.length||new Set(files.map(file=>file.name)).size!==files.length
  ||files.some((file,index)=>index>0&&pythonNameCompare(files[index-1].name,file.name)>=0)
  ||bytes>summary.source_bytes||(terminal?page.next_cursor!==null:page.next_cursor!==files.at(-1)?.id))throw invalid();
 // Only a one-page manifest is complete in this response. Multi-page integrity
 // is checked by the authenticated backend; never hash a subset as the full set.
 if(expectedOffset===0&&terminal&&(bytes!==summary.source_bytes||await readableManifestHash(files)!==summary.source_hash))throw invalid();
 return {selected_source_set_id:value.selected_source_set_id,source_set:summary,files,files_page:{offset:expectedOffset,limit:50,total:summary.file_count,next_cursor:page.next_cursor as string|null},assessment_summary:assessmentSummary(value.assessment_summary,summary)};
}
export function parseSourceSelection(value:unknown):SourceSelectionAck{
 if(!fields(value,['selected_source_set_id','source_set','assessment_summary','selection_changed'])||!isSourceSetId(value.selected_source_set_id)||typeof value.selection_changed!=='boolean')throw invalid();
 const summary=metadata(value.source_set,value.selected_source_set_id);
 if(summary.id!==value.selected_source_set_id||!summary.is_selected)throw invalid();assessmentSummary(value.assessment_summary,summary);
 return {selectedSourceSetId:summary.id,sourceHash:summary.source_hash,selectionChanged:value.selection_changed,sourceSet:summary};
}
export function assertRefreshedSourceProject(value:unknown,projectId:string,ack:SourceSelectionAck){
 if(!object(value)||value.id!==projectId||!assessmentMatches(value.inventory,ack.selectedSourceSetId,ack.sourceHash))throw invalid();
}

async function interrupted<T>(promise:Promise<T>,signal:AbortSignal):Promise<T>{
 let abort=()=>{};const stopped=new Promise<never>((_,reject)=>{abort=()=>reject(signal.reason);if(signal.aborted)abort();else signal.addEventListener('abort',abort,{once:true});});
 try{return await Promise.race([promise,stopped]);}finally{signal.removeEventListener('abort',abort);}
}
async function bodyBytes(response:Response,maximum:number,signal:AbortSignal){
 signal.throwIfAborted();const length=response.headers.get('content-length');
 if(length!==null&&(!/^[0-9]+$/.test(length)||Number(length)>maximum))throw invalid();
 if(!response.body)throw invalid();const reader=response.body.getReader(),parts:Uint8Array[]=[];let total=0;
 const cancel=()=>{void reader.cancel(signal.reason).catch(()=>{});};signal.addEventListener('abort',cancel,{once:true});
 try{while(true){const next=await interrupted(reader.read(),signal);signal.throwIfAborted();if(next.done)break;total+=next.value.length;if(total>maximum)throw invalid();parts.push(next.value);}}
 catch(error){cancel();throw error;}finally{signal.removeEventListener('abort',cancel);reader.releaseLock();}
 const result=new Uint8Array(total);let offset=0;for(const part of parts){result.set(part,offset);offset+=part.length;}return result.buffer;
}
async function jsonBody(response:Response,signal:AbortSignal,maximum=maxJSONBytes){
 const text=new TextDecoder('utf-8',{fatal:true}).decode(await bodyBytes(response,maximum,signal));
 const stack:(Set<string>|null)[]=[];for(const token of text.matchAll(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]]/g)){
  const part=token[0];if(part==='{'||part==='['){stack.push(part==='{'?new Set():null);if(stack.length>20)throw invalid();}
  else if(part==='}'||part===']'){if(!stack.length)throw invalid();stack.pop();}
  else if(/^\s*:/.test(text.slice(token.index!+part.length))){const keys=stack[stack.length-1],key=JSON.parse(part);if(!keys||keys.has(key))throw invalid();keys.add(key);}
 }return JSON.parse(text) as unknown;
}
type Operation='read'|'select'|'exclude'|'export';
const responseLimitMessage='Source history could not be displayed within the response limit. No source version was changed. Refresh or ask the operator for help.';
const exportLimitMessage='This source version is too large for one readable export. Its files remain saved; use a smaller coherent version or ask the operator for an approved export.';
function failure(status:number,operation:Operation){
 if(status===401)return new SourceHistoryError('Sign in again to view saved source versions.',false,status);
 if(status===403)return new SourceHistoryError('You do not have access to this source history.',false,status);
 if(status===404)return new SourceHistoryError('This source version is not available for this project.',true,status);
 if(status===409&&operation==='export')return new SourceHistoryError('This version could not be exported safely. No file was downloaded.',false,status);
 if(status===409)return new SourceHistoryError('The saved source selection changed or could not be verified. Refresh the project before choosing a version.',true,status);
 if(status===422)return new SourceHistoryError(operation==='exclude'?'Choose a current file and keep at least one readable file. Upload a replacement first if needed.':'The source version selection was not valid. Refresh the project before trying again.',true,status);
 return new SourceHistoryError('Source history could not be confirmed. Reopen the project to refresh it before trying again.',true,status);
}
async function responseFailure(response:Response,operation:Operation,signal:AbortSignal){
 if(response.status===409){
  try{const value=await jsonBody(response,signal,4096);
   if(fields(value,['code','detail'])){
    if(value.code==='SOURCE_HISTORY_RESPONSE_TOO_LARGE'&&value.detail===responseLimitMessage&&operation!=='export')return new SourceHistoryError(responseLimitMessage,true,409);
    if(value.code==='SOURCE_HISTORY_EXPORT_TOO_LARGE'&&value.detail===exportLimitMessage&&operation==='export')return new SourceHistoryError(exportLimitMessage,false,409);
   }
  }catch{signal.throwIfAborted();}
 }
 return failure(response.status,operation);
}
async function request<T>(projectId:string,suffix:string,operation:Operation,consume:(response:Response,signal:AbortSignal)=>Promise<T>,body?:unknown,outer?:AbortSignal):Promise<T>{
 if(!projectPattern.test(projectId)||!/^\/(?:source-sets)(?:\?before=ss-[a-f0-9]{32}|\/ss-[a-f0-9]{32}(?:\/(?:select|exclude|download)|\?files_after=[A-Za-z0-9%+_.!~*'()-]+)?)?(?![\s\S])/.test(suffix))throw invalid();
 outer?.throwIfAborted();const controller=new AbortController(),signal=controller.signal;
 const abort=()=>controller.abort(outer?.reason);outer?.addEventListener('abort',abort,{once:true});
 const timer=setTimeout(()=>controller.abort(new SourceHistoryError(operation==='select'||operation==='exclude'?'The source change outcome could not be confirmed. Reopen the project before trying again.':'Source history is taking longer than expected. Refresh the project to try again.',true)),15000);
 let response:Response|undefined;
 try{
  const pending=fetch('/api/projects/'+projectId+suffix,{method:body===undefined?'GET':'POST',body:body===undefined?undefined:JSON.stringify(body),headers:body===undefined?undefined:{'Content-Type':'application/json'},credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal})
   .then(value=>{if(signal.aborted){void value.body?.cancel().catch(()=>{});signal.throwIfAborted();}return value;});
  response=await interrupted(pending,signal);if(response.redirected)throw invalid();if(!response.ok)throw await interrupted(responseFailure(response,operation,signal),signal);
  signal.throwIfAborted();const value=await interrupted(consume(response,signal),signal);signal.throwIfAborted();return value;
 }catch(error){if(error instanceof SourceHistoryError)throw error;throw new SourceHistoryError('Source history could not be confirmed. Reopen the project to refresh it before trying again.',true);}
 finally{clearTimeout(timer);outer?.removeEventListener('abort',abort);if(response?.body&&!response.bodyUsed&&!response.body.locked)void response.body.cancel().catch(()=>{});}
}
export async function listSourceSets(projectId:string,before:string|null=null,signal?:AbortSignal){
 if(!pointer(before))throw invalid();return request(projectId,'/source-sets'+(before?'?before='+encodeURIComponent(before):''),'read',async(response,signal)=>parseSourceSetPage(await jsonBody(response,signal)),undefined,signal);
}
export async function inspectSourceSet(projectId:string,id:string,signal?:AbortSignal,after:string|null=null,expectedOffset=0){
 if(!isSourceSetId(id)||!(after===null||fileId(after))||!integer(expectedOffset,0,maxSourceBytes)||(after===null)!==(expectedOffset===0))throw invalid();
 return request(projectId,'/source-sets/'+id+(after===null?'':'?files_after='+encodeURIComponent(after)),'read',async(response,signal)=>parseSourceSetDetail(await jsonBody(response,signal),id,expectedOffset),undefined,signal);
}
export async function selectSourceSet(projectId:string,id:string,expected:string|null){
 if(!isSourceSetId(id)||!pointer(expected))throw invalid();const result=await request(projectId,'/source-sets/'+id+'/select','select',async(response,signal)=>parseSourceSelection(await jsonBody(response,signal)),{expected_current_source_set_id:expected});
 if(result.selectedSourceSetId!==id)throw invalid();return result;
}
export async function excludeSourceFile(projectId:string,id:string,excludedFileId:string,expected:string){
 if(!isSourceSetId(id)||expected!==id||!fileId(excludedFileId))throw invalid();const result=await request(projectId,'/source-sets/'+id+'/exclude','exclude',async(response,signal)=>parseSourceSelection(await jsonBody(response,signal)),{expected_current_source_set_id:expected,excluded_file_ids:[excludedFileId]});
 if(result.selectedSourceSetId===id||!result.selectionChanged)throw invalid();return result;
}
export async function exportSourceSet(projectId:string,id:string,signal?:AbortSignal){
 if(!isSourceSetId(id))throw invalid();return request(projectId,'/source-sets/'+id+'/download','export',async(response,signal)=>{
  if(response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/zip')throw invalid();
  const raw=await bodyBytes(response,maxExportBytes,signal),magic=new Uint8Array(raw,0,Math.min(raw.byteLength,4));
  if(magic.length!==4||magic[0]!==80||magic[1]!==75||magic[2]!==3||magic[3]!==4)throw invalid();
  return {blob:new Blob([raw],{type:'application/zip'}),filename:'fox-source-set-'+id+'.zip'};
 },undefined,signal);
}
