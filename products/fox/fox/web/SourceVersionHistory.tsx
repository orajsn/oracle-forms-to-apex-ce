import React,{useEffect,useState} from 'react';
import {listSourceSets,inspectSourceSet,exportSourceSet,isSourceSetId,sourceSetDate,sourceSetOriginLabel,sourceFileName,sameSourceSet,pythonNameCompare,sourceHistoryErrorMessage,sourceHistoryRefreshRequired,
 type SourceSetMetadata,type SourceSetDetail,type SourceManifestFile,type SourceVersionActionResult} from './sourceVersionPresentation';

export type SourceVersionHistoryProps={
 projectId:string;selectedSourceSetId:string|null;currentSourceHash:string;busy:boolean;
 onUseVersion:(id:string,expected:string|null)=>Promise<SourceVersionActionResult>;
 onExcludeFile:(id:string,fileId:string,expected:string)=>Promise<SourceVersionActionResult>;
 onRefreshProject:()=>Promise<boolean>;
};
export type SourceHistoryViewState={items:SourceSetMetadata[];nextCursor:string|null;inspected:SourceSetDetail|null;
 manifestCursors:(string|null)[];manifestPageIndex:number;removal:{file:SourceManifestFile;confirmed:boolean}|null;loaded:boolean;working:boolean;refreshRequired:boolean;error:string;notice:string};
const initial=():SourceHistoryViewState=>({items:[],nextCursor:null,inspected:null,manifestCursors:[],manifestPageIndex:0,removal:null,loaded:false,working:false,refreshRequired:false,error:'',notice:''});
const conflict='The current source version changed. Refresh the project before choosing or removing files.';

// Testable interaction state; mutations remain in the parent's global busy flow.
export class SourceHistorySession{
 state=initial();externalBusy=false;
 private readonly controller=new AbortController();private disposed=false;
 constructor(readonly projectId:string,readonly currentId:string|null,readonly currentHash:string,private changed:(value:SourceHistoryViewState)=>void){}
 private update(patch:Partial<SourceHistoryViewState>){if(!this.disposed){this.state={...this.state,...patch};this.changed(this.state);}}
 dispose(){this.disposed=true;this.controller.abort();}
 private mismatch(){this.update({refreshRequired:true,error:conflict,removal:null});}
 private known(id:string){return this.state.items.some(item=>item.id===id)||this.state.inspected?.source_set.id===id||id===this.currentId;}
 private async page(older:boolean){
  const before=older?this.state.nextCursor:null;if(older&&!before)return;
  const value=await listSourceSets(this.projectId,before,this.controller.signal);
  if(value.selected_source_set_id!==this.currentId||value.source_sets.some(item=>item.is_selected&&item.source_hash!==this.currentHash)){this.mismatch();return;}
  if(older&&(value.source_sets.some(item=>this.state.items.some(old=>old.id===item.id))||value.next_cursor===before)){this.mismatch();return;}
  const items=older?[...this.state.items,...value.source_sets]:value.source_sets;
  if(value.next_cursor===null&&this.currentId&&!items.some(item=>item.id===this.currentId)){this.mismatch();return;}
  this.update({items,nextCursor:value.next_cursor,loaded:true,refreshRequired:false,
   ...(older?{}:{inspected:null,manifestCursors:[],manifestPageIndex:0,removal:null})});
 }
 async load(older=false){
  if(this.disposed||this.state.working||(older&&(this.externalBusy||this.state.refreshRequired)))return;
  this.update({working:true,error:'',notice:''});
  try{await this.page(older);}catch(error){this.update({error:sourceHistoryErrorMessage(error),refreshRequired:sourceHistoryRefreshRequired(error)});}
  finally{this.update({working:false});}
 }
 private async loadManifest(id:string,after:string|null,offset:number,index:number,reset:boolean){
  if(this.disposed||this.state.working||this.externalBusy||this.state.refreshRequired||!this.known(id)||!isSourceSetId(id))return;
  this.update({working:true,error:'',notice:'',removal:null});
  try{const value=await inspectSourceSet(this.projectId,id,this.controller.signal,after,offset);
   const previous=this.state.items.find(item=>item.id===id);
   if(value.selected_source_set_id!==this.currentId||(id===this.currentId&&value.source_set.source_hash!==this.currentHash)
    ||(previous&&!sameSourceSet(previous,value.source_set))){this.mismatch();return;}
   const shown=this.state.inspected;
   if(!reset&&(!shown||shown.source_set.id!==id||!sameSourceSet(shown.source_set,value.source_set)
    ||(index>this.state.manifestPageIndex&&(pythonNameCompare(shown.files.at(-1)!.name,value.files[0].name)>=0||value.files.some(file=>shown.files.some(old=>old.id===file.id||old.name===file.name))))
    ||value.files_page.next_cursor!==null&&this.state.manifestCursors.slice(0,index+1).includes(value.files_page.next_cursor))){this.mismatch();return;}
   const cursors=reset?[null]:[...this.state.manifestCursors.slice(0,index),after];
   this.update({inspected:value,manifestCursors:cursors,manifestPageIndex:index});
  }catch(error){this.update({error:sourceHistoryErrorMessage(error),refreshRequired:sourceHistoryRefreshRequired(error)});}
  finally{this.update({working:false});}
 }
 async inspect(id:string){await this.loadManifest(id,null,0,0,true);}
 async manifestNext(){
  const shown=this.state.inspected;if(!shown||shown.files_page.next_cursor===null)return;
  await this.loadManifest(shown.source_set.id,shown.files_page.next_cursor,shown.files_page.offset+shown.files.length,this.state.manifestPageIndex+1,false);
 }
 async manifestPrevious(){
  const shown=this.state.inspected,index=this.state.manifestPageIndex-1;if(!shown||index<0||index>=this.state.manifestCursors.length)return;
  await this.loadManifest(shown.source_set.id,this.state.manifestCursors[index],index*50,index,false);
 }
 closeManifest(){if(!this.state.working&&!this.externalBusy)this.update({inspected:null,manifestCursors:[],manifestPageIndex:0,removal:null});}
 beginRemoval(id:string){
  const detail=this.state.inspected;if(this.disposed||this.state.working||this.externalBusy||this.state.refreshRequired||!detail||detail.source_set.id!==this.currentId||!detail.source_set.is_selected)return;
  const file=detail.files.find(item=>item.id===id);if(!file)return;
  if(detail.source_set.file_count===1){this.update({error:'Upload a replacement before removing the only readable file.'});return;}
  this.update({removal:{file,confirmed:false},error:'',notice:''});
 }
 confirmRemoval(value:boolean){if(this.state.removal&&!this.state.working&&!this.externalBusy&&!this.state.refreshRequired)this.update({removal:{...this.state.removal,confirmed:value}});}
 cancelRemoval(){if(!this.state.working&&!this.externalBusy)this.update({removal:null});}
 private async action(callback:()=>Promise<SourceVersionActionResult>){
  this.update({working:true,error:'',notice:'',removal:null});
  try{const result=await callback();
   if(result?.ok===true)this.update({notice:'The current source set was updated. Review its assessment and confirm processing separately.',refreshRequired:true});
   else this.update({error:result?.refreshRequired===false?'The source change was not made. Review the project message before trying again.':'The source change was not confirmed. Reopen the project to refresh it before trying again.',refreshRequired:result?.refreshRequired!==false});
  }catch{this.update({error:'The source change was not confirmed. Reopen the project to refresh it before trying again.',refreshRequired:true});}
  finally{this.update({working:false});}
 }
 async useVersion(id:string,callback:SourceVersionHistoryProps['onUseVersion']){
  if(this.disposed||this.state.working||this.externalBusy||this.state.refreshRequired||!isSourceSetId(id)||!this.known(id)||id===this.currentId)return;
  await this.action(()=>callback(id,this.currentId));
 }
 async remove(callback:SourceVersionHistoryProps['onExcludeFile']){
  const removal=this.state.removal,detail=this.state.inspected;
  if(this.disposed||this.state.working||this.externalBusy||this.state.refreshRequired||!removal?.confirmed||!detail||detail.source_set.id!==this.currentId||!this.currentId||detail.source_set.file_count<=1||!detail.files.some(file=>file.id===removal.file.id))return;
  await this.action(()=>callback(detail.source_set.id,removal.file.id,this.currentId!));
 }
 async refresh(callback:()=>Promise<boolean>){
  if(this.disposed||this.state.working||this.externalBusy)return;this.update({working:true,error:'',notice:'',removal:null});
  try{if(await callback()!==true){this.update({error:'The project could not be refreshed. Reopen it before changing source versions.',refreshRequired:true});return;}
   if(!this.disposed)await this.page(false);
  }catch{this.update({error:'The project could not be refreshed. Reopen it before changing source versions.',refreshRequired:true});}
  finally{this.update({working:false});}
 }
 async download(id:string){
  if(this.disposed||this.state.working||this.externalBusy||!isSourceSetId(id)||!this.known(id))return null;
  this.update({working:true,error:'',notice:''});
  try{const result=await exportSourceSet(this.projectId,id,this.controller.signal);return this.disposed?null:result;}
  catch(error){this.update({error:sourceHistoryErrorMessage(error),refreshRequired:this.state.refreshRequired||sourceHistoryRefreshRequired(error)});return null;}
  finally{this.update({working:false});}
 }
}

type ViewProps={state:SourceHistoryViewState;currentId:string|null;currentHash:string;busy:boolean;
 onInspect:(id:string)=>void;onUse:(id:string)=>void;onExport:(id:string)=>void;onOlder:()=>void;onRefresh:()=>void;onClose:()=>void;
 onManifestNext:()=>void;onManifestPrevious:()=>void;onBeginRemoval:(id:string)=>void;onConfirmRemoval:(value:boolean)=>void;onCancelRemoval:()=>void;onRemove:()=>void};
export function SourceVersionHistoryView(props:ViewProps){
 const {state,currentId,currentHash,busy}=props,locked=busy||state.working,changeLocked=locked||state.refreshRequired,detail=state.inspected;
 return <section className="panel" aria-label="Saved source versions">
  <div className="section-heading"><h2>Saved source versions</h2><button type="button" className="secondary" disabled={locked} onClick={props.onRefresh}>Refresh project</button></div>
  <p>Each saved version lists a complete readable source set. Choosing one changes the current assessment only; it does not process source, restore confirmations or change saved runs and proofs.</p>
  <p className="subtle">Choosing or removing a file clears pending upload/preparation selections and processing confirmations. Original files and saved versions remain available.</p>
  <p className="manifest">{state.refreshRequired?'Last loaded project source hash':'Current source hash'}: <code>{/^[a-f0-9]{64}(?![\s\S])/.test(currentHash)?currentHash:'Unavailable — refresh the project'}</code></p>
  {state.loaded&&state.items.length===0&&<p>No saved source versions yet. Upload readable source to save the first complete set.</p>}
  {state.items.map(item=><article className="finding" key={item.id} aria-label={'Source version '+item.id}>
   <div className="section-heading"><strong>{sourceSetOriginLabel(item.origin)}</strong>{item.is_selected&&<span className="badge">{state.refreshRequired?'Current — refresh needed':'Current'}</span>}</div>
   <p><time dateTime={new Date(item.created*1000).toISOString()}>{sourceSetDate(item.created)}</time> · {item.file_count} {item.file_count===1?'file':'files'} · {item.source_bytes.toLocaleString()} bytes</p>
   <p className="manifest">Source-set SHA-256 <code>{item.source_hash}</code></p>
   {item.origin==='legacy-current'&&<p className="subtle">Captured from the current source set when version history was introduced. Earlier complete versions are not reconstructed from old per-file history.</p>}
   {item.run_ids.length>0&&<p className="subtle">{item.run_ids.length} linked saved {item.run_ids.length===1?'run':'runs'}. Its verification and business acceptance remain separate.</p>}
   <button type="button" className="secondary" disabled={changeLocked} onClick={()=>props.onInspect(item.id)}>Inspect manifest</button>{' '}
   <button type="button" disabled={changeLocked||item.is_selected} onClick={()=>props.onUse(item.id)}>Use this version</button>{' '}
   <button type="button" className="secondary" disabled={locked} onClick={()=>props.onExport(item.id)}>Export readable source</button>
  </article>)}
  {state.loaded&&!state.refreshRequired&&state.nextCursor&&currentId&&!state.items.some(item=>item.id===currentId)&&<p>The current version is on an older page. <button type="button" className="secondary" disabled={changeLocked} onClick={()=>props.onInspect(currentId)}>Inspect current version</button></p>}
  {state.nextCursor?<button type="button" className="secondary" disabled={changeLocked} onClick={props.onOlder}>Load older versions</button>:state.loaded&&!state.refreshRequired&&state.items.length>0&&<p className="subtle">All saved versions have been listed.</p>}
  {detail&&<section className="finding" aria-label="Readable source manifest">
   <div className="section-heading"><h3>Readable source manifest</h3><button type="button" className="secondary" disabled={locked} onClick={props.onClose}>Close manifest</button></div>
   <p>{sourceSetOriginLabel(detail.source_set.origin)} · {detail.source_set.file_count} files{detail.source_set.is_selected?(state.refreshRequired?' · Current at last load — refresh needed':' · Current version'):''}</p>
   {detail.source_set.origin==='legacy-current'&&<p className="subtle">This is the legacy current set captured when version history was introduced, not a reconstruction of earlier complete versions.</p>}
   <p className="manifest">Complete source-set SHA-256 <code>{detail.source_set.source_hash}</code></p>
   <p>Showing files {detail.files_page.offset+1}–{detail.files_page.offset+detail.files.length} of {detail.files_page.total}.</p>
   <p className="subtle">The server checks the complete saved set. This view displays one manifest page; its files alone do not establish the complete source-set hash. Source checks are not processing permission, technical verification or business acceptance.</p>
   <ul>{detail.files.map(file=><li key={file.id}><strong>{sourceFileName(file.name)}</strong> · {file.bytes.toLocaleString()} bytes<p className="manifest"><code>{file.sha256}</code></p>
    {detail.source_set.is_selected&&<button type="button" className="secondary" disabled={changeLocked||detail.source_set.file_count===1} onClick={()=>props.onBeginRemoval(file.id)}>Remove from current version</button>}
   </li>)}</ul>
   <button type="button" className="secondary" disabled={changeLocked||state.manifestPageIndex===0} onClick={props.onManifestPrevious}>Previous files</button>{' '}
   <button type="button" className="secondary" disabled={changeLocked||detail.files_page.next_cursor===null} onClick={props.onManifestNext}>Next files</button>
   {detail.source_set.is_selected&&detail.source_set.file_count===1&&<p className="subtle">Upload a replacement before removing the only readable file.</p>}
   {state.removal&&<div role="group" aria-label="Confirm source-set change"><p>Use a source set without <strong>{sourceFileName(state.removal.file.name)}</strong>? The original version and its file stay saved.</p>
    <label className="acceptance-check"><input type="checkbox" checked={state.removal.confirmed} disabled={changeLocked} onChange={event=>props.onConfirmRemoval(event.target.checked)}/><span>I confirm this file should be excluded from the current source set, not erased from history.</span></label>
    <button type="button" disabled={changeLocked||!state.removal.confirmed} onClick={props.onRemove}>Confirm removal from current version</button>{' '}<button type="button" className="secondary" disabled={locked} onClick={props.onCancelRemoval}>Cancel</button>
   </div>}
  </section>}
  <p className="subtle">Readable export contains the saved source files and integrity metadata only. It is not an APEX package, processing approval or an import-ready artifact. Unpack readable files for reuse.</p>
  {state.working&&<p role="status">Loading or updating source history…</p>}{state.error&&<p role="alert">{state.error}</p>}{state.notice&&<p role="status">{state.notice}</p>}
 </section>;
}

export default function SourceVersionHistory(props:SourceVersionHistoryProps){
 const [session,setSession]=useState<SourceHistorySession|null>(null),[state,setState]=useState<SourceHistoryViewState>(initial);
 useEffect(()=>{const next=new SourceHistorySession(props.projectId,props.selectedSourceSetId,props.currentSourceHash,setState);setSession(next);setState(next.state);void next.load();return()=>next.dispose();},[props.projectId,props.selectedSourceSetId,props.currentSourceHash]);
 const contextual=session?.projectId===props.projectId&&session?.currentId===props.selectedSourceSetId&&session?.currentHash===props.currentSourceHash;
 if(session)session.externalBusy=props.busy||!contextual;
 async function download(id:string){if(!session||!contextual)return;const value=await session.download(id);if(!value)return;const url=URL.createObjectURL(value.blob),anchor=document.createElement('a');anchor.href=url;anchor.download=value.filename;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
 return <SourceVersionHistoryView state={state} currentId={props.selectedSourceSetId} currentHash={props.currentSourceHash} busy={props.busy||!contextual}
  onInspect={id=>void session?.inspect(id)} onUse={id=>void session?.useVersion(id,props.onUseVersion)} onExport={id=>void download(id)}
  onOlder={()=>void session?.load(true)} onRefresh={()=>void session?.refresh(props.onRefreshProject)} onClose={()=>session?.closeManifest()}
  onManifestNext={()=>void session?.manifestNext()} onManifestPrevious={()=>void session?.manifestPrevious()}
  onBeginRemoval={id=>session?.beginRemoval(id)} onConfirmRemoval={value=>session?.confirmRemoval(value)} onCancelRemoval={()=>session?.cancelRemoval()} onRemove={()=>void session?.remove(props.onExcludeFile)}/>;
}
