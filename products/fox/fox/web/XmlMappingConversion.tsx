import React,{useEffect,useRef,useState} from 'react';
import type {SourceBinding} from './projectConversion';
import {activeMapping,mappingCount,mappingLabel,safeDownload,parseOverview,parseRun,mappingStorageKey,type MappingOverview,type MappingRun} from './xmlMappingPresentation';
import './xmlMapping.css';
import XmlMappingDiscrepancies from './XmlMappingDiscrepancies';

type Props={projectId:string;source:SourceBinding;busy:boolean;outputOnly?:boolean;onFenceChange?:(fenced:boolean)=>void};
const DEADLINE_MS=8000;
class MappingHttpError extends Error {
 constructor(readonly notAdmitted:boolean){super('Mapping request rejected');}
}
async function requestJson(url:string,init:RequestInit={}):Promise<unknown>{
 const controller=new AbortController();let timeout:ReturnType<typeof setTimeout>;
 try{return await Promise.race([fetch(url,{...init,credentials:'same-origin',redirect:'error',signal:controller.signal}).then(async r=>{if(!r.ok)throw new MappingHttpError(r.headers.get('X-FOX-Admission')==='not-admitted'||[400,401,403,404,405,413,415,422,429].includes(r.status));return r.json();}),new Promise<never>((_,reject)=>{timeout=setTimeout(()=>{controller.abort();reject(new Error('Request timed out'));},DEADLINE_MS);})]);}finally{clearTimeout(timeout!);}
}
export default function XmlMappingConversion({projectId,source,busy,outputOnly=false,onFenceChange}:Props){
 const identity=JSON.stringify([projectId,source.source_hash,source.selected_source_set_id]);
 const mounted=useRef(true),revision=useRef(0),lock=useRef(false),timer=useRef<ReturnType<typeof setTimeout>|null>(null),polls=useRef(0),overviewRead=useRef(false);
 const [overview,setOverview]=useState<MappingOverview|null>(null),[loading,setLoading]=useState(true),[error,setError]=useState(''),[posting,setPosting]=useState(false),[unknown,setUnknown]=useState(false),[synthetic,setSynthetic]=useState(false),[local,setLocal]=useState(false);
 const base=`/api/projects/${encodeURIComponent(projectId)}/xml-mapping`,storageKey=mappingStorageKey(source);
 const clearRequest=(requestId:string)=>{if(sessionStorage.getItem(storageKey)===requestId)sessionStorage.removeItem(storageKey);};
 const notifyFence=()=>{try{onFenceChange?.(Boolean(sessionStorage.getItem(storageKey)));}catch{onFenceChange?.(true);}};
 async function refresh(){
  if(overviewRead.current)return;overviewRead.current=true;if(timer.current)clearTimeout(timer.current);
  const rev=++revision.current;if(mounted.current){setLoading(true);setError('');}
  try{const data=parseOverview(await requestJson(base),source);if(!data)throw new Error('Invalid overview');if(rev!==revision.current)return;
   let pending:string|null;try{pending=sessionStorage.getItem(storageKey);}catch{throw new Error('Storage unavailable');}
   if(pending&&data.runs.some(r=>r.request_id===pending)){clearRequest(pending);notifyFence();if(mounted.current)setUnknown(Boolean(sessionStorage.getItem(storageKey)));}
   if(mounted.current)setOverview(data);
  }catch{if(mounted.current&&rev===revision.current){setOverview(null);setError('Could not load mapping status for this source version. Refresh status before continuing.');}}finally{overviewRead.current=false;if(mounted.current)setLoading(false);}
 }
 useEffect(()=>{mounted.current=true;try{setUnknown(Boolean(sessionStorage.getItem(storageKey)));}catch{setUnknown(true);}notifyFence();void refresh();return()=>{mounted.current=false;revision.current++;if(timer.current)clearTimeout(timer.current);};},[identity]);
 const active=overview?.runs.find(r=>r.current_source&&activeMapping(r));
 useEffect(()=>{if(!active||loading||overviewRead.current||polls.current>=20)return;timer.current=setTimeout(async()=>{if(overviewRead.current)return;polls.current++;const rev=++revision.current;try{const run=parseRun(await requestJson(`${base}/runs/${encodeURIComponent(active.id)}`),source,active.id);if(!run)throw new Error('Invalid run');if(mounted.current&&rev===revision.current)setOverview(old=>old?{...old,runs:old.runs.map(r=>r.id===run.id?run:r)}:old);}catch{if(mounted.current&&rev===revision.current)setError('Could not refresh the run. Use Refresh mapping status to check again.');}},3000);return()=>{if(timer.current)clearTimeout(timer.current);};},[identity,active?.id,active?.state,overview,loading]);
 async function start(){
  if(lock.current||busy||unknown||!overview?.available||!synthetic||!local||active)return;
  lock.current=true;++revision.current;setLoading(false);setPosting(true);setError('');const requestId=crypto.randomUUID();
  try{sessionStorage.setItem(storageKey,requestId);notifyFence();}catch{lock.current=false;setPosting(false);setError('This browser cannot retain the request safety record. Enable session storage and refresh before starting.');return;}
  try{const run=parseRun(await requestJson(`${base}/runs`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source_hash:overview.source_hash,selected_source_set_id:overview.selected_source_set_id,source_binding:overview.source_binding,catalog_sha256:overview.catalog_sha256,request_id:requestId,approved_synthetic_scope:true,approved_local_source_processing:true})}),source,undefined,requestId);
   if(!run||!run.current_source)throw new Error('Invalid run');
   clearRequest(requestId);notifyFence();++revision.current;if(mounted.current){setLoading(false);setUnknown(false);setOverview(old=>old?{...old,runs:[run,...old.runs.filter(r=>r.id!==run.id)]}:old);polls.current=0;}
  }catch(error){if(error instanceof MappingHttpError&&error.notAdmitted){try{clearRequest(requestId);notifyFence();}catch{}if(mounted.current){setUnknown(false);setError('This request was not admitted. Refresh mapping status and review the current requirements.');void refresh();}}else if(mounted.current){let retained=true;try{retained=sessionStorage.getItem(storageKey)===requestId;}catch{}if(retained){setUnknown(true);setError('The start response was not confirmed. Check the saved run history; FOX will not automatically submit it again.');void refresh();}}}
  finally{lock.current=false;if(mounted.current)setPosting(false);}
 }
 const runs=overview?.runs??[];
 return <section className="fw-surface xml-mapping" aria-label={outputOnly?'Reusable mapping output':'Reusable XML mapping'}>
  <div className="fw-detail-heading"><div><p className="fw-eyebrow">REUSABLE XML MAPPINGS</p><h2>{outputOnly?'Mapping APEX output':'Generate with reusable mappings'}</h2><p>FOX applies installed mappings on the FOX server. This route does not transmit source to AI.</p></div><button type="button" className="fw-secondary" disabled={loading} onClick={()=>{polls.current=0;void refresh();}}>Refresh mapping status</button></div>
  <p>This partial conversion uses synthetic data, read-only reports and supported session drafts. Behavior not yet converted is explained below. A generated package does not establish APEX runtime verification or business acceptance.</p>
  {loading&&<p role="status">Loading mapping status…</p>}{error&&<p className="fw-notice" role="alert">{error}</p>}
  {unknown&&<p className="fw-notice" role="status">The previous request outcome is unknown. Review saved history and contact the operator if it cannot be found. Starting another run is locked.</p>}
  {overview&&!overview.available&&<p className="fw-notice">{overview.reason||'Mapping is not available for this source version. Add the complete supported Forms XML source set and refresh status.'}</p>}
  {overview&&<p className="fw-small">{overview.scope_notice} Sources: {mappingCount(overview.source_count)} · Code units: {mappingCount(overview.code_unit_count)}</p>}
  {!outputOnly&&<><fieldset className="fw-confirmations"><legend>Confirm this conversion scope</legend><label className="fw-check"><input type="checkbox" checked={synthetic} disabled={busy||posting||unknown} onChange={e=>setSynthetic(e.target.checked)}/>I understand the synthetic data and session-draft scope, with remaining conversion gaps.</label><label className="fw-check"><input type="checkbox" checked={local} disabled={busy||posting||unknown} onChange={e=>setLocal(e.target.checked)}/>I approve processing these source files on the FOX server.</label></fieldset><button type="button" disabled={busy||posting||loading||unknown||!overview?.available||!synthetic||!local||Boolean(active)} onClick={()=>void start()}>{posting?'Starting…':'Generate APEX package'}</button></>}
  <h3>Saved mapping runs</h3>{!loading&&runs.length===0&&<p>No mapping runs reported for this project.</p>}
  {runs.map(run=>{const url=safeDownload(run,projectId,source.source_hash,source.selected_source_set_id);return <article className="xml-mapping-run" key={run.id}><div className="fw-detail-heading"><strong>{mappingLabel(run.state)}</strong><span className="fw-badge fw-neutral">{run.current_source?'Current source':'Earlier source'}</span></div><p>{run.message}</p><p>Generated or adapted units: {mappingCount(run.generated_units)} · Not yet converted: {mappingCount(run.unsupported_units)} · Total units: {mappingCount(run.total_units)}</p>{run.context_summary&&<div className="xml-mapping-context"><p>Read-only relationship views: {run.context_summary.relations_generated} &middot; Read-navigation gaps: {run.context_summary.relations_not_converted}</p><p>Assignment rules encoded, event wiring pending: {run.context_summary.assignments_generated_unwired}. These remain in Not yet converted; no insert/update action is enabled.</p><p className="fw-small">Automatic query, cascading deletion and unsaved-record behavior are not implemented by these read-only views.</p></div>}{run.buffer_summary&&run.buffer_summary.record_validation_flows>0&&<div className="xml-mapping-buffer"><p>Connected draft-record checks: {run.buffer_summary.record_validation_flows}.</p><p className="fw-small">The generated screen checks edited records before keeping a draft or moving to another record. Drafts stay in the session; customer tables are not saved. Installed APEX runtime verification is still pending.</p></div>}{run.policy_summary&&<div className="xml-mapping-policy"><p>Policy rules encoded, event wiring pending: {run.policy_summary.rules_generated_unwired}.</p><p className="fw-small">Warnings, failure checks, conditional assignments and permission changes are preserved in review code. These rules remain in Not yet converted; no permissions or writes are activated.</p></div>}{run.discrepancies&&<XmlMappingDiscrepancies report={run.discrepancies}/>}
  {!run.discrepancies&&run.gaps_available&&run.gap_summary&&<div className="xml-mapping-gaps"><p>FOX mapping: {run.gap_summary.engine_mapping} · FOX context: {run.gap_summary.engine_context} · Missing source: {run.gap_summary.missing_source} · Review needed: {run.gap_summary.review_required}</p><details><summary>Why units are not yet converted</summary><ul>{run.gaps?.map(gap=><li key={gap.source_unit_id}><strong>{gap.source_name}</strong> <span>({gap.source_file}, line {gap.source_line})</span><p>{({engine_mapping:'FOX mapping',engine_context:'FOX context',missing_source:'Missing source',review_required:'Review needed'} as const)[gap.category]}: {gap.message}</p><p>Next action: {gap.next_action} · Owner: {({FOX_ENGINE:'FOX team',SOURCE_OWNER:'Source owner',REVIEWER:'Reviewer'} as const)[gap.owner]}</p></li>)}</ul></details></div>}<p className="fw-small">Runtime verification: not reported · Business behavior: not accepted</p>{url&&<a className="fw-secondary xml-mapping-download" href={url}>Download native APEXlang package</a>}<p className="fw-small">Run <code>{run.id}</code></p></article>;})}
  {active&&polls.current>=20&&<p className="fw-small">Automatic checks have stopped. Refresh mapping status to check the saved run.</p>}
 </section>;
}
