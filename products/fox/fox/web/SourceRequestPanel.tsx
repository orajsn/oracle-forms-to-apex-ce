import {useState} from 'react';
import type {ProjectConversionPlan} from './projectConversion';
import {readSourceRequests,referenced,sourceRequestText,type SourceRequest} from './sourceRequests';
import './sourceRequests.css';
function RequestCard({group,plan,onAddFiles}:{group:SourceRequest;plan:ProjectConversionPlan;onAddFiles:()=>void}){
 const [copyStatus,setCopyStatus]=useState('');
 const missing=group.state==='MISSING_SOURCE',available=group.state==='SOURCE_AVAILABLE';
 const text=sourceRequestText(group,plan);
 async function copy(){try{if(!navigator.clipboard)throw new Error();await navigator.clipboard.writeText(text);setCopyStatus('Request copied.');}catch{setCopyStatus('Select the request text below and copy it manually.');}}
 return <article className="fw-surface sr-card" aria-label={`Source request ${group.target}`}>
  <div className="fw-detail-heading"><h3>{group.target}</h3><span className={'fw-badge '+(available?'fw-neutral':'fw-attention')}>{missing?'Source missing':available?'Source available · mapping not verified':'Routine not confirmed'}</span></div>
  <p>{group.form_count} {group.form_count===1?'form':'forms'} · {group.reference_count} {group.reference_count===1?'caller':'callers'}</p>
  {group.missing_parts.length>0&&<p><strong>Provide:</strong> {group.missing_parts.map(p=>p==='package'?'Package specification (.pks or readable SQL)':'Package body (.pkb or readable SQL)').join(' and ')}</p>}
  {available?<p>No missing source is reported for this dependency. Its availability does not establish translated behavior; review the remaining findings below.</p>:<><p><strong>Who can help:</strong> Application owner / DBA</p><ul>{group.actions.map(a=><li key={a}>{a}</li>)}</ul></>}
  <details><summary>Show all affected callers</summary><ul>{group.references.map(ref=>{
   const {form,dep}=referenced(plan,ref),loc=dep.source_location;
   return <li key={ref.module_id+':'+ref.dependency_index}><strong>{form.form_name}</strong>{loc?.block&&<> → Block {loc.block}</>}{loc?.button?<> → Button {loc.button}</>:loc?.item&&<> → Item {loc.item}</>}{loc?.trigger&&<> → Trigger {loc.trigger}</>}{loc?.program_unit&&<> → Program {loc.program_unit}</>}
    <p><code>{dep.source}</code>{dep.routine&&<> · Routine <code>{dep.routine}</code></>}</p>
    {loc?.code_line&&<p>Code line {loc.code_line} within the extracted code, not an XML file line.</p>}</li>;
  })}</ul></details>
  {!available&&<><div className="fw-actions"><button type="button" className="fw-secondary" onClick={onAddFiles}>Add requested source</button><button type="button" className="fw-secondary" onClick={()=>void copy()}>Copy request</button></div>
   {copyStatus&&<p role="status">{copyStatus}</p>}<details open={copyStatus.startsWith('Select')}><summary>Request text for your source owner</summary><textarea aria-label={`Request text for ${group.target}`} readOnly value={text} rows={8}/></details></>}
 </article>;
}
export default function SourceRequests({value,plan,onAddFiles}:{value:unknown;plan:ProjectConversionPlan;onAddFiles:()=>void}){
 if(!plan.forms.some(f=>f.dependencies.length))return null;
 let list;try{list=readSourceRequests(value,plan);}catch{return <section className="fw-surface" role="status">Grouped source requests are unavailable or out of date. Refresh the project; individual findings below remain available.</section>;}
 if(!list.complete)return <section className="fw-surface" role="status">{list.reason} Individual findings below remain available.</section>;
 return <section className="sr-list" aria-label="Source requests across forms">
  <h2>Source requests across your forms</h2>
  <p><strong>{list.counts!.requests===0?'No outstanding source requests reported':`${list.counts!.requests} grouped source ${list.counts!.requests===1?'request':'requests'} across ${list.counts!.forms} ${list.counts!.forms===1?'form':'forms'}`}</strong></p>
  <p>Ask once for shared source. Every known caller is retained. Detailed findings below still decide whether conversion can continue.</p>
  {list.counts!.requests>0&&<a className="button secondary" href={`/api/projects/${encodeURIComponent(plan.project_id)}/source-requests.txt?source_hash=${plan.source_hash}&plan_sha256=${plan.plan_sha256}`}>Download request list</a>}
  {list.groups.map(group=><RequestCard key={group.id} group={group} plan={plan} onAddFiles={onAddFiles}/>)}
 </section>;
}
