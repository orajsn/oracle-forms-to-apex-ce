import React,{useMemo,useState} from 'react';
import type {Discrepancies, MappingGap} from './xmlMappingPresentation';
import './xmlMappingDiscrepancies.css';

const statuses={generated:'Generated or adapted',partial:'Partly connected',encoded_unwired:'Encoded, awaiting connection',unimplemented:'Not yet implemented'} as const;
const partialReasons=new Set(['policy_rule_partial_draft_guard','item_lookup_partly_connected','approval_readiness_partly_connected','staged_query_partly_connected','master_population_partly_connected',
 'master_query_helper_partly_connected','master_clear_partly_connected']);
const kinds={database_object:'Database object',routine_reference:'Routine reference',forms_api:'Forms behavior',local_routine:'Local routine',report:'Report',source_link:'Source link'} as const;
export default function XmlMappingDiscrepancies({report,gaps}:{report:Discrepancies;gaps?:MappingGap[]}){
 const [filter,setFilter]=useState('all'),[search,setSearch]=useState('');
 const {partialIds,counts}=useMemo(()=>{
  const byId=new Map(gaps?.filter(g=>partialReasons.has(g.reason)).map(g=>[g.source_unit_id,g]));
  const partialIds=new Set<string>();
  const counts={generated:0,partial:0,encoded_unwired:0,unimplemented:0};
  for(const u of report.units){
   const g=byId.get(u.source_unit_id);
   if(u.status!=='generated'&&g&&g.source_name===u.source_name&&g.source_file===u.source_file&&g.source_line===u.source_line){
    partialIds.add(u.source_unit_id);
    counts.partial++;
   }else counts[u.status]++;
  }
  return {partialIds,counts};
 },[report,gaps]);
 const {unitNames,references}=useMemo(()=>{
  const unitNames=new Map(report.units.map(unit=>[unit.source_unit_id,unit.source_name]));
  const references=new Map<string,Set<string>>();
  for(const dependency of report.dependencies){
   for(const occurrence of dependency.occurrences){
    for(const id of occurrence.source_unit_ids){
     if(!references.has(id))references.set(id,new Set());
     references.get(id)!.add(dependency.name);
    }
   }
  }
  return {unitNames,references};
 },[report]);
 const query=search.trim().toLocaleLowerCase();
 const displayedStatus=(u:Discrepancies['units'][number])=>partialIds.has(u.source_unit_id)?'partial':u.status;
 const units=report.units.filter(u=>(filter==='all'||displayedStatus(u)===filter)&&(!query||[u.source_name,u.source_file,String(u.source_line),...(references.get(u.source_unit_id)??[])].some(v=>v.toLocaleLowerCase().includes(query))));
 return <section className="xml-discrepancies" aria-label="Source discrepancies">
  <h4>Source behavior and conversion progress</h4>
  <p>Supported parts can be generated while these findings are reviewed. APEX runtime checks and business review are still pending.</p>
  <p>Generated or adapted: {counts.generated} · {counts.partial>0&&<>Partly connected: {counts.partial} · </>}Encoded, awaiting connection: {counts.encoded_unwired} · Not yet implemented: {counts.unimplemented} · Total source units: {report.summary.total_units}</p>
  <details><summary>Inspect source units and adaptation notes ({report.summary.total_units})</summary>
   <div className="xml-discrepancy-filters"><label>Status <select aria-label="Status" value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All units</option><option value="generated">Generated or adapted</option>{counts.partial>0&&<option value="partial">Partly connected</option>}<option value="encoded_unwired">Encoded, awaiting connection</option><option value="unimplemented">Not yet implemented</option></select></label><label>Search units <input type="search" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Name, reference, file or line"/></label></div>
   <p className="fw-small">Showing {units.length} of {report.units.length} units.</p>
   {units.length===0?<p>No units match these filters.</p>:<ul>{units.map(u=><li key={u.source_unit_id}><strong>{u.source_name}</strong> <span>({u.source_file}, line {u.source_line})</span><p>{statuses[displayedStatus(u)]}: {u.message}</p><p>Next action: {u.next_action}</p>{references.has(u.source_unit_id)&&<p>References in this unit · {[...references.get(u.source_unit_id)!].join(', ')}</p>}</li>)}</ul>}
  </details>
  <details><summary>References to check ({report.summary.dependency_groups} {report.summary.dependency_groups===1?'group':'groups'}, {report.summary.dependency_references} {report.summary.dependency_references===1?'reference':'references'})</summary>
   <p>These reference counts are separate from unit conversion progress. A reference requiring verification does not necessarily mean a file is missing. A source definition being present does not mean it is implemented or verified.</p>
   {report.dependencies.length===0?<p>No references reported.</p>:<ul>{report.dependencies.map(d=><li key={d.id}><strong>{d.name}</strong> · {kinds[d.kind]} · {d.status==='unverified'?'Needs verification':'Source definition present'}<p>{d.message}</p><p>Next action: {d.next_action}</p><ul>{d.occurrences.map((o,i)=><li key={i}>{o.source_unit_ids.length>0&&o.source_unit_ids.map(id=>unitNames.get(id)).join(', ')+' · '}{o.source_file}, line {o.source_line}</li>)}</ul></li>)}</ul>}
  </details>
 </section>;
}
