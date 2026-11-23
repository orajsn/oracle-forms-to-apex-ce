import React,{useMemo,useRef,useState} from 'react';
import type {Discrepancies, GapRequirements, MappingGap, MappingRun} from './xmlMappingPresentation';
import './xmlMappingDiscrepancies.css';
import SupportingFileEvidence from './SupportingFileEvidence';

const statuses={generated:'Generated or adapted',partial:'Partly connected',encoded_unwired:'Encoded, awaiting connection',unimplemented:'Not yet implemented'} as const;
const partialReasons=new Set(['policy_rule_partial_draft_guard','item_lookup_partly_connected','item_entry_partly_connected','item_entry_draft_connected','approval_readiness_partly_connected','staged_query_partly_connected','delete_check_partly_connected','master_population_partly_connected',
 'master_query_helper_partly_connected','master_clear_partly_connected','module_navigation_partly_connected','saved_display_partly_connected']);
const kinds={database_object:'Database object',routine_reference:'Routine reference',forms_api:'Forms behavior',local_routine:'Local routine',report:'Report',source_link:'Source link',forms_library:'Attached Forms library',forms_menu:'Referenced Forms menu'} as const;
function Requirements({value}:{value:GapRequirements}){
 const groups=[['Database routine calls',value.routines],['Referenced tables or views',value.tables],
  ['Report definitions to verify',value.reports],['Forms session values',value.forms_state],
  ['Calls in a query skipped after trigger failure',value.unreached_calls]] as const;
 return <>{groups.map(([label,names])=>names.length>0&&<p key={label}><strong>{label}</strong> · {names.join(', ')}</p>)}
  {value.limited&&<p>Reference detail is limited. Review the preserved source for this action.</p>}</>;
}
export default function XmlMappingDiscrepancies({report,gaps,previous,initialView='all'}:{report:Discrepancies;gaps?:MappingGap[];previous?:Pick<MappingRun,'discrepancies'|'gaps'>;initialView?:'all'|'remaining'|'external'}){
 const [filter,setFilter]=useState<string>(initialView),[search,setSearch]=useState('');
 const unitDetails=useRef<HTMLDetailsElement>(null);
 const gapById=useMemo(()=>new Map(gaps?.map(g=>[g.source_unit_id,g])),[gaps]);
 const matchesUnit=(u:Discrepancies['units'][number], g?:MappingGap)=>!!g&&g.source_file===u.source_file
  &&g.source_line===u.source_line&&g.source_name===u.source_name;
 const wiredEntryIds=new Set(report.units.filter(u=>{
  const gap=gapById.get(u.source_unit_id);
  return gap&&matchesUnit(u,gap)&&['item_entry_draft_connected','item_entry_draft_callable'].includes(gap.reason);
 }).map(u=>u.source_unit_id));
 const previousIds=useMemo(()=>{
  const prior=previous?.discrepancies;
  if(!prior||!previous?.gaps||prior.source_binding!==report.source_binding)return new Set<string>();
  const hashes=new Map(report.units.map(u=>[u.source_unit_id,u.source_unit_sha256]));
  const partial=new Set(previous.gaps.filter(g=>partialReasons.has(g.reason)).map(g=>g.source_unit_id));
  return new Set(prior.units.filter(u=>u.status==='unimplemented'&&!partial.has(u.source_unit_id)&&hashes.get(u.source_unit_id)===u.source_unit_sha256).map(u=>u.source_unit_id));
 },[previous,report]);
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
 const externalIds=new Set(report.units.filter(u=>{
  const gap=gapById.get(u.source_unit_id), r=gap?.requirements;
  return displayedStatus(u)==='unimplemented'&&matchesUnit(u,gap)
   &&r&&(r.routines.length>0||r.tables.length>0||r.reports.length>0);
 }).map(u=>u.source_unit_id));
 const units=report.units.filter(u=>{
  const req=gapById.get(u.source_unit_id)?.requirements;
  const matches=filter==='all'||displayedStatus(u)===filter||(filter==='remaining'&&u.status!=='generated')||(filter==='prior'&&previousIds.has(u.source_unit_id))||(filter==='external'&&externalIds.has(u.source_unit_id))||(filter==='wiring'&&wiredEntryIds.has(u.source_unit_id));
  return matches&&(!query||[u.source_name,u.source_file,String(u.source_line),u.message,u.next_action,req?.owner_path??'',
   ...(req?.reports??[]),...(req?.routines??[]),...(req?.tables??[]),...(req?.forms_state??[]),...(references.get(u.source_unit_id)??[])].some(v=>v.toLocaleLowerCase().includes(query)));
 });
 const remaining=report.units.length-counts.generated;
 function showUnits(view:'remaining'|'external'|'wiring'){setFilter(view);setSearch('');if(unitDetails.current){unitDetails.current.open=true;unitDetails.current.querySelector('summary')?.focus();}}
 return <section className="xml-discrepancies" aria-label="Source discrepancies">
  <h4>Source behavior and conversion progress</h4>
  <p>Supported parts can be generated while these findings are reviewed. APEX runtime checks and business review are still pending.</p>
  <p>Generated or adapted: {counts.generated} · {counts.partial>0&&<>Partly connected: {counts.partial} · </>}Encoded, awaiting connection: {counts.encoded_unwired} · Not yet implemented: {counts.unimplemented} · Total source units: {report.summary.total_units}</p>
  <SupportingFileEvidence report={report} gaps={gaps}/>
  {remaining>0&&<div className="xml-discrepancy-actions"><button type="button" onClick={()=>showUnits('remaining')}>Show remaining gaps ({remaining})</button>
   {wiredEntryIds.size>0&&<button type="button" className="secondary" onClick={()=>showUnits('wiring')}>Entry wiring ({wiredEntryIds.size})</button>}
   {externalIds.size>0&&<button type="button" className="secondary" onClick={()=>showUnits('external')}>External gaps ({externalIds.size})</button>}</div>}
  <details ref={unitDetails} open={initialView!=='all'||undefined}><summary>Inspect source units and adaptation notes ({report.summary.total_units})</summary>
   <div className="xml-discrepancy-filters"><label>Status <select aria-label="Status" value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All units</option><option value="remaining">All remaining gaps</option>{wiredEntryIds.size>0&&<option value="wiring">Entry wiring</option>}{externalIds.size>0&&<option value="external">Unimplemented with external references</option>}{previousIds.size>0&&<option value="prior">Unimplemented in the previous run ({previousIds.size})</option>}<option value="generated">Generated or adapted</option>{counts.partial>0&&<option value="partial">Partly connected</option>}<option value="encoded_unwired">Encoded, awaiting connection</option><option value="unimplemented">Not yet implemented</option></select></label><label>Search units <input type="search" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Field, action, reference or source line"/></label></div>
   <p className="fw-small">Showing {units.length} of {report.units.length} units.</p>
   {units.length===0?<p>No units match these filters.</p>:<ul>{units.map(u=>{
    const req=gapById.get(u.source_unit_id)?.requirements;
    const listed=new Set([...(req?.routines??[]),...(req?.tables??[]),...(req?.reports??[]),...(req?.unreached_calls??[])]);
    const otherRefs=[...(references.get(u.source_unit_id)??[])].filter(v=>!listed.has(v.toUpperCase()));
    return <li key={u.source_unit_id}><strong>{u.source_name}</strong> <span>({u.source_file}, line {u.source_line})</span>
     {req?.owner_path&&<p>{req.owner_path}</p>}<p>{statuses[displayedStatus(u)]} · {u.message}</p><p>{(displayedStatus(u)==='unimplemented'&&req?.next_check)||u.next_action}</p>
     {req&&<Requirements value={req}/>}
     {otherRefs.length>0&&<p>References in this unit · {otherRefs.join(', ')}</p>}
    </li>})}</ul>}
  </details>
  <details><summary>References to check ({report.summary.dependency_groups} {report.summary.dependency_groups===1?'group':'groups'}, {report.summary.dependency_references} {report.summary.dependency_references===1?'reference':'references'})</summary>
   <p>These reference counts are separate from unit conversion progress. A reference requiring verification does not necessarily mean a file is missing. A source definition being present does not mean it is implemented or verified.</p>
   {report.dependencies.length===0?<p>No references reported.</p>:<ul>{report.dependencies.map(d=><li key={d.id}><strong>{d.name}</strong> · {kinds[d.kind]} · {d.status==='unverified'?'Needs verification':'Source definition present'}<p>{d.message}</p><p>Next action: {d.next_action}</p><ul>{d.occurrences.map((o,i)=><li key={i}>{o.source_unit_ids.length>0&&o.source_unit_ids.map(id=>unitNames.get(id)).join(', ')+' · '}{o.source_file}, line {o.source_line}</li>)}</ul></li>)}</ul>}
  </details>
 </section>;
}
