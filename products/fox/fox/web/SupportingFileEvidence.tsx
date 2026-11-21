import {useMemo,useState} from 'react';
import type {Discrepancies,MappingGap} from './xmlMappingPresentation';

const fileTypes = {
 menu: 'Forms menu (.mmb or menu XML)',
 library: 'Forms library source (.pll or .pld)',
 report: 'Report definition (.rdf or readable report export)',
 routine: 'Routine source (procedure, package spec and body, or Forms library)',
 table: 'Table or view definition (DDL)',
} as const;
type FileKind = keyof typeof fileTypes;
type Finding = {kind:FileKind; name:string; places:Set<string>};

function collect(report:Discrepancies,gaps:MappingGap[]|undefined){
 const findings=new Map<string,Finding>();
 const units=new Map(report.units.map(u=>[u.source_unit_id,u]));
 const contained=new Set<string>();
 function add(kind:FileKind,name:string,place:string){
  const key=kind+'|'+name.toUpperCase();
  const row=findings.get(key)??{kind,name,places:new Set<string>()};
  row.places.add(place);findings.set(key,row);
 }
 for(const dep of report.dependencies){
  for(const site of dep.occurrences){
   if(dep.status==='source_definition_present'||dep.kind==='forms_api'){
    for(const id of site.source_unit_ids)contained.add(id+'|'+dep.name.toUpperCase());
   }else if(dep.kind==='forms_library'||dep.kind==='forms_menu'||dep.kind==='report'){
    const kind=dep.kind==='forms_menu'?'menu':dep.kind==='forms_library'?'library':'report';
    add(kind,dep.name,site.source_file+', line '+site.source_line);
   }
  }
 }
 for(const gap of gaps??[]){
  const u=units.get(gap.source_unit_id),r=gap.requirements;
  if(!u||!r||u.status==='generated'||gap.source_name!==u.source_name||gap.source_file!==u.source_file||gap.source_line!==u.source_line)continue;
  const place=(r.owner_path||u.source_name)+' · '+u.source_file+', line '+u.source_line;
  for(const n of r.routines)if(!contained.has(u.source_unit_id+'|'+n.toUpperCase()))add('routine',n,place);
  for(const n of r.tables)if(!['DUAL','SYS.DUAL'].includes(n.toUpperCase()))add('table',n,place);
  for(const n of r.reports)add('report',n,place);
 }
 return [...findings.values()].sort((a,b)=>a.name.localeCompare(b.name));
}

export default function SupportingFileEvidence({report,gaps}:{report:Discrepancies;gaps?:MappingGap[]}){
 const rows=useMemo(()=>collect(report,gaps),[report,gaps]);
 const [expanded,setExpanded]=useState(false);
 if(!rows.length)return null;
 return <details className="xml-supporting-files" onToggle={e=>setExpanded(e.currentTarget.open)}><summary>Supporting files to check ({rows.length})</summary>
  <p>These names come from registrations and unfinished actions in this form. Check which definitions the project already has before requesting files.</p>
  {expanded&&(Object.keys(fileTypes) as FileKind[]).map(kind=>{
   const group=rows.filter(r=>r.kind===kind);
   return group.length>0&&<section key={kind} aria-label={fileTypes[kind]}><h5>{fileTypes[kind]}</h5>
    {kind==='menu'&&<p>The form names these menus. Their menu modules are absent from this XML run.</p>}
    <ul>{group.map(r=><li key={r.name}><details><summary>{r.name}</summary><ul>{[...r.places].map(place=><li key={place}>{place}</li>)}</ul></details></li>)}</ul>
   </section>;
  })}
 </details>;
}
