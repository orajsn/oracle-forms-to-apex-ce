import type {ProjectConversionPlan,ProjectDependency,ProjectForm} from './projectConversion';
export type RequestRef={module_id:string;dependency_index:number};
export type SourceRequest={id:string;kind:string;target:string;state:'MISSING_SOURCE'|'ROUTINE_UNCONFIRMED'|'SOURCE_AVAILABLE';missing_parts:string[];routines:string[];actions:string[];references:RequestRef[];form_count:number;reference_count:number};
export type SourceRequests={complete:boolean;reason:string|null;groups:SourceRequest[];counts:null|{groups:number;requests:number;source_available:number;forms:number;references:number}};
const object=(v:unknown):v is Record<string,unknown>=>typeof v==='object'&&v!==null&&!Array.isArray(v);
const text=(v:unknown,n=4096):v is string=>typeof v==='string'&&v.length>0&&v.length<=n&&!/[\u0000-\u001f]/.test(v);
const integer=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const strings=(v:unknown):v is string[]=>Array.isArray(v)&&v.every(item=>text(item))&&new Set(v).size===v.length;
const same=(a:unknown,b:unknown)=>JSON.stringify(a)===JSON.stringify(b);
const need=(v:unknown):void=>{if(!v)throw new Error('Grouped source requests are unavailable. Refresh the assessment; detailed findings remain available.');};
export function referenced(plan:ProjectConversionPlan,ref:RequestRef):{form:ProjectForm;dep:ProjectDependency}{
 const form=plan.forms.find(f=>f.module_id===ref.module_id);need(form&&integer(ref.dependency_index)&&ref.dependency_index<form.dependencies.length);
 return {form:form!,dep:form!.dependencies[ref.dependency_index]};
}
export function readSourceRequests(value:unknown,plan:ProjectConversionPlan):SourceRequests{
 need(object(value));const row=value as Record<string,unknown>;
 need(row.schema_version===1&&row.scope==='fox-source-requests-v1'&&row.project_id===plan.project_id
  &&row.source_hash===plan.source_hash&&row.plan_sha256===plan.plan_sha256&&typeof row.complete==='boolean'&&Array.isArray(row.groups));
 if(row.complete===false){need(row.counts===null&&(row.groups as unknown[]).length===0&&text(row.reason,500));return {complete:false,reason:row.reason as string,groups:[],counts:null};}
 need(plan.assessment_complete&&row.reason===null&&(row.groups as unknown[]).length<=500&&object(row.counts));
 const seen=new Set<string>(),ids=new Set<string>(),keys=new Set<string>();
 const groups=(row.groups as unknown[]).map(value=>{
  need(object(value));const g=value as unknown as SourceRequest;
  need(text(g.id,40)&&/^req-[a-f0-9]{24}$/.test(g.id)&&!ids.has(g.id)&&text(g.kind,160)&&text(g.target,512)
   &&['MISSING_SOURCE','ROUTINE_UNCONFIRMED','SOURCE_AVAILABLE'].includes(g.state)&&strings(g.missing_parts)
   &&g.missing_parts.every(p=>['package','package_body'].includes(p))&&strings(g.routines)&&strings(g.actions)
   &&Array.isArray(g.references)&&g.references.length>0&&g.references.length<=1000);ids.add(g.id);
  const groupKey=JSON.stringify([g.kind,g.target,g.state,g.missing_parts]);need(!keys.has(groupKey));keys.add(groupKey);
  const deps=g.references.map(ref=>{
   need(object(ref)&&Object.keys(ref).sort().join(',')==='dependency_index,module_id'&&text(ref.module_id,200)&&integer(ref.dependency_index));
   const key=ref.module_id+':'+ref.dependency_index;need(!seen.has(key));seen.add(key);
   const {dep}=referenced(plan,ref);
   const state=dep.status==='MISSING'?'MISSING_SOURCE':dep.routine_check==='NOT_CONFIRMED'?'ROUTINE_UNCONFIRMED':'SOURCE_AVAILABLE';
   need(dep.kind===g.kind&&dep.target===g.target&&state===g.state&&same(dep.missing_parts??[],g.missing_parts));return dep;
  });
  need(integer(g.form_count)&&g.form_count===new Set(g.references.map(r=>r.module_id)).size
   &&integer(g.reference_count)&&g.reference_count===g.references.length
   &&same([...new Set(deps.flatMap(d=>d.routine?[d.routine]:[]))].sort(),g.routines)
   &&same([...new Set(deps.map(d=>d.action))],g.actions));return g;
 });
 const expected=plan.forms.reduce((n,f)=>n+f.dependencies.length,0);need(seen.size===expected&&expected<=1000);
 const counts={groups:groups.length,requests:groups.filter(g=>g.state!=='SOURCE_AVAILABLE').length,
  source_available:groups.filter(g=>g.state==='SOURCE_AVAILABLE').length,forms:new Set(groups.filter(g=>g.state!=='SOURCE_AVAILABLE').flatMap(g=>g.references.map(r=>r.module_id))).size,references:seen.size};
 need(Object.entries(counts).every(([key,n])=>(row.counts as Record<string,unknown>)[key]===n));
 return {complete:true,reason:null,groups,counts};
}
export function sourceRequestText(group:SourceRequest,plan:ProjectConversionPlan):string{
 const lines=['FOX source request: '+group.target,'Source version: '+plan.source_hash,
  'Who can help: application owner / DBA',...group.actions.map(a=>'Action: '+a)];
 for(const ref of group.references){
  const {form,dep}=referenced(plan,ref),loc=dep.source_location;
  const path=['Form '+form.form_name,...(['block','button','item','trigger','program_unit'] as const).flatMap(k=>loc?.[k]?[k.replace('_',' ')+' '+loc[k]]:[])];
  lines.push('Caller: '+path.join(' → ')+'; source: '+dep.source+(dep.routine?'; routine: '+dep.routine:''));
 }
 lines.push('Readable source only. Keep raw binaries local; do not include credentials or production records.',
  'Source availability is not proof of translated APEX behavior. Review all remaining findings.');return lines.join('\n');
}
