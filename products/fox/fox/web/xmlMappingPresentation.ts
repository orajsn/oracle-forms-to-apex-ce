import type {SourceBinding} from './projectConversion';
export type GapCategory = 'engine_mapping'|'engine_context'|'missing_source'|'review_required';
export type MappingGap = {source_unit_id:string;source_name:string;source_file:string;source_line:number;category:GapCategory;reason:string;message:string;next_action:string;owner:'FOX_ENGINE'|'SOURCE_OWNER'|'REVIEWER'};
export type DiscrepancyUnit = {source_unit_id:string;source_unit_sha256:string;source_name:string;source_file:string;source_line:number;status:'generated'|'encoded_unwired'|'unimplemented';message:string;next_action:string};
export type DiscrepancyDependency = {id:string;kind:'database_object'|'routine_reference'|'forms_api'|'local_routine'|'report'|'source_link';name:string;status:'unverified'|'source_definition_present';message:string;next_action:string;occurrences:{source_object_id:string;source_file:string;source_line:number;source_unit_ids:string[]}[]};
export type Discrepancies = {schema_version:1;scope:'fox-source-discrepancies-v1';source_binding:string;summary:{total_units:number;generated_units:number;encoded_unwired_units:number;unimplemented_units:number;dependency_groups:number;dependency_references:number};units:DiscrepancyUnit[];dependencies:DiscrepancyDependency[];runtime_verified:false;business_behavior_accepted:false};
export type MappingRun = {saved_source_binding?:string;id:string;request_id:string|null;project_id:string;source_hash:string;selected_source_set_id:string|null;state:'QUEUED'|'PROCESSING'|'GENERATED'|'ATTENTION';message:string;created:number;updated:number;format_validated:boolean;generated_units:number|null;unsupported_units:number|null;total_units:number|null;download_url:string|null;package_sha256:string|null;current_source:boolean;runtime_verified:false;business_behavior_accepted:false;conversion_profile:'xml-mapping-v1';synthetic_save_summary?:{screens:number;before_write_events:number}|null;lookup_summary?:{generated_lookup_handlers:number;original_reads_enabled:false}|null;buffer_summary?:{record_validation_flows:number}|null;policy_summary?:{rules_generated_unwired:number}|null;context_summary?:{relations_generated:number;relations_not_converted:number;assignments_generated_unwired:number}|null;gap_summary?:Record<GapCategory,number>|null;gaps_available?:boolean;gaps?:MappingGap[];discrepancies?:Discrepancies|null};
export type MappingOverview = {project_id:string;source_hash:string;selected_source_set_id:string|null;source_binding:string|null;catalog_sha256:string;available:boolean;reason:string|null;source_count:number|null;code_unit_count:number|null;scope_notice:string;runs:MappingRun[]};
const record=(v:unknown):v is Record<string,unknown>=>typeof v==='object'&&v!==null&&!Array.isArray(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const sid=(v:unknown):v is string|null=>v===null||(typeof v==='string'&&/^ss-[a-f0-9]{32}$/.test(v));
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length<=4000;
const count=(v:unknown):v is number|null=>v===null||(typeof v==='number'&&Number.isSafeInteger(v)&&v>=0);
const stamp=(v:unknown):v is number=>typeof v==='number'&&Number.isFinite(v)&&v>=0;
const exactKeys=(v:Record<string,unknown>,keys:string[])=>Object.keys(v).length===keys.length&&keys.every(k=>Object.prototype.hasOwnProperty.call(v,k));
const nonempty=(v:unknown):v is string=>text(v)&&v.trim().length>0;
const integer=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<=10000;
const line=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0;
function parseDiscrepancies(v:unknown,run:Record<string,unknown>):v is Discrepancies {
 if(!record(v)||!exactKeys(v,['schema_version','scope','source_binding','summary','units','dependencies','runtime_verified','business_behavior_accepted'])||v.schema_version!==1||v.scope!=='fox-source-discrepancies-v1'||!hash(v.source_binding)||v.runtime_verified!==false||v.business_behavior_accepted!==false||run.state!=='GENERATED'||!record(v.summary)||!exactKeys(v.summary,['total_units','generated_units','encoded_unwired_units','unimplemented_units','dependency_groups','dependency_references'])||!Object.values(v.summary).every(integer)||!Array.isArray(v.units)||v.units.length>10000||!Array.isArray(v.dependencies)||v.dependencies.length>10000)return false;
 const summary=v.summary,ids=new Set<string>(),locations=new Map<string,{file:string;line:number}>(),totals={generated:0,encoded_unwired:0,unimplemented:0};
 for(const u of v.units){
  if(!record(u)||!exactKeys(u,['source_unit_id','source_unit_sha256','source_name','source_file','source_line','status','message','next_action'])||!['source_unit_id','source_name','source_file','message','next_action'].every(k=>nonempty(u[k]))||!hash(u.source_unit_sha256)||!line(u.source_line)||!['generated','encoded_unwired','unimplemented'].includes(u.status as string)||ids.has(u.source_unit_id as string))return false;
  ids.add(u.source_unit_id as string);locations.set(u.source_unit_id as string,{file:u.source_file as string,line:u.source_line as number});totals[u.status as keyof typeof totals]++;
 }
 if(summary.total_units!==v.units.length||summary.generated_units!==totals.generated||summary.encoded_unwired_units!==totals.encoded_unwired||summary.unimplemented_units!==totals.unimplemented||summary.total_units!==run.total_units||summary.generated_units!==run.generated_units||totals.encoded_unwired+totals.unimplemented!==run.unsupported_units||summary.dependency_groups!==v.dependencies.length)return false;
 let references=0;const depIds=new Set<string>();
 for(const d of v.dependencies){
  if(!record(d)||!exactKeys(d,['id','kind','name','status','message','next_action','occurrences'])||!['id','name','message','next_action'].every(k=>nonempty(d[k]))||!['database_object','routine_reference','forms_api','local_routine','report','source_link'].includes(d.kind as string)||!['unverified','source_definition_present'].includes(d.status as string)||d.status==='source_definition_present'&&d.kind!=='local_routine'||depIds.has(d.id as string)||!Array.isArray(d.occurrences)||d.occurrences.length===0||d.occurrences.length>10000)return false;
  depIds.add(d.id as string);
  for(const o of d.occurrences){
   if(!record(o)||!exactKeys(o,['source_object_id','source_file','source_line','source_unit_ids'])||!nonempty(o.source_object_id)||!nonempty(o.source_file)||!line(o.source_line)||!Array.isArray(o.source_unit_ids)||o.source_unit_ids.length>10000||!o.source_unit_ids.every((id:unknown)=>nonempty(id)&&ids.has(id))||new Set(o.source_unit_ids).size!==o.source_unit_ids.length)return false;
   if(!o.source_unit_ids.every((id:string)=>locations.get(id)?.file===o.source_file&&locations.get(id)?.line===o.source_line))return false;if(++references>10000)return false;
  }
 }
 return references===summary.dependency_references;
}
export const mappingStorageKey=(source:SourceBinding)=>`fox.xml-mapping.uncertain:${JSON.stringify([source.project_id,source.source_hash,source.selected_source_set_id])}`;
export function hasMappingFence(projectId:string):boolean {try{for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);if(!k?.startsWith('fox.xml-mapping.uncertain:'))continue;try{const v=JSON.parse(k.slice('fox.xml-mapping.uncertain:'.length));if(Array.isArray(v)&&v[0]===projectId&&sessionStorage.getItem(k))return true;}catch{return true;}}return false;}catch{return true;}}
export function parseRun(value:unknown,source:SourceBinding,expectedId?:string,expectedRequest?:string):MappingRun|null {
 if(!record(value)||typeof value.id!=='string'||!/^fox-[a-f0-9]{20}$/.test(value.id)||value.project_id!==source.project_id||!hash(value.source_hash)||!sid(value.selected_source_set_id)||!['QUEUED','PROCESSING','GENERATED','ATTENTION'].includes(value.state as string)||!text(value.message)||!stamp(value.created)||!stamp(value.updated)||value.updated<value.created||value.conversion_profile!=='xml-mapping-v1'||value.runtime_verified!==false||value.business_behavior_accepted!==false||typeof value.current_source!=='boolean'||typeof value.format_validated!=='boolean'||!count(value.generated_units)||!count(value.unsupported_units)||!count(value.total_units)||!(value.request_id===null||uuid(value.request_id))||!(value.package_sha256===null||hash(value.package_sha256))||!(value.download_url===null||typeof value.download_url==='string'))return null;
 if(value.context_summary!==undefined&&value.context_summary!==null){
  const c=value.context_summary;
  if(value.state!=='GENERATED'||!record(c)||Object.keys(c).length!==3||!['relations_generated','relations_not_converted','assignments_generated_unwired'].every(k=>Number.isSafeInteger(c[k])&&(c[k] as number)>=0)||(c.assignments_generated_unwired as number)>(value.unsupported_units as number))return null;
 }
 if(value.policy_summary!==undefined&&value.policy_summary!==null){
  const p=value.policy_summary;
  if(value.state!=='GENERATED'||!record(p)||Object.keys(p).length!==1||!Number.isSafeInteger(p.rules_generated_unwired)||(p.rules_generated_unwired as number)<0||(p.rules_generated_unwired as number)+(record(value.context_summary)?value.context_summary.assignments_generated_unwired as number:0)>(value.unsupported_units as number))return null;
 }
 if(value.synthetic_save_summary!==undefined&&value.synthetic_save_summary!==null){
  const save=value.synthetic_save_summary;
  if(value.state!=='GENERATED'||!record(save)||!exactKeys(save,['screens','before_write_events'])||
   !integer(save.screens)||!integer(save.before_write_events)||save.screens>save.before_write_events||
   (save.screens===0)!==(save.before_write_events===0)||save.before_write_events>(value.generated_units as number))return null;
 }
 if(value.buffer_summary!==undefined&&value.buffer_summary!==null){
  const b=value.buffer_summary;
  if(value.state!=='GENERATED'||!record(b)||Object.keys(b).length!==1||!Number.isSafeInteger(b.record_validation_flows)||(b.record_validation_flows as number)<0||(b.record_validation_flows as number)>(value.generated_units as number))return null;
 }
 if(value.lookup_summary!==undefined&&value.lookup_summary!==null){
  const l=value.lookup_summary;
  if(value.state!=='GENERATED'||!record(l)||Object.keys(l).length!==2||!Number.isSafeInteger(l.generated_lookup_handlers)||(l.generated_lookup_handlers as number)<0||(l.generated_lookup_handlers as number)>(value.generated_units as number)||l.original_reads_enabled!==false)return null;
 }
 const fields=['gap_summary','gaps_available','gaps'];
 const present=fields.filter(k=>Object.prototype.hasOwnProperty.call(value,k)).length;
 if(present!==0&&present!==3)return null;
 if(present===3){
  if(typeof value.gaps_available!=='boolean'||!Array.isArray(value.gaps)||value.gaps.length>10000)return null;
  if(!value.gaps_available){if(value.gap_summary!==null||value.gaps.length!==0)return null;}
  else {
   if(value.state!=='GENERATED'||!record(value.gap_summary))return null;
   const summary=value.gap_summary;
   const categories:GapCategory[]=['engine_mapping','engine_context','missing_source','review_required'];
   if(Object.keys(value.gap_summary).length!==4||categories.some(k=>!Number.isSafeInteger(summary[k])||(summary[k] as number)<0))return null;
   if(new Set(value.gaps.map(g=>record(g)?g.source_unit_id:null)).size!==value.gaps.length)return null;
   const owners:Record<GapCategory,string>={engine_mapping:'FOX_ENGINE',engine_context:'FOX_ENGINE',missing_source:'SOURCE_OWNER',review_required:'REVIEWER'};
   const totals:Record<GapCategory,number>={engine_mapping:0,engine_context:0,missing_source:0,review_required:0};
   for(const gap of value.gaps){
    if(!record(gap)||!categories.includes(gap.category as GapCategory)||!['source_unit_id','source_name','source_file','reason','message','next_action'].every(k=>text(gap[k])&&(gap[k] as string).length>0)||!Number.isSafeInteger(gap.source_line)||(gap.source_line as number)<1||gap.owner!==owners[gap.category as GapCategory])return null;
    totals[gap.category as GapCategory]++;
   }
   if(categories.some(k=>totals[k]!==summary[k])||value.gaps.length!==value.unsupported_units)return null;
  }
 }
 if(value.saved_source_binding!==undefined&&(value.state!=='GENERATED'||!hash(value.saved_source_binding)))return null;
 if(value.discrepancies!==undefined&&value.discrepancies!==null&&(!parseDiscrepancies(value.discrepancies,value)||value.saved_source_binding!==undefined&&value.discrepancies.source_binding!==value.saved_source_binding))return null;
 if(expectedId&&value.id!==expectedId||expectedRequest&&value.request_id!==expectedRequest)return null;
 if(value.request_id===null&&(value.state!=='ATTENTION'||value.selected_source_set_id!==null||value.current_source))return null;
 if(value.request_id!==null&&value.selected_source_set_id===null)return null;
 if(value.current_source!==(value.request_id!==null&&value.source_hash===source.source_hash&&value.selected_source_set_id===source.selected_source_set_id))return null;
 const exact=`/api/projects/${encodeURIComponent(source.project_id)}/xml-mapping/runs/${encodeURIComponent(value.id)}/download`;
 if(value.state==='GENERATED') {if(!value.format_validated||!hash(value.package_sha256)||value.download_url!==exact||value.generated_units===null||value.unsupported_units===null||value.total_units===null||value.generated_units+value.unsupported_units>value.total_units)return null;}
 else if(value.format_validated||value.download_url!==null||value.package_sha256!==null||value.generated_units!==null||value.unsupported_units!==null||value.total_units!==null)return null;
 return value as MappingRun;
}
export function parseOverview(value:unknown,source:SourceBinding):MappingOverview|null {
 if(!record(value)||value.project_id!==source.project_id||value.source_hash!==source.source_hash||value.selected_source_set_id!==source.selected_source_set_id||!hash(value.source_hash)||!sid(value.selected_source_set_id)||!hash(value.catalog_sha256)||!(value.source_binding===null||hash(value.source_binding))||typeof value.available!=='boolean'||!(value.reason===null||text(value.reason))||!text(value.scope_notice)||!count(value.source_count)||!count(value.code_unit_count)||!Array.isArray(value.runs)||value.available&&(value.source_binding===null||value.selected_source_set_id===null))return null;
 // A saved report belongs to its verified run, not to today's interpretation
 // of the same XML. Older servers lack that field: retain their original check.
 const runs=value.runs.map(v=>parseRun(v,source));if(runs.some(v=>!v||!('saved_source_binding' in v)&&v.current_source&&v.discrepancies&&v.discrepancies.source_binding!==value.source_binding)||new Set(runs.map(v=>v!.id)).size!==runs.length)return null;
 return {...value,runs} as MappingOverview;
}
export const mappingCount=(value:unknown)=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=0?String(value):'Not reported';
export const activeMapping=(run:MappingRun)=>run.state==='QUEUED'||run.state==='PROCESSING';
export const mappingLabel=(state:string)=>({QUEUED:'Waiting to start',PROCESSING:'Processing',GENERATED:'APEXlang generated and format validated',ATTENTION:'Needs attention'} as Record<string,string>)[state]??'Status unavailable';
export function safeDownload(run:MappingRun,projectId:string,sourceHash:string,sourceSet:string|null){const exact=`/api/projects/${encodeURIComponent(projectId)}/xml-mapping/runs/${encodeURIComponent(run.id)}/download`;return run.project_id===projectId&&run.source_hash===sourceHash&&run.selected_source_set_id===sourceSet&&run.current_source&&run.state==='GENERATED'&&run.format_validated&&run.download_url===exact?exact:null;}
