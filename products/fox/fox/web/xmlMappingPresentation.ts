import type {SourceBinding} from './projectConversion';
export type MappingRun = {id:string;request_id:string|null;project_id:string;source_hash:string;selected_source_set_id:string|null;state:'QUEUED'|'PROCESSING'|'GENERATED'|'ATTENTION';message:string;created:number;updated:number;format_validated:boolean;generated_units:number|null;unsupported_units:number|null;total_units:number|null;download_url:string|null;package_sha256:string|null;current_source:boolean;runtime_verified:false;business_behavior_accepted:false;conversion_profile:'xml-mapping-v1'};
export type MappingOverview = {project_id:string;source_hash:string;selected_source_set_id:string|null;source_binding:string|null;catalog_sha256:string;available:boolean;reason:string|null;source_count:number|null;code_unit_count:number|null;scope_notice:string;runs:MappingRun[]};
const record=(v:unknown):v is Record<string,unknown>=>typeof v==='object'&&v!==null&&!Array.isArray(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const sid=(v:unknown):v is string|null=>v===null||(typeof v==='string'&&/^ss-[a-f0-9]{32}$/.test(v));
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length<=4000;
const count=(v:unknown):v is number|null=>v===null||(typeof v==='number'&&Number.isSafeInteger(v)&&v>=0);
const stamp=(v:unknown):v is number=>typeof v==='number'&&Number.isFinite(v)&&v>=0;
export const mappingStorageKey=(source:SourceBinding)=>`fox.xml-mapping.uncertain:${JSON.stringify([source.project_id,source.source_hash,source.selected_source_set_id])}`;
export function hasMappingFence(projectId:string):boolean {try{for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);if(!k?.startsWith('fox.xml-mapping.uncertain:'))continue;try{const v=JSON.parse(k.slice('fox.xml-mapping.uncertain:'.length));if(Array.isArray(v)&&v[0]===projectId&&sessionStorage.getItem(k))return true;}catch{return true;}}return false;}catch{return true;}}
export function parseRun(value:unknown,source:SourceBinding,expectedId?:string,expectedRequest?:string):MappingRun|null {
 if(!record(value)||typeof value.id!=='string'||!/^fox-[a-f0-9]{20}$/.test(value.id)||value.project_id!==source.project_id||!hash(value.source_hash)||!sid(value.selected_source_set_id)||!['QUEUED','PROCESSING','GENERATED','ATTENTION'].includes(value.state as string)||!text(value.message)||!stamp(value.created)||!stamp(value.updated)||value.updated<value.created||value.conversion_profile!=='xml-mapping-v1'||value.runtime_verified!==false||value.business_behavior_accepted!==false||typeof value.current_source!=='boolean'||typeof value.format_validated!=='boolean'||!count(value.generated_units)||!count(value.unsupported_units)||!count(value.total_units)||!(value.request_id===null||uuid(value.request_id))||!(value.package_sha256===null||hash(value.package_sha256))||!(value.download_url===null||typeof value.download_url==='string'))return null;
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
 const runs=value.runs.map(v=>parseRun(v,source));if(runs.some(v=>!v)||new Set(runs.map(v=>v!.id)).size!==runs.length)return null;
 return {...value,runs} as MappingOverview;
}
export const mappingCount=(value:unknown)=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=0?String(value):'Not reported';
export const activeMapping=(run:MappingRun)=>run.state==='QUEUED'||run.state==='PROCESSING';
export const mappingLabel=(state:string)=>({QUEUED:'Waiting to start',PROCESSING:'Processing',GENERATED:'APEXlang generated and format validated',ATTENTION:'Needs attention'} as Record<string,string>)[state]??'Status unavailable';
export function safeDownload(run:MappingRun,projectId:string,sourceHash:string,sourceSet:string|null){const exact=`/api/projects/${encodeURIComponent(projectId)}/xml-mapping/runs/${encodeURIComponent(run.id)}/download`;return run.project_id===projectId&&run.source_hash===sourceHash&&run.selected_source_set_id===sourceSet&&run.current_source&&run.state==='GENERATED'&&run.format_validated&&run.download_url===exact?exact:null;}
