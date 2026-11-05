// Presentation-only projection. A matching source identity must come from the
// parent workspace, not from the same untrusted facts payload.
type Obj=Record<string,unknown>;
const obj=(v:unknown):v is Obj=>!!v&&typeof v==='object'&&!Array.isArray(v);
const number=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const identifier=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z][A-Za-z0-9_$# .-]{0,255}$/.test(v);
const filename=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_. -]{0,119}$/.test(v)&&!v.includes('..')&&!/[ .]$/.test(v);
const path=(v:unknown):v is string=>typeof v==='string'&&v.length<=2048&&/^(?:\/(?:[A-Za-z_][A-Za-z0-9_.-]*\[[1-9][0-9]*\]|\*\[position\(\)=[1-9][0-9]*\]))+$/.test(v);
const fail=():never=>{throw new Error('Facts are incomplete, unexpected or no longer match the selected source. Refresh the source assessment.');};
export type SourceIdentity={name:string;sha256:string;bytes:number};
type Location={path:string;line:number;column:number;byte_offset:number};
type Block={id:string;name:string|null;classification:'database'|'control'|'unknown';location:Location;items:{id:string;name:string|null;database_item:boolean|null;location:Location}[]};
export type FactsView={source:SourceIdentity;blocks:Block[];unassigned:Block['items'];totals:{blocks:number;items:number;triggers:number;code_units:number};findingCount:number;reviewRequirements:string[]};
function location(v:unknown):Location{
 if(!obj(v)||!path(v.path)||!number(v.line)||v.line<1||!number(v.column)||!number(v.byte_offset))return fail();
 return {path:v.path,line:v.line,column:v.column,byte_offset:v.byte_offset};
}
function id(v:unknown):v is string{return typeof v==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(v);}
function name(v:unknown):v is string|null{return v===null||identifier(v);}
function array(v:unknown):unknown[]{if(!Array.isArray(v)||v.length>100000)return fail();return v;}
export function readFormsFacts(value:unknown,expected:SourceIdentity):FactsView{
 if(!obj(value)||value.schema_version!==1||value.scope!=='fox-forms-facts-v1'||value.assessment_status!=='LOCAL_FACTS_ONLY'
  ||!obj(value.source)||!filename(value.source.name)||!hash(value.source.sha256)||!number(value.source.bytes)||value.source.bytes<1||value.source.encoding!=='utf-8'
  ||!expected||value.source.name!==expected.name||value.source.sha256!==expected.sha256||value.source.bytes!==expected.bytes
  ||!obj(value.safety)||value.safety.local_only!==true||value.safety.code_executed!==false||value.safety.model_submission_allowed!==false
  ||value.safety.import_allowed!==false||value.safety.native_generation_allowed!==false||!obj(value.totals))return fail();
 const collections=['modules','blocks','items','code_units','objects','links','dependencies'] as const;
 for(const key of collections){const rows=array(value[key]);if(!number(value.totals[key])||value.totals[key]!==rows.length)return fail();}
 if(!number(value.totals.triggers)||!number(value.totals.program_units))return fail();
 const seen=new Set<string>(),blocks:Block[]=[],unassigned:Block['items']=[],byId=new Map<string,Block>();
 const objects=array(value.objects);const objectMap=new Map<string,Obj>();
 for(const row of objects){if(!obj(row)||!id(row.id)||objectMap.has(row.id)||typeof row.kind!=='string')return fail();objectMap.set(row.id,row);}
 const sameObject=(row:Obj)=>id(row.id)&&objectMap.has(row.id)&&JSON.stringify(objectMap.get(row.id))===JSON.stringify(row);
 if(objects.filter(row=>obj(row)&&row.kind==='Trigger').length!==value.totals.triggers||objects.filter(row=>obj(row)&&row.kind==='ProgramUnit').length!==value.totals.program_units)return fail();
 for(const row of array(value.blocks)){
  if(!obj(row)||!id(row.id)||seen.has(row.id)||!sameObject(row)||row.kind!=='Block'||!name(row.name)||!['database','control','unknown'].includes(String(row.classification)))return fail();
  const block:Block={id:row.id,name:row.name,classification:row.classification as Block['classification'],location:location(row.location),items:[]};
  seen.add(row.id);byId.set(row.id,block);blocks.push(block);
 }
 for(const row of array(value.items)){
  if(!obj(row)||!id(row.id)||seen.has(row.id)||!sameObject(row)||row.kind!=='Item'||!name(row.name)||(row.block_id!==null&&(!id(row.block_id)||!byId.has(row.block_id)))||![true,false,null].includes(row.database_item as boolean|null))return fail();
  seen.add(row.id);const item={id:row.id,name:row.name,database_item:row.database_item as boolean|null,location:location(row.location)};
  if(row.block_id===null)unassigned.push(item);else byId.get(row.block_id as string)!.items.push(item);
 }
 if(objects.filter(row=>obj(row)&&row.kind==='Block').length!==blocks.length||objects.filter(row=>obj(row)&&row.kind==='Item').length!==array(value.items).length)return fail();
 const findings=array(value.findings);
 const review=new Set<string>();
 const messages:Record<string,string>={DEPENDENCIES_UNVERIFIED:'Provide authoritative definitions for referenced database objects, routines, libraries and reports.',CODE_REQUIRES_REVIEW:'Review source code and its dependencies; local inventory did not execute or verify behavior.',DYNAMIC_REFERENCE_REVIEW:'Review dynamic SQL targets against the application source.',SOURCE_LINK_UNRESOLVED:'Provide the missing source for unresolved relationships.',SOURCE_LINK_AMBIGUOUS:'Resolve ambiguous source relationships before design.',BIND_BLOCK_UNRESOLVED:'Identify the block referenced by code before design.',BLOCK_TYPE_UNKNOWN:'Confirm the database or control purpose of blocks marked for review.',ITEM_WITHOUT_BLOCK:'Identify the parent block of items listed without one.',OBJECT_NAME_UNAVAILABLE:'Inspect source locations where object names could not be represented.',CONFLICTING_OBJECT_NAME:'Resolve duplicate names within the same source scope.',UNINTERPRETED_XML_ELEMENTS:'Review XML elements that the local inventory could not interpret.',REFERENCE_NAME_UNAVAILABLE:'Review source references whose names could not be represented.',NESTED_MODULE:'Review the nested module structure.',OBJECT_OUTSIDE_MODULE:'Review objects outside an identified module.',BEHAVIOR_NOT_ASSESSED:'Business behavior and acceptance remain unverified.'};
 for(const row of findings){if(!obj(row)||typeof row.code!=='string'||!['review','unknown'].includes(String(row.severity))||!Array.isArray(row.object_ids)||row.object_ids.some(x=>!id(x)||!objectMap.has(x)))return fail();review.add(messages[row.code]||'Review additional findings in the source assessment.');}
 return {source:{name:value.source.name,sha256:value.source.sha256,bytes:value.source.bytes},blocks,unassigned,
  totals:{blocks:blocks.length,items:array(value.items).length,triggers:value.totals.triggers,code_units:value.totals.code_units as number},findingCount:findings.length,reviewRequirements:[...review]};
}
