// Presentation only: none of these summaries grant conversion or acceptance.
type RecordValue=Record<string,unknown>;
const record=(value:unknown):value is RecordValue=>typeof value==='object'&&value!==null&&!Array.isArray(value);
const text=(value:unknown):value is string=>typeof value==='string'&&value.trim().length>0;

export type SourceBlocker={key:string;code:string;message:string;source?:string;evidence?:string};
export function presentSourceFindings(value:unknown):{
 blockers:SourceBlocker[];blockerCount:number;blockerCountLabel:string;detailsIncomplete:boolean;assessmentFindingCount:number|null;
}{
 const inventory=record(value)?value:{};
 const native=record(inventory.native_assessment)?inventory.native_assessment:null;
 const blockers:SourceBlocker[]=[],seen=new Set<string>();
 let detailsIncomplete=!record(value)||typeof inventory.conversion_eligible!=='boolean';
 function collect(raw:unknown){
  if(!Array.isArray(raw)){detailsIncomplete=true;return;}
  for(const item of raw){
   if(!record(item)||!text(item.code)||!text(item.message)){detailsIncomplete=true;continue;}
   const sources=new Set<string>();
   if(item.source!==undefined){if(text(item.source))sources.add(item.source);else detailsIncomplete=true;}
   if(item.sources!==undefined){
    if(!Array.isArray(item.sources)||!item.sources.length)detailsIncomplete=true;
    if(Array.isArray(item.sources))for(const source of item.sources){if(text(source))sources.add(source);else detailsIncomplete=true;}
   }
   const evidence=text(item.evidence)?item.evidence:undefined;
   if(item.evidence!==undefined&&!evidence)detailsIncomplete=true;
   // Expand multi-file restrictions into the same per-source entries displayed.
   // Exact duplicates collapse across producers, not different fixes.
   for(const source of sources.size?[...sources]:[undefined]){
    const key=JSON.stringify([item.code,source??null,evidence??null,item.message]);
    if(!seen.has(key)){seen.add(key);blockers.push({key,code:item.code,message:item.message,source,evidence});}
   }
  }
 }
 collect(inventory.conversion_blockers);
 if(native)collect(native.blockers);
 else if(inventory.native_assessment!==undefined&&inventory.native_assessment!==null)detailsIncomplete=true;
 if(inventory.conversion_profile==='native-table-form-v1'&&!native)detailsIncomplete=true;
 if(inventory.conversion_eligible===false&&Array.isArray(inventory.conversion_blockers)&&!inventory.conversion_blockers.length)detailsIncomplete=true;
 if(native&&native.state!=='READY'&&Array.isArray(native.blockers)&&!native.blockers.length)detailsIncomplete=true;
 const blockerCount=blockers.length;
 return {blockers,blockerCount,detailsIncomplete,
  blockerCountLabel:detailsIncomplete?(blockerCount?blockerCount+'+':'Unavailable'):String(blockerCount),
  assessmentFindingCount:Array.isArray(inventory.issues)?inventory.issues.length:null};
}

export function presentReviewer(value:unknown):{
 verdict:string;notes:string[];notesStyle:'paragraph'|'list';notice:string|null;
}{
 const reviewer=record(value)?value:null;
 let verdict='Reviewer verdict unavailable';
 if(reviewer?.verdict==='approve')verdict='Approved by the reviewer';
 else if(reviewer?.verdict==='reject')verdict='Not approved by the reviewer';
 else if(text(reviewer?.verdict))verdict='Unrecognized reviewer verdict: '+reviewer.verdict;
 const raw=reviewer?.notes;
 if(typeof raw==='string')return {verdict,notes:text(raw)?[raw]:[],notesStyle:'paragraph',notice:text(raw)?null:'No reviewer notes recorded.'};
 if(Array.isArray(raw)){
  const notes=raw.filter(text),unsupported=notes.length!==raw.length;
  return {verdict,notes,notesStyle:'list',notice:unsupported
   ?'Some reviewer notes are blank or use an unsupported format. Review the recorded evidence for the complete feedback.'
   :notes.length?null:'No reviewer notes recorded.'};
 }
 return {verdict,notes:[],notesStyle:'paragraph',notice:raw===undefined
  ?'No reviewer notes recorded.'
  :'Reviewer notes use an unsupported format. Review the recorded evidence for details.'};
}
