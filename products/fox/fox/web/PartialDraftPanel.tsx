import React,{useEffect,useId,useRef,useState} from 'react';
import {ArrowRight,FileCode2,LoaderCircle,TriangleAlert} from 'lucide-react';
import type {SourceBinding} from './projectConversion';

export type DraftScope={scope:'fox-partial-draft-v1';project_id:string;parent_source_hash:string;parent_plan_sha256:string;draft_sha256:string;
 available:boolean;warning:string;next_action:string;derived_source_hash?:string;selected_source_set_id?:string;parent_source_set_id?:string;
 included_forms:{form_name:string;draft_form_name:string;source_name:string;components:string[]}[];
 omitted_forms:{form_name:string;source_name:string;reason:string}[];
 omissions:{form_name:string|null;code:string;message:string;required_action:string;draft_disposition:string;source_location?:Record<string,string|number>}[]};
const record=(value:unknown):value is Record<string,unknown>=>typeof value==='object'&&value!==null&&!Array.isArray(value);
const text=(value:unknown):value is string=>typeof value==='string'&&value.length>0&&value.length<=8192;
const hash=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const sid=(value:unknown):value is string=>typeof value==='string'&&/^ss-[a-f0-9]{32}$/.test(value);

export function readDraftScope(value:unknown,projectId:string,sourceHash:string,preview=false):DraftScope|null{
 if(!record(value)||value.scope!=='fox-partial-draft-v1'||value.project_id!==projectId||typeof value.available!=='boolean'
  ||!hash(value.parent_source_hash)||!hash(value.parent_plan_sha256)||!hash(value.draft_sha256)||!text(value.warning)||!text(value.next_action)
  ||!Array.isArray(value.included_forms)||!Array.isArray(value.omitted_forms)||!Array.isArray(value.omissions)
  ||value.included_forms.length>50||value.omitted_forms.length>50||value.omissions.length>5000
  ||(preview?value.parent_source_hash!==sourceHash:value.derived_source_hash!==sourceHash))return null;
 if(!value.included_forms.every(item=>record(item)&&text(item.form_name)&&text(item.draft_form_name)&&text(item.source_name)
   &&Array.isArray(item.components)&&item.components.every(text))
  ||!value.omitted_forms.every(item=>record(item)&&text(item.form_name)&&text(item.source_name)&&text(item.reason))
  ||!value.omissions.every(item=>record(item)&&(item.form_name===null||text(item.form_name))&&text(item.code)&&text(item.message)
   &&text(item.required_action)&&text(item.draft_disposition)
   &&(item.source_location===undefined||record(item.source_location)&&Object.entries(item.source_location).every(([key,value])=>
    key==='code_line'?Number.isSafeInteger(value)&&Number(value)>0:
    ['form','block','item','button','trigger','program_unit','code_property'].includes(key)&&text(value)))))return null;
 if(value.selected_source_set_id!==undefined&&!sid(value.selected_source_set_id)||value.parent_source_set_id!==undefined&&!sid(value.parent_source_set_id))return null;
 if(value.available!==Boolean(value.included_forms.length))return null;
 return value as unknown as DraftScope;
}

export function DraftScopeSummary({value,projectId,sourceHash,onOriginal}:{value:unknown;projectId:string;sourceHash:string;onOriginal?:(id:string)=>void}){
 if(value===null||value===undefined)return null;
 const scope=readDraftScope(value,projectId,sourceHash);
 if(!scope)return <div className="fw-notice" role="alert">The draft-scope report is unavailable. Do not treat this as a complete conversion.</div>;
 return <section className="fw-draft-banner" aria-label="Partial draft scope"><div className="fw-detail-heading"><div><p className="fw-eyebrow">PARTIAL DEMO DRAFT</p><h3>{scope.included_forms.length} forms included · {scope.omitted_forms.length} forms omitted</h3><p>{scope.omissions.length} recorded omissions. Omitted actions are not implemented.</p></div><TriangleAlert size={23}/></div><p>{scope.warning}</p>
  <details><summary>See included components and remaining work</summary><ScopeContents scope={scope}/></details>
  <div className="fw-actions"><a className="fw-scope-link" href={`/api/projects/${encodeURIComponent(projectId)}/draft-scope?source_hash=${encodeURIComponent(sourceHash)}`}>Download scope report</a>{onOriginal&&scope.parent_source_set_id&&<button type="button" className="fw-secondary" onClick={()=>onOriginal(scope.parent_source_set_id!)}>Return to original sources</button>}</div>
  <p className="fw-small">You can finish the generated application in APEX. A later FOX generation is a separate application/package, not a merge of your APEX edits.</p>
 </section>;
}

export function ScopeContents({scope,showOmissions=false}:{scope:DraftScope;showOmissions?:boolean}){
 return <div className="fw-draft-scope"><h3>Included in this draft</h3>{scope.included_forms.length?<ul>{scope.included_forms.map((form,index)=><li key={index}><strong>{form.form_name}</strong><span>{form.components.join(' · ')}</span><small>{form.source_name}</small></li>)}</ul>:<p>No supported form subset is available yet.</p>}
  {scope.omitted_forms.length>0&&<><h3>Forms left out</h3><ul>{scope.omitted_forms.map((form,index)=><li key={index}><strong>{form.form_name}</strong><span>{form.reason}</span><small>{form.source_name}</small></li>)}</ul></>}
  {scope.omissions.length>0&&<details open={showOmissions||undefined}><summary>Review all {scope.omissions.length} skipped behaviours and dependencies</summary><ul>{scope.omissions.map((item,index)=><li key={index}><strong>{item.form_name??'Project supporting source'} · {item.code.replaceAll('_',' ').toLowerCase()}</strong><span>{item.message}</span>{item.source_location&&<small>Where: {['form','block','button','item','trigger','program_unit'].flatMap(key=>typeof item.source_location?.[key]==='string'?[String(item.source_location[key])]:[]).join(' → ')}{item.source_location.code_line?` · Code line ${item.source_location.code_line}`:''}</small>}<small>Next: {item.required_action}</small><small>{item.draft_disposition}</small></li>)}</ul></details>}
 </div>;
}

export default function PartialDraftPanel({binding,planHash,busy,unknownOutcome,mode,onMode,onPreview,onCreate}:{
 binding:SourceBinding;planHash:string|null;busy:boolean;unknownOutcome:boolean;mode:'complete'|'partial';onMode:(mode:'complete'|'partial')=>void;
 onPreview?:()=>Promise<unknown>;onCreate?:(draftSha:string)=>Promise<boolean>;
}){
 const id=useId(),[preview,setPreview]=useState<DraftScope|null>(null),[loading,setLoading]=useState(false),[error,setError]=useState(''),[accepted,setAccepted]=useState(false);
 const mounted=useRef(true);useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;};},[]);
 async function inspect(){
  if(!onPreview||loading||busy||unknownOutcome)return;
  setLoading(true);setError('');setAccepted(false);setPreview(null);
  try{const result=readDraftScope(await onPreview(),binding.project_id,binding.source_hash,true);
   if(!mounted.current)return;
   if(!result||result.parent_plan_sha256!==planHash||result.selected_source_set_id!==binding.selected_source_set_id)throw new Error();
   setPreview(result);
  }catch{if(mounted.current)setError('The draft preview could not be checked. Refresh the project and try again; nothing has been converted.');}
  finally{if(mounted.current)setLoading(false);}
 }
 return <section className="fw-surface" aria-label="Choose conversion scope"><p className="fw-eyebrow">CHOOSE YOUR OUTPUT</p><h2>Complete conversion or an early draft?</h2><p>Keep working towards the full application, or explore a clearly labelled subset in APEX now.</p>
  <fieldset className="fw-generation-options"><legend className="fw-sr-only">Conversion scope</legend>{([
   ['complete','Complete conversion','Resolve every required finding before generating the supported application.'],
   ['partial','Partial draft / demo','Generate proven components. Review and explicitly accept what will be left out.'],
  ] as const).map(([value,title,description])=><label key={value} className={mode===value?'is-selected':''}><input type="radio" name={id+'-scope'} checked={mode===value} disabled={busy||unknownOutcome||loading} onChange={()=>onMode(value)}/><span><strong>{title}</strong><small>{description}</small></span></label>)}</fieldset>
  {mode==='partial'&&<div className="fw-draft-preview"><p className="fw-notice">A partial draft can omit business behaviour, but its APEX package must still pass technical checks. Forms without proven table keys or field mappings stay out.</p><button type="button" className="fw-secondary" disabled={!onPreview||busy||unknownOutcome||loading} onClick={()=>void inspect()}>{loading?<LoaderCircle size={17} className="fw-spinner"/>:<FileCode2 size={17}/>} {preview?'Refresh draft preview':'Preview what can be generated'}</button>{!onPreview&&<p className="fw-small">Draft preparation is not connected in this deployment.</p>}
   {error&&<p className="fw-alert" role="alert">{error}</p>}{preview&&<><ScopeContents scope={preview} showOmissions/>{preview.available?<><label className="fw-check"><input type="checkbox" checked={accepted} disabled={busy||unknownOutcome||loading} onChange={event=>setAccepted(event.target.checked)}/>I accept the listed omissions. This is a partial demo, not a complete conversion.</label><button type="button" disabled={!accepted||!onCreate||busy||unknownOutcome||loading} onClick={()=>void onCreate?.(preview.draft_sha256)}>Create draft source version <ArrowRight size={17}/></button><p className="fw-small">This creates no APEX app yet. Your originals remain saved. Next, confirm processing and generate the new draft through the normal review and technical checks.</p></>:<p className="fw-notice" role="status">{preview.next_action}</p>}</>}
  </div>}
 </section>;
}
