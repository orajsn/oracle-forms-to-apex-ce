import React,{useEffect,useRef,useState} from 'react';

export type CountSelection={source_name:string;source_sha256:string;module:string;block:string;item:string};
export type CountChoice={status:'pending'}|{status:'none'}|{status:'selected';selection:CountSelection;approved:boolean};
type Binding={source_hash:string;source_binding:string;selected_source_set_id:string;target_profile_sha256:string|null};
type Check={selection:CountSelection;requires_explicit_partial_scope_consent:true};
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=512&&!/[\u0000-\u001f]/.test(v);
function parse(value:any,binding:Binding):{checks:Check[];truncated:boolean;unsupported:number}{
 const keys=['source_name','source_sha256','module','block','item'];
 if(!value||value.scope!=='fox-prototype-count-check-discovery-v1'||value.count_guard_policy!=='forms-isolated-count-check-v1'||value.source_hash!==binding.source_hash||value.source_binding!==binding.source_binding||value.selected_source_set_id!==binding.selected_source_set_id||value.target_profile_sha256!==binding.target_profile_sha256||typeof value.conversion_configured!=='boolean'||value.conversion_configured!==(binding.target_profile_sha256!==null)||value.processing_approved!==false||value.partial_scope_approved!==false||value.business_behavior_accepted!==false||!Array.isArray(value.checks)||value.checks.length>64||!Array.isArray(value.unsupported)||value.unsupported.length>64||typeof value.descriptors_truncated!=='boolean'||!Number.isSafeInteger(value.considered_button_count)||value.considered_button_count<0||!text(value.scope_notice))throw new Error('Invalid discovery');
 for(const check of value.checks){const s=check?.selection;if(!s||typeof s!=='object'||Array.isArray(s)||Object.keys(s).length!==5||!keys.every(k=>Object.hasOwn(s,k))||!hash(s.source_sha256)||!['source_name','module','block','item'].every(k=>text(s[k]))||check.requires_explicit_partial_scope_consent!==true||!text(check.scope_notice))throw new Error('Invalid check');}
 return {checks:value.checks,truncated:value.descriptors_truncated,unsupported:value.unsupported.length};
}
export default function PrototypeCountChecks({projectId,binding,disabled,onChange}:{projectId:string;binding:Binding;disabled:boolean;onChange:(choice:CountChoice)=>void}){
 const [data,setData]=useState<ReturnType<typeof parse>|null>(null),[state,setState]=useState<'idle'|'loading'|'ready'|'unavailable'|'error'>('idle'),[selected,setSelected]=useState(-2),[approved,setApproved]=useState(false);
 const revision=useRef(0),controller=useRef<AbortController|null>(null);useEffect(()=>()=>{revision.current++;controller.current?.abort();},[]);
 async function discover(){
  if(disabled)return;const token=++revision.current,requestController=new AbortController();controller.current=requestController;const timer=setTimeout(()=>requestController.abort(),15000);setData(null);setSelected(-2);setApproved(false);onChange({status:'pending'});setState('loading');
  try{const response=await fetch(`/api/projects/${encodeURIComponent(projectId)}/prototype-count-checks`,{credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:requestController.signal});
   if(response.status===404){if(token===revision.current)setState('unavailable');return;}
   if(!response.ok)throw new Error('Discovery failed');const result=parse(await response.json(),binding);if(token===revision.current){setData(result);setState('ready');}
  }catch{if(token===revision.current)setState('error');}finally{clearTimeout(timer);if(controller.current===requestController)controller.current=null;}
 }
 function choose(index:number){setSelected(index);setApproved(false);onChange(index<0?{status:'none'}:{status:'selected',selection:data!.checks[index].selection,approved:false});}
 return <div className="fw-notice" aria-label="Optional source check"><h3>Optional source check</h3><p>Find a supported check in the selected Forms source. This is optional and applies only to a new prototype.</p>
  <button type="button" className="fw-secondary" disabled={disabled||state==='loading'} onClick={()=>void discover()}>{state==='loading'?'Checking source…':state==='idle'?'Find source checks':'Check source again'}</button>
  {state==='unavailable'&&<p role="status">Source checks are unavailable on this FOX version. You can continue without one.</p>}
  {state==='error'&&<p role="alert">Source checks could not be verified. Check the selected source and destination, then try again or continue without a check.</p>}
  {(state==='error'||state==='unavailable'||state==='ready'&&data?.checks.length===0)&&<button type="button" className="fw-secondary" disabled={disabled||selected===-1} onClick={()=>choose(-1)}>Continue without a source check</button>}
  {state==='ready'&&data&&<><p>This checks saved synthetic detail rows: matching null or zero values block; negative nonzero values do not. No matching rows pass this check. Unsaved Forms data is not checked.</p><p>The original approval or action is not performed. Remaining behavior needs remediation and human review; this is not business acceptance.</p>
   {data.checks.length?<fieldset className="fw-confirmations"><legend>Choose at most one check</legend><label className="fw-check"><input type="radio" name="count-check" checked={selected===-1} disabled={disabled} onChange={()=>choose(-1)}/>No source check</label>{data.checks.map((check,i)=><label className="fw-check" key={i}><input type="radio" name="count-check" checked={selected===i} disabled={disabled} onChange={()=>choose(i)}/><span style={{overflowWrap:'anywhere',minWidth:0}}>{check.selection.source_name} → {check.selection.module} / {check.selection.block} / {check.selection.item}</span></label>)}</fieldset>:<p>No supported source check was found. The original action is not converted by this option.</p>}
   {data.unsupported>0&&<p>Some source buttons are not supported by this check and need review.</p>}{data.truncated&&<p>Not all source buttons are shown. Ask your operator to review the source.</p>}
   {selected>=0&&<label className="fw-check"><input type="checkbox" checked={approved} disabled={disabled} onChange={e=>{setApproved(e.target.checked);onChange({status:'selected',selection:data.checks[selected].selection,approved:e.target.checked});}}/><span>I approve this partial scope only. The original action and remaining behavior are not included.</span></label>}
  </>}
 </div>;
}
