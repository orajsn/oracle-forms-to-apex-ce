import React,{useEffect,useRef,useState} from 'react';
import type {SourceBinding} from './projectConversion';
import type {WorkbenchActionResult} from './ProjectWorkbench';

type Chunk={id:string;sha256:string;bytes:number;label?:string};
type Assessment={source_hash:string;source_binding:string;selected_source_set_id:string;target_profile_sha256:string|null;conversion_configured:boolean;source_count:number;code_unit_count:number;chunks:Chunk[];scope_notice:string};
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function parse(value:unknown):Assessment{
 const a=value as Assessment;
 if(!a||!hash(a.source_hash)||!hash(a.source_binding)||typeof a.selected_source_set_id!=='string'||!a.selected_source_set_id||typeof a.conversion_configured!=='boolean'||!(a.target_profile_sha256===null||hash(a.target_profile_sha256))||!Number.isSafeInteger(a.source_count)||a.source_count<0||!Number.isSafeInteger(a.code_unit_count)||!Array.isArray(a.chunks)||a.chunks.length!==a.code_unit_count||a.chunks.length>4096||typeof a.scope_notice!=='string'||!a.chunks.every(c=>c&&typeof c.id==='string'&&c.id.length>0&&hash(c.sha256)&&Number.isSafeInteger(c.bytes)&&c.bytes>=0)||new Set(a.chunks.map(c=>c.id)).size!==a.chunks.length)throw new Error('The prototype assessment could not be verified. Refresh the project or ask your operator for help.');
 return a;
}
async function request(path:string,body?:unknown){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
 try{
  const multipart=body instanceof FormData;
  const response=await fetch(path,{method:body===undefined?'GET':'POST',headers:body===undefined||multipart?undefined:{'Content-Type':'application/json'},body:body===undefined?undefined:multipart?body:JSON.stringify(body),credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal});
  const data=await response.json();
  if(!response.ok){const error=Object.assign(new Error(typeof data?.detail==='string'?data.detail:'The request was rejected. Refresh the project or contact your operator.'),{status:response.status});throw error;}
  return data;
 }finally{clearTimeout(timer);}
}
export default function PrototypeConversion({projectId,source,busy,unknownOutcome,hasRun,execute,onRefresh}:{projectId:string;source:SourceBinding;busy:boolean;unknownOutcome:boolean;hasRun:boolean;execute:(action:()=>Promise<WorkbenchActionResult>,readOnly?:boolean)=>Promise<boolean>;onRefresh?:()=>Promise<WorkbenchActionResult>}){
 const [assessment,setAssessment]=useState<Assessment|null>(null),[loading,setLoading]=useState(false),[error,setError]=useState(''),[selected,setSelected]=useState<string[]>([]),[consents,setConsents]=useState([false,false,false]),[submitted,setSubmitted]=useState(false);
 const [xmlFiles,setXmlFiles]=useState<File[]>([]),[receipts,setReceipts]=useState<File[]>([]),[uploadError,setUploadError]=useState('');
 const binding=`${projectId}:${source.source_hash}:${source.selected_source_set_id}`;
 const currentBinding=useRef(binding);currentBinding.current=binding;
 useEffect(()=>{setAssessment(null);setSelected([]);setConsents([false,false,false]);setError('');setLoading(false);setXmlFiles([]);setReceipts([]);setUploadError('');},[binding]);
 function pairingError(){
  if(xmlFiles.length<1||xmlFiles.length>4||receipts.length!==xmlFiles.length)return 'Choose one to four redacted XML files and one receipt for each.';
  if(xmlFiles.some(f=>!f.name.toLowerCase().endsWith('.xml'))||new Set(xmlFiles.map(f=>f.name)).size!==xmlFiles.length)return 'Choose distinct redacted Forms XML files, not raw Forms binaries.';
  if(xmlFiles.length>1&&(new Set(receipts.map(f=>f.name)).size!==receipts.length||xmlFiles.some(f=>!receipts.some(r=>r.name===f.name+'.redaction.json'))))return 'For multiple files, name each receipt exactly as its XML filename plus .redaction.json.';
  return '';
 }
 async function upload(){
  const problem=pairingError();if(problem){setUploadError(problem);return;}if(busy||unknownOutcome||!onRefresh)return;
  const body=new FormData();for(const file of xmlFiles)body.append('files',file,file.name);
  for(const receipt of receipts)body.append('receipts',receipt,xmlFiles.length===1?xmlFiles[0].name+'.redaction.json':receipt.name);
  body.append('expected_current_source_set_id',source.selected_source_set_id??'null');setUploadError('');
  await execute(async()=>{try{
   const result=await request(`/api/projects/${encodeURIComponent(projectId)}/prototype-sources`,body);
   if(!hash(result?.source_hash)||typeof result.selected_source_set_id!=='string'||!result.selected_source_set_id||typeof result.changed!=='boolean'||result.processing_approved!==false)throw new Error('Unconfirmed source upload');
   setXmlFiles([]);setReceipts([]);setAssessment(null);setSelected([]);setConsents([false,false,false]);
   const refreshed=await onRefresh();if(refreshed.status!=='confirmed')throw new Error('Source refresh not confirmed');
   return {status:'confirmed',message:'Redacted source saved. No run or model processing was started. Review the prototype scope before processing.'};
  }catch(e){const status=(e as {status?:number}).status;if(status&&status>=400&&status<500)return {status:'rejected',message:e instanceof Error?e.message:'The source upload was rejected. Refresh the project.'};throw e;}});
 }
 async function assess(){
  const captured=binding;
  setLoading(true);setError('');setAssessment(null);setSelected([]);setConsents([false,false,false]);
  try{const a=parse(await request(`/api/projects/${encodeURIComponent(projectId)}/prototype-assessment`));
   if(a.source_hash!==source.source_hash||a.selected_source_set_id!==source.selected_source_set_id)throw new Error('The source version changed. Refresh the project before reviewing the prototype.');
   if(currentBinding.current===captured)setAssessment(a);
  }catch(e){if(currentBinding.current===captured)setError(e instanceof Error?e.message:'Assessment unavailable. Refresh the project and try again.');}finally{if(currentBinding.current===captured)setLoading(false);}
 }
 const current=assessment?.source_hash===source.source_hash&&assessment?.selected_source_set_id===source.selected_source_set_id;
 const enabled=Boolean(current&&assessment?.conversion_configured&&assessment.target_profile_sha256&&consents.every(Boolean)&&!busy&&!loading&&!unknownOutcome&&!hasRun&&!submitted);
 async function submit(){
  if(!enabled||!assessment)return;
  const approved=Object.fromEntries(assessment.chunks.filter(c=>selected.includes(c.id)).map(c=>[c.id,c.sha256]));
  await execute(async()=>{
   try{const result=await request(`/api/projects/${encodeURIComponent(projectId)}/prototype-runs`,{source_hash:assessment.source_hash,source_binding:assessment.source_binding,expected_current_source_set_id:assessment.selected_source_set_id,target_profile_sha256:assessment.target_profile_sha256,approved_chunk_hashes:approved,approved_redacted_source:consents[0],approved_external_ai:consents[1],approved_prototype_scope:consents[2]});
    if(typeof result?.id!=='string'||!/^fox-[a-f0-9]{20}$/.test(result.id)||result.state!=='QUEUED'||result.conversion_profile!=='native-blueprint-prototype-v1')throw new Error('Unconfirmed prototype request');
    setSubmitted(true);if(onRefresh)await onRefresh();
    return {status:'confirmed',message:'Prototype request submitted. Check the run status; generation, technical verification and business acceptance are separate steps.'};
   }catch(e){const status=(e as {status?:number}).status;if(status&&status>=400&&status<500)return {status:'rejected',message:e instanceof Error?e.message:'The request was rejected. Refresh the project.'};throw e;}
  });
 }
 return <section className="fw-surface" aria-label="Native APEX prototype"><h2>Generate native APEX prototype</h2><p>This separate prototype uses synthetic storage. Missing dependencies and unsupported behavior remain for remediation. It is not a complete conversion, technical verification or business acceptance.</p>
  <div className="fw-surface"><h3>Add prepared redacted Forms</h3><p>Keep original FMB files and credentials on your computer. Choose one to four locally prepared, redacted Forms XML files and the matching redaction receipt for each. Uploading saves sources only; it does not start a run or model processing.</p>
   <label>Redacted Forms XML files <input type="file" multiple accept=".xml" disabled={busy||unknownOutcome} onChange={e=>{setXmlFiles(Array.from(e.target.files??[]));e.target.value='';setUploadError('');}}/></label>
   <label>Matching redaction receipts <input type="file" multiple accept=".json" disabled={busy||unknownOutcome} onChange={e=>{setReceipts(Array.from(e.target.files??[]));e.target.value='';setUploadError('');}}/></label>
   <p className="fw-small">For multiple XML files, each receipt must be named exactly like its XML file followed by .redaction.json. For one XML file, you may select receipt.json.</p>
   <p className="fw-small">{xmlFiles.length} XML files and {receipts.length} receipts selected.</p>
   <button type="button" className="fw-secondary" disabled={busy||unknownOutcome||!onRefresh||xmlFiles.length===0||receipts.length===0} onClick={()=>void upload()}>Upload redacted sources</button>{!onRefresh&&<p className="fw-small">Project refresh is unavailable. Ask your operator for help before uploading.</p>}{uploadError&&<p className="fw-alert" role="alert">{uploadError}</p>}
  </div>
  <button type="button" className="fw-secondary" disabled={busy||loading||unknownOutcome||!source.selected_source_set_id} onClick={()=>void assess()}>{loading?'Checking prototype scope…':'Review prototype scope'}</button>
  {!source.selected_source_set_id&&<p className="fw-small">Add and select a source version first.</p>}{error&&<p className="fw-alert" role="alert">{error}</p>}
  {current&&assessment&&<><p>{assessment.scope_notice}</p><p>{assessment.source_count} source files; {assessment.code_unit_count} code units identified.</p>{!assessment.conversion_configured&&<p className="fw-notice">The prototype processing route is not configured. Ask your operator to configure it; your sources remain saved. This does not establish live readiness.</p>}
   <fieldset className="fw-confirmations"><legend>Choose code units to send for analysis</legend><p>Only identifiers and hashes are shown here, not code. Review the corresponding original source before approving. No selection means a metadata-only prototype; business code is omitted.</p>
    {assessment.chunks.length>0?<><button type="button" className="fw-secondary" disabled={busy||unknownOutcome} onClick={()=>{setSelected(assessment.chunks.map(c=>c.id));setConsents([false,false,false]);}}>Select all code units</button> <button type="button" className="fw-secondary" disabled={busy||unknownOutcome} onClick={()=>{setSelected([]);setConsents([false,false,false]);}}>Clear selection</button>{assessment.chunks.map(c=><div key={c.id}><label className="fw-check"><input type="checkbox" disabled={busy||unknownOutcome} checked={selected.includes(c.id)} onChange={e=>{setSelected(e.target.checked?[...selected,c.id]:selected.filter(id=>id!==c.id));setConsents([false,false,false]);}}/><span style={{overflowWrap:'anywhere',minWidth:0}}>{typeof c.label==='string'&&c.label.trim()?c.label:c.id} · {c.bytes} bytes</span></label><details className="fw-evidence"><summary>Code unit reference</summary><p style={{overflowWrap:'anywhere'}}>ID: {c.id}<br/>SHA-256: {c.sha256}</p></details></div>)}</>:<p>No code units were identified. Only a metadata-only prototype can be requested.</p>}
   </fieldset><fieldset className="fw-confirmations"><legend>Confirm before processing</legend>{['I reviewed and redacted credentials, production records and restricted personal information.','I have permission to use the configured external AI processing route for these sources and selected code units.','I understand this is a synthetic-storage prototype; omitted or unsupported behavior needs remediation and human review.'].map((label,i)=><label className="fw-check" key={label}><input type="checkbox" checked={consents[i]} disabled={busy||unknownOutcome} onChange={e=>setConsents(consents.map((v,j)=>j===i?e.target.checked:v))}/>{label}</label>)}</fieldset>
   <p className="fw-small">{selected.length} of {assessment.chunks.length} code units selected{selected.length===0?' — metadata-only; no business code selected':''}.</p><button type="button" disabled={!enabled} onClick={()=>void submit()}>Generate native APEX prototype</button>{(hasRun||submitted)&&<p className="fw-small">A request exists for this source version. Review its status or output; it will not be submitted again.</p>}
  </>}
 </section>;
}
