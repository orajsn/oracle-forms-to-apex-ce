import {useEffect,useRef,useState, FormEvent} from 'react';
import {createRoot} from 'react-dom/client';
import {ArrowRight, FolderOpen, Plus, Upload, Download, ShieldCheck, ChevronLeft, LogOut, FileCode2, TriangleAlert} from 'lucide-react';
import './style.css';
import './sourcePreparation.css';
import {checkSelectedSources,uploadManifestName,type UploadMode} from './preparedUpload';
import {presentSourceFindings,presentReviewer} from './productPresentation';
import {presentVerificationStatus} from './verificationPresentation';
import LocalPreparation from './LocalPreparation';
import SourceVersionHistory from './SourceVersionHistory';
import ProjectWorkbench,{ProjectDashboard,type HumanReviewControls,type WorkbenchActionResult} from './ProjectWorkbench';
import {presentProjectRun,runBelongsToProject,type ActionCapability,type ProcessConfirmations,type ProjectActionContext,type ProjectRun} from './projectConversion';
import {selectSourceSet,excludeSourceFile,assertRefreshedSourceProject,sourceHistoryErrorMessage,sourceHistoryRefreshRequired,type SourceSelectionAck} from './sourceVersionPresentation';

type Project={id:string;name:string;customer:string;description:string;file_count:number;run_count:number};
type Finding={source:string;target:string;kind:string;status:string;action:string;title?:string;evidence?:string};
type Run={id:string;state:string;message:string;source_hash:string;downloadable:boolean;stage?:string;stage_message?:string;stage_updated_at_utc?:string;verification_status?:unknown};
type NativeAssessment={state:string;profile_id:string;scope_note:string;blockers:{code:string;message:string;source?:string;evidence?:string}[];native_form:null|{table_name:string;supported_operations:string[];columns:{name:string;label:string;data_type:string;length?:number;nullable:boolean;primary_key:boolean;identity:boolean}[]}};
type Session={username:string;conversion_configured:boolean;conversion_profile:string;configuration_scope:string;configuration_checks:{code:string;ready:boolean;message:string}[]};
type SourcePreparation={mode:string;matches_current_source:boolean;scope:string;receipt_id?:string;extraction_job_id?:string;canonical_manifest_sha256?:string;readable_source_hash?:string;files?:{name:string;sha256:string;bytes:number}[]};
type Inventory={selected_source_set_id:string|null;files:{file:string;bytes:number;sha256:string;blocks:string[]}[];dependencies:Finding[];issues:Finding[];missing_count:number;source_hash:string;scope_note:string;source_bytes:number;conversion_source_bytes:number;max_conversion_bytes:number;forms_source_files:string[];conversion_eligible:boolean;conversion_blockers:{code:string;message:string}[];conversion_profile:string;native_assessment?:NativeAssessment;source_preparation?:SourcePreparation};
type Detail=Project & {inventory:Inventory;runs:(Run&Partial<ProjectRun>)[];project_plan?:unknown;project_plan_error?:string;project_capabilities?:{upload?:ActionCapability;process?:ActionCapability};processing_notice?:string};
async function api(path:string,init?:RequestInit){
 const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),15000);
 try{const r=await fetch('/api'+path,{...init,signal:controller.signal});const data=await r.json();
 if(!r.ok){const error=Object.assign(new Error(typeof data.detail==='string'?data.detail:'Please check the submitted fields.'),{status:r.status});throw error;}return data;
 }catch(e){if(controller.signal.aborted)throw new Error('FOX is taking longer than expected. Check the existing status before another operation.');throw e;}finally{clearTimeout(timer);}
}
const json=(body:unknown)=>({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
const runLabel=(state:string)=>({QA_REQUIRED:'Lab verification pending',REVIEW_REQUIRED:'Human review required',QUEUED:'Queued',PROCESSING:'Converting',ATTENTION:'Needs operator attention',ACCEPTED:'Accepted',VERIFIED:'Technical checks passed'}[state]||state);
function SourceUpload({busy,preparation,onUpload}:{busy:boolean;preparation?:SourcePreparation;onUpload:(files:File[],mode:UploadMode)=>Promise<boolean>}){
 const [mode,setMode]=useState<UploadMode>('prepared'),[selected,setSelected]=useState<File[]>([]);
 const matched=preparation?.mode==='PREPARED_SET_MATCH'&&preparation.matches_current_source;
 async function upload(){if(await onUpload(selected,mode))setSelected([]);}
 return <section className="panel" aria-label="Prepare and upload source">
  <h2>1. Prepare locally. 2. Upload and assess.</h2>
  <p>Have FMB, MMB, OLB or PLL files? Keep raw binaries on your computer. Run the local FOX extractor with your installed Oracle Forms tooling; no local daemon is needed.</p>
  <details><summary>How to prepare raw Forms files</summary><ol>
   <li>Use the local FOX checkout and its Python environment, with Oracle Forms and Java installed. Check the tooling:</li></ol>
   <pre className="command-example">{'python -m fox.extractor check --oracle-home "<Oracle Forms home>" --java "<Java executable>"'}</pre>
   <p>Prepare into a separate output folder:</p><pre className="command-example">{'python -m fox.extractor prepare --source "<local source folder>" --output "<separate output folder>" --oracle-home "<Oracle Forms home>" --java "<Java executable>"'}</pre>
   <p>Then verify the generated job:</p><pre className="command-example">{'python -m fox.extractor verify --job "<prepared job folder>"'}</pre>
   <p>FMB/MMB/OLB use Oracle Forms2XML. PLL uses the FOX Oracle JDAPI readable-source XML adapter. Already-readable files can be prepared without the Oracle flags.</p>
   <p>Review and redact before upload. If output needs editing, copy only the reviewed readable files into a new source folder and prepare it again, so its manifest matches. Select only the contents of the new job’s <code>ready/</code> folder: readable files plus <code>{uploadManifestName}</code>. Keep the private root <code>manifest.json</code>, raw files and logs local.</p>
  </details>
  <div className="source-mode" role="group" aria-label="Source upload mode"><button className={mode==='prepared'?'':'secondary'} disabled={busy} aria-pressed={mode==='prepared'} onClick={()=>{setMode('prepared');setSelected([]);}}>Prepared source set</button><button className={mode==='direct'?'':'secondary'} disabled={busy} aria-pressed={mode==='direct'} onClick={()=>{setMode('direct');setSelected([]);}}>Direct readable files</button></div>
  {mode==='prepared'?<p>Select <code>{uploadManifestName}</code> and all its readable files together. FOX checks their exact names, sizes and SHA-256 hashes. A fresh project is recommended for each prepared set.</p>:<p>Upload readable Forms XML, PLD, SQL or package source directly. Source assessment still runs, but this path has no local-preparation manifest.</p>}
  <p className="subtle">UTF-8 · 5 MB/file · 25 MB/upload · at most 50 readable files. Archives and raw binaries are not uploaded.</p>
  <label className="button secondary upload-button"><Upload size={16}/> Choose {mode==='prepared'?'prepared set':'readable files'}<input key={mode} aria-label={mode==='prepared'?'Choose prepared manifest and readable files':'Choose direct readable source files'} type="file" multiple disabled={busy} accept={mode==='prepared'?'.json,.xml,.pld,.sql,.pks,.pkb,.txt':'.xml,.pld,.sql,.pks,.pkb,.txt'} onChange={e=>{setSelected(Array.from(e.target.files||[]));e.target.value='';}}/></label>
  {selected.length>0&&<div className="selected-sources" aria-live="polite"><strong>{selected.length} selected files</strong><ul>{selected.map((file,i)=><li key={`${file.name}-${i}`}>{file.name} <small>({file.size.toLocaleString()} bytes)</small></li>)}</ul></div>}
  <button className="source-upload-submit" disabled={busy||!selected.length} onClick={()=>void upload()}>{busy?'Checking files…':'Upload and assess'} <ArrowRight size={16}/></button>
  {preparation&&<div className="finding" aria-label="Source preparation receipt"><strong>{matched?'Prepared set matches the current project':preparation.mode==='PREPARED_SET_PARTIAL_OR_CHANGED'?'Prepared set differs from the current project':preparation.mode==='PREPARED_RECEIPT_UNAVAILABLE'?'Preparation receipt unavailable':'Direct readable source'}</strong>
   {preparation.mode==='PREPARED_SET_PARTIAL_OR_CHANGED'&&<p>The last verified upload is not the full current source set. Extra files, later versions or a previously stored newer version remain in project history. The prepared-set receipt does not certify this whole project.</p>}
   <p>{preparation.scope}</p>{preparation.extraction_job_id&&<details><summary>View integrity receipt</summary><p>Local extraction job: <code>{preparation.extraction_job_id}</code></p><p>{preparation.files?.length} readable files in the verified upload.</p><p className="manifest">Readable-set SHA-256 <code>{preparation.readable_source_hash}</code></p><p className="manifest">Canonical manifest SHA-256 <code>{preparation.canonical_manifest_sha256}</code></p></details>}
  </div>}
 </section>;
}
function SourceOverview({inventory,acceptedCount,onReview}:{inventory:Inventory;acceptedCount:number;onReview:(tab:string)=>void}){
 const summary=presentSourceFindings(inventory);
 return <><div className="metrics"><div><strong>{inventory.files.length}</strong><span>Source files</span></div><div><strong>{inventory.missing_count}</strong><span>Missing candidates</span></div><div><strong>{summary.blockerCountLabel}</strong><span>Conversion blockers</span><small>{summary.assessmentFindingCount===null?'Assessment findings unavailable':summary.assessmentFindingCount+' assessment findings (separate)'}</small></div><div><strong>{acceptedCount}</strong><span>Accepted packages</span></div></div>
 {(summary.blockerCount>0||summary.detailsIncomplete)&&<p><button className="secondary" onClick={()=>onReview('Sources')}>Review conversion blockers <ArrowRight size={16}/></button></p>}
 {summary.assessmentFindingCount!==null&&summary.assessmentFindingCount>0&&<p className="subtle">Assessment findings are listed separately in Dependencies. They are not the conversion-blocker count.</p>}</>;
}
function SourceEligibility({inventory}:{inventory:Inventory}){
 const native=inventory.native_assessment;
 const ready=inventory.conversion_eligible&&(!native||native.state==='READY');
 const summary=presentSourceFindings(inventory);
 return <section className="panel" aria-label="Source conversion eligibility"><div className="section-heading"><h2>{native?'Native APEX source preflight':'Source preflight'}</h2><span className={'badge '+(ready?'':'warn')}>{ready?'Source checks passed':'Action required'}</span></div><p>{inventory.conversion_source_bytes.toLocaleString()} / {inventory.max_conversion_bytes.toLocaleString()} UTF-8 bytes for conversion · {inventory.forms_source_files.length} recognized Forms source files.</p><p>The assessment upload limit is separate. Conversion accepts at most {(inventory.max_conversion_bytes/1000).toLocaleString()} KB across the current source version, including dependencies.</p>
 {summary.blockerCount>0&&<div aria-label="Conversion blockers"><h3>What is needed before conversion</h3><p>{summary.blockerCount} reported {summary.blockerCount===1?'blocker':'blockers'} to resolve. Repeated identical findings are shown once; findings for different files remain separate.</p>{summary.blockers.map(item=><div className="finding" key={item.key}><strong>{item.message}</strong>{(item.source||item.evidence)&&<p><code>{[item.source,item.evidence].filter(Boolean).join(' · ')}</code></p>}</div>)}</div>}
 {summary.detailsIncomplete&&<p role="status">Some source-check details are unavailable. The blocker count may be incomplete; review the assessment or ask the FOX operator before continuing.</p>}
 {native?<><p>Native beta: one table-backed Forms block, supplied synthetic table DDL and an explicit identity key. Output uses native APEX report and form components for search, create and edit. Additional behavior must be mapped before conversion.</p>{native.native_form&&<details><summary>Review supplied table and field mapping</summary><h3>{native.native_form.table_name}</h3>{native.native_form.columns.map(column=><p key={column.name}><strong>{column.label}</strong> <code>{column.name} · {column.data_type}{column.length?'('+column.length+')':''} · {column.primary_key?'identity primary key':column.nullable?'optional':'required'}</code></p>)}{native.state!=='READY'&&<p>This candidate is incomplete; it cannot start conversion while requirements remain.</p>}</details>}<p className="subtle">{native.scope_note}</p></>:ready&&<p>Source checks passed. Review the dependency findings and remediation, then confirm processing consent. These checks do not establish complete dependencies or working application behavior.</p>}</section>;
}
function ReviewerFeedback({reviewer}:{reviewer:unknown}){
 const feedback=presentReviewer(reviewer);
 return <section aria-label="Reviewer feedback"><h3>Reviewer feedback</h3><p><strong>{feedback.verdict}</strong></p>{feedback.notesStyle==='list'&&feedback.notes.length>0?<ul>{feedback.notes.map((note,index)=><li key={index}>{note}</li>)}</ul>:feedback.notes.map((note,index)=><p key={index}>{note}</p>)}{feedback.notice&&<p className="subtle">{feedback.notice}</p>}<p className="subtle">Reviewer approval does not replace your business-flow review and human acceptance.</p></section>;
}
function verifiedLabSummary(run:Run,technical:any):{passed:number;notApplicable:number|null}|null{
 const v1=technical?.scope==='fox-native-technical-verification-v1'&&technical.schema_version===1;
 const v2=technical?.scope==='fox-native-technical-verification-v2'&&technical.schema_version===2&&technical.policy_id==='jsn-clean-native-v2';
 if(!['VERIFIED','ACCEPTED'].includes(run.state)||(!v1&&!v2)||technical.job_id!==run.id
  ||technical.source_manifest_sha256!==run.source_hash||technical.authenticated_runtime_passed!==true||technical.clean_schema_install_passed!==true
  ||typeof technical.package_sha256!=='string'||!/^[a-f0-9]{64}(?![^])/.test(technical.package_sha256)
  ||!Array.isArray(technical.required_tests)||!technical.required_tests.length
  ||!technical.required_tests.every((test:unknown)=>typeof test==='string'&&test.length>0)
  ||new Set(technical.required_tests).size!==technical.required_tests.length)return null;
 if(v1)return {passed:technical.required_tests.length,notApplicable:null};
 const plan=technical.test_plan,cases=plan?.cases;
 if(plan?.scope!=='fox-native-qa-plan-v2'||plan.schema_version!==1||!Array.isArray(cases)||cases.length!==14
  ||!cases.every((item:any)=>typeof item?.name==='string'&&item.name.length>0&&typeof item.applicable==='boolean')
  ||new Set(cases.map((item:any)=>item.name)).size!==cases.length)return null;
 const applicable=cases.filter((item:any)=>item.applicable).map((item:any)=>item.name).sort();
 if(applicable.length<10||JSON.stringify(applicable)!==JSON.stringify([...technical.required_tests].sort()))return null;
 return {passed:technical.required_tests.length,notApplicable:cases.filter((item:any)=>!item.applicable).length};
}
function RunEvidence({pid,run}:{pid:string;run:Run}){
 const [evidence,setEvidence]=useState<any>(null);
 useEffect(()=>{api(`/projects/${pid}/runs/${run.id}/evidence`).then(setEvidence).catch(()=>{});},[pid,run.id,run.state]);
 if(!evidence)return null;
 const technical=evidence.technical_verification;
 const labVerified=verifiedLabSummary(run,technical);
 return <section aria-label="Conversion evidence"><h3>Test the APEX prototype</h3><p>{evidence.prototype_scope}</p><a className="button secondary" href={evidence.application_url} target="_blank" rel="noopener noreferrer">Open APEX app {evidence.application_id} <ArrowRight size={16}/></a>{run.state==='QA_REQUIRED'?<p>Technical conversion checks passed; lab verification is pending. Acceptance and download stay locked until the required verification is recorded.</p>:labVerified?<section aria-label="Recorded lab verification" className="finding"><strong>Exact package verified in an isolated APEX workspace</strong><p>{labVerified.notApplicable===null?`${labVerified.passed} required browser checks passed, including two-user edit protection.`:`${labVerified.passed} applicable browser checks passed; ${labVerified.notApplicable} not applicable. Includes two-user edit protection.`} Tested with APEX {technical.observed_versions?.apex}.</p><p className="subtle">Package SHA-256: <code>{technical.package_sha256}</code></p><a href={`/api/projects/${pid}/runs/${run.id}/evidence`} target="_blank" rel="noopener noreferrer">View verification and remediation evidence</a><p>These checks cover the exported prototype. Your business-flow review and acceptance are still separate.</p></section>:<p>{evidence.runtime_smoke_scope==='login_page_reachability_only'?'The pipeline runtime check proves login-page reachability only. ':''}Review the recorded verification and test the supported business flow before accepting. A successful import does not prove customer compatibility.</p>}<ReviewerFeedback reviewer={evidence.reviewer}/>{evidence.remediation_items?.map((item:any,i:number)=><div className="finding" key={i}><strong>{item.kind}</strong><p>{item.file}: {item.detail||item.action||JSON.stringify(item)}</p></div>)}</section>;
}
function ManagedVerificationStatus({run}:{run:Run}){
 const status=presentVerificationStatus(run.state,run.verification_status);
 if(!status)return null;
 return <section className="finding" aria-label="Managed verification status" aria-live="polite"><div className="section-heading"><h4>Managed verification</h4><span className={'badge '+(status.contactOperator?'warn':'')}>{status.label}</span></div><p>{status.message}</p><p className="subtle">{status.contactMessage}{status.lastSeen&&<> Last recorded contact: <time dateTime={status.lastSeen.value}>{status.lastSeen.label}</time>.</>}</p><p className="subtle">Contact is reported for the verification service, not this specific run. It does not prove that this attempt is still active.</p>{status.action&&<p><strong>{status.action}</strong></p>}<p className="subtle">Verification is managed by the FOX operator. You do not need to install or run test tools.</p></section>;
}
function Acceptance({pid,run,onAccepted,sourceBusy,isCurrent}:{pid:string;run:Run;onAccepted:()=>Promise<void>;sourceBusy:boolean;isCurrent:()=>boolean}){
 const [tested,setTested]=useState(false),[reviewed,setReviewed]=useState(false),[notes,setNotes]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const reviewRevision=useRef(0),reviewVersion=reviewRevision.current;
 function changeReview(update:()=>void){if(sourceBusy||busy||!isCurrent()||reviewVersion!==reviewRevision.current)return;reviewRevision.current++;update();}
 async function accept(){if(sourceBusy||busy||!isCurrent()||reviewVersion!==reviewRevision.current||!tested||!reviewed||!notes.trim())return;reviewRevision.current++;setBusy(true);setError('');try{await api(`/projects/${pid}/runs/${run.id}/accept`,json({source_hash:run.source_hash,business_flow_tested:tested,remediation_reviewed:reviewed,notes}));await onAccepted();}catch(e){setError((e as Error).message);}finally{setBusy(false);}}
 return <section aria-label="Human acceptance"><h3>Final human review</h3><p>Confirm the business behavior in the tested APEX app. Import success does not prove equivalence.</p><label className="acceptance-check"><input type="checkbox" disabled={sourceBusy||busy} checked={tested} onChange={e=>changeReview(()=>setTested(e.target.checked))}/><span>I tested the business flow.</span></label><label className="acceptance-check"><input type="checkbox" disabled={sourceBusy||busy} checked={reviewed} onChange={e=>changeReview(()=>setReviewed(e.target.checked))}/><span>I reviewed the unresolved remediation.</span></label><label>Test notes<textarea disabled={sourceBusy||busy} value={notes} maxLength={2000} onChange={e=>changeReview(()=>setNotes(e.target.value))}/></label>{error&&<p role="alert">{error}</p>}<button disabled={sourceBusy||busy||!tested||!reviewed||!notes.trim()} onClick={()=>void accept()}>Accept tested package</button></section>;
}
function ProjectAcceptance({controls,onAccept}:{controls:HumanReviewControls;onAccept:(values:{business_flow_tested:boolean;remediation_reviewed:boolean;notes:string})=>Promise<WorkbenchActionResult>}){
 const [tested,setTested]=useState(false),[reviewed,setReviewed]=useState(false),[notes,setNotes]=useState('');
 return <section aria-label="Human acceptance"><h3>Final human review</h3><p>Test each supported business flow in the APEX application and review the unresolved remediation. Technical checks do not establish business equivalence.</p><label className="acceptance-check"><input type="checkbox" disabled={controls.disabled} checked={tested} onChange={event=>setTested(event.target.checked)}/><span>I tested the business flow.</span></label><label className="acceptance-check"><input type="checkbox" disabled={controls.disabled} checked={reviewed} onChange={event=>setReviewed(event.target.checked)}/><span>I reviewed the unresolved remediation.</span></label><label>Test notes<textarea disabled={controls.disabled} value={notes} maxLength={2000} onChange={event=>setNotes(event.target.value)}/></label><button type="button" disabled={controls.disabled||!tested||!reviewed||!notes.trim()} onClick={()=>{if(!controls.disabled&&tested&&reviewed&&notes.trim())void controls.perform(()=>onAccept({business_flow_tested:tested,remediation_reviewed:reviewed,notes}));}}>Accept tested package</button></section>;
}
function ProjectEvidence({pid,run}:{pid:string;run:ProjectRun}){
 const [evidence,setEvidence]=useState<any>(null),[error,setError]=useState('');
 const previewUrl=(run as ProjectRun&{application_url?:unknown}).application_url;
 const canPreview=presentProjectRun(run,run.source_hash,pid).canPreview&&typeof previewUrl==='string'&&/^https:\/\//i.test(previewUrl);
 useEffect(()=>{let current=true;setEvidence(null);setError('');api(`/projects/${pid}/runs/${run.id}/evidence`).then(value=>{if(current)setEvidence(value);}).catch(()=>{if(current)setError('Evidence could not be loaded. No result is being assumed.');});return()=>{current=false;};},[pid,run.id,run.state]);
 return <section className="panel" aria-label="Project conversion evidence"><h2>Mapping and remediation</h2><p>Run <code>{run.id}</code></p>{canPreview&&<a className="button secondary" href={previewUrl as string} target="_blank" rel="noopener noreferrer">Open APEX application <ArrowRight size={16}/></a>}{error?<p role="alert">{error}</p>:!evidence?<p role="status">Loading recorded evidence…</p>:<><p>{evidence.prototype_scope}</p><ReviewerFeedback reviewer={evidence.reviewer}/>{Array.isArray(evidence.remediation_items)&&evidence.remediation_items.map((item:any,index:number)=><div className="finding" key={index}><strong>{typeof item?.kind==='string'?item.kind:'Remediation item'}</strong><p>{[item?.file,item?.detail??item?.action].filter(value=>typeof value==='string').join(': ')}</p></div>)}<a href={`/api/projects/${pid}/runs/${run.id}/evidence`} target="_blank" rel="noopener noreferrer">View complete recorded evidence</a><p>Technical verification and genuine human acceptance are separate. No missing evidence is counted as passed.</p></>}</section>;
}
function App(){
 const [startupError,setStartupError]=useState('');
 const [session,setSession]=useState<Session|null>(null),[loading,setLoading]=useState(true),[projects,setProjects]=useState<Project[]>([]),[detail,setDetail]=useState<Detail|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[creating,setCreating]=useState(false),[tab,setTab]=useState('Sources'),[consent,setConsent]=useState([false,false,false]);
 const [sourceUiEpoch,setSourceUiEpoch]=useState(0),[consentSource,setConsentSource]=useState<string|null>(null);
 const [preparationOpen,setPreparationOpen]=useState(false),[evidenceRun,setEvidenceRun]=useState<string|null>(null);
 type PendingProjectAction={kind:'generate'|'accept'|'source';source_hash:string;run_id?:string;target_source_set_id?:string;ack?:{source_hash:string;selected_source_set_id:string|null}};
 const pendingProjectActions=useRef<Record<string,PendingProjectAction>>({});
 const [uncertainProjects,setUncertainProjects]=useState<Record<string,boolean>>({});
 type PendingProjectCreation={name:string;customer:string;prior_ids:string[];id?:string};
 const creationPending=useRef<PendingProjectCreation|null>(null),creationInFlight=useRef(false);
 const [creationUnknown,setCreationUnknown]=useState(false);
 const safetyOwner=useRef<string|null>(null),safetyReady=useRef(false),safetyCorrupt=useRef(false);
 const [safetyStorageReady,setSafetyStorageReady]=useState(false),[safetyWarning,setSafetyWarning]=useState('');
 const safetyStorageKey='fox.project-uncertainty.v1';
 function storageProblem(corrupt=false){safetyReady.current=false;safetyCorrupt.current=corrupt;setSafetyStorageReady(false);setSafetyWarning(corrupt?'Saved operation safety state could not be verified. Project changes are paused. Check saved project status; no operation will be repeated.':'Browser session storage is unavailable. Project changes are paused so an unanswered request cannot be retried after reload. Check saved project status when storage is available.');}
 function writeSafety(projectActions:Record<string,PendingProjectAction>,creation:PendingProjectCreation|null){
  if(!safetyOwner.current||safetyCorrupt.current)return false;
  try{const raw=JSON.stringify({version:1,owner:safetyOwner.current,projects:projectActions,creation});if(raw.length>65536||Object.keys(projectActions).length>100)throw new Error('Safety state exceeds its limit.');sessionStorage.setItem(safetyStorageKey,raw);safetyReady.current=true;setSafetyStorageReady(true);setSafetyWarning('');return true;}
  catch{storageProblem();return false;}
 }
 function restoreSafety(value:Session){
  if(value.conversion_profile!=='native-project-v1')return;
  const sameOwner=safetyOwner.current===value.username;
  if(safetyOwner.current&&safetyOwner.current!==value.username){pendingProjectActions.current={};creationPending.current=null;setUncertainProjects({});setCreationUnknown(false);setCreating(false);}
  safetyOwner.current=value.username;
  try{
   const raw=sessionStorage.getItem(safetyStorageKey);let saved:any=null;
   if(raw!==null){if(raw.length>65536){storageProblem(true);return;}try{saved=JSON.parse(raw);}catch{storageProblem(true);return;}
    if(!saved||typeof saved!=='object'||Array.isArray(saved)||saved.version!==1||typeof saved.owner!=='string'||!saved.owner||saved.owner.length>128){storageProblem(true);return;}
    if(saved.owner!==value.username){sessionStorage.removeItem(safetyStorageKey);saved=null;}
   }
   if(saved){
    const object=(item:any)=>item&&typeof item==='object'&&!Array.isArray(item),exact=(item:any,keys:string[])=>object(item)&&Object.keys(item).sort().join('|')===keys.sort().join('|');
    const pid=(item:any)=>typeof item==='string'&&/^[a-f0-9]{32}$/.test(item),hash=(item:any)=>typeof item==='string'&&/^[a-f0-9]{64}$/.test(item),sid=(item:any)=>typeof item==='string'&&/^ss-[a-f0-9]{32}$/.test(item);
    let valid=exact(saved,['version','owner','projects','creation'])&&object(saved.projects)&&Object.keys(saved.projects).length<=100;
    if(valid)for(const [id,rawPending] of Object.entries(saved.projects)){
     const item=rawPending as any;valid=pid(id)&&object(item)&&Object.keys(item).every(key=>['kind','source_hash','run_id','target_source_set_id','ack'].includes(key))&&['generate','accept','source'].includes(item.kind)&&hash(item.source_hash)
      &&(item.run_id===undefined||typeof item.run_id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$/.test(item.run_id))&&(item.kind!=='accept'||typeof item.run_id==='string')
      &&(item.target_source_set_id===undefined||sid(item.target_source_set_id))&&(item.ack===undefined||exact(item.ack,['source_hash','selected_source_set_id'])&&hash(item.ack.source_hash)&&(item.ack.selected_source_set_id===null||sid(item.ack.selected_source_set_id)));
     if(!valid)break;
    }
    if(valid&&saved.creation!==null){const item=saved.creation;valid=object(item)&&Object.keys(item).every(key=>['name','customer','prior_ids','id'].includes(key))&&typeof item.name==='string'&&item.name.length<=80&&/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(item.name)&&typeof item.customer==='string'&&item.customer.length<=100&&!/[\u0000-\u001f\u007f]/.test(item.customer)&&Array.isArray(item.prior_ids)&&item.prior_ids.length<=100&&item.prior_ids.every(pid)&&new Set(item.prior_ids).size===item.prior_ids.length&&(item.id===undefined||pid(item.id));}
    if(!valid){storageProblem(true);return;}
   }
   safetyCorrupt.current=false;const projectActions=saved?.projects??(sameOwner?pendingProjectActions.current:{}),creation=saved?.creation??(sameOwner?creationPending.current:null);
   if(!writeSafety(projectActions,creation))return;
   pendingProjectActions.current=projectActions;creationPending.current=creation;setUncertainProjects(Object.fromEntries(Object.keys(projectActions).map(id=>[id,true])));setCreationUnknown(Boolean(creation));if(creation)setCreating(true);
  }catch{storageProblem();}
 }
 async function checkSavedProjectStatus(){
  if(busy||sourceActionInFlight.current||!session)return;setBusy(true);setError('');restoreSafety(session);
  try{await refresh();setError(safetyReady.current?'Saved project status loaded. Open the affected project and check its existing result before another operation.':'Saved projects were loaded read-only. The safety state is still unavailable; no pending operation was assumed complete.');}
  catch{setError('Saved project status could not be loaded. No operation was repeated.');}finally{setBusy(false);}
 }
 async function signOutWorkbench(){await api('/logout',json({}));try{sessionStorage.removeItem(safetyStorageKey);}catch{/* Never reuse in-memory authority after logout. */}safetyOwner.current=null;safetyReady.current=false;safetyCorrupt.current=false;pendingProjectActions.current={};creationPending.current=null;setUncertainProjects({});setCreationUnknown(false);setSafetyStorageReady(false);setSafetyWarning('');setSession(null);closeProject();}
 function sourceIdentity(value:Detail|null){return value?JSON.stringify([value.id,value.inventory.selected_source_set_id,value.inventory.source_hash]):null;}
 const sourceKey=sourceIdentity(detail),sourceUiKey=sourceKey+'-'+sourceUiEpoch,consentIsCurrent=sourceKey!==null&&consentSource===sourceKey;
 const detailRequest=useRef(0),listRequest=useRef(0),sourceActionInFlight=useRef(false),requestedProject=useRef<string|null>(detail?.id??null),observedSource=useRef(sourceKey),sourceEpoch=useRef(0),consentRevision=useRef(0);
 const consentVersion=consentRevision.current;
 function sourceUiIsCurrent(){return sourceKey!==null&&requestedProject.current===detail?.id&&observedSource.current===sourceKey&&sourceEpoch.current===sourceUiEpoch;}
 function resetConsent(){consentRevision.current++;setConsent([false,false,false]);setConsentSource(null);}
 function resetSourceUi(){resetConsent();sourceEpoch.current++;setSourceUiEpoch(value=>value+1);}
 function closeProject(){if(sourceActionInFlight.current&&detail?.inventory.conversion_profile==='native-project-v1')return;detailRequest.current++;requestedProject.current=null;observedSource.current=null;setDetail(null);setPreparationOpen(false);setEvidenceRun(null);resetSourceUi();}
 async function refresh(){const request=++listRequest.current;const value=await api('/projects');if(request===listRequest.current)setProjects(value);}
 async function open(id:string,currentOnly=false){
  if(sourceActionInFlight.current||(currentOnly&&requestedProject.current!==id))return;
  if(!currentOnly)requestedProject.current=id;const request=++detailRequest.current,value=await api('/projects/'+id);
  if(request!==detailRequest.current||requestedProject.current!==id)return;
  if(value?.id!==id||!readableSourceState(value?.inventory))throw new Error('Source state is unavailable.');
  const identity=sourceIdentity(value);if(identity!==observedSource.current)resetSourceUi();observedSource.current=identity;
  setDetail(current=>request===detailRequest.current&&requestedProject.current===id?value:current);
 }
 function readableSourceState(value:any){return value&&typeof value.source_hash==='string'&&/^[a-f0-9]{64}(?![^])/.test(value.source_hash)&&(value.selected_source_set_id===null||(typeof value.selected_source_set_id==='string'&&/^ss-[a-f0-9]{32}(?![^])/.test(value.selected_source_set_id)));}
 async function readSourceProject(pid:string){const value=await api('/projects/'+pid);if(value?.id!==pid||!readableSourceState(value?.inventory))throw new Error('Source state is unavailable.');return value as Detail;}
 function sourceActionError(error:unknown,pid:string,request:number,refreshRequired:boolean){
  if(request!==detailRequest.current)return;
  setError(sourceHistoryErrorMessage(error)+(refreshRequired?' Reopen the project to load its current source state before continuing.':''));
  if(refreshRequired){if(requestedProject.current===pid){requestedProject.current=null;observedSource.current=null;}setDetail(current=>request===detailRequest.current&&current?.id===pid?null:current);}
 }
 async function changeSource(operation:(pid:string)=>Promise<SourceSelectionAck>){
  if(!detail||busy||sourceActionInFlight.current||!sourceUiIsCurrent())return {ok:false,refreshRequired:false};
  const pid=detail.id,request=++detailRequest.current;listRequest.current++;sourceActionInFlight.current=true;setBusy(true);setError('');resetSourceUi();let acknowledged=false;
  try{const ack=await operation(pid);acknowledged=true;const value=await readSourceProject(pid);assertRefreshedSourceProject(value,pid,ack);await refresh();if(request===detailRequest.current){resetSourceUi();observedSource.current=sourceIdentity(value);}setDetail(current=>request===detailRequest.current&&current?.id===pid?value:current);return {ok:true,refreshRequired:false};}
  catch(error){const refreshRequired=acknowledged||sourceHistoryRefreshRequired(error);sourceActionError(error,pid,request,refreshRequired);return {ok:false,refreshRequired};}
  finally{sourceActionInFlight.current=false;setBusy(false);}
 }
 async function refreshSourceProject(){
  if(!detail||busy||sourceActionInFlight.current||!sourceUiIsCurrent())return false;
  const pid=detail.id,request=++detailRequest.current;listRequest.current++;sourceActionInFlight.current=true;setBusy(true);setError('');resetSourceUi();
  try{const value=await readSourceProject(pid);await refresh();if(request===detailRequest.current){resetSourceUi();observedSource.current=sourceIdentity(value);}setDetail(current=>request===detailRequest.current&&current?.id===pid?value:current);return true;}
  catch(error){sourceActionError(error,pid,request,true);return false;}
  finally{sourceActionInFlight.current=false;setBusy(false);}
 }
 async function startup(){setLoading(true);setStartupError('');try{const s=await api('/session');setSession(s);restoreSafety(s);await refresh();}catch(e){if((e as {status?:number}).status!==401)setStartupError((e as Error).message);}finally{setLoading(false);}}
 useEffect(()=>{void startup();},[]);
 useEffect(()=>{if(busy||!detail?.runs.some(r=>['QUEUED','PROCESSING','QA_REQUIRED'].includes(r.state)))return;const delay=detail.runs.some(r=>['QUEUED','PROCESSING'].includes(r.state))?3000:15000;const timer=setInterval(()=>open(detail.id,true).catch(()=>{}),delay);return()=>clearInterval(timer);},[detail,busy]);
 async function act(fn:()=>Promise<void>){if(sourceActionInFlight.current)return;setError('');setBusy(true);try{await fn();}catch(e){setError((e as Error).message);}finally{setBusy(false);}}
 async function login(e:FormEvent<HTMLFormElement>){e.preventDefault();const d=new FormData(e.currentTarget);await act(async()=>{await api('/login',json(Object.fromEntries(d)));const value=await api('/session');setSession(value);restoreSafety(value);await refresh();});}
 async function create(e:FormEvent<HTMLFormElement>){e.preventDefault();const d=new FormData(e.currentTarget);const name=String(d.get('name')??'').trim();if(session?.conversion_profile==='native-project-v1'&&(!name||name.length>80||!/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(name))){setError('Use up to 80 plain letters, numbers, spaces, dots, hyphens or underscores for the project name.');return;}d.set('name',name);await act(async()=>{const p=await api('/projects',json(Object.fromEntries(d)));setCreating(false);await refresh();await open(p.id);});}
 async function createWorkbenchProject(event:FormEvent<HTMLFormElement>){
  event.preventDefault();if(busy||creationInFlight.current||creationPending.current||!safetyReady.current)return;
  const data=new FormData(event.currentTarget),name=String(data.get('name')??'').trim(),customer=String(data.get('customer')??'').trim(),description=String(data.get('description')??'').trim();
  if(!name||name.length>80||!/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(name)){setError('Use up to 80 plain letters, numbers, spaces, dots, hyphens or underscores for the project name.');return;}
  const pending:PendingProjectCreation={name,customer,prior_ids:projects.filter(project=>project.name===name&&project.customer===customer).map(project=>project.id)};
  if(pending.prior_ids.length>100||!writeSafety(pendingProjectActions.current,pending)){storageProblem();return;}
  creationInFlight.current=true;setBusy(true);setError('');creationPending.current=pending;
  let acknowledged=false;
  try{const result=await api('/projects',json({name,customer,description}));acknowledged=true;if(typeof result?.id!=='string'||!/^[a-f0-9]{32}$/.test(result.id))throw new Error('Project acknowledgement is incomplete.');creationPending.current.id=result.id;if(!writeSafety(pendingProjectActions.current,creationPending.current))throw new Error('Safety state unavailable.');await refresh();await open(result.id);if(!writeSafety(pendingProjectActions.current,null))throw new Error('Safety state unavailable.');creationPending.current=null;setCreationUnknown(false);setCreating(false);}
  catch(caught){if(!acknowledged&&[400,401,403,409,422].includes((caught as {status?:number})?.status??0)&&writeSafety(pendingProjectActions.current,null)){creationPending.current=null;setError(caught instanceof Error?caught.message:'The project could not be created.');}else{setCreationUnknown(true);setError('Project creation could not be confirmed. Check the saved project list before submitting it again.');}}
  finally{creationInFlight.current=false;setBusy(false);}
 }
 async function reconcileProjectCreation(){
  const pending=creationPending.current;if(!pending||busy||creationInFlight.current)return;
  creationInFlight.current=true;setBusy(true);setError('');
  try{const values=await api('/projects') as Project[];if(!Array.isArray(values))throw new Error('Project list unavailable.');setProjects(values);
   const matches=values.filter(project=>pending.id?project.id===pending.id:!pending.prior_ids.includes(project.id)&&project.name===pending.name&&project.customer===pending.customer);
   if(matches.length!==1){setError('The saved list does not yet confirm that project creation. Creating it again remains paused. No request was repeated.');return;}
   await open(matches[0].id);if(!writeSafety(pendingProjectActions.current,null)){setError('The project was found, but its safety state could not be saved. Changes remain paused.');return;}creationPending.current=null;setCreationUnknown(false);setCreating(false);
  }catch{setError('The project list could not be checked. Creating it again remains paused.');}
  finally{creationInFlight.current=false;setBusy(false);}
 }
 async function upload(files:File[],mode:UploadMode){
  if(!detail||busy||sourceActionInFlight.current||!sourceUiIsCurrent())return false;
  const pid=detail.id,expected=detail.inventory.selected_source_set_id,request=++detailRequest.current;listRequest.current++;sourceActionInFlight.current=true;setBusy(true);setError('');resetConsent();let posted=false,acknowledged=false;
  try{
   if(expected!==null&&(typeof expected!=='string'||!/^ss-[a-f0-9]{32}(?![^])/.test(expected)))throw new Error('Source state is unavailable.');
   const selected=await checkSelectedSources(files,mode);if(request!==detailRequest.current)return false;
   const d=new FormData();selected.files.forEach(f=>d.append('files',f));if(selected.manifest)d.append('prepared_manifest',selected.manifest);d.append('expected_current_source_set_id',expected===null?'null':expected);
   posted=true;const assessment=await api('/projects/'+pid+'/sources',{method:'POST',body:d});acknowledged=true;
   const value=await readSourceProject(pid);if(!readableSourceState(assessment)||assessment.selected_source_set_id!==value.inventory.selected_source_set_id||assessment.source_hash!==value.inventory.source_hash)throw new Error('Source state changed while refreshing.');
   await refresh();if(request===detailRequest.current){resetSourceUi();observedSource.current=sourceIdentity(value);}setDetail(current=>request===detailRequest.current&&current?.id===pid?value:current);return true;
  }catch(error){const rejected=posted&&!acknowledged&&[401,403,413,415,422].includes((error as {status?:number})?.status??0);const refreshRequired=acknowledged||(posted&&!rejected&&sourceHistoryRefreshRequired(error))||(!posted&&!readableSourceState(detail.inventory));sourceActionError(error,pid,request,refreshRequired);return false;}
  finally{sourceActionInFlight.current=false;setBusy(false);}
 }
 function projectContext():ProjectActionContext|null{
  if(!detail)return null;
  const plan=detail.project_plan as {plan_sha256?:unknown}|undefined;
  return {project_id:detail.id,source_hash:detail.inventory.source_hash,selected_source_set_id:detail.inventory.selected_source_set_id,expected_current_source_set_id:detail.inventory.selected_source_set_id,plan_sha256:typeof plan?.plan_sha256==='string'?plan.plan_sha256:null};
 }
 function currentProjectContext(context:ProjectActionContext){
  const current=projectContext();return Boolean(current&&sourceUiIsCurrent()&&current.project_id===context.project_id&&current.source_hash===context.source_hash&&current.selected_source_set_id===context.selected_source_set_id&&context.expected_current_source_set_id===current.selected_source_set_id&&context.plan_sha256===current.plan_sha256);
 }
 function setProjectUncertain(pid:string,pending:PendingProjectAction|null){
  const next={...pendingProjectActions.current};if(pending)next[pid]=pending;else delete next[pid];
  if(!writeSafety(next,creationPending.current))return false;
  pendingProjectActions.current=next;setUncertainProjects(current=>({...current,[pid]:Boolean(pending)}));return true;
 }
 function reconciledProjectAction(value:Detail,pending:PendingProjectAction){
  if(pending.kind==='source')return pending.ack?value.inventory.source_hash===pending.ack.source_hash&&value.inventory.selected_source_set_id===pending.ack.selected_source_set_id:Boolean(pending.target_source_set_id&&value.inventory.selected_source_set_id===pending.target_source_set_id);
  const run=value.runs.find(item=>runBelongsToProject(item,value.id)&&item.source_hash===pending.source_hash&&(!pending.run_id||item.id===pending.run_id));
  return Boolean(run&&(pending.kind==='generate'||presentProjectRun(run as ProjectRun,value.inventory.source_hash,value.id).humanAccepted));
 }
 function publishProject(value:Detail,request:number){
  if(request!==detailRequest.current||requestedProject.current!==value.id)return;
  const identity=sourceIdentity(value);if(identity!==observedSource.current)resetSourceUi();observedSource.current=identity;setDetail(value);
 }
 async function refreshProjectWorkbench(pid:string):Promise<WorkbenchActionResult>{
  if(busy||sourceActionInFlight.current||requestedProject.current!==pid)return {status:'rejected',message:'Wait for the current operation to finish.'};
  const request=++detailRequest.current;sourceActionInFlight.current=true;setBusy(true);setError('');
  try{const value=await readSourceProject(pid);publishProject(value,request);if(!safetyReady.current&&session)restoreSafety(session);const pending=pendingProjectActions.current[pid];
   const safe=safetyReady.current&&(!pending||reconciledProjectAction(value,pending))&&setProjectUncertain(pid,null);
   return {status:'confirmed',safe_to_continue:safe,message:safe?'Current project status loaded.':'Current status loaded, but the previous operation is not confirmed. Actions remain paused; contact FOX support with this project name. No operation was repeated.'};
  }catch{return {status:'unconfirmed',message:'The status check failed. No operation was repeated.'};}
  finally{sourceActionInFlight.current=false;setBusy(false);}
 }
 async function projectMutation(context:ProjectActionContext,pending:PendingProjectAction,operation:()=>Promise<void>):Promise<WorkbenchActionResult>{
  if(busy||sourceActionInFlight.current||!safetyReady.current||pendingProjectActions.current[context.project_id]||!currentProjectContext(context))return {status:'rejected',message:'The project or source version changed, or its safety state is unavailable. Refresh it before continuing.'};
  const pid=context.project_id,request=++detailRequest.current;sourceActionInFlight.current=true;setBusy(true);setError('');
  if(!setProjectUncertain(pid,pending)){sourceActionInFlight.current=false;setBusy(false);return {status:'rejected',message:'The safety state could not be saved. No request was sent.'};}let acknowledged=false;
  try{await operation();acknowledged=true;if(!writeSafety(pendingProjectActions.current,creationPending.current))return {status:'unconfirmed'};const value=await readSourceProject(pid);publishProject(value,request);
   if(!reconciledProjectAction(value,pending))return {status:'unconfirmed'};
   if(!setProjectUncertain(pid,null))return {status:'unconfirmed'};void refresh().catch(()=>{});return {status:'confirmed'};
  }catch(caught){const status=(caught as {status?:number})?.status;
   if(!acknowledged&&[400,401,403,404,409,413,415,422].includes(status??0)&&setProjectUncertain(pid,null)){return {status:'rejected',message:caught instanceof Error?caught.message:'The request was rejected. Refresh the project.'};}
   return {status:'unconfirmed'};
  }finally{sourceActionInFlight.current=false;setBusy(false);}
 }
 async function uploadProjectSources(files:File[],mode:UploadMode,context:ProjectActionContext):Promise<WorkbenchActionResult>{
  let selected:Awaited<ReturnType<typeof checkSelectedSources>>;
  try{selected=await checkSelectedSources(files,mode);}catch(caught){return {status:'rejected',message:caught instanceof Error?caught.message:'The selected files could not be checked.'};}
  const pending:PendingProjectAction={kind:'source',source_hash:context.source_hash};
  return projectMutation(context,pending,async()=>{const data=new FormData();selected.files.forEach(file=>data.append('files',file));if(selected.manifest)data.append('prepared_manifest',selected.manifest);data.append('expected_current_source_set_id',context.expected_current_source_set_id??'null');
   const result=await api(`/projects/${context.project_id}/sources`,{method:'POST',body:data});if(!readableSourceState(result))throw new Error('Upload acknowledgement is incomplete.');pending.ack={source_hash:result.source_hash,selected_source_set_id:result.selected_source_set_id};
  });
 }
 async function selectProjectVersion(id:string,context:ProjectActionContext):Promise<WorkbenchActionResult>{
  const pending:PendingProjectAction={kind:'source',source_hash:context.source_hash,target_source_set_id:id};
  return projectMutation(context,pending,async()=>{const ack=await selectSourceSet(context.project_id,id,context.expected_current_source_set_id);pending.ack={source_hash:ack.sourceHash,selected_source_set_id:ack.selectedSourceSetId};});
 }
 async function excludeProjectFile(id:string,fileId:string,expected:string){
  const context=projectContext();if(!context||context.expected_current_source_set_id!==expected)return {ok:false,refreshRequired:true};
  const pending:PendingProjectAction={kind:'source',source_hash:context.source_hash};
  const result=await projectMutation(context,pending,async()=>{const ack=await excludeSourceFile(context.project_id,id,fileId,expected);pending.ack={source_hash:ack.sourceHash,selected_source_set_id:ack.selectedSourceSetId};});
  return {ok:result.status==='confirmed',refreshRequired:result.status!=='confirmed'};
 }
 async function generateProject(context:ProjectActionContext,confirmations:ProcessConfirmations){
  if(!context.plan_sha256||!context.expected_current_source_set_id||!Object.values(confirmations).every(value=>value===true))return {status:'rejected' as const,message:'Review the current plan and confirm all three processing statements.'};
  const pending:PendingProjectAction={kind:'generate',source_hash:context.source_hash};
  return projectMutation(context,pending,async()=>{const result=await api(`/projects/${context.project_id}/runs`,json({source_hash:context.source_hash,expected_current_source_set_id:context.expected_current_source_set_id,plan_sha256:context.plan_sha256,...confirmations}));if(typeof result?.id!=='string')throw new Error('Run acknowledgement is incomplete.');pending.run_id=result.id;});
 }
 async function acceptProject(context:ProjectActionContext,values:{business_flow_tested:boolean;remediation_reviewed:boolean;notes:string}){
  if(!context.run_id||context.run_source_hash!==context.source_hash||!values.business_flow_tested||!values.remediation_reviewed||!values.notes.trim())return {status:'rejected' as const,message:'Complete your review of the current source version first.'};
  return projectMutation(context,{kind:'accept',source_hash:context.run_source_hash,run_id:context.run_id},async()=>{await api(`/projects/${context.project_id}/runs/${context.run_id}/accept`,json({source_hash:context.run_source_hash,...values}));});
 }
 function projectOutput(context:ProjectActionContext,kind:'preview'|'download'|'evidence'){
  if(!detail||busy||pendingProjectActions.current[context.project_id]||!currentProjectContext(context))return;
  const run=detail.runs.find(item=>item.id===context.run_id&&item.source_hash===context.run_source_hash);if(!run||!runBelongsToProject(run,detail.id))return;
  const view=presentProjectRun(run,detail.inventory.source_hash,detail.id);
  if(kind==='download'&&view.canDownload)window.location.assign(`/api/projects/${detail.id}/runs/${run.id}/download`);
  else if(kind==='evidence'||kind==='preview'&&view.canPreview)setEvidenceRun(run.id);
 }
 if(loading)return <main className="signin"><span className="brand">FOX<span> / </span>Opening your workspace…</span></main>;
 if(startupError)return <main className="signin"><section className="login"><h1>FOX</h1><p role="alert">{startupError}</p><button onClick={()=>void startup()}>Retry connection</button></section></main>;
 if(!session)return <main className="signin"><section className="login"><div className="eyebrow">FORMS → APEX</div><h1>Meet FOX<span>.</span></h1><p>Your Forms modernization workspace.<br/>Source evidence in. Reviewed prototypes out.</p><form onSubmit={login}><label>Username<input name="username" autoComplete="username" required/></label><label>Password<input name="password" type="password" autoComplete="current-password" required/></label>{error&&<div role="alert" className="error">{error}</div>}<button disabled={busy}>Sign in <ArrowRight size={17}/></button></form><small>Internal development preview · Authorized, redacted sources only</small></section></main>;
 if((detail?.inventory.conversion_profile??session.conversion_profile)==='native-project-v1'){
  const paused=!safetyStorageReady||Boolean(detail&&uncertainProjects[detail.id]),context=projectContext();
  const selectedEvidence=detail?.runs.find(run=>run.id===evidenceRun&&runBelongsToProject(run,detail.id));
  return <div className="shell"><aside><a className="brand" href="#" onClick={event=>{event.preventDefault();closeProject();}}>FOX<span>●</span></a><p className="brand-sub">FORMS TO APEX</p><nav><button className="nav-active" disabled={busy} onClick={()=>{closeProject();setCreating(false);}}><FolderOpen size={18}/> Projects <span>{projects.length}</span></button></nav><div className="aside-foot"><ShieldCheck size={20}/><strong>Evidence before export</strong><p>One project. All its forms.<br/>One reviewed APEX application.</p><small>Internal preview</small></div></aside><div className="workspace"><header><span>Modernization workspace</span><div>{session.username}<button className="icon" disabled={busy} aria-label="Sign out" onClick={()=>act(signOutWorkbench)}><LogOut size={17}/></button></div></header><main>{error&&<div role="alert" className="error">{error}</div>}{safetyWarning&&<section className="panel" role="alert"><h2>Check saved project status</h2><p>{safetyWarning}</p><button type="button" disabled={busy} onClick={()=>void checkSavedProjectStatus()}>Check saved project status</button></section>}
   {!detail?<ProjectDashboard projects={projects} busy={busy} onNewProject={creationUnknown||!safetyStorageReady?undefined:()=>setCreating(value=>!value)} onOpenProject={id=>void act(async()=>{setPreparationOpen(false);setEvidenceRun(null);await open(id);})} createProjectContent={<>{creationUnknown&&<section className="panel" role="status"><h2>Check the saved project first</h2><p>The creation result is unconfirmed. No duplicate project request will be sent.</p><button type="button" disabled={busy} onClick={()=>void reconcileProjectCreation()}>Check project creation status</button></section>}{creating&&<form className="panel project-form" onSubmit={createWorkbenchProject}><h2>Start a project</h2><label>Customer / organization<input name="customer" defaultValue={creationPending.current?.customer??''} disabled={busy||creationUnknown||!safetyStorageReady} required maxLength={100}/></label><label>Project name<input name="name" defaultValue={creationPending.current?.name??''} disabled={busy||creationUnknown||!safetyStorageReady} required maxLength={80} pattern="[A-Za-z0-9][A-Za-z0-9 ._\-]*" title="Up to 80 plain letters, numbers, spaces, dots, hyphens or underscores"/></label><label>Business flow<textarea name="description" disabled={busy||creationUnknown||!safetyStorageReady} maxLength={1000} placeholder="What should this application help someone do?"/></label><button disabled={busy||creationUnknown||!safetyStorageReady}>Create project <ArrowRight size={16}/></button></form>}</>}/>:<>
    <ProjectWorkbench key={detail.id} project={detail} source={{project_id:detail.id,source_hash:detail.inventory.source_hash,selected_source_set_id:detail.inventory.selected_source_set_id}} plan={detail.project_plan} runs={detail.runs as ProjectRun[]} capabilities={{upload:detail.project_capabilities?.upload,generate:detail.project_capabilities?.process,local_preparation:{enabled:true}}} processingNotice={detail.processing_notice??''} busy={busy} unknownOutcome={paused} error={detail.project_plan_error} onBack={closeProject}
     onUpload={uploadProjectSources} onGenerate={generateProject} onSelectVersion={selectProjectVersion} onRefresh={value=>refreshProjectWorkbench(value.project_id)} onReloadProject={refreshProjectWorkbench}
     onRecovery={(kind,value)=>kind==='check_status'?refreshProjectWorkbench(value.project_id):Promise.resolve({status:'rejected',message:'Only a read-only status check is available. No retry or import was started.'})}
     onOpenPreparation={()=>setPreparationOpen(value=>!value)} onPreview={value=>projectOutput(value,'preview')} onDownload={value=>projectOutput(value,'download')} onEvidence={value=>projectOutput(value,'evidence')}
     renderHumanReview={(run,value,controls)=><ProjectAcceptance key={`${run.id}:${value.source_hash}:${value.selected_source_set_id}`} controls={controls} onAccept={review=>acceptProject(value,review)}/>}/>
    {selectedEvidence&&<ProjectEvidence key={`${detail.id}:${selectedEvidence.id}`} pid={detail.id} run={selectedEvidence as ProjectRun}/>}
    {preparationOpen&&<section aria-label="Local source preparation"><button type="button" className="secondary" disabled={busy} onClick={()=>setPreparationOpen(false)}>Close local preparation</button><LocalPreparation key={'project-local-'+sourceUiKey} busy={busy||paused} onUseReviewed={async files=>Boolean(context&&(await uploadProjectSources(files,'prepared',context)).status==='confirmed')}/></section>}
    <details className="panel"><summary>Source history and preparation receipt</summary><p>Saved versions and earlier results remain available. Selecting a different version clears unsubmitted conversion consent.</p><SourceVersionHistory key={detail.id+'-'+detail.inventory.selected_source_set_id+'-'+detail.inventory.source_hash} projectId={detail.id} selectedSourceSetId={detail.inventory.selected_source_set_id} currentSourceHash={detail.inventory.source_hash} busy={busy||paused} onUseVersion={async(id,expected)=>{if(!context||expected!==context.expected_current_source_set_id)return {ok:false,refreshRequired:true};const result=await selectProjectVersion(id,context);return {ok:result.status==='confirmed',refreshRequired:result.status!=='confirmed'};}} onExcludeFile={excludeProjectFile} onRefreshProject={async()=>{const result=await refreshProjectWorkbench(detail.id);return result.status==='confirmed'&&result.safe_to_continue===true;}}/>{detail.inventory.source_preparation&&<section aria-label="Source preparation receipt"><h3>{detail.inventory.source_preparation.mode==='PREPARED_SET_MATCH'&&detail.inventory.source_preparation.matches_current_source?'Prepared set matches the current sources':'Preparation receipt'}</h3><p>{detail.inventory.source_preparation.scope}</p>{detail.inventory.source_preparation.extraction_job_id&&<p>Local preparation job: <code>{detail.inventory.source_preparation.extraction_job_id}</code></p>}</section>}<a href={`/api/projects/${detail.id}/assessment`}>Download source assessment</a><p className="manifest">Current manifest SHA-256 <code>{detail.inventory.source_hash}</code></p></details>
   </>}
  </main><footer className="page-footer">FOX · Forms to APEX <span>Internal preview · No production data</span></footer></div></div>;
 }
 return <div className="shell"><aside><a className="brand" href="#" onClick={closeProject}>FOX<span>●</span></a><p className="brand-sub">FORMS TO APEX</p><nav><button className="nav-active" onClick={()=>{closeProject();setCreating(false);}}><FolderOpen size={18}/> Projects <span>{projects.length}</span></button></nav><div className="aside-foot"><ShieldCheck size={20}/><strong>Evidence before export</strong><p>AI-assisted conversion.<br/>Deterministic release checks.</p><small>Internal MVP · v0.1</small></div></aside><div className="workspace"><header><span>Modernization workspace</span><div>{session.username}<button className="icon" aria-label="Sign out" onClick={()=>act(async()=>{await api('/logout',json({}));setSession(null);closeProject();})}><LogOut size={17}/></button></div></header><main>{error&&<div role="alert" className="error">{error}</div>}
 {!detail?<><div className="page-heading"><div><div className="eyebrow">YOUR PORTFOLIO</div><h1>Every form has a story.</h1><p>Keep each customer's sources, gaps and conversion history together.</p></div><button onClick={()=>setCreating(!creating)}><Plus size={17}/> New project</button></div>{creating&&<form className="panel project-form" onSubmit={create}><h2>Start a project</h2><label>Customer / organization<input name="customer" required maxLength={100}/></label><label>Project name<input name="name" required maxLength={120}/></label><label>Business flow<textarea name="description" maxLength={1000} placeholder="What should the application help someone do?"/></label><button disabled={busy}>Create project <ArrowRight size={16}/></button></form>}<div className="section-heading"><h2>Projects</h2><span>{projects.length} workspaces</span></div>{projects.length===0?<section className="empty panel"><FolderOpen size={32}/><h2>A clean starting point.</h2><p>Create your first project, then add readable Forms XML and related source.<br/>FOX will flag candidate dependencies and separate remediation work.</p></section>:<div className="project-grid">{projects.map(p=><button className="project-card" key={p.id} onClick={()=>act(async()=>{setTab('Sources');setConsent([false,false,false]);await open(p.id);})}><div className="card-top"><FolderOpen size={22}/><ArrowRight size={18}/></div><div className="eyebrow">{p.customer}</div><h2>{p.name}</h2><p>{p.description||'No business flow described yet.'}</p><footer><span>{p.file_count} source files</span><span>{p.run_count} conversion runs</span></footer></button>)}</div>}<div className="boundary"><ShieldCheck size={21}/><p><strong>A prototype, with a clear boundary.</strong> Source presence is not proof of behavioral equivalence. Downloads are unlocked only after reviewer, SQLcl, import, runtime and reimport checks pass, followed by human acceptance.</p></div></>:<>
 <button className="back" onClick={closeProject}><ChevronLeft size={16}/> All projects</button><div className="page-heading"><div><div className="eyebrow">{detail.customer}</div><h1>{detail.name}</h1><p>{detail.description||'A focused Forms modernization project.'}</p></div><a className="button secondary" href={`/api/projects/${detail.id}/assessment`}><Download size={16}/> Assessment</a></div><SourceOverview inventory={detail.inventory} acceptedCount={detail.runs.filter(r=>r.state==='ACCEPTED').length} onReview={setTab}/><div className="tabs" role="tablist">{['Sources','Dependencies','Conversion runs'].map(t=><button role="tab" aria-selected={tab===t} key={t} className={tab===t?'selected':''} onClick={()=>setTab(t)}>{t}</button>)}</div>
 {tab==='Sources'&&<><LocalPreparation key={'local-'+sourceUiKey} busy={busy} onUseReviewed={files=>upload(files,'prepared')}/><SourceUpload key={'upload-'+sourceUiKey} busy={busy} preparation={detail.inventory.source_preparation} onUpload={upload}/><SourceVersionHistory key={detail.id+'-'+detail.inventory.selected_source_set_id+'-'+detail.inventory.source_hash} projectId={detail.id} selectedSourceSetId={detail.inventory.selected_source_set_id} currentSourceHash={detail.inventory.source_hash} busy={busy} onUseVersion={(sid,expected)=>changeSource(pid=>selectSourceSet(pid,sid,expected))} onExcludeFile={(sid,fileId,expected)=>changeSource(pid=>excludeSourceFile(pid,sid,fileId,expected))} onRefreshProject={refreshSourceProject}/><SourceEligibility inventory={detail.inventory}/><section className="panel"><h2>Current source versions</h2>{detail.inventory.files.length===0?<p>No source files yet. Your originals remain on your computer.</p>:detail.inventory.files.map(f=><div className="file-row" key={f.file}><FileCode2 size={20}/><div><strong>{f.file}</strong><small>SHA-256 {f.sha256.slice(0,16)}…</small></div><span>{(f.bytes/1024).toFixed(1)} KB</span></div>)}</section><p>Next: review missing linkages in <strong>Dependencies</strong>, then open <strong>Conversion runs</strong> to approve processing and convert this source version.</p></>}
 {tab==='Dependencies'&&<><div className="notice"><TriangleAlert size={20}/><p>{detail.inventory.scope_note}</p></div><section className="panel"><h2>Source linkages</h2>{detail.inventory.dependencies.length===0?<p>No static linkages detected. This does not prove that dependencies are complete.</p>:detail.inventory.dependencies.map((d,i)=><div className="finding" key={i}><span className={'badge '+(d.status==='MISSING'?'warn':'')}>{d.status.replaceAll('_',' ')}</span><h3>{d.target} <small>{d.kind}</small></h3><code>{d.source} · {d.evidence}</code><p>{d.action}</p></div>)}</section><section className="panel"><h2>Separate remediation work</h2>{detail.inventory.issues.length===0?<p>No supported rule matched. Manual behavioral review is still required.</p>:detail.inventory.issues.map((d,i)=><div className="finding" key={i}><h3>{d.title}</h3><code>{d.source} · {d.target}</code><p>{d.action}</p></div>)}</section></>}
 {tab==='Conversion runs'&&<><SourceEligibility inventory={detail.inventory}/><section className="panel"><div className="section-heading"><h2>Process this source version</h2><span className="badge">{session.conversion_configured?'Integration configured':'Integration pending'}</span></div><p>{session.conversion_profile==='native-table-form-v1'?'Native beta: assess → OPAF mapping → independent review → deterministic native APEX generation → SQLcl validation → test import/export → required lab verification → human review → download. This is a synthetic table-form prototype, not a complete customer application conversion.':'Embedded workflow: analyze → generate → independent review → SQLcl validation → test import → login-page check → SQL package reimport → human acceptance. The legacy profile produces a read-only HTML prototype inside APEX, not native database CRUD.'}</p><p className="subtle">{session.configuration_scope}</p>{!session.conversion_configured&&<div className="notice"><div><strong>Conversion configuration needs operator attention.</strong><p>Assessment remains available. No conversion can start yet.</p><ul>{session.configuration_checks.filter(check=>!check.ready).map(check=><li key={check.code}>{check.message}</li>)}</ul></div></div>}<div className="consents">{['I reviewed and redacted credentials, production records and personal identifiers.','I am authorized to send this source through OCI’s externally hosted xAI processing path.','This is a bounded prototype; synthetic data only, with remediation handled separately.'].map((label,i)=><label key={i}><input type="checkbox" checked={consentIsCurrent&&consent[i]} onChange={e=>{if(!sourceUiIsCurrent()||consentVersion!==consentRevision.current)return;consentRevision.current++;setConsentSource(sourceKey);const checked=e.target.checked;setConsent(current=>(consentIsCurrent?current:[false,false,false]).map((v,j)=>i===j?checked:v));}}/>{label}</label>)}</div><button disabled={!consentIsCurrent||busy||!session.conversion_configured||!consent.every(Boolean)||!detail.inventory.conversion_eligible||(session.conversion_profile==='native-table-form-v1'&&detail.inventory.native_assessment?.state!=='READY')} onClick={()=>{if(!consentIsCurrent||consentVersion!==consentRevision.current||sourceActionInFlight.current||!sourceUiIsCurrent())return;void act(async()=>{await api(`/projects/${detail.id}/runs`,json({source_hash:detail.inventory.source_hash,approved_redacted_source:consent[0],approved_external_ai:consent[1],approved_prototype_scope:consent[2]}));await open(detail.id,true);});}}>Process source <ArrowRight size={16}/></button>{detail.inventory.missing_count>0&&<p className="subtle">Resolve the missing source candidates first.</p>}</section><section className="panel"><h2>Run history</h2>{detail.runs.length===0?<p>No conversion runs. Source changes get a new manifest and a separate run.</p>:detail.runs.map(r=><div className="finding" key={r.id}><span className="badge">{runLabel(r.state)}</span><h3>{r.id}</h3><p>{r.message}</p>{['PROCESSING','ATTENTION'].includes(r.state)&&r.stage_message&&<p className="subtle" role="status">{r.state==='ATTENTION'?'Last recorded step: ':'Current step: '}{r.stage_message}</p>}{r.state==='QA_REQUIRED'&&<ManagedVerificationStatus run={r}/>}{r.source_hash!==detail.inventory.source_hash&&<small>Earlier source version — not the current manifest.</small>}{['QA_REQUIRED','REVIEW_REQUIRED','VERIFIED','ACCEPTED'].includes(r.state)&&<RunEvidence pid={detail.id} run={r}/>} {['REVIEW_REQUIRED','VERIFIED'].includes(r.state)&&r.source_hash===detail.inventory.source_hash&&<Acceptance key={sourceUiKey+'-'+r.id} pid={detail.id} run={r} sourceBusy={busy} isCurrent={()=>!sourceActionInFlight.current&&sourceUiIsCurrent()} onAccepted={()=>open(detail.id,true)}/>} {r.state==='ACCEPTED'&&r.downloadable&&<a className="button secondary" href={`/api/projects/${detail.id}/runs/${r.id}/download`}><Download size={16}/> Accepted APEX package</a>}</div>)}</section></>}
 <p className="manifest">Current manifest SHA-256 <code>{detail.inventory.source_hash}</code></p></>}
 </main><footer className="page-footer">FOX · Forms to APEX <span>Internal preview · No production data</span></footer></div></div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
