import React,{useEffect,useId,useMemo,useRef,useState,type ReactNode} from 'react';
import {ArrowLeft,ArrowRight,Check,CheckCircle2,ChevronDown,Download,FileCode2,FolderOpen,HelpCircle,Layers,LoaderCircle,Plus,RefreshCw,Search,ShieldCheck,TriangleAlert,Upload} from 'lucide-react';
import {checkSelectedSources,uploadManifestName,type UploadMode} from './preparedUpload';
import {actionContext,available,findingOwnerLabels,formReadinessLabels,presentProjectPlan,presentProjectRun,processAvailability,recoveryAvailability,runBelongsToProject,validSourceBinding,workbenchSteps,
 type ActionCapability,type ProcessConfirmations,type ProjectActionContext,type ProjectConversionPlan,type ProjectFinding,type ProjectForm,type ProjectRun,type SourceBinding,type WorkbenchStep} from './projectConversion';
import './projectWorkbench.css';

export type WorkbenchProject={id:string;name:string;customer:string;description?:string;file_count?:number;run_count?:number};
export type SavedSourceVersion={id:string;label:string;source_hash:string;file_count:number};
export type WorkbenchActionResult={status:'confirmed'|'rejected'|'unconfirmed';message?:string;safe_to_continue?:boolean};
export type HumanReviewControls={disabled:boolean;perform:(action:()=>Promise<WorkbenchActionResult>)=>Promise<boolean>};
export type WorkbenchCapabilities={upload?:ActionCapability;select_version?:ActionCapability;generate?:ActionCapability;local_preparation?:ActionCapability};
export type ProjectWorkbenchProps={
 project:WorkbenchProject;source:SourceBinding;plan:unknown;runs:ProjectRun[];versions?:SavedSourceVersion[];
 capabilities:WorkbenchCapabilities;processingNotice:string;busy?:boolean;error?:string;unknownOutcome?:boolean;
 onBack?:()=>void;
 onUpload?:(files:File[],mode:UploadMode,context:ProjectActionContext)=>Promise<WorkbenchActionResult>;
 onGenerate?:(context:ProjectActionContext,confirmations:ProcessConfirmations)=>Promise<WorkbenchActionResult>;
 onSelectVersion?:(versionId:string,context:ProjectActionContext)=>Promise<WorkbenchActionResult>;
 onRefresh?:(context:ProjectActionContext)=>Promise<WorkbenchActionResult>;
 onReloadProject?:(projectId:string)=>Promise<WorkbenchActionResult>;
 onRecovery?:(kind:'check_status'|'retry_step'|'resume',context:ProjectActionContext)=>Promise<WorkbenchActionResult>;
 onPreview?:(context:ProjectActionContext)=>void;
 onDownload?:(context:ProjectActionContext)=>void;
 onEvidence?:(context:ProjectActionContext)=>void;
 onOpenPreparation?:()=>void;
 // The host's existing acceptance mutation must use controls.perform. The
 // fieldset also disables its native controls during another/unknown action.
 renderHumanReview?:(run:ProjectRun,context:ProjectActionContext,controls:HumanReviewControls)=>ReactNode;
};

const blankConfirmations=():ProcessConfirmations=>({approved_redacted_source:false,approved_external_ai:false,approved_prototype_scope:false});
const count=(value:unknown):value is number=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=0;
const readable=/\.(xml|pld|sql|pks|pkb|txt)$/i;
const rawForms=/\.(fmb|mmb|olb|pll)$/i;
const message=(value:unknown,fallback:string)=>typeof value==='string'&&value.trim()&&value.length<=2000?value:fallback;
const readyTone=(state:ProjectForm['state'])=>state==='READY'?'ready':state==='NEEDS_HUMAN'?'human':'attention';

export function ProjectDashboard({projects,busy=false,onOpenProject,onNewProject,createProjectContent}: {
 projects:WorkbenchProject[];busy?:boolean;onOpenProject:(id:string)=>void;onNewProject?:()=>void;createProjectContent?:ReactNode;
}){
 const [query,setQuery]=useState('');
 const filtered=projects.filter(project=>[project.name,project.customer,project.description??''].some(value=>value.toLocaleLowerCase().includes(query.toLocaleLowerCase())));
 return <section className="fox-workbench fw-dashboard" aria-label="FOX projects">
  <div className="fw-heading"><div><p className="fw-eyebrow">FORMS TO APEX</p><h1>Your projects</h1><p>Keep each application’s forms together. Each project produces one APEX application.</p></div><button type="button" onClick={onNewProject} disabled={busy||!onNewProject}><Plus size={18}/> New project</button></div>
  {createProjectContent}
  {projects.length>0&&<div className="fw-list-heading"><h2>{projects.length} {projects.length===1?'project':'projects'}</h2><label className="fw-search"><Search size={17}/><span className="fw-sr-only">Search projects</span><input type="search" placeholder="Search projects or teams" value={query} onChange={event=>setQuery(event.target.value)}/></label></div>}
  {projects.length===0?<div className="fw-empty"><FolderOpen size={32}/><h2>Start with one application</h2><p>Create a project, add its Forms sources and supporting definitions, then review what FOX can generate.</p></div>:filtered.length===0?<p className="fw-empty" role="status">No projects match this search.</p>:<div className="fw-project-grid">{filtered.map(project=><button type="button" className="fw-project-card" key={project.id} disabled={busy} onClick={()=>onOpenProject(project.id)}><div className="fw-card-top"><FolderOpen size={23}/><ArrowRight size={18}/></div><span className="fw-eyebrow">{project.customer||'Application project'}</span><h3>{project.name}</h3><p>{project.description||'Add the forms and definitions that belong to this application.'}</p><div className="fw-card-meta"><span>{count(project.file_count)?`${project.file_count} source files`:'Sources not yet counted'}</span><span>{count(project.run_count)?`${project.run_count} conversion runs`:'Run history unavailable'}</span></div></button>)}</div>}
 </section>;
}

function StatusBadge({state}:{state:ProjectForm['state']}){
 return <span className={`fw-badge fw-${readyTone(state)}`}>{state==='READY'?<CheckCircle2 size={14}/>:state==='NEEDS_HUMAN'?<HelpCircle size={14}/>:<TriangleAlert size={14}/>} {formReadinessLabels[state]}</span>;
}

function Finding({finding,moduleName,onUpload}:{finding:ProjectFinding;moduleName?:string;onUpload:()=>void}){
 const title=finding.code==='BUSINESS_CODE_REVIEW_REQUIRED'?'Business behavior needs a human decision':finding.message;
 return <article className={`fw-finding fw-finding-${finding.category.toLowerCase()}`}>
  <div className="fw-finding-title">{finding.category==='NEEDS_HUMAN'?<HelpCircle size={19}/>:<TriangleAlert size={19}/>}<div><h3>{title}</h3>{moduleName&&<p className="fw-small">Form: {moduleName}</p>}</div></div>
  <p className="fw-next-action"><strong>Next action</strong>{finding.required_action}</p>
  <p className="fw-owner">Who can help: <strong>{findingOwnerLabels[finding.owner]}</strong></p>
  {finding.category==='NEEDS_HUMAN'&&<p className="fw-human-boundary">FOX will not guess the intended business behavior. This remains blocked until the required meaning is supplied.</p>}
  {finding.category==='MISSING_INPUT'&&finding.owner==='SOURCE_OWNER'&&<button type="button" className="fw-secondary" onClick={onUpload}><Upload size={15}/> Add requested files</button>}
  {(finding.source||finding.evidence||title!==finding.message)&&<details className="fw-evidence"><summary>Where this was found <ChevronDown size={14}/></summary>{title!==finding.message&&<p>{finding.message}</p>}{finding.source&&<p>Source: <code>{finding.source}</code></p>}{finding.evidence&&<p>{finding.evidence}</p>}<p className="fw-small">Reference: {finding.code}</p></details>}
 </article>;
}

function FormDetails({form,onResolve}:{form:ProjectForm;onResolve:()=>void}){
 return <section className="fw-surface fw-form-detail" aria-label={`Details for ${form.form_name}`}>
  <div className="fw-detail-heading"><div><p className="fw-eyebrow">FORM DETAILS</p><h2>{form.form_name}</h2><p className="fw-filename">{form.source_name}</p></div><StatusBadge state={form.state}/></div>
  <h3>What will be generated</h3>
  {form.planned_pages?<><div className="fw-mapping"><span>Table-backed records</span><ArrowRight size={15}/><strong>Native APEX report</strong><small>Planned page {form.planned_pages.report_page}</small></div><div className="fw-mapping"><span>Record entry and editing</span><ArrowRight size={15}/><strong>Native APEX form</strong><small>Planned page {form.planned_pages.form_page}</small></div><p className="fw-small">This is a plan, not a generated or validated application.</p></>:<p>Page planning is not available for this form yet. Review its findings before conversion.</p>}
  {form.storage_mapping?<section aria-label="Planned prototype table"><h3>Source and prototype tables</h3><div className="fw-mapping" aria-label="Source to prototype table mapping"><div>Original table<br/><code>{form.table_name}</code></div><ArrowRight size={15}/><div>Planned empty table<br/><code>{form.storage_mapping.target_table_name}</code></div></div><p className="fw-small">Your original files stay unchanged. No production data is copied.</p><p className="fw-small">Changing the table structure creates a separate empty prototype table. This is not a data migration.</p><details className="fw-evidence"><summary>Show table mapping evidence <ChevronDown size={14}/></summary><p>Project reference: <code>{form.storage_mapping.project_id}</code></p><p>Source structure SHA-256: <code>{form.storage_mapping.source_schema_sha256}</code></p><p>Mapping identity SHA-256: <code>{form.storage_mapping.identity_sha256}</code></p><ul>{form.ddl_sources.map(item=><li key={item.name}>{item.name}: <code>{item.sha256}</code></li>)}</ul><p>This mapping describes the plan only. It does not establish generation, verification or business acceptance.</p></details></section>:form.table_name&&<p className="fw-small">Supplied table: <code>{form.table_name}</code></p>}
  {form.mapping.length>0&&<details className="fw-evidence"><summary>Component mapping <ChevronDown size={14}/></summary><ul>{form.mapping.map((item,index)=><li key={`${item.source_component}-${index}`}><span>{item.source_component}</span> → <span>{item.target_component==='native_report'?'Native APEX report':'Native APEX form'}</span> <small>(Planned)</small></li>)}</ul></details>}
  <h3>Linked source and definitions</h3>
  {form.ddl_sources.length>0?<ul className="fw-dependencies">{form.ddl_sources.map(item=><li key={item.name}><FileCode2 size={16}/><span>{item.name}</span><span className="fw-badge fw-neutral">Definition supplied</span></li>)}</ul>:<p className="fw-small">No database definition has been linked to this form.</p>}
  {form.dependencies.length>0?<ul className="fw-dependencies">{form.dependencies.map((item,index)=><li key={`${item.kind}-${item.target}-${index}`}><FileCode2 size={16}/><div><strong>{item.target}</strong><p>{item.action}</p></div><span className={`fw-badge ${item.status==='MISSING'?'fw-attention':'fw-neutral'}`}>{item.status==='MISSING'?'Missing':'Source present'}</span></li>)}</ul>:<p className="fw-small">No additional dependency candidates were reported. This is not a completeness guarantee.</p>}
  {form.findings.length>0&&<div className="fw-inline-action"><p>{form.findings.length} {form.findings.length===1?'finding needs':'findings need'} attention.</p><button type="button" className="fw-secondary" onClick={onResolve}>Resolve findings <ArrowRight size={16}/></button></div>}
 </section>;
}

function ReviewForms({plan,onResolve,onContinue}:{plan:ProjectConversionPlan;onResolve:()=>void;onContinue?:()=>void}){
 const [selectedId,setSelectedId]=useState(plan.forms[0]?.module_id??'');
 const [query,setQuery]=useState('');
 const [attentionOnly,setAttentionOnly]=useState(false);
 const [page,setPage]=useState(0);
 useEffect(()=>{setSelectedId(plan.forms[0]?.module_id??'');setQuery('');setAttentionOnly(false);setPage(0);},[plan.plan_sha256]);
 const filtered=plan.forms.filter(item=>(!attentionOnly||item.state!=='READY')&&`${item.form_name} ${item.source_name}`.toLocaleLowerCase().includes(query.toLocaleLowerCase()));
 const pages=Math.max(1,Math.ceil(filtered.length/12)),currentPage=Math.min(page,pages-1),shown=filtered.slice(currentPage*12,(currentPage+1)*12);
 const selected=plan.forms.find(item=>item.module_id===selectedId)??plan.forms[0];
 if(!plan.assessment_complete)return <section className="fw-surface"><h2>Assessment not completed</h2><p>{plan.summary.unassessed_sources} selected sources have not been assessed. Resolve the project-level finding before looking for form mappings.</p><button type="button" onClick={onResolve}>Review what is needed <ArrowRight size={16}/></button></section>;
 if(!plan.forms.length)return <section className="fw-empty"><FileCode2 size={30}/><h2>No Forms modules are ready to review</h2><p>Add readable Forms XML and the related database definitions, or review the reported project findings.</p><button type="button" className="fw-secondary" onClick={onResolve}>Review findings</button></section>;
 return <><div className="fw-list-heading"><div><h2>Review every form</h2><p>All selected forms belong to one planned APEX application.</p></div>{plan.can_generate&&onContinue?<button type="button" onClick={onContinue}>Continue to conversion <ArrowRight size={16}/></button>:plan.summary.blocking_findings>0?<button type="button" className="fw-secondary" onClick={onResolve}>Resolve {plan.summary.blocking_findings} findings <ArrowRight size={16}/></button>:null}</div>
  <div className="fw-form-tools"><label className="fw-search"><Search size={16}/><span className="fw-sr-only">Search forms</span><input type="search" value={query} placeholder="Find a form or source file" onChange={event=>{setQuery(event.target.value);setPage(0);}}/></label><label className="fw-check"><input type="checkbox" checked={attentionOnly} onChange={event=>{setAttentionOnly(event.target.checked);setPage(0);}}/>Show forms needing attention</label></div>
  <div className="fw-form-layout"><div><div className="fw-form-list" aria-label="Forms in this project">{shown.length?shown.map(form=><button type="button" className={`fw-form-card ${selected?.module_id===form.module_id?'is-selected':''}`} aria-pressed={selected?.module_id===form.module_id} key={form.module_id} onClick={()=>setSelectedId(form.module_id)}><div className="fw-form-card-title"><FileCode2 size={20}/><strong>{form.form_name}</strong></div><span className="fw-filename">{form.source_name}</span><StatusBadge state={form.state}/><span className="fw-small">{form.findings.length?`${form.findings.length} findings to resolve`:'Included in the planned project app'}</span></button>):<p className="fw-empty" role="status">No forms match this filter.</p>}</div>{pages>1&&<div className="fw-pagination"><button type="button" className="fw-secondary" disabled={currentPage===0} onClick={()=>setPage(currentPage-1)}>Previous</button><span>Page {currentPage+1} of {pages} · {filtered.length} forms</span><button type="button" className="fw-secondary" disabled={currentPage+1>=pages} onClick={()=>setPage(currentPage+1)}>Next</button></div>}</div>{selected&&<FormDetails form={selected} onResolve={onResolve}/>}</div>
 </>;
}

type RunExecute=(action:()=>Promise<WorkbenchActionResult>,readOnly?:boolean)=>Promise<boolean>;

function RunRecovery({run,binding,plan,busy,onRecovery,execute}:{run:ProjectRun;binding:SourceBinding;plan:ProjectConversionPlan|null;busy:boolean;onRecovery?:ProjectWorkbenchProps['onRecovery'];execute?:RunExecute}){
 const view=presentProjectRun(run,binding.source_hash,binding.project_id);
 let context:ProjectActionContext|null=null;
 try{if(run.project_id===binding.project_id)context=actionContext(binding,plan,run.id,run.source_hash);}catch{/* No action for an incomplete binding. */}
 const recovery=recoveryAvailability(run,Boolean(onRecovery)&&Boolean(context)&&Boolean(execute),busy);
 if(!view.error&&!['ATTENTION','FAILED'].includes(run.state))return null;
 return <>{view.error&&<div className="fw-notice" role="alert" aria-label="Run needs attention"><h3>{view.error.message}</h3><p><strong>Next action:</strong> {view.error.action}</p><p>Who can help: {findingOwnerLabels[view.error.owner]}</p></div>}
  <div className="fw-inline-action"><button type="button" className="fw-secondary" disabled={!recovery.enabled} onClick={()=>{const bound=context,kind=recovery.kind;if(bound&&kind&&execute&&onRecovery)void execute(()=>onRecovery(kind,bound),kind==='check_status');}}><RefreshCw size={15}/>{recovery.label}</button>{recovery.reason&&<p className="fw-small">{recovery.reason}</p>}<p className="fw-small">Completed work is retained. An uncertain database operation is checked before any repeat is allowed.</p></div>
 </>;
}

function OutputRun({run,binding,plan,busy,reviewControls,onPreview,onDownload,onEvidence,renderHumanReview,onRecovery,execute}:{run:ProjectRun;binding:SourceBinding;plan:ProjectConversionPlan|null;busy:boolean;reviewControls?:HumanReviewControls;onPreview?:ProjectWorkbenchProps['onPreview'];onDownload?:ProjectWorkbenchProps['onDownload'];onEvidence?:ProjectWorkbenchProps['onEvidence'];renderHumanReview?:ProjectWorkbenchProps['renderHumanReview'];onRecovery?:ProjectWorkbenchProps['onRecovery'];execute?:RunExecute}){
 const view=presentProjectRun(run,binding.source_hash,binding.project_id);
 let context:ProjectActionContext|null=null;
 try{if(run.project_id===binding.project_id)context=actionContext(binding,plan,run.id,run.source_hash);}catch{/* An incomplete binding is display-only. */}
 return <article className="fw-surface fw-output" aria-label={`Output for run ${run.id}`}>
  <div className="fw-detail-heading"><div><p className="fw-eyebrow">ONE PROJECT · ONE APEX APPLICATION</p><h2>{view.generated?'APEX application generated':'APEX output is not ready yet'}</h2><p className="fw-small">Run <code>{run.id}</code>{view.earlierSource?' · Earlier source version':''}</p></div><span className={`fw-badge fw-${view.tone}`}>{view.label}</span></div>
  <div className="fw-output-facts"><div><CheckCircle2 size={19}/><strong>APEX generated</strong><span>{view.generated?'Reported as generated':'Not confirmed'}</span></div><div><ShieldCheck size={19}/><strong>Technical verification</strong><span>{view.technicalVerified?'Checks passed':'Not yet confirmed'}</span></div><div><HelpCircle size={19}/><strong>Business behavior</strong><span>{view.humanAccepted?'Human review recorded':'Human validation required'}</span></div></div>
  {!view.error&&<p>{view.message}</p>}
  <RunRecovery run={run} binding={binding} plan={plan} busy={busy} onRecovery={onRecovery} execute={execute}/>
  {view.earlierSource&&!view.humanAccepted&&<p className="fw-notice">This unaccepted output belongs to an earlier source version. Select that version before reviewing it. It cannot certify the current sources.</p>}
  {view.detailsIncomplete&&<p className="fw-notice" role="status">Some run details are unavailable. No missing check is being shown as passed.</p>}
  <div className="fw-actions"><button type="button" className="fw-secondary" disabled={busy||!context||!view.canPreview||!onPreview} onClick={()=>{if(context)onPreview?.(context);}}>Preview APEX <ArrowRight size={16}/></button><button type="button" disabled={busy||!context||!view.canDownload||!onDownload} onClick={()=>{if(context)onDownload?.(context);}}><Download size={17}/> Download APEX package</button>{onEvidence&&<button type="button" className="fw-text-button" disabled={busy||!context} onClick={()=>{if(context)onEvidence(context);}}>View mapping and remediation</button>}</div>
  {!view.canDownload&&<p className="fw-small">{view.downloadReason}</p>}
  {view.canDownload&&!onDownload&&<p className="fw-small">The download handler is not connected in this deployment.</p>}
  <p className="fw-small">The project package contains native APEX SQL, schema DDL, APEXlang where supported, import requirements and per-form remediation. Generated does not mean the business behavior has been accepted.</p>
  {view.canReview&&context&&renderHumanReview&&reviewControls&&<fieldset key={`${run.id}:${binding.source_hash}:${binding.selected_source_set_id}`} className="fw-human-review" aria-label="Genuine human review" disabled={busy||reviewControls.disabled}><legend>Human review</legend>{(busy||reviewControls.disabled)&&<p className="fw-notice">Review controls are paused until the current operation is confirmed. Your unsubmitted notes are kept.</p>}{renderHumanReview(run,context,{...reviewControls,disabled:busy||reviewControls.disabled})}</fieldset>}
  {view.canReview&&(!renderHumanReview||!reviewControls)&&<p className="fw-notice">Technical checks passed. Human review has not been connected in this view; no acceptance has been recorded here.</p>}
 </article>;
}

export default function ProjectWorkbench(props:ProjectWorkbenchProps){
 const {project,source,capabilities,processingNotice,runs,versions=[]}=props;
 const selectedVersion=versions.find(version=>version.id===source.selected_source_set_id);
 const versionMismatch=Boolean(selectedVersion&&selectedVersion.source_hash!==source.source_hash);
 const bindingValid=validSourceBinding(source)&&source.project_id===project.id&&!versionMismatch;
 const id=useId(),planResult=useMemo(()=>bindingValid?presentProjectPlan(props.plan,source):{plan:null,message:'The project and source binding do not match. Refresh before continuing.'},[props.plan,bindingValid,source.project_id,source.source_hash,source.selected_source_set_id]);
 const plan=planResult.plan;
 const bindingKey=JSON.stringify([project.id,source.source_hash,source.selected_source_set_id,plan?.plan_sha256??null]);
 const currentBinding=useRef(bindingKey);currentBinding.current=bindingKey;
 const previousBinding=useRef(bindingKey);
 const inFlight=useRef<symbol|null>(null);
 const [step,setStep]=useState<WorkbenchStep>(()=>plan?.source_files.length?'review':'upload'),[mode,setMode]=useState<UploadMode>('prepared'),[fileSelection,setFileSelection]=useState<{binding:string;files:File[]}>({binding:bindingKey,files:[]});
 const [approval,setApproval]=useState<{binding:string;values:ProcessConfirmations}>({binding:bindingKey,values:blankConfirmations()}),[pending,setPending]=useState(false),[uncertain,setUncertain]=useState(false),[localMessage,setLocalMessage]=useState('');
 const selected=fileSelection.binding===bindingKey?fileSelection.files:[];
 const confirmations=approval.binding===bindingKey?approval.values:blankConfirmations();
 const setSelected=(files:File[])=>setFileSelection({binding:currentBinding.current,files});
 const setConfirmations=(values:ProcessConfirmations)=>setApproval({binding:currentBinding.current,values});
 useEffect(()=>{if(previousBinding.current===bindingKey)return;previousBinding.current=bindingKey;inFlight.current=null;setSelected([]);setConfirmations(blankConfirmations());setUncertain(false);setLocalMessage('');setPending(false);setStep(plan?.source_files.length?'review':'upload');},[bindingKey]);
 const busy=Boolean(props.busy||pending),unknownOutcome=Boolean(props.unknownOutcome||uncertain);
 const sourceContext=()=>actionContext(source,plan);
 const projectRuns=Array.isArray(runs)?runs.filter(run=>runBelongsToProject(run,project.id)):[];
 const runIntegrityIssue=!Array.isArray(runs)||projectRuns.length!==runs.length;
 const activeRun=projectRuns.find(run=>run.source_hash===source.source_hash)??null;
 const uploadCapability=available(capabilities.upload,Boolean(props.onUpload),'Upload is not connected in this deployment.');
 const generate=processAvailability(plan,capabilities.generate,Boolean(props.onGenerate),confirmations,processingNotice,busy,unknownOutcome);
 const canGenerate=generate.enabled&&bindingValid&&!activeRun&&!runIntegrityIssue;
 const generateReason=runIntegrityIssue?'Run history is incomplete or belongs to another project. Refresh before starting a conversion.':activeRun?'This source version already has a run. Review its status or output; do not submit it again.':generate.reason;

 async function execute(action:()=>Promise<WorkbenchActionResult>,readOnly=false,projectOnly=false):Promise<boolean>{
  if(currentBinding.current!==bindingKey||inFlight.current!==null||busy||(!readOnly&&unknownOutcome)||(!bindingValid&&!(readOnly&&projectOnly)))return false;
  const captured=currentBinding.current;
  const token=Symbol('workbench action');inFlight.current=token;
  setPending(true);setLocalMessage('');
  try{
   const result=await action();
   if(currentBinding.current!==captured)return false;
   if(result?.status==='confirmed'){
    if(readOnly&&result.safe_to_continue===true)setUncertain(false);
    if(result.message)setLocalMessage(message(result.message,'The action was confirmed.'));
    return true;
   }
   if(result?.status==='rejected')setLocalMessage(message(result.message,'The action was rejected. Review the current findings before continuing.'));
   else {setUncertain(true);setLocalMessage('The result could not be confirmed. Check the existing status before trying another operation.');}
  }catch{
   if(currentBinding.current===captured){if(!readOnly)setUncertain(true);setLocalMessage(readOnly?'The status check could not be completed. No retry or import was started.':'The result could not be confirmed. Check the existing status before trying another operation.');}
  }finally{if(inFlight.current===token){inFlight.current=null;if(currentBinding.current===captured)setPending(false);}}
  return false;
 }
 function selectFiles(files:File[]){
  setLocalMessage('');
  if(files.some(file=>rawForms.test(file.name))){setSelected([]);setLocalMessage('These are raw Forms binaries. Prepare them locally with the approved Oracle tooling first; nothing has been uploaded.');return;}
  if(files.some(file=>!readable.test(file.name)&&file.name!==uploadManifestName)){setSelected([]);setLocalMessage('Choose readable XML, PLD, SQL, PKS, PKB or TXT files. Keep archives, private extraction files and raw binaries local.');return;}
  setSelected(files);
 }
 async function upload(){
  if(!props.onUpload||!uploadCapability.enabled||busy||unknownOutcome||!bindingValid)return;
  const captured=currentBinding.current,files=[...selected],context=sourceContext();
  if(await execute(async()=>{
   try{await checkSelectedSources(files,mode);}catch(error){return {status:'rejected',message:message(error instanceof Error?error.message:null,'The selected files could not be checked. Nothing was uploaded.')};}
   if(currentBinding.current!==captured)return {status:'rejected',message:'The selected source version changed. Nothing was uploaded.'};
   return props.onUpload!(files,mode,context);
  }))setSelected([]);
 }
 const reloadProject=()=>{if(props.onReloadProject)void execute(()=>props.onReloadProject!(project.id),true,true);};
 const errorText=props.error?message(props.error,'The last error details are unavailable. Check the project status.'):localMessage;
 const summary=plan?.summary;
 return <section className="fox-workbench" aria-label="Project conversion workspace">
  {props.onBack&&<button type="button" className="fw-back" onClick={props.onBack} disabled={busy}><ArrowLeft size={15}/> All projects</button>}
  <div className="fw-heading"><div><p className="fw-eyebrow">{project.customer||'APPLICATION PROJECT'}</p><h1>{project.name}</h1><p>{project.description||'Prepare the forms for one native APEX application.'}</p></div><div className="fw-project-outcome"><Layers size={21}/><span>One project<br/><strong>One APEX application</strong></span></div></div>
  <div className="fw-summary" aria-label="Project readiness"><div><strong>{plan?.assessment_complete?summary?.form_count:'—'}</strong><span>{plan?.assessment_complete?'Forms assessed':'Assessment not completed'}</span></div><div><strong>{plan?.assessment_complete?summary?.ready_forms:'—'}</strong><span>Ready to generate</span></div><div><strong>{summary?.blocking_findings??'—'}</strong><span>Findings to resolve</span></div><div><strong>{summary?.needs_human_forms??'—'}</strong><span>Forms needing a decision</span></div></div>
  <nav className="fw-steps" aria-label="Conversion steps">{workbenchSteps.map((item,index)=><button type="button" key={item.id} aria-current={step===item.id?'step':undefined} className={step===item.id?'is-current':''} onClick={()=>setStep(item.id)}><span className="fw-step-number">{index+1}</span><span>{item.label}</span></button>)}</nav>
  {errorText&&<div className="fw-alert" role="alert"><TriangleAlert size={19}/><p>{errorText}</p></div>}
  {!bindingValid&&<div className="fw-alert" role="alert"><div><p>The selected project and source version do not match. Reload this project before taking action.</p>{props.onReloadProject?<button type="button" className="fw-secondary" disabled={busy} onClick={reloadProject}><RefreshCw size={15}/> Reload project</button>:props.onBack?<button type="button" className="fw-secondary" disabled={busy} onClick={props.onBack}><ArrowLeft size={15}/> Return to projects</button>:<p className="fw-small">Reload this browser page to obtain the current project state. No conversion action is available from this stale view.</p>}</div></div>}
  {runIntegrityIssue&&<p className="fw-alert" role="alert">Some run records could not be matched to this project. Refresh status; no missing result is being treated as complete.</p>}
  {unknownOutcome&&<div className="fw-notice"><strong>Check the existing result first.</strong><p>FOX has not confirmed the previous operation. Starting it again could duplicate work. No automatic retry was made.</p><button type="button" className="fw-secondary" disabled={busy||!props.onRefresh||!bindingValid} onClick={()=>void execute(()=>props.onRefresh!(sourceContext()),true)}><RefreshCw size={15}/> Check status</button></div>}
  {planResult.message&&step!=='upload'&&<p className="fw-notice" role="status">{planResult.message}</p>}
  <div className="fw-version-row"><span>Current source version</span>{versions.length>0?<label><span className="fw-sr-only">Select a saved source version</span><select value={source.selected_source_set_id??''} disabled={busy||unknownOutcome||!bindingValid||!available(capabilities.select_version,Boolean(props.onSelectVersion),'Source-version selection is not connected.').enabled} onChange={event=>{const version=event.target.value;void execute(()=>props.onSelectVersion!(version,sourceContext()));}}><option value="" disabled>No version selected</option>{versions.map(version=><option value={version.id} key={version.id}>{version.label} · {version.file_count} files</option>)}</select></label>:<strong>{plan?.source_files.length?'Selected sources':'No saved version to select'}</strong>}<span className="fw-small">Earlier versions and results are kept.</span>{props.onRefresh&&<button type="button" className="fw-text-button" disabled={busy||!bindingValid} onClick={()=>void execute(()=>props.onRefresh!(sourceContext()),true)}><RefreshCw size={14}/> Refresh</button>}</div>

  {step==='upload'&&<section className="fw-surface" aria-label="Upload project sources"><div className="fw-section-intro"><Upload size={25}/><div><h2>Add all the forms for this application</h2><p>Include readable Forms sources, table definitions and related libraries or package source. FOX will assess them together.</p></div></div><details className="fw-preparation-help"><summary>I have FMB, MMB, OLB or PLL files <ChevronDown size={15}/></summary><p>These binary files need approved Oracle tooling on your computer before FOX can read them. The hosted browser does not perform that conversion or upload raw binaries.</p><ol><li>Use the local FOX preparation tool supplied by your deployment operator.</li><li>Choose the source folder and review the readable output for restricted information.</li><li>Bring the readable files and <code>{uploadManifestName}</code> from its <code>ready</code> folder here.</li></ol>{available(capabilities.local_preparation,Boolean(props.onOpenPreparation),'Local preparation is not available in this hosted view.').enabled?<button type="button" className="fw-secondary" disabled={busy} onClick={props.onOpenPreparation}>Open local preparation</button>:<p className="fw-small">{available(capabilities.local_preparation,Boolean(props.onOpenPreparation),'Local preparation is not available in this hosted view.').reason}</p>}<p className="fw-small">Reading a library is not the same as converting its business logic. Unclear behavior will remain a decision for your team.</p></details>
   <fieldset className="fw-upload-mode"><legend>Which files do you have?</legend><label className="fw-check"><input type="radio" name={`${id}-upload-mode`} checked={mode==='prepared'} disabled={busy} onChange={()=>{setMode('prepared');setSelected([]);setLocalMessage('');}}/>A prepared source set, with its manifest</label><label className="fw-check"><input type="radio" name={`${id}-upload-mode`} checked={mode==='direct'} disabled={busy} onChange={()=>{setMode('direct');setSelected([]);setLocalMessage('');}}/>Readable files, without a preparation manifest</label></fieldset>
   <div className="fw-drop-area" onDragOver={event=>event.preventDefault()} onDrop={event=>{event.preventDefault();if(!busy&&!unknownOutcome&&uploadCapability.enabled)selectFiles(Array.from(event.dataTransfer.files));}}><Upload size={27}/><h3>Drop readable files here</h3><p>{mode==='prepared'?`Select ${uploadManifestName} and every readable file listed in it.`:'XML, PLD, SQL, PKS, PKB or TXT. Archives and raw binaries remain local.'}</p><label className="fw-file-button"><input key={`${bindingKey}:${mode}`} type="file" multiple accept={mode==='prepared'?'.json,.xml,.pld,.sql,.pks,.pkb,.txt':'.xml,.pld,.sql,.pks,.pkb,.txt'} aria-label="Choose project source files" disabled={busy||unknownOutcome||!uploadCapability.enabled||!bindingValid} onChange={event=>{selectFiles(Array.from(event.target.files??[]));event.target.value='';}}/><span>Choose files</span></label></div>
   {selected.length>0&&<div className="fw-selected-files" aria-live="polite"><h3>{selected.length} selected files</h3><ul>{selected.map((file,index)=><li key={`${file.name}-${index}`}><FileCode2 size={15}/><span>{file.name}</span><small>{file.size.toLocaleString()} bytes</small></li>)}</ul></div>}
   <div className="fw-actions"><button type="button" disabled={busy||unknownOutcome||!bindingValid||!uploadCapability.enabled||selected.length===0} onClick={()=>void upload()}>{busy?<LoaderCircle size={17} className="fw-spinner"/>:<Upload size={17}/>} Upload and assess</button>{plan&&plan.forms.length>0&&<button type="button" className="fw-secondary" onClick={()=>setStep('review')}>Review existing forms <ArrowRight size={16}/></button>}</div>{!uploadCapability.enabled&&<p className="fw-small">{uploadCapability.reason}</p>}
   {plan&&plan.source_files.length>0&&<details className="fw-evidence"><summary>{plan.source_files.length} files in the selected version <ChevronDown size={15}/></summary><ul className="fw-source-list">{plan.source_files.slice(0,50).map(file=><li key={file.name}><span>{file.name}</span><small>{file.disposition==='MAPPED'?'Included':file.disposition==='BLOCKED'?'Needs attention':'Not mapped'}</small></li>)}</ul>{plan.source_files.length>50&&<p className="fw-small">Showing the first 50 files. Use the complete source-version inventory to inspect all {plan.source_files.length}.</p>}</details>}
  </section>}

  {step==='review'&&plan&&<ReviewForms plan={plan} onResolve={()=>setStep('resolve')} onContinue={()=>setStep('convert')}/>}
  {step==='resolve'&&plan&&<section aria-label="Resolve project findings"><div className="fw-list-heading"><div><h2>What is needed before conversion</h2><p>Missing information and human decisions are separate from unsupported technical features.</p></div></div>{plan.state==='EMPTY'?<div className="fw-surface"><h3>Add your source files first</h3><p>An empty project is not ready to generate an application.</p><button type="button" onClick={()=>setStep('upload')}>Add source files <Upload size={16}/></button></div>:plan.summary.blocking_findings===0?<div className="fw-surface fw-clear"><CheckCircle2 size={26}/><h3>No blocking findings reported</h3><p>This source plan is ready. It is not yet a generated app or proof of business behavior.</p><button type="button" onClick={()=>setStep('convert')}>Review processing <ArrowRight size={16}/></button></div>:<>{plan.project_findings.map((item,index)=><Finding key={`project-${index}`} finding={item} onUpload={()=>setStep('upload')}/>)}{plan.forms.flatMap(form=>form.findings.map((item,index)=><Finding key={`${form.module_id}-${index}`} finding={item} moduleName={form.form_name} onUpload={()=>setStep('upload')}/>))}<p className="fw-small">Updating files creates a new source version and a new assessment. Previous results are retained; they do not certify changed sources.</p></>}</section>}

  {step==='convert'&&<section aria-label="Convert the project"><div className="fw-surface"><h2>Generate one APEX application</h2><p>{plan?.assessment_complete?`${plan.summary.form_count} selected forms will be considered together. FOX will not silently leave out a blocked form.`:'Complete the source assessment before conversion.'}</p><p>FOX maps and reviews the supplied structure, generates native components, then validates and tests the output. Business meaning stays with your team.</p>{processingNotice?<div className="fw-processing-notice"><strong>Processing route</strong><p>{processingNotice}</p></div>:<p className="fw-notice">The processing route has not been reported. Conversion stays unavailable.</p>}
    <fieldset className="fw-confirmations"><legend>Confirm before processing this source version</legend>{([
     ['approved_redacted_source','I checked that these files contain no passwords, production records or restricted personal information.'],
     ['approved_external_ai','I have permission to use the processing route shown above for these files.'],
     ['approved_prototype_scope','I understand this is a bounded prototype using synthetic data, with business behavior validated by a person.'],
    ] as const).map(([key,label])=><label className="fw-check" key={key}><input type="checkbox" checked={confirmations[key]} disabled={busy||unknownOutcome} onChange={event=>setConfirmations({...confirmations,[key]:event.target.checked})}/>{label}</label>)}</fieldset>
    <div className="fw-actions"><button type="button" disabled={!canGenerate} onClick={()=>void execute(()=>props.onGenerate!(sourceContext(),{...confirmations}))}>{busy?<LoaderCircle size={17} className="fw-spinner"/>:<Layers size={17}/>} Generate APEX application</button>{activeRun&&<button type="button" className="fw-secondary" onClick={()=>setStep('output')}>View existing run</button>}</div>{!canGenerate&&<p className="fw-small">{generateReason}</p>}
   </div>{activeRun&&<RunProgress run={activeRun} binding={source} plan={plan} busy={busy} onRecovery={props.onRecovery} execute={execute}/>}
  </section>}

  {step==='output'&&<section aria-label="APEX project output">{projectRuns.length===0?<div className="fw-surface fw-empty"><Layers size={30}/><h2>{runIntegrityIssue?'Output status is unavailable':'Your APEX package will appear here'}</h2><p>{runIntegrityIssue?'Refresh the project before relying on its run history.':'First upload and assess the sources, resolve the required findings, then generate the project application.'}</p><button type="button" className="fw-secondary" onClick={()=>setStep(plan?.can_generate?'convert':'review')}>Back to the project steps <ArrowRight size={16}/></button></div>:projectRuns.map(run=><OutputRun key={run.id} run={run} binding={source} plan={plan} busy={busy} reviewControls={{disabled:busy||unknownOutcome||!bindingValid,perform:action=>execute(action)}} onPreview={props.onPreview} onDownload={props.onDownload} onEvidence={props.onEvidence} onRecovery={props.onRecovery} execute={execute} renderHumanReview={bindingValid?props.renderHumanReview:undefined}/>)}</section>}
 </section>;
}

function RunProgress({run,binding,plan,busy,onRecovery,execute}:{run:ProjectRun;binding:SourceBinding;plan:ProjectConversionPlan|null;busy:boolean;onRecovery?:ProjectWorkbenchProps['onRecovery'];execute:(action:()=>Promise<WorkbenchActionResult>,readOnly?:boolean)=>Promise<boolean>}){
 const view=presentProjectRun(run,binding.source_hash,binding.project_id);
 const stageLabels={queued:'Waiting',running:'Processing',generated:'Generated',blocked:'Needs input',failed:'Stopped'};
 return <section className="fw-surface" aria-label="Current conversion progress"><div className="fw-detail-heading"><div><p className="fw-eyebrow">SAVED RUN</p><h2>{view.label}</h2>{!view.error&&<p>{view.stageMessage||view.message}</p>}</div><code>{run.id}</code></div>
  {view.detailsIncomplete&&<p className="fw-notice" role="status">Some progress or error details could not be read. No missing result is being shown as successful.</p>}
  {view.steps.length>0?<ol className="fw-run-steps">{view.steps.map(item=><li key={item.id} className={`fw-run-step-${item.state}`}><span aria-hidden="true">{item.state==='complete'?<Check size={15}/>:item.state==='running'?<LoaderCircle size={15} className="fw-spinner"/>:item.state==='blocked'?<TriangleAlert size={15}/>:<span className="fw-step-dot"/>}</span><div><strong>{item.label}</strong><small>{item.state==='complete'?'Completed':item.state==='running'?'Reported as in progress':item.state==='blocked'?'Blocked':'Not yet reported complete'}</small>{item.message&&<p>{item.message}</p>}</div></li>)}</ol>:<p className="fw-small">Detailed stage checkpoints have not been reported for this run. No progress percentage is assumed.</p>}
  {view.forms.length>0?<div className="fw-form-progress"><h3>Per-form response</h3>{view.forms.map(item=><div key={item.module_id}><strong>{plan?.forms.find(form=>form.module_id===item.module_id)?.form_name??item.module_id}</strong><span>{stageLabels[item.state]}</span>{item.message&&<p>{item.message}</p>}</div>)}</div>:<p className="fw-small">Per-form processing results have not been reported yet.</p>}
  <RunRecovery run={run} binding={binding} plan={plan} busy={busy} onRecovery={onRecovery} execute={execute}/>
 </section>;
}
