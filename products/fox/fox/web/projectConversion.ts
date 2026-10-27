// Presentation contracts only. Server-side source, proof and mutation gates remain authoritative.
export type FormReadiness='READY'|'MISSING_INPUT'|'NEEDS_HUMAN'|'UNSUPPORTED';
export type FindingCategory='MISSING_INPUT'|'NEEDS_HUMAN'|'UNSUPPORTED';
export type FindingOwner='SOURCE_OWNER'|'BUSINESS_OWNER'|'OPERATOR';
export type ProjectFinding={code:string;category:FindingCategory;message:string;source:string;evidence:string;owner:FindingOwner;required_action:string};
export type ProjectDependency={kind:string;target:string;status:'SOURCE_PRESENT'|'MISSING';source:string;evidence:string;action:string};
export type ProjectStorageMapping={schema_version:1;scope:'fox-project-storage-v1';project_id:string;source_table_name:string;source_schema_sha256:string;identity_sha256:string;target_table_name:string};
export type ProjectForm={module_id:string;form_name:string;source_name:string;source_sha256:string;state:FormReadiness;table_name:string|null;storage_mapping?:ProjectStorageMapping;findings:ProjectFinding[];dependencies:ProjectDependency[];ddl_sources:{name:string;sha256:string}[];mapping:{source_component:string;target_component:string;status:string}[];planned_pages:{report_page:number;form_page:number}|null};
export type ProjectSource={name:string;sha256:string;bytes:number;kind:'FORM_XML'|'TABLE_DDL'|'SUPPORTING_SOURCE'|'UNSUPPORTED_XML';module_ids:string[];disposition:'MAPPED'|'BLOCKED'|'UNASSIGNED'};
export type ProjectConversionPlan={schema_version:1;scope:'fox-project-conversion-plan-v1';profile_id:'native-project-v1';project_id:string;project_name:string;source_hash:string;state:'READY'|'BLOCKED'|'EMPTY';assessment_complete:boolean;can_generate:boolean;plan_sha256:string;forms:ProjectForm[];project_findings:ProjectFinding[];source_files:ProjectSource[];summary:{form_count:number;ready_forms:number;missing_input_forms:number;needs_human_forms:number;unsupported_forms:number;blocking_findings:number;unassessed_sources:number}};
export type SourceBinding={project_id:string;source_hash:string;selected_source_set_id:string|null};
export type ProjectActionContext=SourceBinding&{expected_current_source_set_id:string|null;plan_sha256:string|null;run_id?:string;run_source_hash?:string};
export type ActionCapability={enabled:boolean;reason?:string};
export type ProcessConfirmations={approved_redacted_source:boolean;approved_external_ai:boolean;approved_prototype_scope:boolean};
export type WorkbenchStep='upload'|'review'|'resolve'|'convert'|'output';
export const workbenchSteps:{id:WorkbenchStep;label:string}[]=[{id:'upload',label:'Upload'},{id:'review',label:'Review forms'},{id:'resolve',label:'Resolve'},{id:'convert',label:'Convert'},{id:'output',label:'Output'}];

const record=(value:unknown):value is Record<string,unknown>=>typeof value==='object'&&value!==null&&!Array.isArray(value);
const text=(value:unknown,max=4096):value is string=>typeof value==='string'&&value.trim().length>0&&value.length<=max&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value);
const optionalText=(value:unknown,max=4096):value is string=>typeof value==='string'&&value.length<=max&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value);
const hash=(value:unknown):value is string=>typeof value==='string'&&value.length===64&&/^[a-f0-9]{64}$/.test(value);
const opaque=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$/.test(value);
const integer=(value:unknown,min=0,max=Number.MAX_SAFE_INTEGER):value is number=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=min&&value<=max;
const oneOf=<T extends string>(value:unknown,values:readonly T[]):value is T=>typeof value==='string'&&values.includes(value as T);
const formStates=['READY','MISSING_INPUT','NEEDS_HUMAN','UNSUPPORTED'] as const;
const categories=['MISSING_INPUT','NEEDS_HUMAN','UNSUPPORTED'] as const;
const owners=['SOURCE_OWNER','BUSINESS_OWNER','OPERATOR'] as const;
const fail=()=>new Error('The project assessment is incomplete or out of date. Refresh it before converting.');
const need=(condition:unknown):void=>{if(!condition)throw fail();};

function finding(value:unknown):ProjectFinding{
 if(!record(value)||!text(value.code,160)||!oneOf(value.category,categories)||!text(value.message)
  ||!(value.source===null||optionalText(value.source,256))||!(value.evidence===null||optionalText(value.evidence))||!oneOf(value.owner,owners)||!text(value.required_action))throw fail();
 return {code:value.code,category:value.category,message:value.message,source:value.source??'',evidence:value.evidence??'',owner:value.owner,required_action:value.required_action};
}
function dependency(value:unknown):ProjectDependency{
 if(!record(value)||!text(value.kind,160)||!text(value.target,512)||!oneOf(value.status,['SOURCE_PRESENT','MISSING'])
  ||!optionalText(value.source,256)||!optionalText(value.evidence)||!text(value.action))throw fail();
 return {kind:value.kind,target:value.target,status:value.status,source:value.source,evidence:value.evidence,action:value.action};
}
function storageMapping(value:unknown,projectId:string,sourceTable:unknown):ProjectStorageMapping{
 const fields=['schema_version','scope','project_id','source_table_name','source_schema_sha256','identity_sha256','target_table_name'];
 if(!record(value)||Object.keys(value).length!==fields.length||!fields.every(key=>Object.hasOwn(value,key))
  ||value.schema_version!==1||value.scope!=='fox-project-storage-v1'||value.project_id!==projectId
  ||typeof value.source_table_name!=='string'||!/^[A-Z][A-Z0-9_$#]{0,127}(?![\s\S])/.test(value.source_table_name)||value.source_table_name!==sourceTable
  ||!hash(value.source_schema_sha256)||!hash(value.identity_sha256)||value.target_table_name!=='FOX_NATIVE_'+value.identity_sha256.slice(0,19).toUpperCase())throw fail();
 return {schema_version:1,scope:'fox-project-storage-v1',project_id:projectId,source_table_name:value.source_table_name,
  source_schema_sha256:value.source_schema_sha256,identity_sha256:value.identity_sha256,target_table_name:value.target_table_name};
}
function form(value:unknown,projectId:string):ProjectForm{
 if(!record(value)||!opaque(value.module_id)||!text(value.form_name,256)||!text(value.source_name,256)
  ||!hash(value.source_sha256)||!oneOf(value.state,formStates)||(value.table_name!==null&&!text(value.table_name,128))
  ||!Array.isArray(value.findings)||!Array.isArray(value.dependencies)||!Array.isArray(value.ddl_sources)||!Array.isArray(value.mapping))throw fail();
 const findings=value.findings.map(finding),dependencies=value.dependencies.map(dependency);
 const ddlSources=value.ddl_sources.map((item:unknown)=>{
  if(!record(item)||!text(item.name,256)||!hash(item.sha256))throw fail();
  return {name:item.name,sha256:item.sha256};
 });
 const mapping=value.mapping.map((item:unknown)=>{
  if(!record(item)||!text(item.source_component,512)||!oneOf(item.target_component,['native_report','native_form'])||item.status!=='PLANNED_NOT_GENERATED')throw fail();
  return {source_component:item.source_component,target_component:item.target_component,status:item.status};
 });
 let pages:ProjectForm['planned_pages']=null;
 if(value.planned_pages!==null){
  const raw=value.planned_pages;
  if(!record(raw)||!integer(raw.report_page,1,9998)||!integer(raw.form_page,1,9998)||raw.report_page===raw.form_page)throw fail();
  pages={report_page:raw.report_page,form_page:raw.form_page};
 }
 need(value.state==='READY'?(findings.length===0&&value.table_name!==null):findings.length>0);
 const storage=Object.hasOwn(value,'storage_mapping')?storageMapping(value.storage_mapping,projectId,value.table_name):undefined;
 return {module_id:value.module_id,form_name:value.form_name,source_name:value.source_name,source_sha256:value.source_sha256,
  state:value.state,table_name:value.table_name as string|null,...(storage?{storage_mapping:storage}:{}),findings,dependencies,ddl_sources:ddlSources,mapping,planned_pages:pages};
}
function source(value:unknown):ProjectSource{
 if(!record(value)||!text(value.name,256)||!hash(value.sha256)||!integer(value.bytes,1)
  ||!oneOf(value.kind,['FORM_XML','TABLE_DDL','SUPPORTING_SOURCE','UNSUPPORTED_XML'])
  ||!oneOf(value.disposition,['MAPPED','BLOCKED','UNASSIGNED'])||!Array.isArray(value.module_ids)||!value.module_ids.every(opaque)
  ||new Set(value.module_ids).size!==value.module_ids.length)throw fail();
 return {name:value.name,sha256:value.sha256,bytes:value.bytes,kind:value.kind,module_ids:[...value.module_ids],disposition:value.disposition};
}

export function validSourceBinding(value:unknown):value is SourceBinding{
 return record(value)&&opaque(value.project_id)&&hash(value.source_hash)
  &&(value.selected_source_set_id===null||opaque(value.selected_source_set_id));
}

export function readProjectPlan(value:unknown,binding:SourceBinding):ProjectConversionPlan{
 if(!validSourceBinding(binding)||!record(value)||value.schema_version!==1||value.scope!=='fox-project-conversion-plan-v1'
  ||value.profile_id!=='native-project-v1'||value.project_id!==binding.project_id||value.source_hash!==binding.source_hash
  ||!text(value.project_name,120)||!oneOf(value.state,['READY','BLOCKED','EMPTY'])||typeof value.can_generate!=='boolean'||typeof value.assessment_complete!=='boolean'
  ||!hash(value.plan_sha256)||!Array.isArray(value.forms)||!Array.isArray(value.project_findings)||!Array.isArray(value.source_files)||!record(value.summary))throw fail();
 const forms=value.forms.map(item=>form(item,binding.project_id)),findings=value.project_findings.map(finding),sources=value.source_files.map(source);
 const mapped=forms.filter(item=>item.storage_mapping!==undefined);
 need(mapped.length===0||mapped.length===forms.length);
 const sourceMappings=new Map<string,ProjectStorageMapping>(),targetSources=new Map<string,string>();
 for(const item of mapped){
  const mapping=item.storage_mapping!,previous=sourceMappings.get(mapping.source_table_name),targetSource=targetSources.get(mapping.target_table_name);
  need(!previous||previous.source_schema_sha256===mapping.source_schema_sha256&&previous.identity_sha256===mapping.identity_sha256&&previous.target_table_name===mapping.target_table_name);
  need(targetSource===undefined||targetSource===mapping.source_table_name);
  sourceMappings.set(mapping.source_table_name,mapping);targetSources.set(mapping.target_table_name,mapping.source_table_name);
 }
 const ids=new Set(forms.map(item=>item.module_id)),sourceNames=new Set(sources.map(item=>item.name));
 need(ids.size===forms.length&&sourceNames.size===sources.length);
 for(const item of forms){
  const file=sources.find(file=>file.name===item.source_name);
  need(file&&file.kind==='FORM_XML'&&file.sha256===item.source_sha256&&file.module_ids.includes(item.module_id));
 }
 for(const file of sources){
  need(file.module_ids.every(id=>ids.has(id)));
  if(file.kind==='FORM_XML'&&value.assessment_complete)need(file.module_ids.length>0&&file.module_ids.every(id=>forms.some(item=>item.module_id===id&&item.source_name===file.name)));
 }
 const pageIds=forms.flatMap(item=>item.planned_pages?[item.planned_pages.report_page,item.planned_pages.form_page]:[]);
 need(new Set(pageIds).size===pageIds.length);
 const expected={form_count:forms.length,ready_forms:forms.filter(item=>item.state==='READY').length,
  missing_input_forms:forms.filter(item=>item.state==='MISSING_INPUT').length,needs_human_forms:forms.filter(item=>item.state==='NEEDS_HUMAN').length,
  unsupported_forms:forms.filter(item=>item.state==='UNSUPPORTED').length,blocking_findings:findings.length+forms.reduce((count,item)=>count+item.findings.length,0),
  unassessed_sources:value.assessment_complete?0:sources.length};
 for(const [key,count]of Object.entries(expected))need(value.summary[key]===count&&integer(value.summary[key]));
 need(value.assessment_complete||(forms.length===0&&sources.every(item=>item.disposition==='BLOCKED')&&findings.length>0));
 const ready=value.assessment_complete&&forms.length>0&&expected.ready_forms===forms.length&&expected.blocking_findings===0&&sources.every(item=>item.disposition!=='BLOCKED');
 need(value.can_generate===ready&&(value.state==='READY')===ready);
 need(mapped.length===0||ready);
 need(!ready||mapped.length===forms.length||forms.every(item=>item.table_name?.startsWith('FOX_NATIVE_')));
 if(ready)need(forms.every(item=>item.planned_pages!==null));
 need(value.state==='EMPTY'?sources.length===0&&forms.length===0: sources.length>0);
 return {schema_version:1,scope:'fox-project-conversion-plan-v1',profile_id:'native-project-v1',project_id:binding.project_id,
  project_name:value.project_name,source_hash:binding.source_hash,state:value.state,assessment_complete:value.assessment_complete,can_generate:value.can_generate,
  plan_sha256:value.plan_sha256,forms,project_findings:findings,source_files:sources,summary:expected};
}

export function presentProjectPlan(value:unknown,binding:SourceBinding):{plan:ProjectConversionPlan|null;message:string|null}{
 try{return {plan:readProjectPlan(value,binding),message:null};}
 catch{return {plan:null,message:fail().message};}
}

export const formReadinessLabels:Record<FormReadiness,string>={READY:'Ready to generate',MISSING_INPUT:'Files or definitions needed',NEEDS_HUMAN:'Your decision is needed',UNSUPPORTED:'Not supported yet'};
export const findingOwnerLabels:Record<FindingOwner,string>={SOURCE_OWNER:'Source or database owner',BUSINESS_OWNER:'Business / application owner',OPERATOR:'FOX support team'};

export function actionContext(binding:SourceBinding,plan:ProjectConversionPlan|null,runId?:string,runSourceHash?:string):ProjectActionContext{
 need(validSourceBinding(binding)&&(!plan||(plan.project_id===binding.project_id&&plan.source_hash===binding.source_hash)));
 need(runId===undefined?runSourceHash===undefined:opaque(runId)&&hash(runSourceHash));
 return {...binding,expected_current_source_set_id:binding.selected_source_set_id,plan_sha256:plan?.plan_sha256??null,...(runId?{run_id:runId,run_source_hash:runSourceHash}:{})};
}

export function available(value:unknown,handlerPresent:boolean,fallback:string):ActionCapability{
 if(!handlerPresent)return {enabled:false,reason:fallback};
 if(!record(value)||typeof value.enabled!=='boolean')return {enabled:false,reason:'This action has not been enabled by the server.'};
 return value.enabled?{enabled:true}:{enabled:false,reason:text(value.reason)?value.reason:fallback};
}

export function processAvailability(plan:ProjectConversionPlan|null,capability:unknown,handlerPresent:boolean,confirmations:ProcessConfirmations,processingNotice:string,busy=false,unknownOutcome=false):ActionCapability{
 if(busy)return {enabled:false,reason:'Wait for the current action to finish.'};
 if(unknownOutcome)return {enabled:false,reason:'Check the existing run status before starting another operation.'};
 if(!plan)return {enabled:false,reason:'Refresh the project assessment before converting.'};
 if(!plan.can_generate)return {enabled:false,reason:plan.state==='EMPTY'?'Add your source files first.':'Resolve every selected form’s blocking finding before generating the project app.'};
 const enabled=available(capability,handlerPresent,'Conversion has not been connected for this deployment.');
 if(!enabled.enabled)return enabled;
 if(!text(processingNotice))return {enabled:false,reason:'The processing route must be confirmed by the FOX support team.'};
 const required=['approved_redacted_source','approved_external_ai','approved_prototype_scope'] as const;
 if(!record(confirmations)||Object.keys(confirmations).length!==required.length||!required.every(key=>Object.hasOwn(confirmations,key)&&confirmations[key]===true))return {enabled:false,reason:'Review and confirm the three processing statements first.'};
 return {enabled:true};
}

export type RunStep={id:string;label:string;state:'pending'|'running'|'complete'|'blocked';message?:string};
export type FormRunStatus={module_id:string;state:'queued'|'running'|'generated'|'blocked'|'failed';message?:string};
export type RecoveryAction={kind:'check_status'|'retry_step'|'resume';enabled:boolean;reason?:string;safety:'read_only'|'server_confirmed_safe';label?:string};
export type ProjectRun={id:string;project_id:string;source_hash:string;state:string;message:string;stage_message?:string;
 artifact_generated?:boolean;technical_verified?:boolean;human_accepted?:boolean;downloadable?:boolean;preview_available?:boolean;review_available?:boolean;
 steps?:RunStep[];forms?:FormRunStatus[];recovery?:RecoveryAction;error?:{message:string;action:string;owner:FindingOwner}};
export type RunPresentation={label:string;tone:'neutral'|'active'|'attention'|'success';earlierSource:boolean;generated:boolean;technicalVerified:boolean;humanAccepted:boolean;canPreview:boolean;canReview:boolean;canDownload:boolean;downloadReason:string;message:string;stageMessage:string|null;error:{message:string;action:string;owner:FindingOwner}|null;steps:RunStep[];forms:FormRunStatus[];detailsIncomplete:boolean};

export function runBelongsToProject(value:unknown,projectId:string):value is ProjectRun{
 return record(value)&&opaque(value.id)&&value.project_id===projectId&&hash(value.source_hash)&&typeof value.state==='string'&&typeof value.message==='string';
}

export function presentProjectRun(run:ProjectRun,sourceHash:string,projectId:string):RunPresentation{
 if(!record(run))return {label:'Status unavailable',tone:'attention',earlierSource:true,generated:false,technicalVerified:false,humanAccepted:false,canPreview:false,canReview:false,canDownload:false,downloadReason:'The run status could not be established.',message:'Run details are unavailable.',stageMessage:null,error:null,steps:[],forms:[],detailsIncomplete:true};
 const states:Record<string,[string,RunPresentation['tone']]>={QUEUED:['Waiting to start','neutral'],PROCESSING:['Converting project','active'],ATTENTION:['Action needed','attention'],FAILED:['Conversion stopped','attention'],QA_REQUIRED:['Technical checks pending','active'],REVIEW_REQUIRED:['Review required','attention'],VERIFIED:['Technical checks passed','success'],ACCEPTED:['Human review recorded','success']};
 const valid=opaque(run.id)&&opaque(projectId)&&run.project_id===projectId&&hash(run.source_hash)&&hash(sourceHash)&&Object.hasOwn(states,run.state);
 const earlierSource=run.source_hash!==sourceHash;
 const generated=valid&&run.artifact_generated===true;
 const technicalVerified=generated&&run.technical_verified===true&&['VERIFIED','ACCEPTED'].includes(run.state);
 const humanAccepted=technicalVerified&&run.human_accepted===true&&run.state==='ACCEPTED';
 const steps=Array.isArray(run.steps)?run.steps.filter(item=>record(item)&&opaque(item.id)&&text(item.label,200)&&oneOf(item.state,['pending','running','complete','blocked'])&&(item.message===undefined||text(item.message))):[];
 const forms=Array.isArray(run.forms)?run.forms.filter(item=>record(item)&&opaque(item.module_id)&&oneOf(item.state,['queued','running','generated','blocked','failed'])&&(item.message===undefined||text(item.message))):[];
 const duplicateSteps=new Set(steps.map(item=>item.id)).size!==steps.length,duplicateForms=new Set(forms.map(item=>item.module_id)).size!==forms.length;
 const canDownload=humanAccepted&&run.downloadable===true;
 const message=text(run.message)?run.message:'No run summary has been reported.';
 const stageMessage=text(run.stage_message)?run.stage_message:null;
 const error=record(run.error)&&text(run.error.message)&&text(run.error.action)&&oneOf(run.error.owner,owners)
  ?{message:run.error.message,action:run.error.action,owner:run.error.owner}:null;
 const malformedDetails=!text(run.message)||(run.stage_message!==undefined&&run.stage_message!==null&&!stageMessage)
  ||(run.error!==undefined&&run.error!==null&&!error);
 const downloadReason=canDownload?'':!generated?'The APEX package has not been reported as generated.':!technicalVerified?'Technical verification must pass before review and release.':!humanAccepted?'Genuine human review is still required before download.':'The server has not enabled download for this package.';
 const missingEvidence=run.state==='VERIFIED'&&!technicalVerified||run.state==='ACCEPTED'&&!humanAccepted;
 return {label:missingEvidence?'Verification evidence unavailable':valid?states[run.state][0]:'Status unavailable',tone:missingEvidence?'attention':valid?states[run.state][1]:'attention',earlierSource,generated,technicalVerified,humanAccepted,
  canPreview:generated&&run.preview_available===true,canReview:technicalVerified&&!humanAccepted&&!earlierSource&&run.review_available===true,
  canDownload,downloadReason,message,stageMessage,error,steps:duplicateSteps?[]:steps,forms:duplicateForms?[]:forms,
  detailsIncomplete:!valid||missingEvidence||malformedDetails||duplicateSteps||duplicateForms||(Array.isArray(run.steps)&&steps.length!==run.steps.length)||(Array.isArray(run.forms)&&forms.length!==run.forms.length)};
}

export function recoveryAvailability(run:ProjectRun,handlerPresent:boolean,busy=false):ActionCapability&{kind:RecoveryAction['kind']|null;label:string}{
 const action=run.recovery;
 const denied=(reason:string)=>({kind:null,label:'Check run status',enabled:false,reason});
 if(busy)return denied('Wait for the current action to finish.');
 if(!handlerPresent||!record(action)||!oneOf(action.kind,['check_status','retry_step','resume']))return denied('A safe continuation action has not been reported. Contact the FOX support team with the run ID.');
 if(action.kind!=='check_status'&&!['ATTENTION','FAILED'].includes(run.state))return denied('This run is not in a state that permits a retry or continuation.');
 const safety=action.kind==='check_status'?action.safety==='read_only':action.safety==='server_confirmed_safe';
 if(!safety)return denied('The previous result must be checked before a retry can be offered.');
 const enabled=available(action,true,'This action is not currently permitted.');
 return {...enabled,kind:action.kind,label:action.kind==='check_status'?'Check run status':action.kind==='retry_step'?'Retry failed step':'Continue from saved work'};
}
