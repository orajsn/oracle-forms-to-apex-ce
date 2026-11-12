import React,{useEffect,useRef,useState} from 'react';
import './PrototypeProgress.css';

const stages=[['mapping','Mapping and review'],['validate','Validate APEX'],['prepare_schema','Prepare demo tables'],['import','Import new application'],['verify_runtime','Test pages'],['export','Build download']] as const;
type StageStatus='not_observed'|'working'|'recorded'|'attention';
type Progress={stages:{id:string;status:StageStatus}[]};
const labels:Record<StageStatus,string>={not_observed:'Not yet recorded',working:'Working',recorded:'Recorded',attention:'Needs attention'};

function checked(value:unknown,projectId:string,runId:string,sourceHash:string,state:string):Progress {
 const p=value as Record<string,unknown> | null;
 if(!p||p.schema_version!==1||p.scope!=='fox-prototype-progress-v1'||p.project_id!==projectId||p.run_id!==runId||p.source_hash!==sourceHash||p.state!==state||p.progress_available!==true||p.advisory!==true||p.technically_verified!==false||p.business_behavior_accepted!==false||typeof p.message!=='string'||typeof p.observed_at_utc!=='string'||!Number.isFinite(Date.parse(p.observed_at_utc))||!(p.current_stage===null||stages.some(([id])=>id===p.current_stage))||!Array.isArray(p.stages)||p.stages.length!==stages.length||!p.stages.every((item:unknown,i:number)=>{const s=item as {id?:unknown;status?:unknown}|null;return s&&s.id===stages[i][0]&&typeof s.status==='string'&&Object.prototype.hasOwnProperty.call(labels,s.status);}))throw new Error('Unverified progress');
 const recorded=p.stages as Progress['stages'];
 let afterRecorded=false,active:string|null=null;
 for(const stage of recorded){
  if(stage.status==='recorded'){if(afterRecorded)throw new Error('Unverified progress');continue;}
  afterRecorded=true;
  if(stage.status==='working'||stage.status==='attention'){
   if(active!==null||(stage.status==='working'&&state!=='PROCESSING')||(stage.status==='attention'&&state!=='ATTENTION'))throw new Error('Unverified progress');
   active=stage.id;
  }else if(active===null){active='';}
 }
 if(p.current_stage!==(active||null))throw new Error('Unverified progress');
 return {stages:recorded};
}

export default function PrototypeProgress({projectId,runId,sourceHash,state}:{projectId:string;runId:string;sourceHash:string;state:string}){
 const [progress,setProgress]=useState<Progress|null>(null),[loading,setLoading]=useState(true),[unavailable,setUnavailable]=useState(false);
 const revision=useRef(0),controller=useRef<AbortController|null>(null);
 async function refresh(){
  const current=++revision.current;controller.current?.abort();const abort=new AbortController();controller.current=abort;
  setProgress(null);setUnavailable(false);setLoading(true);
  const timer=setTimeout(()=>abort.abort(),15000);
  try{
   const response=await fetch(`/api/projects/${encodeURIComponent(projectId)}/prototype-runs/${encodeURIComponent(runId)}/progress`,{method:'GET',credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:abort.signal});
   if(!response.ok)throw new Error('Unavailable');
   const result=checked(await response.json(),projectId,runId,sourceHash,state);
   if(revision.current===current&&!abort.signal.aborted)setProgress(result);
  }catch{if(revision.current===current)setUnavailable(true);}
  finally{clearTimeout(timer);if(revision.current===current){setLoading(false);controller.current=null;}}
 }
 useEffect(()=>{void refresh();return()=>{revision.current++;controller.current?.abort();};},[projectId,runId,sourceHash,state]);
 return <section className="fw-progress" aria-label="Prototype progress">
  <div className="fw-progress-heading"><h3>Prototype progress</h3><button type="button" className="fw-secondary" disabled={loading} onClick={()=>void refresh()}>Refresh progress</button></div>
  {loading&&<p role="status">Checking recorded progress…</p>}
  {unavailable&&<p role="status">Progress is unavailable or does not match this run. Refresh progress, or refresh the project and ask your operator for help if it remains unavailable.</p>}
  {progress&&<><ol className="fw-progress-stages">{progress.stages.map((stage,i)=><li key={stage.id}><span>{stages[i][1]}</span><strong>{labels[stage.status]}</strong></li>)}</ol><p className="fw-small">These are advisory records, not proof of technical verification or business acceptance. A recorded step does not mean the full conversion is complete.</p></>}
 </section>;
}
