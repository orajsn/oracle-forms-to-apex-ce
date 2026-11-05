import React,{useState} from 'react';
import {CheckCircle2,RefreshCw,TriangleAlert} from 'lucide-react';

type Configuration={conversion_configured:boolean;configuration_scope:string;
 configuration_checks:{code:string;ready:boolean;message:string}[]};

export default function SetupReadiness({configuration,onCheck}:{configuration:Configuration;onCheck:()=>Promise<unknown>}){
 const [busy,setBusy]=useState(false),[status,setStatus]=useState('Not checked in this view'),[checkedAt,setCheckedAt]=useState('');
 async function check(){if(busy)return;setBusy(true);try{
  const value=await onCheck() as {status?:unknown;worker?:{healthy?:unknown}};
  setStatus(value?.status==='ok'&&value.worker?.healthy===true?'FOX service and conversion worker report healthy':'Service or worker needs attention; ask the deployment operator.');
  setCheckedAt(new Date().toLocaleTimeString());
 }catch{setStatus('The service check could not be completed. No conversion was started.');setCheckedAt('');}finally{setBusy(false);}}
 const labels:Record<string,string>={PROFILE:'OPAF workflow configuration',CREDENTIALS:'Protected connection configuration',
  ADAPTER:'Embedded conversion route',INTERNAL_CONVERTER:'Internal converter configuration',CONVERTER:'Converter configuration'};
 return <details className="panel fox-workbench fw-setup" aria-label="Setup and readiness"><summary>Setup &amp; readiness · {configuration.conversion_configured?'Conversion configured':'Configuration needs attention'}</summary>
  <h2>What is connected?</h2><p>Configuration, service health and a successful conversion are different checks.</p>
  <div className="fw-readiness-grid">{configuration.configuration_checks.map(row=><div key={row.code} className="fw-readiness-item">{row.ready?<CheckCircle2 size={18}/>:<TriangleAlert size={18}/>}<div><strong>{labels[row.code]??row.code.toLowerCase().replaceAll('_',' ')}</strong><span>{row.ready?'Configured — connection not tested here':'Needs administrator setup'}</span><small>{row.message}</small></div></div>)}</div>
  <p className="fw-small">{configuration.configuration_scope}</p><div className="fw-preparation-help"><h3>Forms preparation</h3><p>Raw FMB, MMB, OLB and PLL require supported Oracle Forms tooling on a configured preparation host. This browser view does not prove that extraction is installed or working.</p><h3>APEX output and technical verification</h3><p>The exact target version, validation and runtime results belong to each conversion run. A healthy service does not mean those checks passed.</p></div>
  <div className="fw-inline-action"><button type="button" className="fw-secondary" disabled={busy} onClick={()=>void check()}><RefreshCw size={16}/> {busy?'Checking service…':'Check service health'}</button><p role="status">{status}{checkedAt?` · Checked at ${checkedAt}`:''}</p></div>
 </details>;
}
