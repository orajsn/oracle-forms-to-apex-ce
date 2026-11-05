import React from 'react';

export default function ApexHandoff({evidence}:{evidence:unknown}){
 const record=(value:unknown):value is Record<string,unknown>=>typeof value==='object'&&value!==null&&!Array.isArray(value);
 const technical=record(evidence)&&record(evidence.technical_verification)?evidence.technical_verification:null;
 const versions=technical?.scope==='fox-project-technical-verification-v1'&&record(technical.observed_versions)?technical.observed_versions:null;
 const version=(name:string)=>versions&&typeof versions[name]==='string'&&/^[0-9][0-9A-Za-z.+_-]{0,79}$/.test(versions[name])?versions[name] as string:'Not established in this evidence';
 return <section className="fox-workbench fw-handoff" aria-label="APEX import handoff"><h3>Continue in native APEX</h3>
  <div className="fw-readiness-grid">{[['apex','Tested APEX release'],['database','Tested database release'],['sqlcl','Tested SQLcl release']].map(([key,label])=><div className="fw-readiness-item" key={key}><div><strong>{label}</strong><span>{version(key)}</span></div></div>)}</div>
  <p className="fw-small">These are the recorded test versions, not a promise of compatibility with every later or earlier target.</p>
  <ol><li>Read the package’s <code>README.txt</code>, source-to-page mapping and remaining-work report.</li><li>In a compatible, approved empty test schema, review and run <code>schema/01_synthetic_schema.sql</code>. It contains no customer data or business APIs.</li><li>Import <code>sql/fNNN.sql</code> into APEX using a new application ID and alias. Do not replace an existing application.</li><li>Configure authentication for your target and test the flow. Continue development in APEX as needed.</li></ol>
  <p>FOX does not merge later regenerations into your APEX edits. Business approval remains a separate human decision.</p>
 </section>;
}
