import React from 'react';
import {readFormsFacts} from './formsFactsPresentation';
import type {SourceIdentity} from './formsFactsPresentation';
import './formsUnderstanding.css';

// The parent supplies both the selected source identity and separately obtained
// review status. This component never starts work or makes network requests.
export type UnderstandingStatus={state:'not_run'|'working'|'reviewed';source_sha256:string};
export type FormsUnderstandingProps={facts:unknown|null;selectedSource:SourceIdentity|null;understanding?:UnderstandingStatus|null};
const labels={database:'Database block',control:'Control block',unknown:'Block type needs review'};
const itemLabel=(value:boolean|null)=>value===true?'Database item':value===false?'Control item':'Item type needs review';
export function FormsUnderstanding({facts,selectedSource,understanding}:FormsUnderstandingProps){
 let view:ReturnType<typeof readFormsFacts>|null=null,invalid=false;
 if(facts!==null){try{if(!selectedSource)throw new Error();view=readFormsFacts(facts,selectedSource);}catch{invalid=true;}}
 const statusValid=!!view&&(!understanding||(['not_run','working','reviewed'].includes(understanding.state)&&understanding.source_sha256===view.source.sha256));
 if(understanding&&!statusValid)invalid=true;
 const state=statusValid&&understanding?understanding.state:'not_run';
 return <section className="forms-understanding" aria-label="Forms understanding">
  <div className="forms-understanding__section"><h2>Understand the Forms source</h2>
   <p>FOX first records what it can observe in the readable source. Understanding the application and reviewing a design are separate steps.</p>
   {invalid?<p className="forms-understanding__notice forms-understanding__error" role="alert">The assessment or review status is incomplete or no longer matches the selected source. Refresh the source assessment before continuing.</p>
    :!view?<p className="forms-understanding__notice">No source facts yet. Add readable Forms XML and run a local assessment first. Keep the original Forms files.</p>
    :<><p>Source: <strong>{view.source.name}</strong> · {view.source.bytes.toLocaleString()} bytes</p><p><small>Source SHA-256: <code>{view.source.sha256}</code></small></p>
     <div className="forms-understanding__stats"><div><strong>{view.totals.blocks}</strong><span>blocks observed</span></div><div><strong>{view.totals.items}</strong><span>items observed</span></div><div><strong>{view.totals.triggers}</strong><span>triggers observed</span></div><div><strong>{view.findingCount}</strong><span>findings to review</span></div></div>
     <p className="forms-understanding__notice">Local facts only. Source code was not executed. An inventory is not a reviewed design, a conversion, or permission to generate or import an application.</p></>}
  </div>
  {!invalid&&view&&<><div className="forms-understanding__section"><h3>Application understanding</h3>
   <p><strong>{state==='working'?'In progress':state==='reviewed'?'Review recorded':'Not run'}</strong></p>
   {state==='not_run'?<p>No application understanding or design review is recorded for this source. Relevant source material, transfer permission, dependencies and human decisions must be checked before that work can begin.</p>
    :state==='working'?<p>Understanding is in progress. A reviewed design and its coverage are not yet confirmed.</p>
    :<p>A review status was supplied for this source. Inspect the actual reviewed design and unresolved decisions before any next step; this inventory does not establish their completeness.</p>}
   <p>Database definitions, supporting libraries and business decisions may be needed. Review findings and provide the missing inputs identified by the assessment and design review.</p>
   {view.reviewRequirements.length>0&&<><h3>What needs review</h3><ul>{view.reviewRequirements.map(text=><li key={text}>{text}</li>)}</ul></>}
  </div><div className="forms-understanding__section"><h3>Observed blocks and items</h3>
   <p>Types below reflect source metadata, not confirmed application behavior. Locations refer to the readable XML; source code and values are not shown.</p>
   {view.blocks.length===0?<p>No blocks were observed in this source. Review the source and assessment before proceeding.</p>:view.blocks.map((block,index)=><details className="forms-understanding__block" key={block.id}>
    <summary>{block.name||`Unnamed block ${index+1}`} · {labels[block.classification]} · {block.items.length} items</summary>
    <p><small>XML location: <code>{block.location.path}</code> · line {block.location.line}, column {block.location.column}</small></p>
    {block.items.length===0?<p>No items observed in this block.</p>:<ul>{block.items.map((item,i)=><li key={item.id}><strong>{item.name||`Unnamed item ${i+1}`}</strong> — {itemLabel(item.database_item)}<br/><small><code>{item.location.path}</code> · line {item.location.line}, column {item.location.column}</small></li>)}</ul>}
   </details>)}
   {view.unassigned.length>0&&<div className="forms-understanding__notice"><strong>{view.unassigned.length} items have no identified block</strong><p>Review their source locations before design.</p><ul>{view.unassigned.map((item,i)=><li key={item.id}>{item.name||`Unnamed item ${i+1}`} — {itemLabel(item.database_item)}<br/><small><code>{item.location.path}</code> · line {item.location.line}, column {item.location.column}</small></li>)}</ul></div>}
  </div></>}
 </section>;
}
