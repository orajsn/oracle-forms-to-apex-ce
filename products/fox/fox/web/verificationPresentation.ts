// Read-only presentation of the owner-checked public status. Never a gate.
type VerificationState='queued'|'running'|'attention'|'not_queued'|'unavailable'|'disabled';
type OperatorContact='recent'|'stale'|'not_reported'|'unknown';
type SeenAt={value:string;label:string};
export type VerificationPresentation={
 state:VerificationState;label:string;message:string;
 operatorContact:OperatorContact;contactMessage:string;lastSeen:SeenAt|null;
 contactOperator:boolean;action:string|null;
};
const activeStates=new Set(['queued','running','attention','not_queued','unavailable']);
const contacts=new Set(['recent','stale','not_reported','unknown']);
const record=(value:unknown):value is Record<string,unknown>=>typeof value==='object'&&value!==null&&!Array.isArray(value);
const descriptions:Record<VerificationState,{label:string;message:string}>={
 queued:{label:'Queued for verification',message:'This package is queued for the FOX verification operator. A result has not yet been recorded.'},
 running:{label:'Verification attempt started',message:'A verification attempt has started, but its result has not yet been recorded. This does not confirm that the attempt is still running.'},
 attention:{label:'Operator attention required',message:'Verification needs operator reconciliation. It will not be retried automatically.'},
 not_queued:{label:'Not yet queued for verification',message:'The verification handoff is waiting for the FOX operator to reconcile it.'},
 unavailable:{label:'Verification status unavailable',message:'The package’s verification status could not be established.'},
 disabled:{label:'Managed verification not configured',message:'Managed verification is not configured for this deployment. The FOX operator must verify this package.'},
};
const contactMessages:Record<OperatorContact,string>={
 recent:'Latest reported operator contact: recent.',
 stale:'Latest reported operator contact: stale.',
 not_reported:'No operator contact has been reported.',
 unknown:'The latest status report cannot establish operator contact.',
};

function seenAt(value:unknown):SeenAt|null{
 if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)(?![^])/.test(value))return null;
 const date=new Date(value);
 if(!Number.isFinite(date.getTime()))return null;
 const canonical=date.toISOString();
 // Date.parse can normalize impossible dates/hours; do not display those.
 if(canonical.slice(0,19)!==value.slice(0,19))return null;
 return {value,label:canonical.slice(0,19).replace('T',' ')+' UTC'};
}

export function presentVerificationStatus(runState:unknown,value:unknown):VerificationPresentation|null{
 // A queue completion never substitutes for the VERIFIED/ACCEPTED proof path.
 if(runState!=='QA_REQUIRED')return null;
 const raw=record(value)?value:null;
 const disabled=raw?.configured===false&&raw.state==='disabled';
 const valid=disabled||(raw?.configured===true&&typeof raw.state==='string'&&activeStates.has(raw.state));
 const state:VerificationState=valid?raw!.state as VerificationState:'unavailable';
 let operatorContact:OperatorContact=disabled?'not_reported':
  valid&&state!=='unavailable'&&typeof raw!.operator_contact==='string'&&contacts.has(raw!.operator_contact)
   ?raw!.operator_contact as OperatorContact:'unknown';
 let lastSeen:SeenAt|null=null;
 if(valid&&state!=='disabled'&&state!=='unavailable'&&(operatorContact==='recent'||operatorContact==='stale')){
  const supplied=raw!.operator_last_seen_at_utc;
  if(supplied!==undefined&&supplied!==null){
   lastSeen=seenAt(supplied);
   if(!lastSeen)operatorContact='unknown';
  }
 }
 const contactOperator=!['queued','running'].includes(state)||operatorContact!=='recent';
 return {state,...descriptions[state],operatorContact,contactMessage:contactMessages[operatorContact],lastSeen,
  contactOperator,action:contactOperator?'Contact the FOX operator to check and reconcile verification for this package.':null};
}
