export type Release={version:string;released_on:string;title:string;changes:string[];limitations:string[]};
export type ReleaseState={kind:'checking'|'matched'|'mismatch'|'unavailable';label:string;message:string};
const version=(v:unknown):v is string=>typeof v==='string'&&/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(v);
export function readRelease(value:unknown):Release{
 if(typeof value!=='object'||value===null||Array.isArray(value))throw new Error('Release information is unavailable.');
 const row=value as Record<string,unknown>;
 const text=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length>0&&v.length<=n&&!/[\u0000-\u001f]/.test(v);
 const list=(v:unknown):v is string[]=>Array.isArray(v)&&v.length>=1&&v.length<=12&&v.every(item=>text(item,400));
 if(Object.keys(row).sort().join(',')!=='changes,limitations,released_on,title,version'||!version(row.version)
  ||!text(row.released_on,10)||!/^\d{4}-\d{2}-\d{2}$/.test(row.released_on)
  ||!Number.isFinite(Date.parse(row.released_on+'T00:00:00Z'))
  ||new Date(row.released_on+'T00:00:00Z').toISOString().slice(0,10)!==row.released_on
  ||!text(row.title,120)||!list(row.changes)||!list(row.limitations))throw new Error('Release information is unavailable.');
 return {version:row.version,released_on:row.released_on,title:row.title,changes:[...row.changes],limitations:[...row.limitations]};
}
export function presentRelease(uiVersion:string,serverVersion:string|null,checking=false):ReleaseState{
 if(!version(uiVersion))throw new Error('Invalid UI release.');
 if(checking)return {kind:'checking',label:`UI v${uiVersion} · checking server`,message:'Checking the server version…'};
 if(serverVersion===null||!version(serverVersion))return {kind:'unavailable',label:`UI v${uiVersion} · server unconfirmed`,message:'Server version unconfirmed. You can keep working; retry this read-only check.'};
 if(serverVersion!==uiVersion)return {kind:'mismatch',label:`UI v${uiVersion} · Server v${serverVersion}`,message:'UI and server versions differ. Refresh the page; contact your FOX administrator if the mismatch remains.'};
 return {kind:'matched',label:`FOX v${uiVersion}`,message:'UI and server versions match. This is software identity, not a conversion verification result.'};
}
