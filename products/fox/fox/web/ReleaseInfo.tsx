import {useEffect,useState} from 'react';
import metadata from '../fox/release.json';
import {presentRelease,readRelease} from './releasePresentation';
import './releaseInfo.css';
const bundled=readRelease(metadata);
export function ReleaseDetails({serverVersion=null,checking=false,onRetry}:{serverVersion?:string|null;checking?:boolean;onRetry?:()=>void}){
 const state=presentRelease(bundled.version,serverVersion,checking);
 return <section className="release-info" aria-label="FOX release information">
  <details><summary>{state.label} · What changed</summary><div className="release-notes">
   <p role="status" aria-live="polite">{state.message}</p>
   {state.kind==='unavailable'&&onRetry&&<button type="button" className="secondary" onClick={onRetry}>Retry version check</button>}
   <h3>{bundled.title}</h3><p className="subtle">UI release {bundled.version} · {bundled.released_on}</p>
   {state.kind!=='matched'&&<p>These notes describe the UI files loaded in this browser. The server release is different or unconfirmed.</p>}
   <ul>{bundled.changes.map(item=><li key={item}>{item}</li>)}</ul>
   <h4>Still important</h4><ul>{bundled.limitations.map(item=><li key={item}>{item}</li>)}</ul>
  </div></details>
 </section>;
}
export default function ReleaseInfo(){
 const [serverVersion,setServerVersion]=useState<string|null>(null),[checking,setChecking]=useState(true),[attempt,setAttempt]=useState(0);
 useEffect(()=>{
  const controller=new AbortController();let active=true;setChecking(true);
  const timer=setTimeout(()=>controller.abort(),6000);
  void fetch('/api/release',{signal:controller.signal,cache:'no-store'}).then(async response=>{
   if(!response.ok)throw new Error('Release information unavailable');
   const raw=await response.text();if(raw.length>16384)throw new Error('Release information too large');
   const release=readRelease(JSON.parse(raw));if(active)setServerVersion(release.version);
  }).catch(()=>{if(active)setServerVersion(null);}).finally(()=>{clearTimeout(timer);if(active)setChecking(false);});
  return ()=>{active=false;clearTimeout(timer);controller.abort();};
 },[attempt]);
 return <ReleaseDetails serverVersion={serverVersion} checking={checking} onRetry={()=>setAttempt(n=>n+1)}/>;
}
