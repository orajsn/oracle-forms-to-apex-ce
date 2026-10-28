'use strict';
(()=>{
  const el=id=>document.getElementById(id);
  let planHash=null, busy=false, attempted=false, connectionAttempted=false, connectionTarget=null, connectionsSaved=false;
  const hints={INSTALLATION_PARENT_MISSING:'The parent folder does not exist. Choose a folder inside an existing location you own.',INSTALLATION_PARENT_UNSAFE:'Choose a protected parent folder. FOX will not silently change its permissions.',INSTALLATION_PARENT_NOT_OWNED:'Choose a parent folder owned by the account running setup.',EXISTING_INSTALLATION_NOT_ADOPTED:'This folder already exists without verified FOX setup metadata. Choose a new folder or ask the operator to inspect it.',SETUP_AUTHENTICATION_REQUIRED:'The setup code is missing or incorrect.',SETUP_SESSION_EXPIRED:'Restart the setup launcher for a new code. Keep the existing installation folder; its state is preserved.'};
  function outcome(title,text,code=''){el('outcome').hidden=false;el('outcome-title').textContent=title;el('outcome-text').textContent=text;el('code-label').textContent=code;}
  function lock(value){busy=value;document.body.classList.toggle('busy',value);el('review').disabled=value||attempted;el('initialize').disabled=value||attempted||!planHash||!el('confirmed').checked;el('recheck').disabled=value;el('installation-root').disabled=value||attempted;el('save-connections').disabled=value||connectionAttempted||connectionsSaved||!connectionTarget||!el('connections-confirmed').checked;}
  async function request(path,body){const response=await fetch(path,{method:body?'POST':'GET',cache:'no-store',headers:{Authorization:'Bearer '+el('setup-code').value,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});const data=await response.json();if(!response.ok)throw new Error(data.code||'SETUP_REQUEST_REJECTED');return data;}
  function show(data){
    planHash=data.plan_sha256;
    connectionsSaved=data.connections?.status==='CONNECTION_INPUTS_SAVED_NOT_TESTED';
    const storagePrepared=['STORAGE_OBSERVED_NOT_INSTALLED','STORAGE_INITIALIZED_NOT_INSTALLED','STORAGE_REUSED_NOT_INSTALLED'].includes(data.storage?.status);
    el('step-storage').classList.toggle('current',!storagePrepared);el('step-storage').classList.toggle('done',storagePrepared);
    el('step-connections').classList.toggle('current',storagePrepared);
    if(storagePrepared){el('step-storage').removeAttribute('aria-current');el('step-connections').setAttribute('aria-current','step');}
    else{el('step-connections').removeAttribute('aria-current');el('step-storage').setAttribute('aria-current','step');}
    el('plan-form').hidden=storagePrepared;el('confirmed').closest('label').hidden=storagePrepared;el('initialize').hidden=storagePrepared;
    if(data.connection_write_attempted===true)connectionAttempted=true;
    else if(data.connection_write_attempted===false&&data.state==='STORAGE_PREPARED'&&!connectionsSaved)connectionAttempted=false;
    const target=data.connection_targets?.[0];connectionTarget=target?.profile_id||null;
    el('target-label').textContent=target?target.label+' — '+target.profile_id:'';
    el('connections-form').hidden=data.state!=='STORAGE_PREPARED'||connectionsSaved;
    const labels={STORAGE_NOT_STARTED:'New installation folder',STORAGE_PENDING_NOT_INSTALLED:'Retained plan; storage preparation has not started',STORAGE_OBSERVED_NOT_INSTALLED:'Existing storage phase verified',STORAGE_INITIALIZED_NOT_INSTALLED:'Storage prepared',STORAGE_REUSED_NOT_INSTALLED:'Existing storage rechecked'};
    if(data.installation_root){el('review-panel').hidden=false;el('root-label').textContent=data.installation_root;el('storage-label').textContent=labels[data.storage?.status]||'Needs inspection';}else{el('review-panel').hidden=true;}
    if(data.write_attempted===true)attempted=true;
    else if(data.write_attempted===false){attempted=false;el('confirmed').checked=false;}
    if(data.state==='REVIEW_PLAN')el('outcome').hidden=true;
    if(data.state==='STORAGE_PREPARED'){attempted=true;outcome('Storage is prepared','Your local storage phase is confirmed. Connections, service startup and end-to-end verification still need to be completed. FOX is not yet conversion-ready.');}
    else if(data.state==='CONNECTION_INPUTS_SAVED'){attempted=true;outcome('Protected settings are saved','Your FOX access and paired OPAF settings are retained locally. Connectivity has not been tested. Service startup and end-to-end verification remain incomplete; FOX is not conversion-ready.');}
    else if(data.state==='ATTENTION'){attempted=true;outcome('Setup needs inspection','The retained attempt has not been repeated. Keep this folder and use the diagnostic code when asking the operator to inspect it.',data.code);}
    else if(data.state==='CHOOSE_LOCATION'){outcome('Choose your installation folder','Enter a new local folder, then review the setup before approving changes.');}
  }
  el('confirmed').addEventListener('change',()=>lock(busy));
  el('connections-confirmed').addEventListener('change',()=>lock(busy));
  el('installation-root').addEventListener('input',()=>{planHash=null;el('confirmed').checked=false;el('review-panel').hidden=true;lock(busy);});
  el('plan-form').addEventListener('submit',async event=>{event.preventDefault();if(busy||attempted)return;lock(true);try{show(await request('/api/plan',{installation_root:el('installation-root').value}));el('confirmed').checked=false;}catch(error){planHash=null;outcome('Setup could not be planned',hints[error.message]||'No storage preparation was requested. Check the installation folder or setup code.',error.message);}finally{lock(false);}});
  el('initialize').addEventListener('click',async()=>{if(busy||attempted||!planHash||!el('confirmed').checked)return;attempted=true;lock(true);outcome('Preparing storage','Keep this page open. If the connection is interrupted, recheck saved state instead of repeating the request.');try{show(await request('/api/initialize',{plan_sha256:planHash,confirmed:true}));}catch(error){outcome('The setup result is uncertain','Do not repeat preparation. Recheck the saved state first; the server may have completed the action.',error.message);}finally{lock(false);}});
  el('recheck').addEventListener('click',async()=>{if(busy)return;lock(true);try{show(await request('/api/status'));}catch(error){outcome('State could not be checked','No preparation or retry was requested. Check the setup code and try this read-only check again.',error.message);}finally{lock(false);}});
  el('connections-form').addEventListener('submit',async event=>{event.preventDefault();if(busy||connectionAttempted||connectionsSaved||!connectionTarget||!planHash||!el('connections-confirmed').checked)return;connectionAttempted=true;lock(true);
    try{show(await request('/api/connections',{plan_sha256:planHash,confirmed:true,settings:{target_profile_id:connectionTarget,fox_username:el('fox-username').value,fox_password:el('fox-password').value,opaf_username:el('opaf-username').value,opaf_password:el('opaf-password').value}}));}
    catch(error){outcome('Settings could not be confirmed','Recheck saved state before another action. Existing settings have not been replaced.',error.message);}
    finally{el('fox-password').value='';el('opaf-password').value='';el('connections-confirmed').checked=false;lock(false);}
  });
})();
