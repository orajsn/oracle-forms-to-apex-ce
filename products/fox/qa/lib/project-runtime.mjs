/** Project case engine. The driver performs browser actions; none of the
 * observations below are inferred from a successful click or planned values.
 * A model driver is useful in unit tests but is NOT Oracle verification. */
import {check,canonicalQaPlan,canonicalPrimaryKey,deriveNativeQaValues,sha256,samePrimaryKeySet,outcomeV2} from './contracts.mjs';
import {PROJECT_OBSERVATION_SCOPE,createProjectRowLedger,assertProjectFormBaseline,retainProjectFormRow} from './project-profile.mjs';

const same=(a,b)=>canonicalQaPlan(a)===canonicalQaPlan(b);
const now=()=>new Date().toISOString();
const optionalChecks=()=>['database_constraints','database_sql_readback'].map(name=>({name,required:false,status:'NOT_RUN',
  reason:'This runner observes authenticated browser behavior only; independent operator SQL checks are separate.'}));
const makeTests=plan=>plan.cases.map(item=>({...structuredClone(item),required:item.applicable,
  status:item.applicable?'NOT_RUN':'NOT_APPLICABLE',field_results:[],reason:item.applicable?'Not reached':'No matching editable fields in the exact specification'}));

export function createProjectRuntimeResult(binding,runId) {
  return {schema_version:1,scope:'fox-project-runtime-qa-v1',run_id:runId,status:'RUNNING',started_at:now(),
    application_id:binding.target.target.application_id,target:binding.target,target_receipt_sha256:binding.targetReceiptSha256,
    input_sha256:binding.inputSha256,test_plan:binding.plan,test_plan_sha256:sha256(canonicalQaPlan(binding.plan)),
    credentials_recorded:false,browser_storage_saved:false,human_acceptance_recorded:false,delete_or_reset_performed:false,
    browser_errors:[],network_denials:[],browser_dialogs:[],write_attempts:[],dispatch_state:'PREFLIGHT',
    forms:binding.plan.forms.map(form=>({module_id:form.module_id,status:'NOT_RUN',
      form_binding:Object.fromEntries(Object.entries(form).filter(([key])=>!['cases','row_tracking','edit_field'].includes(key))),
      tests:makeTests(form),additional_checks:optionalChecks()})),final_table_records:{}};
}

/** Verify every observed report page before using a complete-table claim. */
export function validateProjectObservation(observation) {
  check(observation?.observation_scope===PROJECT_OBSERVATION_SCOPE&&Array.isArray(observation.records),'Complete table observation required');
  const keys=observation.records.map(record=>canonicalPrimaryKey(record.primary_key));
  const pagination=observation.pagination;
  check(pagination&&Array.isArray(pagination.page_primary_keys)&&pagination.page_primary_keys.length>0,
    'Measured report pagination is required');
  const flattened=pagination.page_primary_keys.flatMap(page=>{check(Array.isArray(page),'Invalid report page keys');return page;});
  check(samePrimaryKeySet(keys,flattened)&&Number.isSafeInteger(pagination.reported_total_rows)
    &&pagination.reported_total_rows===flattened.length&&pagination.terminal_next_page_enabled===false,
  'Incomplete, duplicate or nonterminal report pagination');
  return keys;
}

function assertContext(context,form,app,kind) {
  const expected={application_id:app,page_id:form[kind==='report'?'report_page_id':'form_page_id'],
    page_item_names:kind==='report'?[]:form.items.map(item=>item.item)};
  check(same(context,expected),'Observed rendered application, page or full item set differs from the mapped module');
  return context;
}

export async function executeProjectCases(binding,driver,result,{persist=async()=>{},beginAttempt=async()=>{}}={}) {
  const {project,plan,accounts}=binding,app=binding.target.target.application_id;
  let ledger=createProjectRowLedger(project,plan),attemptStarted=false;
  const persistResult=async()=>persist(result);
  const guard=()=>check(result.browser_errors.length===0&&result.network_denials.length===0
    &&!driver.hasUnexpectedDialog(),'Unsafe browser state; no further business write is allowed');
  const identities=[accounts.primary,accounts.secondary].map(account=>sha256(account.username.trim().toLowerCase()));
  check(accounts.twoIndependentAccounts&&new Set(identities).size===2,'Two independent QA accounts are required');
  try {
    await driver.start();
    for(let index=0;index<plan.forms.length;index++) {
      const form=plan.forms[index],native=project.forms[index].native_form,receipt=result.forms[index];
      receipt.started_at=now();receipt.status='RUNNING';await persistResult();
      let retainedKey=null,expectedValues=deriveNativeQaValues(native,'create');
      const baseline=structuredClone(ledger.tables[form.table_name]);
      receipt.row_tracking={mode:'retained_table_baseline_then_observed_pk',observation_scope:PROJECT_OBSERVATION_SCOPE,
        baseline_records:baseline,pk_set_checks:[]};
      const context=async(state,kind)=>assertContext(await driver.context(state,form,kind),form,app,kind);
      const values=phase=>deriveNativeQaValues(native,phase);
      const observedRecord=(observation,key=retainedKey)=>{
        const matches=observation.records.filter(row=>row.primary_key===key);
        check(matches.length===1,'Retained row is missing or duplicated');return matches[0];
      };
      const assertValues=(record,expected)=>check(same(record.values,expected),'Fresh readback differs from every intended field value');
      async function observe(testName,fieldName=null,{newRow=false}={}) {
        guard();const observation=await driver.observeTable('primary',form,native);
        const keys=validateProjectObservation(observation),baselineKeys=baseline.map(row=>row.primary_key);
        for(const row of baseline)check(same(observedRecord(observation,row.primary_key),row),'A prior form row changed or disappeared');
        if(newRow) {
          const created=keys.filter(key=>!baselineKeys.includes(key));
          check(created.length===1&&keys.length===baselineKeys.length+1,'Create did not produce exactly one new identity');
          retainedKey=created[0];receipt.row_tracking.retained_primary_key={name:form.primary_key.name,value:retainedKey};
        }
        check(samePrimaryKeySet(keys,retainedKey?[...baselineKeys,retainedKey]:baselineKeys),'Unexpected insert or deletion changed the retained row set');
        if(retainedKey)assertValues(observedRecord(observation),expectedValues);
        receipt.row_tracking.pk_set_checks.push({test_name:testName,field_name:fieldName,observed_primary_keys:keys,
          observation_scope:PROJECT_OBSERVATION_SCOPE,pagination:observation.pagination});
        await persistResult();return observation;
      }
      async function write(state,button,intended) {
        guard();await context(state,'form');
        if(!attemptStarted){await beginAttempt();attemptStarted=true;result.dispatch_state='ATTEMPT_STARTED';await persistResult();}
        // Driver rechecks the actual PK and every intended input immediately
        // before its single click. No failed/uncertain submission is retried.
        await driver.submit(state,form,button,intended,button==='Create'?null:retainedKey,async measured=>{
          guard();result.write_attempts.push({sequence:result.write_attempts.length+1,module_id:form.module_id,
            button,primary_key:{name:form.primary_key.name,value:button==='Create'?null:retainedKey},
            intended_values:measured,submitted_at:now(),outcome:'Inspect fresh readback; never replay an uncertain attempt'});
          await persistResult();guard();
        });
      }
      async function run(name,fn) {
        const entry=receipt.tests.find(item=>item.name===name);
        if(!entry.applicable)return;
        entry.started_at=now();
        try {guard();entry.evidence=await fn();guard();entry.status='PASSED';delete entry.reason;
          entry.field_results=entry.field_names.map(field_name=>({field_name,status:'PASSED'}));
        } catch(error) {entry.status='FAILED';entry.reason=driver.redact(error);throw error;}
        finally {entry.finished_at=now();await persistResult();}
      }
      await run('login',async()=>{
        await driver.navigate('primary',form);const report=await context('primary','report');
        await driver.createPage('primary',form);const edit=await context('primary','form');
        await driver.cancel('primary',form);
        return {authenticated:true,rendered_application_id:report.application_id,report_page_id:report.page_id,
          form_page_id:edit.page_id,navigation_module_id:form.module_id,rendered_contexts:[report,edit]};
      });
      const initial=await observe('preflight');
      assertProjectFormBaseline(ledger,project,plan,form.module_id,initial);
      receipt.row_tracking.baseline_records=initial.records;receipt.row_tracking.baseline_pagination=initial.pagination;
      await run('create',async()=>{
        await driver.createPage('primary',form);const rendered=await context('primary','form');
        const attempted=await driver.fill('primary',form,values('create'));
        check(same(attempted,values('create')),'Created input differs from the deterministic intended values');
        await write('primary','Create',attempted);const returned=await driver.saved('primary',form);
        assertContext(returned,form,app,'report');const observation=await observe('create',null,{newRow:true});
        return {rendered_contexts:[rendered],attempted_values:attempted,action:'CREATE',returned_report_page_id:returned.page_id,
          observed_record:observedRecord(observation)};
      });
      for(const [name,key] of [['search_positive',()=>retainedKey],['search_negative',()=> '0']])await run(name,async()=>{
        const observation=await driver.search('primary',form,native,key());
        check(samePrimaryKeySet(observation.primary_keys,name==='search_positive'?[retainedKey]:[]),'Exact-key search returned unexpected rows');
        return {rendered_contexts:[assertContext(observation.context,form,app,'report')],filter_column:form.primary_key.name,
          filter_value:key(),observed_primary_keys:observation.primary_keys};
      });
      await run('reread',async()=>{
        await driver.openRecord('primary',form,native,retainedKey);const rendered=await context('primary','form');
        const record=await driver.readRecord('primary',form,native);assertValues(record,expectedValues);
        await driver.cancel('primary',form);await observe('reread');
        return {rendered_contexts:[rendered],observed_record:record};
      });
      for(const name of ['edit_save','cancel_edit','cancel_create'])await run(name,async()=>{
        if(name==='cancel_create')await driver.createPage('primary',form);
        else await driver.openRecord('primary',form,native,retainedKey);
        const rendered=await context('primary','form'),attempted=await driver.fill('primary',form,values(name==='edit_save'?'edit':name));
        check(same(attempted,values(name==='edit_save'?'edit':name)),'Edited input differs from the deterministic intended values');
        let returned;
        if(name==='edit_save'){await write('primary','Save Changes',attempted);returned=await driver.saved('primary',form);expectedValues=values('edit');}
        else returned=await driver.cancel('primary',form);
        assertContext(returned,form,app,'report');const observation=await observe(name);
        return {rendered_contexts:[rendered],attempted_values:attempted,action:name==='edit_save'?'SAVE':'CANCEL',
          returned_report_page_id:returned.page_id,observed_record:observedRecord(observation)};
      });
      for(const name of ['required_fields','invalid_number','invalid_date','maximum_length'])await run(name,async()=>{
        const fieldObservations=[];let rendered;
        for(const fieldName of receipt.tests.find(item=>item.name===name).field_names) {
          await driver.openRecord('primary',form,native,retainedKey);const observedContext=await context('primary','form');
          if(rendered)check(same(rendered,observedContext),'Conditional case changed module surface');else rendered=observedContext;
          const column=native.columns.find(item=>item.name===fieldName);
          const attempted=name==='maximum_length'?'X'.repeat(column.length+1):{required_fields:'',invalid_number:'not-a-number',invalid_date:'not-a-date'}[name];
          const actual=await driver.probe('primary',form,column,attempted,name);
          let rejected=false;
          if(name!=='maximum_length'||actual===attempted){
            check(actual===attempted,'Invalid input was transformed; the required validation is not proven');
            await write('primary','Save Changes',{...expectedValues,[fieldName]:actual});
            rejected=await driver.rejected('primary',form);check(rejected===true,'No visible validation feedback');
          }else check(actual==='X'.repeat(column.length),'Maximum-length input was unexpectedly transformed');
          await driver.cancel('primary',form);const observation=await observe(name,fieldName);
          fieldObservations.push({field_name:fieldName,item_name:form.item_prefix+fieldName,attempted_value:attempted,
            persisted_value:observedRecord(observation).values[fieldName],validation_message_visible:rejected,
            ...(name==='maximum_length'?{declared_limit:column.length,observed_input_value:actual}:{})});
        }
        return {rendered_contexts:[rendered],field_observations:fieldObservations};
      });
      await run('concurrent_edit',async()=>{
        await driver.navigate('secondary',form);
        await driver.openRecord('primary',form,native,retainedKey);await driver.openRecord('secondary',form,native,retainedKey);
        const contexts=[await context('primary','form'),await context('secondary','form')];
        assertValues(await driver.readRecord('primary',form,native),expectedValues);
        assertValues(await driver.readRecord('secondary',form,native),expectedValues);
        const winner={...expectedValues,[form.edit_field]:values('winner')[form.edit_field]};
        const stale={...expectedValues,[form.edit_field]:values('stale')[form.edit_field]};
        await driver.fill('primary',form,winner);await write('primary','Save Changes',winner);
        await driver.saved('primary',form);expectedValues=winner;
        await driver.fill('secondary',form,stale);await write('secondary','Save Changes',stale);
        check(await driver.rejected('secondary',form,{stale:true})===true,'Stale writer was not visibly rejected');
        await driver.cancel('secondary',form);const observation=await observe('concurrent_edit');
        return {rendered_contexts:contexts,field:form.edit_field,independent_browser_contexts:2,
          account_identity_sha256:identities,account_contexts:identities.map((account_identity_sha256,i)=>({account_identity_sha256,rendered_context:contexts[i]})),
          attempted_stale_value:stale[form.edit_field],stale_writer_rejected:true,observed_record:observedRecord(observation)};
      });
      const final=await observe('final');receipt.row_tracking.final_records=final.records;receipt.row_tracking.final_pagination=final.pagination;
      ledger=retainProjectFormRow(ledger,project,plan,form.module_id,{observation_scope:PROJECT_OBSERVATION_SCOPE,
        baseline_records:initial.records,retained_primary_key:receipt.row_tracking.retained_primary_key,final_records:final.records});
      await run('browser_runtime_errors',async()=>{
        await driver.navigate('primary',form);const rendered=await context('primary','report');guard();
        return {rendered_contexts:[rendered],unhandled_error_count:result.browser_errors.length};
      });
      receipt.status=outcomeV2(receipt.tests,form);check(receipt.status==='PASSED','Project form coverage is incomplete');
      receipt.finished_at=now();await persistResult();
    }
    // Re-observe every physical table after all forms; the ledger itself is
    // never substituted for this final measured readback.
    for(const table of plan.tables) {
      const index=plan.forms.findIndex(form=>form.table_name===table.table_name),form=plan.forms[index];
      const observed=await driver.observeTable('primary',form,project.forms[index].native_form);validateProjectObservation(observed);
      const sort=records=>[...records].sort((a,b)=>a.primary_key.localeCompare(b.primary_key));
      check(same(sort(observed.records),sort(ledger.tables[table.table_name])),'Final physical table differs from the retained ledger');
      result.final_table_records[table.table_name]=observed.records;
    }
    guard();result.status='PASSED';result.dispatch_state='ATTEMPT_COMPLETED';
  } catch(error) {
    result.status='FAILED';result.failure=driver.redact(error);
    result.dispatch_state=attemptStarted?'ATTEMPT_INCOMPLETE':'PREFLIGHT_BLOCKED';
    const active=result.forms.find(form=>form.status==='RUNNING');
    if(active){active.status='FAILED';active.finished_at=now();}
  } finally {
    result.finished_at=now();
    // A full disk or failed durable write must not leak authenticated sessions.
    try{await persistResult();}finally{await driver.close();}
  }
  return result;
}
