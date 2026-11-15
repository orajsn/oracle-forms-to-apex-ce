/** Native isolated-check QA. Fixed synthetic fixtures; never approval or SQL. */
import {check,sha256,canonicalQaPlan,parseUniqueJson} from './contracts.mjs';

export const COUNT_PROFILE='native-blueprint-prototype-count-guard-v1';
export const COUNT_CHECKS=['count_guard_source_bound_fixture','count_guard_null_rejected',
  'count_guard_zero_rejected','count_guard_positive_passed','count_guard_negative_nonzero_passed',
  'count_guard_unrelated_rows_ignored','count_guard_no_approval_request'];
export const FAILURE='Check blocked: a matching persisted row has a null or zero value. No approval was performed.';
export const SUCCESS='Null/zero check passed for persisted matching rows only. No approval was performed.';
const digest=value=>sha256(canonicalQaPlan(value));
const same=(a,b)=>canonicalQaPlan(a)===canonicalQaPlan(b);

export function consumeCountSubmission(request,intent){
  try{
    if(!intent||intent.submitted||request.method()!=='POST')return false;
    const raw=request.postData();if(typeof raw!=='string'||raw.length>2_000_000)return false;
    const body=new URLSearchParams(raw),chunks=body.getAll('p_json');
    // Oracle APEX 26.1.6 page.js browserSubmit removes ordinary page-item
    // names and appends ordered p_json chunks produced by server.js chunk().
    // There is deliberately no guessed direct-field fallback for this profile.
    if(body.has(intent.key_item)||!chunks.length||chunks.length>250
      ||chunks.some(chunk=>!chunk.length||chunk.length>8000))return false;
    const json=parseUniqueJson(chunks.join('')),items=json?.pageItems?.itemsToSubmit;
    if(!Array.isArray(items))return false;
    const targets=items.filter(item=>item?.n===intent.key_item);
    if(targets.length!==1)return false;
    const target=targets[0];
    if(Object.keys(target).some(key=>!['n','v','ck'].includes(key))
      ||typeof target.v!=='string'||target.v!==intent.key
      ||('ck' in target&&typeof target.ck!=='string'))return false;
    intent.submitted=true;return true;
  }catch{return false;}
}

export function validateCountFixture(packet){
  const s=packet.spec,g=s?.count_guard,b=packet.binding,f=packet.count_guard_fixture;
  check(s?.profile_id===COUNT_PROFILE&&s.schema_version===3&&g?.partial_scope_consent===true
    &&g.policy_id==='forms-null-zero-count-guard-v1'&&g.scope==='isolated_pre_action_validation_only',
    'Source check policy differs');
  check(f&&Object.keys(f).sort().join(',')==='fixture_sql_sha256,plan,plan_sha256,prepared,request_sha256,rows'
    &&f.prepared===true&&/^[a-f0-9]{64}$/.test(f.request_sha256)&&/^[a-f0-9]{64}$/.test(f.fixture_sql_sha256)
    &&digest(f)===b.count_guard_fixture_sha256,'Source check fixture receipt differs');
  const ids=g.source_objects,owner=s.blocks.find(row=>row.source_block_id===ids?.owner_block),
    detail=s.blocks.find(row=>row.source_block_id===ids?.detail_block),
    bind=s.blocks.find(row=>row.source_block_id===ids?.bind_block);
  check(owner&&detail&&bind===owner&&detail!==owner&&owner.classification==='database'
    &&detail.classification==='database','Source check blocks differ');
  const value=detail.fields.find(row=>row.source_item_id===ids.value_item),
    key=detail.fields.find(row=>row.source_item_id===ids.key_item),
    bindField=bind.fields.find(row=>row.source_item_id===ids.bind_item);
  check(value&&key&&bindField&&value!==key&&value.data_type==='NUMBER'
    &&key.data_type===bindField.data_type&&['VARCHAR2','NUMBER'].includes(key.data_type),
    'Source check field types differ');
  const seed=digest([b.job_id,s.project_id,s.source_binding,g]);
  let keys;
  if(key.data_type==='VARCHAR2'){
    check(Number.isSafeInteger(key.length)&&Number.isSafeInteger(bindField.length)
      &&Math.min(key.length,bindField.length)>=16,'Source check marker cannot fit');
    keys=Array.from({length:4},(_,i)=>`FCG${seed.slice(0,12).toUpperCase()}${i}`);
  }else{
    const base=100000000000000n+BigInt(`0x${seed.slice(0,11)}`)*10n;
    keys=Array.from({length:4},(_,i)=>(base+BigInt(i)).toString());
  }
  const page=2*owner.sequence-1,names=['null','zero','positive','negative'],values=[null,0,2,-1];
  const expected={schema_version:1,scope:'fox-count-guard-synthetic-fixture-v1',job_id:b.job_id,
    project_id:s.project_id,source_binding:s.source_binding,rendering_spec_sha256:digest(s),
    source_rule_sha256:g.source_rule_sha256,table_name:detail.table_name,source_block_id:detail.source_block_id,
    key_column:key.name,value_column:value.name,key_type:key.data_type,page_id:page,
    key_item:`P${page}_FOX_COUNT_GUARD_KEY`,request:'FOX_COUNT_GUARD_CHECK',
    other_columns:detail.fields.filter(row=>![key.name,value.name].includes(row.name)).map(row=>row.name),
    cases:names.map((name,i)=>({case:name,key:keys[i],value:values[i],expected_blocked:i<2})),
    data_mode:'synthetic_qa_only',rows_retained:true};
  check(same(f.plan,expected)&&f.plan_sha256===digest(expected),'Source check fixture plan differs');
  check(Array.isArray(f.rows)&&f.rows.length===4&&f.rows.every((row,i)=>row
    &&Object.keys(row).sort().join(',')==='case,primary_key'&&row.case===names[i]
    &&typeof row.primary_key==='string'&&/^[1-9][0-9]{0,37}$/.test(row.primary_key))
    &&new Set(f.rows.map(row=>row.primary_key)).size===4,'Source check fixture row identities differ');
  return {owner,plan:expected,receipt:f};
}

export async function exerciseCountGuard(page,packet,{guard,navigate,identity,account,act,submit,record}){
  const {owner,plan}=validateCountFixture(packet);
  const checks=Object.fromEntries(COUNT_CHECKS.map(name=>[name,false]));
  checks.count_guard_source_bound_fixture=true;
  for(const row of plan.cases){
    guard();await navigate(owner);await identity(plan.page_id);await account();
    const input=page.locator(`[name="${plan.key_item}"]`);
    check(await input.count()===1,'Source check grouping input is missing or ambiguous');
    await act(()=>input.fill(row.key));
    check(await input.inputValue()===row.key,'Source check grouping value changed');
    await record({case:row.case,fixture_sha256:packet.binding.count_guard_fixture_sha256,
      request:plan.request,state:'READ_ONLY_CHECK_ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'});
    await submit(plan.page_id,()=>act(()=>page.getByRole('button',
      {name:'Check null or zero values only',exact:true}).click()),row);
    guard();await identity(plan.page_id);await account();
    const expected=row.expected_blocked?FAILURE:SUCCESS,unexpected=row.expected_blocked?SUCCESS:FAILURE;
    await page.getByText(expected,{exact:true}).waitFor({state:'visible'});
    check(!await page.getByText(unexpected,{exact:true}).isVisible(),'Source check returned conflicting outcomes');
    const errors=await page.locator('.t-Alert--danger:visible,#APEX_ERROR_MESSAGE:visible,.t-Form-error:visible,[aria-invalid="true"]:visible')
      .allTextContents();
    check(errors.every(text=>row.expected_blocked&&text.includes(FAILURE)),
      'Source check returned an unrelated APEX error');
    checks[{null:'count_guard_null_rejected',zero:'count_guard_zero_rejected',
      positive:'count_guard_positive_passed',negative:'count_guard_negative_nonzero_passed'}[row.case]]=true;
  }
  // The positive/negative groups coexisted with both blocking groups. Success
  // therefore also tests that another group's missing/zero rows were not counted.
  checks.count_guard_unrelated_rows_ignored=true;
  // This browser path only submits the generated read-only request. The gateway
  // independently re-reads every fixture column before publishing a final receipt.
  checks.count_guard_no_approval_request=true;
  return checks;
}
