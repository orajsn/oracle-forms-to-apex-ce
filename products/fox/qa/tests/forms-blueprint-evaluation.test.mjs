// Authored synthetic expectations only. No provider, browser, Oracle or network.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {evaluateFormsBlueprint,hashFormsBenchmarkSource} from '../lib/forms-blueprint-evaluation.mjs';

const benchmark = JSON.parse(readFileSync(new URL('../fixtures/forms-understanding-benchmark-v1.json',import.meta.url),'utf8'));
const [multi,missing,prototype] = benchmark.cases;
const clone = value => structuredClone(value);

// Mechanical authored reference response. This is not a generated model result.
function response(fixture) {
  return {
    schema_version:1,source_binding:hashFormsBenchmarkSource(fixture.source),
    screens:[{id:'screen:main',title:'Synthetic proposed screen'}],
    objects:fixture.source.objects.map(obj => ({...obj,disposition:obj.kind === 'trigger' ? 'unresolved' : 'proposed',
      reason:obj.kind === 'trigger' ? 'Behavior translation needs independent review.' : 'Proposed screen mapping only.',
      ...(obj.kind !== 'trigger' ? {screen_id:'screen:main'} : {}),
      ...(obj.kind === 'block' ? {native_component:fixture.allowed_components[obj.block_type][0]} : {})})),
    claims:fixture.source.facts.map(fact => ({...clone(fact),id:`claim:${fact.id}`,fact_id:fact.id,status:'fact'})),
    gaps:fixture.source.gaps.map(gap => ({...gap,reason:gap.description})),
    relationships:[],actions:[],assumptions:[],questions:[],
  };
}
function codes(fixture,b,telemetry) {
  return evaluateFormsBlueprint(fixture,b,telemetry).issues.map(issue => issue.code);
}

test('public synthetic cases cover required labels and preserve separate evidence levels',()=>{
  assert.deepEqual(benchmark.candidate_models,['xai.grok-4.7','xai.grok-4.3']);
  const labels = new Set(benchmark.cases.flatMap(fixture => fixture.labels));
  for (const label of ['multi-block','ordinary-business-dml','control-versus-data','missing-ddl','missing-package','prototype','hallucinated-reference']) assert.ok(labels.has(label));
  for (const fixture of benchmark.cases) {
    const b = response(fixture),before = clone(b),result = evaluateFormsBlueprint(fixture,b);
    assert.equal(result.passed,true,JSON.stringify(result.issues));
    assert.equal(result.metrics.object_coverage,1);
    assert.equal(result.metrics.invented_fact_claims,0);
    assert.equal(result.measured,null);
    assert.equal(result.business_correctness_verified,false);
    assert.equal(result.native_apex_validity_verified,false);
    assert.equal(result.provider_connection_verified,false);
    assert.equal(result.model_winner,null);
    assert.deepEqual(b,before);
  }
});

test('all blocks, items and triggers need unique explicit dispositions',()=>{
  for (const obj of multi.source.objects) {
    const b = response(multi);b.objects = b.objects.filter(row => row.id !== obj.id);
    assert.ok(codes(multi,b).includes('unaccounted-source-object'),obj.id);
  }
  const b = response(multi);b.objects.push(clone(b.objects[0]));
  assert.ok(codes(multi,b).includes('duplicate-entry'));
  b.objects[0].disposition = 'converted';
  assert.ok(codes(multi,b).includes('invalid-disposition'));
});

test('control blocks cannot become data tables and unsupported components are rejected',()=>{
  const b = response(multi),control = b.objects.find(obj => obj.id === 'block:FILTER');
  control.block_type = 'data';control.native_component = 'interactive-grid';
  const failures = codes(multi,b);
  assert.ok(failures.includes('control-data-confusion'));
  assert.ok(failures.includes('unsupported-native-mapping'));
});

test('ordinary source DML is evidence, not an automatic blocked assessment',()=>{
  const result = evaluateFormsBlueprint(multi,response(multi));
  assert.equal(result.passed,true);
  assert.equal(result.metrics.supported_fact_claims,3);
  const b = response(multi);b.claims = b.claims.filter(claim => claim.kind !== 'action');
  assert.ok(codes(multi,b).includes('unaccounted-source-fact'));
});

test('keys, tables, routines and relationships cannot be invented as source facts',()=>{
  for (const kind of ['key','table','routine','relationship']) {
    const b = response(missing);
    b.claims.push({id:`invented:${kind}`,kind,subject:'block:REQUESTS',value:'SYN_INVENTED',status:'fact',
      fact_id:'fact:not-supplied',evidence_refs:['src:approve']});
    const result = evaluateFormsBlueprint(missing,b);
    assert.equal(result.passed,false);
    assert.equal(result.metrics.invented_fact_claims,1);
  }
  const b = response(multi);b.claims[0].evidence_refs = ['src:invented'];
  assert.ok(codes(multi,b).includes('unsupported-fact'));
  b.claims[0].evidence_refs = ['src:save'];
  assert.ok(codes(multi,b).includes('unsupported-fact'));
  const forgedKey = response(multi);forgedKey.claims.find(claim => claim.kind === 'key').value = ['SYN_NEW_KEY'];
  assert.ok(codes(multi,forgedKey).includes('unsupported-fact'));
});

test('missing DDL, package spec and body remain separate explicit gaps',()=>{
  for (const gap of missing.source.gaps) {
    const b = response(missing);b.gaps = b.gaps.filter(row => row.id !== gap.id);
    assert.ok(codes(missing,b).includes('unreported-gap'),gap.id);
  }
  const b = response(missing);b.gaps[0].kind = 'converted';
  assert.ok(codes(missing,b).includes('invalid-gap'));
});

test('synthetic prototype assumptions are allowed only with declared labels, never as facts',()=>{
  const b = response(prototype);
  b.assumptions = [{id:'prototype:synthetic-key',scope:'prototype-only',reason:'Synthetic demo identifier, not a source key.'}];
  b.claims = [{id:'claim:demo-key',kind:'key',subject:'block:SCRATCH',value:['DEMO_ID'],status:'assumption',
    assumption_id:'prototype:synthetic-key',reason:'Proposed only; no source DDL exists.'}];
  assert.equal(evaluateFormsBlueprint(prototype,b).passed,true);
  b.claims[0].status = 'fact';
  assert.ok(codes(prototype,b).includes('unsupported-fact'));
  b.claims[0].status = 'assumption';b.assumptions[0].scope = 'approved';
  assert.ok(codes(prototype,b).includes('undeclared-prototype-assumption'));
  b.assumptions = [];
  assert.ok(codes(prototype,b).includes('unlabelled-assumption'));
});

test('source edits including a dependency change invalidate the binding',()=>{
  const b = response(multi),changed = clone(multi);
  changed.source.snippets[0].text += ' -- revised';
  assert.ok(codes(changed,b).includes('stale-or-unbound-source'));
  const dependency = clone(multi);dependency.source.gaps[0].description += ' Revised dependency.';
  assert.ok(codes(dependency,b).includes('stale-or-unbound-source'));
  const reordered = {...multi.source,objects:multi.source.objects};
  assert.equal(hashFormsBenchmarkSource(reordered),hashFormsBenchmarkSource(multi.source));
  b.source_binding = null;
  assert.ok(codes(multi,b).includes('stale-or-unbound-source'));
});

test('missing structure, unknown source objects, screens and design claim links fail closed',()=>{
  for (const key of ['objects','claims','gaps','screens','relationships','actions','assumptions','questions']) {
    const b = response(multi);delete b[key];
    assert.ok(codes(multi,b).includes('missing-structure'),key);
  }
  for (const bad of [null,[],{},'not structured']) assert.equal(evaluateFormsBlueprint(multi,bad).passed,false);
  const b = response(multi);b.objects.push({id:'block:INVENTED',kind:'block',disposition:'proposed',reason:'Fake'});
  b.objects[0].screen_id = 'screen:absent';
  b.relationships = [{id:'rel:fake',claim_ids:['claim:absent']}];
  b.actions = [{id:'action:fake',claim_ids:[]}];
  b.questions = [{id:'question:fake',subject:'item:absent',text:'What is this?'}];
  const failures = codes(multi,b);
  for (const code of ['unknown-source-object','unknown-screen','unbound-design-reference','unbound-question']) assert.ok(failures.includes(code));
});

test('explicit unresolved facts and omissions are not counted as successful mappings',()=>{
  const b = response(multi);
  b.claims[0].status = 'unresolved';b.claims[0].reason = 'Needs review of this extracted source fact.';
  b.objects[0].disposition = 'omitted';b.objects[0].reason = 'Explicitly omitted from this prototype.';
  const result = evaluateFormsBlueprint(multi,b);
  assert.equal(result.passed,true);
  assert.equal(result.metrics.supported_fact_claims,2);
  assert.equal(result.metrics.acknowledged_facts,3);
  assert.equal(result.metrics.omitted_objects,1);
  assert.equal(result.metrics.proposed_blocks,2);
});

test('only supplied measured telemetry is reported, without inference or fabricated zeroes',()=>{
  const b = response(multi),telemetry = {provenance:'measured',receipt_id:'synthetic-test-only',latency_ms:12.5,input_tokens:100};
  const result = evaluateFormsBlueprint(multi,b,telemetry);
  assert.equal(result.passed,true);
  assert.deepEqual(result.measured,telemetry);
  assert.equal(Object.hasOwn(result.measured,'output_tokens'),false);
  for (const invalid of [null,{}, {provenance:'estimated',receipt_id:'x',latency_ms:1},
    {provenance:'measured',latency_ms:1},{...telemetry,input_tokens:-1},{...telemetry,input_tokens:1.2},
    {...telemetry,output_tokens:Infinity},{...telemetry,latency_ms:NaN},{...telemetry,model:'xai.grok-4.7'}]) {
    const bad = evaluateFormsBlueprint(multi,b,invalid);
    assert.ok(bad.issues.some(issue => issue.code === 'invalid-measurement'));
    assert.equal(bad.measured,null);
  }
});
