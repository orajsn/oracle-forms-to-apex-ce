/** Offline G2 evaluation only. Never invokes a provider, imports APEX or accepts
 * business behavior. Facts are labelled by fixture authors, not model outputs.
 *
 * Contract v1: source_binding is hashFormsBenchmarkSource(case.source).
 * objects accounts for every supplied block/item/trigger exactly once with
 * disposition proposed|omitted|unresolved and a reason. Blocks also declare their
 * source block_type. Proposed objects name a screen_id; proposed blocks select
 * an allowed native_component. These are proposals, never implementation proof.
 * claims have kind/subject/value, status fact|assumption|unresolved and references.
 * A fact must match a fixture fact_id AND its complete authoritative evidence_refs.
 * Every labelled fact must be acknowledged as fact or explicitly unresolved.
 * Assumptions reference a fixture-allowed assumption_id; unknowns need a reason.
 * gaps account for every fixture gap with matching kind/subject and a reason.
 * screens, relationships, actions, assumptions and questions are explicit arrays.
 * Relationships/actions point to claims; they cannot smuggle in free-form facts.
 * Prototype assumptions are explicitly scoped; no user approval is inferred.
 * Optional telemetry accepts only {provenance:'measured',receipt_id,...metrics};
 * no missing latency/token/repair values are estimated or filled with zeroes.
 */
import {createHash} from 'node:crypto';

export const FORMS_BLUEPRINT_EVALUATION_SCOPE = 'fox-offline-blueprint-evaluation-v1';
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const ordered = value => Array.isArray(value) ? value.map(ordered) : record(value)
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key,ordered(value[key])])) : value;
const canonical = value => JSON.stringify(ordered(value));
const same = (a,b) => canonical(a) === canonical(b);
export const hashFormsBenchmarkSource = source => createHash('sha256').update(canonical(source)).digest('hex');

export function evaluateFormsBlueprint(fixture, blueprint, telemetry) {
  // A broken author contract is an evaluator error, not a scored model failure.
  if (!record(fixture?.source) || !Array.isArray(fixture.source.objects)
      || !Array.isArray(fixture.source.facts) || !Array.isArray(fixture.source.gaps)
      || !record(fixture.allowed_components) || !Array.isArray(fixture.allowed_assumptions)) {
    throw new TypeError('Expected a labelled synthetic benchmark case');
  }
  const issues = [];
  const fail = (code,ref) => issues.push({code,ref});
  const expectedObjects = new Map(fixture.source.objects.map(obj => [obj.id,obj]));
  const facts = new Map(fixture.source.facts.map(fact => [fact.id,fact]));
  const expectedGaps = new Map(fixture.source.gaps.map(gap => [gap.id,gap]));
  const sourceRefs = new Set([...expectedObjects.keys(),...fixture.source.snippets.map(src => src.id)]);
  const b = record(blueprint) ? blueprint : {};
  if (b.schema_version !== 1) fail('blueprint-version','schema_version');
  if (b.source_binding !== hashFormsBenchmarkSource(fixture.source)) fail('stale-or-unbound-source','source_binding');
  const arrays = {};
  for (const key of ['objects','claims','gaps','screens','relationships','actions','assumptions','questions']) {
    arrays[key] = Array.isArray(b[key]) ? b[key] : [];
    if (!Array.isArray(b[key])) fail('missing-structure',key);
  }
  const index = (rows,type) => {
    const map = new Map();
    for (const row of rows) {
      if (!record(row) || !nonempty(row.id)) { fail('invalid-entry',type); continue; }
      if (map.has(row.id)) { fail('duplicate-entry',`${type}:${row.id}`); continue; }
      map.set(row.id,row);
    }
    return map;
  };
  const screens = index(arrays.screens,'screens');
  for (const screen of screens.values()) {
    if (!nonempty(screen.title)) fail('screen-title',screen.id);
  }
  const assumptions = index(arrays.assumptions,'assumptions');
  for (const assumption of assumptions.values()) {
    if (!fixture.allowed_assumptions.includes(assumption.id)
        || assumption.scope !== 'prototype-only' || !nonempty(assumption.reason)) {
      fail('undeclared-prototype-assumption',assumption.id);
    }
  }
  const objects = index(arrays.objects,'objects');
  for (const [id,obj] of objects) {
    const expected = expectedObjects.get(id);
    if (!expected) { fail('unknown-source-object',id); continue; }
    if (!['proposed','omitted','unresolved'].includes(obj.disposition) || !nonempty(obj.reason)) fail('invalid-disposition',id);
    if (obj.kind !== expected.kind) fail('object-kind',id);
    if (expected.kind === 'block' && obj.block_type !== expected.block_type) fail('control-data-confusion',id);
    if (obj.disposition === 'proposed') {
      if (!screens.has(obj.screen_id)) fail('unknown-screen',id);
      if (expected.kind === 'block' && !fixture.allowed_components[expected.block_type]?.includes(obj.native_component)) {
        fail('unsupported-native-mapping',id);
      }
    }
  }
  for (const id of expectedObjects.keys()) if (!objects.has(id)) fail('unaccounted-source-object',id);
  const claims = index(arrays.claims,'claims'), acknowledgedFacts = new Set();
  let inventedFacts = 0, validFacts = 0;
  for (const [id,claim] of claims) {
    if (!sourceRefs.has(claim.subject) || !nonempty(claim.kind) || !Object.hasOwn(claim,'value')) fail('invalid-claim',id);
    if (claim.status === 'fact') {
      const fact = facts.get(claim.fact_id);
      if (!fact || !same([claim.kind,claim.subject,claim.value],[fact.kind,fact.subject,fact.value])
          || !Array.isArray(claim.evidence_refs)
          || !same([...claim.evidence_refs].sort(),[...fact.evidence_refs].sort())
          || claim.evidence_refs.some(ref => !sourceRefs.has(ref))) {
        inventedFacts++; fail('unsupported-fact',id);
      } else { validFacts++; acknowledgedFacts.add(claim.fact_id); }
    } else if (claim.status === 'assumption') {
      if (!assumptions.has(claim.assumption_id) || !nonempty(claim.reason)) fail('unlabelled-assumption',id);
    } else if (claim.status !== 'unresolved' || !nonempty(claim.reason)) fail('invalid-claim-status',id);
    else if (claim.fact_id !== undefined) {
      const fact = facts.get(claim.fact_id);
      if (!fact || !same([claim.kind,claim.subject,claim.value],[fact.kind,fact.subject,fact.value])) fail('invalid-fact-disposition',id);
      else acknowledgedFacts.add(claim.fact_id);
    }
  }
  for (const id of facts.keys()) if (!acknowledgedFacts.has(id)) fail('unaccounted-source-fact',id);
  const gaps = index(arrays.gaps,'gaps');
  for (const [id,gap] of gaps) {
    const expected = expectedGaps.get(id);
    if (!expected || gap.kind !== expected.kind || gap.subject !== expected.subject || !nonempty(gap.reason)) fail('invalid-gap',id);
  }
  for (const id of expectedGaps.keys()) if (!gaps.has(id)) fail('unreported-gap',id);
  for (const type of ['relationships','actions']) {
    for (const row of index(arrays[type],type).values()) {
      if (!Array.isArray(row.claim_ids) || row.claim_ids.length === 0
          || row.claim_ids.some(id => !claims.has(id))) fail('unbound-design-reference',row.id);
    }
  }
  for (const question of index(arrays.questions,'questions').values()) {
    if (!sourceRefs.has(question.subject) || !nonempty(question.text)) fail('unbound-question',question.id);
  }
  let measured = null;
  if (telemetry !== undefined) {
    const metrics = ['latency_ms','input_tokens','output_tokens','repair_attempts'];
    const keys = record(telemetry) ? Object.keys(telemetry) : [];
    const supplied = metrics.filter(key => Object.hasOwn(telemetry ?? {},key));
    if (!record(telemetry) || telemetry.provenance !== 'measured' || !nonempty(telemetry.receipt_id)
        || supplied.length === 0 || keys.some(key => !['provenance','receipt_id',...metrics].includes(key))
        || supplied.some(key => !Number.isFinite(telemetry[key]) || telemetry[key] < 0
          || (key !== 'latency_ms' && !Number.isInteger(telemetry[key])))) {
      fail('invalid-measurement','telemetry');
    } else measured = {...telemetry};
  }
  const accounted = [...expectedObjects.keys()].filter(id => objects.has(id)).length;
  const reportedGaps = [...expectedGaps.keys()].filter(id => gaps.has(id)).length;
  const blockCount = fixture.source.objects.filter(obj => obj.kind === 'block').length;
  const supportedMappings = [...objects.values()].filter(obj => {
    const expected = expectedObjects.get(obj.id);
    return expected?.kind === 'block' && expected.block_type === obj.block_type && obj.disposition === 'proposed'
      && screens.has(obj.screen_id) && fixture.allowed_components[expected.block_type]?.includes(obj.native_component);
  }).length;
  const factClaims = arrays.claims.filter(claim => claim?.status === 'fact').length;
  return {
    schema_version:1,scope:FORMS_BLUEPRINT_EVALUATION_SCOPE,case_id:fixture.id,
    passed:issues.length === 0,issues,
    metrics:{source_objects:expectedObjects.size,accounted_objects:accounted,
      object_coverage:expectedObjects.size ? accounted/expectedObjects.size : null,
      required_gaps:expectedGaps.size,reported_gaps:reportedGaps,
      fact_claims:factClaims,
      supported_fact_claims:validFacts,invented_fact_claims:inventedFacts,
      invented_fact_rate:factClaims ? inventedFacts/factClaims : null,
      labelled_facts:facts.size,acknowledged_facts:acknowledgedFacts.size,
      source_blocks:blockCount,supported_native_mapping_proposals:supportedMappings,
      native_mapping_proposal_coverage:blockCount ? supportedMappings/blockCount : null,
      proposed_blocks:[...objects.values()].filter(obj => expectedObjects.get(obj.id)?.kind === 'block' && obj.disposition === 'proposed').length,
      omitted_objects:[...objects.values()].filter(obj => obj.disposition === 'omitted').length,
      unresolved_objects:[...objects.values()].filter(obj => obj.disposition === 'unresolved').length},
    measured,
    evidence_level:'offline-structured-fixture-only',
    business_correctness_verified:false,native_apex_validity_verified:false,
    provider_connection_verified:false,model_winner:null,
  };
}
