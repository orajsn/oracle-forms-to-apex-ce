"""Synthetic pure DSC evidence only; no provider, database or execution proof."""
from copy import deepcopy
import socket
import subprocess

import pytest

from fox import forms_dsc_identity as dsc
from fox.forms_blueprint import BLUEPRINT_SCOPE
from fox.forms_facts import assess_forms_xml, FORMS_NAMESPACE
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.opaf import canonical_hash


def example(body=None, namespace='', max_owned_objects=32):
    if body is None:
        body = ('<DataSourceColumn DSCName="COL_A"/><DataSourceColumn DSCName="COL_B"/>'
                '<Item Name="FIELD" DatabaseItem="false" ItemType="Text Item"/>'
                '<Trigger Name="T" TriggerText="BEGIN NULL; END;"/>')
    raw = (f'<Module{namespace}><FormModule Name="S"><Block Name="B" DatabaseBlock="false">'
           + body + '</Block></FormModule></Module>').encode()
    docs = [('synthetic.xml', raw)]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=max_owned_objects)
    request = next(row for row in plan['requests'] if any(obj['kind'] == 'DataSourceColumn' for obj in row['owned_objects']))
    candidate = {'focus_id':request['focus_id'], 'focus_binding':request['focus_binding'],
        'blueprint':{'schema_version':1, 'scope':BLUEPRINT_SCOPE, 'source_binding':packet['source_binding'],
        'objects':[{'source_object_id':row['id'], 'disposition':'unresolved',
                    'reason':'OBJECT_NAME_UNAVAILABLE' if row['kind']=='DataSourceColumn' else 'Synthetic unrelated mapping.'}
                   for row in request['owned_objects']],
        **{key:[] for key in ('screens','claims','relationships','actions','questions','assumptions')}}}
    return docs, packet, plan, request, candidate


def test_legacy_bytes_facts_packet_requests_and_source_binding_never_change():
    docs, packet, plan, request, candidate = example()
    originals = deepcopy((docs, packet, plan, request, candidate))
    hashes = [canonical_hash(value) for value in (packet, plan, request, candidate)]
    supplement = dsc.build_identity_supplement(docs)
    projected, receipt = dsc.project_candidate_reasons(docs, request, candidate, supplement)
    assert (docs, packet, plan, request, candidate) == originals
    assert [canonical_hash(value) for value in (packet, plan, request, candidate)] == hashes
    assert local_packet(docs) == packet
    assert build_focus_plan(docs,expected_source_binding=packet['source_binding'],
        approved_chunk_hashes=plan['selected_chunk_hashes'],max_owned_objects=32)==plan
    assert all(row['name'] is None for row in packet['sources'][0]['facts']['objects'] if row['kind']=='DataSourceColumn')
    assert supplement['legacy_source_binding']==projected['blueprint']['source_binding']==packet['source_binding']
    assert receipt['old_candidate_sha256']==hashes[-1]
    raw = b'<Module><FormModule Name="S"><Block Name="B" DatabaseBlock="false"><DataSourceColumn DSCName="ID"/></Block></FormModule></Module>'
    assert local_packet([('dsc.xml',raw)])['source_binding']=='9d5f8cccb53eec23355ae97a7c81e4e893d946517a91110952daf2c41092c140'


@pytest.mark.parametrize('namespace', ['', f' xmlns="{FORMS_NAMESPACE}"'])
def test_exact_source_id_ordinal_location_parent_and_direct_provenance(namespace):
    docs, packet, _, _, _ = example(namespace=namespace)
    supplement=dsc.build_identity_supplement(docs)
    rows=[row for row in packet['sources'][0]['facts']['objects'] if row['kind']=='DataSourceColumn']
    assert supplement['schema_version']==1 and supplement['identity_count']==2
    for source,identity in zip(rows,supplement['identities'],strict=True):
        assert identity['source_object_id']==source['id'] and identity['location']==source['location']
        assert identity['parent_id']==identity['block_id']==source['block_id']
        assert identity['source_sha256']==packet['sources'][0]['source']['sha256']
        assert identity['provenance']=='direct_unqualified' and identity['identity_attribute']=='DSCName'
    assert [row['name'] for row in supplement['identities']]==['COL_A','COL_B']
    assert dsc.validate_identity_supplement(docs,supplement)==supplement
    assert all(supplement['safety'][key] is False for key in ('code_executed','transfer_authorized',
        'model_submission_allowed','native_generation_allowed','review_approved','business_behavior_accepted'))
    assert 'BEGIN' not in str(supplement) and 'TriggerText' not in str(supplement)


def test_forms_element_prefix_and_other_supported_provenance_are_not_identity_aliases():
    raw=(f'<f:FormModule xmlns:f="{FORMS_NAMESPACE}" xmlns:S_default="{FORMS_NAMESPACE}" Name="S">'
         '<f:Block Name="B" S_default:DatabaseBlock="false"><f:DataSourceColumn DSCName="COL"/>'
         '</f:Block></f:FormModule>').encode()
    assert dsc.build_identity_supplement([('prefixed.xml',raw)])['identities'][0]['name']=='COL'


def test_unrelated_unsupported_typed_metadata_is_not_revalidated_or_approved():
    raw=(b'<FormModule Name="S"><Block Name="B" DatabaseBlock="not-a-boolean">'
         b'<DataSourceColumn DSCName="COL" DSCLength="opaque-length"/>'
         b'<Item Name="I" ItemType="Unlisted widget" MaximumLength="not-a-number" DataType="opaque-type"/>'
         b'</Block></FormModule>')
    docs=[('opaque.xml',raw)]
    before=local_packet(docs)
    supplement=dsc.build_identity_supplement(docs)
    assert supplement['identities'][0]['name']=='COL'
    assert supplement['legacy_source_binding']==before['source_binding']
    assert local_packet(docs)==before and before['sources'][0]['facts']['blocks'][0]['classification']=='unknown'
    assert all(value not in str(supplement) for value in ('not-a-boolean','opaque-length','Unlisted widget','not-a-number','opaque-type'))
    assert supplement['safety']['native_generation_allowed'] is False
    assert supplement['safety']['review_approved'] is False


@pytest.mark.parametrize('body',[
    '<DataSourceColumn/>', '<DataSourceColumn Name="COL"/>',
    '<DataSourceColumn Name="COL" DSCName="COL"/>',
    '<DataSourceColumn DSCName="COL"/><DataSourceColumn DSCName="COL"/>',
    '<DataSourceColumn DSCName="COL"/><DataSourceColumn DSCName="col"/>',
    '<DataSourceColumn DSCName="123"/>', '<DataSourceColumn DSCName="bad/name"/>',
    '<DataSourceColumn DSCName=""/>', '<DataSourceColumn DSCName="A&#10;B"/>',
    '<DataSourceColumn DSCName="A&quot;B"/>', '<Item Name="I" DSCName="COL"/>',
    '<Item Name="I"><DataSourceColumn DSCName="COL"/></Item>',
    '<DataSourceColumn xmlns:x="urn:foreign" x:DSCName="COL"/>',
    f'<DataSourceColumn xmlns:x="{FORMS_NAMESPACE}" x:DSCName="COL"/>',
    f'<DataSourceColumn xmlns:S_default="{FORMS_NAMESPACE}" S_default:DSCName="COL"/>',
    f'<DataSourceColumn xmlns:S_overridden="{FORMS_NAMESPACE}" S_overridden:DSCName="COL"/>',
    f'<DataSourceColumn xmlns:UNKNOWN_inherited="{FORMS_NAMESPACE}" UNKNOWN_inherited:DSCName="COL"/>',
    f'<DataSourceColumn xmlns:S_default="{FORMS_NAMESPACE}" DSCName="COL" S_default:DSCName="COL"/>',
    '<x:DataSourceColumn xmlns:x="urn:foreign" DSCName="COL"/>',
    '<x:DataSourceColumn xmlns:x="urn:foreign" Name="COL"/>',
    '<x:DataSourceColumn xmlns:x="urn:foreign"/>',
    f'<DataSourceColumn xmlns:x="urn:foreign" DSCName="COL" x:Name="COL"/>',
    f'<DataSourceColumn xmlns:S_inherited="{FORMS_NAMESPACE}" DSCName="COL" S_inherited:Name="COL"/>',
    '<Coordinate><DataSourceColumn DSCName="COL"/></Coordinate>',
    '<x:Block xmlns:x="urn:foreign"><DataSourceColumn DSCName="COL"/></x:Block>',
])
def test_identity_ambiguities_wrong_kind_foreign_inherited_and_unsafe_refused(body):
    raw=('<FormModule Name="S"><Block Name="B" DatabaseBlock="false">'+body+'</Block></FormModule>').encode()
    with pytest.raises(ValueError,match='outside the exact supported scope'):
        dsc.build_identity_supplement([('invalid.xml',raw)])


def test_same_name_in_different_blocks_is_not_duplicate_same_parent():
    raw=b'<FormModule Name="S"><Block Name="A"><DataSourceColumn DSCName="COL"/></Block><Block Name="B"><DataSourceColumn DSCName="COL"/></Block></FormModule>'
    assert dsc.build_identity_supplement([('two.xml',raw)])['identity_count']==2


def test_non_owned_dsc_references_are_checked_against_the_whole_supplement():
    docs,_,_,request,candidate=example(max_owned_objects=2)
    supplement=dsc.build_identity_supplement(docs)
    owned={row['id'] for row in request['owned_objects']}
    outside=next(row['source_object_id'] for row in supplement['identities'] if row['source_object_id'] not in owned)
    block=next(row['id'] for row in request['owned_objects'] if row['kind']=='Block')
    candidate['blueprint']['questions']=[{'id':'q','source_object_id':block,'text':'Inspect '+outside}]
    with pytest.raises(ValueError):dsc.project_candidate_reasons(docs,request,candidate,supplement)


def test_bounded_source_identity_is_not_promoted_to_a_sql_identifier():
    docs,_,_,_,_=example(body='<DataSourceColumn DSCName="Column Label-1"/>')
    assert dsc.build_identity_supplement(docs)['identities'][0]['name']=='Column Label-1'
    for invalid in (None,7,{},'bad/name'):
        with pytest.raises(ValueError):dsc.projected_reason(invalid)


@pytest.mark.parametrize('reason',sorted(dsc.OLD_REASONS))
def test_projection_changes_only_exact_reasons_and_preserves_all_other_fields(reason):
    docs,_,_,request,candidate=example()
    for row in candidate['blueprint']['objects']:
        if row['reason']=='OBJECT_NAME_UNAVAILABLE':row['reason']=reason
    # Ordinary Item evidence/action, even sharing a DSC technical-name string,
    # is retained, not inferred to be a DSC business relationship.
    item=next(row for row in request['owned_objects'] if row['kind']=='Item')
    candidate['blueprint']['claims']=[{'id':'claim','source_object_id':item['id'],'kind':'behavior.intent',
        'status':'proposal','value':'COL_A','evidence_refs':[item['id']],'reason':'Synthetic Item proposal.'}]
    candidate['blueprint']['actions']=[{'id':'action','claim_ids':['claim']}]
    original=deepcopy(candidate); supplement=dsc.build_identity_supplement(docs)
    projected,receipt=dsc.project_candidate_reasons(docs,request,candidate,supplement)
    restored=deepcopy(projected)
    for before,after in zip(original['blueprint']['objects'],restored['blueprint']['objects'],strict=True):
        assert after['disposition']=='unresolved'
        if before['source_object_id'] in receipt['changed_object_ids']:
            assert after['reason']!=before['reason'] and 'does not implement or render' in after['reason']
            after['reason']=before['reason']
    assert restored==original and candidate==original
    assert receipt['changed_object_count']==2 and receipt['new_independent_review_required'] is True
    assert receipt['old_candidate_sha256']==canonical_hash(original)
    assert receipt['new_candidate_sha256']==canonical_hash(projected)
    assert dsc.validate_candidate_projection(docs,request,candidate,supplement,projected,receipt)==receipt


@pytest.mark.parametrize('change',['disposition','reason','extra-key','claim','claim-value','claim-reason',
                                  'question','assumption','screen','relationship','other-mapping'])
def test_projection_refuses_wider_changes_or_any_dsc_dependency_or_global_prose(change):
    docs,_,_,request,candidate=example(); supplement=dsc.build_identity_supplement(docs)
    ref=supplement['identities'][0]['source_object_id']
    row=next(row for row in candidate['blueprint']['objects'] if row['source_object_id']==ref)
    item=next(row for row in request['owned_objects'] if row['kind']=='Item')
    if change=='disposition':row['disposition']='omitted'
    elif change=='reason':row['reason']='Unknown column; implement it automatically.'
    elif change=='extra-key':row['screen_id']='screen'
    elif change in ('claim','claim-value','claim-reason'):
        claim={'id':'claim','source_object_id':item['id'],'kind':'behavior.intent','status':'proposal',
               'value':'Synthetic Item value.','evidence_refs':[item['id']],'reason':'Synthetic Item proposal.'}
        if change=='claim':claim.update(source_object_id=ref,evidence_refs=[ref])
        elif change=='claim-value':claim['value']=ref
        else:claim['reason']='DSCName requires interpretation.'
        candidate['blueprint']['claims']=[claim]
    elif change=='question':candidate['blueprint']['questions']=[{'id':'q','source_object_id':item['id'],'text':'Column names are missing.'}]
    elif change=='assumption':candidate['blueprint']['assumptions']=[{'id':'a','text':'All identities are unavailable.','scope':'prototype-only'}]
    elif change=='screen':candidate['blueprint']['screens']=[{'id':'s','title':'DataSourceColumn display'}]
    elif change=='relationship':candidate['blueprint']['relationships']=[{'id':ref,'claim_ids':[]}]
    else:
        next(row for row in candidate['blueprint']['objects'] if row['source_object_id']==item['id'])['reason']=ref
    with pytest.raises(ValueError):dsc.project_candidate_reasons(docs,request,candidate,supplement)


def test_reconstruction_rejects_forged_flags_bindings_names_receipts_and_no_aliasing():
    docs,_,_,request,candidate=example();supplement=dsc.build_identity_supplement(docs)
    for change in ('name','flag','binding','location'):
        forged=deepcopy(supplement)
        if change=='name':forged['identities'][0]['name']='INVENTED'
        elif change=='flag':forged['safety']['review_approved']=True
        elif change=='binding':forged['legacy_source_binding']='0'*64
        else:forged['identities'][0]['location']['line']+=1
        with pytest.raises(ValueError):dsc.validate_identity_supplement(docs,forged)
    changed_docs=[(docs[0][0],docs[0][1].replace(b'COL_A',b'OTHER'))]
    with pytest.raises(ValueError):dsc.validate_identity_supplement(changed_docs,supplement)
    changed=deepcopy(request);changed['owned_objects'][0]['name']='INVENTED'
    with pytest.raises(ValueError):dsc.project_candidate_reasons(docs,changed,candidate,supplement)
    projected,receipt=dsc.project_candidate_reasons(docs,request,candidate,supplement)
    tampered=deepcopy(projected);tampered['blueprint']['objects'][0]['reason']='Other text'
    with pytest.raises(ValueError):dsc.validate_candidate_projection(docs,request,candidate,supplement,tampered,receipt)
    forged=deepcopy(receipt);forged['new_independent_review_required']=False
    with pytest.raises(ValueError):dsc.validate_candidate_projection(docs,request,candidate,supplement,projected,forged)
    receipt['safety']['review_approved']=True
    projected['blueprint']['objects'][0]['reason']='Mutated returned copy'
    fresh,new_receipt=dsc.project_candidate_reasons(docs,request,candidate,supplement)
    assert fresh!=projected and new_receipt['safety']['review_approved'] is False
    assert supplement['safety']['review_approved'] is False


def test_no_external_io_and_bounded_malformed_input(monkeypatch):
    def forbidden(*args,**kwargs):raise AssertionError('Pure layer attempted external I/O')
    monkeypatch.setattr(socket,'socket',forbidden);monkeypatch.setattr(subprocess,'Popen',forbidden)
    docs,_,_,request,candidate=example()
    supplement=dsc.build_identity_supplement(docs)
    assert dsc.project_candidate_reasons(docs,request,candidate,supplement)[1]['changed_object_count']==2
    for value in ([],None,[('x.xml',b'<!DOCTYPE x><FormModule Name="S"/>')],[('x.xml',b'x')]):
        with pytest.raises(ValueError):dsc.build_identity_supplement(value)
    cyclic={};cyclic['self']=cyclic
    with pytest.raises(ValueError):dsc.project_candidate_reasons(docs,request,cyclic,supplement)
