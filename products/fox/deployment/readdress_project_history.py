"""Package unchanged retired ancestry for a new destination, never retire a producer.

This is an offline artifact transformation. The current installation pins the
parent archive; all historical source/proof checks remain real. Old bytes are
preserved, including the original attestation and destination. Fresh current-
operator exclusion, journal preservation and cutover are separate requirements.
"""
from copy import deepcopy
from datetime import datetime,timezone


def _proposal(installation_raw,installation_sha256,attestation_raw,members,manifest_raw,configuration_raw):
    from qa.operator import hosted_service as service,retirement_handoff as h,product_queue_transport as bridge
    installation=service.installation_document(installation_raw,expected_sha256=installation_sha256)
    h.need(type(attestation_raw)is bytes and h.sha(attestation_raw)==installation['retirement']['attestation_sha256'],
           'ARCHIVAL_PARENT_ATTESTATION_CHANGED')
    parent=h.parse(attestation_raw)
    h.need(h.canonical(parent)==attestation_raw and type(parent.get('plan'))is dict
           and parent.get('authorized_plan_sha256')==h.sha(h.canonical(parent['plan']))
           and h.utc(parent['issued_at_utc'])<=datetime.now(timezone.utc),
           'ARCHIVAL_PARENT_PLAN_OR_ISSUANCE_CHANGED')
    h.need(type(members)is dict and type(parent.get('inventory'))is dict
           and set(parent['inventory'])==set(members) and 0<len(members)<=4096,
           'ARCHIVAL_PARENT_INVENTORY_CHANGED')
    for name,raw in members.items():
        h.relative(name)
        h.need(type(raw)is bytes and 0<len(raw)<=h.MAX_FILE
               and parent['inventory'][name]=={'sha256':h.sha(raw),'bytes':len(raw)},
               'ARCHIVAL_PARENT_BYTES_CHANGED')
    h.need(sum(map(len,members.values()))<=h.MAX_TOTAL,'ARCHIVAL_PARENT_BOUND_EXCEEDED')
    h.need(h.sha(members['destination/manifest.json'])==installation['release']['sha256']
           and h.sha(members['destination/configuration.json'])==installation['admission']['sha256']
           and parent['plan']['destination']['provider_configuration_sha256']==installation['provider']['sha256'],
           'ARCHIVAL_PARENT_INSTALLATION_DIFFERS')
    old_manifest=bridge.validate_release(h.parse(members['destination/manifest.json']))
    old_configuration=h.parse(members['destination/configuration.json'])
    expected_parent_destination={'release_sha256':installation['release']['sha256'],
        'configuration_sha256':installation['admission']['sha256'],
        'provider_configuration_sha256':installation['provider']['sha256'],
        'infrastructure':old_configuration['infrastructure'],'images':old_manifest['images'],
        'reader_sources':{name:old_manifest['code'][name] for name in h._reader_sources()}}
    h.need(parent['plan']['destination']==expected_parent_destination
           and old_manifest['hosted_runtime_configuration_sha256']==installation['provider']['sha256']
           and old_configuration['current_release_sha256']==installation['release']['sha256']
           and old_configuration['provider_configuration_sha256']==installation['provider']['sha256'],
           'ARCHIVAL_PARENT_DESTINATION_CHANGED')
    historical=[members['source/manifest.json'],members['source/authority-manifest.json'],
        *(members['manifests/'+role+'.json'] for role in h.ROLES),members['destination/manifest.json']]
    destination=h._destination(manifest_raw,configuration_raw,historical)
    plan=deepcopy(parent['plan']);plan['destination']=destination
    plan['archival_readdress']={'scope':'fox-archival-destination-plan-v1',
        'parent_installation_sha256':installation_sha256,'parent_attestation_sha256':h.sha(attestation_raw),
        'parent_release_sha256':installation['release']['sha256'],
        'parent_configuration_sha256':installation['admission']['sha256'],
        'source_checks_reexecuted':False,'current_hosted_retirement_proven':False,
        'deployment_authorized':False,'human_acceptance_recorded':False,'automatic_replay_permitted':False}
    copied=dict(members)
    prefix='provenance/'+h.sha(attestation_raw)
    for suffix,raw in (('installation.json',installation_raw),('attestation.json',attestation_raw),
            ('manifest.json',members['destination/manifest.json']),
            ('configuration.json',members['destination/configuration.json'])):
        name=prefix+'/'+suffix
        h.need(name not in copied,'ARCHIVAL_PROVENANCE_COLLISION')
        copied[name]=raw
    copied['destination/manifest.json']=manifest_raw
    copied['destination/configuration.json']=configuration_raw
    h.need(len(copied)<=4096 and sum(map(len,copied.values()))<=h.MAX_TOTAL,'ARCHIVAL_NEW_BOUND_EXCEEDED')
    return parent,plan,copied


def plan_archive(*,installation_raw,installation_sha256,attestation_raw,members,manifest_raw,configuration_raw):
    from qa.operator import retirement_handoff as h
    _,plan,_=_proposal(installation_raw,installation_sha256,attestation_raw,members,manifest_raw,configuration_raw)
    return {'status':'ARCHIVAL_DESTINATION_PROPOSED_NOT_SEALED','plan':plan,
        'plan_sha256':h.sha(h.canonical(plan)),'deployment_authorized':False,'current_hosted_retirement_proven':False}


def seal_archive(*,installation_raw,installation_sha256,attestation_raw,members,manifest_raw,
                 configuration_raw,authorized_plan_sha256,now=None):
    from qa.operator import retirement_handoff as h
    parent,plan,copied=_proposal(installation_raw,installation_sha256,attestation_raw,members,manifest_raw,configuration_raw)
    h.need(type(authorized_plan_sha256)is str and h.SHA.fullmatch(authorized_plan_sha256)
           and h.sha(h.canonical(plan))==authorized_plan_sha256,'ARCHIVAL_EXACT_PLAN_NOT_AUTHORIZED')
    value=deepcopy(parent)
    value.update(plan=plan,authorized_plan_sha256=authorized_plan_sha256,
        issued_at_utc=(now or datetime.now(timezone.utc)).isoformat(),
        inventory={name:{'sha256':h.sha(raw),'bytes':len(raw)} for name,raw in sorted(copied.items())})
    raw=h.canonical(value)
    # Genuine full validation of every original failure/retry/idle transcript,
    # source closure and proof, plus the new release/reader/admission binding.
    h.validate_bundle(raw,copied,expected_attestation_sha256=h.sha(raw),
        expected_release_sha256=plan['destination']['release_sha256'],
        expected_configuration_sha256=plan['destination']['configuration_sha256'])
    h.need(value['history']==parent['history'] and value['original_typed_checks']==parent['original_typed_checks'],
           'ARCHIVAL_SOURCE_FACTS_CHANGED')
    return h.RetirementBundle(raw,tuple(sorted(copied.items())))
