"""Read-only grouping of assessed dependencies; never a conversion decision."""
import hashlib
import json
import re

MAX_REFERENCES=1000
MAX_GROUPS=500
STATES=('MISSING_SOURCE','ROUTINE_UNCONFIRMED','SOURCE_AVAILABLE')


def build_source_requests(plan: dict) -> dict:
    if not (type(plan) is dict and type(plan.get('project_id')) is str
            and all(type(plan.get(k)) is str and re.fullmatch('[a-f0-9]{64}',plan[k])
                    for k in ('source_hash','plan_sha256'))):
        raise ValueError('An assessed project/source plan is required.')
    result={'schema_version':1,'scope':'fox-source-requests-v1',
        **{k:plan[k] for k in ('project_id','source_hash','plan_sha256')},
        'complete':False,'reason':None,'groups':[],'counts':None}
    if plan.get('assessment_complete') is not True:
        return {**result,'reason':'Assessment is incomplete. Review the project findings before requesting more files.'}
    total=sum(len(form['dependencies']) for form in plan['forms'])
    if total>MAX_REFERENCES:
        return {**result,'reason':'The grouped list exceeds its display limit. Individual form findings remain available; no conversion rule was changed.'}
    groups={}
    for form in plan['forms']:
        for index,dep in enumerate(form['dependencies']):
            if dep.get('status') not in ('MISSING','SOURCE_PRESENT'):
                return {**result,'reason':'Some source availability is unconfirmed. Review the individual form findings.'}
            state='MISSING_SOURCE' if dep['status']=='MISSING' else 'ROUTINE_UNCONFIRMED' if dep.get('routine_check')=='NOT_CONFIRMED' else 'SOURCE_AVAILABLE'
            parts=tuple(dep.get('missing_parts',[]))
            key=(dep['kind'],dep['target'],state,parts)
            if key not in groups:
                identity=json.dumps([plan['project_id'],plan['source_hash'],plan['plan_sha256'],key],ensure_ascii=False,separators=(',',':')).encode()
                groups[key]={'id':'req-'+hashlib.sha256(identity).hexdigest()[:24],
                    'kind':dep['kind'],'target':dep['target'],'state':state,'missing_parts':list(parts),
                    'routines':[],'actions':[],'references':[],'form_count':0,'reference_count':0}
            row=groups[key]
            row['references'].append({'module_id':form['module_id'],'dependency_index':index})
            if dep.get('routine') and dep['routine'] not in row['routines']:row['routines'].append(dep['routine'])
            if dep['action'] not in row['actions']:row['actions'].append(dep['action'])
    if len(groups)>MAX_GROUPS:
        return {**result,'reason':'The grouped list exceeds its display limit. Review the individual form findings.'}
    rows=sorted(groups.values(),key=lambda g:(STATES.index(g['state']),g['kind'],g['target'],g['missing_parts']))
    for row in rows:
        row['routines'].sort()
        row['form_count']=len({ref['module_id'] for ref in row['references']})
        row['reference_count']=len(row['references'])
    ready={**result,'complete':True,'groups':rows,'counts':{'groups':len(rows),
        'requests':sum(row['state']!='SOURCE_AVAILABLE' for row in rows),
        'source_available':sum(row['state']=='SOURCE_AVAILABLE' for row in rows),
        'forms':len({ref['module_id'] for row in rows if row['state']!='SOURCE_AVAILABLE' for ref in row['references']}),'references':total}}
    if len(json.dumps(ready,ensure_ascii=False).encode())>128000:
        return {**result,'reason':'The grouped list exceeds its display limit. Individual form findings remain available.'}
    return ready


def request_text(plan:dict,checklist:dict,group_id:str|None=None)->str:
    if not checklist['complete']:
        raise ValueError('A complete grouped request list is not available. Review individual findings.')
    rows=[g for g in checklist['groups'] if g['state']!='SOURCE_AVAILABLE' and (group_id is None or g['id']==group_id)]
    lines=['FOX source requests','Project: '+plan['project_name'],'Source version: '+plan['source_hash'],
        'This requests readable source only. Source availability does not establish converted APEX behavior.','']
    if not rows:lines.append('No outstanding source request groups. Review remaining form findings; this is not conversion readiness.')
    for row in rows:
        lines += [row['target']+' — '+('source missing' if row['state']=='MISSING_SOURCE' else 'routine not confirmed'),
            'Who can help: application owner / DBA',*('Action: '+action for action in row['actions'])]
        for ref in row['references']:
            form=next(f for f in plan['forms'] if f['module_id']==ref['module_id']);dep=form['dependencies'][ref['dependency_index']]
            location=dep.get('source_location',{})
            path=['Form '+form['form_name'],*(label+' '+str(location[k]) for k,label in
                (('block','Block'),('button','Button'),('item','Item'),('trigger','Trigger'),('program_unit','Program')) if location.get(k))]
            lines.append('Caller: '+' → '.join(path)+'; source: '+dep['source']+(('; routine: '+dep['routine']) if dep.get('routine') else ''))
        lines.append('')
    lines.append('Raw FMB/MMB/OLB/PLL stays local and needs supported Oracle preparation. Do not include credentials or production records.')
    return '\n'.join(lines)+'\n'
