"""Keep v3 mapper unchanged; add only a partition-aware independent reviewer."""
from copy import deepcopy
from pathlib import Path
from deployment import forms_understanding_profiles as base
from deployment.forms_understanding_profiles_v3 import build_candidates as build_v3


def build_candidates():
    result = deepcopy(build_v3())
    result['scope'] = 'fox-forms-understanding-candidates-v4'
    candidate = result['candidates']['reviewer43']
    old_name = candidate['header']['name']
    name = 'JSNFOXG2Understandingv4PartitionReview43'
    candidate['header'].update(name=name, description='Independent non-executable partition review; full application coverage remains a separate merge gate.')
    graph = candidate['graph']
    replacements = {node['id']: node['id'].replace('g2-v3-', 'g2-v4-', 1) for node in graph['nodes']}
    for node in graph['nodes']:
        node['id'] = replacements[node['id']]
        node['data']['title'] = node['data']['title'].replace(old_name, name)
    for edge in graph['edges']:
        edge['id'] = edge['id'].replace('g2-v3-', 'g2-v4-', 1)
        for endpoint in ('source', 'target'):
            edge[endpoint] = replacements[edge[endpoint]]
            edge[endpoint+'Handle'] = edge['data'][endpoint+'HandleId']+'-'+edge[endpoint]
    raw = (Path(__file__).resolve().parent/'prompts/forms-understanding-review-v4.txt').read_bytes()
    prompt = raw.decode('utf-8')
    if prompt.count('{{request}}') != 1:
        raise ValueError('Exactly one reviewer request slot is required.')
    graph['nodes'][1]['data']['template']['prompt']['value'] = prompt
    base._check_graph(graph)
    candidate.update(prompt_sha256=base._sha(raw), header_sha256=base._sha(base._canonical(candidate['header'])),
                     graph_sha256=base._sha(base._canonical(graph)))
    return result
