"""One additive tool-free clause-analysis workflow; no remote actions or activation."""
from copy import deepcopy
from pathlib import Path

from deployment import forms_understanding_profiles as base

ROOT = Path(__file__).resolve().parent
ROLES = {'baseline43': ('JSNFOXClauseAnalysisV1Grok43', 'JSN Forms Converter 4.3')}


def build_candidates():
    template, template_sha = base._template('understanding')
    raw = (ROOT / 'prompts' / 'forms-clause-analysis-v1.txt').read_bytes()
    prompt = raw.decode('utf-8')
    if not prompt.strip() or prompt.count('{{request}}') != 1:
        raise ValueError('Exactly one request slot is required.')
    candidates = {}
    for role, (name, connection) in ROLES.items():
        graph = deepcopy(template['data'])
        replacements = {node['id']: 'clause-v1-' + role + '-' + stage
                        for node, stage in zip(graph['nodes'], ('input', 'prompt', 'llm', 'output'))}
        for node in graph['nodes']:
            node['id'] = replacements[node['id']]
            node['data']['title'] = name + ': ' + node['data']['type']
            node['data']['description'] = 'Clause interpretation only; no execution or acceptance authority.'
        for index, edge in enumerate(graph['edges']):
            edge['id'] = 'clause-v1-' + role + '-edge-' + str(index + 1)
            for endpoint in ('source', 'target'):
                edge[endpoint] = replacements[edge[endpoint]]
                edge[endpoint + 'Handle'] = edge['data'][endpoint + 'HandleId'] + '-' + edge[endpoint]
        graph['nodes'][1]['data']['template']['prompt']['value'] = prompt
        llm = graph['nodes'][2]['data']['template']
        llm['llmToUse']['value'] = connection
        llm['temperature']['value'] = 0
        base._check_graph(graph)
        header = {field: deepcopy(template[field]) for field in base._HEADERS}
        header.update(name=name, description='Literal interpretation of two supplied Forms clauses; tool-free, no generation or acceptance authority.')
        candidates[role] = {'header': header, 'graph': graph, 'connection_name': connection,
                            'source_template_sha256': template_sha, 'prompt_sha256': base._sha(raw),
                            'header_sha256': base._sha(base._canonical(header)),
                            'graph_sha256': base._sha(base._canonical(graph))}
    return {'schema_version': 1, 'scope': 'fox-forms-clause-analysis-candidates-v1',
            'profile_activation': False, 'model_invocation': False, 'candidates': candidates}
