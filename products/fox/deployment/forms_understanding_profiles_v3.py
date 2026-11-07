"""Two additive tool-free roles clarifying analysis versus executable generation."""
from copy import deepcopy
from pathlib import Path
from deployment import forms_understanding_profiles as base

ROOT = Path(__file__).resolve().parent
ROLES = {
    'baseline43': ('JSNFOXG2Understandingv3Baseline43', 'JSN Forms Converter 4.3', 'understanding'),
    'reviewer43': ('JSNFOXG2Understandingv3IndependentReview43', 'JSN Forms Reviewer', 'review'),
}


def build_candidates():
    candidates = {}
    for key, (name, connection, kind) in ROLES.items():
        template, template_sha = base._template(kind)
        filename = 'forms-understanding-v3.txt' if kind == 'understanding' else 'forms-understanding-review-v3.txt'
        raw = (ROOT / 'prompts' / filename).read_bytes()
        prompt = raw.decode('utf-8')
        if prompt.count('{{request}}') != 1 or not prompt.strip():
            raise ValueError('Exactly one request slot is required.')
        graph = deepcopy(template['data'])
        replacements = {node['id']: 'g2-v3-'+key+'-'+stage for node, stage in
                        zip(graph['nodes'], ('input', 'prompt', 'llm', 'output'))}
        for node in graph['nodes']:
            node['id'] = replacements[node['id']]
            node['data']['title'] = name+': '+node['data']['type']
            node['data']['description'] = 'Non-executing source-bound analysis; no runtime or acceptance authority.'
        for index, edge in enumerate(graph['edges']):
            edge['id'] = 'g2-v3-'+key+'-edge-'+str(index+1)
            for endpoint in ('source', 'target'):
                edge[endpoint] = replacements[edge[endpoint]]
                edge[endpoint+'Handle'] = edge['data'][endpoint+'HandleId']+'-'+edge[endpoint]
        graph['nodes'][1]['data']['template']['prompt']['value'] = prompt
        graph['nodes'][2]['data']['template']['llmToUse']['value'] = connection
        graph['nodes'][2]['data']['template']['temperature']['value'] = 0
        base._check_graph(graph)
        header = {field: template[field] for field in base._HEADERS}
        header.update(name=name, description='Versioned non-executable Forms analysis/review; complete ownership and explicit behavior interpretation without runtime authority.')
        candidates[key] = {'header': header, 'graph': graph, 'connection_name': connection,
                           'source_template_sha256': template_sha, 'prompt_sha256': base._sha(raw),
                           'header_sha256': base._sha(base._canonical(header)),
                           'graph_sha256': base._sha(base._canonical(graph))}
    return {'schema_version': 1, 'scope': 'fox-forms-understanding-candidates-v3',
            'profile_activation': False, 'model_invocation': False, 'candidates': candidates}
