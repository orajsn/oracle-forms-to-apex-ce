"""SQLcl 26.1.2 generated starter; model output cannot change authentication."""
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).parent / 'templates' / 'starter'
TEMPLATE_ID = 'sqlcl-26.1.2-fox-v1'


def template_files():
    return {p.relative_to(ROOT).as_posix(): p.read_text(encoding='utf-8')
            for p in sorted(ROOT.rglob('*')) if p.is_file() and
            (p.suffix != '.apx' or p.read_text(encoding='utf-8').strip())}


def template_context():
    files = template_files()
    return {'template_id': TEMPLATE_ID,
            'page_example': files['pages/p00001-home.apx'],
            'policy': 'Only pages/p00001-home.apx is replaceable in this first MVP. The complete Oracle-generated starter, authentication and metadata are retained. Return this page in apexlang_files; do not output the entire starter.',
            'sha256': hashlib.sha256(''.join(k+'\n'+v for k,v in files.items()).encode()).hexdigest()}


def merge_template(template_id, generated):
    if template_id != TEMPLATE_ID:
        raise ValueError('Unknown or changed starter template')
    if set(generated) != {'pages/p00001-home.apx'}:
        raise ValueError('The first MVP supports only the reviewed Home page overlay')
    result = template_files()
    result.update(generated)
    return result


def render_prototype_html(template_id, content):
    if template_id != TEMPLATE_ID or not isinstance(content, str) or not content.strip() or len(content)>12000:
        raise ValueError('A reviewed HTML prototype under 12000 characters is required')
    if '```' in content or re.search(r'<\s*(?:iframe|object|embed|form|link|base)\b|<script[^>]+src\s*=|https?://|\b(?:fetch|eval)\s*\(|XMLHttpRequest|document\.cookie', content, re.I):
        raise ValueError('External resources, embedded frames, forms and network scripts are not supported')
    page = template_files()['pages/p00001-home.apx']
    placeholder = '                <p>FOX synthetic prototype. Business validation is required.</p>'
    if page.count(placeholder)!=1:
        raise RuntimeError('Canonical page template changed')
    html = '\n'.join('                '+line for line in content.splitlines())
    return {'pages/p00001-home.apx':page.replace(placeholder,html)}
