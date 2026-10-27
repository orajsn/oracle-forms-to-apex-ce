import pytest
from forms2apex.starter import TEMPLATE_ID, template_files, render_prototype_html, merge_template

def test_preserves_apex_scaffolding():
    overlay=render_prototype_html(TEMPLATE_ID,'<table><tr><td>Synthetic 1</td></tr></table>')
    page=overlay['pages/p00001-home.apx']
    assert page.rstrip().endswith(')')
    assert page.count('```')==2
    files=merge_template(TEMPLATE_ID,overlay)
    assert files['shared-components/authentications.apx']==template_files()['shared-components/authentications.apx']
    assert 'supporting-objects/deinstall-script.sql' in files
    assert 'shared-components/static-files.apx' not in files

@pytest.mark.parametrize('html',['```\n)','<script src="https://example.invalid/x.js"></script>','<iframe src="/x"></iframe>','<script>fetch("/x")</script>'])
def test_blocks_template_and_network_escape(html):
    with pytest.raises(ValueError): render_prototype_html(TEMPLATE_ID,html)
