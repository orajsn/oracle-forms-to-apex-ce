"""Accepted source bytes survive staging, inventory and offline provenance."""
import hashlib
import json

import pytest

from forms2apex.fox_gateway import stage_snapshot
from forms2apex.forms_inventory import inspect_intake
from forms2apex.clean_package import _source_identity, PackageValidationError


@pytest.mark.parametrize('bom',[False,True],ids=['utf8','utf8-bom'])
@pytest.mark.parametrize('newline',['\n','\r\n'],ids=['lf','crlf'])
def test_exact_source_encoding_round_trips_through_inventory(tmp_path,bom,newline):
    text=newline.join(['<FormModule Name="SYNTHETIC">','  <Block Name="TEST"/>','</FormModule>',''])
    raw=(b'\xef\xbb\xbf' if bom else b'')+text.encode('utf-8')
    digest=hashlib.sha256(raw).hexdigest()
    source_hash=hashlib.sha256(('source.xml:'+digest).encode()).hexdigest()
    job_id='fox-'+'a'*20
    stage_snapshot(tmp_path,job_id,{'source_hash':source_hash,
        'files':[{'name':'source.xml','text':raw.decode('utf-8-sig'),'sha256':digest}]})
    job=tmp_path/job_id
    assert (job/'intake/source.xml').read_bytes()==raw
    inventory=inspect_intake(job)
    module=inventory['modules'][0]
    assert module['readable_source']==text
    assert module['bytes']==len(raw) and module['sha256']==digest
    # JSON persistence must not normalize line endings in the source value.
    restored=json.loads(json.dumps(inventory,ensure_ascii=False))
    assert restored['modules'][0]['readable_source']==text
    assert _source_identity(restored)==source_hash


def test_normalized_newlines_cannot_match_original_crlf_source(tmp_path):
    raw=b'<FormModule Name="SYNTHETIC">\r\n<Block Name="TEST"/>\r\n</FormModule>\r\n'
    digest=hashlib.sha256(raw).hexdigest()
    source_hash=hashlib.sha256(('source.xml:'+digest).encode()).hexdigest()
    job_id='fox-'+'b'*20
    stage_snapshot(tmp_path,job_id,{'source_hash':source_hash,
        'files':[{'name':'source.xml','text':raw.decode(),'sha256':digest}]})
    inventory=inspect_intake(tmp_path/job_id)
    inventory['modules'][0]['readable_source']=inventory['modules'][0]['readable_source'].replace('\r\n','\n')
    with pytest.raises(PackageValidationError):_source_identity(inventory)
