"""Content identities for job transitions; not a signature or host-admin boundary."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from .starter import TEMPLATE_ID, template_context
from .native import TEMPLATE_ID as NATIVE_TEMPLATE_ID, context as native_context


def file_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Required evidence file is missing or linked')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError('Required source or draft directory is missing or linked')
    members={}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Linked files are not permitted in frozen evidence')
        if path.is_file():
            members[path.relative_to(root).as_posix()]=file_digest(path)
        elif not path.is_dir():
            raise RuntimeError('Unsupported entry in frozen evidence')
    if not members:
        raise RuntimeError('Frozen evidence cannot be empty')
    return hashlib.sha256(json.dumps(members,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def inspection_binding(root: Path) -> dict:
    return {'intake_sha256':tree_digest(root/'intake'),
            'inventory_sha256':file_digest(root/'normalized-forms-inventory.json'),
            'remediation_sha256':file_digest(root/'migration-and-exception-report.json')}


def draft_binding(root: Path) -> dict:
    spec=json.loads((root/'migration-spec.json').read_text(encoding='utf-8'))
    template_id=spec.get('template_id')
    if template_id == NATIVE_TEMPLATE_ID:
        template=native_context()
    elif template_id == TEMPLATE_ID:
        template=template_context()
    else:
        raise RuntimeError('Unknown template in draft evidence')
    binding={'schema_version':1,'job_id':root.name,**inspection_binding(root),
            'reviewed_spec_sha256':file_digest(root/'migration-spec.json'),
            'template_id':template_id,'template_sha256':template['sha256'],
            'draft_sha256':tree_digest(root/'apexlang'),
            'draft_zip_sha256':file_digest(root/f'{root.name}-apexlang.zip')}
    if template_id==NATIVE_TEMPLATE_ID:
        binding['native_review_sha256']=file_digest(root/'native-review.json')
    return binding


@contextmanager
def draft_snapshot(root: Path, expected_digest: str):
    # SQLcl receives a private copy, not the mutable working directory.
    # Managed workflow transitions are serialized by ConverterWorkflow.
    with tempfile.TemporaryDirectory(prefix='.checked-draft-',dir=root) as temporary:
        snapshot=Path(temporary)/'apexlang'
        shutil.copytree(root/'apexlang',snapshot,symlinks=True)
        if tree_digest(snapshot)!=expected_digest:
            raise RuntimeError('Draft changed while preparing its checked snapshot')
        yield snapshot
