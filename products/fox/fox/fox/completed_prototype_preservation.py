"""Read-only semantic check for retained completed native prototypes.

Only the fully measured technical child imports this module. The protected
queue reader repeats the dependency-bounded projection/tree/database pins.
Never invokes a gateway, browser, model, SQLcl, recovery or state promotion.
"""
from pathlib import Path


def validate_completed_fox(job, target, *, package_raw):
    from .paused_stage_preservation import completed_projection, completed_tree, hashed, need
    from .prototype_download import retained_export_request, validate_generated_package
    from .verification_recovery import _load
    job = Path(job)
    before = completed_tree(job)
    snapshot = _load((job / 'source-snapshot.json').read_bytes(), 20_000_000)
    request, receipt = retained_export_request(job, snapshot, target)
    projection = completed_projection(job)
    need(projection['export_request_sha256'] == hashed(request)
         and projection['package_sha256'] == receipt['package_sha256'], 'INERT_COMPLETED_EXPORT_CHANGED')
    validate_generated_package(package_raw, request=request, export_receipt=receipt)
    need(completed_tree(job) == before, 'INERT_COMPLETED_FOX_CHANGED_DURING_READ')
    return projection
