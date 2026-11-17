"""Processing eligibility for retained source provenance; no provider consent."""
from . import source_history

DEVELOPMENT_REASON = (
    'Development sources are preserved for review and analysis. '
    'AI conversion for this source mode is not enabled yet; '
    'the existing redacted-source approval does not authorize it.'
)


def source_processing_policy(connection, project_id, sources):
    development = source_history.development_source_present(connection, project_id, sources)
    return {'source_processing_allowed': not development,
            'source_processing_reason': DEVELOPMENT_REASON if development else None}
