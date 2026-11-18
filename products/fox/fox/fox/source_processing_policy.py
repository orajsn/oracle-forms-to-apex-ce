"""Current source provenance and durable owner processing consent."""
from . import source_history

DEVELOPMENT_REASON = (
    'Use Generate APEX package with explicit development-source processing approval. '
    'The legacy redacted-source route does not process preserved development code.'
)
DEVELOPMENT_EVENT = 'approved_development_conversion'


def source_processing_policy(connection, project_id, sources):
    development = source_history.development_source_present(connection, project_id, sources)
    return {'source_processing_allowed': not development,
            'source_processing_reason': DEVELOPMENT_REASON if development else None,
            'processing_mode': 'development' if development else 'legacy_redacted'}


def current_processing_approval(connection, snapshot, run_id, sources):
    """Recheck mode/provenance and the original owner event before fresh work."""
    from .development_source import POLICY_ID
    from .development_processing import describe_development_processing
    from .opaf import canonical_hash
    selected = snapshot['prototype']
    provenance = source_history.source_provenance(connection, snapshot['project_id'], sources)
    development = any(row['policy_id'] == POLICY_ID for row in provenance)
    if not development:
        return 'processing_mode' not in selected
    if selected.get('processing_mode') != 'development':
        return False
    context = describe_development_processing(
        [(row['name'], source_history.readable_source_bytes(row)) for row in sources],
        project_id=snapshot['project_id'], selected_source_set_id=snapshot['selected_source_set_id'],
        source_hash=snapshot['source_hash'], source_provenance=provenance,
        target_profile_sha256=selected['target_profile_sha256'], delivery_mode=selected.get('delivery_mode'),
        chunk_evidence_policy=selected.get('chunk_evidence_policy'))
    binding = {**context, 'approved_chunk_hashes': selected['approved_chunk_hashes']}
    if (binding != selected.get('development_processing')
            or canonical_hash(binding) != selected.get('development_processing_sha256')):
        return False
    approvals = snapshot['approvals']
    return connection.execute(
        'SELECT 1 FROM events WHERE owner=? AND action=? AND object_id=? AND created=?',
        (approvals['owner'], DEVELOPMENT_EVENT, run_id, approvals['approved_at'])).fetchone() is not None
