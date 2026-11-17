import React, {useId, useMemo, useState} from 'react';
import './RemediationReview.css';

export type RemediationReviewProps = {records: readonly Record<string, unknown>[]; sourceKey: string};
const labels: Record<string, string> = {
  blueprint_unresolved: 'Mapping needs review', blueprint_omitted: 'Omitted components',
  source_behavior_not_implemented: 'Behavior still to implement', grid_editing_not_implemented: 'Grid editing not implemented',
  button_not_implemented: 'Button actions not implemented', code_unit_not_translated: 'Code still to convert',
  dependency_not_implemented: 'Dependencies to review', required_input_unknown: 'Required-field rules to confirm',
  required_input_not_implemented: 'Required-field rules not implemented', count_check_remainder_not_converted: 'Remaining action not converted',
};
const text = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value : null;
const show = (value: unknown) => JSON.stringify(value, null, 2) ?? String(value);
const groupFor = (record: Record<string, unknown>) => typeof record.code === 'string' && Object.hasOwn(labels, record.code) ? record.code : '';
const searchable = (record: Record<string, unknown>) => [record.reason, record.next_action, record.reference, record.evidence, record.code, record.kind, record.source_object_id, record.code_unit_id, labels[groupFor(record)] ?? 'Other findings'].filter(value => value !== undefined && value !== null).map(show).join(' ').toLocaleLowerCase();
const coordinate = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;

function Review({records}: Pick<RemediationReviewProps, 'records'>) {
  const [search, setSearch] = useState('');
  const searchId = useId();
  const groups = useMemo(() => {
    const result = new Map<string, {total: number; items: Record<string, unknown>[]}>();
    const query = search.trim().toLocaleLowerCase();
    records.forEach(record => {
      const key = groupFor(record);
      const group = result.get(key) ?? {total: 0, items: []};
      group.total++;
      if (!query || searchable(record).includes(query)) group.items.push(record);
      result.set(key, group);
    });
    return [...result.entries()];
  }, [records, search]);
  const shown = groups.reduce((sum, [, group]) => sum + group.items.length, 0);
  return <section className="remediation-review" aria-label="Remediation review">
    <h3>What needs attention</h3>
    <p>Choose a category or search to review the remaining work.</p>
    {records.length === 0 ? <p>No findings were provided.</p> : <>
      <div className="remediation-review__search"><label htmlFor={searchId}>Search findings</label><div><input id={searchId} type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search actions or evidence"/><button type="button" onClick={() => setSearch('')} disabled={!search}>Clear search</button></div></div>
      <p aria-live="polite">Showing {shown} of {records.length} findings</p>
      {shown === 0 && <p>No findings match your search. Clear the search to see all findings.</p>}
      <div className="remediation-review__groups">{groups.filter(([, group]) => !search.trim() || group.items.length > 0).map(([code, group]) => <details key={code || 'other'} className="remediation-review__group">
        <summary><strong>{labels[code] ?? 'Other findings'}</strong> <span>{search.trim() ? `${group.items.length} of ${group.total}` : group.total} {group.total === 1 ? 'finding' : 'findings'}</span></summary>
        {group.items.length === 0 ? <p>No findings in this group match your search.</p> : <ol className="remediation-review__list">{group.items.map((record, index) => {
          const evidence = Array.isArray(record.evidence) ? record.evidence : record.evidence && typeof record.evidence === 'object' ? [record.evidence] : [];
          return <li className="remediation-review__card" key={index}>
            {text(record.kind) && <p><strong>Kind:</strong> {text(record.kind)}</p>}
            <p><strong>Reason:</strong> {text(record.reason) ?? 'Not provided'}</p>
            <p><strong>Next action:</strong> {text(record.next_action) ?? 'Not provided'}</p>
            {evidence.length > 0 && <div><strong>Evidence provided:</strong><ul>{evidence.map((item, evidenceIndex) => {
              if (!item || typeof item !== 'object' || Array.isArray(item)) return <li key={evidenceIndex}>{show(item)}</li>;
              const entry = item as Record<string, unknown>;
              const location = entry.location && typeof entry.location === 'object' && !Array.isArray(entry.location) ? entry.location as Record<string, unknown> : null;
              return <li key={evidenceIndex}>{(['name', 'confidence', 'kind'] as const).map(field => text(entry[field]) && <p key={field}><strong>{field === 'name' ? 'Name' : field === 'confidence' ? 'Confidence' : 'Kind'}:</strong> {text(entry[field])}</p>)}
                {location ? <p><strong>Extracted XML location:</strong> {[text(location.path), coordinate(location.line) !== null ? `line ${coordinate(location.line)}` : null, coordinate(location.column) !== null ? `column ${coordinate(location.column)}` : null].filter(Boolean).join(', ') || 'Not provided'}</p> : text(entry.location) && <p><strong>Location:</strong> {text(entry.location)}</p>}
              </li>;
            })}</ul></div>}
            <details><summary>Show original record details</summary><pre>{show(record)}</pre></details>
          </li>;
        })}</ol>}
      </details>)}</div>
    </>}
  </section>;
}
export default function RemediationReview({records, sourceKey}: RemediationReviewProps) {
  return <Review key={sourceKey} records={records}/>;
}
