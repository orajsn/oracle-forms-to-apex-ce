"""Pure timestamped QA-producer classification, shared by host and validators.

Python 3.6 compatible. No I/O, runtime discovery, caller-authorized exceptions,
container mutation, or conversion/recovery authority. Raw container status is
never rewritten: CREATED_NEVER_STARTED is distinct from STOPPED_NON_LIVE.
"""
import calendar
from datetime import datetime
from decimal import Decimal
import hashlib
import json
import re

SCOPE = 'fox-timestamped-producer-inventory-witness-v1'
ROW_KEYS = frozenset(('id', 'name', 'image', 'status', 'running', 'pid', 'exit_code',
                      'created_at', 'started_at', 'finished_at'))
SNAPSHOT_KEYS = frozenset(('observed_at_utc', 'rootless_container_count', 'rootless_inventory_sha256', 'producers'))
STATES = frozenset(('created', 'running', 'paused', 'restarting', 'stopping', 'stopped', 'exited', 'configured', 'initialized', 'unknown'))
CLASSIFICATIONS = frozenset(('CREATED_NEVER_STARTED', 'STOPPED_NON_LIVE', 'LIVE', 'UNKNOWN'))
MAX_ROOTLESS = 256
MAX_RELEVANT = 64
MAX_WITNESS_BYTES = 48_000
ZERO = '0001-01-01T00:00:00Z'


class InventoryContractError(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise InventoryContractError(code)


def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


def canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                           allow_nan=False) + '\n').encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise InventoryContractError('INVENTORY_JSON_INVALID') from None


def timestamp(value):
    need(type(value) is str, 'INVENTORY_UTC_INVALID')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)', value)
    need(match is not None, 'INVENTORY_UTC_INVALID')
    try:
        whole = calendar.timegm(datetime.strptime(match.group(1), '%Y-%m-%dT%H:%M:%S').timetuple())
    except (ValueError, OverflowError):
        raise InventoryContractError('INVENTORY_UTC_INVALID') from None
    return Decimal(whole) + Decimal('0.' + (match.group(2) or '0'))


def classify_row(row, observed_at_utc):
    """Derive state from complete measured metadata, never an ID/name exemption."""
    need(type(row) is dict and set(row) == ROW_KEYS, 'INVENTORY_ROW_FIELDS_INVALID')
    need(digest(row['id']) and type(row['name']) is str
         and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', row['name'])
         and type(row['image']) is str and re.fullmatch('sha256:[a-f0-9]{64}', row['image'])
         and type(row['status']) is str and row['status'] in STATES
         and type(row['running']) is bool and type(row['pid']) is int and 0 <= row['pid'] <= 2 ** 31 - 1
         and type(row['exit_code']) is int and 0 <= row['exit_code'] <= 255,
         'INVENTORY_ROW_IDENTITY_OR_STATE_INVALID')
    now = timestamp(observed_at_utc)
    created, started, finished = (timestamp(row[key]) for key in ('created_at', 'started_at', 'finished_at'))
    zero = timestamp(ZERO)
    need(created > zero and created <= now + 5, 'INVENTORY_CREATED_TIME_INVALID')
    if row['running'] or row['pid'] > 0 or row['status'] in ('running', 'paused', 'restarting', 'stopping'):
        return 'LIVE'
    if (row['status'] == 'created' and row['running'] is False and row['pid'] == 0 and row['exit_code'] == 0
            and started == zero and finished == zero):
        return 'CREATED_NEVER_STARTED'
    if (row['status'] in ('stopped', 'exited') and row['running'] is False and row['pid'] == 0
            and started != zero and finished != zero and created <= started <= finished <= now + 5):
        return 'STOPPED_NON_LIVE'
    return 'UNKNOWN'


def validate_snapshot(value):
    need(type(value) is dict and set(value) == SNAPSHOT_KEYS, 'INVENTORY_SNAPSHOT_FIELDS_INVALID')
    timestamp(value['observed_at_utc'])
    rows = value['producers']
    need(type(rows) is list and len(rows) <= MAX_RELEVANT
         and type(value['rootless_container_count']) is int
         and len(rows) + 3 <= value['rootless_container_count'] <= MAX_ROOTLESS
         and digest(value['rootless_inventory_sha256']), 'INVENTORY_SNAPSHOT_BOUNDS_INVALID')
    ids, names = [], set()
    counts = {'live_producer_count': 0, 'unknown_producer_count': 0, 'never_started_producer_count': 0,
              'stopped_non_live_producer_count': 0}
    keys = {'LIVE': 'live_producer_count', 'UNKNOWN': 'unknown_producer_count',
            'CREATED_NEVER_STARTED': 'never_started_producer_count', 'STOPPED_NON_LIVE': 'stopped_non_live_producer_count'}
    for row in rows:
        need(type(row) is dict and set(row) == ROW_KEYS | {'classification'}, 'INVENTORY_ROW_FIELDS_INVALID')
        raw = {key: row[key] for key in ROW_KEYS}
        kind = classify_row(raw, value['observed_at_utc'])
        need(row['classification'] == kind and row['classification'] in CLASSIFICATIONS,
             'INVENTORY_CLASSIFICATION_MISMATCH')
        need(row['id'] not in ids and row['name'] not in names, 'INVENTORY_DUPLICATE_ROW')
        ids.append(row['id']); names.add(row['name']); counts[keys[kind]] += 1
    need(ids == sorted(ids), 'INVENTORY_ROWS_NOT_CANONICAL')
    return counts


def stable_snapshot(value):
    """Within one observation, only sampling time may differ."""
    validate_snapshot(value)
    return {key: value[key] for key in SNAPSHOT_KEYS if key != 'observed_at_utc'}


def validate_witness(value, observed_at_utc):
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'before', 'after'}
         and type(value['schema_version']) is int and value['schema_version'] == 1 and value['scope'] == SCOPE,
         'INVENTORY_WITNESS_FIELDS_INVALID')
    raw = canonical(value)
    need(0 < len(raw) <= MAX_WITNESS_BYTES, 'INVENTORY_WITNESS_TOO_LARGE')
    before_counts = validate_snapshot(value['before'])
    after_counts = validate_snapshot(value['after'])
    before = timestamp(value['before']['observed_at_utc'])
    after = timestamp(value['after']['observed_at_utc'])
    observed = timestamp(observed_at_utc)
    need(before <= after <= observed + 5 and after - before <= 120 and observed - before <= 150,
         'INVENTORY_WITNESS_TIME_INVALID')
    need(stable_snapshot(value['before']) == stable_snapshot(value['after']) and before_counts == after_counts,
         'INVENTORY_CHANGED_WITHIN_OBSERVATION')
    need(after_counts['live_producer_count'] == after_counts['unknown_producer_count'] == 0,
         'INVENTORY_LIVE_OR_UNKNOWN_PRODUCER_PRESENT')
    return dict(after_counts, inventory_evidence_sha256=hashlib.sha256(raw).hexdigest())
