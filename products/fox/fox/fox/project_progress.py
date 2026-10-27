"""Bounded advisory project progress; never an execution/acceptance receipt.

Writers receive an independently validated plan. Readers require its expected
identity and complete module set. Pipeline resumes rebuild stages from checked
role/review/generation receipts, never from this replaceable UI document.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import tempfile

MAX_PROGRESS_BYTES = 24_000
FILENAME = 'project-progress.json'
SCOPE = 'fox-native-project-progress-v1'
FORM_MESSAGES = {
    'pending': 'Waiting for processing.',
    'mapping': 'Mapping the supplied form.',
    'mapped': 'Mapping completed; independent review is pending.',
    'reviewing': 'Independent review is running.',
    'reviewed': 'Independent review passed; application generation is pending.',
    'generated': 'Included in the generated application; testing and acceptance are separate.',
    'attention': 'Processing needs operator attention; the whole project is blocked.',
}
PROJECT_STAGES = frozenset({'preparing', 'mapping', 'reviewing', 'generating', 'generated',
    'validating', 'schema_preparing', 'importing', 'packaging', 'downloaded', 'attention'})
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z')


def _utc(value):
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        raise ValueError('Invalid advisory timestamp')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate advisory field')
        value[key] = item
    return value


def _validate(value, job_id, source_hash, plan_sha256, module_ids):
    expected = sorted(module_ids)
    if (not isinstance(job_id, str) or not re.fullmatch(r'fox-[a-f0-9]{20}', job_id)
            or not all(isinstance(item, str) and _SHA.fullmatch(item) for item in (source_hash, plan_sha256))
            or not 1 <= len(expected) <= 50 or len(set(expected)) != len(expected)
            or not all(isinstance(item, str) and re.fullmatch(r'form-[a-f0-9]{20}', item) for item in expected)):
        raise ValueError('Invalid advisory identity')
    if (type(value) is not dict or set(value) != {'schema_version', 'scope', 'job_id', 'source_hash',
            'plan_sha256', 'updated_at_utc', 'project_stage', 'forms', 'human_acceptance_recorded', 'authorization_scope'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['scope'] != SCOPE or value['job_id'] != job_id
            or value['source_hash'] != source_hash or value['plan_sha256'] != plan_sha256
            or value['authorization_scope'] != 'advisory_only' or value['human_acceptance_recorded'] is not False
            or value['project_stage'] not in PROJECT_STAGES or type(value['forms']) is not list
            or len(value['forms']) != len(expected)):
        raise ValueError('Unbound advisory progress')
    updated = _utc(value['updated_at_utc'])
    if (updated - datetime.now(timezone.utc)).total_seconds() > 5:
        raise ValueError('Future advisory progress')
    for row, module_id in zip(value['forms'], expected):
        if (type(row) is not dict or set(row) != {'module_id', 'stage', 'message', 'updated_at_utc'}
                or row['module_id'] != module_id or row['stage'] not in FORM_MESSAGES
                or row['message'] != FORM_MESSAGES[row['stage']] or _utc(row['updated_at_utc']) > updated):
            raise ValueError('Invalid advisory form progress')
    return value


def read_project_progress(job: Path, *, job_id, source_hash, plan_sha256, module_ids):
    """Return exact source-bound advisory progress, or {} without error text."""
    try:
        job = Path(job); path = job / FILENAME
        if job.is_symlink() or job.name != job_id or path.is_symlink():
            return {}
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_PROGRESS_BYTES:
            return {}
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
                return {}
            raw = stream.read(MAX_PROGRESS_BYTES + 1)
        if len(raw) != before.st_size:
            return {}
        value = json.loads(raw, object_pairs_hook=_keys)
        return _validate(value, job_id, source_hash, plan_sha256, module_ids)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        return {}


class ProjectProgress:
    """In-memory state reset per attempt; completion is supplied by the pipeline."""
    def __init__(self, job, plan):
        self.job = Path(job)
        self.ids = sorted(form['module_id'] for form in plan['forms'])
        now = datetime.now(timezone.utc).isoformat()
        self.value = {'schema_version': 1, 'scope': SCOPE, 'job_id': self.job.name,
            'source_hash': plan['source_hash'], 'plan_sha256': plan['plan_sha256'], 'updated_at_utc': now,
            'project_stage': 'preparing', 'human_acceptance_recorded': False, 'authorization_scope': 'advisory_only',
            'forms': [{'module_id': module, 'stage': 'pending', 'message': FORM_MESSAGES['pending'],
                       'updated_at_utc': now} for module in self.ids]}
        self.active_module = None
        self.publish()

    def publish(self):
        _validate(self.value, self.job.name, self.value['source_hash'], self.value['plan_sha256'], self.ids)
        raw = json.dumps(self.value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        if len(raw) > MAX_PROGRESS_BYTES or self.job.is_symlink() or (self.job / FILENAME).is_symlink():
            raise ValueError('Unsafe advisory progress file')
        fd, name = tempfile.mkstemp(prefix='.project-progress-', dir=self.job)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.job / FILENAME)
            if os.name != 'nt':
                descriptor = os.open(self.job, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            Path(name).unlink(missing_ok=True)

    def stage(self, stage):
        if stage not in PROJECT_STAGES:
            raise ValueError('Unknown advisory project stage')
        self.value.update(project_stage=stage, updated_at_utc=datetime.now(timezone.utc).isoformat())
        self.publish()

    def form(self, module_id, stage):
        if module_id not in self.ids or stage not in FORM_MESSAGES:
            raise ValueError('Unknown advisory form stage')
        now = datetime.now(timezone.utc).isoformat()
        self.value['updated_at_utc'] = now
        row = next(item for item in self.value['forms'] if item['module_id'] == module_id)
        row.update(stage=stage, message=FORM_MESSAGES[stage], updated_at_utc=now)
        self.active_module = module_id if stage in {'mapping', 'mapped', 'reviewing'} else None
        self.publish()

    def generated(self):
        # Caller must have validated the parent generation receipt first.
        now = datetime.now(timezone.utc).isoformat()
        for row in self.value['forms']:
            row.update(stage='generated', message=FORM_MESSAGES['generated'], updated_at_utc=now)
        self.active_module = None
        self.value.update(project_stage='generated', updated_at_utc=now)
        self.publish()

    def attention(self):
        if self.active_module is not None:
            self.form(self.active_module, 'attention')
        self.stage('attention')
