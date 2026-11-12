"""Bounded advisory local progress, never source/review/execution authority.

No XML parsing, epoch reconstruction, model/configuration load or HTTP. Recorded
means matching local metadata only; technical and business acceptance stay false.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from .opaf import canonical_hash

STAGES = ('mapping', 'validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
MAX_METADATA_BYTES = 2_000_000
MAX_SNAPSHOT_BYTES = 20_000_000
MAX_TOTAL_BYTES = 32_000_000
MAX_READS = 24
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_RUN = re.compile(r'fox-[a-f0-9]{20}\Z')
_FOCUS = re.compile(r'focus-[a-f0-9]{24}\Z')


class NotPrototypeRun(ValueError):
    """A well-formed snapshot belongs to another conversion workflow."""


class _Unavailable(ValueError):
    pass


class _Metadata:
    def __init__(self):
        self.bytes = 0
        self.pins = {}

    @staticmethod
    def safe(path):
        path = Path(path).absolute()
        for part in (path, *path.parents):
            value = part.lstat()
            if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
                raise _Unavailable()
        return path

    @staticmethod
    def identity(value):
        return tuple(getattr(value, key) for key in
                     ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns'))

    def exists(self, path):
        try:
            path = self.safe(path)
        except FileNotFoundError:
            return False
        value = path.lstat()
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise _Unavailable()
        return True

    def read(self, path, limit=MAX_METADATA_BYTES):
        path = self.safe(path)
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= limit or len(self.pins) >= MAX_READS
                or self.bytes + before.st_size > MAX_TOTAL_BYTES):
            raise _Unavailable()
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        identity = self.identity(before)
        if (len(raw) != before.st_size or identity != self.identity(opened)
                or identity != self.identity(after) or identity != self.identity(path.lstat())):
            raise _Unavailable()
        self.pins[path] = identity
        self.bytes += len(raw)

        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise _Unavailable()
                result[key] = value
            return result

        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(_Unavailable()))
        if type(value) is not dict:
            raise _Unavailable()
        return value

    def unchanged(self):
        for path, identity in self.pins.items():
            if self.identity(self.safe(path).lstat()) != identity:
                raise _Unavailable()


def _require(value):
    if not value:
        raise _Unavailable()


def _mapping_pending(metadata, pipeline, rid, binding):
    # Direct initial focus markers only; no recursive epoch/history walk. A
    # historical completed marker never means a model is currently running.
    with os.scandir(pipeline) as entries:
        names = []
        for index, entry in enumerate(entries):
            _require(index < 512)
            if _FOCUS.fullmatch(entry.name):
                names.append(entry.name)
    for name in sorted(names):
        directory = metadata.safe(pipeline / name)
        for role in ('mapper', 'reviewer'):
            intent = directory / (role + '-intent.json')
            if not metadata.exists(intent) or metadata.exists(directory / (role + '.json')):
                continue
            value = metadata.read(intent, 65_536)
            _require(value.get('job_id') == rid and value.get('source_hash') == binding
                     and type(value.get('request_sha256')) is str and _SHA.fullmatch(value['request_sha256']))
            return True
    return False


def prototype_progress(root, run, owner):
    """Observe an already authenticated exact project/run row without writes."""
    pid, rid, source_hash, state = (run[key] for key in ('project', 'id', 'source_hash', 'state'))
    result = {'schema_version': 1, 'scope': 'fox-prototype-progress-v1',
              'project_id': pid, 'run_id': rid, 'source_hash': source_hash, 'state': state,
              'observed_at_utc': datetime.now(timezone.utc).isoformat(), 'current_stage': None,
              'stages': [{'id': name, 'status': 'not_observed'} for name in STAGES],
              'message': 'Progress is not currently available. Saved work is unchanged.',
              'progress_available': False, 'advisory': True, 'technically_verified': False, 'business_behavior_accepted': False}
    try:
        _require(type(rid) is str and _RUN.fullmatch(rid) and type(source_hash) is str and _SHA.fullmatch(source_hash))
        metadata = _Metadata()
        job = Path(root).absolute() / 'jobs' / rid
        snapshot = metadata.read(job / 'source-snapshot.json', MAX_SNAPSHOT_BYTES)
        if snapshot.get('conversion_profile') != 'native-blueprint-prototype-v1':
            raise NotPrototypeRun()
        selected = snapshot['prototype']
        _require(snapshot['project_id'] == snapshot['project'] == pid
                 and snapshot['source_hash'] == source_hash and snapshot['approvals']['owner'] == owner
                 and type(selected['source_binding']) is str and _SHA.fullmatch(selected['source_binding'])
                 and type(selected['focus_plan_sha256']) is str and _SHA.fullmatch(selected['focus_plan_sha256']))
        pipeline = job / 'prototype-pipeline'
        if not metadata.exists(pipeline / 'binding.json'):
            metadata.unchanged()
            result['message'] = 'Waiting for mapping to be recorded.' if state == 'QUEUED' else 'Checking saved work / waiting for next recorded step.'
            result['progress_available'] = True
            return result
        binding = metadata.read(pipeline / 'binding.json', 65_536)
        source_binding = selected['source_binding']
        _require(binding['job_id'] == rid and binding['project_id'] == pid
                 and binding['source_binding'] == source_binding
                 and binding['focus_plan_sha256'] == selected['focus_plan_sha256'])
        required = ('native-plan.json', 'rendered.json', 'sources-manifest.json', 'review-index.json')
        if not all(metadata.exists(pipeline / name) for name in required):
            pending = _mapping_pending(metadata, pipeline, rid, source_binding)
            if state in ('PROCESSING', 'ATTENTION') and pending:
                result['current_stage'] = 'mapping'
                result['stages'][0]['status'] = 'working' if state == 'PROCESSING' else 'attention'
                result['message'] = 'Mapping was requested; waiting for a recorded update.' if state == 'PROCESSING' else 'The current mapping needs attention. Saved work is preserved.'
            else:
                result['message'] = 'Checking saved work / waiting for next recorded step.'
            metadata.unchanged()
            result['progress_available'] = True
            return result
        native, rendered, manifest, reviews = (metadata.read(pipeline / name) for name in required)
        _require(native['source_binding'] == rendered['source_binding'] == manifest['source_binding'] == reviews['source_binding'] == source_binding
                 and native['rendering_spec']['project_id'] == pid and native['rendering_spec']['source_binding'] == source_binding
                 and native['plan_sha256'] == rendered['plan_sha256']
                 and type(native['plan_sha256']) is str and _SHA.fullmatch(native['plan_sha256'])
                 and canonical_hash({key: value for key, value in native.items() if key != 'plan_sha256'}) == native['plan_sha256']
                 and type(rendered['zip_sha256']) is str and _SHA.fullmatch(rendered['zip_sha256']))
        authority = {'schema_version': 1, 'scope': 'fox-prototype-source-authority-v1',
                     'binding_sha256': canonical_hash(binding), 'sources_manifest_sha256': canonical_hash(manifest),
                     'review_index_sha256': canonical_hash(reviews)}
        result['stages'][0]['status'] = 'recorded'
        prior = {}
        waiting = False
        for index, stage in enumerate(STAGES[1:], start=1):
            request = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1',
                       'job_id': rid, 'project_id': pid, 'source_binding': source_binding,
                       'plan_sha256': native['plan_sha256'], 'rendering_spec': native['rendering_spec'],
                       'rendered_zip_sha256': rendered['zip_sha256'], 'source_authority': authority, 'prior_receipts': dict(prior)}
            intent_path, receipt_path = pipeline / (stage + '-intent.json'), pipeline / (stage + '.json')
            has_intent, has_receipt = metadata.exists(intent_path), metadata.exists(receipt_path)
            _require(not waiting or not (has_intent or has_receipt))
            if waiting:
                continue
            if has_intent:
                _require(metadata.read(intent_path, 1024) == {'request_sha256': canonical_hash(request)})
            if has_receipt:
                value = metadata.read(receipt_path)
                _require(value.get('stage') == stage and value.get('source_binding') == source_binding
                         and value.get('plan_sha256') == native['plan_sha256']
                         and value.get('request_sha256') == canonical_hash(request)
                         and value.get('status') == 'COMPLETE' and value.get('business_behavior_accepted') in (None, False))
                gates = {'validate': ('passed',), 'prepare_schema': ('ready_for_import',),
                         'import': ('imported',), 'verify_runtime': ('passed', 'authenticated', 'business_pages_tested'),
                         'export': ('exported',)}
                _require(all(value.get(key) is True for key in gates[stage]))
                if stage == 'import':
                    _require(type(value.get('application_id')) is int and value['application_id'] > 0)
                if stage == 'export':
                    _require(type(value.get('package_sha256')) is str and _SHA.fullmatch(value['package_sha256']))
                result['stages'][index]['status'] = 'recorded'
                prior[stage] = value
            else:
                waiting = True
                if has_intent and state in ('PROCESSING', 'ATTENTION'):
                    result['current_stage'] = stage
                    result['stages'][index]['status'] = 'working' if state == 'PROCESSING' else 'attention'
        metadata.unchanged()
        if result['current_stage'] is not None:
            result['message'] = 'The current step needs attention. Saved work is preserved.' if state == 'ATTENTION' else 'The current step was requested; waiting for its recorded result.'
        else:
            result['message'] = 'Recorded stage updates are available.' if not waiting else 'Checking saved work / waiting for next recorded step.'
        result['progress_available'] = True
        return result
    except NotPrototypeRun:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
        result['progress_available'] = False
        result['current_stage'] = None
        result['stages'] = [{'id': name, 'status': 'not_observed'} for name in STAGES]
        result['message'] = 'Progress is not currently available. Saved work is unchanged.'
        return result
