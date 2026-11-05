"""Public software identity only; never read environment, job data or secrets."""
from datetime import date
from importlib.resources import files
import json
import re


class ReleaseMetadataError(ValueError):
    pass


def need(condition):
    if not condition:
        raise ReleaseMetadataError('Invalid release metadata.')


def validate_release(raw: bytes) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        raise ReleaseMetadataError('Invalid release metadata.')
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ReleaseMetadataError('Invalid release metadata.')
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
        need(type(value) is dict and set(value) == {'version','released_on','title','changes','limitations'})
        need(type(value['version']) is str and re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)',value['version']))
        need(type(value['released_on']) is str and date.fromisoformat(value['released_on']).isoformat() == value['released_on'])
        need(type(value['title']) is str and 0 < len(value['title']) <= 120 and not any(ord(c)<32 for c in value['title']))
        for name in ('changes','limitations'):
            need(type(value[name]) is list and 1 <= len(value[name]) <= 12)
            need(all(type(item) is str and 0 < len(item) <= 400 and not any(ord(c) < 32 for c in item) for item in value[name]))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ReleaseMetadataError('Invalid release metadata.') from None
    return value


def public_release() -> dict:
    return validate_release(files(__package__).joinpath('release.json').read_bytes())
