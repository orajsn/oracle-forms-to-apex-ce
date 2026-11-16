"""Bounded metadata-only provider measurements, never sealed model evidence."""
import math
from time import monotonic


class ProviderTiming:
    _COUNTS = {'http_requests', 'tls_connections', 'request_body_bytes', 'response_body_bytes'}
    _DURATIONS = {'environment_seconds', 'setup_seconds', 'before_invoke_seconds', 'request_seconds'}

    def __init__(self, provider):
        if provider not in {'opaf', 'oci_genai'}:
            raise ValueError('Unsupported timing provider.')
        self.started = self.previous = monotonic()
        self.value = {'schema_version': 1, 'scope': 'fox-provider-timing-v1', 'provider': provider}

    @staticmethod
    def _duration(value):
        return round(min(max(value, 0), 604800), 6) if math.isfinite(value) else 604800

    def mark(self, name):
        if name not in self._DURATIONS:
            raise ValueError('Unsupported provider timing.')
        now = monotonic()
        self.value[name] = self._duration(now - self.previous)
        self.previous = now

    def begin_request(self):
        """Exclude local binding checks from the HTTP/SDK request measurement."""
        self.previous = monotonic()

    def increment(self, name, amount=1):
        if name not in self._COUNTS or type(amount) is not int or amount < 0:
            raise ValueError('Unsupported provider count.')
        self.value[name] = min(self.value.get(name, 0) + amount, 2**53 - 1)

    def finish(self):
        return {**self.value, 'total_seconds': self._duration(monotonic() - self.started)}
