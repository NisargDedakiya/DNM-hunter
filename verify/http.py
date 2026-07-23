"""HTTP transport abstraction for the verification layer.

Every oracle talks to the target through this thin interface, never through a
concrete client. That single seam is what makes the whole layer unit-testable
offline: tests inject a fake client that simulates a vulnerable (or patched)
target, and the exact same oracle code that runs in production runs in the tests.
"""

from __future__ import annotations

import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str | None = None


@dataclass
class HttpResponse:
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0


class HttpClient(Protocol):
    """Anything that can send an HttpRequest and return an HttpResponse."""
    def send(self, req: HttpRequest) -> HttpResponse: ...


class UrllibHttpClient:
    """Production client — stdlib only, measures wall-clock latency for the timing
    oracle. Deliberately minimal; the point of the abstraction is that a heavier
    client (httpx, requests) can drop in without touching oracle code."""

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def send(self, req: HttpRequest) -> HttpResponse:
        data = req.body.encode() if req.body is not None else None
        request = urllib.request.Request(req.url, data=data, headers=req.headers, method=req.method)
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                body = resp.read().decode(errors="replace")
                elapsed = (time.perf_counter() - start) * 1000.0
                return HttpResponse(resp.status, dict(resp.headers), body, elapsed)
        except urllib.error.HTTPError as e:  # 4xx/5xx are still responses we want to inspect
            body = e.read().decode(errors="replace") if e.fp else ""
            elapsed = (time.perf_counter() - start) * 1000.0
            return HttpResponse(e.code, dict(e.headers or {}), body, elapsed)


def with_param(url: str, key: str, value: str) -> str:
    """Return `url` with query parameter `key` set to `value` (added or replaced)."""
    parts = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
    q.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def form_body(fields: dict, key: str, value: str) -> str:
    """Return a urlencoded body with `key` set to `value`."""
    merged = dict(fields)
    merged[key] = value
    return urlencode(merged)


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()
