#!/usr/bin/env python3
"""Shared TypeSafe HTTP transport: pinned model + bounded retry/backoff.

Both TypeSafe seams (ts_triage, ts_claims) post one JSON body to the System One
API; this module owns the transport policy so the two cannot drift:

- the model is pinned to `TYPESAFE_MODEL` (default `jev-latest`);
- HTTP 429 and 5xx are retried up to three attempts, honoring `Retry-After`
  (seconds or HTTP-date) when present and falling back to 1s then 2s; the header is
  clamped to `[default_backoff, 60s]`, a past date or nonsense value uses the default;
- every other 4xx raises immediately.

`opener` and `sleep` inject the network and the clock for tests; production
callers use the defaults.
"""
from __future__ import annotations

import email.utils
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

API = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"
RETRY_ATTEMPTS = 3
RETRY_BACKOFF = (1.0, 2.0)


def model_name() -> str:
    """Pinned model, overridable with TYPESAFE_MODEL (default jev-latest)."""
    return os.environ.get("TYPESAFE_MODEL") or DEFAULT_MODEL


RETRY_AFTER_MAX = 60.0


def retry_delay(headers: Any, attempt: int) -> float:
    """Seconds to wait before retry `attempt` (1-based): bounded Retry-After, else 1s/2s.

    The server's `Retry-After` (delta-seconds or HTTP-date) is clamped to
    `[default_backoff, RETRY_AFTER_MAX]`: a value below the default backoff never makes
    the client retry FASTER than it would without the header, and a value above 60 s is
    capped so a hostile/broken header cannot park the client for hours. A past date or
    an unparseable value falls back to the default backoff.
    """
    default_backoff = RETRY_BACKOFF[min(attempt - 1, len(RETRY_BACKOFF) - 1)]
    value = None
    if headers is not None:
        try:
            value = headers.get("Retry-After")
        except (AttributeError, TypeError):
            value = None
    parsed = None
    if value:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            try:
                when = email.utils.parsedate_to_datetime(str(value))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                parsed = (when - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                parsed = None
    if parsed is None:
        return default_backoff
    return min(RETRY_AFTER_MAX, max(parsed, default_backoff))


def post_json(payload: dict, *, api_key: str, timeout: int = 60, url: str = API,
              opener: Callable | None = None, sleep: Callable | None = None) -> dict:
    """POST one JSON body, retrying 429/5xx; returns the decoded response dict."""
    opener = opener or urllib.request.urlopen
    sleep = sleep or time.sleep
    body = json.dumps(payload).encode()
    request_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        request = urllib.request.Request(url, data=body, headers=request_headers)
        try:
            with opener(request, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if (exc.code == 429 or 500 <= exc.code < 600) and attempt < RETRY_ATTEMPTS:
                sleep(retry_delay(exc.headers, attempt))
                continue
            raise
    raise RuntimeError("unreachable: retry loop exhausted without a return or raise")
