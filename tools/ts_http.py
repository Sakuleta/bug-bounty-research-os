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
from typing import Any, Callable, Iterable

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


# Choice answers are validated before they become values (ported from jev-ultrafast's
# `validate_choice`): a probability simplex that is not ≈1 or a choice that is not the
# argmax is a model/reporting error, never a verdict. Tolerance absorbs float noise.
CHOICE_TOLERANCE = 0.05


def validate_choice(answer: Any, choices: Iterable[str], *,
                    tolerance: float = CHOICE_TOLERANCE) -> str | None:
    """None when `answer` is a valid choice over `choices`; else the rejection reason.

    Shape-aware and fail-closed: `choice` must be one of `choices`, and `probabilities`
    — when present and non-empty — must be a probability simplex over the WHOLE answer
    space: every choice present, no label outside it, the values finite, non-negative
    and summing to ≈1, and the choice at (or tied for) the argmax. A partial map has no
    total to check and no simplex to trust, so it is rejected rather than treated as
    evidence. Answers carrying no probabilities at all (the IDF and `unavailable`
    shapes) never reach this function. Returning a reason means "reject": callers must
    fall back or flag, never take the value. Ties at the argmax are allowed (the model
    must at least pick a maximum).
    """
    if not isinstance(answer, dict):
        return f"answer is not an object (got {type(answer).__name__})"
    choice = answer.get("choice")
    allowed = list(choices)
    if not isinstance(choice, str) or not choice.strip() or choice not in allowed:
        return f"choice {choice!r} is not one of {', '.join(allowed)}"
    probs = answer.get("probabilities")
    if probs is None or probs == {}:
        return None
    if not isinstance(probs, dict):
        return f"probabilities is not an object (got {type(probs).__name__})"
    values: dict[str, float] = {}
    for key, value in probs.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"probability {key!r} is not a number ({value!r})"
        number = float(value)
        if number != number or number in (float("inf"), float("-inf")):
            return f"probability {key!r} is not finite ({value!r})"
        if number < 0:
            return f"probability {key!r} is negative ({number})"
        values[str(key)] = number
    if choice not in values:
        return f"choice {choice!r} carries no probability in the returned map"
    if set(values) != set(allowed):
        missing = sorted(set(allowed) - set(values))
        extra = sorted(set(values) - set(allowed))
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("outside the answer space: " + ", ".join(extra))
        return ("probabilities map does not cover the answer space ("
                + "; ".join(detail) + ") — a partial map is not a simplex")
    total = sum(values.values())
    if abs(total - 1.0) > tolerance:
        return f"probability simplex sums to {total:.4f} (expected 1.0 ± {tolerance})"
    best = max(values.values())
    if values[choice] < best - 1e-9:
        argmax = [k for k, v in values.items() if v >= best - 1e-9]
        return (f"choice {choice!r} is not the argmax ({values[choice]:.4f}; "
                f"max {best:.4f} at {', '.join(sorted(argmax))})")
    return None
