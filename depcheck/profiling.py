"""Opt-in local work measurements; no telemetry, persistence or thresholds."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import time
from typing import Any, Callable, ParamSpec, TypeVar

_P = ParamSpec("_P")
_R = TypeVar("_R")
_PROFILE: ContextVar[dict[str, dict[str, Any]] | None] = ContextVar(
    "depcheck_profile", default=None
)


def count_work(name: str, **counts: int) -> None:
    """Record additive work units separately from inclusive phase durations."""
    profile = _PROFILE.get()
    if profile is not None:
        record = profile.setdefault(name, {})
        for key, value in counts.items():
            record[key] = record.get(key, 0) + value


@contextmanager
def capture_profile(*, enabled: bool = True) -> Iterator[dict[str, dict[str, Any]]]:
    measurements: dict[str, dict[str, Any]] = {}
    if not enabled:
        yield measurements
        return
    token = _PROFILE.set(measurements)
    try:
        yield measurements
    finally:
        _PROFILE.reset(token)


def measured(name: str) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]:
    def decorate(function: Callable[_P, _R]) -> Callable[_P, _R]:
        @wraps(function)
        def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            profile = _PROFILE.get()
            if profile is None:
                return function(*args, **kwargs)
            started = time.perf_counter()
            failed = False
            try:
                return function(*args, **kwargs)
            except BaseException:
                failed = True
                raise
            finally:
                record = profile.setdefault(
                    name, {"calls": 0, "seconds": 0.0, "failed_calls": 0}
                )
                record["calls"] += 1
                record["seconds"] += time.perf_counter() - started
                record["failed_calls"] += int(failed)

        return wrapper

    return decorate


def profile_payload(measurements: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "clock": "perf_counter",
        "duration_semantics": "inclusive; nested phases overlap and must not be summed",
        "coverage": "instrumented-functions-only",
        "phases": dict(sorted(measurements.items())),
    }
