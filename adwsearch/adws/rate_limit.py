# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""OPSEC rate-limit for the ADWS transport (sleep + jitter between requests).

Wraps an :class:`AdwsConnection` (or any object exposing ``request(events)`` and
``close()``) so every SOAP send is preceded by a configurable pause. The first
request is not delayed — there is no predecessor to space out from — every
subsequent one waits ``sleep + random.uniform(0, jitter)`` seconds.

Enabled from the CLI via ``--sleep`` / ``--jitter``; when both are 0 the CLI
skips wrapping entirely so the no-OPSEC codepath has zero overhead.
"""

import random
import time


class RequestPacer:
    def __init__(self, sleep: float = 0.0, jitter: float = 0.0,
                 *, sleeper=time.sleep, rng=None):
        self._sleep = sleep
        self._jitter = jitter
        self._sleeper = sleeper
        self._rng = rng or random.Random()
        self._first = True

    def wait(self):
        if not self._first:
            jitter_component = (self._rng.uniform(0, self._jitter)
                                if self._jitter > 0 else 0.0)
            delay = self._sleep + jitter_component
            if delay > 0:
                self._sleeper(delay)
        self._first = False


class RateLimitedTransport:
    def __init__(self, inner, sleep: float = 0.0, jitter: float = 0.0,
                 *, sleeper=time.sleep, rng=None, pacer=None):
        self._inner = inner
        self._pacer = pacer if pacer is not None else RequestPacer(
            sleep, jitter, sleeper=sleeper, rng=rng)

    def request(self, events):
        self._pacer.wait()
        return self._inner.request(events)

    def close(self):
        return self._inner.close()
