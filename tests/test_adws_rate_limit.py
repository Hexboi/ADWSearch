# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""RateLimitedTransport wrapper — deterministic tests with injected sleeper/rng."""

from adwsearch.adws.rate_limit import RateLimitedTransport


class _FakeInner:
    def __init__(self):
        self.requests = []
        self.closed = False

    def request(self, events):
        self.requests.append(events)
        return ["response-for", events]

    def close(self):
        self.closed = True


class _RecordingSleeper:
    def __init__(self):
        self.calls = []

    def __call__(self, delay):
        self.calls.append(delay)


class _FixedRng:
    """Deterministic Random that always yields the same uniform() value."""

    def __init__(self, value: float):
        self._value = value

    def uniform(self, a, b):
        return self._value


def test_first_request_does_not_sleep():
    sleeper = _RecordingSleeper()
    inner = _FakeInner()
    rl = RateLimitedTransport(inner, sleep=1.0, jitter=0.5,
                              sleeper=sleeper, rng=_FixedRng(0.3))
    result = rl.request(["req1"])
    assert result == ["response-for", ["req1"]]
    assert sleeper.calls == []
    assert inner.requests == [["req1"]]


def test_subsequent_requests_sleep_sleep_plus_jitter():
    sleeper = _RecordingSleeper()
    inner = _FakeInner()
    rl = RateLimitedTransport(inner, sleep=1.0, jitter=2.0,
                              sleeper=sleeper, rng=_FixedRng(0.5))
    rl.request(["req1"])
    rl.request(["req2"])
    rl.request(["req3"])
    # uniform(0, 2.0) fixed at 0.5 -> delay = 1.0 + 0.5 = 1.5 per every non-first
    assert sleeper.calls == [1.5, 1.5]
    assert inner.requests == [["req1"], ["req2"], ["req3"]]


def test_zero_sleep_and_zero_jitter_never_sleeps():
    sleeper = _RecordingSleeper()
    inner = _FakeInner()
    rl = RateLimitedTransport(inner, sleep=0.0, jitter=0.0, sleeper=sleeper)
    for i in range(5):
        rl.request([f"req{i}"])
    assert sleeper.calls == []
    assert len(inner.requests) == 5


def test_close_delegates_to_inner():
    inner = _FakeInner()
    rl = RateLimitedTransport(inner)
    assert inner.closed is False
    rl.close()
    assert inner.closed is True
