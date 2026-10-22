import pytest

from mcp_tenant_gate.ratelimit import FakeClock, RateLimiter, TokenBucket


def test_bucket_allows_capacity_then_blocks():
    b = TokenBucket(3, 1, FakeClock())
    assert [b.try_take() for _ in range(4)] == [True, True, True, False]


def test_bucket_refills_with_time_and_caps_at_capacity():
    clock = FakeClock()
    b = TokenBucket(2, 1, clock)
    b.try_take()
    b.try_take()
    assert not b.try_take()
    clock.advance(1.0)
    assert b.try_take() and not b.try_take()
    clock.advance(1000)
    assert b.tokens == pytest.approx(2.0)


def test_clock_going_backwards_adds_nothing():
    clock = FakeClock(100)
    b = TokenBucket(1, 10, clock)
    assert b.try_take()
    clock.now = 50
    assert not b.try_take()


def test_zero_refill_is_a_hard_quota():
    clock = FakeClock()
    b = TokenBucket(2, 0, clock)
    b.try_take()
    b.try_take()
    clock.advance(10 ** 6)
    assert not b.try_take()


def test_buckets_are_per_tenant():
    rl = RateLimiter(FakeClock())
    assert all(rl.allow("a", 5, 1) for _ in range(5))
    assert not rl.allow("a", 5, 1)
    assert rl.allow("b", 5, 1)  # tenant a's flood does not starve tenant b


@pytest.mark.parametrize("cap,refill", [(0, 1), (-1, 1), (1, -1)])
def test_bad_bucket_settings(cap, refill):
    with pytest.raises(ValueError):
        TokenBucket(cap, refill, FakeClock())
