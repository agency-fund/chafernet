"""Property-based tests of the conversion layer: every 64-bit timestamp, str plaintext, and Context argument crosses
from Python to Rust and back intact. That the cipher round-trips, and matches libsodium, is tested in Rust."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from chafernet import Chafernet, Context, Keyset, TokenExpiredError, TokenNotYetValidError

CHAF = Chafernet(Keyset.generate())
# With no clock skew allowed and a ttl of 0, a token decrypts only at the second of its timestamp.
EXACT = Chafernet(Keyset.generate(), max_clock_skew=0)

timestamps = st.integers(min_value=0, max_value=2**64 - 1)


@given(timestamps)
def test_timestamps_cross_intact(timestamp):
    token = EXACT.encrypt(b"x", current_time=timestamp)
    assert EXACT.decrypt_with_timestamp(token, 0, current_time=timestamp) == (b"x", timestamp)
    if timestamp > 0:
        with pytest.raises(TokenNotYetValidError) as early:
            EXACT.decrypt(token, 0, current_time=timestamp - 1)
        assert early.value.timestamp == timestamp
    if timestamp < 2**64 - 1:
        with pytest.raises(TokenExpiredError) as late:
            EXACT.decrypt(token, 0, current_time=timestamp + 1)
        assert late.value.timestamp == timestamp


@given(st.text())
def test_str_plaintext_is_utf8(plaintext):
    assert CHAF.decrypt(CHAF.encrypt(plaintext), None) == plaintext.encode()


@given(st.text(), st.lists(st.binary()))
def test_context_and_its_digest_are_interchangeable(domain, parts):
    context = Context(domain, *parts)
    assert context == Context(domain, *parts)
    assert CHAF.decrypt(CHAF.encrypt(b"x", context), None, context.digest) == b"x"
