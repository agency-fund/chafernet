"""Tests of what the binding adds to the crate: argument conversion, exceptions, Context, and Keyset from Python.

The behavior of tokens (authentication, tampering, time checks, rotation) and the test vectors are tested in Rust,
in chafernet/tests/public_api.rs and chafernet/src.
"""

import base64
import json

import pytest

import chafernet
from chafernet import (
    DEFAULT_MAX_CLOCK_SKEW,
    Chafernet,
    Context,
    InvalidTokenError,
    Keyset,
    PlaintextFormatVersionError,
    TokenExpiredError,
    TokenNotYetValidError,
)


@pytest.fixture
def keyset() -> Keyset:
    return Keyset.generate()


@pytest.fixture
def chaf(keyset: Keyset) -> Chafernet:
    return Chafernet(keyset)


def test_round_trip(chaf):
    token = chaf.encrypt(b"hello", b"aad")
    assert isinstance(token, str)
    assert chaf.decrypt(token, 60, b"aad") == b"hello"
    assert chaf.decrypt(token, None, aad=b"aad") == b"hello"


def test_decrypt_with_timestamp(chaf):
    token = chaf.encrypt(b"hello", b"aad", current_time=100)
    assert chaf.decrypt_with_timestamp(token, 10, b"aad", current_time=110) == (b"hello", 100)
    assert chaf.decrypt_with_timestamp(token, None, aad=b"aad", current_time=10**9) == (b"hello", 100)
    with pytest.raises(TypeError):
        chaf.decrypt_with_timestamp(token)  # type: ignore[call-arg]


def test_str_plaintext_is_utf8(chaf):
    token = chaf.encrypt("héllo")
    assert chaf.decrypt(token, 60) == "héllo".encode()
    with pytest.raises(TypeError, match="plaintext must be str or bytes, not int"):
        chaf.encrypt(1)  # type: ignore[arg-type]


def test_aad_is_bytes_context_or_none(chaf):
    token = chaf.encrypt(b"x")
    assert chaf.decrypt(token, None) == b"x"
    assert chaf.decrypt(token, None, aad=b"") == b"x"
    assert chaf.decrypt(token, None, aad=None) == b"x"
    for aad in ["str", 1, [b"p"], bytearray(b"p")]:
        message = f"aad must be bytes or a Context, not {type(aad).__name__}"
        with pytest.raises(TypeError, match=message):
            chaf.encrypt(b"x", aad)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match=message):
            chaf.decrypt(token, None, aad)  # type: ignore[arg-type]


def test_signatures(chaf, keyset):
    token = chaf.encrypt(b"x")
    with pytest.raises(TypeError):
        chaf.decrypt(token)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        chaf.encrypt(b"x", b"aad", 100)  # type: ignore[misc]
    with pytest.raises(TypeError):
        chaf.decrypt(token, 60, b"", 100)  # type: ignore[misc]
    with pytest.raises(TypeError):
        Chafernet(keyset, 5)  # type: ignore[misc]


def test_integer_arguments(chaf, keyset):
    token = chaf.encrypt(b"x", current_time=100)
    assert chaf.decrypt(token, 0, current_time=100) == b"x"
    last = chaf.encrypt(b"x", current_time=2**64 - 1)
    assert chaf.decrypt(last, 2**64 - 1, current_time=2**64 - 1) == b"x"
    assert Chafernet(keyset, max_clock_skew=2**64 - 1).decrypt(token, None, current_time=0) == b"x"
    assert Chafernet(keyset, max_clock_skew=0).decrypt(token, None, current_time=100) == b"x"
    with pytest.raises(ValueError, match="ttl must not be negative"):
        chaf.decrypt(token, -1, current_time=100)
    with pytest.raises(ValueError, match="ttl must be less than 2\\*\\*64"):
        chaf.decrypt(token, 2**64, current_time=100)
    with pytest.raises(ValueError, match="current_time must not be negative"):
        chaf.encrypt(b"x", current_time=-1)
    with pytest.raises(ValueError, match="current_time must not be negative"):
        chaf.decrypt(token, 30, current_time=-1)
    with pytest.raises(ValueError, match="current_time must be less than 2\\*\\*64"):
        chaf.encrypt(b"x", current_time=2**64)
    with pytest.raises(ValueError, match="max_clock_skew must not be negative"):
        Chafernet(keyset, max_clock_skew=-1)
    with pytest.raises(ValueError, match="max_clock_skew must be less than 2\\*\\*64"):
        Chafernet(keyset, max_clock_skew=2**64)
    # Beyond any fixed-width conversion, still the same ValueError rather than an OverflowError.
    with pytest.raises(ValueError, match="ttl must be less than 2\\*\\*64"):
        chaf.decrypt(token, 2**200, current_time=100)
    with pytest.raises(ValueError, match="max_clock_skew must not be negative"):
        Chafernet(keyset, max_clock_skew=-(2**200))
    with pytest.raises(TypeError):
        chaf.decrypt(token, 1.5)  # type: ignore[arg-type]


def test_exceptions():
    assert issubclass(InvalidTokenError, Exception) and not issubclass(InvalidTokenError, ValueError)
    subclasses = [TokenExpiredError, TokenNotYetValidError, PlaintextFormatVersionError]
    assert all(issubclass(error, InvalidTokenError) for error in subclasses)
    assert str(InvalidTokenError("why")) == "why" and InvalidTokenError("why").args == ("why",)
    assert str(TokenExpiredError("old")) == "old"
    for error in [InvalidTokenError, *subclasses]:
        assert error.__module__ == "chafernet" and error.__name__.endswith("Error")


@pytest.mark.parametrize(
    "base", [InvalidTokenError, TokenExpiredError, TokenNotYetValidError, PlaintextFormatVersionError]
)
def test_exceptions_subclass_with_their_own_init(base):
    class SessionTokenError(base):  # type: ignore[misc, valid-type]
        def __init__(self, user: str, reason: str) -> None:
            super().__init__(f"{user}: {reason}")
            self.user = user

    error = SessionTokenError("alice", "expired")
    assert str(error) == "alice: expired" and error.user == "alice" and isinstance(error, InvalidTokenError)


def test_invalid_token_error(chaf):
    with pytest.raises(InvalidTokenError) as raised:
        chaf.decrypt(chaf.encrypt(b"x", b"aad"), None, b"other")
    assert type(raised.value) is InvalidTokenError and str(raised.value)


def test_token_expired_error(chaf):
    with pytest.raises(TokenExpiredError) as raised:
        chaf.decrypt(chaf.encrypt(b"x", current_time=100), 30, current_time=131)
    # The timestamp is an attribute and stays out of the message, which may be shown to the token's holder.
    assert raised.value.timestamp == 100 and str(raised.value) == "token has expired"
    assert TokenExpiredError("old").timestamp is None


def test_token_not_yet_valid_error(chaf):
    with pytest.raises(TokenNotYetValidError) as raised:
        chaf.decrypt(chaf.encrypt(b"x", current_time=100), None, current_time=100 - DEFAULT_MAX_CLOCK_SKEW - 1)
    assert raised.value.timestamp == 100 and str(raised.value) == "token's timestamp is in the future"
    assert TokenNotYetValidError("early").timestamp is None


def test_plaintext_format_version_error():
    # A genuine token whose version byte is 2, made with PyNaCl as tools/gen_vectors.py makes its tokens: the key is
    # bytes(range(32)), the nonce 24 zero bytes, the timestamp 100, and the plaintext b"x".
    chaf = Chafernet(Keyset.from_keys(["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]))
    token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlwaMx-yI5Rly9vXLR15y_lEylW-OpAIuyS4="
    with pytest.raises(PlaintextFormatVersionError, match="plaintext format version 2; only 1 is supported"):
        chaf.decrypt(token, None, current_time=100)


def test_context_and_its_digest_are_interchangeable(chaf):
    context = Context("session", b"user:42", b"10.0.0.7")
    assert isinstance(context.digest, bytes) and len(context.digest) == 32
    token = chaf.encrypt(b"x", context)
    assert chaf.decrypt(token, None, Context("session", b"user:42", b"10.0.0.7")) == b"x"
    assert chaf.decrypt(token, None, aad=context.digest) == b"x"
    assert chaf.decrypt(chaf.encrypt(b"x", context.digest), None, context) == b"x"
    # A domain alone is a context too.
    assert chaf.decrypt(chaf.encrypt(b"x", Context("session")), None, Context("session")) == b"x"


def test_context_is_a_value():
    context = Context("session", b"user:42", b"")
    assert context == Context("session", b"user:42", b"")
    assert hash(context) == hash(Context("session", b"user:42", b""))
    assert context != Context("session", b"user:42")
    assert context != context.digest
    assert context.__eq__(context.digest) is NotImplemented
    assert {context, Context("session", b"user:42", b"")} == {context}
    assert repr(context) == f"<Context {context.digest.hex()}>"
    with pytest.raises(AttributeError):
        context.digest = b"other"  # type: ignore[misc]
    with pytest.raises(TypeError, match="parts must be bytes, not str"):
        Context("d", "not bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Context(b"not str", b"p")  # type: ignore[arg-type]


def keys_of(keyset: Keyset) -> list[str]:
    """The keys in base64, from the JSON text form: Keyset does not hand out its keys."""
    keys: list[str] = json.loads(keyset.to_json())["keys"]
    return keys


def test_keyset_text_forms(keyset):
    text = keyset.to_base64()
    assert Keyset.from_base64(text) == keyset
    assert Chafernet(text).decrypt(Chafernet(keyset).encrypt(b"x"), None) == b"x"
    document = json.loads(base64.standard_b64decode(text))
    assert list(document) == ["keys"] and len(base64.standard_b64decode(document["keys"][0])) == 32
    assert keyset.to_json() == json.dumps(document, separators=(",", ":"))
    assert Keyset.from_json(keyset.to_json()) == keyset
    assert Keyset.from_keys(document["keys"]) == keyset
    assert keyset != keyset.with_new_key()
    assert keyset != text
    assert keyset.__eq__(text) is NotImplemented
    assert repr(keyset) == "<Keyset with 1 keys>"
    assert repr(Chafernet(keyset)) == "<Chafernet(1 keys)>"


def test_keyset_text_may_be_bytes_like(keyset):
    text, json_text = keyset.to_base64(), keyset.to_json()
    for convert in [str.encode, lambda t: bytearray(t.encode()), lambda t: memoryview(t.encode())]:
        assert Keyset.from_base64(convert(text)) == keyset
        assert Keyset.from_json(convert(json_text)) == keyset
        assert Keyset.from_keys([convert(key) for key in keys_of(keyset)]) == keyset
        assert Chafernet(convert(text)).decrypt(Chafernet(keyset).encrypt(b"x"), None) == b"x"
    with pytest.raises(ValueError):
        Keyset.from_base64(b"\xff")
    with pytest.raises(TypeError, match="expected str or a bytes-like object, not int"):
        Keyset.from_base64(1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="keyset must be a Keyset, str, or bytes-like object, not int"):
        Chafernet(42)  # type: ignore[arg-type]


def test_keyset_buffers_can_be_wiped(keyset):
    for buffer, text in [
        (keyset.to_base64_buffer(), keyset.to_base64()),
        (keyset.to_json_buffer(), keyset.to_json()),
    ]:
        assert type(buffer) is bytearray and buffer == text.encode()
        buffer[:] = bytes(len(buffer))
        assert buffer == bytes(len(text))
    assert Keyset.from_base64(keyset.to_base64_buffer()) == keyset


def test_key_rotation():
    first = Keyset.generate()
    token = Chafernet(first).encrypt(b"x")
    second = first.with_new_key()
    assert (len(first), len(second), len(second.without_oldest())) == (1, 2, 1)
    assert keys_of(second)[1:] == keys_of(first)
    assert Chafernet(second).decrypt(token, None) == b"x"
    assert second.without_oldest() == Keyset.from_keys(keys_of(second)[:1])
    with pytest.raises(ValueError, match="only one key"):
        first.without_oldest()


def test_keyset_errors():
    for bad in [
        lambda: Keyset.from_base64("!"),
        lambda: Keyset.from_json("[]"),
        lambda: Keyset.from_keys([]),
        lambda: Chafernet("!"),
    ]:
        with pytest.raises(ValueError) as raised:
            bad()
        assert str(raised.value)


def test_module():
    assert isinstance(chafernet.__version__, str)
    assert DEFAULT_MAX_CLOCK_SKEW == 30
