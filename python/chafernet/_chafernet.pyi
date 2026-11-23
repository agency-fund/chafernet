# Generated from the Rust source by `task stubs`; do not edit.
from collections.abc import Buffer, Sequence
from typing import Any, Final, final
from typing_extensions import disjoint_base

__all__ = ["DEFAULT_MAX_CLOCK_SKEW", "__version__", "Chafernet", "Context", "InvalidTokenError", "Keyset", "PlaintextFormatVersionError", "TokenExpiredError", "TokenNotYetValidError"]

DEFAULT_MAX_CLOCK_SKEW: Final[int]
"""
How many seconds in the future a token's timestamp may be before ``decrypt`` rejects it, allowing for clocks
that disagree slightly, unless a ``Chafernet`` is made with another ``max_clock_skew``.
"""

__version__: Final[str]
"""
The version of the package.
"""

@final
class Chafernet:
    """
    Encrypts and decrypts tokens with a ``Keyset``.

    A token is ``base64url(nonce ‖ XChaCha20-Poly1305(key, nonce, version ‖ timestamp ‖ plaintext, aad))``: a random
    24-byte nonce, then the ciphertext of a version byte (1), the timestamp as 8 big-endian bytes of seconds since the
    Unix epoch, and the plaintext, with the 16-byte authentication tag at the end.

    The additional authenticated data (``aad``) is not stored in the token; the same value must be given to decrypt
    it, which binds the token to its purpose and context without revealing them. It is a ``Context`` (a domain and
    parts, whose digest is the data) or ``bytes`` used as they are; omitted, it is empty.
    """
    def __new__(cls, keyset: Keyset | str | Buffer, /, *, max_clock_skew: int = ...) -> Chafernet:
        """
        A Chafernet that encrypts with the keyset's first key and decrypts with any of its keys. ``keyset`` may also
        be the text form of a keyset, as ``Keyset.to_base64()`` writes it. ``max_clock_skew`` is how many seconds in
        the future a token's timestamp may be before ``decrypt`` rejects it, allowing for clocks that disagree
        slightly; the default is ``DEFAULT_MAX_CLOCK_SKEW``.

        Raises:
            ValueError: ``keyset`` is text that is not a keyset, or ``max_clock_skew`` is negative or 2**64 or more.
        """
    def __repr__(self, /) -> str: ...
    def decrypt(self, token: str, ttl: int | None, /, aad: bytes | Context | None = None, *, current_time: int | None = None) -> bytes:
        """
        Decrypts ``token``, checking its timestamp against the current time: with a ``ttl`` in seconds, the token must
        have been encrypted no more than ``ttl`` seconds ago, and in any case no more than ``max_clock_skew`` seconds
        in the future. ``ttl=None`` accepts a token however old. ``aad`` is as for ``encrypt`` and must match what
        the token was encrypted with; ``current_time`` replaces the clock.

        Raises:
            InvalidTokenError: ``token`` cannot be decoded, was not encrypted with one of the keys and this additional
                authenticated data, or has been altered.
            PlaintextFormatVersionError: ``token`` is genuine but has another plaintext format version.
            TokenExpiredError: ``token`` is older than ``ttl``.
            TokenNotYetValidError: ``token`` has a timestamp more than ``max_clock_skew`` seconds in the future.
            ValueError: ``ttl`` or ``current_time`` is negative or 2**64 or more.
        """
    def decrypt_with_timestamp(self, token: str, ttl: int | None, /, aad: bytes | Context | None = None, *, current_time: int | None = None) -> tuple[bytes, int]:
        """
        Decrypts ``token`` as ``decrypt`` does, with the same arguments and the same time checks, and returns the
        plaintext and the token's timestamp, in seconds since the Unix epoch: for a caller that acts on a token's age,
        such as one that replaces a token halfway through its life. A token that fails the time checks gives its
        timestamp only on the exception, as ``TokenExpiredError.timestamp`` or ``TokenNotYetValidError.timestamp``,
        and never as a result.

        Raises:
            InvalidTokenError: ``token`` cannot be decoded, was not encrypted with one of the keys and this additional
                authenticated data, or has been altered.
            PlaintextFormatVersionError: ``token`` is genuine but has another plaintext format version.
            TokenExpiredError: ``token`` is older than ``ttl``.
            TokenNotYetValidError: ``token`` has a timestamp more than ``max_clock_skew`` seconds in the future.
            ValueError: ``ttl`` or ``current_time`` is negative or 2**64 or more.
        """
    def encrypt(self, plaintext: str | bytes, /, aad: bytes | Context | None = None, *, current_time: int | None = None) -> str:
        """
        Encrypts ``plaintext`` (``str`` as UTF-8) into a token.

        The additional authenticated data is ``aad``: a ``Context`` (the purpose of the tokens, such as
        ``"shard-ip"``, and the fields of the context: a collection name, a tenant), or ``bytes`` used as they are;
        omitted, it is empty. The timestamp is the current time, or ``current_time`` in seconds since the Unix epoch.

        Raises:
            ValueError: ``current_time`` is negative or 2**64 or more.
        """

@final
class Context:
    """
    The purpose and context a token is bound to: a ``domain`` (``"shard-ip"``) and the ``parts`` that identify the
    context (a collection name, a tenant). Passed as the ``aad`` of ``encrypt`` and ``decrypt``, it stands for its
    ``digest``: 32 bytes, the SHA-256 digest of ``"chafernet.aad.v1"``, ``domain``, and each part, every one preceded
    by its length as 8 big-endian bytes. A token encrypted with a ``Context`` and one encrypted with its ``digest``
    as raw ``aad`` are the same token.

    A ``Context`` keeps only its digest. It is a value: equal to another with the same digest, which means the same
    domain and parts, hashable, and immutable.
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __new__(cls, domain: str, /, *parts: bytes) -> Context: ...
    def __repr__(self, /) -> str: ...
    @property
    def digest(self, /) -> bytes:
        """
        The additional authenticated data the context stands for.
        """

@disjoint_base
class InvalidTokenError(Exception):
    """
    Raised by ``decrypt`` and ``decrypt_with_timestamp`` when a token cannot be decrypted: it is not a token, was not
    encrypted with one of the keys and the same ``aad``, or has been altered. The message says which.

    Its subclasses are raised for a token that is genuine, encrypted with one of the keys and the same ``aad``, but
    cannot be used: ``TokenExpiredError`` and ``TokenNotYetValidError`` for one outside its time window, and
    ``PlaintextFormatVersionError`` for one in a format this version of the package cannot read. An ``InvalidTokenError``
    that is none of them is a token that is not ours, or is damaged.

    A plain ``Exception`` rather than a ``ValueError``, as ``cryptography.fernet.InvalidToken`` is, so that code
    catching bad tokens does not also catch the ``ValueError`` and ``TypeError`` that a wrong call raises.
    """
    def __new__(cls, /, *args: object) -> InvalidTokenError:
        """
        The arguments are passed on to Exception, so ``args`` holds them and ``str()`` is the message. Any arguments are
        accepted, so that a subclass can define ``__init__`` with its own.
        """

@final
class Keyset:
    """
    The keys a ``Chafernet`` uses: the first encrypts, and all are tried in order to decrypt.

    To rotate keys, prepend a new one with ``with_new_key()``, deploy the new keyset everywhere, and drop the old key
    with ``without_oldest()`` once every token it encrypted has expired. The text form, ``to_base64()``, is standard base64 of the JSON document
    ``{"keys":["<base64 key>",...]}``, for passing a keyset in configuration.
    """
    def __eq__(self, other: object, /) -> Any: ...
    def __len__(self, /) -> int:
        """
        The number of keys, at least one.
        """
    def __repr__(self, /) -> str: ...
    @staticmethod
    def from_base64(text: str | Buffer) -> Keyset:
        """
        A keyset from its text form, as ``to_base64()`` writes it, given as ``str`` or as a bytes-like object.

        Raises:
            ValueError: ``text`` is not base64, does not decode to the JSON document, or holds no key or a key that is
                not valid.
        """
    @staticmethod
    def from_json(json: str | Buffer) -> Keyset:
        """
        A keyset from its JSON form, ``{"keys":["<base64 key>",...]}``, given as ``str`` or as a bytes-like object.

        Raises:
            ValueError: ``json`` is not that document, or holds no key or a key that is not valid.
        """
    @staticmethod
    def from_keys(keys: Sequence[str | Buffer]) -> Keyset:
        """
        A keyset from keys in base64, each a ``str`` or a bytes-like object, the first of which encrypts.

        Raises:
            ValueError: ``keys`` is empty or holds a key that is not valid base64 of 32 bytes.
        """
    @staticmethod
    def generate() -> Keyset:
        """
        A keyset holding one new random key.
        """
    def to_base64(self, /) -> str:
        """
        The keyset as standard base64 of its JSON form.

        Python cannot wipe a ``str``, so the key material stays in memory until it is overwritten. Where that matters,
        use ``to_base64_buffer()``.
        """
    def to_base64_buffer(self, /) -> bytearray:
        """
        ``to_base64()`` as a ``bytearray``, which the caller can wipe once done with it, as in
        ``buffer[:] = bytes(len(buffer))``. Any ``str`` or ``bytes`` made from it is a copy that cannot be wiped.
        """
    def to_json(self, /) -> str:
        """
        The keyset as compact JSON, ``{"keys":["<base64 key>",...]}``.

        Python cannot wipe a ``str``, so the key material stays in memory until it is overwritten. Where that matters,
        use ``to_json_buffer()``.
        """
    def to_json_buffer(self, /) -> bytearray:
        """
        ``to_json()`` as a ``bytearray``, which the caller can wipe once done with it, as in
        ``buffer[:] = bytes(len(buffer))``. Any ``str`` or ``bytes`` made from it is a copy that cannot be wiped.
        """
    def with_new_key(self, /) -> Keyset:
        """
        A copy of the keyset with a new random key prepended, which becomes the one that encrypts.
        """
    def without_oldest(self, /) -> Keyset:
        """
        A copy of the keyset without its last key, the oldest.

        Raises:
            ValueError: the keyset has only one key.
        """

@disjoint_base
class PlaintextFormatVersionError(InvalidTokenError):
    """
    Raised by ``decrypt`` for a token that is genuine but whose plaintext format version is not
    the one this version of the package reads: it was made by another implementation, newer or older, that holds the
    same keys. It is not a sign of forgery, and trying again does not help. When a format version is introduced, every
    reader must understand it before any writer produces it.

    The version is a byte encrypted with the plaintext, so it covers the layout of the plaintext only. A token made with
    another cipher or nonce length never authenticates, and raises a plain ``InvalidTokenError``.
    """
    def __new__(cls, /, *args: object) -> PlaintextFormatVersionError: ...

@disjoint_base
class TokenExpiredError(InvalidTokenError):
    """
    Raised by ``decrypt`` for a token that is genuine but older than ``ttl``.
    """
    def __new__(cls, /, *args: object) -> TokenExpiredError: ...
    @property
    def timestamp(self, /) -> int | None:
        """
        The token's timestamp, in seconds since the Unix epoch, to tell a token that has just expired from one long
        dead; ``None`` on an instance made in Python. It is genuine, but the token's holder cannot read it, so it is
        not in the message; pass it on only where that is meant.
        """

@disjoint_base
class TokenNotYetValidError(InvalidTokenError):
    """
    Raised by ``decrypt`` for a token that is genuine but has a timestamp more than the ``Chafernet``'s
    ``max_clock_skew`` seconds in the future.
    """
    def __new__(cls, /, *args: object) -> TokenNotYetValidError: ...
    @property
    def timestamp(self, /) -> int | None:
        """
        The token's timestamp, in seconds since the Unix epoch, to see how far apart the clocks are; ``None`` on an
        instance made in Python. As for ``TokenExpiredError``, it is not in the message.
        """
