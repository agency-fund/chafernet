"""Authenticated, encrypted, timestamped tokens using XChaCha20-Poly1305, for Python and Rust.

>>> from chafernet import Chafernet, Context, Keyset
>>> keyset = Keyset.generate()
>>> chafernet = Chafernet(keyset)
>>> context = Context("list-cursor.v1", b"tenant-17", b"orders")
>>> cursor = chafernet.encrypt(b'{"after": 1042}', context)
>>> chafernet.decrypt(cursor, 3600, context)
b'{"after": 1042}'
"""

from chafernet._chafernet import (
    DEFAULT_MAX_CLOCK_SKEW,
    Chafernet,
    Context,
    InvalidTokenError,
    Keyset,
    PlaintextFormatVersionError,
    TokenExpiredError,
    TokenNotYetValidError,
    __version__,
)

__all__ = [
    "DEFAULT_MAX_CLOCK_SKEW",
    "Chafernet",
    "Context",
    "InvalidTokenError",
    "Keyset",
    "PlaintextFormatVersionError",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "__version__",
]
