{% include "frontmatter.md" %}

This package wraps the [chafernet]({{ repository }}/tree/main/chafernet#readme) Rust crate.

```shell
uv add chafernet
```

chafernet supports CPython {{ python_versions }}, including the free-threaded builds. Wheels are built for manylinux
(glibc 2.28+) and musllinux (musl 1.2+, as in Alpine) on x86_64 and aarch64, for macOS on x86_64 and arm64, and for
Windows on x64 and ARM64.

```python
>>> from chafernet import Chafernet, Context, InvalidTokenError, Keyset
>>> keyset = Keyset.generate()
>>> chafernet = Chafernet(keyset)
>>> # A pagination cursor for one tenant's orders.
>>> context = Context("list-cursor.v1", b"tenant-17", b"orders")
>>> cursor = chafernet.encrypt(b'{"after": 1042}', context)
>>> chafernet.decrypt(cursor, 3600, context)
b'{"after": 1042}'
>>> chafernet.decrypt(cursor, 3600, Context("list-cursor.v1", b"tenant-17", b"invoices"))
Traceback (most recent call last):
    ...
chafernet.InvalidTokenError: token was not encrypted with these keys and this aad, or has been altered

```

## Design

**Keysets.** A `Keyset` is one or more keys. By convention the first one encrypts, and decrypting tries each in turn, so
keys rotate without breaking tokens in flight: add a new key in front, and once nothing the oldest one encrypted is
still valid, drop it. A keyset's text form is a single string for configuration.

**Hard to misuse.** Nonces are generated inside the library and cannot be supplied. `decrypt` takes a `ttl` with no
default, so a token's lifetime is always a decision. The additional authenticated data is one argument, a `Context` or
raw `bytes`. A bad token raises `InvalidTokenError`, with subclasses for a genuine token that cannot be used: one
outside its time window, or one in a plaintext format this version cannot read. It is not a `ValueError`, so a wrong
call is never mistaken for a bad token.

**Context is optional.** Without one, a token is bound only to the keys. A `Context` binds it to a purpose and the
fields that identify its use, such as a user or a tenant; it is not stored in the token, and decrypting needs the same
one.

**Key material in memory.** The Rust core zeroes the keys and plaintexts it holds. Python cannot wipe a `str` or the
`bytes` that `decrypt` returns, so `to_base64()` and `to_json()` have variants that return a `bytearray`, to wipe after
use.

## Compared with Fernet

The API follows `cryptography.fernet.Fernet` and `MultiFernet`: `encrypt` and `decrypt`, with `ttl` in seconds. The
differences:

* Tokens are bound to a purpose and context with an `aad` argument: a `Context` or raw `bytes`.
* The exception is `InvalidTokenError`, named as PEP 8 asks, rather than `InvalidToken`.
* `current_time=` replaces `encrypt_at_time` and `decrypt_at_time`.
* `decrypt_with_timestamp` replaces `extract_timestamp`: it returns the timestamp with the plaintext, and only for a
  token that passed the time checks. One that failed them has its timestamp on the exception, as `timestamp`, and
  not in the message.
* `ttl` is a required argument of `decrypt`, so that a token's lifetime is a decision rather than an omission.
* The time checks are stricter: a token from the future is rejected even with `ttl=None`, where Fernet skips both
  checks, and the clock skew allowed is 30 seconds rather than 60, and is set per `Chafernet` rather than fixed.
* Tokens are not interchangeable with Fernet's: the cipher, the layout, and the key format all differ.

{% include "footer.md" %}
