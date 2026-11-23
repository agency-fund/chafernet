<!-- Generated from gendocs/python.tpl.md by tools/gen_readmes.py; edit the template and run `task readme`. -->
# chafernet

[![CI](https://github.com/agency-fund/chafernet/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agency-fund/chafernet/actions/workflows/ci.yml?query=branch%3Amain)

Chafernet is [Fernet](https://github.com/fernet/spec) with a modern cipher: an authenticated, encrypted, timestamped
token that a server can hand to a client and later read back, trusting that it has not been altered or replayed past its
lifetime. It ships as a Rust crate and a Python package built from the same Rust code.

A token is `base64url(nonce ‖ XChaCha20-Poly1305(key, nonce, version ‖ timestamp ‖ plaintext, aad))`. Compared with
Fernet:

* The cipher is XChaCha20-Poly1305 (as in libsodium), an AEAD with a random 192-bit nonce, in place of Fernet's
  AES-128-CBC encryption authenticated by a separate HMAC-SHA256, so a token is one AEAD operation under one key rather
  than encrypt-then-MAC under two.
* The timestamp is encrypted along with the plaintext rather than left readable in the token.
* Additional authenticated data (AAD) binds a token to a context, such as a user or a purpose, without storing it in the
  token: a token decrypts only with the AAD it was encrypted with. A `Context` turns a purpose and the fields of a
  context into AAD without the application designing an encoding.
* A keyset holds several keys, so that keys can be rotated: the first key encrypts, and every key is tried when
  decrypting.

Decrypting checks a time-to-live and tolerates some clock skew, as Fernet does, but more strictly: a token from the
future is rejected even without a time-to-live, and the skew allowed is 30 seconds (configurable) rather than 60.

> [!IMPORTANT]
> chafernet is
> [Level 5: Bots coded, human understands completely](https://www.visidata.org/blog/2026/ai/#level-5%3A-bots-coded%2C-human-understands-completely)

## When to use it

A Chafernet token is for state a server hands to a client and later reads back without keeping a copy.

> [!TIP]
> If you are looking for session tokens and the server can keep a table, a random identifier looked up in that table is
> simpler, revocable at once, and has nothing to parse.

The keyset is the secret key, unencrypted. Store it somewhere only your service can read, such as your platform's
secrets manager, keyring, or a KMS, never in source control, and rotate it with `with_new_key()` rather than by
replacing it, so that tokens in flight still decrypt. Everything a token is bound to, such as the user or the purpose,
belongs in the additional authenticated data.

This package wraps the [chafernet](https://github.com/agency-fund/chafernet/tree/main/chafernet#readme) Rust crate.

```shell
uv add chafernet
```

chafernet supports CPython 3.14 and 3.15, including the free-threaded builds. Wheels are built for manylinux (glibc
2.28+) and musllinux (musl 1.2+, as in Alpine) on x86_64 and aarch64, for macOS on x86_64 and arm64, and for Windows on
x64 and ARM64.

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
  token that passed the time checks. One that failed them has its timestamp on the exception, as `timestamp`, and not in
  the message.
* `ttl` is a required argument of `decrypt`, so that a token's lifetime is a decision rather than an omission.
* The time checks are stricter: a token from the future is rejected even with `ttl=None`, where Fernet skips both
  checks, and the clock skew allowed is 30 seconds rather than 60, and is set per `Chafernet` rather than fixed.
* Tokens are not interchangeable with Fernet's: the cipher, the layout, and the key format all differ.

## License

MIT; see [LICENSE](https://github.com/agency-fund/chafernet/blob/main/LICENSE).
