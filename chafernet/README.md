<!-- Generated from gendocs/rust.tpl.md by tools/gen_readmes.py; edit the template and run `task readme`. -->
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

This library has [Python bindings](https://github.com/agency-fund/chafernet/tree/main/python#readme).

## Usage

Add a dependency on `chafernet`:

```shell
cargo add chafernet
```

Example:

```rust
use std::time::Duration;

use chafernet::{Chafernet, Context, InvalidToken, Keyset};

fn main() -> Result<(), InvalidToken> {
    let keyset = Keyset::generate();
    let chafernet = Chafernet::new(&keyset);

    // A pagination cursor for one tenant's orders.
    let context = Context::new("list-cursor.v1", &[b"tenant-17", b"orders"]);
    let cursor = chafernet.encrypt(br#"{"after":1042}"#).aad(context).seal();
    let position = chafernet.decrypt(&cursor).aad(context).ttl(Duration::from_secs(3600)).open()?;
    assert_eq!(position, br#"{"after":1042}"#);

    // Another context, another key, or a change to the token is an error, as is a token older than the TTL.
    let invoices = Context::new("list-cursor.v1", &[b"tenant-17", b"invoices"]);
    assert_eq!(chafernet.decrypt(&cursor).aad(invoices).open(), Err(InvalidToken::Unauthenticated));
    Ok(())
}
```

## Crate features

* `wasm_js`: for `wasm32-unknown-unknown` in a JavaScript host (a browser, Node.js, Deno), takes random keys and nonces
  from the host's `crypto.getRandomValues()`, and the current time from `Date.now()`. Without it, the crate builds on
  that target only with a custom getrandom backend, and then has no clock: give every builder `.at()`.

## Design

**Keysets.** A `Keyset` is one or more keys. By convention the first one encrypts, and decrypting tries each in turn, so
keys rotate without breaking tokens in flight: prepend a new key, and once nothing the oldest one encrypted is still
valid, retire it. A keyset's text form is a single string for configuration.

**Hard to misuse.** Nonces are generated inside the crate and cannot be supplied. The additional authenticated data is
set at most once, which the compiler enforces, and a builder does nothing until it is sealed or opened. Every token is
timestamped, a token from the future is rejected even without a TTL, and the TTL is the caller's choice. An
`InvalidToken` indicates the reason a token cannot be used, whether it is not ours, outside its time window, or from an
incompatible version of the library.

**Context is optional.** Without one, a token is bound only to the keys. A `Context` binds it to a purpose and the
fields that identify its use, such as a user or a tenant; it is not stored in the token, and decrypting needs the same
one.

**Keys are zeroized.** Keys, and plaintexts until they are returned, are zeroed when dropped; `Key`, `Keyset`, and
`Chafernet` are not `Clone`, so copies of key material are made only inside the crate, where each is zeroed. Keys are
compared in constant time and never shown by `Debug`.

The crate has no `unsafe` code and depends on the RustCrypto `chacha20poly1305` crate for the cipher.

## Minimum Rust version

1.93.0.

## License

MIT; see [LICENSE](https://github.com/agency-fund/chafernet/blob/main/LICENSE).
