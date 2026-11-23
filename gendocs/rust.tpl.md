{% include "frontmatter.md" %}

This library has [Python bindings]({{ repository }}/tree/main/python#readme).

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

**Keysets.** A {{ api("Keyset") }} is one or more keys. By convention the first one encrypts, and decrypting tries each
in turn, so keys rotate without breaking tokens in flight: prepend a new key, and once nothing the oldest one encrypted
is still valid, retire it. A keyset's text form is a single string for configuration.

**Hard to misuse.** Nonces are generated inside the crate and cannot be supplied. The additional authenticated data is
set at most once, which the compiler enforces, and a builder does nothing until it is sealed or opened. Every token is
timestamped, a token from the future is rejected even without a TTL, and the TTL is the caller's choice. An {{
api("InvalidToken") }} indicates the reason a token cannot be used, whether it is not ours, outside its time window, or
from an incompatible version of the library.

**Context is optional.** Without one, a token is bound only to the keys. A {{ api("Context") }} binds it to a purpose
and the fields that identify its use, such as a user or a tenant; it is not stored in the token, and decrypting needs
the same one.

**Keys are zeroized.** Keys, and plaintexts until they are returned, are zeroed when dropped; {{ api("Key") }}, {{
api("Keyset") }}, and {{ api("Chafernet") }} are not `Clone`, so copies of key material are made only inside the crate,
where each is zeroed. Keys are compared in constant time and never shown by `Debug`.

The crate has no `unsafe` code and depends on the RustCrypto `chacha20poly1305` crate for the cipher.

## Minimum Rust version

{{ rust_version }}.

{% include "footer.md" %}
