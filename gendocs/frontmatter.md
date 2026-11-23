{% if target == "github" %}

# chafernet

[![CI]({{ repository }}/actions/workflows/ci.yml/badge.svg?branch=main)]({{ repository
}}/actions/workflows/ci.yml?query=branch%3Amain)

{% endif %}
Chafernet is [Fernet](https://github.com/fernet/spec) with a modern cipher: an authenticated, encrypted, timestamped
token that a server can hand to a client and later read back, trusting that it has not been altered or replayed past its
lifetime. It ships as a {{ repo_link("Rust crate", "chafernet/README.md") }} and a {{ repo_link("Python package",
"python/README.md") }} built from the same Rust code.

A token is `base64url(nonce ‖ XChaCha20-Poly1305(key, nonce, version ‖ timestamp ‖ plaintext, aad))`. Compared with
Fernet:

* The cipher is XChaCha20-Poly1305 (as in libsodium), an AEAD with a random 192-bit nonce, in place of Fernet's
  AES-128-CBC encryption authenticated by a separate HMAC-SHA256, so a token is one AEAD operation under one key
  rather than encrypt-then-MAC under two.
* The timestamp is encrypted along with the plaintext rather than left readable in the token.
* Additional authenticated data (AAD) binds a token to a context, such as a user or a purpose, without storing it in the
  token: a token decrypts only with the AAD it was encrypted with. A {{ api("Context") }} turns a purpose and the fields
  of a context into AAD without the application designing an encoding.
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
secrets manager, keyring, or a KMS, never in source control, and rotate it with {{ api("Keyset::with_new_key()",
"with_new_key()") }} rather than by replacing it, so that tokens in flight still decrypt. Everything a token is bound
to, such as the user or the purpose, belongs in the additional authenticated data.
