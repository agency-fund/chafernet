//! Additional authenticated data: raw bytes, or derived from the purpose and context of a token.

use std::fmt;

use sha2::{Digest, Sha256};

/// The fixed first part of every derived AAD, which keeps it apart from digests other code makes of the same parts.
const PREFIX: &[u8] = b"chafernet.aad.v1";

/// The purpose and context a token is bound to: a `domain` (the purpose of the tokens, such as `"shard-ip"` or
/// `"replica-ip"`) and the `parts` that identify the context (a collection name, a tenant). Given as the
/// [`aad`](crate::Encrypt::aad) of a builder, it stands for a fixed-size digest of its fields, so that no caller has
/// to design a delimiter-safe encoding of several fields, and tokens for one domain never decrypt under another
/// even if the parts coincide.
///
/// The digest is SHA-256 of `"chafernet.aad.v1"`, `domain`, and each part, every one preceded by its length as
/// 8 big-endian bytes. The encoding is injective: because every field, the prefix included, is preceded by its
/// exact length, two different sequences of fields never produce the same bytes, so the digest separates
/// `["ab", ""]` from `["a", "b"]`, a part that happens to hold a delimiter from two parts, and a `domain` from a
/// part. SHA-256 is then a plain hash of that one unambiguous string, with no secret input, so length extension
/// does not apply. Using a `Context` is a choice of the application, not of the format: a token encrypted with the
/// digest as raw `aad` bytes ([`as_bytes`](Self::as_bytes)) is the same token.
///
/// ```
/// use chafernet::{Chafernet, Context, Keyset};
///
/// let chafernet = Chafernet::new(&Keyset::generate());
/// let context = Context::new("list-cursor.v1", &[b"tenant-17", b"orders"]);
/// let cursor = chafernet.encrypt(br#"{"after":1042}"#).aad(context).seal();
/// assert!(chafernet.decrypt(&cursor).aad(context).open().is_ok());
/// // The same parts under another purpose do not decrypt it.
/// let other = Context::new("export-cursor.v1", &[b"tenant-17", b"orders"]);
/// assert!(chafernet.decrypt(&cursor).aad(other).open().is_err());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Context([u8; 32]);

impl Context {
    /// The context of a `domain` and its `parts`.
    #[must_use]
    pub fn new(domain: &str, parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for part in [PREFIX, domain.as_bytes()]
            .into_iter()
            .chain(parts.iter().copied())
        {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    /// The digest the context stands for: the additional authenticated data as the cipher sees it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Context(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// The additional authenticated data of a builder: bytes used as they are, or a [`Context`]. Made by
/// [`Encrypt::aad`](crate::Encrypt::aad) and [`Decrypt::aad`](crate::Decrypt::aad) from what they are given.
#[derive(Clone, Copy)]
pub struct Aad<'a>(Repr<'a>);

#[derive(Clone, Copy)]
enum Repr<'a> {
    Raw(&'a [u8]),
    Context(Context),
}

impl Aad<'_> {
    /// The bytes to authenticate.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Repr::Raw(bytes) => bytes,
            Repr::Context(context) => context.as_bytes(),
        }
    }
}

impl fmt::Debug for Aad<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Repr::Raw(_) => f.write_str("Aad(..)"),
            Repr::Context(context) => write!(f, "Aad({context:?})"),
        }
    }
}

impl<'a> From<&'a [u8]> for Aad<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(Repr::Raw(bytes))
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Aad<'a> {
    fn from(bytes: &'a [u8; N]) -> Self {
        Self(Repr::Raw(bytes))
    }
}

impl<'a> From<&'a Vec<u8>> for Aad<'a> {
    fn from(bytes: &'a Vec<u8>) -> Self {
        Self(Repr::Raw(bytes))
    }
}

impl From<Context> for Aad<'_> {
    fn from(context: Context) -> Self {
        Self(Repr::Context(context))
    }
}

impl From<&Context> for Aad<'_> {
    fn from(context: &Context) -> Self {
        Self(Repr::Context(*context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest as computed by hand from the documented formula, so that other implementations can match it.
    #[test]
    fn known_answer() {
        let mut hasher = Sha256::new();
        for part in [&b"chafernet.aad.v1"[..], b"session", b"user:42", b""] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        let expected: [u8; 32] = hasher.finalize().into();
        let context = Context::new("session", &[b"user:42", b""]);
        assert_eq!(context.as_bytes(), &expected);
        assert_eq!(format!("{context:?}"), format!("Context({VECTOR})"));
    }

    /// `Context::new("session", ["user:42", ""])`, pinned so that a change to the formula is noticed.
    const VECTOR: &str = "69304271712f1288dc3ba52a39088930a3a6609474b72dc9988b64c70420f336";
}
