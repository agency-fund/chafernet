//! Keys and keysets.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::TryRng as _;
use rand::rngs::SysRng;
use serde::Deserialize;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

/// The length of a key in bytes.
pub const KEY_LEN: usize = 32;

/// A 256-bit XChaCha20-Poly1305 key.
///
/// Keys are zeroed when dropped, compared in constant time, and never shown by `Debug`. The text form is standard
/// base64 with padding, 44 characters long. Zeroing is best effort: the text forms this crate returns, and copies the
/// caller makes, are ordinary strings and arrays.
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// A new random key from the operating system's random number generator.
    ///
    /// # Panics
    ///
    /// If the operating system's random number generator fails.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .expect("the operating system's random number generator failed");
        Self(bytes)
    }

    /// A key from its bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Decodes a key from its base64 text form, as [`to_base64`](Self::to_base64) writes it, given as `&str` or as
    /// bytes. Surrounding ASCII whitespace (a trailing newline from a file) is ignored.
    ///
    /// # Errors
    ///
    /// [`KeyError`] if the text is not base64, or decodes to other than 32 bytes.
    pub fn from_base64(text: impl AsRef<[u8]>) -> Result<Self, KeyError> {
        let mut decoded = BASE64
            .decode(text.as_ref().trim_ascii())
            .map_err(|_| KeyError::Base64)?;
        let key = <[u8; KEY_LEN]>::try_from(decoded.as_slice())
            .map(Self)
            .map_err(|_| KeyError::Length(decoded.len()));
        decoded.zeroize();
        key
    }

    /// The key as standard base64 with padding, in a string that is zeroized when dropped.
    #[must_use]
    pub fn to_base64(&self) -> Zeroizing<String> {
        // A slice rather than the array, which encode() would take by value and so copy.
        Zeroizing::new(BASE64.encode(self.0.as_slice()))
    }

    /// The key's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// A copy of the key. Not `Clone`, so that copies of key material are made only here, by the keyset, where each
    /// is zeroed when dropped.
    fn duplicate(&self) -> Self {
        Self(self.0)
    }
}

impl From<[u8; KEY_LEN]> for Key {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// Fails with [`KeyError::Length`] for a slice of other than 32 bytes.
impl TryFrom<&[u8]> for Key {
    type Error = KeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; KEY_LEN]>::try_from(bytes)
            .map(Self)
            .map_err(|_| KeyError::Length(bytes.len()))
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Key {}

// By hand rather than derived, so that `Zeroize` is not public: zeroizing a key in place would leave a usable all-zero
// key.
impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

/// The error for text that is not a key: see [`Key::from_base64`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// The text is not valid base64.
    Base64,
    /// The text decodes to this many bytes rather than 32.
    Length(usize),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Base64 => f.write_str("key is not valid standard base64 with padding"),
            KeyError::Length(len) => write!(f, "key is {len} bytes long rather than {KEY_LEN}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The keys a [`Chafernet`](crate::Chafernet) uses: the first encrypts, and all are tried in order to decrypt.
///
/// A keyset never has fewer than one key, and it is a value: rotating makes a new one. To rotate keys, prepend a new
/// one with [`with_new_key`](Self::with_new_key), deploy the new keyset everywhere, and drop the oldest with
/// [`without_oldest`](Self::without_oldest) once every token the old key encrypted has expired.
///
/// The text form is standard base64 of the JSON document `{"keys":["<base64 key>",...]}`, which is how keysets are
/// usually passed in configuration:
///
/// ```
/// use chafernet::Keyset;
///
/// let keyset = Keyset::generate();
/// let text = keyset.to_base64();
/// assert_eq!(Keyset::from_base64(&text)?, keyset);
/// # Ok::<(), chafernet::KeysetError>(())
/// ```
#[derive(PartialEq, Eq)]
pub struct Keyset {
    // A boxed slice, not a Vec: it cannot grow, so no reallocation moves keys and leaves copies behind, and it has no
    // spare capacity to hold a removed one. Every change builds a new one; the old keys are zeroed as it drops.
    keys: Box<[Key]>,
}

/// `len` keys in an allocation of exactly that size, so that boxing it moves nothing.
fn exact(len: usize, keys: impl Iterator<Item = Key>) -> Box<[Key]> {
    let mut exact = Vec::with_capacity(len);
    exact.extend(keys.take(len));
    exact.into_boxed_slice()
}

/// The JSON document behind the text form. Each key's text is zeroized as it drops, even when parsing fails partway.
#[derive(Deserialize)]
struct KeysetJson {
    keys: Vec<Zeroizing<String>>,
}

impl Keyset {
    /// A keyset holding one key.
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self {
            keys: Box::new([key]),
        }
    }

    /// A keyset holding one new random key.
    ///
    /// # Panics
    ///
    /// If the operating system's random number generator fails.
    #[must_use]
    pub fn generate() -> Self {
        Self::new(Key::generate())
    }

    /// A copy of the keyset with a new random key prepended, which becomes the one that encrypts.
    ///
    /// # Panics
    ///
    /// If the operating system's random number generator fails.
    #[must_use]
    pub fn with_new_key(&self) -> Self {
        let keys = std::iter::once(Key::generate()).chain(self.keys.iter().map(Key::duplicate));
        Self {
            keys: exact(self.keys.len() + 1, keys),
        }
    }

    /// A copy of the keyset without its last key, the oldest, or `None` if that is its only key: a keyset never has
    /// fewer than one.
    #[must_use]
    pub fn without_oldest(&self) -> Option<Self> {
        let rest = self.keys.split_last()?.1;
        (!rest.is_empty()).then(|| Self {
            keys: exact(rest.len(), rest.iter().map(Key::duplicate)),
        })
    }

    /// The number of keys, at least one.
    #[must_use]
    #[expect(clippy::len_without_is_empty, reason = "a keyset is never empty")]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// The keys, the first of which encrypts.
    #[must_use]
    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    /// The key that encrypts.
    #[must_use]
    pub fn primary(&self) -> &Key {
        &self.keys[0]
    }

    /// Decodes a keyset from its text form, as [`to_base64`](Self::to_base64) writes it, given as `&str` or as bytes.
    /// Surrounding ASCII whitespace (a trailing newline from a file) is ignored.
    ///
    /// # Errors
    ///
    /// [`KeysetError`] if the text is not base64, does not decode to the JSON document, or holds no key or a key that
    /// is not valid.
    pub fn from_base64(text: impl AsRef<[u8]>) -> Result<Self, KeysetError> {
        let mut json = BASE64
            .decode(text.as_ref().trim_ascii())
            .map_err(|_| KeysetError::Base64)?;
        let keyset = Self::from_json_bytes(&json);
        json.zeroize();
        keyset
    }

    /// The keyset as standard base64 of its JSON form, in a string that is zeroized when dropped.
    #[must_use]
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(self.to_json().as_bytes()))
    }

    /// Decodes a keyset from its JSON form, `{"keys":["<base64 key>",...]}`, given as `&str` or as bytes.
    ///
    /// # Errors
    ///
    /// [`KeysetError`] if the text is not that JSON document, or holds no key or a key that is not valid.
    pub fn from_json(json: impl AsRef<[u8]>) -> Result<Self, KeysetError> {
        Self::from_json_bytes(json.as_ref())
    }

    fn from_json_bytes(json: &[u8]) -> Result<Self, KeysetError> {
        // Only the position: serde_json's message can quote the input, which is key material.
        let parsed: KeysetJson = serde_json::from_slice(json).map_err(|e| KeysetError::Json {
            line: e.line(),
            column: e.column(),
        })?;
        let texts = parsed.keys;
        if texts.is_empty() {
            return Err(KeysetError::Empty);
        }
        let mut keys = Vec::with_capacity(texts.len());
        for (index, text) in texts.iter().enumerate() {
            keys.push(Key::from_base64(text).map_err(|error| KeysetError::Key { index, error })?);
        }
        // Full, so boxing it moves nothing.
        Ok(Self {
            keys: keys.into_boxed_slice(),
        })
    }

    /// The keyset as compact JSON, `{"keys":["<base64 key>",...]}`, in a string that is zeroized when dropped.
    #[must_use]
    pub fn to_json(&self) -> Zeroizing<String> {
        // Base64 needs no JSON escaping, so the document is assembled directly, in a buffer of the final size so that
        // it never reallocates and leaves a copy behind.
        let key_len =
            base64::encoded_len(KEY_LEN, true).expect("a key's base64 length fits in usize");
        let mut json = Zeroizing::new(String::with_capacity(
            r#"{"keys":[]}"#.len() + self.keys.len() * (key_len + 3),
        ));
        json.push_str(r#"{"keys":["#);
        for (i, key) in self.keys.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push('"');
            BASE64.encode_string(key.0.as_slice(), &mut json);
            json.push('"');
        }
        json.push_str("]}");
        json
    }
}

/// Parses the text form, as [`Keyset::from_base64`] does.
impl FromStr for Keyset {
    type Err = KeysetError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_base64(text)
    }
}

impl From<Key> for Keyset {
    fn from(key: Key) -> Self {
        Self::new(key)
    }
}

/// Fails with [`KeysetError::Empty`] for an empty vector.
impl TryFrom<Vec<Key>> for Keyset {
    type Error = KeysetError;

    fn try_from(keys: Vec<Key>) -> Result<Self, Self::Error> {
        if keys.is_empty() {
            return Err(KeysetError::Empty);
        }
        // Copied rather than boxed in place: the vector may have spare capacity, which into_boxed_slice() would shed by
        // reallocating, leaving copies of the keys behind. The originals are zeroed as `keys` drops.
        Ok(Self {
            keys: exact(keys.len(), keys.iter().map(Key::duplicate)),
        })
    }
}

impl fmt::Debug for Keyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyset({} keys)", self.len())
    }
}

/// The error for text that is not a keyset: see [`Keyset::from_base64`] and [`Keyset::from_json`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeysetError {
    /// The text is not valid base64.
    Base64,
    /// The text is not the JSON document `{"keys":[...]}`. The error is reported by position only, since the
    /// parser's message can quote the text, which is key material.
    Json {
        /// The line of the error, from 1.
        line: usize,
        /// The column of the error, from 1.
        column: usize,
    },
    /// The list of keys is empty.
    Empty,
    /// A key in the list is not valid.
    Key {
        /// The index of the key in the list.
        index: usize,
        /// What is wrong with it.
        error: KeyError,
    },
}

impl fmt::Display for KeysetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeysetError::Base64 => f.write_str("keyset is not valid standard base64 with padding"),
            KeysetError::Json { line, column } => write!(
                f,
                r#"keyset is not the JSON document {{"keys":[...]}} (error at line {line}, column {column})"#
            ),
            KeysetError::Empty => f.write_str("keyset has no keys"),
            KeysetError::Key { index, error } => write!(f, "key {index} of the keyset: {error}"),
        }
    }
}

impl std::error::Error for KeysetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeysetError::Key { error, .. } => Some(error),
            _ => None,
        }
    }
}
