//! Encrypting and decrypting tokens.

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE as BASE64URL;
use chacha20poly1305::aead::AeadInOut as _;
use chacha20poly1305::{KeyInit as _, Tag, XChaCha20Poly1305, XNonce};
use rand::TryRng as _;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

use crate::aad::Aad;
use crate::keyset::{Key, Keyset};

/// The version of the plaintext format: the byte at the start of every token's plaintext, ahead of the timestamp.
///
/// It is encrypted with the rest, so it is read only once a key has authenticated the token, and it says how what
/// follows it is laid out, nothing else. It cannot announce another cipher, nonce length, or tag: a token made
/// with those fails as [`InvalidToken::Unauthenticated`] before the byte is reached.
pub const PLAINTEXT_FORMAT_VERSION: u8 = 1;

/// How far in the future a token's timestamp may be before it is rejected, allowing for clocks that disagree
/// slightly, unless a `Chafernet` is given another with [`max_clock_skew`](Chafernet::max_clock_skew).
pub const DEFAULT_MAX_CLOCK_SKEW: Duration = Duration::from_secs(30);

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// The version byte and the timestamp.
const HEADER_LEN: usize = 1 + 8;
/// The shortest possible token, once decoded: the nonce, the header, and the tag.
const MIN_TOKEN_LEN: usize = NONCE_LEN + HEADER_LEN + TAG_LEN;

/// Encrypts and decrypts tokens with a [`Keyset`].
///
/// ```
/// use chafernet::{Chafernet, Context, Keyset};
/// use std::time::Duration;
///
/// let chafernet = Chafernet::new(&Keyset::generate());
/// let context = Context::new("list-cursor.v1", &[b"tenant-17", b"orders"]);
/// let cursor = chafernet.encrypt(br#"{"after":1042}"#).aad(context).seal();
/// let position = chafernet.decrypt(&cursor).aad(context).ttl(Duration::from_secs(3600)).open()?;
/// assert_eq!(position, br#"{"after":1042}"#);
/// # Ok::<(), chafernet::InvalidToken>(())
/// ```
///
/// [`encrypt`](Self::encrypt) and [`decrypt`](Self::decrypt) return builders: [`Encrypt`] and [`Decrypt`]. Their
/// settings are the additional authenticated data ([`aad`](Encrypt::aad)), either raw bytes or a [`Context`](crate::Context)
/// made of a purpose and the fields of a context; the time, for tests and callers with their own clock
/// ([`at`](Encrypt::at)); and, for decrypting, the time-to-live ([`ttl`](Decrypt::ttl)). The additional
/// authenticated data can be set once: a builder that has it is of another type, without `aad`.
///
/// A token is `base64url(nonce ‖ XChaCha20-Poly1305(key, nonce, version ‖ timestamp ‖ plaintext, aad))`, with a
/// random 24-byte nonce, the version byte [`PLAINTEXT_FORMAT_VERSION`], the timestamp as 8 big-endian bytes of
/// seconds since the Unix epoch, and the 16-byte authentication tag at the end, as libsodium's
/// `crypto_aead_xchacha20poly1305_ietf` writes it. The base64 is URL-safe with padding.
///
/// The additional authenticated data is not stored in the token; the same must be given to decrypt it, which binds
/// the token to a context (a user, a purpose) without revealing it. Without `aad`, it is empty.
///
/// A `Chafernet` holds one copy of each key, which the cipher zeroes when the `Chafernet` is dropped. It is not
/// `Clone`, so that no further copies are made by accident.
pub struct Chafernet {
    ciphers: Vec<XChaCha20Poly1305>,
    max_clock_skew: Duration,
}

impl Chafernet {
    /// A Chafernet that encrypts with the keyset's first key and decrypts with any of its keys, allowing
    /// [`DEFAULT_MAX_CLOCK_SKEW`] on a token's timestamp.
    #[must_use]
    pub fn new(keyset: &Keyset) -> Self {
        Self {
            ciphers: keyset
                .keys()
                .iter()
                .map(|key| XChaCha20Poly1305::new(key.as_bytes().into()))
                .collect(),
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
        }
    }

    /// The Chafernet with `max_clock_skew`, rather than [`DEFAULT_MAX_CLOCK_SKEW`], as how far in the future a token's
    /// timestamp may be before [`open`](Decrypt::open) rejects it, as in
    /// `Chafernet::new(&keyset).max_clock_skew(Duration::from_secs(5))`. Timestamps have whole seconds, so
    /// `max_clock_skew` is truncated to whole seconds.
    #[must_use]
    pub fn max_clock_skew(mut self, max_clock_skew: Duration) -> Self {
        self.max_clock_skew = max_clock_skew;
        self
    }

    /// A Chafernet with a single key, allowing [`DEFAULT_MAX_CLOCK_SKEW`].
    #[must_use]
    pub fn with_key(key: &Key) -> Self {
        Self {
            ciphers: vec![XChaCha20Poly1305::new(key.as_bytes().into())],
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
        }
    }

    /// Starts encrypting `plaintext`: set the additional authenticated data and the time on the builder, then
    /// [`seal`](Encrypt::seal) it into a token.
    pub fn encrypt<'a>(&'a self, plaintext: &'a [u8]) -> Encrypt<'a, NoAad> {
        Encrypt {
            chafernet: self,
            plaintext,
            aad: NoAad,
            timestamp: None,
        }
    }

    /// Starts decrypting `token`: set the additional authenticated data, the time-to-live, and the time on the
    /// builder, then [`open`](Decrypt::open) it into the plaintext, or into the plaintext and the timestamp with
    /// [`open_with_timestamp`](Decrypt::open_with_timestamp).
    pub fn decrypt<'a>(&'a self, token: &'a str) -> Decrypt<'a, NoAad> {
        Decrypt {
            chafernet: self,
            token,
            aad: NoAad,
            ttl: None,
            now: None,
        }
    }

    /// The deterministic core of encryption, for test vectors. Reusing a nonce with a key is fatal to the
    /// cipher's security, so this is not public.
    pub(crate) fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        timestamp: u64,
        nonce: &[u8; NONCE_LEN],
    ) -> String {
        // The token is built in one buffer of its final size and encrypted in place, so the plaintext is copied
        // once and overwritten by the ciphertext, leaving no copy to zero.
        let mut raw = Vec::with_capacity(NONCE_LEN + HEADER_LEN + plaintext.len() + TAG_LEN);
        raw.extend_from_slice(nonce);
        raw.push(PLAINTEXT_FORMAT_VERSION);
        raw.extend_from_slice(&timestamp.to_be_bytes());
        raw.extend_from_slice(plaintext);
        let tag = self.ciphers[0]
            .encrypt_inout_detached(&XNonce::from(*nonce), aad, (&mut raw[NONCE_LEN..]).into())
            .expect("XChaCha20-Poly1305 encryption cannot fail");
        raw.extend_from_slice(&tag);
        BASE64URL.encode(raw)
    }

    /// Decodes and authenticates `token`, returning the nonce, the header, and the plaintext, decrypted in place
    /// in a buffer that is zeroed when dropped.
    fn authenticate(&self, token: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, InvalidToken> {
        let mut raw = BASE64URL
            .decode(token)
            .map_err(|_| InvalidToken::Malformed)?;
        if raw.len() < MIN_TOKEN_LEN {
            return Err(InvalidToken::Malformed);
        }
        let tag_start = raw.len() - TAG_LEN;
        let tag = Tag::try_from(&raw[tag_start..]).expect("TAG_LEN bytes");
        let nonce = XNonce::try_from(&raw[..NONCE_LEN]).expect("NONCE_LEN bytes");
        let ciphertext = &mut raw[NONCE_LEN..tag_start];
        // A key that fails to authenticate the ciphertext leaves it unchanged, so each key is tried on it in turn.
        if !self.ciphers.iter().any(|cipher| {
            cipher
                .decrypt_inout_detached(&nonce, aad, (&mut *ciphertext).into(), &tag)
                .is_ok()
        }) {
            return Err(InvalidToken::Unauthenticated);
        }
        raw.truncate(tag_start);
        let message = Zeroizing::new(raw);
        match message[NONCE_LEN] {
            PLAINTEXT_FORMAT_VERSION => Ok(message),
            version => Err(InvalidToken::PlaintextFormatVersion(version)),
        }
    }
}

impl From<&Keyset> for Chafernet {
    fn from(keyset: &Keyset) -> Self {
        Self::new(keyset)
    }
}

impl From<&Key> for Chafernet {
    fn from(key: &Key) -> Self {
        Self::with_key(key)
    }
}

impl fmt::Debug for Chafernet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Chafernet({} keys)", self.ciphers.len())
    }
}

/// The state of a builder's additional authenticated data: [`NoAad`] or [`WithAad`]. Sealed; the two states are
/// the only ones.
pub trait AadState: sealed::Sealed {
    /// The bytes to authenticate.
    fn bytes(&self) -> &[u8];
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::NoAad {}
    impl Sealed for super::WithAad<'_> {}
}

/// The state of a builder whose additional authenticated data has not been set: it is empty, and
/// [`aad`](Encrypt::aad) is available.
#[derive(Clone, Copy, Debug)]
pub struct NoAad;

impl AadState for NoAad {
    fn bytes(&self) -> &[u8] {
        b""
    }
}

/// The state of a builder whose additional authenticated data has been set by [`aad`](Encrypt::aad), which
/// cannot be called again, so setting the data twice does not compile.
///
/// ```compile_fail
/// let chafernet = chafernet::Chafernet::new(&chafernet::Keyset::generate());
/// chafernet.encrypt(b"x").aad(b"a").aad(chafernet::Context::new("list-cursor.v1", &[])).seal();
/// ```
///
/// ```compile_fail
/// let chafernet = chafernet::Chafernet::new(&chafernet::Keyset::generate());
/// chafernet.decrypt("t").aad(chafernet::Context::new("list-cursor.v1", &[])).aad(b"a").open();
/// ```
#[derive(Clone, Copy, Debug)]
pub struct WithAad<'a>(Aad<'a>);

impl AadState for WithAad<'_> {
    fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Encrypts a plaintext into a token: see [`Chafernet::encrypt`]. `A` is [`NoAad`] until [`aad`](Self::aad) is
/// called, and [`WithAad`] after.
#[must_use = "a token is made by calling seal() on the builder"]
pub struct Encrypt<'a, A: AadState = NoAad> {
    chafernet: &'a Chafernet,
    plaintext: &'a [u8],
    aad: A,
    timestamp: Option<u64>,
}

impl<'a> Encrypt<'a, NoAad> {
    /// Sets the additional authenticated data: bytes used as they are, or a [`Context`](crate::Context) of the
    /// purpose of the tokens and the fields that identify the context.
    pub fn aad(self, aad: impl Into<Aad<'a>>) -> Encrypt<'a, WithAad<'a>> {
        Encrypt {
            chafernet: self.chafernet,
            plaintext: self.plaintext,
            aad: WithAad(aad.into()),
            timestamp: self.timestamp,
        }
    }
}

impl<'a, A: AadState> Encrypt<'a, A> {
    /// Uses `timestamp`, in seconds since the Unix epoch, as the token's timestamp rather than the current time.
    pub fn at(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Encrypts the plaintext into a token.
    ///
    /// # Panics
    ///
    /// If the operating system's random number generator fails to produce a nonce.
    #[must_use]
    pub fn seal(self) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        SysRng
            .try_fill_bytes(&mut nonce)
            .expect("the operating system's random number generator failed");
        self.chafernet.encrypt_with_nonce(
            self.plaintext,
            self.aad.bytes(),
            self.timestamp.unwrap_or_else(now),
            &nonce,
        )
    }
}

/// Decrypts a token into its plaintext: see [`Chafernet::decrypt`]. `A` is [`NoAad`] until [`aad`](Self::aad) is
/// called, and [`WithAad`] after.
#[must_use = "a token is decrypted by calling open() or open_with_timestamp() on the builder"]
pub struct Decrypt<'a, A: AadState = NoAad> {
    chafernet: &'a Chafernet,
    token: &'a str,
    aad: A,
    ttl: Option<Duration>,
    now: Option<u64>,
}

impl<'a> Decrypt<'a, NoAad> {
    /// Sets the additional authenticated data the token was encrypted with: bytes used as they are, or a
    /// [`Context`](crate::Context), as for [`Encrypt::aad`].
    pub fn aad(self, aad: impl Into<Aad<'a>>) -> Decrypt<'a, WithAad<'a>> {
        Decrypt {
            chafernet: self.chafernet,
            token: self.token,
            aad: WithAad(aad.into()),
            ttl: self.ttl,
            now: self.now,
        }
    }
}

impl<'a, A: AadState> Decrypt<'a, A> {
    /// Requires the token to have been encrypted no more than `ttl` ago. Without a `ttl`, a token of any age is
    /// accepted. Timestamps have whole seconds, so `ttl` is truncated to whole seconds.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Uses `now`, in seconds since the Unix epoch, as the current time rather than the clock.
    pub fn at(mut self, now: u64) -> Self {
        self.now = Some(now);
        self
    }

    /// Decrypts the token, checking its timestamp against the current time: it must be no more than `ttl` in the
    /// past, if a `ttl` was set, and in any case no more than the `Chafernet`'s
    /// `max_clock_skew` ([`Chafernet::max_clock_skew`]) in the future.
    ///
    /// # Errors
    ///
    /// [`InvalidToken`] if the token cannot be decoded, was not encrypted with one of the keys and this additional
    /// authenticated data, has another plaintext format version, or fails the time checks.
    pub fn open(self) -> Result<Vec<u8>, InvalidToken> {
        self.open_with_timestamp().map(|(plaintext, _)| plaintext)
    }

    /// Decrypts the token as [`open`](Self::open) does, with the same time checks, and returns its timestamp, in
    /// seconds since the Unix epoch, with the plaintext: for a caller that acts on a token's age, such as one
    /// that replaces a token halfway through its life. A token that fails the time checks gives its timestamp
    /// only in the error, [`InvalidToken::Expired`] or [`InvalidToken::NotYetValid`], and never as a result.
    ///
    /// ```
    /// use chafernet::{Chafernet, Keyset};
    /// use std::time::Duration;
    ///
    /// let chafernet = Chafernet::new(&Keyset::generate());
    /// let token = chafernet.encrypt(b"hello").at(1_700_000_000).seal();
    /// let (plaintext, timestamp) = chafernet
    ///     .decrypt(&token)
    ///     .ttl(Duration::from_secs(3600))
    ///     .at(1_700_000_600)
    ///     .open_with_timestamp()?;
    /// assert_eq!((plaintext.as_slice(), timestamp), (&b"hello"[..], 1_700_000_000));
    /// # Ok::<(), chafernet::InvalidToken>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`InvalidToken`], as for [`open`](Self::open).
    pub fn open_with_timestamp(self) -> Result<(Vec<u8>, u64), InvalidToken> {
        let mut message = self.chafernet.authenticate(self.token, self.aad.bytes())?;
        let timestamp = header_timestamp(&message);
        let now = self.now.unwrap_or_else(now);
        if let Some(ttl) = self.ttl
            && timestamp.saturating_add(ttl.as_secs()) < now
        {
            return Err(InvalidToken::Expired { timestamp });
        }
        if now.saturating_add(self.chafernet.max_clock_skew.as_secs()) < timestamp {
            return Err(InvalidToken::NotYetValid { timestamp });
        }
        message.drain(..NONCE_LEN + HEADER_LEN);
        // The plaintext is the caller's from here; the buffer is moved out, not copied, and no longer zeroed.
        Ok((std::mem::take(&mut *message), timestamp))
    }
}

/// The timestamp in an authenticated message: the nonce, then the header.
fn header_timestamp(message: &[u8]) -> u64 {
    u64::from_be_bytes(
        message[NONCE_LEN + 1..NONCE_LEN + HEADER_LEN]
            .try_into()
            .expect("8 bytes"),
    )
}

/// The current time in seconds since the Unix epoch (0 if the clock is before it). On wasm32-unknown-unknown without
/// `wasm_js`, which builds only with a custom getrandom backend, there is no clock and this panics; such callers must
/// give every builder `at()`.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown", feature = "wasm_js")))]
fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The current time in seconds since the Unix epoch, from the JavaScript host: on wasm32-unknown-unknown,
/// `SystemTime::now()` panics.
#[cfg(all(target_arch = "wasm32", target_os = "unknown", feature = "wasm_js"))]
fn now() -> u64 {
    // Date.now() is whole milliseconds; the cast saturates, so a clock before the epoch reads as 0, as above.
    (js_sys::Date::now() / 1000.0).floor() as u64
}

/// The error for a token that cannot be decrypted: see [`Decrypt::open`].
///
/// [`Malformed`](Self::Malformed) and [`Unauthenticated`](Self::Unauthenticated) say the token is not one of ours,
/// or is damaged. The others can occur only for a genuine token, one that was encrypted with one of the keys and
/// the same additional authenticated data: [`Expired`](Self::Expired) and [`NotYetValid`](Self::NotYetValid) for
/// one outside its time window, and [`PlaintextFormatVersion`](Self::PlaintextFormatVersion) for one whose
/// plaintext this version of the crate cannot read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidToken {
    /// The token is not base64, or is too short to hold a nonce, a header, and a tag.
    Malformed,
    /// No key decrypts the token with this additional authenticated data: it was encrypted with another key, with
    /// other data, or has been altered.
    Unauthenticated,
    /// The token is genuine, but the version of its plaintext format, given here, is not
    /// [`PLAINTEXT_FORMAT_VERSION`]: it was made by another implementation, newer or older, that holds the same
    /// keys. It is not a sign of forgery, and trying again does not help. When a format version is introduced,
    /// every reader must understand it before any writer produces it.
    ///
    /// This covers the layout of the plaintext only. A token made with another cipher or nonce length never
    /// authenticates, so it is [`Unauthenticated`](Self::Unauthenticated) rather than this.
    PlaintextFormatVersion(u8),
    /// The token's timestamp is more than `ttl` in the past.
    Expired {
        /// When the token was encrypted, in seconds since the Unix epoch.
        timestamp: u64,
    },
    /// The token's timestamp is more than `max_clock_skew` ([`Chafernet::max_clock_skew`]) in the
    /// future.
    NotYetValid {
        /// When the token was encrypted, in seconds since the Unix epoch.
        timestamp: u64,
    },
}

impl fmt::Display for InvalidToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidToken::Malformed => f.write_str("token is not base64url or is too short"),
            InvalidToken::Unauthenticated => f.write_str(
                "token was not encrypted with these keys and this aad, or has been altered",
            ),
            InvalidToken::PlaintextFormatVersion(version) => {
                write!(
                    f,
                    "token is genuine but has plaintext format version {version}; only \
                     {PLAINTEXT_FORMAT_VERSION} is supported"
                )
            }
            InvalidToken::Expired { .. } => f.write_str("token has expired"),
            InvalidToken::NotYetValid { .. } => f.write_str("token's timestamp is in the future"),
        }
    }
}

impl std::error::Error for InvalidToken {}

// The behavior of tokens is tested through the public API, in tests/public_api.rs. Only what needs the private
// encrypt_with_nonce is tested here.
#[cfg(test)]
mod tests {
    use super::*;

    /// The tokens in tests/vectors.json were produced with PyNaCl (libsodium) by tools/gen_vectors.py.
    #[test]
    fn matches_libsodium_vectors() {
        #[derive(serde::Deserialize)]
        struct Vectors {
            keyset: String,
            keys: Vec<String>,
            vectors: Vec<Vector>,
        }
        #[derive(serde::Deserialize)]
        struct Vector {
            name: String,
            key: usize,
            nonce: String,
            aad: String,
            timestamp: u64,
            plaintext: String,
            token: String,
        }
        fn unhex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        }
        let vectors: Vectors =
            serde_json::from_str(include_str!("../../tests/vectors.json")).unwrap();
        let keyset = Keyset::from_base64(&vectors.keyset).unwrap();
        assert_eq!(
            keyset
                .keys()
                .iter()
                .map(|key| key.to_base64().as_str().to_owned())
                .collect::<Vec<_>>(),
            vectors.keys
        );
        let chafernet = Chafernet::new(&keyset);
        for v in &vectors.vectors {
            let (aad, plaintext) = (unhex(&v.aad), unhex(&v.plaintext));
            let nonce: [u8; NONCE_LEN] = unhex(&v.nonce).try_into().unwrap();
            let encrypted = Chafernet::with_key(&keyset.keys()[v.key]).encrypt_with_nonce(
                &plaintext,
                &aad,
                v.timestamp,
                &nonce,
            );
            assert_eq!(encrypted, v.token, "{}", v.name);
            assert_eq!(
                chafernet
                    .decrypt(&v.token)
                    .aad(&aad)
                    .at(v.timestamp)
                    .open_with_timestamp()
                    .unwrap(),
                (plaintext, v.timestamp),
                "{}",
                v.name
            );
        }
    }
}
