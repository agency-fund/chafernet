//! Chafernet tokens for Python: the `chafernet._chafernet` extension module, built on the `chafernet` crate.

use std::sync::OnceLock;
use std::time::Duration;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyInt, PyString, PyTuple};
use pyo3::{
    Borrowed, PyTypeInfo, inspect::PyStaticExpr, type_hint_identifier, type_hint_subscript,
    type_hint_union,
};
use zeroize::Zeroizing;

/// Raised by ``decrypt`` and ``decrypt_with_timestamp`` when a token cannot be decrypted: it is not a token, was not
/// encrypted with one of the keys and the same ``aad``, or has been altered. The message says which.
///
/// Its subclasses are raised for a token that is genuine, encrypted with one of the keys and the same ``aad``, but
/// cannot be used: ``TokenExpiredError`` and ``TokenNotYetValidError`` for one outside its time window, and
/// ``PlaintextFormatVersionError`` for one in a format this version of the package cannot read. An ``InvalidTokenError``
/// that is none of them is a token that is not ours, or is damaged.
///
/// A plain ``Exception`` rather than a ``ValueError``, as ``cryptography.fernet.InvalidToken`` is, so that code
/// catching bad tokens does not also catch the ``ValueError`` and ``TypeError`` that a wrong call raises.
#[pyclass(extends = PyException, module = "chafernet", name = "InvalidTokenError", frozen, subclass, weakref)]
struct InvalidTokenError;

#[pymethods]
impl InvalidTokenError {
    /// The arguments are passed on to Exception, so ``args`` holds them and ``str()`` is the message. Any arguments are
    /// accepted, so that a subclass can define ``__init__`` with its own.
    #[new]
    #[pyo3(signature = (*args: "object"))]
    #[allow(unused_variables)]
    fn new(args: &Bound<'_, PyTuple>) -> Self {
        InvalidTokenError
    }
}

/// Raised by ``decrypt`` for a token that is genuine but older than ``ttl``.
#[pyclass(extends = InvalidTokenError, module = "chafernet", name = "TokenExpiredError", frozen, subclass, weakref)]
struct TokenExpiredError {
    timestamp: OnceLock<u64>,
}

#[pymethods]
impl TokenExpiredError {
    #[new]
    #[pyo3(signature = (*args: "object"))]
    fn new(args: &Bound<'_, PyTuple>) -> PyClassInitializer<Self> {
        PyClassInitializer::from(InvalidTokenError::new(args)).add_subclass(TokenExpiredError {
            timestamp: OnceLock::new(),
        })
    }

    /// The token's timestamp, in seconds since the Unix epoch, to tell a token that has just expired from one long
    /// dead; ``None`` on an instance made in Python. It is genuine, but the token's holder cannot read it, so it is
    /// not in the message; pass it on only where that is meant.
    #[getter]
    fn timestamp(&self) -> Option<u64> {
        self.timestamp.get().copied()
    }
}

/// Raised by ``decrypt`` for a token that is genuine but has a timestamp more than the ``Chafernet``'s
/// ``max_clock_skew`` seconds in the future.
#[pyclass(extends = InvalidTokenError, module = "chafernet", name = "TokenNotYetValidError", frozen, subclass, weakref)]
struct TokenNotYetValidError {
    timestamp: OnceLock<u64>,
}

#[pymethods]
impl TokenNotYetValidError {
    #[new]
    #[pyo3(signature = (*args: "object"))]
    fn new(args: &Bound<'_, PyTuple>) -> PyClassInitializer<Self> {
        PyClassInitializer::from(InvalidTokenError::new(args)).add_subclass(TokenNotYetValidError {
            timestamp: OnceLock::new(),
        })
    }

    /// The token's timestamp, in seconds since the Unix epoch, to see how far apart the clocks are; ``None`` on an
    /// instance made in Python. As for ``TokenExpiredError``, it is not in the message.
    #[getter]
    fn timestamp(&self) -> Option<u64> {
        self.timestamp.get().copied()
    }
}

/// Raised by ``decrypt`` for a token that is genuine but whose plaintext format version is not
/// the one this version of the package reads: it was made by another implementation, newer or older, that holds the
/// same keys. It is not a sign of forgery, and trying again does not help. When a format version is introduced, every
/// reader must understand it before any writer produces it.
///
/// The version is a byte encrypted with the plaintext, so it covers the layout of the plaintext only. A token made with
/// another cipher or nonce length never authenticates, and raises a plain ``InvalidTokenError``.
#[pyclass(extends = InvalidTokenError, module = "chafernet", name = "PlaintextFormatVersionError", frozen, subclass, weakref)]
struct PlaintextFormatVersionError;

#[pymethods]
impl PlaintextFormatVersionError {
    #[new]
    #[pyo3(signature = (*args: "object"))]
    fn new(args: &Bound<'_, PyTuple>) -> PyClassInitializer<Self> {
        PyClassInitializer::from(InvalidTokenError::new(args))
            .add_subclass(PlaintextFormatVersionError)
    }
}

/// The purpose and context a token is bound to: a ``domain`` (``"shard-ip"``) and the ``parts`` that identify the
/// context (a collection name, a tenant). Passed as the ``aad`` of ``encrypt`` and ``decrypt``, it stands for its
/// ``digest``: 32 bytes, the SHA-256 digest of ``"chafernet.aad.v1"``, ``domain``, and each part, every one preceded
/// by its length as 8 big-endian bytes. A token encrypted with a ``Context`` and one encrypted with its ``digest``
/// as raw ``aad`` are the same token.
///
/// A ``Context`` keeps only its digest. It is a value: equal to another with the same digest, which means the same
/// domain and parts, hashable, and immutable.
#[pyclass(module = "chafernet", name = "Context", frozen, eq, hash)]
#[derive(PartialEq, Hash)]
struct PyContext {
    digest: [u8; 32],
}

#[pymethods]
impl PyContext {
    #[new]
    #[pyo3(signature = (domain, /, *parts: "bytes"))]
    fn new(domain: &str, parts: Bound<'_, PyTuple>) -> PyResult<Self> {
        let mut slices = Vec::with_capacity(parts.len());
        for part in parts.as_slice() {
            let Ok(part) = part.cast::<PyBytes>() else {
                return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "parts must be bytes, not {}",
                    part.get_type().name()?
                )));
            };
            slices.push(part.as_bytes());
        }
        let digest = *chafernet::Context::new(domain, &slices).as_bytes();
        Ok(Self { digest })
    }

    /// The additional authenticated data the context stands for.
    #[getter]
    fn digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.digest)
    }

    fn __repr__(&self) -> String {
        let hex: String = self
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("<Context {hex}>")
    }
}

/// The ``aad`` argument of a call: ``bytes`` used as they are, or a ``Context``, whose digest is used.
enum AadArg<'py> {
    Raw(Bound<'py, PyBytes>),
    Context([u8; 32]),
}

// Written out rather than derived: the derived extraction tries each variant in turn and builds a Python exception
// for each that fails, which cost a Context about 2 µs per call.
impl<'a, 'py> FromPyObject<'a, 'py> for AadArg<'py> {
    type Error = PyErr;
    const INPUT_TYPE: PyStaticExpr = type_hint_union!(PyBytes::TYPE_HINT, PyContext::TYPE_HINT);

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(context) = obj.cast::<PyContext>() {
            Ok(AadArg::Context(context.get().digest))
        } else if let Ok(bytes) = obj.cast::<PyBytes>() {
            Ok(AadArg::Raw(bytes.to_owned()))
        } else {
            Err(pyo3::exceptions::PyTypeError::new_err(format!(
                "aad must be bytes or a Context, not {}",
                obj.get_type().name()?
            )))
        }
    }
}

impl AadArg<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            AadArg::Raw(bytes) => bytes.as_bytes(),
            AadArg::Context(digest) => digest,
        }
    }
}

/// The additional authenticated data of a call: ``aad`` as given, or empty.
fn aad_bytes<'a>(aad: &'a Option<AadArg<'_>>) -> &'a [u8] {
    aad.as_ref().map_or(b"", AadArg::bytes)
}

/// Key material given as text: a ``str``, or a bytes-like object such as a ``bytearray``, which the caller can wipe
/// once done with it. Copied into a buffer that is zeroized when dropped.
struct KeyText(Zeroizing<Vec<u8>>);

impl<'a, 'py> FromPyObject<'a, 'py> for KeyText {
    type Error = PyErr;
    const INPUT_TYPE: PyStaticExpr = type_hint_union!(
        PyString::TYPE_HINT,
        type_hint_identifier!("collections.abc", "Buffer")
    );

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(text) = obj.cast::<PyString>() {
            return Ok(KeyText(Zeroizing::new(text.to_str()?.as_bytes().to_vec())));
        }
        let Ok(buffer) = PyBuffer::<u8>::get(&obj) else {
            return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                "expected str or a bytes-like object, not {}",
                obj.get_type().name()?
            )));
        };
        let mut bytes = Zeroizing::new(vec![0; buffer.item_count()]);
        buffer.copy_to_slice(obj.py(), &mut bytes)?;
        Ok(KeyText(bytes))
    }
}

/// A list of keys in base64.
struct KeyList(Vec<KeyText>);

impl<'a, 'py> FromPyObject<'a, 'py> for KeyList {
    type Error = PyErr;
    const INPUT_TYPE: PyStaticExpr = type_hint_subscript!(
        type_hint_identifier!("collections.abc", "Sequence"),
        KeyText::INPUT_TYPE
    );

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        obj.extract().map(KeyList)
    }
}

/// A plaintext argument: ``str`` (encrypted as UTF-8) or ``bytes``.
struct Plaintext(Py<PyAny>);

impl<'a, 'py> FromPyObject<'a, 'py> for Plaintext {
    type Error = PyErr;
    const INPUT_TYPE: PyStaticExpr = type_hint_union!(PyString::TYPE_HINT, PyBytes::TYPE_HINT);

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if obj.is_instance_of::<PyString>() || obj.is_instance_of::<PyBytes>() {
            Ok(Plaintext(obj.to_owned().unbind()))
        } else {
            Err(pyo3::exceptions::PyTypeError::new_err(format!(
                "plaintext must be str or bytes, not {}",
                obj.get_type().name()?
            )))
        }
    }
}

impl Plaintext {
    fn as_bytes<'py>(&'py self, py: Python<'py>) -> PyResult<&'py [u8]> {
        let obj = self.0.bind(py);
        if let Ok(s) = obj.cast::<PyString>() {
            Ok(s.to_str()?.as_bytes())
        } else {
            Ok(obj.cast::<PyBytes>()?.as_bytes())
        }
    }
}

/// The keys a ``Chafernet`` uses: the first encrypts, and all are tried in order to decrypt.
///
/// To rotate keys, prepend a new one with ``with_new_key()``, deploy the new keyset everywhere, and drop the old key
/// with ``without_oldest()`` once every token it encrypted has expired. The text form, ``to_base64()``, is standard base64 of the JSON document
/// ``{"keys":["<base64 key>",...]}``, for passing a keyset in configuration.
#[pyclass(module = "chafernet", name = "Keyset", frozen)]
struct PyKeyset(chafernet::Keyset);

#[pymethods]
impl PyKeyset {
    /// A keyset holding one new random key.
    #[staticmethod]
    fn generate() -> Self {
        Self(chafernet::Keyset::generate())
    }

    /// A keyset from its text form, as ``to_base64()`` writes it, given as ``str`` or as a bytes-like object.
    ///
    /// Raises:
    ///     ValueError: ``text`` is not base64, does not decode to the JSON document, or holds no key or a key that is
    ///         not valid.
    #[staticmethod]
    fn from_base64(text: KeyText) -> PyResult<Self> {
        chafernet::Keyset::from_base64(&*text.0)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// A keyset from its JSON form, ``{"keys":["<base64 key>",...]}``, given as ``str`` or as a bytes-like object.
    ///
    /// Raises:
    ///     ValueError: ``json`` is not that document, or holds no key or a key that is not valid.
    #[staticmethod]
    fn from_json(json: KeyText) -> PyResult<Self> {
        chafernet::Keyset::from_json(&*json.0)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// A keyset from keys in base64, each a ``str`` or a bytes-like object, the first of which encrypts.
    ///
    /// Raises:
    ///     ValueError: ``keys`` is empty or holds a key that is not valid base64 of 32 bytes.
    #[staticmethod]
    fn from_keys(keys: KeyList) -> PyResult<Self> {
        let keys = keys
            .0
            .iter()
            .enumerate()
            .map(|(index, text)| {
                chafernet::Key::from_base64(&*text.0)
                    .map_err(|e| PyValueError::new_err(format!("key {index} of the keyset: {e}")))
            })
            .collect::<PyResult<Vec<_>>>()?;
        chafernet::Keyset::try_from(keys)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// The keyset as standard base64 of its JSON form.
    ///
    /// Python cannot wipe a ``str``, so the key material stays in memory until it is overwritten. Where that matters,
    /// use ``to_base64_buffer()``.
    fn to_base64<'py>(&self, py: Python<'py>) -> Bound<'py, PyString> {
        PyString::new(py, &self.0.to_base64())
    }

    /// The keyset as compact JSON, ``{"keys":["<base64 key>",...]}``.
    ///
    /// Python cannot wipe a ``str``, so the key material stays in memory until it is overwritten. Where that matters,
    /// use ``to_json_buffer()``.
    fn to_json<'py>(&self, py: Python<'py>) -> Bound<'py, PyString> {
        PyString::new(py, &self.0.to_json())
    }

    /// ``to_base64()`` as a ``bytearray``, which the caller can wipe once done with it, as in
    /// ``buffer[:] = bytes(len(buffer))``. Any ``str`` or ``bytes`` made from it is a copy that cannot be wiped.
    fn to_base64_buffer<'py>(&self, py: Python<'py>) -> Bound<'py, PyByteArray> {
        PyByteArray::new(py, self.0.to_base64().as_bytes())
    }

    /// ``to_json()`` as a ``bytearray``, which the caller can wipe once done with it, as in
    /// ``buffer[:] = bytes(len(buffer))``. Any ``str`` or ``bytes`` made from it is a copy that cannot be wiped.
    fn to_json_buffer<'py>(&self, py: Python<'py>) -> Bound<'py, PyByteArray> {
        PyByteArray::new(py, self.0.to_json().as_bytes())
    }

    /// A copy of the keyset with a new random key prepended, which becomes the one that encrypts.
    fn with_new_key(&self) -> Self {
        Self(self.0.with_new_key())
    }

    /// A copy of the keyset without its last key, the oldest.
    ///
    /// Raises:
    ///     ValueError: the keyset has only one key.
    fn without_oldest(&self) -> PyResult<Self> {
        self.0
            .without_oldest()
            .map(Self)
            .ok_or_else(|| PyValueError::new_err("keyset has only one key"))
    }

    fn __eq__<'py>(&self, py: Python<'py>, other: &Bound<'py, PyAny>) -> Py<PyAny> {
        match other.cast::<Self>() {
            Ok(other) => pyo3::types::PyBool::new(py, other.get().0 == self.0)
                .to_owned()
                .into_any()
                .unbind(),
            Err(_) => py.NotImplemented(),
        }
    }

    /// The number of keys, at least one.
    fn __len__(&self) -> usize {
        self.0.len()
    }

    fn __repr__(&self) -> String {
        format!("<Keyset with {} keys>", self.0.len())
    }
}

/// Encrypts and decrypts tokens with a ``Keyset``.
///
/// A token is ``base64url(nonce ‖ XChaCha20-Poly1305(key, nonce, version ‖ timestamp ‖ plaintext, aad))``: a random
/// 24-byte nonce, then the ciphertext of a version byte (1), the timestamp as 8 big-endian bytes of seconds since the
/// Unix epoch, and the plaintext, with the 16-byte authentication tag at the end.
///
/// The additional authenticated data (``aad``) is not stored in the token; the same value must be given to decrypt
/// it, which binds the token to its purpose and context without revealing them. It is a ``Context`` (a domain and
/// parts, whose digest is the data) or ``bytes`` used as they are; omitted, it is empty.
#[pyclass(module = "chafernet", name = "Chafernet", frozen)]
struct PyChafernet(chafernet::Chafernet);

/// A number of seconds: any Python ``int``, so that one out of range is the ``ValueError`` of ``seconds``, which names
/// the argument, rather than an ``OverflowError`` from the conversion.
#[derive(Clone, Copy)]
enum Seconds {
    Fits(u64),
    Negative,
    TooLarge,
}

impl<'a, 'py> FromPyObject<'a, 'py> for Seconds {
    type Error = PyErr;
    const INPUT_TYPE: PyStaticExpr = PyInt::TYPE_HINT;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        let Ok(int) = obj.cast::<PyInt>() else {
            return Err(PyTypeError::new_err(format!(
                "expected int, not {}",
                obj.get_type().name()?
            )));
        };
        if let Ok(value) = int.extract::<u64>() {
            Ok(Seconds::Fits(value))
        } else if int.lt(0)? {
            Ok(Seconds::Negative)
        } else {
            Ok(Seconds::TooLarge)
        }
    }
}

/// The seconds, or a ``ValueError`` naming the argument if they are negative or do not fit the 64 bits of a timestamp.
fn seconds(name: &str, value: Seconds) -> PyResult<u64> {
    match value {
        Seconds::Fits(value) => Ok(value),
        Seconds::Negative => Err(PyValueError::new_err(format!(
            "{name} must not be negative"
        ))),
        Seconds::TooLarge => Err(PyValueError::new_err(format!(
            "{name} must be less than 2**64"
        ))),
    }
}

#[pymethods]
impl PyChafernet {
    /// A Chafernet that encrypts with the keyset's first key and decrypts with any of its keys. ``keyset`` may also
    /// be the text form of a keyset, as ``Keyset.to_base64()`` writes it. ``max_clock_skew`` is how many seconds in
    /// the future a token's timestamp may be before ``decrypt`` rejects it, allowing for clocks that disagree
    /// slightly; the default is ``DEFAULT_MAX_CLOCK_SKEW``.
    ///
    /// Raises:
    ///     ValueError: ``keyset`` is text that is not a keyset, or ``max_clock_skew`` is negative or 2**64 or more.
    #[new]
    #[pyo3(signature = (keyset, /, *, max_clock_skew: "int" = Seconds::Fits(chafernet::DEFAULT_MAX_CLOCK_SKEW.as_secs())))]
    fn new(keyset: KeysetArg<'_>, max_clock_skew: Seconds) -> PyResult<Self> {
        let max_clock_skew = Duration::from_secs(seconds("max_clock_skew", max_clock_skew)?);
        let chafernet = match keyset {
            KeysetArg::Keyset(keyset) => chafernet::Chafernet::new(&keyset.get().0),
            KeysetArg::Text(text) => chafernet::Chafernet::new(
                &chafernet::Keyset::from_base64(&*text.0)
                    .map_err(|e| PyValueError::new_err(e.to_string()))?,
            ),
        };
        Ok(Self(chafernet.max_clock_skew(max_clock_skew)))
    }

    /// Encrypts ``plaintext`` (``str`` as UTF-8) into a token.
    ///
    /// The additional authenticated data is ``aad``: a ``Context`` (the purpose of the tokens, such as
    /// ``"shard-ip"``, and the fields of the context: a collection name, a tenant), or ``bytes`` used as they are;
    /// omitted, it is empty. The timestamp is the current time, or ``current_time`` in seconds since the Unix epoch.
    ///
    /// Raises:
    ///     ValueError: ``current_time`` is negative or 2**64 or more.
    #[pyo3(signature = (plaintext, /, aad = None, *, current_time: "int | None" = None))]
    fn encrypt(
        &self,
        py: Python<'_>,
        plaintext: Plaintext,
        aad: Option<AadArg<'_>>,
        current_time: Option<Seconds>,
    ) -> PyResult<String> {
        let current_time = current_time
            .map(|t| seconds("current_time", t))
            .transpose()?;
        let plaintext = plaintext.as_bytes(py)?;
        let aad = aad_bytes(&aad);
        Ok(py.detach(|| {
            let mut encrypt = self.0.encrypt(plaintext).aad(aad);
            if let Some(timestamp) = current_time {
                encrypt = encrypt.at(timestamp);
            }
            encrypt.seal()
        }))
    }

    /// Decrypts ``token``, checking its timestamp against the current time: with a ``ttl`` in seconds, the token must
    /// have been encrypted no more than ``ttl`` seconds ago, and in any case no more than ``max_clock_skew`` seconds
    /// in the future. ``ttl=None`` accepts a token however old. ``aad`` is as for ``encrypt`` and must match what
    /// the token was encrypted with; ``current_time`` replaces the clock.
    ///
    /// Raises:
    ///     InvalidTokenError: ``token`` cannot be decoded, was not encrypted with one of the keys and this additional
    ///         authenticated data, or has been altered.
    ///     PlaintextFormatVersionError: ``token`` is genuine but has another plaintext format version.
    ///     TokenExpiredError: ``token`` is older than ``ttl``.
    ///     TokenNotYetValidError: ``token`` has a timestamp more than ``max_clock_skew`` seconds in the future.
    ///     ValueError: ``ttl`` or ``current_time`` is negative or 2**64 or more.
    #[pyo3(signature = (token, ttl: "int | None", /, aad = None, *, current_time: "int | None" = None))]
    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        ttl: Option<Seconds>,
        aad: Option<AadArg<'_>>,
        current_time: Option<Seconds>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.decrypt_with_timestamp(py, token, ttl, aad, current_time)
            .map(|(plaintext, _)| plaintext)
    }

    /// Decrypts ``token`` as ``decrypt`` does, with the same arguments and the same time checks, and returns the
    /// plaintext and the token's timestamp, in seconds since the Unix epoch: for a caller that acts on a token's age,
    /// such as one that replaces a token halfway through its life. A token that fails the time checks gives its
    /// timestamp only on the exception, as ``TokenExpiredError.timestamp`` or ``TokenNotYetValidError.timestamp``,
    /// and never as a result.
    ///
    /// Raises:
    ///     InvalidTokenError: ``token`` cannot be decoded, was not encrypted with one of the keys and this additional
    ///         authenticated data, or has been altered.
    ///     PlaintextFormatVersionError: ``token`` is genuine but has another plaintext format version.
    ///     TokenExpiredError: ``token`` is older than ``ttl``.
    ///     TokenNotYetValidError: ``token`` has a timestamp more than ``max_clock_skew`` seconds in the future.
    ///     ValueError: ``ttl`` or ``current_time`` is negative or 2**64 or more.
    #[pyo3(signature = (token, ttl: "int | None", /, aad = None, *, current_time: "int | None" = None))]
    fn decrypt_with_timestamp<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        ttl: Option<Seconds>,
        aad: Option<AadArg<'_>>,
        current_time: Option<Seconds>,
    ) -> PyResult<(Bound<'py, PyBytes>, u64)> {
        let ttl = ttl.map(|t| seconds("ttl", t)).transpose()?;
        let current_time = current_time
            .map(|t| seconds("current_time", t))
            .transpose()?;
        let aad = aad_bytes(&aad);
        let (plaintext, timestamp) = py
            .detach(|| {
                let mut decrypt = self.0.decrypt(token).aad(aad);
                if let Some(ttl) = ttl {
                    decrypt = decrypt.ttl(Duration::from_secs(ttl));
                }
                if let Some(now) = current_time {
                    decrypt = decrypt.at(now);
                }
                decrypt.open_with_timestamp()
            })
            .map_err(|error| invalid_token(py, error))?;
        // The Python bytes are a copy that Python cannot wipe; this one, at least, is wiped when dropped.
        let plaintext = Zeroizing::new(plaintext);
        Ok((PyBytes::new(py, &plaintext), timestamp))
    }

    fn __repr__(&self) -> String {
        format!("<{:?}>", self.0)
    }
}

/// The ``keyset`` argument of ``Chafernet``: a ``Keyset`` or its text form.
enum KeysetArg<'py> {
    Keyset(Bound<'py, PyKeyset>),
    Text(KeyText),
}

impl<'a, 'py> FromPyObject<'a, 'py> for KeysetArg<'py> {
    type Error = PyErr;
    const INPUT_TYPE: PyStaticExpr = type_hint_union!(PyKeyset::TYPE_HINT, KeyText::INPUT_TYPE);

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(keyset) = obj.cast::<PyKeyset>() {
            return Ok(KeysetArg::Keyset(keyset.to_owned()));
        }
        match KeyText::extract(obj) {
            Ok(text) => Ok(KeysetArg::Text(text)),
            Err(_) => Err(pyo3::exceptions::PyTypeError::new_err(format!(
                "keyset must be a Keyset, str, or bytes-like object, not {}",
                obj.get_type().name()?
            ))),
        }
    }
}

/// The Python exception for `error`. The timestamp of a token outside its time window is set on the exception, which
/// is made here rather than when it is raised, so that it is there to set.
fn invalid_token(py: Python<'_>, error: chafernet::InvalidToken) -> PyErr {
    match error {
        chafernet::InvalidToken::Expired { timestamp } => {
            let raised = PyErr::new::<TokenExpiredError, _>(error.to_string());
            if let Ok(exception) = raised.value(py).cast::<TokenExpiredError>() {
                let _ = exception.get().timestamp.set(timestamp);
            }
            raised
        }
        chafernet::InvalidToken::NotYetValid { timestamp } => {
            let raised = PyErr::new::<TokenNotYetValidError, _>(error.to_string());
            if let Ok(exception) = raised.value(py).cast::<TokenNotYetValidError>() {
                let _ = exception.get().timestamp.set(timestamp);
            }
            raised
        }
        chafernet::InvalidToken::PlaintextFormatVersion(_) => {
            PyErr::new::<PlaintextFormatVersionError, _>(error.to_string())
        }
        _ => PyErr::new::<InvalidTokenError, _>(error.to_string()),
    }
}

#[pymodule(gil_used = false)]
mod _chafernet {
    #[pymodule_export]
    use super::{
        InvalidTokenError, PlaintextFormatVersionError, PyChafernet, PyContext, PyKeyset,
        TokenExpiredError, TokenNotYetValidError,
    };

    /// The version of the package.
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const __version__: &str = env!("CARGO_PKG_VERSION");

    /// How many seconds in the future a token's timestamp may be before ``decrypt`` rejects it, allowing for clocks
    /// that disagree slightly, unless a ``Chafernet`` is made with another ``max_clock_skew``.
    #[pymodule_export]
    const DEFAULT_MAX_CLOCK_SKEW: u64 = chafernet::DEFAULT_MAX_CLOCK_SKEW.as_secs();
}
