//! The crate as a user sees it: only `chafernet::*`, no access to anything private.

use std::collections::HashSet;
use std::error::Error;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE as BASE64URL};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305};
use chafernet::{
    Aad, Chafernet, Context, DEFAULT_MAX_CLOCK_SKEW, InvalidToken, KEY_LEN, Key, KeyError, Keyset,
    KeysetError, PLAINTEXT_FORMAT_VERSION,
};

/// A token built with the cipher alone, as the format is documented: a check that the crate's tokens are nothing
/// more than that.
fn handmade_token(
    key: &Key,
    nonce: &[u8; 24],
    version: u8,
    timestamp: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> String {
    let mut message = vec![version];
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(plaintext);
    let ciphertext = XChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt(nonce.into(), Payload { msg: &message, aad })
        .unwrap();
    let mut token = nonce.to_vec();
    token.extend_from_slice(&ciphertext);
    BASE64URL.encode(token)
}

#[test]
fn round_trips_through_the_builders() {
    let chafernet = Chafernet::new(&Keyset::generate());
    for plaintext in [&b""[..], b"\0", b"hello", &[0xff; 5000]] {
        let token = chafernet.encrypt(plaintext).seal();
        assert_eq!(chafernet.decrypt(&token).open().unwrap(), plaintext);
        assert_eq!(
            chafernet
                .decrypt(&token)
                .ttl(Duration::from_secs(60))
                .open()
                .unwrap(),
            plaintext
        );
        let token = chafernet
            .encrypt(plaintext)
            .aad(b"aad")
            .at(1_700_000_000)
            .seal();
        assert_eq!(
            chafernet
                .decrypt(&token)
                .aad(b"aad")
                .at(1_700_000_010)
                .ttl(Duration::from_secs(10))
                .open_with_timestamp()
                .unwrap(),
            (plaintext.to_vec(), 1_700_000_000)
        );
    }
    assert_ne!(
        chafernet.encrypt(b"x").seal(),
        chafernet.encrypt(b"x").seal()
    );
    // Settings may come in any order around the aad.
    let context = Context::new("session", &[]);
    let token = chafernet.encrypt(b"x").at(5).aad(context).seal();
    let opened = chafernet
        .decrypt(&token)
        .at(5)
        .aad(context)
        .ttl(Duration::ZERO)
        .open();
    assert_eq!(opened.unwrap(), b"x");
}

#[test]
fn aad_takes_every_form() {
    let chafernet = Chafernet::new(&Keyset::generate());
    let array = *b"aad";
    let vec = array.to_vec();
    let slice: &[u8] = &vec;
    let token = chafernet.encrypt(b"x").aad(&array).seal();
    assert_eq!(chafernet.decrypt(&token).aad(&vec).open().unwrap(), b"x");
    assert_eq!(chafernet.decrypt(&token).aad(slice).open().unwrap(), b"x");
    assert_eq!(
        chafernet
            .decrypt(&token)
            .aad(Aad::from(slice))
            .open()
            .unwrap(),
        b"x"
    );
    let context = Context::new("session", &[b"user:42", b"10.0.0.7"]);
    let token = chafernet.encrypt(b"x").aad(context).seal();
    assert_eq!(
        chafernet
            .decrypt(&token)
            .aad(Aad::from(&context))
            .open()
            .unwrap(),
        b"x"
    );
    assert_eq!(
        chafernet
            .decrypt(&token)
            .aad(context.as_bytes())
            .open()
            .unwrap(),
        b"x"
    );
    assert_eq!(
        chafernet
            .decrypt(&token)
            .aad(&context.as_bytes()[..])
            .open()
            .unwrap(),
        b"x"
    );
    assert_eq!(Aad::from(context).as_bytes(), context.as_bytes());
    assert_eq!(Aad::from(&context).as_bytes(), context.as_bytes());
    assert_eq!(Aad::from(&array).as_bytes(), b"aad");
    assert_eq!(Aad::from(&vec).as_bytes(), b"aad");
    assert_eq!(Aad::from(slice).as_bytes(), b"aad");
    // Any other context, and no context, is another aad.
    for other in [
        Context::new("session", &[b"user:43", b"10.0.0.7"]),
        Context::new("reset", &[b"user:42", b"10.0.0.7"]),
        Context::new("session", &[b"user:42"]),
        Context::new("session", &[b"user:4210.0.0.7"]),
        Context::new("session", &[]),
    ] {
        assert_eq!(
            chafernet.decrypt(&token).aad(other).open().unwrap_err(),
            InvalidToken::Unauthenticated
        );
    }
    assert_eq!(
        chafernet.decrypt(&token).open().unwrap_err(),
        InvalidToken::Unauthenticated
    );
    // No aad is the empty aad.
    let token = chafernet.encrypt(b"x").seal();
    assert_eq!(chafernet.decrypt(&token).aad(b"").open().unwrap(), b"x");
}

#[test]
fn context_is_a_value() {
    let context = Context::new("session", &[b"user:42"]);
    let same = Context::new("session", &[b"user:42"]);
    assert_eq!(context, same);
    assert_ne!(context, Context::new("session", &[b"user:43"]));
    assert_eq!(HashSet::from([context, same]).len(), 1);
    let copied = context;
    assert_eq!(copied, context);
    assert_eq!(context.as_bytes().len(), 32);
    // Parts are length-prefixed, and the domain is apart from the parts.
    assert_ne!(
        Context::new("d", &[b"a", b"b"]),
        Context::new("d", &[b"ab"])
    );
    assert_ne!(Context::new("d", &[b"a", b""]), Context::new("d", &[b"a"]));
    assert_ne!(Context::new("d", &[]), Context::new("e", &[]));
    assert_ne!(Context::new("", &[b"d"]), Context::new("d", &[]));
    let debug = format!("{context:?}");
    assert!(
        debug.starts_with("Context(") && debug.len() == "Context()".len() + 64,
        "{debug}"
    );
    assert_eq!(format!("{:?}", Aad::from(b"x")), "Aad(..)");
    assert_eq!(
        format!("{:?}", Aad::from(context)),
        format!("Aad({context:?})")
    );
}

#[test]
fn tokens_are_the_documented_construction() {
    let keyset = Keyset::generate();
    let chafernet = Chafernet::new(&keyset);
    let nonce = [7u8; 24];
    let token = handmade_token(
        keyset.primary(),
        &nonce,
        PLAINTEXT_FORMAT_VERSION,
        1234,
        b"hello",
        b"aad",
    );
    assert_eq!(
        chafernet
            .decrypt(&token)
            .aad(b"aad")
            .at(1234)
            .open_with_timestamp()
            .unwrap(),
        (b"hello".to_vec(), 1234)
    );
    // And the crate's own tokens have the same layout: nonce, ciphertext, tag, in base64url with padding.
    let token = chafernet.encrypt(b"hello!").seal();
    let raw = BASE64URL.decode(&token).unwrap();
    assert_eq!(raw.len(), 24 + 1 + 8 + 6 + 16);
    assert_eq!(BASE64URL.encode(&raw), token);
    assert!(token.ends_with("=="), "{token}");
}

#[test]
fn other_versions_are_rejected() {
    let keyset = Keyset::generate();
    let chafernet = Chafernet::new(&keyset);
    for version in [0, 2, 255] {
        let token = handmade_token(keyset.primary(), &[0; 24], version, 0, b"", b"");
        assert_eq!(
            chafernet.decrypt(&token).open().unwrap_err(),
            InvalidToken::PlaintextFormatVersion(version)
        );
    }
    // The version is read only from a token that authenticates: with the wrong key, it is never reached.
    let token = handmade_token(&Key::generate(), &[0; 24], 2, 0, b"", b"");
    assert_eq!(
        chafernet.decrypt(&token).open().unwrap_err(),
        InvalidToken::Unauthenticated
    );
}

#[test]
fn altered_tokens_are_rejected() {
    let chafernet = Chafernet::new(&Keyset::generate());
    let token = chafernet.encrypt(b"hello").aad(b"aad").seal();
    let unauthenticated = |result: Result<Vec<u8>, InvalidToken>| {
        assert_eq!(result.unwrap_err(), InvalidToken::Unauthenticated);
    };
    unauthenticated(chafernet.decrypt(&token).open());
    unauthenticated(chafernet.decrypt(&token).aad(b"aae").open());
    unauthenticated(
        Chafernet::new(&Keyset::generate())
            .decrypt(&token)
            .aad(b"aad")
            .open(),
    );
    let raw = BASE64URL.decode(&token).unwrap();
    for i in 0..raw.len() {
        let mut damaged = raw.clone();
        damaged[i] ^= 1;
        unauthenticated(
            chafernet
                .decrypt(&BASE64URL.encode(&damaged))
                .aad(b"aad")
                .open(),
        );
    }
    unauthenticated(
        chafernet
            .decrypt(&BASE64URL.encode(&raw[..raw.len() - 1]))
            .aad(b"aad")
            .open(),
    );
    // Bytes of the right length that no key made.
    unauthenticated(chafernet.decrypt(&BASE64URL.encode([0u8; 49])).open());
}

#[test]
fn malformed_tokens_are_rejected() {
    let chafernet = Chafernet::new(&Keyset::generate());
    // The shortest token is 49 bytes: nonce, version, timestamp, and tag.
    for token in ["", "!", "abc", &BASE64URL.encode([0u8; 48])] {
        assert_eq!(
            chafernet.decrypt(token).open().unwrap_err(),
            InvalidToken::Malformed,
            "{token:?}"
        );
    }
    // Unpadded, and standard rather than URL-safe base64, are not accepted. The nonce is random, so make a token that
    // has a character the alphabets differ on.
    let token = std::iter::repeat_with(|| chafernet.encrypt(&[0xfb; 7]).seal())
        .find(|token| token.contains(['-', '_']))
        .unwrap();
    assert!(token.ends_with('='));
    let standard = token.replace('-', "+").replace('_', "/");
    for other in [token.trim_end_matches('='), &standard] {
        assert_eq!(
            chafernet.decrypt(other).open().unwrap_err(),
            InvalidToken::Malformed
        );
    }
}

/// Every error's message, pinned here and nowhere else.
#[test]
fn error_messages() {
    let messages = [
        (
            InvalidToken::Malformed.to_string(),
            "token is not base64url or is too short",
        ),
        (
            InvalidToken::Unauthenticated.to_string(),
            "token was not encrypted with these keys and this aad, or has been altered",
        ),
        (
            InvalidToken::PlaintextFormatVersion(9).to_string(),
            "token is genuine but has plaintext format version 9; only 1 is supported",
        ),
        (
            InvalidToken::Expired { timestamp: 1234 }.to_string(),
            "token has expired",
        ),
        (
            InvalidToken::NotYetValid { timestamp: 1234 }.to_string(),
            "token's timestamp is in the future",
        ),
        (
            KeyError::Base64.to_string(),
            "key is not valid standard base64 with padding",
        ),
        (
            KeyError::Length(3).to_string(),
            "key is 3 bytes long rather than 32",
        ),
        (
            KeysetError::Base64.to_string(),
            "keyset is not valid standard base64 with padding",
        ),
        (KeysetError::Empty.to_string(), "keyset has no keys"),
        (
            KeysetError::Key {
                index: 1,
                error: KeyError::Length(3),
            }
            .to_string(),
            "key 1 of the keyset: key is 3 bytes long rather than 32",
        ),
    ];
    for (message, expected) in messages {
        assert_eq!(message, expected);
    }
    let _: Box<dyn Error> = Box::new(InvalidToken::Malformed);
    assert_eq!(
        Keyset::from_json("[]").unwrap_err().to_string(),
        r#"keyset is not the JSON document {"keys":[...]} (error at line 1, column 2)"#
    );
}

#[test]
fn ttl_and_clock_skew() {
    let keyset = Keyset::generate();
    let chafernet = Chafernet::new(&keyset);
    let token = chafernet.encrypt(b"x").at(100).seal();
    let ttl = Duration::from_secs(30);
    let open = |chafernet: &Chafernet, token: &str, ttl: Option<Duration>, now: u64| {
        let decrypt = chafernet.decrypt(token).at(now);
        match ttl {
            Some(ttl) => decrypt.ttl(ttl).open(),
            None => decrypt.open(),
        }
    };
    assert_eq!(open(&chafernet, &token, Some(ttl), 130).unwrap(), b"x");
    assert_eq!(
        open(&chafernet, &token, Some(ttl), 131).unwrap_err(),
        InvalidToken::Expired { timestamp: 100 }
    );
    assert_eq!(open(&chafernet, &token, None, 1 << 40).unwrap(), b"x");
    assert_eq!(
        open(&chafernet, &token, Some(Duration::ZERO), 100).unwrap(),
        b"x"
    );
    assert_eq!(
        open(&chafernet, &token, Some(Duration::ZERO), 101).unwrap_err(),
        InvalidToken::Expired { timestamp: 100 }
    );
    // The timestamp may be up to the clock skew in the future, whatever the ttl.
    assert_eq!(DEFAULT_MAX_CLOCK_SKEW, Duration::from_secs(30));
    assert_eq!(open(&chafernet, &token, Some(ttl), 70).unwrap(), b"x");
    for ttl in [Some(ttl), None] {
        assert_eq!(
            open(&chafernet, &token, ttl, 69).unwrap_err(),
            InvalidToken::NotYetValid { timestamp: 100 }
        );
    }
    // The skew is the Chafernet's to set.
    let strict = Chafernet::new(&keyset).max_clock_skew(Duration::ZERO);
    assert_eq!(open(&strict, &token, None, 100).unwrap(), b"x");
    assert_eq!(
        open(&strict, &token, None, 99).unwrap_err(),
        InvalidToken::NotYetValid { timestamp: 100 }
    );
    let lax = Chafernet::new(&keyset).max_clock_skew(Duration::MAX);
    let last = lax.encrypt(b"x").at(u64::MAX).seal();
    assert_eq!(open(&lax, &last, None, 0).unwrap(), b"x");
    // Arithmetic at the ends of the range does not overflow.
    assert_eq!(open(&chafernet, &last, Some(ttl), u64::MAX).unwrap(), b"x");
    assert_eq!(
        open(&chafernet, &last, Some(ttl), 0).unwrap_err(),
        InvalidToken::NotYetValid {
            timestamp: u64::MAX
        }
    );
    assert_eq!(
        open(&chafernet, &token, Some(Duration::MAX), u64::MAX).unwrap(),
        b"x"
    );
}

#[test]
fn keys_rotate() {
    let first = Keyset::generate();
    let token = Chafernet::new(&first).encrypt(b"x").seal();
    let second = first.with_new_key();
    assert_eq!((first.len(), second.len()), (1, 2));
    assert_eq!(&second.keys()[1..], first.keys());
    assert_ne!(second.primary(), first.primary());
    let rotated = Chafernet::new(&second);
    assert_eq!(rotated.decrypt(&token).open().unwrap(), b"x");
    let newer = rotated.encrypt(b"y").seal();
    assert_eq!(
        Chafernet::new(&first).decrypt(&newer).open().unwrap_err(),
        InvalidToken::Unauthenticated
    );
    assert_eq!(
        Chafernet::with_key(second.primary())
            .decrypt(&newer)
            .open()
            .unwrap(),
        b"y"
    );
    assert_eq!(
        Chafernet::from(second.primary())
            .decrypt(&newer)
            .open()
            .unwrap(),
        b"y"
    );
    let retired = second.without_oldest().unwrap();
    assert_eq!(retired.keys(), &second.keys()[..1]);
    assert_eq!(
        second.keys().len(),
        2,
        "without_oldest leaves the keyset as it was"
    );
    assert!(retired.without_oldest().is_none());
    assert_eq!(
        Chafernet::new(&retired).decrypt(&token).open().unwrap_err(),
        InvalidToken::Unauthenticated
    );
    assert_eq!(
        Chafernet::from(&retired).decrypt(&newer).open().unwrap(),
        b"y"
    );
}

#[test]
fn keysets_have_text_forms() {
    let keyset = Keyset::generate().with_new_key();
    let text = keyset.to_base64();
    assert_eq!(Keyset::from_base64(&text).unwrap(), keyset);
    assert_eq!(text.parse::<Keyset>().unwrap(), keyset);
    assert_eq!(
        Keyset::from_base64(format!(" {}\n", text.as_str())).unwrap(),
        keyset
    );
    let json = String::from_utf8(BASE64.decode(&text).unwrap()).unwrap();
    assert_eq!(json, keyset.to_json().as_str());
    assert_eq!(Keyset::from_json(&json).unwrap(), keyset);
    // Other fields are ignored, as a JSON reader with a schema does.
    let extended = json.replacen('{', r#"{"comment":"x","#, 1);
    assert_eq!(Keyset::from_json(&extended).unwrap(), keyset);
    let expected_json = format!(
        "{{\"keys\":[{}]}}",
        keyset
            .keys()
            .iter()
            .map(|key| format!("\"{}\"", key.to_base64().as_str()))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(json, expected_json);
    // Keys are not Clone; a caller copies one through its bytes.
    let copy = |key: &Key| Key::from_bytes(*key.as_bytes());
    assert_eq!(
        Keyset::try_from(keyset.keys().iter().map(copy).collect::<Vec<_>>()).unwrap(),
        keyset
    );
    assert_eq!(
        Keyset::from(copy(keyset.primary())).keys(),
        &keyset.keys()[..1]
    );
    assert_eq!(
        Keyset::new(copy(keyset.primary())).keys(),
        &keyset.keys()[..1]
    );
    assert_eq!(format!("{keyset:?}"), "Keyset(2 keys)");
    assert_eq!(
        format!("{:?}", Chafernet::new(&keyset)),
        "Chafernet(2 keys)"
    );
    // Text may also be given as bytes.
    assert_eq!(Keyset::from_base64(text.as_bytes()).unwrap(), keyset);
    assert_eq!(Keyset::from_json(json.as_bytes()).unwrap(), keyset);
    assert_eq!(
        Key::from_base64(keyset.primary().to_base64().as_bytes()).unwrap(),
        *keyset.primary()
    );
    assert_eq!(
        Keyset::from_base64(b"\xff").unwrap_err(),
        KeysetError::Base64
    );
    // Chafernet reads the same text through Keyset.
    let chafernet = Chafernet::new(&text.parse::<Keyset>().unwrap());
    assert_eq!(
        chafernet
            .decrypt(&Chafernet::new(&keyset).encrypt(b"x").seal())
            .open()
            .unwrap(),
        b"x"
    );
}

#[test]
fn keys_have_text_and_byte_forms() {
    let key = Key::generate();
    assert_eq!(key.to_base64().len(), 44);
    assert_eq!(Key::from_base64(key.to_base64()).unwrap(), key);
    assert_eq!(
        Key::from_base64(format!("{}\n", key.to_base64().as_str())).unwrap(),
        key
    );
    assert_eq!(Key::from_bytes(*key.as_bytes()), key);
    assert_eq!(Key::from(*key.as_bytes()), key);
    assert_eq!(Key::try_from(&key.as_bytes()[..]).unwrap(), key);
    assert_eq!(BASE64.decode(key.to_base64()).unwrap(), key.as_bytes());
    assert_eq!(KEY_LEN, 32);
    assert_ne!(Key::generate(), Key::generate());
    assert_eq!(
        format!("{key:?}"),
        "Key(..)",
        "the bytes are not in Debug output"
    );
    assert_eq!(Key::from_base64("!").unwrap_err(), KeyError::Base64);
    assert_eq!(Key::from_base64("AAAA").unwrap_err(), KeyError::Length(3));
    assert_eq!(
        Key::try_from(&[0u8; 31][..]).unwrap_err(),
        KeyError::Length(31)
    );
}

#[test]
fn keyset_errors() {
    let key = Key::generate().to_base64();
    let cases = [
        ("!".to_owned(), KeysetError::Base64),
        (BASE64.encode(r#"{"keys":[]}"#), KeysetError::Empty),
        (
            BASE64.encode(format!(r#"{{"keys":["{}","AAAA"]}}"#, key.as_str())),
            KeysetError::Key {
                index: 1,
                error: KeyError::Length(3),
            },
        ),
        (
            BASE64.encode(r#"{"keys":["!"]}"#),
            KeysetError::Key {
                index: 0,
                error: KeyError::Base64,
            },
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(Keyset::from_base64(&text).unwrap_err(), expected);
        assert_eq!(text.parse::<Keyset>().unwrap_err(), expected);
    }
    for json in ["[]", "{}", r#"{"keys":[1]}"#] {
        assert!(
            matches!(
                Keyset::from_json(json).unwrap_err(),
                KeysetError::Json { .. }
            ),
            "{json}"
        );
    }
    assert!(matches!(
        Keyset::from_base64(BASE64.encode("[]")).unwrap_err(),
        KeysetError::Json { .. }
    ));
    // serde_json quotes a string where it expects a list; the error must not carry the key it holds.
    let key = Key::generate().to_base64();
    let error = Keyset::from_json(format!(r#"{{"keys":"{}"}}"#, key.as_str())).unwrap_err();
    assert_eq!(
        error,
        KeysetError::Json {
            line: 1,
            column: 54
        }
    );
    assert!(!format!("{error} {error:?}").contains(key.as_str()));
    assert_eq!(
        Keyset::try_from(Vec::<Key>::new()).unwrap_err(),
        KeysetError::Empty
    );
    let error = Keyset::from_json(r#"{"keys":["AAAA"]}"#).unwrap_err();
    assert!(error.source().is_some(), "the key error is the source");
    assert!(Keyset::from_json("[]").unwrap_err().source().is_none());
}

#[test]
#[cfg_attr(
    target_family = "wasm",
    ignore = "the WebAssembly targets tested have no threads"
)]
fn chafernet_is_shared_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Chafernet>();
    assert_send_sync::<Keyset>();
    assert_send_sync::<Context>();
    let chafernet = std::sync::Arc::new(Chafernet::new(&Keyset::generate()));
    let threads: Vec<_> = (0..4u8)
        .map(|n| {
            let chafernet = chafernet.clone();
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let token = chafernet.encrypt(&[n]).aad(&[n]).seal();
                    assert_eq!(chafernet.decrypt(&token).aad(&[n]).open().unwrap(), [n]);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
}
