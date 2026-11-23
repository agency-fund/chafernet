"""Generates tests/vectors.json: tokens produced with PyNaCl (libsodium), the reference the format was defined against.

Each vector gives the keyset, a fixed nonce, the aad, the timestamp, and the plaintext, and the token that
XChaCha20-Poly1305 produces for them, so that the Rust crate's tests can check the wire format
byte for byte without PyNaCl at hand. Run with a Python that has PyNaCl: `uv run --with pynacl tools/gen_vectors.py`.
"""

import base64
import json
from pathlib import Path

import nacl.secret

VERSION = 1
# Fixed keys and nonces, so that the file is reproducible. Never reuse these anywhere else.
KEYS = [bytes(range(32)), bytes(range(100, 132)), bytes([0xAB] * 32)]
NONCES = [bytes(range(24)), bytes([0x42] * 24), bytes(range(200, 224))]


def keyset_base64(keys: list[bytes]) -> str:
    keys_b64 = [base64.standard_b64encode(k).decode() for k in keys]
    return base64.standard_b64encode(json.dumps({"keys": keys_b64}, separators=(",", ":")).encode()).decode()


def token(key: bytes, nonce: bytes, aad: bytes, timestamp: int, plaintext: bytes) -> str:
    message = VERSION.to_bytes(1, "big") + timestamp.to_bytes(8, "big") + plaintext
    return base64.urlsafe_b64encode(nacl.secret.Aead(key).encrypt(message, aad, nonce)).decode()


cases = [
    # (name, index of the key in KEYS that encrypts, nonce, aad, timestamp, plaintext)
    ("empty", 0, NONCES[0], b"", 0, b""),
    ("hello", 0, NONCES[1], b"", 1_700_000_000, b"hello"),
    ("aad", 0, NONCES[2], b"user=ann", 1_700_000_000, b"session 42"),
    ("binary", 1, NONCES[0], b"\x00\xff", 2**40, bytes(range(256))),
    ("older key", 2, NONCES[1], b"aad", 4_102_444_800, b"encrypted with the last key of the keyset"),
    ("max timestamp", 0, NONCES[2], b"", 2**64 - 1, b"x"),
    ("long", 1, NONCES[2], b"", 1_234_567_890, b"abcd" * 1000),
]
vectors = {
    "keyset": keyset_base64(KEYS),
    "keys": [base64.standard_b64encode(k).decode() for k in KEYS],
    "vectors": [
        {
            "name": name,
            "key": key_index,
            "nonce": nonce.hex(),
            "aad": aad.hex(),
            "timestamp": timestamp,
            "plaintext": plaintext.hex(),
            "token": token(KEYS[key_index], nonce, aad, timestamp, plaintext),
        }
        for name, key_index, nonce, aad, timestamp, plaintext in cases
    ],
}
out = Path(__file__).resolve().parent.parent / "tests" / "vectors.json"
out.write_text(json.dumps(vectors, indent=2) + "\n")
print(f"wrote {out}")
