"""
Cross-verification: crypto.js (browser WebCrypto) must be byte-for-byte
compatible with the Python DeniableMulti implementation.

Strategy: run crypto.js under Node (same file the browser loads), compare
deterministic primitives (HKDF / slot position / raw AES-GCM) against the
Python side, then do full round-trips in both directions.

Skipped entirely when node.js is unavailable.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

# Byte-level cross-validation needs the Python reference implementation
# (deniable_core + multi_key), which lives in the FULL project repo — not in
# this standalone webui package. When it (or the cryptography lib it uses) is
# absent, the whole module skips gracefully instead of failing.
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from deniable_core import _hkdf
    from multi_key.deniable_multi import DeniableMulti
    _HAS_REF = True
except ImportError:
    _HAS_REF = False

WEBUI = Path(__file__).resolve().parent.parent
HARNESS = WEBUI / "tests" / "_node_harness.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    NODE is None or not _HAS_REF,
    reason="node.js or the Python reference implementation (deniable_core / multi_key) not available",
)


def node(cmd: dict):
    """Run one harness command; return its 'value' (or raise)."""
    proc = subprocess.run(
        [NODE, str(HARNESS), json.dumps(cmd, ensure_ascii=False)],
        cwd=WEBUI,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out.get("ok"), out.get("error")
    return out["value"]


def key() -> bytes:
    return os.urandom(32)


# Strings exercising custom keys: Chinese, specials, emoji, short, long.
UTF8_KEYS = ["我的秘密密钥", "kEy!@# 特殊字符🔒", "a", "x" * 100, "english pass phrase"]


# ── custom key parsing (parseKey rule) ─────────────────────────────

def test_parse_key_rule():
    """Hex of the selected bit length → decoded bytes; other strings → UTF-8."""
    k = key()
    js = node({"cmd": "parseKey", "key": k.hex()})
    assert js == {"kind": "hex", "byteLen": 32, "hex": k.hex()}

    for s in UTF8_KEYS:
        b = s.encode("utf-8")
        js = node({"cmd": "parseKey", "key": s})
        assert js == {"kind": "utf8", "byteLen": len(b), "hex": b.hex()}, s

    with pytest.raises(Exception, match="empty"):
        node({"cmd": "parseKey", "key": "   "})


@pytest.mark.parametrize("bits", [16, 32, 64, 128, 256, 512])
def test_parse_key_rule_respects_selected_bits(bits):
    """A hex string matching the selected bit length decodes to bits/8 bytes."""
    kb = os.urandom(bits // 8)
    js = node({"cmd": "parseKey", "key": kb.hex(), "bits": bits})
    assert js == {"kind": "hex", "byteLen": bits // 8, "hex": kb.hex()}

    # same string under a different selected length is NOT decoded → utf8
    other = 256 if bits != 256 else 128
    js2 = node({"cmd": "parseKey", "key": kb.hex(), "bits": other})
    assert js2["kind"] == "utf8"

    # generated key has exactly the selected hex length
    gk = node({"cmd": "randomKeyHex", "bits": bits})
    assert len(gk) == bits // 4


def test_64_hex_string_key_is_decoded_not_utf8():
    """A 64-hex string behaves as its decoded 32 bytes (existing ciphertexts
    and in-page generated keys keep working), while its UTF-8 form is a
    different key entirely."""
    k = key()

    # JS encrypts with the hex *string* → Python decrypts with decoded bytes
    hex_ct = node({"cmd": "encryptMany", "messages": ["hex keyed"], "keys": [k.hex()]})
    assert DeniableMulti.decrypt_many(bytes.fromhex(hex_ct), k) == b"hex keyed"

    # Python encrypts with decoded bytes → JS decrypts with the hex *string*
    ct = DeniableMulti.encrypt_many(["py hex"], [k])
    res = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(), "keys": [k.hex()]})
    assert bytes.fromhex(res[0]) == b"py hex"

    # forcing the same text through UTF-8 is a different key → must fail
    res2 = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                 "keys": [{"utf8": k.hex()}]})
    assert res2[0] is None


# ── deterministic primitives ───────────────────────────────────────

def test_hkdf_matches():
    for info in [b"a", b"m/enc", b"m/pos/\x01\x00\x00", b"x" * 50, b""]:
        for length in [2, 16, 32, 64]:
            k = key()
            py = _hkdf(k, info, length)
            js = node({"cmd": "hkdf", "key": k.hex(), "info": info.hex(), "length": length})
            assert js == py.hex(), (info, length)


def test_pos_matches():
    for total in [2, 3, 256, 1000, 4096, 65535]:
        for trial in [0, 1, 7, 31]:
            k = key()
            py = DeniableMulti._pos(k, total, trial)
            js = node({"cmd": "pos", "key": k.hex(), "total": total, "trial": trial})
            assert js == py, (total, trial)


def test_gcm_primitive_matches():
    """Raw AES-GCM (with the derived key used directly): byte-identical ct+tag."""
    ek, nonce, pt = key(), os.urandom(12), os.urandom(60)
    aad = b"app/v1"

    py_ct = AESGCM(ek).encrypt(nonce, pt, aad)
    js_ct = node({"cmd": "gcmEnc", "ek": ek.hex(), "nonce": nonce.hex(),
                  "pt": pt.hex(), "aad": aad.hex()})
    assert js_ct == py_ct.hex()

    # JS decrypts Python's ciphertext (and vice-versa is implied by round-trips)
    js_pt = node({"cmd": "gcmDec", "ek": ek.hex(), "nonce": nonce.hex(),
                  "ct": py_ct.hex(), "aad": aad.hex()})
    assert js_pt == pt.hex()

    # no-AAD path
    py_ct2 = AESGCM(ek).encrypt(nonce, pt, None)
    assert node({"cmd": "gcmEnc", "ek": ek.hex(), "nonce": nonce.hex(),
                 "pt": pt.hex()}) == py_ct2.hex()


# ── size queries ───────────────────────────────────────────────────

def test_min_size_matches():
    for lengths in ([10], [10, 10], [100, 50, 50], [0, 5, 200]):
        assert node({"cmd": "minSize", "lengths": lengths, "pad_to": None}) == \
            DeniableMulti.min_size(lengths)
        assert node({"cmd": "minSize", "lengths": lengths, "pad_to": 256}) == \
            DeniableMulti.min_size(lengths, pad_to=256)


def test_max_size_matches():
    assert node({"cmd": "maxSize"}) == DeniableMulti.max_size()


# ── round-trips: Python encrypts, JS decrypts ──────────────────────

@pytest.mark.parametrize("n,pad_to,aad", [
    (1, None, None),
    (2, None, None),
    (3, 64, None),
    (3, 256, b"deadbeef"),
])
def test_roundtrip_py_to_js(n, pad_to, aad):
    msgs = [f"message {i} 消息" for i in range(n)]  # include non-ASCII
    keys = [key() for _ in range(n)]
    ct = DeniableMulti.encrypt_many(msgs, keys, pad_to=pad_to, aad=aad)

    results = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                    "keys": [k.hex() for k in keys],
                    "aad": aad.hex() if aad else None})
    assert len(results) == n
    for m, r in zip(msgs, results):
        assert bytes.fromhex(r) == m.encode()

    # a wrong key must decrypt to null
    rnd = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                "keys": [key().hex()]})
    assert rnd[0] is None


def test_roundtrip_py_to_js_with_aad_mismatch():
    keys = [key(), key()]
    aad = b"app/v1"
    ct = DeniableMulti.encrypt_many(["real", "fake"], keys, aad=aad)
    ok = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
               "keys": [keys[0].hex()], "aad": aad.hex()})
    assert bytes.fromhex(ok[0]) == b"real"
    missing = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                    "keys": [keys[0].hex()]})
    assert missing[0] is None


def test_empty_message_py_to_js():
    keys = [key(), key()]
    ct = DeniableMulti.encrypt_many(["", "cover"], keys)
    res = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                "keys": [k.hex() for k in keys]})
    assert res[0] == b"".hex()
    assert res[1] == b"cover".hex()


# ── round-trips: JS encrypts, Python decrypts ──────────────────────

@pytest.mark.parametrize("n,pad_to,aad", [
    (1, None, None),
    (2, None, None),
    (3, 128, None),
    (2, 256, b"00ff"),
])
def test_roundtrip_js_to_py(n, pad_to, aad):
    msgs = [f"js message {i}" for i in range(n)]
    keys = [key() for _ in range(n)]
    hex_ct = node({"cmd": "encryptMany", "messages": msgs,
                   "keys": [k.hex() for k in keys],
                   "pad_to": pad_to, "aad": aad.hex() if aad else None})
    raw = bytes.fromhex(hex_ct)
    for m, k in zip(msgs, keys):
        assert DeniableMulti.decrypt_many(raw, k, aad=aad) == m.encode()
    # wrong key → None
    assert DeniableMulti.decrypt_many(raw, key()) is None


def test_empty_message_js_to_py():
    keys = [key()]
    hex_ct = node({"cmd": "encryptMany", "messages": [""], "keys": [keys[0].hex()]})
    assert DeniableMulti.decrypt_many(bytes.fromhex(hex_ct), keys[0]) == b""


def test_binary_message_js_to_py():
    """JS can encrypt raw bytes (passed as hex) that Python must recover intact."""
    keys = [key()]
    blob = bytes(range(256))
    hex_ct = node({"cmd": "encryptMany",
                   "messages": [{"hex": blob.hex()}],
                   "keys": [keys[0].hex()]})
    assert DeniableMulti.decrypt_many(bytes.fromhex(hex_ct), keys[0]) == blob


# ── round-trips with custom (UTF-8) string keys ────────────────────

@pytest.mark.parametrize("s", UTF8_KEYS)
def test_roundtrip_utf8_keys_py_to_js(s):
    """Python encrypts with UTF-8 bytes of a custom string; JS decrypts by
    passing that same string through the browser's parseKey rule."""
    other = key()
    ct = DeniableMulti.encrypt_many(["消息 中文", "cover story"], [s.encode(), other], pad_to=256)
    res = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                "keys": [s, other.hex()]})
    assert bytes.fromhex(res[0]) == "消息 中文".encode(), s
    assert bytes.fromhex(res[1]) == b"cover story"


@pytest.mark.parametrize("s", UTF8_KEYS)
def test_roundtrip_utf8_keys_js_to_py(s):
    """JS encrypts with custom string keys; Python decrypts with the same
    UTF-8 bytes."""
    other = key()
    hex_ct = node({"cmd": "encryptMany", "messages": ["js 消息", "cover"],
                   "keys": [s, other.hex()], "pad_to": 128})
    raw = bytes.fromhex(hex_ct)
    assert DeniableMulti.decrypt_many(raw, s.encode()) == "js 消息".encode(), s
    assert DeniableMulti.decrypt_many(raw, other) == b"cover"


def test_wrong_custom_key_fails_cleanly():
    """A similar-but-wrong custom key must not decrypt (no cross-key leakage)."""
    k = "我的密钥甲"
    ct = DeniableMulti.encrypt_many(["secret"], [k.encode()])
    res = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                "keys": ["我的密钥乙"]})  # different Chinese key
    assert res[0] is None
    # same string, but a typo → fails
    res2 = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                 "keys": ["我的密钥 甲"]})  # extra space
    assert res2[0] is None


@pytest.mark.parametrize("bits", [16, 32, 128, 512])
def test_roundtrip_key_lengths(bits):
    """Keys of various bit lengths round-trip JS↔Python in both directions."""
    k, other = os.urandom(bits // 8), os.urandom(bits // 8)

    # Python encrypts with bits/8-byte keys → JS decrypts with the hex strings
    # at that selected length (parseKey decodes them).
    ct = DeniableMulti.encrypt_many(["长消息 with 中文", "cover"], [k, other], pad_to=256)
    res = node({"cmd": "decryptB64", "b64": base64.b64encode(ct).decode(),
                "keys": [k.hex(), other.hex()], "bits": bits})
    assert bytes.fromhex(res[0]) == "长消息 with 中文".encode()
    assert bytes.fromhex(res[1]) == b"cover"

    # JS encrypts with bits/8-byte keys → Python decrypts with the raw bytes
    hex_ct = node({"cmd": "encryptMany", "messages": ["js msg", "cover"],
                   "keys": [k.hex(), other.hex()], "bits": bits, "pad_to": 128})
    raw = bytes.fromhex(hex_ct)
    assert DeniableMulti.decrypt_many(raw, k) == b"js msg"
    assert DeniableMulti.decrypt_many(raw, other) == b"cover"


def test_key_length_mismatch_does_not_decrypt():
    """The same hex string under a different selected length is a different key."""
    k = os.urandom(16)  # 128-bit key
    hex_ct = node({"cmd": "encryptMany", "messages": ["128bit"], "keys": [k.hex()], "bits": 128})
    # decrypt as 256-bit: the 32-hex string becomes UTF-8 → wrong key
    res = node({"cmd": "decryptB64", "b64": base64.b64encode(bytes.fromhex(hex_ct)).decode(),
                "keys": [k.hex()], "bits": 256})
    assert res[0] is None
    # but with the matching length it works
    res2 = node({"cmd": "decryptB64", "b64": base64.b64encode(bytes.fromhex(hex_ct)).decode(),
                 "keys": [k.hex()], "bits": 128})
    assert bytes.fromhex(res2[0]) == b"128bit"


# ── JS-side validation mirrors Python ──────────────────────────────

def test_js_size_too_small_raises():
    with pytest.raises(Exception, match="container too small"):
        node({"cmd": "encryptMany", "messages": ["x" * 500, "y" * 500],
              "keys": [key().hex(), key().hex()], "size": 256})


def test_js_pad_to_too_small_raises():
    with pytest.raises(Exception, match="pad_to"):
        node({"cmd": "encryptMany", "messages": ["x"],
              "keys": [key().hex()], "pad_to": 4})


def test_js_message_exceeds_pad_to_raises():
    with pytest.raises(Exception, match="longer than pad_to"):
        node({"cmd": "encryptMany", "messages": ["x" * 100],
              "keys": [key().hex()], "pad_to": 64})


def test_js_duplicate_keys_raises():
    k = key().hex()
    with pytest.raises(Exception, match="unique"):
        node({"cmd": "encryptMany", "messages": ["a", "b"], "keys": [k, k]})
