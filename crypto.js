/*
 * DeniableMulti — N-key deniable encryption, ported to the browser.
 *
 * ⚠️ PROOF OF CONCEPT — NOT FOR PRODUCTION.
 * This is a research/educational implementation. It has NOT been formally
 * verified, independently audited, or cryptanalyzed. Do NOT use it to protect
 * real secrets. See README.md and SECURITY.md for the threat model and the
 * reasons it is not production-ready.
 *
 * Byte-for-byte compatible with multi_key/deniable_multi.py (DeniableMulti).
 * One headerless container, N slots, N independent keys. Each key
 * self-locates its own slot: the decryptor never needs to know how many
 * slots exist, and an adversary holding only the keys you reveal cannot
 * count the rest or verify completeness.
 *
 * Crypto runs entirely here, in the browser, via WebCrypto
 * (crypto.subtle + crypto.getRandomValues).  Keys and plaintext never leave
 * the page.  The same file runs unchanged under Node (>= 20) for
 * cross-verification against the Python implementation.
 *
 * Scheme notes (see multi_key/README.md):
 *   enc-key = HKDF(key, "m/enc")                      (salt = 32 zero bytes,
 *   position = HKDF(key, "m/pos/" + size + trial) % total   = Python salt=None)
 *   slot    = [u16 ct.len][nonce 12][AES-GCM ct]
 *   plaintext = [u32 real len][message][optional random padding to pad_to]
 *
 * UMD: usable as `require("./crypto.js")` in Node and as
 * `globalThis.DeniableMulti` in the browser.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.DeniableMulti = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const TE = new TextEncoder();
  const TD = new TextDecoder("utf-8", { fatal: false });

  // Domain separation (byte-for-byte with Python's _DOMAIN + labels).
  const DOMAIN   = new Uint8Array([0x6d]);                       // "m"
  const INFO_POS = new Uint8Array([0x2f, 0x70, 0x6f, 0x73, 0x2f]); // "/pos/"
  const INFO_ENC = new Uint8Array([0x2f, 0x65, 0x6e, 0x63]);      // "/enc"

  const POS_BYTES = 2, MAX_TRIALS = 32, ALIGN = 256, PADX = 4, JITTER = 4;
  const NONCE_LEN = 12, TAG_LEN = 16, LEN_PREFIX = 4;

  // ── bytes / encoding helpers ────────────────────────────────────

  function randomBytes(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  }

  function u16be(v) { return new Uint8Array([(v >> 8) & 0xff, v & 0xff]); }
  function u32be(v) {
    return new Uint8Array([
      (v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff,
    ]);
  }
  function u32read(b, at) {
    return ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
  }

  function concatBytes(...arrs) {
    let n = 0;
    for (const a of arrs) n += a.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }

  function bytesToHex(b) {
    let s = "";
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
    return s;
  }
  function hexToBytes(s) {
    s = String(s).trim();
    if (s.length % 2 !== 0) throw new Error("hex string has odd length");
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function bytesToB64(bytes) {
    const b = bytes; let out = "";
    for (let i = 0; i < b.length; i += 3) {
      const c0 = b[i], c1 = i + 1 < b.length ? b[i + 1] : 0, c2 = i + 2 < b.length ? b[i + 2] : 0;
      out += B64[c0 >> 2]
        + B64[((c0 & 3) << 4) | (c1 >> 4)]
        + B64[((c1 & 15) << 2) | (c2 >> 6)]
        + B64[c2 & 63];
    }
    const rem = b.length % 3;
    if (rem === 1) out = out.slice(0, -2) + "==";
    else if (rem === 2) out = out.slice(0, -1) + "=";
    return out;
  }
  function b64ToBytes(s) {
    s = String(s).replace(/=+$/, "").replace(/\s+/g, "");
    const out = [];
    let buf = 0, bits = 0;
    for (let i = 0; i < s.length; i++) {
      const idx = B64.indexOf(s[i]);
      if (idx < 0) continue;
      buf = (buf << 6) | idx; bits += 6;
      if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
    }
    return new Uint8Array(out);
  }

  function utf8ToBytes(s) { return TE.encode(s); }
  function bytesToUtf8(b) { return TD.decode(b); }

  // Supported key lengths in bits. The scheme itself is key-material-agnostic
  // (HKDF accepts any length); the bit length only controls how many random
  // bytes the generator emits and which hex strings are decoded as raw bytes.
  const KEY_BITS = [16, 32, 64, 128, 256, 512];
  const keyHexLen = (bits) => bits / 4;   // hex chars for a key of `bits`
  const keyByteLen = (bits) => bits / 8;  // bytes for a key of `bits`

  function randomKeyHex(bits) {
    if (bits === undefined || bits === null) bits = 256; // legacy default
    return bytesToHex(randomBytes(keyByteLen(bits)));
  }

  // ── key parsing: any string is a valid key ──────────────────────
  //
  // Rule (documented in README, cross-checked against Python in tests):
  //   * a hex string of the length matching the selected key length (bits/4
  //     hex chars) is decoded to its bytes  — generated / legacy 64-hex keys
  //   * any other non-empty string is used as its UTF-8 bytes, so Chinese,
  //     English, special characters and any length all work; the byte length
  //     is exactly whatever you typed.
  // The hex special case keeps existing ciphertexts (and the in-page
  // "randomize" keys) byte-compatible with the Python implementation.

  const HEX64_RE = /^[0-9a-fA-F]{64}$/;
  const HEXISH_RE = /^[0-9a-fA-F]+$/;

  function parseKey(s, bits) {
    s = String(s).trim();
    if (s.length === 0) throw new Error("key must not be empty");
    if (bits === undefined || bits === null) bits = 256; // legacy default
    if (HEX64_RE.test(s) && bits === 256) return hexToBytes(s);
    if (bits !== 256 && s.length === keyHexLen(bits) && HEXISH_RE.test(s)) return hexToBytes(s);
    return utf8ToBytes(s);
  }
  function keyInfo(s, bits) {
    s = String(s).trim();
    if (s.length === 0) throw new Error("key must not be empty");
    if (bits === undefined || bits === null) bits = 256;
    if (HEX64_RE.test(s) && bits === 256) return { kind: "hex", bytes: hexToBytes(s), byteLen: 32, hexish: true };
    if (bits !== 256 && s.length === keyHexLen(bits) && HEXISH_RE.test(s)) {
      const b = hexToBytes(s);
      return { kind: "hex", bytes: b, byteLen: b.length, hexish: true };
    }
    const b = utf8ToBytes(s);
    return { kind: "utf8", bytes: b, byteLen: b.length, hexish: HEXISH_RE.test(s) && s.length % 2 === 0 };
  }

  // ── wrap-around buffer I/O (mirrors deniable_core _put/_get) ────

  function getBytes(buf, at, n) {
    const sz = buf.length;
    if (at + n <= sz) return buf.slice(at, at + n);
    const cut = sz - at;
    const out = new Uint8Array(n);
    out.set(buf.slice(at), 0);
    out.set(buf.slice(0, n - cut), cut);
    return out;
  }
  function putBytes(buf, at, data) {
    const n = data.length, sz = buf.length;
    if (at + n <= sz) { buf.set(data, at); return; }
    const cut = sz - at;
    buf.set(data.slice(0, cut), at);
    buf.set(data.slice(cut), 0);
  }
  function hits(at, n, used, total) {
    const spans = at + n <= total ? [[at, at + n]] : [[at, total], [0, at + n - total]];
    for (const [a, b] of spans) {
      for (const [ua, ub] of used) if (a < ub && b > ua) return true;
    }
    return false;
  }
  function mark(at, n, total) {
    return at + n <= total ? [[at, at + n]] : [[at, total], [0, at + n - total]];
  }

  // ── cryptography (WebCrypto; salt = 32 zero bytes ≈ Python salt=None) ──

  async function hkdf(key, info, lengthBytes) {
    const ik = await crypto.subtle.importKey("raw", key, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info },
      ik, lengthBytes * 8,
    );
    return new Uint8Array(bits);
  }

  async function gcmEncrypt(ek, nonce, pt, aad) {
    const k = await crypto.subtle.importKey("raw", ek, "AES-GCM", false, ["encrypt"]);
    const opt = { name: "AES-GCM", iv: nonce };
    if (aad) opt.additionalData = aad;
    return new Uint8Array(await crypto.subtle.encrypt(opt, k, pt));
  }
  async function gcmDecrypt(ek, nonce, ct, aad) {
    const k = await crypto.subtle.importKey("raw", ek, "AES-GCM", false, ["decrypt"]);
    const opt = { name: "AES-GCM", iv: nonce };
    if (aad) opt.additionalData = aad;
    return new Uint8Array(await crypto.subtle.decrypt(opt, k, ct));
  }

  // ── slot position — HKDF(key, "m/pos/" + size + trial) ──────────

  async function pos(key, total, trial) {
    const info = concatBytes(DOMAIN, INFO_POS, u16be(total), u16be(trial || 0));
    const h = await hkdf(key, info, POS_BYTES);
    return ((h[0] << 8) | h[1]) % total;
  }
  async function encKey(key) {
    return hkdf(key, concatBytes(DOMAIN, INFO_ENC), 32);
  }

  // ── slot geometry (mirrors DeniableMulti._slot_bytes/_slot_len) ──

  function slotBytes(ptLen) { return POS_BYTES + NONCE_LEN + ptLen + TAG_LEN; }
  function slotLen(raw, p) {
    const prefix = getBytes(raw, p, POS_BYTES);
    const cl = (prefix[0] << 8) | prefix[1];
    if (cl < TAG_LEN) return null;
    return POS_BYTES + NONCE_LEN + cl;
  }
  function encodeSlot(nonce, ct) {
    return concatBytes(u16be(ct.length), nonce, ct);
  }
  function decodeSlot(data) {
    if (data.length < POS_BYTES + NONCE_LEN) return null;
    return { nonce: data.slice(POS_BYTES, POS_BYTES + NONCE_LEN), ct: data.slice(POS_BYTES + NONCE_LEN) };
  }

  // ── size queries ────────────────────────────────────────────────

  function minSize(messageLengths, padTo) {
    const sizes = padTo
      ? messageLengths.map(() => slotBytes(padTo))
      : messageLengths.map((l) => slotBytes(LEN_PREFIX + l));
    const raw = sizes.reduce((a, b) => a + b, 0);
    return Math.ceil(raw / ALIGN) * ALIGN;
  }
  function maxSize() { return 2 ** (8 * POS_BYTES) - 1; }

  // ── core encrypt ────────────────────────────────────────────────

  async function encryptMany(messages, keys, opts) {
    opts = opts || {};
    if (messages.length !== keys.length) throw new Error("messages and keys must have equal length");
    if (messages.length === 0) throw new Error("at least one message/key pair is required");
    const seen = new Set();
    for (const k of keys) {
      const h = bytesToHex(k);
      if (seen.has(h)) throw new Error("keys must be unique");
      seen.add(h);
    }

    const padTo = opts.pad_to;
    const real = messages.map((m) => (typeof m === "string" ? utf8ToBytes(m) : m));

    if (padTo !== undefined && padTo !== null) {
      if (padTo < LEN_PREFIX + 1) throw new Error("pad_to too small: " + padTo);
      for (const m of real) if (m.length > padTo - LEN_PREFIX) throw new Error("message longer than pad_to allows");
    }

    const slots = [];
    for (let i = 0; i < keys.length; i++) {
      let pt = concatBytes(u32be(real[i].length), real[i]);
      if (padTo !== undefined && padTo !== null) {
        pt = concatBytes(pt, randomBytes(padTo - pt.length));
      }
      const ek = await encKey(keys[i]);
      const n = randomBytes(NONCE_LEN);
      const ct = await gcmEncrypt(ek, n, pt, opts.aad);
      slots.push(encodeSlot(n, ct));
    }

    let total;
    if (opts.size !== undefined && opts.size !== null) {
      const need = minSize(real.map((m) => m.length), padTo);
      if (opts.size < need) throw new Error("container too small: " + opts.size + " < " + need);
      if (opts.size > maxSize()) throw new Error("container too large: " + opts.size);
      total = opts.size;
    } else {
      const base = Math.max(slots.reduce((a, s) => a + s.length, 0), 256) * PADX;
      const jit = randomBytes(1)[0] * JITTER;
      total = Math.ceil((base + jit) / ALIGN) * ALIGN;
    }

    const buf = randomBytes(total);
    const used = [];
    for (let i = 0; i < keys.length; i++) {
      let placed = false;
      for (let t = 0; t < MAX_TRIALS; t++) {
        const p = await pos(keys[i], total, t);
        if (!hits(p, slots[i].length, used, total)) {
          putBytes(buf, p, slots[i]);
          used.push(...mark(p, slots[i].length, total));
          placed = true;
          break;
        }
      }
      if (!placed) throw new Error("slot placement: all positions collide");
    }
    return buf;
  }

  // ── core decrypt ────────────────────────────────────────────────

  async function decryptMany(raw, key, aad) {
    const total = raw.length;
    if (total < POS_BYTES) return null;
    const ek = await encKey(key);
    for (let t = 0; t < MAX_TRIALS; t++) {
      const p = await pos(key, total, t);
      const sl = slotLen(raw, p);
      if (sl === null || sl > total) continue;
      const decoded = decodeSlot(getBytes(raw, p, sl));
      if (decoded === null) continue;
      let pt;
      try {
        pt = await gcmDecrypt(ek, decoded.nonce, decoded.ct, aad);
      } catch (e) {
        continue;
      }
      if (pt.length < LEN_PREFIX) continue;
      const n = u32read(pt, 0);
      return pt.slice(LEN_PREFIX, LEN_PREFIX + n);
    }
    return null;
  }

  // ── base64 convenience wrappers (mirror DeniableMulti.encrypt/decrypt) ──

  async function encrypt(messages, keys, opts) {
    opts = Object.assign({}, opts);
    if (opts.aad_hex) { opts.aad = hexToBytes(opts.aad_hex); delete opts.aad_hex; }
    const raw = await encryptMany(messages, keys.map((k) => parseKey(k, opts.bits)), opts);
    return bytesToB64(raw);
  }
  async function decrypt(b64, key, aadHex, bits) {
    try {
      return await decryptMany(b64ToBytes(b64), parseKey(key, bits), aadHex ? hexToBytes(aadHex) : undefined);
    } catch (e) {
      return null;
    }
  }

  return {
    // tunables (mirror the Python class attributes)
    posBytes: POS_BYTES, maxTrials: MAX_TRIALS, align: ALIGN,
    padx: PADX, jitter: JITTER, nonceLen: NONCE_LEN, tagLen: TAG_LEN, lenPrefix: LEN_PREFIX,
    // primitives (exported for the Node cross-verification harness)
    hkdf, encKey, pos, gcmEncrypt, gcmDecrypt,
    // geometry
    slotBytes, slotLen, encodeSlot, decodeSlot,
    minSize, maxSize,
    // core API
    encryptMany, decryptMany,
    // base64 convenience API
    encrypt, decrypt,
    // byte helpers
    bytesToHex, hexToBytes, bytesToB64, b64ToBytes, bytesToUtf8, utf8ToBytes,
    randomBytes, randomKeyHex,
    // key parsing (matching-length hex → decoded bytes, otherwise UTF-8)
    parseKey, keyInfo,
    // key-length helpers (bits: 16 / 32 / 64 / 128 / 256 / 512)
    KEY_BITS, keyHexLen, keyByteLen,
  };
});
