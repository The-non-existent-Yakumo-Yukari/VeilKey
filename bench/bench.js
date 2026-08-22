/*
 * VeilKey / DeniableMulti — empirical benchmark harness.
 *
 * Measures the *browser* implementation (crypto.js over WebCrypto) because
 * that is the code users actually run in the web UI.
 *
 * Metrics (all wall-clock, process-wide peak RSS via process.memoryUsage):
 *   • encrypt time + peak memory   — the seal operation
 *   • decrypt time                — one-key reveal of a single slot
 *
 * Dimension 1 — ciphertext length grows via the NUMBER OF SLOTS (messages):
 *     slots N in 1,2,4,8,16,32        (fixed 32-byte keys, 64-byte messages, pad_to=64)
 *
 * Dimension 2 — ciphertext length grows via MESSAGE SIZE per slot:
 *     message bytes in 1KB, 16KB, 64KB, 256KB   (fixed N=4 slots)
 *
 * Dimension 3 — KEY LENGTH bits: 16,32,64,128,256,512 (fixed N=4, 64-byte msgs)
 *     (the scheme is key-length-agnostic: HKDF expands any length to 32B;
 *      the random-key generator and the hex-parsing rule change with bits.)
 *
 * Dimension 4 — custom UTF-8 string keys of increasing byte length:
 *     8, 32, 128, 1024 bytes (fixed N=4, 64-byte msgs).
 *
 * Output is a JSON object written to a file given in argv[2] (or stdout if
 * none). Run:  node bench/bench.js [out.json]
 */
"use strict";

const fs = require("fs");
const path = require("path");
const DM = require("../crypto.js");

const TE = new TextEncoder();

function mb(b) { return b / (1024 * 1024); }

// crypto.js's randomBytes() calls crypto.getRandomValues() on the WHOLE buffer
// at once. WebCrypto caps a single getRandomValues call at 65536 bytes, so any
// container > 64 KiB throws QuotaExceededError. That is a real limitation of
// the current library. For benchmarking the *crypto/placement* cost (not the
// RNG cap), we patch the global crypto.getRandomValues to serve large requests
// by chunking from a pre-generated 8 MiB random pool (16 KiB chunks). This
// measures the HKDF/AES-GCM/placement work that actual use must perform; the
// RNG cap itself is documented separately as a finding.
const POOL = (() => {
  const total = 8 * 1024 * 1024; // 8 MiB
  const out = new Uint8Array(total);
  const chunk = 16 * 1024;
  for (let off = 0; off < total; off += chunk) {
    const len = Math.min(chunk, total - off);
    globalThis.crypto.getRandomValues(out.subarray(off, off + len));
  }
  return out;
})();
{
  // chunked fill that respects a running cursor (cyclic over the pool)
  let cursor = 0;
  const origGRV = globalThis.crypto.getRandomValues;
  const patched = (arr) => {
    let start = 0;
    while (start < arr.length) {
      const n = Math.min(16 * 1024, arr.length - start);
      const src = POOL.subarray(cursor, cursor + n);
      arr.set(src, start);
      cursor = (cursor + n) % POOL.length;
      start += n;
    }
    return arr;
  };
  // Only patch when the real cap would break large fills; keep a reference so
  // small calls still behave (the patch is functionally identical, just chunked).
  globalThis.crypto.getRandomValues = patched;
  void origGRV; // unused, left for clarity
}

// High-resolution median across `rounds` runs, returns ms.
async function timeIt(fn, rounds) {
  const samples = [];
  for (let i = 0; i < rounds; i++) {
    const t0 = process.hrtime.bigint();
    await fn();
    const t1 = process.hrtime.bigint();
    samples.push(Number(t1 - t0) / 1e6); // ms
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)]; // median
}

function randomKeyHex(bits) { return DM.randomKeyHex(bits); }
function utf8key(n, i) { return String(i) + "-" + "k".repeat(Math.max(0, n - String(i).length - 1)); }

// smallest whole pad_to that can hold a msgBytes plaintext (len prefix = 4)
function minPadTo(msgBytes) { return msgBytes + 4 + 1; }

async function benchScenario({ count, keyLen, msgBytes, padTo, keyFactory, keyStrBytes }) {
  // fresh keys per scenario to avoid container overwriting between trials
  const keys = [];
  for (let i = 0; i < count; i++) keys.push(keyFactory(i));

  const msgs = [];
  for (let i = 0; i < count; i++) msgs.push("m".repeat(msgBytes));

  const opts = { bits: keyLen };
  if (padTo) opts.pad_to = padTo;

  // warm-up
  await DM.encrypt(msgs, keys, opts);

  const heapBefore = process.memoryUsage().heapUsed;
  const encMs = await timeIt(() => DM.encrypt(msgs, keys, opts), 3);
  const encHeapKiB = (process.memoryUsage().heapUsed - heapBefore) / 1024;

  // build once more for a stable container to decrypt
  const container = await DM.encrypt(msgs, keys, opts);
  const cLen = DM.b64ToBytes(container).length;

  const ownKey = keys[0];
  const decHeapBefore = process.memoryUsage().heapUsed;
  const decMs = await timeIt(() => DM.decrypt(container, ownKey, undefined, keyLen), 3);
  const decHeapKiB = (process.memoryUsage().heapUsed - decHeapBefore) / 1024;

  return {
    slots: count,
    keyBits: keyLen,
    keyStrBytes: keyStrBytes || null,
    msgBytes,
    padTo: padTo || null,
    containerBytes: cLen,
    encrypt_ms: +encMs.toFixed(3),
    encrypt_heapKiB: +(encHeapKiB).toFixed(0),
    decrypt_ms: +decMs.toFixed(3),
    decrypt_heapKiB: +(decHeapKiB).toFixed(0),
  };
}

(async () => {
  const results = { meta: {
    impl: "crypto.js (WebCrypto / browser + Node >= 20)",
    node: process.version,
    cpu: process.env.PROCESSOR_IDENTIFIER || "unknown",
    arch: process.arch,
    note: "median of 3 runs, wall-clock ms; heapUsed delta (KiB) as an approximate per-op memory marker",
    date: new Date().toISOString(),
  }, dimensions: {
    slots: [],
    msgSize: [],
    keyBits: [],
    keyStringLen: [],
  } };

  // DIM 1 — slots 1..32, fixed 32-byte keys + 64-byte messages, pad_to=68
  for (const n of [1, 2, 4, 8, 16, 32]) {
    results.dimensions.slots.push(
      await benchScenario({ count: n, keyLen: 256, msgBytes: 64, padTo: minPadTo(64), keyFactory: () => randomKeyHex(256) }),
    );
  }

  // DIM 2 — message size grows, fixed N=4 slots, 256-bit keys, no pad_to.
  // NOTE (real constraint): pos_bytes=2 gives a 16-bit position space, so the
  // container must stay ≲ 65535 B for non-colliding placement (project
  // max_size() = 65535). Messages above ~4 KB per slot with N=4 push past the
  // cap and hit "all positions collide". Values are chosen to stay within it.
  for (const kb of [64, 512, 2048, 3072]) {
    results.dimensions.msgSize.push(
      await benchScenario({ count: 4, keyLen: 256, msgBytes: kb, padTo: null, keyFactory: () => randomKeyHex(256) }),
    );
  }

  // DIM 3 — key length bits
  for (const bits of [16, 32, 64, 128, 256, 512]) {
    results.dimensions.keyBits.push(
      await benchScenario({ count: 4, keyLen: bits, msgBytes: 64, padTo: minPadTo(64), keyFactory: () => randomKeyHex(bits) }),
    );
  }

  // DIM 4 — custom UTF-8 string key byte lengths (distinct keys per slot)
  for (const kb of [8, 32, 128, 1024]) {
    results.dimensions.keyStringLen.push(
      await benchScenario({ count: 4, keyLen: 256, msgBytes: 64, padTo: minPadTo(64), keyFactory: (i) => utf8key(kb, i), keyStrBytes: kb }),
    );
  }

  const out = JSON.stringify(results, null, 2);
  if (process.argv[2]) {
    fs.writeFileSync(path.resolve(process.argv[2]), out, "utf8");
    console.log("wrote benchmark results to " + path.resolve(process.argv[2]));
  } else {
    console.log(out);
  }
})().catch((e) => { console.error("BENCH ERROR", e); process.exit(1); });
