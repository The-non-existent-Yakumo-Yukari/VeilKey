# Benchmarks — empirical performance & memory

> Measured **today**, on this machine, against the code in this repository.
> Numbers are medians of a few runs; treat them as **indicative order-of-magnitude
> figures**, not stable micro-benchmarks. They are **not** production-stable.

**Why two implementations?** `crypto.js` (WebCrypto) is what the browser UI runs;
`multi_key/deniable_multi.py` is the Python reference the JS is **byte-for-byte
compatible** with (verified by the cross-validation suite). Comparing the two
shows the overhead of the WebCrypto build vs. the native-`cryptography` build.

**Environment.** Node `v24.13.0`, Python `3.14.6`, Windows x64 (AuthenticAMD).
JS: median of 3 runs; Python: median of 5 runs. Wall-clock ms.
Memory is reported as a coarse per-op marker: JS uses `heapUsed` delta (KiB),
Python `ru_maxrss` (unavailable on Windows → not reported). Memory numbers are
**approximate** and noisy; treat them as such.

---

## Summary answers to the question

**Q — how does cost scale as ciphertext length (slot count / message size) grows?**

* **Encrypt is roughly linear in N (the number of messages/slots).** Every slot
  costs one HKDF + one AES-GCM + one random-position placement. JS went from
  **0.52 ms (1 slot)** to **8.4 ms (32 slots)**; Python from **0.08 ms** to
  **0.72 ms**.
* **Decrypt is ~flat in N.** Each key self-locates *its own* slot and ignores the
  rest. Decrypting one slot out of 32 was **no slower** than decrypting one out of
  1 (JS ~0.3–0.9 ms across N; Python ~0.05 ms). This is the architectural win of
  self-locating keys.
* **Decrypt with a *wrong* key costs up to τ=32 GCM attempts** (the DoS bound):
  Python ~0.2–0.5 ms. This is the worst case and it is independent of the answer.

**Q — how does cost scale with key length?**

* Essentially **flat**. 16-, 32-, 64-, 128-, 256-, 512-bit keys all encrypt/decrypt
  in roughly the same time, because every key is run through HKDF to a fixed 32-byte
  `K_enc`. The selected bit-length controls **key generation and parsing**, not speed.

**Q — memory?**

* Per-op JS heap deltas were ~0–1 MiB and noisy (GC). Largest observed ~1 MiB for
  the biggest (32-slot) scenario. Metadata is that memory is **not a bottleneck**
  at the scale this scheme can actually produce (see the capacity ceiling below).

---

## Capacity ceiling (read before benchmarking)

The slot-position field is **2 bytes wide** ⇒ the effective position space is
**65536** regardless of container size. Two consequences, both observed:

1. The JS browser build fills the whole container with a **single**
   `crypto.getRandomValues` call, which WebCrypto caps at **65536 bytes** →
   containers ≥ 64 KiB **throw `QuotaExceededError`**.
2. Even with the RNG patched (as our harness does to measure crypto cost alone),
   placement **aborts with "all positions collide"** once slots rival the 65536
   position space (seen at ~4 KiB/slot with N=4).

**Practical ceiling: containers of a few tens of KiB and per-slot messages of a
few KiB.** Raising it requires widening `pos_bytes` (a subclass), which changes
positions and invalidates existing ciphertexts. The benchmark dimensions below are
chosen to stay inside this ceiling so failure modes are not what we "measure".

---

## DIM 1 — Number of slots (message count) → ciphertext length grows

Fixed 256-bit keys, 64-byte messages, `pad_to=69` (uniform slots).

| slots | container B | JS enc ms | JS dec ms | Py enc ms | Py dec ms | Py wrong-key ms |
|------:|-----------:|----------:|----------:|----------:|----------:|----------------:|
| 1 | 2048 | 0.52 | 0.51 | 0.08 | 0.08 | 0.23 |
| 2 | 1792 | 0.54 | 0.49 | 0.14 | 0.03 | 0.29 |
| 4 | 1792 | 1.22 | 0.33 | 0.11 | 0.05 | 0.42 |
| 8 | 3584 | 1.88 | 0.56 | 0.34 | 0.07 | 0.27 |
| 16 | 7424 | 4.80 | 0.58 | 0.39 | 0.05 | 0.24 |
| 32 | 13312 | 8.43 | 0.90 | 0.72 | 0.07 | 0.49 |

> JS enc ~linear in N (≈0.26 ms per extra slot here); JS dec flat (≈0.3–0.9 ms).
> Python is ~5–15× faster than the JS/WebCrypto build on these paths (per-op
> WebCrypto overhead), which is expected and is *not* a security claim.

**Chart:** `bench/bench_chart_slots.png`

## DIM 2 — Message size per slot → ciphertext length grows (fixed N=4)

256-bit keys, no `pad_to`.

| msg/slot | container B | JS enc ms | JS dec ms | Py enc ms | Py dec ms |
|---------:|-----------:|----------:|----------:|----------:|----------:|
| 64 | 2560 | 0.72 | 0.52 | 0.10 | 0.04 |
| 512 | 9216 | 1.02 | 0.50 | 0.20 | 0.05 |
| 2048 | 33792 | 1.38 | 1.47 | 0.22 | 0.04 |
| 3072 | 49920 | 1.83 | 2.33 | 0.20 | 0.05 |

> Mostly flat over this range — AES-GCM on a few KiB is cheap; the dominant cost
> is the per-slot HKDF/placement, not the data volume. At ~3 KiB/slot the container
> is already 49 KB, near the 64 KB ceiling.

## DIM 3 — Key length (16…512 bits), fixed N=4, 64-byte msgs, `pad_to=69`

| key bits | JS enc ms | JS dec ms | Py enc ms | Py dec ms |
|---------:|----------:|----------:|----------:|----------:|
| 16 | 0.91 | 0.32 | 0.11 | 0.07 |
| 32 | 0.87 | 0.32 | 0.11 | 0.09 |
| 64 | 1.20 | 0.30 | 0.15 | 0.05 |
| 128 | 1.09 | 0.37 | 0.20 | 0.05 |
| 256 | 0.93 | 0.25 | 0.12 | 0.05 |
| 512 | 1.07 | 0.37 | 0.12 | 0.05 |

> **Flat.** Key bit-length does not move the needle — HKDF normalizes every key to
> a 32-byte `K_enc`. The UI’s "key bits" selector changes **key entropy and
> parsing**, not runtime.

**Chart:** `bench/bench_chart_keylen.png`

## DIM 4 — Custom UTF-8 string key length (JS only), fixed N=4, 64-byte msgs

| key string bytes | JS enc ms | JS dec ms |
|-----------------:|----------:|----------:|
| 8 | 0.82 | 0.45 |
| 32 | 1.06 | 0.31 |
| 128 | 1.02 | 0.32 |
| 1024 | 0.99 | 0.27 |

> Flat. Cost is invariant to string-key length; the *security* cost is that short
> strings are dictionary-attackable (see SECURITY.md §6).

---

## Comparison with prior work — what we can and cannot claim

**Canelli–Dwork–Naor–Ostrovsky (CDNR97, CRYPTO ’97)** — the foundational
deniable-encryption paper. Our scheme differs **architecturally**:

* **Overhead model differs.** CDNR97’s parity scheme encodes **one bit** as a set
  of $n$ "S-elements" (large expansion) and its multi-prover / receiver-faking
  constructions need **extra rounds of communication**. Our N-key scheme seals
  **whole messages** with **one AES-GCM + one HKDF each** and faking is a **single
  round**: reveal a strict subset of keys. So for message-sized data and the
  honest-but-curious coercer model, the constant factor here is far smaller. We
  do **not** claim equivalent *formal security* — CDNR97 is peer-reviewed, this
  PoC is not.

**StegoED** — we could **not** relocate "StegoED" as a well-defined, published
deniable-encryption scheme (searches only surfaced unrelated covert-channel /
"StegoEDCA" smart-grid results). **We therefore do not fabricate a comparison.**
If you can point us to the exact paper/implementation, we’ll add measured or
source-cited numbers.

**Position on numbers:** all comparative figures here are **our own measured
durations**; none are borrowed from papers, and none are asserted as competitive
against an unverified external baseline. Reproducing them requires this repo + a
machine like ours.

---

## How to reproduce

```bash
# JS/WebCrypto build (the browser code)
node bench/bench.js bench/bench-results.json
# Python reference — PYTHONPATH must see the parent project's deniable_core/multi_key
PYTHONPATH="<parent-with-deniable_core>" python bench/bench_py.py bench/bench-py-results.json
# tables + PNG charts
python bench/make_charts.py
```

Artifacts (all under `bench/`): `bench-results.json`, `bench-py-results.json`,
`bench_table_slots.csv`, `bench_table_allsizes.csv`, `bench_table_keybits.csv`,
`bench_table_keystr.csv`, `bench_table_py_slots.csv`,
`bench_chart_slots.png`, `bench_chart_keylen.png`.
