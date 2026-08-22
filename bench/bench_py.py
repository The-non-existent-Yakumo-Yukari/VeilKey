"""
VeilKey / DeniableMulti — empirical benchmark (Python reference impl).

Measures multi_key.deniable_multi.DeniableMulti (the Python reference that the
browser crypto.js is byte-for-byte compatible with) so the suite can compare
the JS/WebCrypto build against the CPython reference on the same scenarios.

        python bench_py.py [--out bench-py-results.json]

Expects PYTHONPATH to include the folder holding `deniable_core.py` and the
`multi_key` package. Runs the same four dimensions as bench/bench.js.
"""
import gc
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from multi_key.deniable_multi import DeniableMulti  # noqa: E402

def rss_kib():
    # ru_maxrss is not meaningful per-op on Windows / resource may be absent;
    # report tracemalloc peak if enabled, else -1.
    try:
        import tracemalloc
        if tracemalloc.is_tracing():
            _cur, peak = tracemalloc.get_traced_memory()
            return round(peak / 1024)
    except Exception:
        pass
    return -1

def median_ms(fn, rounds=5):
    samples = []
    for _ in range(rounds):
        gc.collect()
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        samples.append((t1 - t0) * 1000.0)
    samples.sort()
    return samples[len(samples) // 2]

def bench_scenario(count, key_len_bits, msg_bytes, pad_to):
    keys = [os.urandom(key_len_bits // 8) for _ in range(count)]
    msgs = [("m" * msg_bytes) for _ in range(count)]

    # warm-up
    DeniableMulti.encrypt_many(msgs, keys, pad_to=pad_to)

    enc_ms = median_ms(lambda: DeniableMulti.encrypt_many(msgs, keys, pad_to=pad_to))
    ct = DeniableMulti.encrypt_many(msgs, keys, pad_to=pad_to)
    cbuf = ct if isinstance(ct, bytes) else bytes(ct)

    own = keys[0]
    dec_ms = median_ms(lambda: DeniableMulti.decrypt_many(cbuf, own))

    # worst-case wrong-key: up to max_trials=32 GCM verification attempts
    wrong = os.urandom(key_len_bits // 8)
    wrong_ms = median_ms(lambda: DeniableMulti.decrypt_many(cbuf, wrong))

    return {
        "slots": count, "keyBits": key_len_bits, "msgBytes": msg_bytes,
        "padTo": pad_to if pad_to else None,
        "containerBytes": len(cbuf),
        "encrypt_ms": round(enc_ms, 3),
        "decrypt_ms": round(dec_ms, 3),
        "decrypt_wrong_key_ms": round(wrong_ms, 3),
        "rss_maxKiB": rss_kib(),
    }

def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "bench-py-results.json"
    pad = 69  # msgBytes 64 + 4 len + 1
    results = {
        "meta": {
            "impl": "Python DeniableMulti (multi_key/deniable_multi.py) via cryptography lib",
            "python": sys.version.split()[0],
            "note": "median of 5 runs, wall-clock ms; ru_maxrss KiB (may be 0 on Windows)",
            "date": time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
        "dimensions": {
            "slots": [bench_scenario(n, 256, 64, pad) for n in (1, 2, 4, 8, 16, 32)],
            "msgSize": [bench_scenario(4, 256, m, None) for m in (64, 512, 2048, 3072)],
            "keyBits": [bench_scenario(4, b, 64, pad) for b in (16, 32, 64, 128, 256, 512)],
        },
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print("wrote " + out_path)

if __name__ == "__main__":
    main()
