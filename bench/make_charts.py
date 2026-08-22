"""
Generate benchmark charts + CSV tables from bench-results.json (JS/WebCrypto)
and bench-py-results.json (Python reference), written by bench/bench.js and
bench/bench_py.py.

Outputs (into the script's folder):
  bench_chart_slots.png      encrypt & decrypt vs number of slots (JS vs Py)
  bench_chart_keylen.png     encrypt & decrypt vs key length (JS vs Py)
  bench_table_slots.csv      full slots-dimension table
  bench_table_allsizes.csv   msg-size dimension (with maxRSS)
  bench_table_keybits.csv
  bench_table_keystr.csv     (JS only; Python has no free-form string-key axis)
"""
import csv
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
JS_PATH = os.path.join(HERE, "bench-results.json")
PY_PATH = os.path.join(HERE, "bench-py-results.json")


def load(p):
    with open(p, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_csv(name, rows, headers):
    path = os.path.join(HERE, name)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        w.writerows(rows)
    print("wrote " + path)


def pair_series(js, py, key, field, default=0.0):
    d = {r[key]: r.get(field, default) for r in js}
    d2 = {r[key]: r.get(field, default) for r in py}
    xs = sorted(set(d) | set(d2))
    return xs, [d.get(x, None) for x in xs], [d2.get(x, None) for x in xs]


def main():
    js = load(JS_PATH)
    py = load(PY_PATH)

    js_slots = js["dimensions"]["slots"]
    py_slots = py["dimensions"]["slots"]

    # ── slots chart: encrypt + decrypt, JS vs Py ──
    xs, js_enc, py_enc = pair_series(js_slots, py_slots, "slots", "encrypt_ms")
    _, js_dec, py_dec = pair_series(js_slots, py_slots, "slots", "decrypt_ms")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    ax1.set_title("Encrypt: wall-clock vs number of slots")
    ax1.plot(xs, js_enc, "o-", label="JS/WebCrypto (crypto.js)")
    ax1.plot(xs, py_enc, "s--", label="Python ref (multi_key)")
    ax1.set_xlabel("slots (messages)")
    ax1.set_ylabel("encrypt ms (median)")
    ax1.grid(alpha=0.3)
    ax1.legend()

    ax2.set_title("Decrypt (one key): wall-clock vs number of slots")
    ax2.plot(xs, js_dec, "o-", label="JS/WebCrypto")
    ax2.plot(xs, py_dec, "s--", label="Python ref")
    ax2.set_xlabel("slots (messages)")
    ax2.set_ylabel("decrypt ms (median)")
    ax2.grid(alpha=0.3)
    ax2.legend()

    fig.tight_layout()
    out1 = os.path.join(HERE, "bench_chart_slots.png")
    fig.savefig(out1, dpi=130)
    print("wrote " + out1)
    plt.close(fig)

    # ── key-length chart ──
    js_kb = js["dimensions"]["keyBits"]
    py_kb = py["dimensions"]["keyBits"]
    xs, js_ke, py_ke = pair_series(js_kb, py_kb, "keyBits", "encrypt_ms")
    _, js_kd, py_kd = pair_series(js_kb, py_kb, "keyBits", "decrypt_ms")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    ax1.set_title("Encrypt vs key length (bits)")
    ax1.plot(xs, js_ke, "o-", label="JS/WebCrypto")
    ax1.plot(xs, py_ke, "s--", label="Python ref")
    ax1.set_xlabel("key bits")
    ax1.set_ylabel("encrypt ms")
    ax1.set_xticks(xs)
    ax1.grid(alpha=0.3)
    ax1.legend()

    ax2.set_title("Decrypt vs key length (bits)")
    ax2.plot(xs, js_kd, "o-", label="JS/WebCrypto")
    ax2.plot(xs, py_kd, "s--", label="Python ref")
    ax2.set_xlabel("key bits")
    ax2.set_ylabel("decrypt ms")
    ax2.set_xticks(xs)
    ax2.grid(alpha=0.3)
    ax2.legend()

    fig.tight_layout()
    out2 = os.path.join(HERE, "bench_chart_keylen.png")
    fig.savefig(out2, dpi=130)
    print("wrote " + out2)
    plt.close(fig)

    # ── CSV tables ──
    write_csv("bench_table_slots.csv", 
              [[r["slots"], r["containerBytes"], r["encrypt_ms"], r["decrypt_ms"]]
               for r in js_slots],
              ["slots", "container_bytes", "encrypt_ms(js)", "decrypt_ms(js)"])
    # combined msg-size (JS heap marker)
    write_csv("bench_table_allsizes.csv",
              [[r["slots"], r["msgBytes"], r["containerBytes"],
                r["encrypt_ms"], r["decrypt_ms"], r.get("encrypt_heapKiB", "")]
               for r in js["dimensions"]["msgSize"]],
              ["slots", "msg_bytes_per_slot", "container_bytes",
               "encrypt_ms", "decrypt_ms", "encrypt_heap_deltaKiB"])
    write_csv("bench_table_keybits.csv",
              [[r["keyBits"], r["encrypt_ms"], r["decrypt_ms"]]
               for r in js["dimensions"]["keyBits"]],
              ["key_bits", "encrypt_ms", "decrypt_ms"])
    # JS-only dimension: custom UTF-8 string key byte length
    write_csv("bench_table_keystr.csv",
              [[r["keyStrBytes"], r["encrypt_ms"], r["decrypt_ms"]]
               for r in js["dimensions"]["keyStringLen"]],
              ["key_string_bytes", "encrypt_ms", "decrypt_ms"])

    # Python wrong-key (DoS) column for the slots dimension
    write_csv("bench_table_py_slots.csv",
              [[r["slots"], r["encrypt_ms"], r["decrypt_ms"], r["decrypt_wrong_key_ms"]]
               for r in py_slots],
              ["slots", "encrypt_ms(py)", "decrypt_ms(py)", "decrypt_wrong_key_ms(py)"])

    print("done")


if __name__ == "__main__":
    main()
