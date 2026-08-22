# VeilKey — DeniableMulti Web UI (N-key deniable encryption)

> ⚠️ **PROOF OF CONCEPT — NOT FOR PRODUCTION.**
>
> This is a **research / educational** implementation. The cryptography
> (`crypto.js`, ported from the Python reference `multi_key/deniable_multi.py`)
> has **not** been formally verified, independently audited, or cryptanalyzed.
> **Do not use it to protect real secrets.** Multiple concrete limitations make
> it unsuitable for production (see [SECURITY.md](SECURITY.md#6-known-limitations--attack-surface-honest-list)):
> a fixed HKDF salt, a small 16-bit slot-position space, a browser RNG cap that
> rejects containers ≥ 64 KiB, no container integrity, and a
> best-effort-but-unproven deniability model. This is a demo of *a* deniable
> scheme, **not** a vetted tool.
>
> 中文版本：[README.cn.md](README.cn.md) · Security model: [SECURITY.md](SECURITY.md) · Benchmarks: [BENCHMARKS.md](BENCHMARKS.md)

---

A **packaged desktop deliverable** for the N-key deniable scheme: run one `.exe`,
a browser window opens, and you encrypt / decrypt entirely inside the page using
WebCrypto. All cryptography stays in the browser; keys and plaintext never leave
the page.

```
webui/  (= this repo)
├── app.py                  # local launcher (pure stdlib, no crypto lib)
├── app.html / app.js       # the UI — bilingual (中文 / English)
├── crypto.js               # DeniableMulti ported to WebCrypto (browser)
├── build.py                # PyInstaller onefile build script
├── bench/                  # performance benchmarks (JS + Python) + charts
├── SECURITY.md             # formal security model & threat model
├── BENCHMARKS.md           # measured performance / memory, vs. prior work
└── tests/                  # pytest + Node cross-validation + jsdom smoke
```

## Quick start

**Double-click `dist/DeniableCipher.exe`.** A browser tab opens at a
`http://127.0.0.1:<port>/<token>/` URL; the page loads fully offline. Close the
page via the button in the UI (or press Ctrl+C / kill the process) to exit.

> ⚠️ Even though it launches as a desktop app, remember: this is **PoC** software
> with unaudited cryptography. It is not a safe place to put real secrets.

No installation, no Python, no network. The exe is a single file (~9.5 MB) and
contains **no third-party crypto library** — all cryptography is WebCrypto
running in your browser.

### The browser page

- **加密 / Encrypt** — add any number of "message + key" rows; keys are
  generated in-page as hex of the selected bit length. Optional `pad_to`,
  container `size`, and AAD. Output is Base64 with copy/save.
- **解密 / Decrypt** — paste the Base64 container + one key → your message. A
  wrong key fails cleanly; non-UTF-8 plaintext falls back to hex.
- **规划 / Plan** — message lengths + `pad_to` → minimum / maximum container size.
- **帮助 / Help** — a reference page explaining every control, kept in sync.
- **密钥长度 / Key bits** (16 / 32 / 64 / 128 / 256 / 512) — for generated random
  keys; remembered in `localStorage`.
- Language toggle 中/EN is remembered in `localStorage`.
- **关闭服务器并退出** button shuts down the local server and ends the exe.

### Keys: any string works, length is up to you

A key can be **any non-empty string** (Chinese, English, specials, any length;
its byte length is shown live). One rule (cross-verified against Python):

> A hex string whose length **matches the selected key bits** (`bits/4` hex
> chars — e.g. 64 hex chars at 256 bits) is decoded to raw bytes. Everything
> else is used as its **UTF-8 bytes**.

> ⚠️ **Strength warning** — a custom string key is only as strong as the string;
> short or predictable passphrases are dictionary-attackable (GCM's tag is a
> verification oracle). Prefer generated random keys.

---

## Security model — the honest summary

Full details: **[SECURITY.md](SECURITY.md)**. Read it; the short version:

* **Computational, not information-theoretic.** Rests on AES-256-GCM and
  HKDF-SHA256 (standard assumptions), against **probabilistic-polynomial-time
  (PPT)** adversaries only.
* **Coercer model (the load-bearing assumption).** Resistance depends on the
  coercer being a PPT, honest-but-curious coercer who forces you to reveal a
  **strict subset** of your keys but **cannot force all N keys at once** and
  cannot pre-determine the hidden content. If that coercer can seize **every**
  key, **everything falls**.
* **N-key goal = deny completeness, not existence.** You can admit there are
  multiple slots: each slot's position derives from its own key, so a coercer
  holding only the keys you reveal **cannot count the rest, cannot tell which
  message you meant, and cannot verify you handed over everything**.
* **Honest limits:** container *size* leaks magnitude; only slots (not the
  surrounding padding) are authenticated; the scheme is a PoC.

---

## Performance & memory

Measured, reproducible numbers (JS WebCrypto build + Python reference):
**[BENCHMARKS.md](BENCHMARKS.md)**.

Key findings (indicative numbers, see the doc):

* **Encrypt scales ~linearly with the number of slots** (one HKDF + one AES-GCM
  per slot): JS 0.5 ms (1 slot) → 8.4 ms (32 slots).
* **Decrypt is ~flat in the number of slots** — each key self-locates its own
  slot (JS ≈0.3–0.9 ms for one slot regardless of N). This is the architectural
  win of self-locating keys.
* **Wrong-key decrypt** costs up to τ=32 GCM verification attempts (the DoS
  bound; Python ≈0.2–0.5 ms).
* **Key length (16…512 bits) is essentially free** — HKDF normalizes every key to
  a 32-byte encryption key, so bit-selection affects key *entropy/parsing*, not
  speed.

  Or, stated against the question "how do speed/memory depend on ciphertext and
  key length": **ciphertext length** mostly follows the number of messages
  (linear encrypt, flat decrypt); **key length** is flat for both speed and
  memory; per-op JS heap deltas were ≈0–1 MiB (noisy, GC-dominated).

Comparative note on prior work: CDNR97-style constructions expand **per bit** and
need **extra rounds** to fake; this scheme seals whole messages with **one
AES-GCM + one HKDF each** and fakes in **a single round** (reveal a strict
subset). We do **not** claim formal parity — see BENCHMARKS.md. "StegoED" could
not be located as a defined scheme, so **no fabricated comparison** is given.

---

## Run from source (development)

```bash
# from the webui/ folder — no extra installs required (pure stdlib)
python app.py
```

Set `DC_TOKEN` / `DC_PORT` / `DC_NO_OPEN` environment variables to pin the
token/port or suppress the auto-opened browser (used by the tests).

## Build the exe

```bash
pip install pyinstaller -i https://pypi.org/simple   # if not installed
python build.py                                      # → dist/DeniableCipher.exe
```

Because `app.py` is pure stdlib, PyInstaller bundles no third-party crypto hooks;
the exe only contains Python's stdlib plus `app.html`, `app.js`, `crypto.js`
(via `--add-data`). `resource_path()` resolves them from `sys._MEIPASS` when
frozen, or the script directory otherwise.

Build options: `--dir` (onedir), `--console` (keep a console), `--name`.

## Benchmarks (reproduce)

```bash
node bench/bench.js bench/bench-results.json                  # JS/WebCrypto build
PYTHONPATH="<parent-with-deniable_core>" python bench/bench_py.py bench/bench-py-results.json
python bench/make_charts.py                                   # tables + PNG charts
```

See [BENCHMARKS.md](BENCHMARKS.md) for the exact scenarios and how to read them.

## Tests

```bash
# from the repository root
pytest                                          # all suites
```

> The cross-compat suite (`test_cross_compat.py`) byte-level compares the JS
> WebCrypto port against the **Python reference implementation**, which lives in
> the full `DeniableCipher` project (the folder containing `deniable_core.py` and
> `multi_key/`), not in this standalone webui package. It auto-skips when that
> reference (or Node) is absent. To run it for real, put the reference on
> `PYTHONPATH`:
>
> ```bash
> PYTHONPATH="C:/path/to/DeniableCipher-main" pytest tests/test_cross_compat.py -v
> ```

- `tests/test_cross_compat.py` — byte-level cross-validation (HKDF, positions,
  raw AES-GCM, full round-trips both directions), incl. arbitrary UTF-8 string
  keys and the hex-parsing rule. Requires Node + the Python reference.
- `tests/test_server.py` — launcher security posture (token gate, CSP/no-store,
  path traversal, shutdown) + a real subprocess lifecycle test.
- `tests/ui_smoke.js` — jsdom harness driving the real page (encrypt/decrypt,
  wrong-key failure, Chinese-string-key round trip, plan, language, rows).
  Requires `jsdom`; skips gracefully when absent.

## Troubleshooting

- **exe exits without opening a page** — check `deniable_error.log` next to the exe
  (a `--noconsole` build has no terminal).
- **No default browser** — open the printed URL manually in dev mode.
- **Port already in use** — the exe always binds an ephemeral port (0) or your
  `DC_PORT`.

## License

MIT (matching the parent `DeniableCipher` project).
