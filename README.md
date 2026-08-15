# DeniableCipher Web UI (`webui/`)

A **packaged desktop deliverable** for the N-key deniable scheme: run one `.exe`,
a browser window opens, and you encrypt / decrypt entirely inside the page.

```
webui/
├── app.py                  # local launcher (pure stdlib, no crypto lib)
├── app.html / app.js       # the UI — bilingual (中文 / English)
├── crypto.js               # DeniableMulti ported to WebCrypto (browser)
├── build.py                # PyInstaller onefile build script
├── dist/DeniableCipher.exe # ← the packaged executable
└── tests/                  # pytest + Node cross-validation + jsdom smoke
```

## Quick start

**Double-click `dist/DeniableCipher.exe`.** A browser tab opens at a
`http://127.0.0.1:<port>/<token>/` URL; the page loads fully offline. Close the
page via the button in the UI (or press Ctrl+C / kill the process) to exit.

No installation, no Python, no network. The exe is a single file (~9.5 MB) and
contains **no third-party crypto library** — all cryptography is WebCrypto
running in your browser.

### The browser page

- **加密 / Encrypt** — add any number of "message + key" rows; keys are
  generated in-page as hex of the selected bit length (one-click per row, or
  randomize all). Optional `pad_to` (uniform slot length), container `size`, and
  AAD. Output is Base64 with a copy/save button.
- **解密 / Decrypt** — paste the Base64 container + one key → the message owned
  by that key. A wrong key fails cleanly; non-UTF-8 plaintext falls back to hex.
- **规划 / Plan** — message lengths + `pad_to` → minimum / maximum container size.
- **帮助 / Help** — a reference page explaining every control and its effect,
  kept in sync with the UI's actual buttons.
- **密钥长度 / Key bits** selector in the header: **16 / 32 / 64 / 128 / 256 /
  512** bits for generated random keys; remembered in `localStorage`.
- Language toggle 中/EN is remembered in `localStorage`.
- **关闭服务器并退出** footer button shuts down the local server and ends the exe
  (the packaged `--noconsole` exe has no Ctrl+C to quit with).

### Keys: any string works, length is up to you

A key can be **any non-empty string** — Chinese, English, special characters,
any length (its byte length is shown live under the field, e.g. `UTF-8 · 18 B`).
One rule (cross-verified against Python in the test suite):

> A hex string whose length **matches the selected key bits** (`bits/4` hex
> chars — e.g. 64 hex chars at 256 bits) is interpreted as the decoded raw
> bytes. At the default 256 bits this keeps the in-page generated keys and any
> existing ciphertexts byte-compatible with the Python implementation.
> Everything else is used as its **UTF-8 bytes**, so `我的密钥`, `pass word!`,
> `a`, … all work, and the effective key length is exactly the text you typed.

⚠️ **Strength warning** — a custom string key is only as strong as the string
itself; short or predictable passphrases are dictionary-attackable (GCM's tag
acts as a verification oracle). The UI shows a warning when a non-hex key is
used. For serious use, prefer the generated keys from "Randomize all" (32 bytes
at the default 256 bits), or a long high-entropy phrase.

## Security model

- **All cryptography is client-side (WebCrypto).** Keys and plaintext never
  leave the browser; the local server is an inert static host and never sees
  them. It imports no crypto library at all.
- **Bound to 127.0.0.1**, served under a strict CSP
  (`script-src 'self'`, no inline scripts) with `no-store` / `nosniff` headers.
- **Per-run random token** in the URL path, compared in constant time
  (`secrets.compare_digest`). Without the token every request is a 404 — a
  malicious web page or local process cannot reach the server.
- The scheme is **DeniableMulti** (fully ported here in `crypto.js`; the Python
  reference implementation used by the tests lives in the full project repo):
  deny **completeness**, not existence. It is fine to admit the container holds
  multiple slots — each slot's position derives from its own key alone, so an
  adversary holding only the keys you reveal cannot count the rest, tell which
  message you meant, or prove you withheld anything. Handing over every key
  exposes everything; container size still leaks magnitude.

## Run from source (development)

```bash
# from the webui/ folder — no extra installs required (pure stdlib)
python app.py
```

Set `DC_TOKEN` / `DC_PORT` / `DC_NO_OPEN` environment variables to pin the
token/port or suppress the auto-opened browser (used by the automated tests).

## Build the exe

```bash
pip install pyinstaller -i https://pypi.org/simple   # if not installed
python build.py                                      # → dist/DeniableCipher.exe
```

Because `app.py` is pure stdlib, PyInstaller bundles no third-party hooks and no
`cryptography`/`cffi` — the exe only contains Python's stdlib plus the three web
assets (`app.html`, `app.js`, `crypto.js`) via `--add-data`. `resource_path()`
resolves them from `sys._MEIPASS` when frozen, or the script directory otherwise.

Build options: `--dir` (onedir instead of onefile), `--console` (keep a console
window for debugging), `--name` (output name).

## Tests

```bash
# from the repository root
pytest                                          # all suites, incl. webui/tests
```

- `tests/test_cross_compat.py` — **byte-level cross-validation** between the
  Python `DeniableMulti` and the JS WebCrypto port (HKDF, slot positions, raw
  AES-GCM, and full encrypt→decrypt round-trips in both directions), including
  **arbitrary UTF-8 string keys** (Chinese, specials, short/long) and the
  64-hex→32-byte parsing rule. Auto-skips if `node` is not on `PATH` or the
  Python reference implementation (`deniable_core` / `multi_key`) is missing.
- `tests/test_server.py` — launcher security posture (token gate, CSP/no-store
  headers, path traversal, shutdown) plus a real subprocess lifecycle test.
- `tests/ui_smoke.js` — jsdom harness driving the real page (encrypt/decrypt,
  wrong-key failure, validation, **custom Chinese-string key round-trip**,
  plan, language toggle, row add/remove). Requires `jsdom` (`npm i jsdom`);
  skips gracefully when absent.

## Troubleshooting

- **exe exits without opening a page** — check `deniable_error.log` written next
  to the exe (a `--noconsole` build has no terminal to print to).
- **No default browser** — open the printed URL manually in dev mode; the
  launcher also logs it before `serve_forever`.
- **Port already in use** — the exe always binds an ephemeral port (0) or your
  `DC_PORT`, so collisions are not expected.
