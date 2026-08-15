/*
 * Browser-level smoke test for the web UI.
 *
 * Loads app.html + crypto.js + app.js into jsdom (Node's WebCrypto injected),
 * then drives the full encrypt / decrypt / plan / language flows and asserts
 * on the resulting DOM state.  Exits non-zero on failure.
 *
 * Requires jsdom:   npm i jsdom        (or run with NODE_PATH pointing at it)
 * Run:              node webui/tests/ui_smoke.js
 */
"use strict";

const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const html = fs.readFileSync(path.join(root, "app.html"), "utf8");
const cryptoJs = fs.readFileSync(path.join(root, "crypto.js"), "utf8");
const appJs = fs.readFileSync(path.join(root, "app.js"), "utf8");

let JSDOM;
try {
  JSDOM = require("jsdom").JSDOM;
} catch (e) {
  console.log("SKIP: jsdom not installed (npm i jsdom)");
  process.exit(0);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeout = 6000, step = 40) {
  const start = Date.now();
  for (;;) {
    if (fn()) return true;
    if (Date.now() - start > timeout) return fn();
    await sleep(step);
  }
}

let checks = 0;
function ok(cond, label) {
  checks++;
  if (!cond) {
    console.error("FAIL: " + label);
    process.exitCode = 1;
  }
}

(async () => {
  const dom = new JSDOM(html, {
    runScripts: "outside-only",
    url: "http://127.0.0.1:1/t/", // http origin → localStorage + secure-ish context
  });
  const w = dom.window;
  const d = w.document;
  // Provide WebCrypto to the page (jsdom's own crypto has no subtle).
  Object.defineProperty(w, "crypto", { value: require("node:crypto").webcrypto, configurable: true });

  w.eval(cryptoJs);
  w.eval(appJs);
  await sleep(150); // let DOMContentLoaded → init() run

  // ── initial state ──
  ok(d.querySelectorAll("#rows .row").length === 2, "two default rows");
  const hex64 = /^[0-9a-fA-F]{64}$/;
  const key0 = d.querySelector("#rows .row .key").value;
  ok(hex64.test(key0), "row-1 key auto-generated (64 hex)");
  ok(d.querySelector("#rows .row .keymeta").textContent.indexOf("hex") !== -1,
    "keymeta shows hex kind for generated key");
  ok(typeof w.DeniableMulti === "object", "crypto.js exposed DeniableMulti");
  ok(d.querySelector("#output-panel").hidden, "output hidden initially");

  // ── language toggle ──
  d.querySelector('.lang-toggle button[data-lang="en"]').click();
  ok(d.querySelector('[data-i18n="tagline"]').textContent === "N-key deniable encryption",
    "EN tagline after toggle");
  d.querySelector('.lang-toggle button[data-lang="zh"]').click();
  ok(d.querySelector('[data-i18n="tagline"]').textContent.indexOf("多密钥") !== -1,
    "ZH tagline after toggle back");

  // ── encrypt ──
  const rows = d.querySelectorAll("#rows .row");
  rows[0].querySelector(".msg").value = "real secret";
  rows[1].querySelector(".msg").value = "cover story";
  d.querySelector("#opt-pad-to").value = "256";
  d.querySelector("#btn-encrypt").click();
  ok(await waitFor(() => !d.querySelector("#output-panel").hidden &&
                       d.querySelector("#output").value.length > 0),
    "encrypt produces output");
  const b64 = d.querySelector("#output").value;
  ok(b64.length > 100, "output is a long base64 string");
  ok(d.querySelector("#output-meta").textContent.indexOf("2") !== -1, "meta shows slot count");

  // ── decrypt with the owning key ──
  d.querySelector('nav.tabs button[data-tab="decrypt"]').click();
  d.querySelector("#dec-container").value = b64;
  d.querySelector("#dec-key").value = key0;
  d.querySelector("#btn-decrypt").click();
  ok(await waitFor(() => !d.querySelector("#dec-result").hidden), "decrypt resolves");
  ok(d.querySelector("#dec-output").value === "real secret", "decrypted message matches");

  // ── decrypt with a wrong key fails cleanly ──
  d.querySelector("#dec-key").value = w.DeniableMulti.randomKeyHex();
  d.querySelector("#btn-decrypt").click();
  ok(await waitFor(() => {
    const t = d.querySelector("#dec-result-title").textContent;
    return !d.querySelector("#dec-result").hidden && (t.indexOf("失败") !== -1 || t.indexOf("failed") !== -1);
  }), "wrong key shows failure state");

  // ── input validation: empty key on encrypt ──
  d.querySelector('nav.tabs button[data-tab="encrypt"]').click();
  const eki = d.querySelector("#rows .row .key");
  eki.value = "";
  d.querySelector("#btn-encrypt").click();
  ok(await waitFor(() => !d.querySelector("#enc-error").hidden), "encrypt validation error appears");
  ok(d.querySelector("#enc-error").textContent.indexOf("空") !== -1, "error mentions empty key (zh)");

  // ── custom string keys (Chinese, arbitrary length) work end-to-end ──
  const ck = d.querySelectorAll("#rows .row")[0].querySelector(".key");
  ck.value = "我的秘密密钥";
  ck.dispatchEvent(new w.Event("input")); // typing a custom key
  d.querySelectorAll("#rows .row")[0].querySelector(".msg").value = "真实消息";
  // clear the stale output from the earlier encrypt so the wait below can only
  // be satisfied by the NEW ciphertext (the async encrypt overwrites it)
  d.querySelector("#output").value = "";
  d.querySelector("#output-panel").hidden = true;
  d.querySelector("#btn-encrypt").click();
  ok(await waitFor(() => !d.querySelector("#output-panel").hidden &&
                       d.querySelector("#output").value.length > 0),
    "encrypt with a Chinese string key");
  ok(!d.querySelector("#enc-warn").hidden, "custom-key strength warning visible");
  ok(d.querySelectorAll("#rows .row")[0].querySelector(".keymeta").textContent.indexOf("UTF-8") !== -1,
    "keymeta shows UTF-8 kind for custom key");
  const cnB64 = d.querySelector("#output").value;

  d.querySelector('nav.tabs button[data-tab="decrypt"]').click();
  d.querySelector("#dec-container").value = cnB64;
  d.querySelector("#dec-key").value = "我的秘密密钥";
  d.querySelector("#btn-decrypt").click();
  ok(await waitFor(() => !d.querySelector("#dec-result").hidden &&
                       d.querySelector("#dec-output").value === "真实消息"),
    "Chinese-string key decrypts its message");

  // wrong custom key fails cleanly
  d.querySelector("#dec-key").value = "另一个密钥";
  d.querySelector("#btn-decrypt").click();
  ok(await waitFor(() => {
    const t = d.querySelector("#dec-result-title").textContent;
    return !d.querySelector("#dec-result").hidden && (t.indexOf("失败") !== -1 || t.indexOf("failed") !== -1);
  }), "wrong custom key shows failure state");

  // ── plan / info ──
  d.querySelector('nav.tabs button[data-tab="info"]').click();
  d.querySelector("#info-lengths").value = "100, 50, 50";
  d.querySelector("#info-pad-to").value = "256";
  d.querySelector("#btn-plan").click();
  ok(d.querySelector("#plan-min").textContent.indexOf("1024") !== -1, "min container 1024 B");
  ok(d.querySelector("#plan-max").textContent.indexOf("65535") !== -1, "max container 65535 B");

  // ── add / remove / randomize rows ──
  d.querySelector("#btn-add").click();
  ok(d.querySelectorAll("#rows .row").length === 3, "add row works");
  const lastRemove = d.querySelectorAll("#rows .row")[2].querySelector(".remove");
  lastRemove.click();
  ok(d.querySelectorAll("#rows .row").length === 2, "remove row works");
  d.querySelector("#btn-random-all").click();
  let allHex = true;
  d.querySelectorAll("#rows .row").forEach((r) => {
    if (!hex64.test(r.querySelector(".key").value)) allHex = false;
  });
  ok(allHex, "randomize-all fills every key");

  // ── key-length selector (bits) ──
  const sel = d.querySelector("#opt-key-bits");
  ok(sel.value === "256", "default key bits = 256");

  // 128-bit: generated keys are 32 hex chars, keymeta reports 16 bytes
  sel.value = "128";
  sel.dispatchEvent(new w.Event("change"));
  d.querySelector("#btn-random-all").click();
  const hex128 = /^[0-9a-fA-F]{32}$/;
  let allHex32 = true;
  d.querySelectorAll("#rows .row").forEach((r) => {
    if (!hex128.test(r.querySelector(".key").value)) allHex32 = false;
  });
  ok(allHex32, "128-bit randomize generates 32-hex keys");
  ok(d.querySelectorAll("#rows .row")[0].querySelector(".keymeta").textContent.indexOf("16 B") !== -1,
    "128-bit keymeta shows 16 bytes");

  // encrypt at 128 bits, decrypt with matching bits
  d.querySelectorAll("#rows .row")[0].querySelector(".msg").value = "bits round trip";
  d.querySelector("#output").value = "";
  d.querySelector("#output-panel").hidden = true;
  d.querySelector("#btn-encrypt").click();
  ok(await waitFor(() => !d.querySelector("#output-panel").hidden &&
                       d.querySelector("#output").value.length > 0),
    "128-bit encrypt works");
  const b128 = d.querySelector("#output").value;
  const k128 = d.querySelectorAll("#rows .row")[0].querySelector(".key").value;

  d.querySelector('nav.tabs button[data-tab="decrypt"]').click();
  d.querySelector("#dec-container").value = b128;
  d.querySelector("#dec-key").value = k128;
  d.querySelector("#btn-decrypt").click();
  ok(await waitFor(() => !d.querySelector("#dec-result").hidden &&
                       d.querySelector("#dec-output").value === "bits round trip"),
    "128-bit decrypt works with matching bits");

  // a hex string of the wrong length vs. the selected bits → UTF-8 + warning
  const dk = d.querySelector("#dec-key");
  dk.value = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  dk.dispatchEvent(new w.Event("input"));
  ok(d.querySelector("#dec-keymeta").textContent.indexOf("UTF-8") !== -1 &&
     d.querySelector("#dec-keymeta").textContent.indexOf("⚠") !== -1,
    "64-hex at 128 bits shows UTF-8 + mismatch warning");

  // restore default bits
  sel.value = "256";
  sel.dispatchEvent(new w.Event("change"));

  // ── help tab ──
  d.querySelector('nav.tabs button[data-tab="help"]').click();
  ok(d.querySelector("#tab-help").classList.contains("active"), "help tab activates");
  ok(d.querySelectorAll("#help-list .help-group").length >= 4, "help renders groups");
  ok(d.querySelectorAll("#help-list .help-item").length >= 12, "help renders items");
  const zhName = d.querySelector("#help-list .help-name").textContent;
  ok(zhName.length > 0, "help items have names");
  d.querySelector('.lang-toggle button[data-lang="en"]').click();
  ok(d.querySelectorAll("#help-list .help-group").length >= 4, "help re-renders in EN");
  const enName = d.querySelector("#help-list .help-name").textContent;
  ok(enName !== zhName, "help content switches language");
  d.querySelector('.lang-toggle button[data-lang="zh"]').click();

  // ── shutdown button present ──
  ok(!!d.querySelector("#btn-shutdown"), "shutdown button present");

  dom.window.close();
  console.log(process.exitCode ? "UI SMOKE: FAILED" : "UI SMOKE: PASSED (" + checks + " checks)");
  process.exit(process.exitCode || 0);
})().catch((e) => {
  console.error("UI SMOKE: ERROR", e);
  process.exit(1);
});
