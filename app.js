/*
 * DeniableCipher Web UI — logic + i18n.
 * Loaded after crypto.js (which provides globalThis.DeniableMulti).
 * All crypto runs in the browser; nothing is sent anywhere.
 *
 * ⚠️ PROOF OF CONCEPT — NOT FOR PRODUCTION. Educational/research only.
 * Do not use to protect real secrets. See SECURITY.md.
 */
"use strict";

const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

/* ═══════════════════════════ i18n ═══════════════════════════ */

const I18N = {
  zh: {
    tagline: "多密钥可否认加密",
    pocBanner: "⚠ 概念验证（PoC）：未审计的加密工程，请勿用于保护真实机密。阅读安全模型。",
    localChip: "仅在本浏览器运行",
    tabEncrypt: "加密",
    tabDecrypt: "解密",
    tabInfo: "规划",
    tabHelp: "帮助",
    encTitle: "把 N 条消息封进一个无头容器",
    btnAdd: "+ 添加消息",
    btnRandom: "随机生成密钥",
    btnRemove: "删除此行",
    btnRandomAll: "全部随机密钥",
    optPadTo: "pad_to · 统一槽长（选填）",
    optSize: "容器大小 · 字节（选填）",
    optAad: "AAD（hex，选填）",
    btnEncrypt: "加密",
    encrypting: "加密中",
    outputTitle: "密文 · Base64",
    btnCopy: "复制",
    copied: "已复制",
    btnSave: "保存",
    meta: (n, b) => n + " 槽 · " + b,
    bytes: (b) => (b >= 1048576 ? (b / 1048576).toFixed(2) + " MiB"
                  : b >= 1024 ? (b / 1024).toFixed(1) + " KiB"
                  : b + " B"),
    errKey: (i) => "第 " + i + " 行：密钥不能为空",
    errAad: "AAD 必须是偶数长度 hex",
    errSize: "容器大小必须是 ≥256 的整数",
    errPadTo: "pad_to 必须是 ≥5 的整数",
    errB64: "请粘贴 Base64 容器",
    errEncrypt: "加密失败",
    keyMeta: (kind, n) => kind === "hex" ? "hex 密钥 · " + n + " B" : "UTF-8 密钥 · " + n + " B",
    customKeyWarn: "检测到自定义密钥：强度取决于字符串本身，短口令可被字典攻击。正式用途建议用「全部随机密钥」生成 32 字节密钥。",
    decTitle: "用一把密钥，解出它对应的那条消息",
    decContainer: "容器 · Base64",
    decKey: "密钥 · 任意字符串",
    btnDecrypt: "解密",
    decrypting: "解密中",
    resultOk: "解密成功",
    resultFail: "解密失败：密钥错误，或容器已损坏",
    hexNote: "（非 UTF-8 文本，已按 hex 显示）",
    infoTitle: "容器大小预算",
    infoLengths: "消息长度 · 逗号分隔",
    infoPadTo: "pad_to（选填）",
    btnPlan: "计算",
    minContainer: "最小容器",
    maxContainer: "最大容器",
    threatTitle: "威胁模型：否认完整性，而非否认存在",
    threatBody: "可以承认容器里有多个槽——每个槽的位置由各自的密钥独立推出。对手只拿着你交出的密钥：数不清还剩多少槽，判断不出你真正想保留哪条，也永远无法证明你没交全。注意：交出全部密钥 = 全部暴露；容器大小仍会泄露内容的量级。",
    footer: "全部计算在浏览器里完成——密钥与明文从不经过本地服务器。",
    phMsg: "要封进容器的消息…",
    phKey: "任意字符串 · 中文/英文/特殊字符；64 位 hex 视为 32 字节密钥",
    phB64: "粘贴容器（Base64）…",
    keylenLabel: "密钥长度",
    keylenTitle: "生成随机密钥的比特长度；也决定哪些 hex 字符串会被当作原始字节密钥解析",
    hexMisMatch: "⚠ 是 hex，但长度与所选密钥长度不符 → 将按 UTF-8 文本处理",
    helpTitle: "每个按钮的作用与影响",
    btnShutdown: "关闭服务器并退出",
    btnShutdownDone: "已关闭 · 现在可以关闭此标签页",
    help: [
      {
        title: "密钥长度",
        items: [
          { name: "密钥长度 · 16–512", desc: "生成随机密钥时的比特长度；同时决定哪些 hex 字符串会被识别为原始字节密钥。", effect: "影响密钥强度与随机密钥长度：16/32 位仅够演示；日常建议 256；512 位强度最高但没有实际必要。可选 16 / 32 / 64 / 128 / 256 / 512。" },
          { name: "中 / EN", desc: "在中文与英文界面之间切换。", effect: "界面文案立即更新，偏好保存在浏览器里，下次打开仍然生效。" },
        ],
      },
      {
        title: "加密页",
        items: [
          { name: "＋ 添加消息", desc: "新增一行「消息 + 密钥」。", effect: "每一行对应容器里的一个独立槽；行数 = 槽数。" },
          { name: "⟳ 随机密钥", desc: "用当前密钥长度生成随机 hex 密钥，填入该行。", effect: "生成强随机密钥；加密后必须用同一把密钥才能解出该行消息。" },
          { name: "× 删除", desc: "移除这一行。", effect: "该槽不再参与本次加密；已生成的密文不受影响。" },
          { name: "全部随机密钥", desc: "为所有行重新生成随机密钥。", effect: "覆盖所有密钥；再次加密后，用旧密钥无法解出新密文。" },
          { name: "pad_to", desc: "把所有明文统一填充到相同长度（字节）。", effect: "所有槽外观长度一致，对手无法从槽长判断哪条是真实消息；容器会变大。" },
          { name: "容器大小", desc: "手动指定容器总字节数（≥256），留空则自动。", effect: "决定密文大小；填得越大越不暴露消息量级，多出的空间是随机噪声。" },
          { name: "AAD", desc: "附加认证数据（hex），解密时必须完全一致。", effect: "AAD 不一致时解密失败；可用来绑定版本号、文件名等上下文。" },
          { name: "加密", desc: "把所有消息 + 密钥封进一个 Base64 容器。", effect: "输出密文与字节数；每条消息只用自己那一行的密钥可解。" },
        ],
      },
      {
        title: "解密页",
        items: [
          { name: "容器 · Base64", desc: "粘贴要解密的密文。", effect: "密钥会在自己的位置自动定位槽，无需知道容器里有多少个槽。" },
          { name: "密钥", desc: "任意字符串，或粘贴生成的 hex 密钥。", effect: "只有与加密时完全相同的密钥才能解出对应消息；错误密钥会明确失败。" },
          { name: "AAD", desc: "与加密时相同的 hex AAD。", effect: "AAD 不一致时即使密钥正确也无法解密。" },
          { name: "解密", desc: "用当前密钥尝试解密容器。", effect: "成功显示明文；失败显示错误提示。" },
        ],
      },
      {
        title: "规划页",
        items: [
          { name: "消息长度", desc: "逗号分隔的每条消息长度。", effect: "用于估算容器大小预算。" },
          { name: "pad_to", desc: "与加密页相同的填充参数。", effect: "有 pad_to 时按统一槽长计算最小容器。" },
          { name: "计算", desc: "根据长度估算最小 / 最大容器大小。", effect: "最小 = 刚好装下全部消息；最大 = 单槽长度的上限。" },
        ],
      },
      {
        title: "其它",
        items: [
          { name: "仅在本浏览器", desc: "所有密码学运算都在浏览器内完成。", effect: "密钥与明文从不经过本地服务器，也不会上网。" },
          { name: "关闭服务器并退出", desc: "停止本地服务器并结束 exe。", effect: "页面随之失效；需要时再次打开 exe 即可。" },
        ],
      },
    ],
  },

  en: {
    tagline: "N-key deniable encryption",
    pocBanner: "⚠ Proof of concept (PoC): unaudited cryptography. Do not use for real secrets. Read the security model.",
    localChip: "Runs only in this browser",
    tabEncrypt: "Encrypt",
    tabDecrypt: "Decrypt",
    tabInfo: "Plan",
    tabHelp: "Help",
    encTitle: "Seal N messages into one headerless container",
    btnAdd: "+ Add message",
    btnRandom: "Generate random key",
    btnRemove: "Remove row",
    btnRandomAll: "Randomize all keys",
    optPadTo: "pad_to · uniform slot length (optional)",
    optSize: "Container size · bytes (optional)",
    optAad: "AAD (hex, optional)",
    btnEncrypt: "Encrypt",
    encrypting: "Encrypting",
    outputTitle: "Ciphertext · Base64",
    btnCopy: "Copy",
    copied: "Copied",
    btnSave: "Save",
    meta: (n, b) => n + " slot" + (n === 1 ? "" : "s") + " · " + b,
    bytes: (b) => (b >= 1048576 ? (b / 1048576).toFixed(2) + " MiB"
                  : b >= 1024 ? (b / 1024).toFixed(1) + " KiB"
                  : b + " B"),
    errKey: (i) => "Row " + i + ": key must not be empty",
    errAad: "AAD must be even-length hex",
    errSize: "Container size must be an integer ≥ 256",
    errPadTo: "pad_to must be an integer ≥ 5",
    errB64: "Paste a Base64 container",
    errEncrypt: "Encryption failed",
    keyMeta: (kind, n) => kind === "hex" ? "hex key · " + n + " B" : "UTF-8 key · " + n + " B",
    customKeyWarn: "Custom keys detected: strength depends on the string itself; short passphrases are dictionary-attackable. For serious use, prefer the 32-byte keys from “Randomize all”.",
    decTitle: "Reveal the message owned by one key",
    decContainer: "Container · Base64",
    decKey: "Key · any string",
    btnDecrypt: "Decrypt",
    decrypting: "Decrypting",
    resultOk: "Decrypted",
    resultFail: "Decryption failed: wrong key or corrupted container",
    hexNote: "(non UTF-8 content, shown as hex)",
    infoTitle: "Container size budget",
    infoLengths: "Message lengths · comma-separated",
    infoPadTo: "pad_to (optional)",
    btnPlan: "Compute",
    minContainer: "Min container",
    maxContainer: "Max container",
    threatTitle: "Threat model: deny completeness, not existence",
    threatBody: "It is fine to admit the container holds multiple slots — each slot's position derives from its own key alone. An adversary holding only the keys you reveal cannot count the remaining slots, cannot tell which message you meant, and can never prove you withheld anything. Note: handing over every key exposes everything, and container size still leaks the magnitude of what is inside.",
    footer: "All computation happens in your browser — keys and plaintext never reach the local server.",
    phMsg: "message to seal…",
    phKey: "any string · Chinese/English/special; 64 hex = 32-byte key",
    phB64: "paste container (Base64)…",
    keylenLabel: "Key bits",
    keylenTitle: "Bit length for generated random keys; also controls how hex string keys are parsed",
    hexMisMatch: "⚠ looks like hex but length ≠ selected key bits → treated as UTF-8 text",
    helpTitle: "What each control does and its effect",
    btnShutdown: "Shut down server & exit",
    btnShutdownDone: "Closed · you can close this tab",
    help: [
      {
        title: "Key length",
        items: [
          { name: "Key bits · 16–512", desc: "Bit length used when generating random keys; also decides which hex strings are recognized as raw key bytes.", effect: "Sets key strength and random-key length: 16/32 bits are demo-only; 256 is the daily default; 512 is the maximum but not meaningfully stronger. Choices: 16 / 32 / 64 / 128 / 256 / 512." },
          { name: "中 / EN", desc: "Switch the interface between Chinese and English.", effect: "UI text updates immediately; the choice is remembered in the browser for next time." },
        ],
      },
      {
        title: "Encrypt tab",
        items: [
          { name: "＋ Add message", desc: "Add a “message + key” row.", effect: "Each row becomes an independent slot in the container; rows = slots." },
          { name: "⟳ Random key", desc: "Generate a random hex key at the current bit length for this row.", effect: "Produces a strong random key; only that key will decrypt this row afterwards." },
          { name: "× Remove", desc: "Delete this row.", effect: "That slot no longer participates in the next encryption; already-made ciphertext is unaffected." },
          { name: "Randomize all", desc: "Regenerate random keys for every row.", effect: "Overwrites all keys; after re-encrypting, old keys can no longer open the new ciphertext." },
          { name: "pad_to", desc: "Pad every plaintext to the same length (bytes).", effect: "All slots look identical in length, so length can't betray which message is real; container grows." },
          { name: "Container size", desc: "Manually set the container's total bytes (≥256); leave empty for auto.", effect: "Controls ciphertext size; larger hides magnitude better, spare space is random noise." },
          { name: "AAD", desc: "Additional authenticated data (hex); must match on decrypt.", effect: "Mismatched AAD fails decryption; useful to bind context like version or filename." },
          { name: "Encrypt", desc: "Seal all messages + keys into one Base64 container.", effect: "Outputs the ciphertext and its size; each message opens only with its own row's key." },
        ],
      },
      {
        title: "Decrypt tab",
        items: [
          { name: "Container · Base64", desc: "Paste the ciphertext to decrypt.", effect: "The key locates its slot by itself; no need to know how many slots exist." },
          { name: "Key", desc: "Any string, or paste a generated hex key.", effect: "Only the exact key used at encryption opens its message; wrong keys fail cleanly." },
          { name: "AAD", desc: "The same hex AAD used at encryption.", effect: "Even a correct key fails if the AAD differs." },
          { name: "Decrypt", desc: "Try to decrypt the container with the current key.", effect: "Shows the plaintext on success, an error on failure." },
        ],
      },
      {
        title: "Plan tab",
        items: [
          { name: "Message lengths", desc: "Comma-separated lengths of each message.", effect: "Used to estimate the container size budget." },
          { name: "pad_to", desc: "Same padding parameter as the Encrypt tab.", effect: "With pad_to, the min container is computed from uniform slot lengths." },
          { name: "Compute", desc: "Estimate the minimum / maximum container size from the lengths.", effect: "Min = just enough for all messages; max = the single-slot length ceiling." },
        ],
      },
      {
        title: "Other",
        items: [
          { name: "Local only", desc: "All cryptography runs inside the browser.", effect: "Keys and plaintext never touch the local server or the network." },
          { name: "Shut down server & exit", desc: "Stop the local server and end the exe.", effect: "The page stops working; reopen the exe when you need it again." },
        ],
      },
    ],
  },
};

let lang = "zh";
try { lang = localStorage.getItem("dc-lang") || "zh"; } catch (e) { /* storage unavailable */ }

function t(key, ...args) {
  const v = (I18N[lang] || I18N.zh)[key];
  return typeof v === "function" ? v(...args) : (v === undefined ? key : v);
}

function render() {
  $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $$("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  $$("[data-i18n-title]").forEach((el) => { el.title = t(el.dataset.i18nTitle); });
  document.documentElement.lang = lang;
  renderHelp();
}

/* ═══════════════════════════ helpers ═══════════════════════════ */

const HEX = /^[0-9a-fA-F]*$/;

function showErr(elm, msg) { elm.textContent = msg; elm.hidden = false; }
function hide(elm) { elm.hidden = true; }

function setBusy(btn, busy, busyText) {
  btn.disabled = busy;
  if (busy) {
    btn.dataset.orig = btn.textContent;
    btn.textContent = "";
    const sp = document.createElement("span");
    sp.className = "spinner";
    sp.setAttribute("aria-hidden", "true");
    btn.appendChild(sp);
    btn.appendChild(document.createTextNode(busyText));
  } else {
    btn.textContent = btn.dataset.orig || btn.textContent;
  }
}

function readInt(id) {
  const v = $(id).value.trim();
  if (v === "") return undefined;
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : null; // null → invalid
}

async function copyText(text, btn) {
  const done = () => {
    const orig = btn.textContent;
    btn.textContent = t("copied");
    setTimeout(() => { btn.textContent = orig; }, 1200);
  };
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    done();
  } catch (e) {
    /* clipboard blocked — select the textarea instead so the user can copy */
    const out = $("#output");
    out.focus(); out.select();
  }
}

/* ═══════════════════════════ state ═══════════════════════════ */

let rowEls = [];

// Selected key length in bits (16 / 32 / 64 / 128 / 256 / 512).
function getBits() {
  const el = $("#opt-key-bits");
  const v = el ? parseInt(el.value, 10) : 256;
  return DeniableMulti.KEY_BITS.indexOf(v) !== -1 ? v : 256;
}

function saveBits() {
  try { localStorage.setItem("dc-bits", $("#opt-key-bits").value); } catch (e) { /* ignore */ }
}

// Show the derived key length/kind under a key input, and keep the custom-key
// strength warning in sync. Any non-empty string is a valid key (a hex string
// of the selected bit length → decoded bytes; anything else → UTF-8 bytes, so
// length is up to you).
function refreshKeyMeta(input, metaEl) {
  const v = input.value.trim();
  if (!v) { metaEl.textContent = ""; metaEl.classList.remove("warn"); return; }
  let info;
  try { info = DeniableMulti.keyInfo(v, getBits()); } catch (e) { metaEl.textContent = ""; return; }
  let text = t("keyMeta", info.kind, info.byteLen);
  if (info.kind === "utf8" && info.hexish) text += " · " + t("hexMisMatch");
  metaEl.textContent = text;
  metaEl.classList.toggle("warn", info.kind === "utf8");
}

function updateCustomKeyWarn() {
  const el = $("#enc-warn");
  if (!el) return;
  let anyCustom = false;
  for (const r of rowEls) {
    const k = r.querySelector(".key").value.trim();
    if (!k) continue;
    try { if (DeniableMulti.keyInfo(k, getBits()).kind === "utf8") { anyCustom = true; break; } } catch (e) { /* ignore */ }
  }
  el.hidden = !anyCustom;
}

function refreshAllKeyMeta() {
  rowEls.forEach((r) => refreshKeyMeta(r.querySelector(".key"), r.querySelector(".keymeta")));
  const dk = $("#dec-key"), dkm = $("#dec-keymeta");
  if (dk && dkm) refreshKeyMeta(dk, dkm);
  updateCustomKeyWarn();
}

function addRow(msg, key) {
  const row = document.createElement("div");
  row.className = "row";

  const ta = document.createElement("textarea");
  ta.className = "msg";
  ta.placeholder = t("phMsg");
  ta.spellcheck = false;
  ta.value = msg;

  const kw = document.createElement("div");
  kw.className = "keywrap";
  const ki = document.createElement("input");
  ki.className = "key";
  ki.placeholder = t("phKey");
  ki.spellcheck = false;
  ki.value = key;
  const km = document.createElement("span");
  km.className = "keymeta";
  ki.addEventListener("input", () => { refreshKeyMeta(ki, km); updateCustomKeyWarn(); });
  kw.appendChild(ki);
  kw.appendChild(km);

  const rb = document.createElement("button");
  rb.type = "button";
  rb.className = "icon-btn";
  rb.title = t("btnRandom");
  rb.textContent = "⟳";
  rb.addEventListener("click", () => {
    ki.value = DeniableMulti.randomKeyHex(getBits());
    refreshKeyMeta(ki, km);
    updateCustomKeyWarn();
  });

  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "icon-btn remove";
  rm.title = t("btnRemove");
  rm.textContent = "×";
  rm.addEventListener("click", () => {
    row.remove();
    rowEls = rowEls.filter((r) => r !== row);
    $("#btn-encrypt").disabled = rowEls.length === 0;
    updateCustomKeyWarn();
  });

  row.appendChild(ta);
  row.appendChild(kw);
  row.appendChild(rb);
  row.appendChild(rm);
  $("#rows").appendChild(row);
  rowEls.push(row);
}

/* ═══════════════════════════ tabs ═══════════════════════════ */

function switchTab(name) {
  $$("nav.tabs button").forEach((b) => {
    b.setAttribute("aria-selected", String(b.dataset.tab === name));
  });
  $$("section.tab").forEach((s) => {
    s.classList.toggle("active", s.id === "tab-" + name);
  });
}

/* ═══════════════════════════ help ═══════════════════════════ */

// Rebuilds the Help tab from the current language's `help` data (name → what
// it is → what it does / effect), so the page stays a self-documenting map of
// every control.
function renderHelp() {
  const host = $("#help-list");
  if (!host) return;
  const groups = (I18N[lang] || I18N.zh).help || [];
  host.innerHTML = "";
  for (const g of groups) {
    const box = document.createElement("div");
    box.className = "help-group";

    const h = document.createElement("h3");
    h.textContent = g.title;
    box.appendChild(h);

    for (const it of g.items) {
      const item = document.createElement("div");
      item.className = "help-item";

      const nm = document.createElement("div");
      nm.className = "help-name";
      nm.textContent = it.name;
      const de = document.createElement("div");
      de.className = "help-desc";
      de.textContent = it.desc;
      const ef = document.createElement("div");
      ef.className = "help-effect";
      ef.textContent = it.effect;

      item.appendChild(nm);
      item.appendChild(de);
      item.appendChild(ef);
      box.appendChild(item);
    }
    host.appendChild(box);
  }
}

/* ═══════════════════════════ encrypt ═══════════════════════════ */

async function doEncrypt() {
  const err = $("#enc-error");
  hide(err);

  const padTo = readInt("#opt-pad-to");
  const size = readInt("#opt-size");
  if (padTo === null) { showErr(err, t("errPadTo")); return; }
  if (size === null) { showErr(err, t("errSize")); return; }

  const aad = $("#opt-aad").value.trim();
  if (aad && !(HEX.test(aad) && aad.length % 2 === 0)) { showErr(err, t("errAad")); return; }

  const messages = [];
  const keys = [];
  for (let i = 0; i < rowEls.length; i++) {
    const msg = rowEls[i].querySelector(".msg").value;
    const key = rowEls[i].querySelector(".key").value.trim();
    if (!key) { showErr(err, t("errKey", i + 1)); return; }
    messages.push(msg);
    keys.push(key);
  }

  const btn = $("#btn-encrypt");
  setBusy(btn, true, t("encrypting"));
  try {
    const b64 = await DeniableMulti.encrypt(messages, keys, {
      pad_to: padTo, size: size, aad_hex: aad || undefined, bits: getBits(),
    });
    $("#output").value = b64;
    const n = DeniableMulti.b64ToBytes(b64).length;
    $("#output-meta").textContent = t("meta", keys.length, t("bytes", n));
    $("#output-panel").hidden = false;
  } catch (e) {
    showErr(err, t("errEncrypt") + ": " + e.message);
  } finally {
    setBusy(btn, false);
  }
}

/* ═══════════════════════════ decrypt ═══════════════════════════ */

async function doDecrypt() {
  const err = $("#dec-error");
  hide(err);
  $("#dec-result").hidden = true;

  const b64 = $("#dec-container").value.trim();
  const key = $("#dec-key").value.trim();
  const aad = $("#dec-aad").value.trim();
  if (!b64) { showErr(err, t("errB64")); return; }
  if (!key) { showErr(err, t("errKey", 1)); return; }
  if (aad && !(HEX.test(aad) && aad.length % 2 === 0)) { showErr(err, t("errAad")); return; }

  const btn = $("#btn-decrypt");
  setBusy(btn, true, t("decrypting"));
  try {
    const pt = await DeniableMulti.decrypt(b64, key, aad || undefined, getBits());
    const box = $("#dec-result");
    box.hidden = false;
    const title = $("#dec-result-title");
    const note = $("#dec-hex-note");
    note.hidden = true;
    const out = $("#dec-output");
    if (pt === null) {
      box.classList.remove("result-ok");
      box.classList.add("result-fail");
      title.textContent = t("resultFail");
      out.value = "";
      return;
    }
    box.classList.remove("result-fail");
    box.classList.add("result-ok");
    title.textContent = t("resultOk");
    const txt = DeniableMulti.bytesToUtf8(pt);
    if (txt.indexOf("�") === -1 && txt.length > 0) {
      out.value = txt;
    } else {
      out.value = DeniableMulti.bytesToHex(pt);
      note.textContent = t("hexNote");
      note.hidden = false;
    }
  } finally {
    setBusy(btn, false);
  }
}

/* ═══════════════════════════ plan / info ═══════════════════════════ */

function doPlan() {
  const padTo = readInt("#info-pad-to");
  if (padTo === null) { /* invalid → treat as empty */ }
  const lengths = $("#info-lengths").value
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => !Number.isNaN(n));
  if (lengths.length === 0) return;
  const mn = DeniableMulti.minSize(lengths, padTo !== undefined && padTo !== null ? padTo : null);
  $("#plan-min").textContent = t("bytes", mn) + " · " + mn;
  $("#plan-max").textContent = t("bytes", DeniableMulti.maxSize()) + " · " + DeniableMulti.maxSize();
}

/* ═══════════════════════════ wire-up ═══════════════════════════ */

function init() {
  render();

  // restore the saved key length before the initial random keys are generated
  let savedBits = null;
  try { savedBits = localStorage.getItem("dc-bits"); } catch (e) { /* ignore */ }
  const ksel = $("#opt-key-bits");
  if (ksel && savedBits && DeniableMulti.KEY_BITS.indexOf(parseInt(savedBits, 10)) !== -1) {
    ksel.value = savedBits;
  }

  // language
  $$(".lang-toggle button").forEach((b) => {
    b.addEventListener("click", () => {
      lang = b.dataset.lang;
      try { localStorage.setItem("dc-lang", lang); } catch (e) { /* ignore */ }
      $$(".lang-toggle button").forEach((x) =>
        x.setAttribute("aria-pressed", String(x.dataset.lang === lang)));
      render();
      refreshAllKeyMeta(); // keymeta text is language-dependent
    });
  });

  // tabs
  $$("nav.tabs button").forEach((b) => {
    b.addEventListener("click", () => switchTab(b.dataset.tab));
  });

  // rows
  $("#btn-add").addEventListener("click", () => addRow("", ""));
  $("#btn-random-all").addEventListener("click", () => {
    rowEls.forEach((r) => { r.querySelector(".key").value = DeniableMulti.randomKeyHex(getBits()); });
    refreshAllKeyMeta();
  });
  const dk = $("#dec-key"), dkm = $("#dec-keymeta");
  if (dk && dkm) dk.addEventListener("input", () => refreshKeyMeta(dk, dkm));

  // key length selector
  if (ksel) ksel.addEventListener("change", () => {
    saveBits();
    refreshAllKeyMeta();
  });

  // encrypt / decrypt / plan
  $("#btn-encrypt").addEventListener("click", doEncrypt);
  $("#btn-decrypt").addEventListener("click", doDecrypt);
  $("#btn-plan").addEventListener("click", doPlan);

  // output actions
  $("#btn-copy").addEventListener("click", () => {
    const out = $("#output");
    if (out.value) copyText(out.value, $("#btn-copy"));
  });
  $("#btn-save").addEventListener("click", () => {
    const out = $("#output");
    if (!out.value) return;
    const blob = new Blob([out.value], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "deniable-cipher.b64";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 100);
  });

  // Enter in the single-key decrypt field triggers decrypt
  $("#dec-key").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doDecrypt();
  });

  // shut down the local server (--noconsole exe has no Ctrl+C)
  $("#btn-shutdown").addEventListener("click", async () => {
    const btn = $("#btn-shutdown");
    btn.disabled = true;
    try {
      await fetch("api/shutdown", { method: "POST" });
    } catch (e) { /* server already gone */ }
    btn.textContent = t("btnShutdownDone");
  });

  // start with two rows, keys generated in-session only
  addRow("", DeniableMulti.randomKeyHex(getBits()));
  addRow("", DeniableMulti.randomKeyHex(getBits()));
  $("#btn-encrypt").disabled = false;
  refreshAllKeyMeta();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
