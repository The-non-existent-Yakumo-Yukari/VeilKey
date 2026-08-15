/*
 * Cross-verification bridge: exposes crypto.js operations over a JSON CLI.
 * Invoked by the pytest suite as:
 *     node _node_harness.js '<json-command>'
 * and prints one JSON object to stdout ({ ok: true, value: ... }).
 * Inputs are hex strings; outputs are hex strings / ints / arrays.
 */
"use strict";

const fs = require("fs");
const DM = require("../crypto.js");

// Resolve a key spec to bytes: a plain string goes through the same parseKey
// rule the browser uses (hex of the selected bit length → decoded bytes, else
// UTF-8); {hex} / {utf8} let tests force an interpretation explicitly.
function keyBytes(k, bits) {
  if (typeof k === "object" && k !== null) {
    return k.hex !== undefined ? DM.hexToBytes(k.hex) : DM.utf8ToBytes(k.utf8);
  }
  return DM.parseKey(k, bits);
}

async function run(cmd) {
  switch (cmd.cmd) {
    case "parseKey": {
      const info = DM.keyInfo(cmd.key, cmd.bits);
      return { value: { kind: info.kind, byteLen: info.byteLen, hex: DM.bytesToHex(info.bytes) } };
    }
    case "randomKeyHex": {
      return { value: DM.randomKeyHex(cmd.bits) };
    }
    case "hkdf": {
      const out = await DM.hkdf(DM.hexToBytes(cmd.key), DM.hexToBytes(cmd.info), cmd.length);
      return { value: DM.bytesToHex(out) };
    }
    case "pos": {
      return { value: await DM.pos(DM.hexToBytes(cmd.key), cmd.total, cmd.trial || 0) };
    }
    case "gcmEnc": {
      const aad = cmd.aad ? DM.hexToBytes(cmd.aad) : undefined;
      const ct = await DM.gcmEncrypt(
        DM.hexToBytes(cmd.ek), DM.hexToBytes(cmd.nonce), DM.hexToBytes(cmd.pt), aad,
      );
      return { value: DM.bytesToHex(ct) };
    }
    case "gcmDec": {
      const aad = cmd.aad ? DM.hexToBytes(cmd.aad) : undefined;
      const pt = await DM.gcmDecrypt(
        DM.hexToBytes(cmd.ek), DM.hexToBytes(cmd.nonce), DM.hexToBytes(cmd.ct), aad,
      );
      return { value: DM.bytesToHex(pt) };
    }
    case "minSize": {
      return { value: DM.minSize(cmd.lengths, cmd.pad_to != null ? cmd.pad_to : null) };
    }
    case "maxSize":
      return { value: DM.maxSize() };

    case "encryptMany": {
      const messages = cmd.messages.map((m) =>
        typeof m === "object" && m !== null ? DM.hexToBytes(m.hex) : m,
      );
      const keys = cmd.keys.map((k) => keyBytes(k, cmd.bits));
      const opts = {};
      if (cmd.pad_to != null) opts.pad_to = cmd.pad_to;
      if (cmd.size != null) opts.size = cmd.size;
      if (cmd.aad) opts.aad = DM.hexToBytes(cmd.aad);
      const raw = await DM.encryptMany(messages, keys, opts);
      return { value: DM.bytesToHex(raw) };
    }

    case "decryptB64":
    case "decryptHex": {
      const raw = cmd.cmd === "decryptB64" ? DM.b64ToBytes(cmd.b64) : DM.hexToBytes(cmd.hex);
      const aad = cmd.aad ? DM.hexToBytes(cmd.aad) : undefined;
      const results = [];
      for (const k of cmd.keys) {
        const pt = await DM.decryptMany(raw, keyBytes(k, cmd.bits), aad);
        results.push(pt === null ? null : DM.bytesToHex(pt));
      }
      return { value: results };
    }

    default:
      throw new Error("unknown cmd: " + cmd.cmd);
  }
}

run(JSON.parse(process.argv[2])).then(
  (out) => console.log(JSON.stringify(Object.assign({ ok: true }, out))),
  (err) => console.log(JSON.stringify({ ok: false, error: String((err && err.stack) || err) })),
);
