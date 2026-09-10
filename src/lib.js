// SPDX-License-Identifier: AGPL-3.0-or-later
// crate-carrier security core — pure functions, no Worker globals, so it
// unit-tests under node. WebCrypto only.
//
// Request signing. Every call carries three headers:
//   x-crate-ts     unix ms
//   x-crate-nonce  random string (client-side uniqueness; see below)
//   x-crate-sig    hex HMAC-SHA256(CARRIER_SECRET, canonical)
//   canonical    = METHOD \n path \n sorted-query \n ts \n nonce
//
// The BODY is deliberately not signed. Bodies are multi-MB ciphertext chunks
// that must stream straight through to R2; hashing them first would mean
// buffering the whole chunk in the Worker. What protects the body is that it
// is already AES-GCM ciphertext authenticated end-to-end by the browser under
// a key this Worker never sees, and TLS in flight. A replayed request within
// the ±5 min window is idempotent for every route (same bytes to the same
// key, same part, same delete), so no nonce store is kept.

const enc = new TextEncoder();
export const WINDOW_MS = 5 * 60 * 1000;

export function canonicalString({ method, path, query, ts, nonce }) {
  const q = query instanceof URLSearchParams ? query : new URLSearchParams(query || "");
  const pairs = [...q.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1));
  return [
    String(method || "GET").toUpperCase(),
    String(path || "/"),
    pairs.map(([k, v]) => `${k}=${v}`).join("&"),
    String(ts || ""),
    String(nonce || ""),
  ].join("\n");
}

export async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return hex(new Uint8Array(sig));
}

function hex(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
  return s;
}

export function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// sign is what the browser does. Returns the three header values.
export async function sign(secret, { method, path, query, ts = Date.now(), nonce = randomNonce() }) {
  const sig = await hmacHex(secret, canonicalString({ method, path, query, ts, nonce }));
  return { "x-crate-ts": String(ts), "x-crate-nonce": nonce, "x-crate-sig": sig };
}

export function randomNonce() {
  return hex(crypto.getRandomValues(new Uint8Array(12)));
}

// verify is what the Worker does. headers: a getter (name) => value|null.
// Returns { ok } or { ok:false, reason }.
export async function verify(secret, { method, path, query, headers, now = Date.now() }) {
  if (!secret) return { ok: false, reason: "carrier not configured (CARRIER_SECRET unset)" };
  const ts = headers("x-crate-ts"), nonce = headers("x-crate-nonce"), sig = headers("x-crate-sig");
  if (!ts || !nonce || !sig) return { ok: false, reason: "missing signature headers" };
  const skew = Math.abs(Number(now) - Number(ts));
  if (!Number.isFinite(skew) || skew > WINDOW_MS) return { ok: false, reason: "stale timestamp" };
  const expect = await hmacHex(secret, canonicalString({ method, path, query, ts, nonce }));
  if (!timingSafeEqual(expect, String(sig))) return { ok: false, reason: "bad signature" };
  return { ok: true };
}

// Object keys: Crate writes objects/<ULID> and .crate/<file>. Accept a
// conservative superset; refuse traversal, control chars, and absurd lengths.
export function validKey(key) {
  if (typeof key !== "string" || key.length === 0 || key.length > 256) return false;
  if (!/^[A-Za-z0-9._\-\/]+$/.test(key)) return false;
  if (key.startsWith("/") || key.includes("//") || key.split("/").some((s) => s === "." || s === "..")) return false;
  return true;
}
