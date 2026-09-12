// SPDX-License-Identifier: AGPL-3.0-or-later
// Conformance — crate-carrier security core (src/lib.js). node, no network.
import assert from "node:assert/strict";
import { sign, verify, canonicalString, validKey, WINDOW_MS } from "../src/lib.js";

const SECRET = "test-secret";
const now = 1_700_000_000_000;
const hdrs = (h) => (n) => h[n] ?? null;

// round trip
{
  const req = { method: "PUT", path: "/o/objects/01ABC", query: "mpu=part&uploadId=u1&n=3", ts: now, nonce: "n1" };
  const h = await sign(SECRET, req);
  assert.deepEqual(await verify(SECRET, { ...req, headers: hdrs(h), now }), { ok: true });
  // query order does not matter
  const h2 = await sign(SECRET, { ...req, query: "n=3&uploadId=u1&mpu=part" });
  assert.equal(h2["x-crate-sig"], h["x-crate-sig"], "canonical query is order-independent");
}

// every signed field is bound
{
  const base = { method: "PUT", path: "/o/objects/01ABC", query: "", ts: now, nonce: "n1" };
  const h = await sign(SECRET, base);
  for (const [label, mut] of [
    ["method", { method: "DELETE" }],
    ["path", { path: "/o/objects/01XYZ" }],
    ["query", { query: "mpu=abort&uploadId=u1" }],
  ]) {
    const r = await verify(SECRET, { ...base, ...mut, headers: hdrs(h), now });
    assert.equal(r.ok, false, `${label} not bound`);
    assert.equal(r.reason, "bad signature");
  }
  const tampered = { ...h, "x-crate-nonce": "n2" };
  assert.equal((await verify(SECRET, { ...base, headers: hdrs(tampered), now })).reason, "bad signature");
  assert.equal((await verify("other", { ...base, headers: hdrs(h), now })).reason, "bad signature");
}

// time window
{
  const base = { method: "GET", path: "/o/x", query: "", ts: now, nonce: "n" };
  const h = await sign(SECRET, base);
  assert.equal((await verify(SECRET, { ...base, headers: hdrs(h), now: now + WINDOW_MS - 1 })).ok, true);
  assert.equal((await verify(SECRET, { ...base, headers: hdrs(h), now: now + WINDOW_MS + 1 })).reason, "stale timestamp");
  assert.equal((await verify(SECRET, { ...base, headers: hdrs(h), now: now - WINDOW_MS - 1 })).reason, "stale timestamp");
}

// missing / unconfigured
{
  assert.equal((await verify(SECRET, { method: "GET", path: "/o/x", query: "", headers: hdrs({}), now })).reason, "missing signature headers");
  assert.match((await verify("", { method: "GET", path: "/o/x", query: "", headers: hdrs({}), now })).reason, /not configured/);
}

// canonical form is stable (a client in another language must reproduce it)
assert.equal(
  canonicalString({ method: "put", path: "/o/a", query: "b=2&a=1", ts: 5, nonce: "z" }),
  "PUT\n/o/a\na=1&b=2\n5\nz",
);

// key validation
for (const good of ["objects/01HXYZ", ".crate/manifest.jsonl.enc", ".crate/crate.json", "a/b/c.bin"]) assert.ok(validKey(good), good);
for (const bad of ["", "/abs", "a//b", "../x", "a/../b", "a/./b", "sp ace", "x\n", "é", "a".repeat(257)]) assert.ok(!validKey(bad), JSON.stringify(bad));

console.log("OK: crate-carrier security core");

// share links: query-string auth for one GET/HEAD until exp
{
  const { shareSign, shareVerify, SHARE_MAX_MS } = await import("../src/lib.js");
  const path = "/o/objects/01ABC";
  const exp = now + 3600_000;
  const q = await shareSign(SECRET, { path, exp });
  const qs = new URLSearchParams(q);
  assert.deepEqual(await shareVerify(SECRET, { method: "GET", path, query: qs, now }), { ok: true });
  assert.deepEqual(await shareVerify(SECRET, { method: "HEAD", path, query: qs, now }), { ok: true });
  // bound to path, exp, secret, method; refused after expiry and beyond the cap
  assert.equal((await shareVerify(SECRET, { method: "GET", path: "/o/objects/01XYZ", query: qs, now })).ok, false);
  assert.equal((await shareVerify(SECRET, { method: "PUT", path, query: qs, now })).ok, false);
  assert.equal((await shareVerify("other", { method: "GET", path, query: qs, now })).ok, false);
  assert.equal((await shareVerify(SECRET, { method: "GET", path, query: qs, now: exp + 1 })).reason, "share link expired");
  const tampered = new URLSearchParams(q); tampered.set("exp", String(exp + 1));
  assert.equal((await shareVerify(SECRET, { method: "GET", path, query: tampered, now })).reason, "bad share signature");
  const far = await shareSign(SECRET, { path, exp: now + SHARE_MAX_MS + 120_000 });
  assert.equal((await shareVerify(SECRET, { method: "GET", path, query: new URLSearchParams(far), now })).reason, "share link too long-lived");
  // the header path is untouched by a share param that is not "1"
  assert.equal((await shareVerify(SECRET, { method: "GET", path, query: "share=1", now })).reason, "missing share parameters");
  console.log("OK: share links — signed query auth for one object, read-only, expiring, bound to path");
}
