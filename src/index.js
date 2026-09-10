// SPDX-License-Identifier: AGPL-3.0-or-later
// crate-carrier — a single-tenant Cloudflare Worker that fronts ONE R2 bucket
// for the Crate browser app. It is the USER'S Worker in the USER'S account;
// the Worker holds an R2 *binding*, so the user never creates an API token,
// never configures CORS, and never copies an account ID. Deleting the Worker
// revokes access instantly.
//
// What it does: signed PUT/GET/HEAD/DELETE of opaque objects, plus R2
// multipart so a file larger than the per-request body cap (100 MB on
// Free/Pro) can be uploaded in parts. What it never sees: a passphrase, a key,
// or a plaintext byte — every object is ciphertext sealed in the browser.
//
// Security core (src/lib.js, unit-tested): HMAC-SHA256 request signature over
// method/path/query/ts/nonce, ±5 min window, constant-time compare, CORS
// scoped to configured origins (never "*"), conservative key validation.

import { verify, validKey } from "./lib.js";

const SINGLE_PUT_MAX = 95 * 1024 * 1024; // under the 100 MB edge cap; larger ⇒ multipart

function corsHeaders(origin, allowOrigins) {
  const ok = allowOrigins.includes(origin);
  return {
    "access-control-allow-origin": ok ? origin : allowOrigins[0],
    "access-control-allow-methods": "GET, HEAD, PUT, POST, DELETE, OPTIONS",
    "access-control-allow-headers": "content-type, if-match, if-none-match, range, x-crate-ts, x-crate-nonce, x-crate-sig",
    "access-control-expose-headers": "etag, content-length, content-range, accept-ranges",
    "access-control-max-age": "600",
    "vary": "origin",
  };
}

function json(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({ "content-type": "application/json" }, extra || {}),
  });
}

function unquote(etag) {
  if (!etag) return null;
  const t = etag.trim();
  return /^"(.*)"$/.test(t) ? t.slice(1, -1) : t;
}

function parseList(v) {
  return String(v || "").split(",").map((s) => s.trim()).filter(Boolean);
}

export default {
  async fetch(request, env) {
    const allowOrigins = parseList(env.ALLOW_ORIGINS || "https://crate.naklios.dev");
    const origin = request.headers.get("origin") || "";
    const cors = corsHeaders(origin, allowOrigins);
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    if (url.pathname === "/" || url.pathname === "/health") {
      return json({ ok: true, service: "crate-carrier", ready: !!env.CARRIER_SECRET, bucket: !!env.BUCKET }, 200, cors);
    }
    if (!url.pathname.startsWith("/o/")) return json({ ok: false, error: "not found" }, 404, cors);
    if (!env.BUCKET) return json({ ok: false, error: "no R2 binding" }, 500, cors);

    const v = await verify(env.CARRIER_SECRET, {
      method, path: url.pathname, query: url.searchParams,
      headers: (n) => request.headers.get(n),
    });
    if (!v.ok) return json({ ok: false, error: "unauthorized: " + v.reason }, 401, cors);

    const key = decodeURIComponent(url.pathname.slice(3));
    if (!validKey(key)) return json({ ok: false, error: "invalid key" }, 400, cors);
    const q = url.searchParams;

    try {
      // ---- multipart --------------------------------------------------------
      if (q.has("mpu")) {
        const op = q.get("mpu");
        if (op === "create" && method === "POST") {
          const mpu = await env.BUCKET.createMultipartUpload(key, {
            httpMetadata: { contentType: request.headers.get("content-type") || "application/octet-stream" },
          });
          return json({ ok: true, key, uploadId: mpu.uploadId }, 200, cors);
        }
        const uploadId = q.get("uploadId");
        if (!uploadId) return json({ ok: false, error: "uploadId required" }, 400, cors);
        const mpu = env.BUCKET.resumeMultipartUpload(key, uploadId);
        if (op === "part" && method === "PUT") {
          const n = Number(q.get("n"));
          if (!Number.isInteger(n) || n < 1 || n > 10000) return json({ ok: false, error: "part number 1..10000" }, 400, cors);
          const part = await mpu.uploadPart(n, request.body);
          return json({ ok: true, partNumber: part.partNumber, etag: part.etag }, 200, cors);
        }
        if (op === "complete" && method === "POST") {
          const parts = await request.json();
          if (!Array.isArray(parts) || parts.length === 0) return json({ ok: false, error: "parts[] required" }, 400, cors);
          const obj = await mpu.complete(parts);
          return json({ ok: true, key, size: obj.size, etag: obj.httpEtag }, 200, { ...cors, etag: obj.httpEtag });
        }
        if (op === "abort" && method === "POST") {
          await mpu.abort();
          return json({ ok: true, aborted: key }, 200, cors);
        }
        return json({ ok: false, error: "bad multipart op" }, 400, cors);
      }

      // ---- single-object ----------------------------------------------------
      if (method === "PUT") {
        const clen = Number(request.headers.get("content-length") || 0);
        if (clen > SINGLE_PUT_MAX) {
          return json({ ok: false, error: `body ${clen} exceeds single-PUT limit ${SINGLE_PUT_MAX}; use multipart` }, 413, cors);
        }
        const opts = { httpMetadata: { contentType: request.headers.get("content-type") || "application/octet-stream" } };
        // ETag-conditional PUT — Crate's manifest concurrency control.
        // R2's onlyIf takes the bare ETag; HTTP carries it quoted. Accept
        // either from the client, hand R2 the unquoted form.
        const ifMatch = unquote(request.headers.get("if-match"));
        const ifNoneMatch = request.headers.get("if-none-match");
        if (ifMatch) opts.onlyIf = { etagMatches: ifMatch };
        else if (ifNoneMatch === "*") opts.onlyIf = { etagDoesNotMatch: "*" };
        const obj = await env.BUCKET.put(key, request.body, opts);
        if (!obj) return json({ ok: false, error: "precondition failed" }, 412, cors);
        return json({ ok: true, key, size: obj.size, etag: obj.httpEtag }, 200, { ...cors, etag: obj.httpEtag });
      }

      if (method === "GET" || method === "HEAD") {
        const range = request.headers.get("range");
        const obj = method === "HEAD"
          ? await env.BUCKET.head(key)
          : await env.BUCKET.get(key, range ? { range: request.headers } : undefined);
        if (!obj) return json({ ok: false, error: "not found" }, 404, cors);
        const h = new Headers(cors);
        obj.writeHttpMetadata(h);
        h.set("etag", obj.httpEtag);
        h.set("accept-ranges", "bytes");
        if (method === "HEAD") { h.set("content-length", String(obj.size)); return new Response(null, { status: 200, headers: h }); }
        if (range && obj.range) {
          const { offset = 0, length = obj.size - offset } = obj.range;
          h.set("content-range", `bytes ${offset}-${offset + length - 1}/${obj.size}`);
          h.set("content-length", String(length));
          return new Response(obj.body, { status: 206, headers: h });
        }
        h.set("content-length", String(obj.size));
        return new Response(obj.body, { status: 200, headers: h });
      }

      if (method === "DELETE") {
        await env.BUCKET.delete(key);
        return json({ ok: true, deleted: key }, 200, cors);
      }

      return json({ ok: false, error: "method not allowed" }, 405, cors);
    } catch (e) {
      // Never echo bodies or headers. R2 errors carry no user data.
      return json({ ok: false, error: "carrier error: " + (e && e.message ? e.message : "unknown") }, 502, cors);
    }
  },
};
