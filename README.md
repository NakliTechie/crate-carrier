# crate-carrier

Your own Cloudflare Worker, in your own Cloudflare account, fronting your own R2 bucket for [Crate](https://crate.naklios.dev) — the end-to-end-encrypted personal cloud folder from [NakliOS](https://naklios.dev).

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/NakliTechie/crate-carrier)

## Why this exists

Crate encrypts every file in your browser before it leaves the tab, and stores the ciphertext in a bucket you own. Until now, connecting the tab to that bucket meant four manual steps in the Cloudflare dashboard: copy an account ID, create a bucket, create an API token (whose secret is shown exactly once), and paste a CORS policy.

This Worker replaces all four with one click. It holds an R2 *binding* — not an API token — so there is no secret to copy, no CORS to configure, and no account ID to find. Cloudflare creates the bucket for you when you deploy.

**What the Worker sees:** ciphertext, and the size and timing of your reads and writes.
**What it never sees:** your passphrase, any key, or a single plaintext byte.
**How to revoke it:** delete the Worker. Access ends instantly. Your bucket and its ciphertext stay yours.

## Deploy

1. Start a new folder at [crate.naklios.dev](https://crate.naklios.dev) and choose **One-click carrier**. Crate shows a generated secret.
2. Click the button above. Cloudflare copies this repository into your GitHub or GitLab account, creates the R2 bucket, and asks for `CARRIER_SECRET` — paste the secret from step 1.
3. Back in Crate, paste your new Worker's URL (`https://crate-carrier.<you>.workers.dev`). Done.

Manual deploy, if you prefer:

```sh
npx wrangler r2 bucket create crate
npx wrangler deploy
openssl rand -hex 32 | npx wrangler secret put CARRIER_SECRET
```

## Security model

- **Signed requests.** Every call carries `x-crate-ts`, `x-crate-nonce`, `x-crate-sig` = HMAC-SHA256(`CARRIER_SECRET`, `METHOD\npath\nsorted-query\nts\nnonce`). Bad signature or a timestamp outside ±5 minutes → 401. Constant-time compare.
- **Bodies are not signed, on purpose.** They are multi-megabyte ciphertext chunks that stream straight through to R2; hashing them first would mean buffering every chunk in the Worker. The body is already authenticated end-to-end by AES-GCM in your browser under a key this Worker never has, and by TLS in flight. Every route is idempotent under replay within the window, so no nonce store is kept.
- **CORS scoped, never `*`.** `ALLOW_ORIGINS` defaults to the two Crate origins; edit it in the Worker's settings if you self-host Crate.
- **Conservative keys.** `[A-Za-z0-9._/-]`, no traversal, ≤ 256 chars.
- **No logging** of bodies or headers. Errors never echo request content.
- **AGPL-3.0-or-later.** The whole Worker is two files: [`src/index.js`](src/index.js) (routing) and [`src/lib.js`](src/lib.js) (the security core, unit-tested by `npm test`).

## Limits you will hit

- **Single `PUT` is capped at 100 MB** by Cloudflare's edge on Free and Pro plans (the Worker refuses at 95 MB with a clear error). Crate uploads larger files with R2 multipart through this Worker — measured working at 250 MB.
- Workers Free plan: 100,000 requests/day. Each file is one request per ~8 MB chunk plus a manifest write.

## Routes

All under `/o/<key>`, all signed.

| Method | Path | Does |
|---|---|---|
| `PUT` | `/o/<key>` | Store; honours `If-Match` / `If-None-Match: *` → 412 |
| `GET` / `HEAD` | `/o/<key>` | Fetch; honours `Range`; returns `ETag` |
| `DELETE` | `/o/<key>` | Delete |
| `POST` | `/o/<key>?mpu=create` | Begin multipart → `{uploadId}` |
| `PUT` | `/o/<key>?mpu=part&uploadId=…&n=…` | One part → `{partNumber, etag}` |
| `POST` | `/o/<key>?mpu=complete&uploadId=…` | Body: `[{partNumber, etag}]` |
| `POST` | `/o/<key>?mpu=abort&uploadId=…` | Discard |
| `GET` | `/` | `{ready, bucket}` — is the secret set, is the bucket bound |
