// Server-only file-bound scan token signing. No administrator login is required.
// This staging interface accepts only benign/inert test files and is publicly accessible.
// LAB_SCAN_TOKEN_PRIVATE_KEY is a server-only Ed25519 PKCS#8 private key (base64 DER).

import { createPrivateKey, randomBytes, sign } from "node:crypto";

const TOKEN_SECONDS = 120;
const AUDIENCE = "filesmagic-security-engine/scan"; // must match app/auth.py
export { MAX_UPLOAD_BYTES, UPLOAD_TOO_LARGE } from "@/lib/api";

export class NotConfiguredError extends Error {}

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new NotConfiguredError(`${name} is not configured`);
  return value;
}

// Short-lived, single-use token for uploading exactly one file (by SHA-256 and size) to the engine.
export function mintScanToken(sha256: string, size: number): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({ aud: AUDIENCE, iat: now, exp: now + TOKEN_SECONDS, jti: randomBytes(16).toString("hex"), sha256, size }),
  );
  const key = createPrivateKey({ key: Buffer.from(env("LAB_SCAN_TOKEN_PRIVATE_KEY"), "base64"), format: "der", type: "pkcs8" });
  return `${payload.toString("base64url")}.${sign(null, payload, key).toString("base64url")}`;
}
