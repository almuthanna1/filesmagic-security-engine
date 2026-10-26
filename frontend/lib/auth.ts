// Server-only: admin sessions and scan-token signing. Imported by route handlers in app/api/
// only. None of these variables has the NEXT_PUBLIC_ prefix, so Next.js never inlines them
// into the browser bundle.
//
//   LAB_ADMIN_PASSWORD_HASH     scrypt$<salt base64>$<hash base64>   (see README)
//   LAB_SESSION_SECRET          >= 32 random characters; rotating it logs everyone out
//   LAB_SCAN_TOKEN_PRIVATE_KEY  base64 DER (PKCS#8) Ed25519 private key; the engine holds the public half

import { createHmac, createPrivateKey, randomBytes, scryptSync, sign, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "lab_session";
const SESSION_SECONDS = 8 * 60 * 60;
const TOKEN_SECONDS = 120;
const AUDIENCE = "filesmagic-security-engine/scan"; // must match app/auth.py
export { MAX_UPLOAD_BYTES, UPLOAD_TOO_LARGE } from "@/lib/api";

export class NotConfiguredError extends Error {}

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new NotConfiguredError(`${name} is not configured`);
  return value;
}

export function checkPassword(password: string): boolean {
  const [scheme, salt, hash] = env("LAB_ADMIN_PASSWORD_HASH").split("$");
  if (scheme !== "scrypt" || !salt || !hash) throw new NotConfiguredError("LAB_ADMIN_PASSWORD_HASH is malformed");
  const expected = Buffer.from(hash, "base64");
  return timingSafeEqual(scryptSync(password, Buffer.from(salt, "base64"), expected.length), expected);
}

function mac(value: string): string {
  const secret = env("LAB_SESSION_SECRET");
  if (secret.length < 32) throw new NotConfiguredError("LAB_SESSION_SECRET must be at least 32 characters");
  return createHmac("sha256", secret).update(value).digest("base64url");
}

export function createSession(): string {
  const exp = String(Math.floor(Date.now() / 1000) + SESSION_SECONDS);
  return `${exp}.${mac(exp)}`;
}

export function validSession(value: string | undefined): boolean {
  const [exp, signature] = (value ?? "").split(".");
  if (!exp || !signature) return false;
  const expected = Buffer.from(mac(exp));
  const actual = Buffer.from(signature);
  return actual.length === expected.length && timingSafeEqual(actual, expected) && Number(exp) > Date.now() / 1000;
}

export const sessionCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict" as const,
  path: "/",
  maxAge: SESSION_SECONDS,
};

// Short-lived, single-use token for uploading exactly one file (by SHA-256 and size) to the engine.
export function mintScanToken(sha256: string, size: number): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({ aud: AUDIENCE, iat: now, exp: now + TOKEN_SECONDS, jti: randomBytes(16).toString("hex"), sha256, size }),
  );
  const key = createPrivateKey({ key: Buffer.from(env("LAB_SCAN_TOKEN_PRIVATE_KEY"), "base64"), format: "der", type: "pkcs8" });
  return `${payload.toString("base64url")}.${sign(null, payload, key).toString("base64url")}`;
}
